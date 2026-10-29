//! The PPP-over-TLS data channel opened with `GET /remote/sslvpn-tunnel`.
//!
//! Every PPP frame is preceded by a 6-byte header: total length (header
//! included), the magic `0x5050`, then the payload length, big-endian.

use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use vpn_core::{PacketIo, SessionContext};

use crate::http::{Client, USER_AGENT};
use crate::ppp::Ppp;
use crate::tls::Stream;

const MAGIC: [u8; 2] = [0x50, 0x50];
const HEADER_LEN: usize = 6;
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);
const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(3);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub struct Tunnel {
    writer: WriteHalf<Stream>,
    frames: mpsc::Receiver<anyhow::Result<Vec<u8>>>,
    reader: JoinHandle<()>,
    pub ppp: Ppp,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Tunnel {
    pub async fn open(client: &Client, mru: u16) -> anyhow::Result<Self> {
        let cookie = client.session_cookie().context("no SSL VPN session cookie")?;
        let mut stream = client.endpoint().connect().await?;
        // The gateway answers with PPP frames directly, no HTTP response.
        let request = format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nUser-Agent: {USER_AGENT}\r\n\
             Cookie: SVPNCOOKIE={cookie}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let (read_half, writer) = tokio::io::split(stream);
        let (tx, frames) = mpsc::channel(256);
        let reader = tokio::spawn(read_loop(read_half, tx));
        Ok(Self { writer, frames, reader, ppp: Ppp::new(mru) })
    }

    /// Runs LCP and IPCP until the link is up.
    pub async fn negotiate(&mut self, ctx: &SessionContext) -> anyhow::Result<()> {
        self.ppp.start();
        self.flush().await?;
        let deadline = tokio::time::sleep(NEGOTIATION_TIMEOUT);
        tokio::pin!(deadline);
        let mut retransmit = interval_at(Instant::now() + RETRANSMIT_INTERVAL, RETRANSMIT_INTERVAL);

        while !self.ppp.is_up() {
            tokio::select! {
                frame = self.frames.recv() => {
                    let frame = frame.context("tunnel closed during PPP negotiation")??;
                    self.input(&frame).await?;
                }
                _ = retransmit.tick() => self.ppp.retransmit()?,
                _ = &mut deadline => bail!("PPP negotiation timed out"),
                _ = ctx.cancel.cancelled() => bail!("connection cancelled"),
            }
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn run(&mut self, ctx: &SessionContext, mut io: PacketIo) -> anyhow::Result<()> {
        let mut keepalive = interval_at(Instant::now() + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    self.ppp.terminate();
                    let _ = tokio::time::timeout(Duration::from_secs(2), self.flush()).await;
                    return Ok(());
                }
                frame = self.frames.recv() => {
                    let frame = frame.context("tunnel closed by gateway")??;
                    if let Some(packet) = self.input(&frame).await? {
                        ctx.stats.record_rx(packet.len());
                        if io.to_tun.send(packet).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                packet = io.from_tun.recv() => {
                    let Some(packet) = packet else { return Ok(()) };
                    // IPv4 only: IPv6 is blocked into the tunnel interface.
                    if packet.first().is_some_and(|b| b >> 4 == 4) {
                        ctx.stats.record_tx(packet.len());
                        // The PPP header and the packet go into one frame.
                        let frame = encode_frame_parts(&[&crate::ppp::PROTO_IP.to_be_bytes(), &packet])?;
                        self.write_encoded(&frame).await?;
                    }
                }
                _ = keepalive.tick() => self.ppp.keepalive()?,
            }
            self.flush().await?;
        }
    }

    /// Feeds a frame to PPP. When it ends the link (e.g. Terminate-Request),
    /// the reply PPP queued (Terminate-Ack) is still sent before failing.
    async fn input(&mut self, frame: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
        let result = self.ppp.input(frame);
        if result.is_err() {
            let _ = tokio::time::timeout(Duration::from_secs(2), self.flush()).await;
        }
        result
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        for frame in self.ppp.drain() {
            self.write_frame(&frame).await?;
        }
        Ok(())
    }

    async fn write_frame(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        self.write_encoded(&encode_frame(payload)?).await
    }

    async fn write_encoded(&mut self, frame: &[u8]) -> anyhow::Result<()> {
        self.writer.write_all(frame).await.context("tunnel write failed")?;
        self.writer.flush().await?;
        Ok(())
    }
}

async fn read_loop(mut reader: ReadHalf<Stream>, tx: mpsc::Sender<anyhow::Result<Vec<u8>>>) {
    loop {
        let frame = read_frame(&mut reader).await;
        let failed = frame.is_err();
        if tx.send(frame).await.is_err() || failed {
            return;
        }
    }
}

pub fn encode_frame(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    encode_frame_parts(&[payload])
}

/// A frame whose payload is `parts`, end to end, built in one buffer.
pub fn encode_frame_parts(parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let payload_len: usize = parts.iter().map(|p| p.len()).sum();
    let len =
        u16::try_from(payload_len).ok().filter(|l| *l <= u16::MAX - HEADER_LEN as u16).context("frame too large")?;
    let mut frame = Vec::with_capacity(payload_len + HEADER_LEN);
    frame.extend_from_slice(&(len + HEADER_LEN as u16).to_be_bytes());
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    for part in parts {
        frame.extend_from_slice(part);
    }
    Ok(frame)
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await.context("tunnel closed by gateway")?;
    if &header == b"HTTP/1" {
        bail!("gateway refused the tunnel (session cookie expired or tunnel mode not allowed)");
    }
    let total = u16::from_be_bytes([header[0], header[1]]) as usize;
    let size = u16::from_be_bytes([header[4], header[5]]) as usize;
    if header[2..4] != MAGIC || total != size + HEADER_LEN || size == 0 {
        bail!("invalid tunnel frame header {}", hex::encode(header));
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await.context("truncated tunnel frame")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let frame = encode_frame(&[0xc0, 0x21, 1, 1, 0, 4]).unwrap();
        assert_eq!(&frame[..6], &[0, 12, 0x50, 0x50, 0, 6]);
        let decoded = read_frame(&mut &frame[..]).await.unwrap();
        assert_eq!(decoded, &[0xc0, 0x21, 1, 1, 0, 4]);
        // An IP packet: the PPP header and the packet, end to end.
        let parts = encode_frame_parts(&[&crate::ppp::PROTO_IP.to_be_bytes(), &[0x45, 0, 0, 20]]).unwrap();
        assert_eq!(parts, encode_frame(&[0, 0x21, 0x45, 0, 0, 20]).unwrap());
        assert!(encode_frame_parts(&[&[0; 65520], &[0; 10]]).is_err(), "too large");
    }

    #[tokio::test]
    async fn rejects_http_answer_and_bad_magic() {
        let err = read_frame(&mut &b"HTTP/1.1 403 Forbidden\r\n"[..]).await.unwrap_err();
        assert!(err.to_string().contains("refused"));
        assert!(read_frame(&mut &[0u8, 8, 0x51, 0x50, 0, 2, 1, 2][..]).await.is_err());
    }
}
