//! The connection to the server: UDP datagrams, or TCP with a 16-bit
//! length before each packet. A task reads it into a channel, so that
//! waiting for a packet is cancel-safe in `select!`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use vpn_core::{FailureExt, FailureKind, Transport};

/// Largest packet accepted from the server.
const MAX_PACKET: usize = 65_535;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

enum Sender {
    Udp(Arc<UdpSocket>),
    Tcp(tokio::net::tcp::OwnedWriteHalf),
}

pub struct Link {
    sender: Sender,
    pub received: mpsc::Receiver<anyhow::Result<Vec<u8>>>,
    reader: tokio::task::JoinHandle<()>,
    pub tcp: bool,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Link {
    pub async fn open(addr: SocketAddr, transport: Transport) -> anyhow::Result<Self> {
        let (tx, received) = mpsc::channel(256);
        match transport {
            Transport::Udp => {
                let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
                let socket = UdpSocket::bind(bind).await.context("cannot open a UDP socket")?;
                socket
                    .connect(addr)
                    .await
                    .kind(FailureKind::Unreachable)
                    .with_context(|| format!("cannot reach {addr}"))?;
                let socket = Arc::new(socket);
                let read = socket.clone();
                let reader = tokio::spawn(async move {
                    let mut buf = vec![0u8; MAX_PACKET];
                    loop {
                        let result = read.recv(&mut buf).await.map(|n| buf[..n].to_vec()).map_err(anyhow::Error::from);
                        // A refused datagram (ICMP) is reported, not fatal;
                        // without a pause it would repeat at once.
                        let failed = result.is_err();
                        if tx.send(result).await.is_err() {
                            return;
                        }
                        if failed {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                });
                Ok(Self { sender: Sender::Udp(socket), received, reader, tcp: false })
            }
            Transport::Tcp => {
                let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .map_err(|_| anyhow::anyhow!("no answer from {addr} (TCP)"))
                    .and_then(|r| r.with_context(|| format!("cannot reach {addr} (TCP)")))
                    .kind(FailureKind::Unreachable)?;
                stream.set_nodelay(true)?;
                let (mut read, write) = stream.into_split();
                let reader = tokio::spawn(async move {
                    loop {
                        let result = async {
                            let len = read.read_u16().await? as usize;
                            let mut packet = vec![0u8; len];
                            read.read_exact(&mut packet).await?;
                            anyhow::Ok(packet)
                        }
                        .await;
                        let end = result.is_err();
                        let result = result.map_err(|e| e.context("the server closed the TCP connection"));
                        if tx.send(result).await.is_err() || end {
                            return;
                        }
                    }
                });
                Ok(Self { sender: Sender::Tcp(write), received, reader, tcp: true })
            }
        }
    }

    pub async fn send(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        match &mut self.sender {
            Sender::Udp(socket) => {
                // ICMP errors of earlier datagrams surface here: not fatal.
                if let Err(e) = socket.send(packet).await {
                    tracing::debug!("UDP send: {e}");
                }
            }
            Sender::Tcp(write) => {
                let len = u16::try_from(packet.len()).context("packet too large")?;
                let mut framed = Vec::with_capacity(packet.len() + 2);
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(packet);
                write.write_all(&framed).await.context("cannot send to the server (TCP)")?;
            }
        }
        Ok(())
    }
}
