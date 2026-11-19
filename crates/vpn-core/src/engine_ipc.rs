//! Protocol between `omnitund` (root) and an engine process (unprivileged,
//! sandboxed): one engine per session, one `Start` per connection attempt.
//! Newline-delimited JSON on a control socket; the tun descriptor travels
//! on a second socket as SCM_RIGHTS, announced by `ToEngine::Tun`. On
//! Windows, where an interface cannot be handed over, the daemon relays
//! its packets on that second channel instead ([`write_packet`]). The
//! user's answers never come this way: the engine asks on its own prompt
//! socket (see `ipc`).
//!
//! The engine is untrusted from the daemon's point of view: everything it
//! sends is validated there (settings bounds, domain syntax, conflicts).

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{FailureKind, Profile, TunnelSettings};

/// Longest control line accepted from either side.
pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ToEngine {
    /// A connection attempt for this profile (certificate files inlined).
    /// `attach_wait_ms`: how long a question waits for the client to attach
    /// to the prompt socket; zero for reconnections, which use remembered
    /// answers or an already attached client.
    Start { profile: Box<Profile>, attach_wait_ms: u64 },
    /// The tun interface for the negotiated settings; its descriptor
    /// follows on the descriptor socket.
    Tun { name: String },
    /// End the current attempt (log out); the engine stays for the next.
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum FromEngine {
    /// Authenticated and negotiated: waiting for `Tun`.
    Connected { settings: TunnelSettings },
    /// Counters of this attempt, from zero.
    Stats { rx_bytes: u64, tx_bytes: u64, rx_packets: u64, tx_packets: u64 },
    /// The attempt is over: the connection failed, the tunnel dropped
    /// (`error`), or it was stopped (`None`).
    Ended { error: Option<EngineError> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineError {
    pub failure: FailureKind,
    pub message: String,
}

/// Largest packet relayed between the daemon and an engine (IPv4's).
pub const MAX_PACKET: usize = u16::MAX as usize;

/// Writes one packet on a packet channel: its length (two bytes, big
/// endian), then the packet.
pub async fn write_packet(out: &mut (impl AsyncWrite + Unpin), packet: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(packet.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "packet too large"))?;
    let mut frame = Vec::with_capacity(2 + packet.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(packet);
    out.write_all(&frame).await
}

/// Reads the next packet into `buf`, returning its length; `None` once the
/// channel is closed between packets.
pub async fn read_packet(input: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    let mut len = [0u8; 2];
    match input.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(len) as usize;
    let packet = buf
        .get_mut(..len)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "packet larger than the buffer"))?;
    input.read_exact(packet).await?;
    Ok(Some(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_keep_their_bounds() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_packet(&mut a, b"first").await.unwrap();
        write_packet(&mut a, b"").await.unwrap();
        write_packet(&mut a, &[7; 300]).await.unwrap();
        drop(a);
        let mut buf = vec![0; MAX_PACKET];
        assert_eq!(read_packet(&mut b, &mut buf).await.unwrap(), Some(5));
        assert_eq!(&buf[..5], b"first");
        assert_eq!(read_packet(&mut b, &mut buf).await.unwrap(), Some(0));
        assert_eq!(read_packet(&mut b, &mut buf).await.unwrap(), Some(300));
        assert_eq!(read_packet(&mut b, &mut buf).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversized_packets_are_refused() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        assert!(write_packet(&mut a, &vec![0; MAX_PACKET + 1]).await.is_err());
        write_packet(&mut a, &[1; 100]).await.unwrap();
        let mut small = [0; 10];
        assert!(read_packet(&mut b, &mut small).await.is_err());
    }
}
