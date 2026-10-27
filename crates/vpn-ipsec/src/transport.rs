//! UDP transport for IKE and UDP-encapsulated ESP (RFC 3948). On port
//! 4500, IKE messages carry a 4-byte zero "non-ESP marker".

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{Context, bail};
use tokio::net::UdpSocket;
use tracing::debug;

pub const NATT_PORT: u16 = 4500;
const NON_ESP_MARKER: [u8; 4] = [0; 4];

pub enum Datagram {
    Ike(Vec<u8>),
    Esp(Vec<u8>),
    Keepalive,
}

pub struct Transport {
    socket: UdpSocket,
    peer: SocketAddrV4,
    natt: bool,
}

impl Transport {
    pub async fn connect(peer: SocketAddrV4) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect(peer).await.with_context(|| format!("cannot reach {peer}"))?;
        Ok(Self { socket, peer, natt: false })
    }

    /// Moves to the NAT-T port (4500) with a fresh socket (RFC 7296 §2.23).
    pub async fn switch_to_natt(&mut self, port: u16) -> anyhow::Result<()> {
        let peer = SocketAddrV4::new(*self.peer.ip(), port);
        *self = Self::connect(peer).await?;
        self.natt = true;
        Ok(())
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.peer
    }

    pub fn local(&self) -> anyhow::Result<SocketAddrV4> {
        match self.socket.local_addr()? {
            SocketAddr::V4(a) => Ok(a),
            SocketAddr::V6(_) => bail!("IPv6 transport is not supported"),
        }
    }

    pub async fn send_ike(&self, msg: &[u8]) -> anyhow::Result<()> {
        if self.natt { self.send(&[&NON_ESP_MARKER[..], msg].concat()).await } else { self.send(msg).await }
    }

    pub async fn send_esp(&self, packet: &[u8]) -> anyhow::Result<()> {
        debug_assert!(self.natt);
        self.send(packet).await
    }

    pub async fn send_keepalive(&self) -> anyhow::Result<()> {
        self.send(&[0xff]).await
    }

    /// Network errors (ICMP unreachable, interface down while roaming…)
    /// are transient: retransmission and dead peer detection decide
    /// whether the gateway is gone.
    async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        match self.socket.send(data).await {
            Ok(_) => Ok(()),
            Err(e) if is_transient(&e) => {
                debug!("transient UDP send error: {e}");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Next datagram from the gateway. ICMP-induced errors are skipped.
    pub async fn recv(&self) -> anyhow::Result<Datagram> {
        let mut buf = vec![0u8; 16384];
        loop {
            let len = match self.socket.recv(&mut buf).await {
                Ok(len) => len,
                Err(e) if is_transient(&e) => {
                    debug!("transient UDP error: {e}");
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let data = &buf[..len];
            if !self.natt {
                return Ok(Datagram::Ike(data.to_vec()));
            }
            match data {
                [0xff] => return Ok(Datagram::Keepalive),
                [0, 0, 0, 0, rest @ ..] => return Ok(Datagram::Ike(rest.to_vec())),
                _ if len >= 8 => return Ok(Datagram::Esp(data.to_vec())),
                _ => debug!("ignoring {len}-byte datagram"),
            }
        }
    }
}

fn is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::AddrNotAvailable
    )
}
