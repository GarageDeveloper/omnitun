//! L2TP over IPsec engine (RFC 3193), as macOS, Windows and Meraki Client
//! VPN do it: an IKEv1 PSK phase 1 and an ESP SA in transport mode for
//! UDP 1701 (`vpn_ipsec::TransportChannel`), then an L2TP tunnel and
//! session (`l2tp`) carrying PPP (`ppp`), which authenticates the user
//! and assigns the address.
//!
//! The IPsec SA runs in its own task; L2TP datagrams go to it as IPv4/UDP
//! packets between our address and the server's.
//!
//! # Security
//!
//! The group pre-shared key authenticates the server: anyone who has it
//! can pose as the server and, with PAP, read the password (MS-CHAPv2
//! responses can be cracked offline). Prefer MS-CHAPv2, which also proves
//! that the server knows the password, and keep the PSK secret.

mod l2tp;
mod ppp;
mod recorder;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use async_trait::async_trait;
use bytes::Bytes;
use ipnet::Ipv4Net;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vpn_core::{
    DnsSettings, Engine, FailureKind, L2TP_PORT, L2tpProfile, PacketIo, PppAuth, Prompt, PromptKind, SessionContext,
    TunnelSettings, failure,
};
use vpn_ipsec::TransportChannel;
use zeroize::Zeroizing;

use crate::l2tp::{Received, Tunnel, ppp_protocol};
use crate::ppp::Ppp;
use crate::recorder::{Direction, Recorder};

/// L2TP, then PPP, must be up within this.
const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(500);
/// Inner MTU: PPP, L2TP, UDP and ESP in UDP inside 1500 bytes.
const TUNNEL_MTU: u16 = 1360;

pub struct L2tpEngine {
    profile: L2tpProfile,
    session: Option<Session>,
}

struct Session {
    tunnel: Tunnel,
    ppp: Ppp,
    to_ipsec: mpsc::Sender<Bytes>,
    from_ipsec: mpsc::Receiver<Bytes>,
    ipsec: Option<JoinHandle<anyhow::Result<()>>>,
    ipsec_cancel: CancellationToken,
    local: Ipv4Addr,
    gateway: Ipv4Addr,
    recorder: Recorder,
}

impl L2tpEngine {
    pub fn new(profile: L2tpProfile) -> Self {
        Self { profile, session: None }
    }

    async fn credentials(&self, ctx: &SessionContext) -> anyhow::Result<(String, Zeroizing<String>)> {
        let ask = |key: &str, kind: PromptKind, text: String| ctx.prompter.ask(Prompt::new(key, kind, text));
        let username = match &self.profile.username {
            Some(user) => user.clone(),
            None => ask("username", PromptKind::Text, format!("User name for {}", ctx.name)).await?,
        };
        let password = Zeroizing::new(
            ask("password", PromptKind::Secret, format!("Password for {username} on {}", ctx.name)).await?,
        );
        Ok((username, password))
    }
}

/// An IPv4/UDP packet from our L2TP port to the server's.
fn udp(local: Ipv4Addr, gateway: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&local.octets());
    packet.extend_from_slice(&gateway.octets());
    let mut sum: u32 = packet.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet.extend_from_slice(&L2TP_PORT.to_be_bytes());
    packet.extend_from_slice(&L2TP_PORT.to_be_bytes());
    packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // no checksum: ESP authenticates it
    packet.extend_from_slice(payload);
    packet
}

/// The network of `address` by its class: what macOS routes through an
/// L2TP VPN that does not take all traffic.
fn classful(address: Ipv4Addr) -> Ipv4Net {
    let prefix = match address.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    };
    Ipv4Net::new(address, prefix).expect("valid prefix").trunc()
}

impl Session {
    /// Sends what L2TP and PPP have queued.
    async fn flush(&mut self) -> anyhow::Result<()> {
        for (protocol, contents) in self.ppp.take_output() {
            if self.tunnel.is_up() {
                let data = self.tunnel.data(protocol, &contents);
                self.send(&data).await?;
            }
        }
        for datagram in self.tunnel.take_output() {
            self.send(&datagram).await?;
        }
        Ok(())
    }

    async fn send(&mut self, datagram: &[u8]) -> anyhow::Result<()> {
        self.recorder.record(Direction::Out, datagram);
        let packet = udp(self.local, self.gateway, datagram);
        self.to_ipsec.send(Bytes::from(packet)).await.map_err(|_| anyhow::anyhow!("the IPsec SA is gone"))
    }

    /// Handles a packet from the IPsec SA; returns an IP packet for the
    /// tunnel interface.
    fn received(&mut self, packet: &[u8], now: Instant) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(datagram) = packet.get(28..) else { return Ok(None) };
        self.recorder.record(Direction::In, datagram);
        match self.tunnel.receive(datagram, now)? {
            Received::Nothing => Ok(None),
            Received::SessionUp => Ok(None),
            Received::Ppp(frame) => match ppp_protocol(&frame) {
                Some((protocol, contents)) => self.ppp.input(protocol, contents, now),
                None => Ok(None),
            },
        }
    }

    fn tick(&mut self, now: Instant) -> anyhow::Result<()> {
        self.tunnel.tick(now)?;
        if self.tunnel.is_up() {
            self.ppp.tick(now)?;
        }
        Ok(())
    }

    /// The IPsec task ended: why.
    async fn ipsec_ended(&mut self) -> anyhow::Error {
        match self.ipsec.take() {
            Some(task) => match task.await {
                Ok(Err(e)) => e.context("the IPsec SA failed"),
                Ok(Ok(())) => anyhow::anyhow!("the IPsec SA closed"),
                Err(e) => anyhow::anyhow!("the IPsec task failed: {e}"),
            },
            None => anyhow::anyhow!("the IPsec SA closed"),
        }
    }

    /// Ends L2TP, then the IPsec SA, best effort.
    async fn close(&mut self) {
        self.recorder.report("disconnected");
        self.tunnel.close(Instant::now());
        if let Err(e) = self.flush().await {
            debug!("L2TP close not sent: {e:#}");
        }
        // Let the StopCCN leave before the SA is deleted.
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.ipsec_cancel.cancel();
        if let Some(task) = self.ipsec.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
    }
}

#[async_trait]
impl Engine for L2tpEngine {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
        if let Some(mut old) = self.session.take() {
            old.close().await;
        }
        self.profile.validate()?;
        let mut channel = TransportChannel::establish(&self.profile.ipsec(), L2TP_PORT, ctx).await?;
        let (local, gateway) = (channel.local(), channel.gateway());
        info!(%gateway, "IPsec transport mode SA up, starting L2TP");
        let (username, password) = self.credentials(ctx).await?;

        // The SA runs in its own task, with its own statistics: the
        // session counts the packets of the tunnel interface.
        let ipsec_cancel = ctx.cancel.child_token();
        let ipsec_ctx = SessionContext {
            name: ctx.name.clone(),
            prompter: ctx.prompter.clone(),
            cancel: ipsec_cancel.clone(),
            stats: Arc::default(),
        };
        let (to_ipsec, from_l2tp) = mpsc::channel(256);
        let (to_l2tp, from_ipsec) = mpsc::channel(256);
        let ipsec = tokio::spawn(async move {
            let result = channel.run(&ipsec_ctx, PacketIo { to_tun: to_l2tp, from_tun: from_l2tp }).await;
            channel.close().await;
            result
        });
        let now = Instant::now();
        let mut session = Session {
            tunnel: Tunnel::new(now),
            ppp: Ppp::new(username, password, self.profile.ppp_auth.clone()),
            to_ipsec,
            from_ipsec,
            ipsec: Some(ipsec),
            ipsec_cancel,
            local,
            gateway,
            recorder: Recorder::new(),
        };
        let deadline = tokio::time::Instant::now() + SETUP_TIMEOUT;
        let result: anyhow::Result<()> = async {
            loop {
                session.flush().await?;
                if session.ppp.up.is_some() {
                    return Ok(());
                }
                tokio::select! {
                    packet = session.from_ipsec.recv() => match packet {
                        Some(packet) => {
                            let now = Instant::now();
                            session.received(&packet, now)?;
                            // PPP starts once the L2TP session is up.
                            if session.tunnel.is_up() {
                                session.ppp.start(now);
                            }
                        }
                        // Cancelled: the IPsec task ends with us.
                    None if ctx.cancel.is_cancelled() => return Ok(()),
                    None => return Err(session.ipsec_ended().await),
                    },
                    _ = tokio::time::sleep(TICK) => session.tick(Instant::now())?,
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(failure(FailureKind::Timeout, "the L2TP server did not set up the session in time"));
                    }
                    _ = ctx.cancel.cancelled() => return Err(failure(FailureKind::Cancelled, "cancelled")),
                }
            }
        }
        .await;
        if let Err(e) = result {
            session.close().await;
            return Err(e);
        }
        let assigned = session.ppp.up.clone().expect("checked above");
        let mut servers: Vec<IpAddr> = assigned.dns.iter().copied().map(IpAddr::V4).collect();
        if servers.is_empty() {
            servers = self.profile.dns_servers.clone();
        }
        if assigned.dns.is_empty() && servers.is_empty() {
            warn!("the L2TP server assigned no DNS server");
        }
        info!(address = %assigned.address, "L2TP over IPsec connected");
        if session.ppp.server_proved() && self.profile.ppp_auth != [PppAuth::MsChapV2] {
            // A server asking for less next time would not be this one.
            info!("the L2TP server proved itself with MS-CHAPv2: PAP and CHAP are no longer accepted");
            self.profile.ppp_auth = vec![PppAuth::MsChapV2];
            let prompter = ctx.prompter.clone();
            tokio::spawn(async move {
                let notice = Prompt::new(
                    vpn_core::prompt::L2TP_SERVER_PROVED,
                    PromptKind::Confirm,
                    "the L2TP server proved itself with MS-CHAPv2",
                );
                if let Err(e) = prompter.ask(notice).await {
                    debug!("the profile keeps its PPP authentications: {e:#}");
                }
            });
        }
        self.session = Some(session);
        Ok(TunnelSettings {
            address: assigned.address,
            mtu: TUNNEL_MTU,
            routes: vec![classful(assigned.address)],
            excluded_routes: Vec::new(),
            full_tunnel: false,
            dns: DnsSettings { servers, search_domains: Vec::new(), match_domains: Vec::new() },
            gateway: IpAddr::V4(gateway),
        })
    }

    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let session = self.session.as_mut().context("the L2TP engine is not connected")?;
        let result = Self::forward(session, ctx, io).await;
        if let Err(e) = &result {
            session.recorder.report(&format!("{e:#}"));
        }
        result
    }

    async fn disconnect(&mut self) -> anyhow::Result<()> {
        if let Some(mut session) = self.session.take() {
            session.close().await;
        }
        Ok(())
    }
}

impl L2tpEngine {
    /// Packets between the tunnel interface and the server until either
    /// ends.
    async fn forward(session: &mut Session, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let PacketIo { to_tun, mut from_tun } = io;
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                packet = session.from_ipsec.recv() => match packet {
                    Some(packet) => {
                        if let Some(ip) = session.received(&packet, Instant::now())? {
                            ctx.stats.record_rx(ip.len());
                            if to_tun.send(Bytes::from(ip)).await.is_err() {
                                bail!("tun interface closed");
                            }
                        }
                    }
                    // Cancelled: the IPsec task ends with us.
                    None if ctx.cancel.is_cancelled() => return Ok(()),
                    None => return Err(session.ipsec_ended().await),
                },
                packet = from_tun.recv() => match packet {
                    Some(packet) if packet.first().is_some_and(|b| b >> 4 == 4) => {
                        let data = session.tunnel.data(ppp::IP, &packet);
                        session.send(&data).await?;
                        ctx.stats.record_tx(packet.len());
                    }
                    Some(_) => {}
                    None => return Ok(()),
                },
                _ = tick.tick() => session.tick(Instant::now())?,
                _ = ctx.cancel.cancelled() => return Ok(()),
            }
            session.flush().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        let packet = udp(Ipv4Addr::new(192, 168, 1, 2), Ipv4Addr::new(203, 0, 113, 1), b"l2tp");
        assert_eq!((packet.len(), packet[9], &packet[20..24]), (32, 17, &[0x06, 0xa5, 0x06, 0xa5][..]));
        assert_eq!(classful(Ipv4Addr::new(10, 9, 0, 2)).to_string(), "10.0.0.0/8");
        assert_eq!(classful(Ipv4Addr::new(172, 16, 5, 9)).to_string(), "172.16.0.0/16");
        assert_eq!(classful(Ipv4Addr::new(192, 168, 7, 9)).to_string(), "192.168.7.0/24");
    }
}
