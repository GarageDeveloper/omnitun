//! WireGuard engine: a client with one peer, the server, as `wg-quick`
//! sets it up. The Noise handshake, the transport keys, replay protection
//! and timers come from boringtun (Cloudflare, BSD-3-Clause); this crate
//! drives its UDP socket and the tun interface.
//!
//! # Security choices
//!
//! - Cryptokey routing: a packet from the peer is accepted only if its
//!   source lies in the peer's `AllowedIPs`, and its destination is our
//!   address; anything else is dropped.
//! - The private key and the pre-shared key are asked like the other
//!   secrets (the user's client answers from the Keychain): they are not
//!   part of the profile the daemon sees.
//! - The socket is connected to the endpoint: datagrams from anywhere
//!   else never reach boringtun, and the endpoint never roams.
//! - The tunnel carries IPv4 only, like the other engines.
//!
//! The server answers nothing to a handshake it cannot authenticate: a
//! wrong key, a peer not declared on the server and a closed port all
//! look the same, a timeout.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tracing::{debug, info};
use vpn_core::wireguard::parse_key;
use vpn_core::{
    DnsSettings, Engine, FailureExt, FailureKind, PacketIo, Prompt, PromptKind, SessionContext, TunnelSettings,
    WIREGUARD_MTU, WireGuardProfile, failure,
};
use zeroize::Zeroizing;

/// Handshake attempts before giving up, each waiting this long for the
/// answer (WireGuard's REKEY_TIMEOUT).
const HANDSHAKE_ATTEMPTS: usize = 3;
const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
/// How often boringtun's timers run (rekeying, keepalives, retries).
const TICK: Duration = Duration::from_millis(250);
/// Large enough for any UDP datagram, and for a tun packet plus the
/// WireGuard overhead.
const BUFFER: usize = 65_536;

pub struct WireGuardEngine {
    profile: WireGuardProfile,
    session: Option<Session>,
}

impl WireGuardEngine {
    pub fn new(profile: WireGuardProfile) -> Self {
        Self { profile, session: None }
    }
}

struct Session {
    socket: UdpSocket,
    peer: IpAddr,
    tunn: Tunn,
    allowed: Allowed,
    /// Where boringtun writes, kept between calls.
    send: Vec<u8>,
}

/// The sources the peer may send from (cryptokey routing), and our
/// addresses.
struct Allowed {
    networks: Vec<Ipv4Net>,
    local: Vec<Ipv4Addr>,
}

impl Allowed {
    fn contains(&self, source: Ipv4Addr) -> bool {
        self.networks.iter().any(|net| net.contains(&source))
    }

    /// A packet from `source` (boringtun read it from the header) to one
    /// of our addresses.
    fn accepts(&self, packet: &[u8], source: Ipv4Addr) -> bool {
        self.contains(source) && packet.get(16..20).is_some_and(|dst| self.local.iter().any(|a| a.octets() == dst))
    }
}

impl Session {
    /// Once the peer has answered, a transient network error (an ICMP
    /// unreachable while it restarts, roaming…) only loses the datagram:
    /// WireGuard's timers recover, or give up with `ConnectionExpired`.
    async fn send_datagram(&self, datagram: &[u8]) -> anyhow::Result<()> {
        match self.socket.send(datagram).await {
            Ok(_) => Ok(()),
            Err(e) if self.established() && vpn_core::net::transient(&e) => {
                debug!("transient UDP send error: {e}");
                Ok(())
            }
            Err(e) => Err(e).kind(FailureKind::Unreachable).context("cannot send to the WireGuard peer"),
        }
    }

    /// Feeds one datagram to boringtun; returns the IPv4 packets for the
    /// tun interface.
    async fn received(&mut self, datagram: &[u8]) -> anyhow::Result<Vec<Bytes>> {
        let mut packets = Vec::new();
        let mut result = self.tunn.decapsulate(Some(self.peer), datagram, &mut self.send);
        loop {
            match result {
                TunnResult::WriteToNetwork(reply) => {
                    let reply = reply.to_vec();
                    self.send_datagram(&reply).await?;
                    // Then the packets queued while there was no session.
                    result = self.tunn.decapsulate(None, &[], &mut self.send);
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, from) if self.allowed.accepts(packet, from) => {
                    packets.push(Bytes::copy_from_slice(packet));
                }
                TunnResult::WriteToTunnelV4(_, from) => {
                    debug!(%from, "dropping a packet from outside the peer's allowed networks, or not to us");
                }
                TunnResult::WriteToTunnelV6(..) => debug!("dropping an IPv6 packet"),
                TunnResult::Err(e) => debug!("WireGuard datagram refused: {e:?}"),
                TunnResult::Done => {}
            }
            return Ok(packets);
        }
    }

    async fn outgoing(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        match self.tunn.encapsulate(packet, &mut self.send) {
            TunnResult::WriteToNetwork(datagram) => {
                let datagram = datagram.to_vec();
                self.send_datagram(&datagram).await
            }
            TunnResult::Err(e) => {
                debug!("cannot encapsulate: {e:?}");
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn tick(&mut self) -> anyhow::Result<()> {
        match self.tunn.update_timers(&mut self.send) {
            TunnResult::WriteToNetwork(datagram) => {
                let datagram = datagram.to_vec();
                self.send_datagram(&datagram).await
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                Err(failure(FailureKind::Timeout, "the WireGuard peer stopped answering"))
            }
            TunnResult::Err(e) => {
                debug!("WireGuard timers: {e:?}");
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn established(&self) -> bool {
        self.tunn.time_since_last_handshake().is_some()
    }

    /// Sends handshake initiations until the peer answers one.
    async fn handshake(&mut self) -> anyhow::Result<()> {
        for attempt in 1..=HANDSHAKE_ATTEMPTS {
            match self.tunn.format_handshake_initiation(&mut self.send, true) {
                TunnResult::WriteToNetwork(datagram) => {
                    let datagram = datagram.to_vec();
                    self.send_datagram(&datagram).await?;
                }
                TunnResult::Err(e) => bail!("cannot start the WireGuard handshake: {e:?}"),
                _ => {}
            }
            debug!(attempt, "WireGuard handshake initiation sent");
            let deadline = tokio::time::Instant::now() + HANDSHAKE_WAIT;
            let mut buffer = vec![0; BUFFER];
            while let Ok(received) = tokio::time::timeout_at(deadline, self.socket.recv(&mut buffer)).await {
                let len = received.kind(FailureKind::Unreachable).context("WireGuard socket")?;
                // Nothing goes to the tun interface before it exists.
                let _ = self.received(&buffer[..len]).await?;
                if self.established() {
                    return Ok(());
                }
            }
        }
        Err(failure(
            FailureKind::Timeout,
            "the WireGuard server did not answer: check its address and port, the keys, and that this \
             device's public key is declared on the server",
        ))
    }
}

impl WireGuardEngine {
    async fn key(ctx: &SessionContext, key: &str, text: String) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let answer = Zeroizing::new(ctx.prompter.ask(Prompt::new(key, PromptKind::Secret, text)).await?);
        parse_key(&answer)
            .map(Zeroizing::new)
            .with_context(|| format!("the {} must be 32 bytes in base64", key.replace('_', " ")))
            .kind(FailureKind::AuthFailed)
    }

    async fn resolve(&self) -> anyhow::Result<SocketAddr> {
        let p = &self.profile;
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((p.endpoint.as_str(), p.port))
            .await
            .kind(FailureKind::Unreachable)
            .with_context(|| format!("cannot resolve {}", p.endpoint))?
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .copied()
            .with_context(|| format!("{} has no address", p.endpoint))
            .kind(FailureKind::Unreachable)
    }

    fn settings(&self, gateway: IpAddr) -> anyhow::Result<TunnelSettings> {
        let p = &self.profile;
        let full_tunnel = p.full_tunnel();
        Ok(TunnelSettings {
            address: p.addresses.first().context("the profile has no address")?.addr(),
            mtu: p.mtu.unwrap_or(WIREGUARD_MTU),
            routes: if full_tunnel { Vec::new() } else { p.allowed_ips.clone() },
            excluded_routes: Vec::new(),
            full_tunnel,
            dns: DnsSettings {
                servers: p.dns_servers.clone(),
                search_domains: p.dns_search.clone(),
                // A full tunnel resolves everything through its servers; a
                // split one, its search domains.
                match_domains: if full_tunnel || p.dns_servers.is_empty() { Vec::new() } else { p.dns_search.clone() },
            },
            gateway,
        })
    }
}

#[async_trait]
impl Engine for WireGuardEngine {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
        self.profile.validate()?;
        let private = Self::key(ctx, "private_key", format!("Private key of {}", ctx.name)).await?;
        let secret = StaticSecret::from(*private);
        if let Some(expected) = &self.profile.local_public_key {
            let public = PublicKey::from(&secret);
            if parse_key(expected).is_none_or(|key| key != *public.as_bytes()) {
                return Err(failure(
                    FailureKind::AuthFailed,
                    "this private key does not go with the profile's public key",
                ));
            }
        }
        let psk = match self.profile.preshared_key {
            true => Some(Self::key(ctx, "psk", format!("Pre-shared key of {}", ctx.name)).await?),
            false => None,
        };
        let peer = PublicKey::from(parse_key(&self.profile.public_key).context("invalid peer public key")?);

        let addr = self.resolve().await?;
        info!(server = %addr, "connecting to the WireGuard peer");
        let local: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
        let socket = UdpSocket::bind(local).await.context("cannot open a UDP socket")?;
        socket.connect(addr).await.kind(FailureKind::Unreachable).with_context(|| format!("cannot reach {addr}"))?;
        // boringtun shifts the index by 8 bits: 24 random bits.
        let index = rand::random::<u32>() & 0x00ff_ffff;
        let tunn = Tunn::new(secret, peer, psk.map(|k| *k), self.profile.persistent_keepalive, index, None);
        let allowed = Allowed {
            networks: if self.profile.full_tunnel() {
                vec![Ipv4Net::default()]
            } else {
                self.profile.allowed_ips.clone()
            },
            local: self.profile.addresses.iter().map(Ipv4Net::addr).collect(),
        };
        let mut session = Session { socket, peer: addr.ip(), tunn, allowed, send: vec![0; BUFFER] };
        session.handshake().await?;
        info!("WireGuard handshake done");
        let settings = self.settings(addr.ip())?;
        self.session = Some(session);
        Ok(settings)
    }

    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let session = self.session.as_mut().context("the WireGuard engine is not connected")?;
        let PacketIo { to_tun, mut from_tun } = io;
        let mut tick = tokio::time::interval(TICK);
        let mut receive = vec![0; BUFFER];
        loop {
            tokio::select! {
                received = session.socket.recv(&mut receive) => match received {
                    Ok(len) => {
                        for packet in session.received(&receive[..len]).await? {
                            ctx.stats.record_rx(packet.len());
                            if to_tun.send(packet).await.is_err() {
                                bail!("tun interface closed");
                            }
                        }
                    }
                    Err(e) if vpn_core::net::transient(&e) => debug!("transient UDP error: {e}"),
                    Err(e) => return Err(e).kind(FailureKind::Unreachable).context("WireGuard socket"),
                },
                packet = from_tun.recv() => match packet {
                    Some(packet) if packet.first().is_some_and(|b| b >> 4 == 4) => {
                        session.outgoing(&packet).await?;
                        ctx.stats.record_tx(packet.len());
                    }
                    Some(_) => {}
                    None => return Ok(()),
                },
                _ = tick.tick() => session.tick().await?,
                _ = ctx.cancel.cancelled() => return Ok(()),
            }
        }
    }

    /// WireGuard has no logout: the peer forgets the session by itself.
    async fn disconnect(&mut self) -> anyhow::Result<()> {
        self.session = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_sources() {
        let allowed = Allowed {
            networks: vec!["10.7.0.0/24".parse().unwrap(), "192.168.5.0/24".parse().unwrap()],
            local: vec![Ipv4Addr::new(10, 7, 0, 2)],
        };
        assert!(allowed.contains(Ipv4Addr::new(10, 7, 0, 1)));
        assert!(allowed.contains(Ipv4Addr::new(192, 168, 5, 200)));
        assert!(!allowed.contains(Ipv4Addr::new(10, 8, 0, 1)));
        let to = |dst: [u8; 4]| [&[0x45, 0, 0, 20][..], &[0; 12], &dst].concat();
        assert!(allowed.accepts(&to([10, 7, 0, 2]), Ipv4Addr::new(10, 7, 0, 1)));
        assert!(!allowed.accepts(&to([10, 7, 0, 3]), Ipv4Addr::new(10, 7, 0, 1)), "not to us");
        assert!(!allowed.accepts(&to([10, 7, 0, 2]), Ipv4Addr::new(10, 8, 0, 1)), "not from the peer's networks");
    }

    fn engine(allowed: &str, dns: &str) -> WireGuardEngine {
        let profile: vpn_core::Profile = toml::from_str(&format!(
            "name = \"wg\"\nprotocol = \"wireguard\"\nendpoint = \"vpn.example.com\"\n\
             public_key = \"YpdTsMtb/QCdYKzHlzKkLcLzEbdTK0vP4ILmdcIvnhc=\"\n\
             addresses = [\"10.7.0.2/32\"]\nallowed_ips = [{allowed}]\n{dns}"
        ))
        .unwrap();
        let vpn_core::ProtocolConfig::WireGuard(p) = profile.protocol else { unreachable!() };
        WireGuardEngine::new(p)
    }

    struct NoPrompter;

    #[async_trait]
    impl vpn_core::Prompter for NoPrompter {
        async fn ask(&self, _prompt: Prompt) -> anyhow::Result<zeroize::Zeroizing<String>> {
            // The test answers, erased like real ones.
            let answer: anyhow::Result<String> = async { bail!("no prompt in this test") }.await;
            answer.map(zeroize::Zeroizing::new)
        }

        async fn open_url(&self, _url: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Answers handshakes and keepalives as the WireGuard server would.
    async fn serve(socket: UdpSocket, mut tunn: Tunn) {
        let (mut buffer, mut out) = (vec![0; BUFFER], vec![0; BUFFER]);
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            let mut result = tunn.decapsulate(Some(from.ip()), &buffer[..len], &mut out);
            while let TunnResult::WriteToNetwork(reply) = result {
                let _ = socket.send_to(reply, from).await;
                result = tunn.decapsulate(None, &[], &mut out);
            }
        }
    }

    /// The server restarts: its port answers ICMP port unreachable for a
    /// while. The tunnel stays up, as with wg-quick.
    #[tokio::test]
    async fn icmp_errors_do_not_end_the_tunnel() {
        let (ours, theirs) = (StaticSecret::from([1; 32]), StaticSecret::from([2; 32]));
        let server_tunn = Tunn::new(theirs.clone(), PublicKey::from(&ours), None, None, 2, None);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let serving = tokio::spawn(serve(server, server_tunn));

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        let allowed = Allowed { networks: vec![Ipv4Net::default()], local: vec![Ipv4Addr::new(10, 7, 0, 2)] };
        let tunn = Tunn::new(ours, PublicKey::from(&theirs), None, None, 1, None);
        let mut session = Session { socket, peer: addr.ip(), tunn, allowed, send: vec![0; BUFFER] };
        session.handshake().await.unwrap();
        serving.abort();
        let _ = serving.await; // the port is closed from now on

        let mut engine = engine("\"0.0.0.0/0\"", "");
        engine.session = Some(session);
        let ctx = SessionContext {
            name: "wg".into(),
            prompter: std::sync::Arc::new(NoPrompter),
            cancel: tokio_util::sync::CancellationToken::new(),
            stats: Default::default(),
        };
        let (to_tun, _tun_rx) = tokio::sync::mpsc::channel(8);
        let (tun_tx, from_tun) = tokio::sync::mpsc::channel(8);
        let run_ctx = ctx.clone();
        let run = tokio::spawn(async move { engine.run(&run_ctx, PacketIo { to_tun, from_tun }).await });
        let packet = [&[0x45, 0, 0, 20][..], &[0; 8], &[10, 7, 0, 2], &[10, 7, 0, 1]].concat();
        for _ in 0..3 {
            tun_tx.send(Bytes::from(packet.clone())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!run.is_finished(), "{:?}", run.await.unwrap());
        ctx.cancel.cancel();
        run.await.unwrap().unwrap();
        assert_eq!(ctx.stats.tx_packets.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[test]
    fn split_and_full_tunnels() {
        let gateway: IpAddr = "203.0.113.1".parse().unwrap();
        let split = engine("\"10.7.0.0/24\"", "dns_servers = [\"10.7.0.1\"]\ndns_search = [\"corp.example\"]")
            .settings(gateway)
            .unwrap();
        assert!(!split.full_tunnel);
        assert_eq!(split.routes, vec!["10.7.0.0/24".parse::<Ipv4Net>().unwrap()]);
        assert_eq!(split.dns.match_domains, vec!["corp.example".to_string()]);
        assert_eq!((split.address, split.mtu), (Ipv4Addr::new(10, 7, 0, 2), WIREGUARD_MTU));

        let full = engine("\"0.0.0.0/0\"", "dns_servers = [\"10.7.0.1\"]").settings(gateway).unwrap();
        assert!(full.full_tunnel && full.routes.is_empty() && full.dns.match_domains.is_empty());
    }
}
