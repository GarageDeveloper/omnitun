//! One connection to a server: the control channel until the server has
//! pushed its options, then the data channel, keepalives and key
//! renegotiation.

use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use tokio::time::sleep_until;
use tracing::{debug, info, warn};
use vpn_core::{Compression, FailureKind, PacketIo, SessionContext, failure};

use crate::control::{BadPacket, Control, Event, HAND_WINDOW};
use crate::crypto::DataCipher;
use crate::link::Link;
use crate::options::Pushed;
use crate::wire;

/// Data channel keepalive payload.
const PING: [u8; 16] = [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];
/// Prefix of option-consistency messages; followed by `OCC_EXIT` when the
/// peer leaves.
const OCC: [u8; 16] = [0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c];
const OCC_EXIT: u8 = 6;

/// A UDP server that never answers is given up after this long, to try
/// the next one.
pub const FIRST_ANSWER: Duration = Duration::from_secs(10);
const PUSH_REQUEST_EVERY: Duration = Duration::from_secs(5);
/// Lifetime of the previous key after a renegotiation (`transition-window`).
const TRANSITION: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(500);
const DEFAULT_PING: u32 = 10;
const DEFAULT_PING_RESTART: u32 = 120;
const MAX_AUTH_PENDING: u64 = 600;

/// Why establishing failed in a way the caller acts on.
#[derive(Debug)]
pub enum Refused {
    /// `AUTH_FAILED`, with its text.
    AuthFailed(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::AuthFailed(text) => write!(f, "{text}"),
        }
    }
}

impl std::error::Error for Refused {}

pub struct Session {
    link: Link,
    pub control: Control,
    cipher: DataCipher,
    ekm: bool,
    compression: Compression,
    peer_id: Option<u32>,
    ping: Duration,
    ping_restart: Duration,
    reneg: Option<Duration>,
    last_received: Instant,
    last_sent: Instant,
    warned_compressed: bool,
}

async fn flush(link: &mut Link, control: &mut Control) -> anyhow::Result<()> {
    for packet in control.outgoing(Instant::now())? {
        link.send(&packet).await?;
    }
    Ok(())
}

/// Runs the control channel until the server's options are all in.
pub async fn establish(link: &mut Link, control: &mut Control, ctx: &SessionContext) -> anyhow::Result<Pushed> {
    let started = Instant::now();
    let mut deadline = started + HAND_WINDOW;
    let mut push_request: Option<Instant> = None;
    let mut pushed = Pushed::default();
    let mut refused_packet: Option<String> = None;
    loop {
        flush(link, control).await?;
        let now = Instant::now();
        if control.remote_sid.is_none() && !link.tcp && now >= started + FIRST_ANSWER {
            return Err(match refused_packet {
                Some(why) => failure(
                    FailureKind::Other,
                    format!("the server's answers fail the control channel check ({why}): check tls-auth or tls-crypt"),
                ),
                None => failure(
                    FailureKind::Unreachable,
                    "no answer from the OpenVPN server: check its address, port and protocol, and the tls-auth or tls-crypt key",
                ),
            });
        }
        if now >= deadline {
            return Err(failure(FailureKind::Timeout, "the OpenVPN server did not finish the negotiation in time"));
        }
        if push_request.is_some_and(|at| at <= now) {
            control.send_message(0, "PUSH_REQUEST")?;
            push_request = Some(now + PUSH_REQUEST_EVERY);
            continue;
        }
        let mut wake = (now + TICK).min(deadline);
        if let Some(due) = control.next_due() {
            wake = wake.min(due);
        }
        let packet = tokio::select! {
            packet = link.received.recv() => packet.context("the connection to the server closed")?,
            _ = sleep_until(wake.into()) => continue,
            _ = ctx.cancel.cancelled() => return Err(failure(FailureKind::Cancelled, "cancelled")),
        };
        let packet = match packet {
            Ok(packet) if !packet.is_empty() => packet,
            Ok(_) => continue,
            Err(e) if !link.tcp => {
                debug!("UDP: {e:#}");
                continue;
            }
            Err(e) => return Err(e.context("the server closed the connection").kind_unreachable()),
        };
        if matches!(wire::opcode(packet[0]), wire::DATA_V1 | wire::DATA_V2) {
            continue;
        }
        let events = match control.receive(&packet) {
            Ok(events) => events,
            Err(e) if e.is::<BadPacket>() => {
                // May come from anyone: ignored, but remembered in case
                // the server only sends those (wrong tls-auth key).
                debug!("ignoring control packet: {e:#}");
                refused_packet = Some(format!("{e:#}"));
                if link.tcp && control.remote_sid.is_none() {
                    return Err(failure(
                        FailureKind::Other,
                        format!(
                            "the server's answer fails the control channel check ({e:#}): check tls-auth or tls-crypt"
                        ),
                    ));
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        for event in events {
            match event {
                Event::KeyExchanged(_) => push_request = Some(Instant::now()),
                Event::Message(text) => {
                    if text.starts_with("PUSH_REPLY") {
                        if !pushed.add(&text)? {
                            return Ok(pushed);
                        }
                        push_request = None;
                    } else if let Some(reason) = text.strip_prefix("AUTH_FAILED") {
                        return Err(Refused::AuthFailed(reason.trim_start_matches(',').to_owned()).into());
                    } else if let Some(rest) = text.strip_prefix("AUTH_PENDING") {
                        let timeout = rest
                            .split(',')
                            .find_map(|kw| kw.trim().strip_prefix("timeout "))
                            .and_then(|t| t.trim().parse().ok())
                            .unwrap_or(120u64)
                            .min(MAX_AUTH_PENDING);
                        info!("the server waits for an authentication outside the VPN ({timeout} s)");
                        // Repeated, it never extends the wait past one
                        // maximum from the start.
                        deadline = (Instant::now() + Duration::from_secs(timeout))
                            .min(started + HAND_WINDOW + Duration::from_secs(MAX_AUTH_PENDING));
                        push_request = None;
                    } else if text.starts_with("INFO_PRE,WEB_AUTH") || text.starts_with("INFO_PRE,OPEN_URL") {
                        bail!("the server asks for a web sign-in, which this client does not support yet");
                    } else if text.starts_with("INFO_PRE,CR_TEXT") {
                        bail!("the server asks a challenge (CR_TEXT), which this client does not support yet");
                    } else {
                        stop_message(&text)?;
                        debug!("control message: {}", redacted(&text));
                    }
                }
            }
        }
    }
}

/// `RESTART`, `HALT` and `EXIT` end the session.
fn stop_message(text: &str) -> anyhow::Result<()> {
    let word = text.split([',', ':']).next().unwrap_or_default();
    if matches!(word, "RESTART" | "HALT" | "EXIT") {
        let reason = text.split_once([',', ':']).map(|(_, r)| r.trim()).unwrap_or_default();
        bail!("the server ended the session ({word}{}{reason})", if reason.is_empty() { "" } else { ": " });
    }
    Ok(())
}

trait KindUnreachable {
    fn kind_unreachable(self) -> anyhow::Error;
}

impl KindUnreachable for anyhow::Error {
    fn kind_unreachable(self) -> anyhow::Error {
        let message = format!("{self:#}");
        failure(FailureKind::Unreachable, message)
    }
}

impl Session {
    pub fn new(
        link: Link,
        mut control: Control,
        pushed: &Pushed,
        profile: &vpn_core::OpenVpnProfile,
    ) -> anyhow::Result<Self> {
        let cipher = match (&pushed.cipher, &pushed.unsupported_cipher) {
            (Some(cipher), _) => *cipher,
            (None, Some(other)) => bail!("the server chose the {other} cipher, which this client does not support"),
            // A server without cipher negotiation uses its configured one,
            // which the profile names.
            (None, None) => profile
                .data_ciphers
                .first()
                .and_then(|c| DataCipher::parse(c))
                .context("no data cipher in the profile")?,
        };
        let sessions = control.sessions();
        let key = control.key(0).context("no key state")?;
        key.derive(cipher, pushed.ekm, (&sessions.0, &sessions.1))?;
        if let Some(token) = &pushed.auth_token {
            use_auth_token(&mut control, token, pushed.auth_token_user.as_deref());
        }
        let now = Instant::now();
        let secs = |s: u32| Duration::from_secs(u64::from(s.max(1)));
        info!(cipher = cipher.name(), ekm = pushed.ekm, peer_id = ?pushed.peer_id, "OpenVPN data channel ready");
        Ok(Self {
            link,
            control,
            cipher,
            ekm: pushed.ekm,
            compression: pushed.compression.unwrap_or(profile.compression),
            peer_id: pushed.peer_id,
            ping: secs(pushed.ping.unwrap_or(DEFAULT_PING)),
            ping_restart: secs(pushed.ping_restart.unwrap_or(DEFAULT_PING_RESTART)),
            reneg: (profile.reneg_sec > 0).then(|| Duration::from_secs(profile.reneg_sec.into())),
            last_received: now,
            last_sent: now,
            warned_compressed: false,
        })
    }

    /// Carries packets until cancelled or the server goes away.
    pub async fn run(&mut self, ctx: &SessionContext, mut io: PacketIo) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                packet = self.link.received.recv() => {
                    let packet = packet.context("the connection to the server closed")?;
                    match packet {
                        Ok(packet) if !packet.is_empty() => self.received(&packet, ctx, &io).await?,
                        Ok(_) => {}
                        Err(e) if !self.link.tcp => debug!("UDP: {e:#}"),
                        Err(e) => return Err(e.kind_unreachable()),
                    }
                }
                packet = io.from_tun.recv() => {
                    let Some(packet) = packet else { return Ok(()) };
                    self.send_data(&packet, ctx).await?;
                }
                _ = tick.tick() => self.timers().await?,
                _ = ctx.cancel.cancelled() => {
                    self.exit_notify().await;
                    return Ok(());
                }
            }
            flush(&mut self.link, &mut self.control).await?;
        }
    }

    async fn received(&mut self, packet: &[u8], ctx: &SessionContext, io: &PacketIo) -> anyhow::Result<()> {
        let (opcode, key_id) = (wire::opcode(packet[0]), wire::key_id(packet[0]));
        if !matches!(opcode, wire::DATA_V1 | wire::DATA_V2) {
            let events = match self.control.receive(packet) {
                Ok(events) => events,
                Err(e) if e.is::<BadPacket>() => {
                    debug!("ignoring control packet: {e:#}");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            for event in events {
                match event {
                    Event::KeyExchanged(id) => self.key_ready(id)?,
                    Event::Message(text) => {
                        if let Some(reason) = text.strip_prefix("AUTH_FAILED") {
                            return Err(failure(
                                FailureKind::AuthFailed,
                                format!("the server refused the renewed authentication{reason}"),
                            ));
                        }
                        stop_message(&text)?;
                        debug!("control message: {}", redacted(&text));
                    }
                }
            }
            self.last_received = Instant::now();
            return Ok(());
        }
        let header_len = if opcode == wire::DATA_V2 { 4 } else { 1 };
        if packet.len() < header_len {
            return Ok(());
        }
        let Some(keys) = self.control.key(key_id).and_then(|k| k.data.as_mut()) else {
            debug!(key_id, "data packet for a key without keys dropped");
            return Ok(());
        };
        let plain = match keys.open(&packet[..header_len], &packet[header_len..]) {
            Ok(plain) => plain,
            Err(e) => {
                debug!("data packet dropped: {e:#}");
                return Ok(());
            }
        };
        self.last_received = Instant::now();
        if plain == PING {
            return Ok(());
        }
        if plain.len() > OCC.len() && plain[..OCC.len()] == OCC {
            if plain[OCC.len()] == OCC_EXIT {
                bail!("the server ended the session");
            }
            return Ok(());
        }
        let Some(ip) = self.decompress(plain) else { return Ok(()) };
        if ip.is_empty() {
            return Ok(());
        }
        ctx.stats.record_rx(ip.len());
        io.to_tun.send(Bytes::from(ip)).await.context("the tunnel interface is gone")?;
        Ok(())
    }

    /// Removes the compression framing; `None` drops the packet.
    fn decompress(&mut self, mut plain: Vec<u8>) -> Option<Vec<u8>> {
        match self.compression {
            Compression::None => Some(plain),
            Compression::Lzo => match plain.first() {
                Some(0xfa) => Some(plain.split_off(1)),
                _ => self.compressed(),
            },
            Compression::Stub => match plain.first() {
                Some(0xfb) if plain.len() > 1 => {
                    let last = plain.pop().unwrap();
                    plain[0] = last;
                    Some(plain)
                }
                _ => self.compressed(),
            },
            Compression::StubV2 => match plain.first() {
                Some(0x50) if plain.get(1) == Some(&0) => Some(plain.split_off(2)),
                Some(0x50) => self.compressed(),
                _ => Some(plain),
            },
        }
    }

    fn compressed(&mut self) -> Option<Vec<u8>> {
        if !self.warned_compressed {
            warn!("the server sends compressed packets, which this client refuses (VORACLE): dropped");
            self.warned_compressed = true;
        }
        None
    }

    fn frame(&self, packet: &[u8]) -> Vec<u8> {
        match self.compression {
            Compression::None => packet.to_vec(),
            Compression::Lzo => [&[0xfa], packet].concat(),
            Compression::Stub => match packet.split_first() {
                Some((first, rest)) => [&[0xfb], rest, &[*first]].concat(),
                None => Vec::new(),
            },
            Compression::StubV2 if packet.first() == Some(&0x50) => [&[0x50, 0], packet].concat(),
            Compression::StubV2 => packet.to_vec(),
        }
    }

    async fn send_data(&mut self, ip: &[u8], ctx: &SessionContext) -> anyhow::Result<()> {
        let payload = self.frame(ip);
        if self.seal_and_send(&payload).await? {
            ctx.stats.record_tx(ip.len());
        }
        Ok(())
    }

    /// Returns whether a key could send it.
    async fn seal_and_send(&mut self, payload: &[u8]) -> anyhow::Result<bool> {
        let peer_id = self.peer_id;
        let Some(key) = self.control.primary() else { return Ok(false) };
        let header: Vec<u8> = match peer_id {
            Some(id) => (u32::from(wire::header_byte(wire::DATA_V2, key.key_id)) << 24 | id).to_be_bytes().to_vec(),
            None => vec![wire::header_byte(wire::DATA_V1, key.key_id)],
        };
        let packet = key.data.as_mut().unwrap().seal(&header, payload)?;
        self.link.send(&packet).await?;
        self.last_sent = Instant::now();
        Ok(true)
    }

    async fn timers(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        if now.duration_since(self.last_received) >= self.ping_restart {
            return Err(failure(FailureKind::Unreachable, "the OpenVPN server stopped answering"));
        }
        if now.duration_since(self.last_sent) >= self.ping {
            self.seal_and_send(&PING).await?;
        }
        // A negotiation that does not finish ends the session.
        if self.control.keys.iter().any(|k| !k.negotiated() && now.duration_since(k.started) >= HAND_WINDOW) {
            bail!("the key renegotiation with the server did not finish in time");
        }
        self.control.keys.retain(|k| k.retire_at.is_none_or(|t| t > now));
        let negotiating = self.control.keys.iter().any(|k| k.data.is_none());
        let worn = self.control.primary().is_some_and(|k| k.data.as_ref().is_some_and(|d| d.worn_out()));
        let due = match (self.reneg, self.control.primary()) {
            (Some(reneg), Some(key)) => now.duration_since(key.started) >= reneg,
            _ => false,
        };
        if !negotiating && (due || worn) {
            let key_id = self.control.renegotiate()?;
            info!(key_id, "renegotiating the data channel keys");
        }
        Ok(())
    }

    /// A renegotiated key is in: it carries data from now on, the previous
    /// one only decrypts for a while.
    fn key_ready(&mut self, key_id: u8) -> anyhow::Result<()> {
        let sessions = self.control.sessions();
        let (cipher, ekm) = (self.cipher, self.ekm);
        let key = self.control.key(key_id).context("no such key state")?;
        key.derive(cipher, ekm, (&sessions.0, &sessions.1))?;
        let now = Instant::now();
        for other in &mut self.control.keys {
            if other.key_id != key_id && other.data.is_some() && other.retire_at.is_none() {
                other.retire_at = Some(now + TRANSITION);
            }
        }
        info!(key_id, "new data channel keys in use");
        Ok(())
    }

    /// Tells a UDP server we leave (`explicit-exit-notify`).
    async fn exit_notify(&mut self) {
        if self.link.tcp {
            return;
        }
        let message = [OCC.as_slice(), &[OCC_EXIT]].concat();
        if let Err(e) = self.seal_and_send(&message).await {
            debug!("exit notification: {e:#}");
        }
    }
}

/// The server's `auth-token` replaces the password in renegotiations.
pub fn use_auth_token(control: &mut Control, token: &str, user: Option<&str>) {
    control.hello.password = zeroize::Zeroizing::new(token.to_owned());
    if let Some(user) = user.and_then(|u| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(u).ok()
    }) {
        control.hello.username = String::from_utf8_lossy(&user).into_owned();
    }
}

/// A control message for the log: the session token is a credential.
fn redacted(text: &str) -> String {
    text.split(',')
        .map(|item| if item.trim_start().starts_with("auth-token") { "auth-token <hidden>" } else { item })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_messages() {
        assert!(stop_message("RESTART,server restarting").is_err());
        assert!(stop_message("HALT").is_err());
        assert!(stop_message("INFO,hello").is_ok());
    }
}
