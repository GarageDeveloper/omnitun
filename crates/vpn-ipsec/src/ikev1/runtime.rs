//! Data path and ISAKMP housekeeping once the IKEv1 tunnel is up: ESP,
//! NAT-T keepalives, RFC 3706 dead peer detection, Quick Mode rekeying,
//! the gateway's Informational exchanges and its re-authentications.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::bail;
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use vpn_core::{PacketIo, SessionContext};

use super::consts::{exchange, notify, protocol};
use super::handshake::{QuickInit, QuickResponse};
use super::isakmp::IsakmpSa;
use super::payload::Payload;
use super::responder::{MainResponder, Reauth};
use super::{Established, Incoming, Info, Phase2, QuickParams, classify_informational, dpd_notify, send_informational};
use crate::esp::{EspSa, NEXT_HEADER_IPV4, NEXT_HEADER_NONE, NEXT_HEADER_UDP};
use crate::ikev2::check_inner;
use crate::ikev2::payload::TrafficSelector;
use crate::transport::{Datagram, Transport};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const DPD_IDLE: Duration = Duration::from_secs(30);
const DPD_RETRY: Duration = Duration::from_secs(5);
const DPD_MAX_TRIES: u32 = 5;
const REKEY_RETRY: Duration = Duration::from_secs(60);
/// A replaced IPsec SA keeps accepting packets until its own end, as the
/// macOS client does (some gateways keep sending on it until then), and
/// for at least this long.
const OLD_SA_GRACE: Duration = Duration::from_secs(30);
/// Replaced SAs kept at most (a gateway rekeying in a loop).
const MAX_OLD_SAS: usize = 4;
/// Unknown SPIs reported in the log, per session.
const MAX_UNKNOWN_LOGGED: usize = 8;
const MAX_TRIES: u32 = 5;
/// After the gateway re-authenticated, how long it may take to renew the
/// IPsec SA itself before we do.
const REAUTH_CHILD_WAIT: Duration = Duration::from_secs(10);

struct PendingQuick {
    init: QuickInit,
    sent: Instant,
    wait: Duration,
    tries: u32,
}

struct Dpd {
    seq: u32,
    sent: Instant,
    tries: u32,
}

#[derive(Default)]
struct Trace {
    rekeys: u32,
    /// The last rekey, until the gateway's first packet on the new SA.
    awaiting_new: Option<Instant>,
    /// Packets received on replaced SAs since the last rekey.
    on_old: u64,
    unknown: u64,
    unknown_logged: Vec<u32>,
    undecryptable: u64,
    /// The last ESP packet from the gateway (`last_rx` counts IKE too).
    last_esp: Option<Instant>,
    /// Dead peer detection probes from the gateway.
    probes: u64,
}

struct Runner<'a> {
    transport: &'a Transport,
    sa: &'a mut IsakmpSa,
    child: &'a mut Phase2,
    quick: &'a QuickParams,
    remote_ts: &'a mut Vec<TrafficSelector>,
    closed: &'a mut bool,
    dpd_enabled: bool,
    phase1_expiry: Instant,
    reauth: Option<&'a Reauth>,
    /// A new phase 1 the gateway started, in progress.
    responder: Option<MainResponder>,
    /// The gateway's main mode message 5 and our message 6, sent again if
    /// it repeats it.
    last_mm6: Option<(Vec<u8>, Vec<u8>)>,
    /// The ISAKMP SA replaced by the gateway's re-authentication, until
    /// the gateway deletes it.
    previous: Option<IsakmpSa>,
    /// When the gateway last re-authenticated, until the IPsec SA is
    /// renewed.
    reauthed: Option<Instant>,
    ctx: &'a SessionContext,
    to_tun: &'a mpsc::Sender<Bytes>,
    assigned: Ipv4Addr,
    dropped: u64,
    pending: Option<PendingQuick>,
    /// A Quick Mode the gateway started, answered, awaiting its HASH(3).
    responding: Option<QuickResponse>,
    /// The gateway's last HASH(2) and our HASH(3), resent if the gateway
    /// retransmits HASH(2) (that exchange is closed, `open` refuses it).
    last_qm3: Option<(Vec<u8>, Vec<u8>)>,
    old: Vec<(Phase2, Instant)>,
    /// What the log tells about rekeys and the packets that missed every
    /// SA, to explain a tunnel that goes silent.
    trace: Trace,
    dpd: Option<Dpd>,
    dpd_seq: u32,
    last_rx: Instant,
    last_tx: Instant,
    next_rekey_attempt: Instant,
}

/// The state of the data path when the session ends, whatever ends it (the
/// layer above may drop this future when L2TP or PPP gives up).
impl Drop for Runner<'_> {
    fn drop(&mut self) {
        let now = Instant::now();
        info!(
            last_from_gateway_s = now.duration_since(self.last_rx).as_secs(),
            last_esp_from_gateway_s = self.trace.last_esp.map(|t| now.duration_since(t).as_secs()),
            gateway_probes = self.trace.probes,
            last_to_gateway_s = now.duration_since(self.last_tx).as_secs(),
            sa_age_s = now.duration_since(self.child.created).as_secs(),
            inbound = format_args!("{:08x}", self.child.inbound.spi),
            inbound_bytes = self.child.inbound.bytes(),
            outbound_bytes = self.child.outbound.bytes(),
            rekeys = self.trace.rekeys,
            gateway_on_new_sa = self.trace.rekeys > 0 && self.trace.awaiting_new.is_none(),
            on_replaced_sa = self.trace.on_old,
            unknown_spi = self.trace.unknown,
            undecryptable = self.trace.undecryptable,
            dropped = self.dropped,
            "IPsec data path at the end of the session"
        );
    }
}

impl Established {
    pub(crate) async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let PacketIo { to_tun, mut from_tun } = io;
        let transport = &self.transport;
        let now = Instant::now();
        let mut runner = Runner {
            transport,
            sa: &mut self.sa,
            child: &mut self.child,
            quick: &self.quick,
            remote_ts: &mut self.remote_ts,
            closed: &mut self.closed,
            dpd_enabled: self.dpd,
            phase1_expiry: self.phase1_expiry,
            reauth: self.reauth.as_ref(),
            responder: None,
            last_mm6: None,
            previous: None,
            reauthed: None,
            ctx,
            to_tun: &to_tun,
            assigned: self.settings.address,
            dropped: 0,
            pending: None,
            responding: None,
            last_qm3: None,
            old: Vec::new(),
            trace: Trace::default(),
            dpd: None,
            dpd_seq: u32::from_be_bytes(crate::crypto::random_bytes(4).try_into().unwrap()) >> 1,
            last_rx: now,
            last_tx: now,
            next_rekey_attempt: now,
        };
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => return Ok(()),
                packet = from_tun.recv() => match packet {
                    Some(packet) => runner.on_tun_packet(&packet).await?,
                    None => return Ok(()),
                },
                datagram = transport.recv() => match datagram? {
                    Datagram::Esp(packet) => runner.on_esp(&packet).await?,
                    Datagram::Ike(raw) => runner.on_ike(raw).await?,
                    Datagram::Keepalive => {}
                },
                _ = tick.tick() => runner.on_tick().await?,
            }
        }
    }

    /// Deletes the IPsec SA and the ISAKMP SA, best effort (IKEv1
    /// Informationals are not acknowledged).
    pub(crate) async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let esp = Payload::Delete {
            protocol: protocol::ESP,
            spi_size: 4,
            spis: vec![self.child.inbound.spi.to_be_bytes().to_vec()],
        };
        let isakmp = Payload::Delete {
            protocol: protocol::ISAKMP,
            spi_size: 16,
            spis: vec![[self.sa.cky_i.to_be_bytes(), self.sa.cky_r.to_be_bytes()].concat()],
        };
        for delete in [esp, isakmp] {
            if let Err(e) = send_informational(&self.transport, &mut self.sa, delete).await {
                debug!("delete not sent: {e:#}");
            }
        }
        info!("IKEv1 SAs deleted");
    }
}

impl Runner<'_> {
    async fn send_ike(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.last_tx = Instant::now();
        self.transport.send_ike(bytes).await
    }

    async fn on_tun_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        if packet.first().is_none_or(|b| b >> 4 != 4) {
            return Ok(()); // IPv4 only
        }
        let esp = match &self.quick.transport {
            None => self.child.outbound.encapsulate(packet, NEXT_HEADER_IPV4)?,
            // The layer above hands IPv4/UDP packets for the SA's port:
            // their UDP segment goes in ESP.
            Some(t) => match super::transport::outbound_segment(packet, t) {
                Some(segment) => self.child.outbound.encapsulate(segment, NEXT_HEADER_UDP)?,
                None => {
                    debug!("dropping a packet the transport mode SA does not cover");
                    return Ok(());
                }
            },
        };
        self.transport.send_esp(&esp).await?;
        self.last_tx = Instant::now();
        self.ctx.stats.record_tx(packet.len());
        Ok(())
    }

    async fn on_esp(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        let spi = u32::from_be_bytes(packet[..4].try_into().expect("datagram has at least 8 bytes"));
        let current = self.child.inbound.spi == spi;
        let sa: &mut EspSa = if current {
            &mut self.child.inbound
        } else if let Some((old, _)) = self.old.iter_mut().find(|(c, _)| c.inbound.spi == spi) {
            &mut old.inbound
        } else {
            self.trace.unknown += 1;
            if self.trace.unknown_logged.len() < MAX_UNKNOWN_LOGGED && !self.trace.unknown_logged.contains(&spi) {
                self.trace.unknown_logged.push(spi);
                info!("ESP for SPI {spi:08x}, none of our IPsec SAs: dropped");
            }
            return Ok(());
        };
        let (next_header, inner) = match sa.decapsulate(packet) {
            Ok(v) => v,
            Err(e) => {
                self.trace.undecryptable += 1;
                if self.trace.undecryptable == 1 {
                    info!("dropping an ESP packet that does not decrypt: {e:#}");
                } else {
                    debug!("dropping ESP packet: {e:#}");
                }
                return Ok(());
            }
        };
        self.alive();
        self.trace.last_esp = Some(Instant::now());
        if current {
            if let Some(at) = self.trace.awaiting_new.take() {
                info!(after_ms = at.elapsed().as_millis() as u64, "the gateway sends on the new IPsec SA");
            }
        } else {
            self.trace.on_old += 1;
            if self.trace.on_old == 1 {
                info!("the gateway still sends on the replaced IPsec SA {spi:08x}");
            }
        }
        if next_header == NEXT_HEADER_NONE {
            return Ok(());
        }
        if let Some(t) = &self.quick.transport {
            let Some(packet) =
                (next_header == NEXT_HEADER_UDP).then(|| super::transport::inbound_packet(&inner, t)).flatten()
            else {
                self.dropped += 1;
                debug!(next_header, "dropping a packet outside the transport mode SA");
                return Ok(());
            };
            self.ctx.stats.record_rx(packet.len());
            if self.to_tun.send(Bytes::from(packet)).await.is_err() {
                bail!("the layer above the IPsec SA is gone");
            }
            return Ok(());
        }
        if next_header != NEXT_HEADER_IPV4 {
            debug!(next_header, "dropping non-IPv4 inner packet");
            return Ok(());
        }
        if let Err(why) = check_inner(&inner, self.remote_ts, self.assigned) {
            self.dropped += 1;
            debug!(dropped = self.dropped, "dropping decrypted packet: {why}");
            return Ok(());
        }
        self.ctx.stats.record_rx(inner.len());
        if self.to_tun.send(Bytes::from(inner)).await.is_err() {
            bail!("tun interface closed");
        }
        Ok(())
    }

    /// Anything authentic from the gateway proves it is alive.
    fn alive(&mut self) {
        self.last_rx = Instant::now();
        self.dpd = None;
    }

    async fn on_ike(&mut self, raw: Vec<u8>) -> anyhow::Result<()> {
        if let Some((qm2, msg3)) = &self.last_qm3
            && *qm2 == raw
        {
            let msg3 = msg3.clone();
            return self.send_ike(&msg3).await;
        }
        // The gateway repeats its message 1: our answer was lost.
        if let Some(r) = &self.responding
            && r.request == raw
        {
            let answer = r.bytes.clone();
            return self.send_ike(&answer).await;
        }
        if raw.get(18) == Some(&exchange::IDENTITY_PROTECTION) {
            return self.on_main_mode(raw).await;
        }
        if self.previous.as_ref().is_some_and(|p| cookies(&raw) == Some((p.cky_i, p.cky_r))) {
            return self.on_previous(raw).await;
        }
        // Every IKE message after setup is rare and may explain a tunnel
        // that dies: logged, with why it is dropped.
        let header = describe_header(&raw, self.sa);
        let (msg, next_iv) = match self.sa.open(&raw) {
            Ok(v) => v,
            Err(e) => {
                info!("IKE from the gateway dropped ({header}): {e:#}");
                return Ok(());
            }
        };
        info!("IKE from the gateway: {header}: {}", describe_payloads(&msg));
        let inc = Incoming { raw, msg, next_iv };
        let msg_id = inc.msg.header.msg_id;
        match inc.msg.header.exchange {
            exchange::INFORMATIONAL => {
                if self.sa.verify(&inc.msg, &[]).is_err() {
                    info!("dropping an unauthenticated Informational");
                    return Ok(());
                }
                self.sa.forget(msg_id);
                for info in classify_informational(&inc.msg) {
                    self.on_info(info).await?;
                }
            }
            exchange::QUICK => {
                if let Some(p) = self.pending.take() {
                    if p.init.accepts(self.sa, &inc) {
                        self.alive();
                        return self.finish_rekey(p.init, inc).await;
                    }
                    self.pending = Some(p);
                }
                if let Some(r) = self.responding.take() {
                    if r.completes(self.sa, &inc.msg) {
                        self.alive();
                        let child = r.finish(self.sa);
                        self.replace_child(child, "IPsec SA rekeyed by the gateway");
                        return Ok(());
                    }
                    self.responding = Some(r);
                }
                if inc.msg.sa().is_some() {
                    match QuickResponse::answer(self.sa, inc, self.quick) {
                        Ok(r) => {
                            self.alive();
                            let answer = r.bytes.clone();
                            if let Some(previous) = self.responding.replace(r) {
                                self.sa.forget(previous.msg_id);
                            }
                            self.send_ike(&answer).await?;
                        }
                        Err(e) => warn!("refused the gateway's Quick Mode: {e:#}"),
                    }
                    return Ok(());
                }
                info!(msg_id, "ignoring a Quick Mode message that answers nothing of ours");
            }
            other => info!(exchange = other, "ignoring an ISAKMP exchange"),
        }
        Ok(())
    }

    async fn on_info(&mut self, info: Info) -> anyhow::Result<()> {
        match info {
            Info::RuThere(seq) => {
                self.trace.probes += 1;
                // A fresh, authenticated probe (replays and reflections are
                // refused by `open`): the gateway is alive.
                self.alive();
                let ack = dpd_notify(self.sa, notify::R_U_THERE_ACK, seq);
                send_informational(self.transport, self.sa, ack).await?;
                self.last_tx = Instant::now();
            }
            Info::RuThereAck(seq) => {
                if self.dpd.as_ref().is_some_and(|d| d.seq == seq) {
                    self.alive();
                }
            }
            Info::DeleteIsakmp => {
                *self.closed = true;
                bail!("the gateway deleted the IKE SA");
            }
            Info::DeleteEsp(spis) => {
                if spis.iter().any(|s| *s == self.child.outbound.spi || *s == self.child.inbound.spi) {
                    bail!("the gateway deleted the IPsec SA");
                }
                self.old.retain(|(c, _)| !spis.contains(&c.outbound.spi) && !spis.contains(&c.inbound.spi));
            }
            Info::Error(e) => {
                if let Some(p) = self.pending.take() {
                    warn!("phase 2 rekey refused: {e}");
                    self.sa.forget(p.init.msg_id);
                    self.next_rekey_attempt = Instant::now() + REKEY_RETRY;
                } else {
                    warn!("gateway reported {e}");
                }
            }
            Info::Other => {}
        }
        Ok(())
    }

    async fn finish_rekey(&mut self, init: QuickInit, inc: Incoming) -> anyhow::Result<()> {
        let qm2 = inc.raw.clone();
        let (child, remote_ts, msg3) = match init.finish(self.sa, inc) {
            Ok(v) => v,
            Err(e) => {
                warn!("phase 2 rekey failed: {e:#}");
                self.next_rekey_attempt = Instant::now() + REKEY_RETRY;
                return Ok(());
            }
        };
        self.send_ike(&msg3).await?;
        self.last_qm3 = Some((qm2, msg3));
        *self.remote_ts = remote_ts;
        self.replace_child(child, "IPsec SA rekeyed");
        Ok(())
    }

    /// Sends on `child` from now on; the replaced SA still accepts packets
    /// until its end.
    fn replace_child(&mut self, child: Phase2, what: &str) {
        let now = Instant::now();
        let old = std::mem::replace(self.child, child);
        let old_ends = old.created + old.lifetime;
        info!(
            inbound = format_args!("{:08x}", self.child.inbound.spi),
            outbound = format_args!("{:08x}", self.child.outbound.spi),
            lifetime_s = self.child.lifetime.as_secs(),
            lifetime_kb = self.child.lifetime_kb,
            replaced = format_args!("{:08x}", old.inbound.spi),
            replaced_ends_in_s = old_ends.saturating_duration_since(now).as_secs(),
            "{what}"
        );
        if self.old.len() >= MAX_OLD_SAS {
            self.old.remove(0);
        }
        self.old.push((old, now));
        self.trace.rekeys += 1;
        self.trace.awaiting_new = Some(now);
        self.trace.on_old = 0;
    }

    /// Starts a Quick Mode replacing the IPsec SA.
    async fn start_rekey(&mut self) -> anyhow::Result<()> {
        let init = QuickInit::start(self.sa, self.quick)?;
        let bytes = init.bytes.clone();
        self.pending = Some(PendingQuick { init, sent: Instant::now(), wait: Duration::from_secs(1), tries: 1 });
        self.send_ike(&bytes).await
    }

    /// A main mode message: the gateway re-authenticates with a new phase
    /// 1, which we answer as the responder.
    async fn on_main_mode(&mut self, raw: Vec<u8>) -> anyhow::Result<()> {
        let header = describe_header(&raw, self.sa);
        if let Some((mm5, mm6)) = &self.last_mm6
            && *mm5 == raw
        {
            let mm6 = mm6.clone();
            return self.send_ike(&mm6).await;
        }
        if let Some(r) = &self.responder
            && r.request == raw
        {
            let answer = r.answer.clone();
            return self.send_ike(&answer).await;
        }
        let Some(reauth) = self.reauth else {
            info!("IKE from the gateway dropped ({header}): a new phase 1 with XAuth is not supported once connected");
            return Ok(());
        };
        if cookies(&raw).is_some_and(|(_, r)| r == 0) {
            match MainResponder::start(reauth, &raw) {
                Ok(r) => {
                    info!(
                        algs = ?r.algs,
                        lifetime_s = r.life.as_secs(),
                        "the gateway starts a new phase 1 (re-authentication): answering it"
                    );
                    let answer = r.answer.clone();
                    self.responder = Some(r);
                    self.send_ike(&answer).await?;
                }
                Err(e) => warn!("refused the gateway's new phase 1: {e:#}"),
            }
            return Ok(());
        }
        let Some(r) = self.responder.as_mut().filter(|r| r.owns(&raw)) else {
            info!("IKE from the gateway dropped ({header}): no phase 1 of that SA in progress");
            return Ok(());
        };
        match r.next(reauth, &raw, self.transport) {
            Ok(None) => {
                let answer = r.answer.clone();
                self.send_ike(&answer).await
            }
            Ok(Some(sa)) => {
                let r = self.responder.take().expect("matched above");
                self.send_ike(&r.answer).await?;
                self.last_mm6 = Some((r.request, r.answer));
                self.adopt(sa, r.life);
                Ok(())
            }
            Err(e) => {
                info!("IKE from the gateway dropped ({header}): {e:#}");
                Ok(())
            }
        }
    }

    /// Uses the ISAKMP SA of the gateway's new phase 1 from now on; the
    /// previous one stays until the gateway deletes it.
    fn adopt(&mut self, sa: IsakmpSa, life: Duration) {
        let now = Instant::now();
        self.alive();
        let previous = std::mem::replace(self.sa, sa);
        self.previous = Some(previous);
        // Exchanges of the previous SA in progress cannot finish on this one.
        if self.pending.take().is_some() {
            self.next_rekey_attempt = now;
        }
        self.responding = None;
        // The gateway re-authenticates before the end of each phase 1.
        self.phase1_expiry = now + life;
        self.reauthed = Some(now);
        info!(
            lifetime_s = life.as_secs(),
            "new phase 1 established with the gateway; the previous one is kept until it deletes it"
        );
    }

    /// A message of the ISAKMP SA the gateway replaced: its deletes and
    /// dead peer detection.
    async fn on_previous(&mut self, raw: Vec<u8>) -> anyhow::Result<()> {
        let mut previous = self.previous.take().expect("checked by the caller");
        let msg = match previous.open(&raw) {
            Ok((msg, _)) if msg.header.exchange == exchange::INFORMATIONAL && previous.verify(&msg, &[]).is_ok() => msg,
            Ok(_) | Err(_) => {
                info!("IKE from the gateway on the previous IKE SA dropped: not an authentic Informational");
                self.previous = Some(previous);
                return Ok(());
            }
        };
        info!("IKE from the gateway on the previous IKE SA: {}", describe_payloads(&msg));
        previous.forget(msg.header.msg_id);
        self.alive();
        let mut keep = true;
        for info in classify_informational(&msg) {
            match info {
                Info::RuThere(seq) => {
                    let ack = dpd_notify(&previous, notify::R_U_THERE_ACK, seq);
                    send_informational(self.transport, &mut previous, ack).await?;
                    self.last_tx = Instant::now();
                }
                Info::DeleteIsakmp => keep = false,
                Info::DeleteEsp(spis) => {
                    self.old.retain(|(c, _)| !spis.contains(&c.outbound.spi) && !spis.contains(&c.inbound.spi));
                    let current = spis.iter().any(|s| *s == self.child.outbound.spi || *s == self.child.inbound.spi);
                    if current && self.pending.is_none() {
                        info!("the gateway deleted the IPsec SA of the previous IKE SA: renewing it");
                        self.start_rekey().await?;
                    }
                }
                Info::Error(e) => warn!("gateway reported {e} on the previous IKE SA"),
                Info::RuThereAck(_) | Info::Other => {}
            }
        }
        if keep {
            self.previous = Some(previous);
        } else {
            info!("the gateway deleted the previous IKE SA");
        }
        Ok(())
    }

    async fn on_tick(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        if now >= self.phase1_expiry {
            bail!("IKEv1 phase 1 lifetime reached; reconnecting to re-authenticate");
        }

        // Quick Mode retransmission / rekey.
        if let Some(p) = &mut self.pending
            && now.duration_since(p.sent) >= p.wait
        {
            if p.tries >= MAX_TRIES {
                warn!("phase 2 rekey got no answer");
                let p = self.pending.take().expect("checked above");
                self.sa.forget(p.init.msg_id);
                self.next_rekey_attempt = now + REKEY_RETRY;
            } else {
                p.tries += 1;
                p.sent = now;
                p.wait = (p.wait * 2).min(Duration::from_secs(8));
                let bytes = p.init.bytes.clone();
                self.send_ike(&bytes).await?;
            }
        }
        if self.child.rekey_due(now) && self.pending.is_none() && now >= self.next_rekey_attempt {
            info!(age_s = now.duration_since(self.child.created).as_secs(), "rekeying the IPsec SA");
            self.start_rekey().await?;
        }
        if let Some(at) = self.reauthed {
            if self.child.created >= at {
                self.reauthed = None;
            } else if now >= at + REAUTH_CHILD_WAIT && self.pending.is_none() && self.responding.is_none() {
                self.reauthed = None;
                info!("the gateway did not renew the IPsec SA after its new phase 1: renewing it");
                self.start_rekey().await?;
            }
        }
        if self.child.expired(now) {
            bail!("IPsec SA expired and could not be rekeyed");
        }

        // Replaced SAs at their end: stop accepting them and tell the
        // gateway.
        let ended = |(c, at): &(Phase2, Instant)| c.expired(now) && now.duration_since(*at) >= OLD_SA_GRACE;
        let expired: Vec<u32> = self.old.iter().filter(|o| ended(o)).map(|(c, _)| c.inbound.spi).collect();
        if !expired.is_empty() {
            self.old.retain(|o| !ended(o));
            info!(
                spis = format_args!("{:08x?}", expired),
                packets_since_rekey = self.trace.on_old,
                "replaced IPsec SA ended: deleting it"
            );
            let delete = Payload::Delete {
                protocol: protocol::ESP,
                spi_size: 4,
                spis: expired.iter().map(|s| s.to_be_bytes().to_vec()).collect(),
            };
            send_informational(self.transport, self.sa, delete).await?;
        }

        // Dead peer detection (RFC 3706), only while the gateway is silent.
        if self.dpd_enabled {
            match &mut self.dpd {
                None if now.duration_since(self.last_rx) >= DPD_IDLE => {
                    self.dpd_seq = self.dpd_seq.wrapping_add(1);
                    self.dpd = Some(Dpd { seq: self.dpd_seq, sent: now, tries: 1 });
                    let probe = dpd_notify(self.sa, notify::R_U_THERE, self.dpd_seq);
                    send_informational(self.transport, self.sa, probe).await?;
                    self.last_tx = now;
                }
                Some(d) if now.duration_since(d.sent) >= DPD_RETRY => {
                    if d.tries >= DPD_MAX_TRIES {
                        bail!("the gateway stopped answering dead peer detection");
                    }
                    d.tries += 1;
                    d.sent = now;
                    let probe = dpd_notify(self.sa, notify::R_U_THERE, d.seq);
                    send_informational(self.transport, self.sa, probe).await?;
                    self.last_tx = now;
                }
                _ => {}
            }
        }

        if now.duration_since(self.last_tx) >= KEEPALIVE_INTERVAL {
            self.transport.send_keepalive().await?;
            self.last_tx = now;
        }
        Ok(())
    }
}

/// The cookies of a raw ISAKMP message.
fn cookies(raw: &[u8]) -> Option<(u64, u64)> {
    let cookie = |at: usize| Some(u64::from_be_bytes(raw.get(at..at + 8)?.try_into().ok()?));
    Some((cookie(0)?, cookie(8)?))
}

/// Exchange, message id and whose SA a raw ISAKMP message claims.
fn describe_header(raw: &[u8], sa: &IsakmpSa) -> String {
    if raw.len() < 28 {
        return format!("{} bytes, too short", raw.len());
    }
    let cookie = |at: usize| u64::from_be_bytes(raw[at..at + 8].try_into().expect("8 bytes"));
    let exchange = match raw[18] {
        exchange::IDENTITY_PROTECTION => "main mode".to_owned(),
        exchange::AGGRESSIVE => "aggressive mode".to_owned(),
        exchange::INFORMATIONAL => "informational".to_owned(),
        exchange::TRANSACTION => "transaction".to_owned(),
        exchange::QUICK => "quick mode".to_owned(),
        other => format!("exchange {other}"),
    };
    let msg_id = u32::from_be_bytes(raw[20..24].try_into().expect("4 bytes"));
    let whose = match (cookie(0) == sa.cky_i, cookie(8) == sa.cky_r) {
        (true, true) => "our IKE SA",
        (true, false) => "our initiator cookie, another responder cookie",
        (false, _) if cookie(8) == 0 => "a new IKE SA the gateway starts",
        (false, _) => "another IKE SA",
    };
    format!("{exchange}, message {msg_id:08x}, {whose}")
}

/// The payloads of a decrypted message, in a few words.
fn describe_payloads(msg: &super::payload::Message) -> String {
    msg.iter()
        .map(|p| match p {
            Payload::Sa(_) => "SA".to_owned(),
            Payload::Ke(_) => "KE".to_owned(),
            Payload::Id(_) => "ID".to_owned(),
            Payload::Hash(_) => "HASH".to_owned(),
            Payload::Nonce(_) => "nonce".to_owned(),
            Payload::Notify(n) => format!("notify {} ({})", n.kind, notify::describe(n.kind)),
            Payload::Delete { protocol, spi_size, spis } => format!(
                "delete protocol {protocol}, SPIs {}",
                spis.iter()
                    .map(|s| if *spi_size == 4 {
                        s.iter().map(|b| format!("{b:02x}")).collect()
                    } else {
                        format!("{} bytes", s.len())
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Payload::VendorId(_) => "vendor id".to_owned(),
            Payload::Attr { .. } => "attributes".to_owned(),
            Payload::NatD { .. } => "NAT-D".to_owned(),
            Payload::Unknown { kind, .. } => format!("payload {kind}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
