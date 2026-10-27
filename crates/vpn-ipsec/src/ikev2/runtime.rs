//! Data path and IKE housekeeping once the tunnel is up: ESP, NAT-T
//! keepalives, dead peer detection, CHILD SA rekeying and the gateway's
//! INFORMATIONAL / CREATE_CHILD_SA requests.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vpn_core::{PacketIo, SessionContext};
use zeroize::Zeroizing;

use super::consts::{exchange, notify, protocol, transform};
use super::handshake::nonzero_u32;
use super::keys::derive_child_keys;
use super::message::Message;
use super::payload::{Notify, Payload, TrafficSelector, Transform};
use super::{ChildSa, Established, IkeSa, check_nonce, request};
use crate::crypto::{KeyExchange, random_bytes};
use crate::esp::{EspSa, NEXT_HEADER_IPV4, NEXT_HEADER_NONE, SEQ_REKEY_THRESHOLD};
use crate::proposal::{self, EspProposal};
use crate::transport::{Datagram, Transport};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const DPD_IDLE: Duration = Duration::from_secs(30);
const REKEY_RETRY: Duration = Duration::from_secs(60);
/// How long a replaced CHILD SA keeps accepting in-flight packets.
const OLD_SA_GRACE: Duration = Duration::from_secs(30);
const MAX_TRIES: u32 = 5;
const NONCE_LEN: usize = 32;

enum PendingKind {
    Dpd,
    RekeyChild { spi: u32, nonce: Vec<u8>, kx: KeyExchange },
    DeleteChild { spi: u32 },
}

struct Pending {
    msg_id: u32,
    bytes: Vec<u8>,
    sent: Instant,
    tries: u32,
    wait: Duration,
    kind: PendingKind,
}

struct Runner<'a> {
    transport: &'a Transport,
    ike: &'a mut IkeSa,
    child: &'a mut ChildSa,
    local_ts: &'a [TrafficSelector],
    remote_ts: &'a [TrafficSelector],
    esp_proposals: &'a [EspProposal],
    closed: &'a mut bool,
    ctx: &'a SessionContext,
    to_tun: &'a mpsc::Sender<Bytes>,
    /// Inner address assigned by the gateway.
    assigned: Ipv4Addr,
    /// Decrypted packets dropped by `check_inner`.
    dropped: u64,
    pending: Option<Pending>,
    old: Vec<(ChildSa, Instant)>,
    last_rx: Instant,
    last_tx: Instant,
    rekey_at: Instant,
    limits: super::Limits,
}

impl Established {
    pub(crate) async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let PacketIo { to_tun, mut from_tun } = io;
        let transport = &self.transport;
        let now = Instant::now();
        let mut runner = Runner {
            transport,
            ike: &mut self.ike,
            rekey_at: self.child.created + self.limits.child_rekey_after,
            limits: self.limits,
            child: &mut self.child,
            local_ts: &self.local_ts,
            remote_ts: &self.remote_ts,
            esp_proposals: &self.esp_proposals,
            closed: &mut self.closed,
            ctx,
            to_tun: &to_tun,
            assigned: self.settings.address,
            dropped: 0,
            pending: None,
            old: Vec::new(),
            last_rx: now,
            last_tx: now,
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
                    Datagram::Ike(raw) => runner.on_ike(&raw).await?,
                    Datagram::Keepalive => {}
                },
                _ = tick.tick() => runner.on_tick().await?,
            }
        }
    }

    /// Deletes the IKE SA (and with it the CHILD SAs), best effort.
    pub(crate) async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let delete = Payload::Delete { protocol: protocol::IKE, spi_size: 0, spis: Vec::new() };
        let (id, bytes) = self.ike.build_request(exchange::INFORMATIONAL, &[delete]);
        let ike = &self.ike;
        match request(&self.transport, &CancellationToken::new(), &bytes, id, ike.spi_i, 2, |r| ike.parse(r)).await {
            Ok(_) => info!("IKE SA deleted"),
            Err(e) => debug!("IKE SA delete not acknowledged: {e:#}"),
        }
    }
}

impl Runner<'_> {
    async fn on_tun_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        if packet.first().is_none_or(|b| b >> 4 != 4) {
            return Ok(()); // IPv4 only
        }
        let esp = self.child.outbound.encapsulate(packet, NEXT_HEADER_IPV4)?;
        if let Err(e) = self.transport.send_esp(&esp).await {
            debug!("ESP send failed: {e:#}");
            return Ok(());
        }
        self.last_tx = Instant::now();
        self.ctx.stats.record_tx(packet.len());
        Ok(())
    }

    async fn on_esp(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        let spi = u32::from_be_bytes(packet[..4].try_into().expect("datagram has at least 8 bytes"));
        let sa: &mut EspSa = if self.child.inbound.spi == spi {
            &mut self.child.inbound
        } else if let Some((old, _)) = self.old.iter_mut().find(|(c, _)| c.inbound.spi == spi) {
            &mut old.inbound
        } else {
            debug!("ESP packet for unknown SPI {spi:#010x}");
            return Ok(());
        };
        match sa.decapsulate(packet) {
            Ok((NEXT_HEADER_IPV4, inner)) => {
                self.last_rx = Instant::now();
                if let Err(reason) = check_inner(&inner, self.remote_ts, self.assigned) {
                    self.dropped += 1;
                    debug!(dropped = self.dropped, "dropping decrypted packet: {reason}");
                    return Ok(());
                }
                self.ctx.stats.record_rx(inner.len());
                self.to_tun.send(Bytes::from(inner)).await.context("tun interface closed")?;
            }
            Ok((NEXT_HEADER_NONE, _)) => self.last_rx = Instant::now(),
            Ok((nh, _)) => debug!("dropping ESP payload with next header {nh}"),
            Err(e) => debug!("dropping ESP packet: {e:#}"),
        }
        Ok(())
    }

    async fn on_ike(&mut self, raw: &[u8]) -> anyhow::Result<()> {
        let msg = match self.ike.parse(raw) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("ignoring IKE message: {e:#}");
                return Ok(());
            }
        };
        self.last_rx = Instant::now();
        if msg.header.is_response() { self.on_response(msg).await } else { self.on_request(msg).await }
    }

    async fn on_response(&mut self, msg: Message) -> anyhow::Result<()> {
        let Some(pending) = self.pending.take_if(|p| p.msg_id == msg.header.msg_id) else {
            return Ok(());
        };
        match pending.kind {
            PendingKind::Dpd => {}
            PendingKind::DeleteChild { spi } => self.old.retain(|(c, _)| c.inbound.spi != spi),
            PendingKind::RekeyChild { spi, nonce, kx } => {
                if let Err(e) = self.finish_rekey(&msg, spi, &nonce, &kx).await {
                    warn!("CHILD SA rekey failed: {e:#}; retrying in {}s", REKEY_RETRY.as_secs());
                    self.rekey_at = Instant::now() + REKEY_RETRY;
                }
            }
        }
        Ok(())
    }

    async fn on_request(&mut self, msg: Message) -> anyhow::Result<()> {
        let id = msg.header.msg_id;
        if let Some((last_id, bytes)) = &self.ike.last_response
            && *last_id == id
        {
            self.transport.send_ike(bytes).await?;
            return Ok(());
        }
        if id != self.ike.next_peer_request_id {
            debug!("ignoring IKE request with unexpected message ID {id}");
            return Ok(());
        }
        self.ike.next_peer_request_id += 1;
        match msg.header.exchange {
            exchange::INFORMATIONAL => self.on_informational(&msg).await,
            exchange::CREATE_CHILD_SA => self.on_create_child(&msg).await,
            other => {
                debug!("answering unexpected exchange {other} with an empty response");
                self.respond(other, id, Vec::new()).await
            }
        }
    }

    async fn on_informational(&mut self, msg: &Message) -> anyhow::Result<()> {
        let mut reply = Vec::new();
        let mut end = None;
        for payload in &msg.payloads {
            let Payload::Delete { protocol: proto, spis, .. } = payload else { continue };
            if *proto == protocol::IKE {
                *self.closed = true;
                end = Some("gateway closed the IKE SA");
                continue;
            }
            let mut ours = Vec::new();
            for spi in spis.iter().filter_map(|s| <[u8; 4]>::try_from(s.as_slice()).ok()).map(u32::from_be_bytes) {
                if self.child.outbound.spi == spi {
                    ours.push(self.child.inbound.spi);
                    end = Some("gateway deleted the IPsec SA");
                } else if let Some(pos) = self.old.iter().position(|(c, _)| c.outbound.spi == spi) {
                    ours.push(self.old.remove(pos).0.inbound.spi);
                }
            }
            if !ours.is_empty() {
                let spis = ours.iter().map(|s| s.to_be_bytes().to_vec()).collect();
                reply.push(Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis });
            }
        }
        self.respond(exchange::INFORMATIONAL, msg.header.msg_id, reply).await?;
        match end {
            Some(reason) => bail!(reason),
            None => Ok(()),
        }
    }

    /// Responder side of CREATE_CHILD_SA: CHILD SA rekeying only.
    async fn on_create_child(&mut self, msg: &Message) -> anyhow::Result<()> {
        let id = msg.header.msg_id;
        let proposals = msg.sa().unwrap_or(&[]);
        if proposals.iter().any(|p| p.protocol == protocol::IKE) {
            self.respond_error(exchange::CREATE_CHILD_SA, id, notify::NO_PROPOSAL_CHOSEN).await?;
            bail!("gateway started an IKE SA rekey, which is not supported yet; reconnect to re-authenticate");
        }
        let rekeyed = msg
            .notify(notify::REKEY_SA)
            .and_then(|n| <[u8; 4]>::try_from(n.spi.as_slice()).ok())
            .map(u32::from_be_bytes);
        let Some(rekeyed) = rekeyed else {
            return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::NO_ADDITIONAL_SAS).await;
        };
        if rekeyed != self.child.outbound.spi {
            return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::CHILD_SA_NOT_FOUND).await;
        }
        let ke = msg.ke();
        let Some((mut chosen, peer_spi, algs)) = proposal::choose_esp(proposals, self.esp_proposals, ke.map(|k| k.0))
        else {
            return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::NO_PROPOSAL_CHOSEN).await;
        };
        // The gateway is the initiator here: its TSi is its own side.
        let ts_i = TrafficSelector::narrow(msg.ts_i(), self.remote_ts);
        let ts_r = TrafficSelector::narrow(msg.ts_r(), self.local_ts);
        if ts_i.is_empty() || ts_r.is_empty() {
            warn!("gateway asked to rekey with traffic selectors outside the tunnel's");
            return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::TS_UNACCEPTABLE).await;
        }
        let Some(ni) = msg.nonce().filter(|n| check_nonce(n, self.ike.keys.prf).is_ok()).map(<[u8]>::to_vec) else {
            return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::INVALID_SYNTAX).await;
        };
        let nr = random_bytes(NONCE_LEN);
        let spi = nonzero_u32();
        let mut payloads = Vec::new();
        let shared = match (algs.pfs, ke) {
            (Some(group), Some((_, data))) => {
                let kx = KeyExchange::generate(group)?;
                let Ok(shared) = kx.shared_secret(data).map(Zeroizing::new) else {
                    return self.respond_error(exchange::CREATE_CHILD_SA, id, notify::INVALID_SYNTAX).await;
                };
                payloads.push(Payload::Ke { group: group.id(), data: kx.public().to_vec() });
                Some(shared)
            }
            _ => None,
        };
        let prf = self.ike.keys.prf;
        let (out, inbound) = derive_child_keys(
            prf,
            &self.ike.keys.sk_d,
            shared.as_ref().map(|s| s.as_slice()),
            &ni,
            &nr,
            algs.encr,
            algs.integ,
            false,
        )?;
        chosen.spi = spi.to_be_bytes().to_vec();
        payloads.insert(0, Payload::Sa(vec![chosen]));
        payloads.insert(1, Payload::Nonce(nr));
        payloads.push(Payload::TsI(ts_i));
        payloads.push(Payload::TsR(ts_r));
        self.respond(exchange::CREATE_CHILD_SA, id, payloads).await?;
        self.install_child(ChildSa {
            inbound: EspSa::new(spi, inbound),
            outbound: EspSa::new(peer_spi, out),
            created: Instant::now(),
        });
        info!("CHILD SA rekeyed by the gateway");
        Ok(())
    }

    async fn start_rekey(&mut self) -> anyhow::Result<()> {
        let group = self.esp_proposals.iter().find_map(|p| p.pfs).unwrap_or(self.ike.algs.dh);
        let kx = KeyExchange::generate(group)?;
        let spi = nonzero_u32();
        let nonce = random_bytes(NONCE_LEN);
        let proposals = self
            .esp_proposals
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut sa = p.sa_proposal(i as u8 + 1, spi, Some(p.pfs.unwrap_or(group)));
                if p.pfs.is_none() {
                    // PFS optional: also offer "no DH" (RFC 7296 §3.3.3).
                    let at = sa.transforms.len() - 1;
                    sa.transforms.insert(at, Transform { kind: transform::DH, id: 0, key_len: None });
                }
                sa
            })
            .collect();
        let mut rekey = Notify::new(notify::REKEY_SA, Vec::new());
        rekey.protocol = protocol::ESP;
        rekey.spi = self.child.inbound.spi.to_be_bytes().to_vec();
        let payloads = vec![
            Payload::Notify(rekey),
            Payload::Sa(proposals),
            Payload::Nonce(nonce.clone()),
            Payload::Ke { group: group.id(), data: kx.public().to_vec() },
            Payload::TsI(self.local_ts.to_vec()),
            Payload::TsR(self.remote_ts.to_vec()),
        ];
        debug!("rekeying CHILD SA");
        self.start_request(exchange::CREATE_CHILD_SA, payloads, PendingKind::RekeyChild { spi, nonce, kx }).await
    }

    async fn finish_rekey(&mut self, msg: &Message, spi: u32, ni: &[u8], kx: &KeyExchange) -> anyhow::Result<()> {
        msg.check_errors()?;
        let (algs, peer_spi) =
            proposal::accept_rekey_esp(msg.sa().context("rekey response without SA")?, self.esp_proposals, kx.group())?;
        let nr = msg.nonce().context("rekey response without nonce")?;
        check_nonce(nr, self.ike.keys.prf)?;
        let shared = match (algs.pfs, msg.ke()) {
            (None, _) => None,
            (Some(g), Some((group, data))) if g == kx.group() && group == g.id() => {
                Some(Zeroizing::new(kx.shared_secret(data)?))
            }
            _ => bail!("rekey response has an inconsistent KE payload"),
        };
        let prf = self.ike.keys.prf;
        let (out, inbound) = derive_child_keys(
            prf,
            &self.ike.keys.sk_d,
            shared.as_ref().map(|s| s.as_slice()),
            ni,
            nr,
            algs.encr,
            algs.integ,
            true,
        )?;
        let old_spi = self.child.inbound.spi;
        self.install_child(ChildSa {
            inbound: EspSa::new(spi, inbound),
            outbound: EspSa::new(peer_spi, out),
            created: Instant::now(),
        });
        info!("CHILD SA rekeyed");
        let delete =
            Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis: vec![old_spi.to_be_bytes().to_vec()] };
        self.start_request(exchange::INFORMATIONAL, vec![delete], PendingKind::DeleteChild { spi: old_spi }).await
    }

    fn install_child(&mut self, new: ChildSa) {
        let old = std::mem::replace(self.child, new);
        self.old.push((old, Instant::now()));
        self.rekey_at = Instant::now() + self.limits.child_rekey_after;
    }

    async fn on_tick(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        if let Some(p) = &mut self.pending {
            if now.duration_since(p.sent) >= p.wait {
                if p.tries >= MAX_TRIES {
                    bail!("gateway stopped responding (dead peer detection)");
                }
                p.tries += 1;
                p.sent = now;
                p.wait = (p.wait * 2).min(Duration::from_secs(8));
                self.transport.send_ike(&p.bytes).await?;
            }
        } else if now >= self.rekey_at
            || self.child.outbound.seq() >= SEQ_REKEY_THRESHOLD
            || self.limits.child_rekey_kb.is_some_and(|kb| {
                self.child.inbound.bytes().max(self.child.outbound.bytes()) >= kb.saturating_mul(1024)
            })
        {
            self.start_rekey().await?;
        } else if self.limits.dpd && now.duration_since(self.last_rx) >= DPD_IDLE {
            self.start_request(exchange::INFORMATIONAL, Vec::new(), PendingKind::Dpd).await?;
        }
        if now.duration_since(self.last_tx) >= KEEPALIVE_INTERVAL {
            self.transport.send_keepalive().await?;
            self.last_tx = now;
        }
        if now.duration_since(self.ike.established) >= self.limits.ike_max_age {
            bail!("IKE SA reached its maximum age; reconnect to re-authenticate");
        }
        self.old.retain(|(_, since)| now.duration_since(*since) < OLD_SA_GRACE);
        Ok(())
    }

    async fn start_request(&mut self, exchange: u8, payloads: Vec<Payload>, kind: PendingKind) -> anyhow::Result<()> {
        let (msg_id, bytes) = self.ike.build_request(exchange, &payloads);
        self.transport.send_ike(&bytes).await?;
        self.pending =
            Some(Pending { msg_id, bytes, sent: Instant::now(), tries: 1, wait: Duration::from_secs(2), kind });
        Ok(())
    }

    async fn respond(&mut self, exchange: u8, msg_id: u32, payloads: Vec<Payload>) -> anyhow::Result<()> {
        let bytes = self.ike.build_response(exchange, msg_id, &payloads);
        self.transport.send_ike(&bytes).await
    }

    async fn respond_error(&mut self, exchange: u8, msg_id: u32, kind: u16) -> anyhow::Result<()> {
        self.respond(exchange, msg_id, vec![Payload::Notify(Notify::new(kind, Vec::new()))]).await
    }
}

/// Accepts a decrypted packet only if it is a well-formed IPv4 packet from
/// the networks negotiated for the tunnel to our assigned address, so a
/// compromised or misconfigured gateway cannot inject arbitrary traffic.
pub(crate) fn check_inner(
    packet: &[u8],
    remote_ts: &[TrafficSelector],
    assigned: Ipv4Addr,
) -> Result<(), &'static str> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err("not an IPv4 packet");
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total < ihl || total != packet.len() {
        return Err("inconsistent IPv4 header lengths");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if dst != assigned {
        return Err("destination is not our tunnel address");
    }
    if !remote_ts.iter().any(|ts| ts.contains(src)) {
        return Err("source outside the negotiated traffic selectors");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(src: [u8; 4], dst: [u8; 4], len: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.resize(usize::from(len).max(20), 0);
        p
    }

    #[test]
    fn inner_packet_checks() {
        let ts = [TrafficSelector {
            start: Ipv4Addr::new(10, 0, 0, 0),
            end: Ipv4Addr::new(10, 255, 255, 255),
            ..TrafficSelector::any()
        }];
        let me = Ipv4Addr::new(10, 9, 0, 2);
        assert!(check_inner(&packet([10, 0, 0, 1], [10, 9, 0, 2], 28), &ts, me).is_ok());
        assert!(check_inner(&packet([192, 168, 1, 1], [10, 9, 0, 2], 28), &ts, me).is_err());
        assert!(check_inner(&packet([10, 0, 0, 1], [10, 9, 0, 3], 28), &ts, me).is_err());
        assert!(check_inner(&packet([10, 0, 0, 1], [10, 9, 0, 2], 28), &[], me).is_err());
        // Length field disagreeing with the buffer.
        let mut p = packet([10, 0, 0, 1], [10, 9, 0, 2], 28);
        p.push(0);
        assert!(check_inner(&p, &ts, me).is_err());
        assert!(check_inner(&packet([10, 0, 0, 1], [10, 9, 0, 2], 28)[..19], &ts, me).is_err());
        // IHL below 5 words, IPv6.
        let mut p = packet([10, 0, 0, 1], [10, 9, 0, 2], 28);
        p[0] = 0x44;
        assert!(check_inner(&p, &ts, me).is_err());
        p[0] = 0x60;
        assert!(check_inner(&p, &ts, me).is_err());
        // Full tunnel accepts any source.
        let any = [TrafficSelector::any()];
        assert!(check_inner(&packet([8, 8, 8, 8], [10, 9, 0, 2], 28), &any, me).is_ok());
    }
}
