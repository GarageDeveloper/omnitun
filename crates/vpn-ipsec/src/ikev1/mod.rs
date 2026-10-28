//! IKEv1 initiator (RFC 2409) for FortiGate dial-up tunnels: aggressive
//! mode with pre-shared key, XAuth (draft-beaulieu-ike-xauth-02),
//! Mode-Config pull (draft-dukes-ike-mode-cfg-02) and Quick Mode with PFS.
//! ESP is always UDP-encapsulated (RFC 3947/3948), like the IKEv2 engine.

pub mod consts;
#[cfg(test)]
mod fuzz;
mod handshake;
pub mod isakmp;
pub mod keys;
pub mod payload;
mod responder;
mod runtime;
mod settings;
#[cfg(test)]
mod tests;
mod transport;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::bail;
use tokio::time::timeout_at;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::crypto::random_bytes;
use crate::esp::EspSa;
use crate::ikev2::payload::TrafficSelector;
use crate::proposal::EspProposal;
use crate::transport::{Datagram, Transport};
use consts::{exchange, notify, protocol};
use isakmp::IsakmpSa;
use payload::{Message, Notify, Payload};

pub(crate) use handshake::{establish, establish_transport};

/// An IPsec SA pair from one Quick Mode.
pub(crate) struct Phase2 {
    pub inbound: EspSa,
    pub outbound: EspSa,
    pub created: Instant,
    /// Negotiated lifetime (ours, or shorter if the gateway said so).
    pub lifetime: Duration,
    /// Rekey after this many kilobytes, if set.
    pub lifetime_kb: Option<u64>,
}

impl Phase2 {
    /// Whether the SAs are close enough to their end to be replaced.
    pub fn rekey_due(&self, now: Instant) -> bool {
        let traffic = self.inbound.bytes().max(self.outbound.bytes());
        now >= self.created + self.lifetime.mul_f32(0.9)
            || self.outbound.seq() >= crate::esp::SEQ_REKEY_THRESHOLD
            || self.lifetime_kb.is_some_and(|kb| traffic >= kb.saturating_mul(1024) / 10 * 9)
    }

    /// Past the end: the SAs must not be used any more.
    pub fn expired(&self, now: Instant) -> bool {
        let traffic = self.inbound.bytes().max(self.outbound.bytes());
        now >= self.created + self.lifetime || self.lifetime_kb.is_some_and(|kb| traffic >= kb.saturating_mul(1024))
    }
}

/// Transport mode for one UDP port (L2TP, RFC 3193): the SAs protect
/// that port between our address and the gateway's.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TransportMode {
    /// Our address on our side of any NAT.
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub port: u16,
    /// NAT-OA payload type, RFC 3947 or draft numbering.
    pub nat_oa: u8,
}

/// Parameters reused by Quick Mode rekeys.
#[derive(Clone)]
pub(crate) struct QuickParams {
    pub esp: Vec<EspProposal>,
    /// UDP encapsulation mode attribute (RFC 3947 or draft value).
    pub encap: u64,
    /// Tunnel mode: the address assigned by Mode-Config.
    pub local: Ipv4Addr,
    /// Transport mode instead of tunnel mode.
    pub transport: Option<TransportMode>,
    /// Phase 2 lifetime offered, in seconds and optionally kilobytes.
    pub lifetime: Duration,
    pub lifetime_kb: Option<u64>,
}

pub(crate) struct Established {
    pub transport: Transport,
    pub sa: IsakmpSa,
    pub child: Phase2,
    pub settings: vpn_core::TunnelSettings,
    pub quick: QuickParams,
    /// Networks the gateway may send from (from the Quick Mode IDcr).
    pub remote_ts: Vec<TrafficSelector>,
    /// The gateway announced RFC 3706 dead peer detection.
    pub dpd: bool,
    /// When the ISAKMP SA must be replaced (re-authentication).
    pub phase1_expiry: Instant,
    /// To answer a new phase 1 the gateway starts; `None` with XAuth.
    pub reauth: Option<responder::Reauth>,
    pub closed: bool,
}

/// A decrypted message from the gateway, not yet authenticated.
pub(crate) struct Incoming {
    pub raw: Vec<u8>,
    pub msg: Message,
    pub next_iv: Vec<u8>,
}

/// Waits for the next encrypted ISAKMP message of `sa` until `deadline`.
/// ESP and keepalives are ignored (none flow before Quick Mode completes).
/// When the gateway retransmits `resend.0` (our answer was lost), `resend.1`
/// is sent again: its exchange is closed, so `open` would refuse it.
pub(crate) async fn next_message(
    transport: &Transport,
    sa: &IsakmpSa,
    cancel: &CancellationToken,
    deadline: tokio::time::Instant,
    resend: Option<&(Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<Option<Incoming>> {
    loop {
        let datagram = tokio::select! {
            _ = cancel.cancelled() => bail!("cancelled"),
            r = timeout_at(deadline, transport.recv()) => match r {
                Err(_) => return Ok(None),
                Ok(r) => r?,
            },
        };
        let Datagram::Ike(raw) = datagram else { continue };
        if let Some((request, answer)) = resend
            && *request == raw
        {
            transport.send_ike(answer).await?;
            continue;
        }
        match sa.open(&raw) {
            Ok((msg, next_iv)) => return Ok(Some(Incoming { raw, msg, next_iv })),
            Err(e) => debug!("dropping ISAKMP message: {e:#}"),
        }
    }
}

/// Sends one Informational exchange (HASH + notify or delete). IKEv1
/// Informationals are not acknowledged.
pub(crate) async fn send_informational(
    transport: &Transport,
    sa: &mut IsakmpSa,
    payload: Payload,
) -> anyhow::Result<()> {
    let msg_id = random_msg_id();
    let bytes = sa.seal(exchange::INFORMATIONAL, msg_id, &[], &[payload]);
    sa.forget(msg_id);
    transport.send_ike(&bytes).await
}

/// RFC 3706 notify (R-U-THERE or R-U-THERE-ACK) carrying `seq`.
pub(crate) fn dpd_notify(sa: &IsakmpSa, kind: u16, seq: u32) -> Payload {
    Payload::Notify(Notify {
        protocol: protocol::ISAKMP,
        spi: [sa.cky_i.to_be_bytes(), sa.cky_r.to_be_bytes()].concat(),
        kind,
        data: seq.to_be_bytes().to_vec(),
    })
}

/// What an authenticated Informational tells us.
pub(crate) enum Info {
    RuThere(u32),
    RuThereAck(u32),
    /// The cookies (16-byte SPIs) of the deleted ISAKMP SAs.
    DeleteIsakmp(Vec<Vec<u8>>),
    DeleteEsp(Vec<u32>),
    Error(String),
    Other,
}

pub(crate) fn classify_informational(msg: &Message) -> Vec<Info> {
    msg.iter()
        .map(|p| match p {
            Payload::Notify(n) if n.kind == notify::R_U_THERE && n.data.len() == 4 => {
                Info::RuThere(u32::from_be_bytes(n.data[..4].try_into().unwrap()))
            }
            Payload::Notify(n) if n.kind == notify::R_U_THERE_ACK && n.data.len() == 4 => {
                Info::RuThereAck(u32::from_be_bytes(n.data[..4].try_into().unwrap()))
            }
            Payload::Notify(n) if n.is_error() => Info::Error(notify::describe(n.kind)),
            Payload::Delete { protocol: protocol::ISAKMP, spis, .. } => Info::DeleteIsakmp(spis.clone()),
            Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis } => Info::DeleteEsp(
                spis.iter().filter_map(|s| s.as_slice().try_into().ok()).map(u32::from_be_bytes).collect(),
            ),
            _ => Info::Other,
        })
        .collect()
}

pub(crate) fn random_msg_id() -> u32 {
    loop {
        let v = u32::from_be_bytes(random_bytes(4).try_into().unwrap());
        if v != 0 {
            return v;
        }
    }
}
