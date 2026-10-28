//! IKEv2 initiator (RFC 7296).

pub mod consts;
#[cfg(test)]
mod fuzz;
mod handshake;
pub mod keys;
pub mod message;
pub mod payload;
mod runtime;
mod settings;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use anyhow::{bail, ensure};
use tokio::time::timeout_at;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::esp::EspSa;
use crate::proposal::{EspProposal, IkeProposal};
use crate::transport::{Datagram, Transport};
use consts::flags;
use keys::IkeKeys;
use message::{Header, Message};
use payload::{Payload, TrafficSelector};

pub(crate) use handshake::{establish, nonzero_u32, nonzero_u64, resolve};
pub(crate) use runtime::check_inner;

/// An established IKE SA (we are the original initiator).
pub(crate) struct IkeSa {
    pub spi_i: u64,
    pub spi_r: u64,
    pub algs: IkeProposal,
    pub keys: IkeKeys,
    next_request_id: u32,
    next_peer_request_id: u32,
    /// Our last response, resent if the peer retransmits its request.
    last_response: Option<(u32, Vec<u8>)>,
    iv_counter: u64,
    pub established: Instant,
}

impl IkeSa {
    fn new(spi_i: u64, spi_r: u64, algs: IkeProposal, keys: IkeKeys) -> Self {
        Self {
            spi_i,
            spi_r,
            algs,
            keys,
            next_request_id: 1,
            next_peer_request_id: 0,
            last_response: None,
            iv_counter: 0,
            established: Instant::now(),
        }
    }

    fn next_iv(&mut self) -> Vec<u8> {
        self.iv_counter += 1;
        self.keys.out.make_iv(self.iv_counter)
    }

    /// Builds an encrypted request; returns its message ID and bytes.
    pub fn build_request(&mut self, exchange: u8, payloads: &[Payload]) -> (u32, Vec<u8>) {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let iv = self.next_iv();
        let bytes = message::build_encrypted(
            self.spi_i,
            self.spi_r,
            exchange,
            flags::INITIATOR,
            id,
            payloads,
            &self.keys.out,
            &iv,
        );
        (id, bytes)
    }

    pub fn build_response(&mut self, exchange: u8, msg_id: u32, payloads: &[Payload]) -> Vec<u8> {
        let iv = self.next_iv();
        let bytes = message::build_encrypted(
            self.spi_i,
            self.spi_r,
            exchange,
            flags::INITIATOR | flags::RESPONSE,
            msg_id,
            payloads,
            &self.keys.out,
            &iv,
        );
        self.last_response = Some((msg_id, bytes.clone()));
        bytes
    }

    pub fn parse(&self, raw: &[u8]) -> anyhow::Result<Message> {
        let header = Header::decode(raw)?;
        ensure!(header.spi_i == self.spi_i && header.spi_r == self.spi_r, "message for another IKE SA");
        message::parse(raw, Some(&self.keys.inbound))
    }
}

/// A CHILD SA: one ESP SA per direction.
pub(crate) struct ChildSa {
    pub inbound: EspSa,
    pub outbound: EspSa,
    pub created: Instant,
}

/// Everything `run` and `disconnect` need after a successful handshake.
pub(crate) struct Established {
    pub transport: Transport,
    pub ike: IkeSa,
    pub child: ChildSa,
    pub settings: vpn_core::TunnelSettings,
    /// Narrowed selectors from IKE_AUTH, reused when rekeying.
    pub local_ts: Vec<TrafficSelector>,
    pub remote_ts: Vec<TrafficSelector>,
    pub esp_proposals: Vec<EspProposal>,
    pub limits: Limits,
    /// Set once the IKE SA is gone (deleted by either side).
    pub closed: bool,
}

/// Lifetimes and liveness checks from the profile.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    /// IKE SA rekeying is not implemented: reconnect (re-authenticate)
    /// shortly before the IKE SA lifetime.
    pub ike_max_age: Duration,
    /// Rekey the CHILD SA after this long...
    pub child_rekey_after: Duration,
    /// ...or after this many kilobytes.
    pub child_rekey_kb: Option<u64>,
    /// Past these, a CHILD SA that could not be rekeyed ends the session.
    pub child_lifetime: Duration,
    pub child_lifetime_kb: Option<u64>,
    pub dpd: bool,
}

impl Limits {
    pub fn new(profile: &vpn_core::IpsecProfile) -> Self {
        Self {
            ike_max_age: Duration::from_secs(profile.phase1_lifetime.into()).mul_f32(0.95),
            child_rekey_after: crate::lifetime(profile.phase2_lifetime).mul_f32(0.9),
            child_rekey_kb: profile.phase2_lifetime_kb.map(|kb| kb.saturating_mul(1024) / 10 * 9 / 1024),
            child_lifetime: crate::lifetime(profile.phase2_lifetime),
            child_lifetime_kb: profile.phase2_lifetime_kb,
            dpd: profile.dpd,
        }
    }
}

/// Nonce sanity (RFC 7296 §2.10): 16 to 256 bytes and at least half the
/// PRF key size.
pub(crate) fn check_nonce(nonce: &[u8], prf: crate::crypto::PrfAlg) -> anyhow::Result<()> {
    ensure!(
        (16..=256).contains(&nonce.len()) && nonce.len() >= prf.output_len() / 2,
        "peer nonce has an invalid length ({} bytes)",
        nonce.len()
    );
    Ok(())
}

/// Sends `bytes` and waits for the matching response, retransmitting with
/// exponential backoff (RFC 7296 §2.1). Datagrams that look like the
/// response but fail `parse` (forged, corrupted, failing integrity) are
/// dropped and waiting continues, so an off-path attacker cannot abort the
/// exchange. Returns the raw response and its parsed form.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn request(
    transport: &Transport,
    cancel: &CancellationToken,
    bytes: &[u8],
    msg_id: u32,
    spi_i: u64,
    attempts: u32,
    parse: impl Fn(&[u8]) -> anyhow::Result<Message>,
) -> anyhow::Result<(Vec<u8>, Message)> {
    let mut wait = Duration::from_secs(1);
    for _ in 0..attempts {
        transport.send_ike(bytes).await?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let datagram = tokio::select! {
                _ = cancel.cancelled() => bail!("cancelled"),
                r = timeout_at(deadline, transport.recv()) => match r {
                    Err(_) => break,
                    Ok(r) => r?,
                },
            };
            let Datagram::Ike(raw) = datagram else { continue };
            match Header::decode(&raw) {
                Ok(h) if h.is_response() && h.msg_id == msg_id && h.spi_i == spi_i => {}
                _ => continue,
            }
            match parse(&raw) {
                Ok(msg) => return Ok((raw, msg)),
                Err(e) => debug!("dropping invalid response: {e:#}"),
            }
        }
        wait = (wait * 2).min(Duration::from_secs(8));
    }
    Err(vpn_core::failure(
        vpn_core::FailureKind::Unreachable,
        format!(
            "no response from {} (UDP {} filtered or gateway down?)",
            transport.peer().ip(),
            transport.peer().port()
        ),
    ))
}

#[cfg(test)]
mod nonce_tests {
    use super::check_nonce;
    use crate::crypto::PrfAlg;

    #[test]
    fn nonce_lengths() {
        assert!(check_nonce(&[0; 15], PrfAlg::HmacSha256).is_err());
        assert!(check_nonce(&[0; 16], PrfAlg::HmacSha256).is_ok());
        assert!(check_nonce(&[0; 256], PrfAlg::HmacSha256).is_ok());
        assert!(check_nonce(&[0; 257], PrfAlg::HmacSha256).is_err());
        // SHA-384 PRF: at least 24 bytes.
        assert!(check_nonce(&[0; 23], PrfAlg::HmacSha384).is_err());
        assert!(check_nonce(&[0; 24], PrfAlg::HmacSha384).is_ok());
        assert!(check_nonce(&[], PrfAlg::HmacSha256).is_err());
    }
}
