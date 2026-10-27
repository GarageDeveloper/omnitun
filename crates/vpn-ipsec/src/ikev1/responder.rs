//! A phase 1 the gateway starts once the tunnel is up: main mode with a
//! pre-shared key (RFC 2409 §5), as the responder. Some gateways
//! (strongSwan-based ones, the Meraki MX) re-authenticate this way before
//! the ISAKMP SA ends and drop the IPsec SAs when nobody answers; the
//! macOS client answers.

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use zeroize::Zeroizing;

use super::consts::{exchange, ike_attr, protocol, vid};
use super::handshake::{
    MIN_LIFETIME, NONCE_LEN, check_remote_id, hash_attr, nat_d_payloads, nat_traversal, phase1_encryption,
};
use super::isakmp::{IsakmpSa, decrypt, encrypt};
use super::keys::{Phase1Keys, derive_phase1, phase1_hash};
use super::payload::{Id, Message, Payload, Proposal, Transform, build_plain, encode_chain};
use crate::crypto::{KeyExchange, ct_eq, random_bytes};
use crate::ikev2::nonzero_u64;
use crate::proposal::Ike1Proposal;
use crate::transport::Transport;

/// What answering a new phase 1 needs, kept from our own.
pub(crate) struct Reauth {
    pub psk: Zeroizing<Vec<u8>>,
    pub offered: Vec<Ike1Proposal>,
    /// Our identity, as in our phase 1.
    pub id: Id,
    pub remote_id: Option<String>,
    /// Longest phase 1 lifetime we accept.
    pub lifetime: Duration,
}

enum Step {
    /// Answered message 1, waiting for the key exchange.
    AwaitKe,
    /// Answered message 3, waiting for the gateway's identity.
    AwaitId {
        keys: Phase1Keys,
        gxi: Vec<u8>,
        gxr: Vec<u8>,
    },
    Done,
}

/// A main mode the gateway started, between its messages.
pub(crate) struct MainResponder {
    pub cky_i: u64,
    pub cky_r: u64,
    pub algs: Ike1Proposal,
    /// The lifetime the gateway proposed (at most ours).
    pub life: Duration,
    /// The gateway's SA payload body, covered by both hashes.
    sa_i: Vec<u8>,
    nat_d_kind: u8,
    step: Step,
    /// The gateway's last message and our answer, sent again if the
    /// gateway repeats it.
    pub request: Vec<u8>,
    pub answer: Vec<u8>,
}

impl MainResponder {
    /// Answers message 1: one of the gateway's transforms among ours.
    pub fn start(reauth: &Reauth, raw: &[u8]) -> anyhow::Result<Self> {
        let msg1 = Message::parse_plain(raw)?;
        let header = msg1.header;
        ensure!(header.exchange == exchange::IDENTITY_PROTECTION && header.cky_r == 0, "not a main mode message 1");
        let sa_i = msg1.sa_body().context("no SA in main mode message 1")?.to_vec();
        let proposals = msg1.sa().context("no SA in main mode message 1")?;
        let (proposal, transform, algs) = choose(proposals, &reauth.offered)?;
        let life = match (transform.attr(ike_attr::LIFE_TYPE), transform.attr(ike_attr::LIFE_DURATION)) {
            (Some(ike_attr::LIFE_SECONDS), Some(secs)) if secs >= MIN_LIFETIME.as_secs() => {
                Duration::from_secs(secs).min(reauth.lifetime)
            }
            _ => reauth.lifetime,
        };
        let (nat_d_kind, _) = nat_traversal(&msg1)?;
        let nat_t = [&vid::NAT_T_RFC3947, &vid::NAT_T_DRAFT03, &vid::NAT_T_DRAFT02N]
            .into_iter()
            .find(|v| msg1.has_vendor_id(&v[..]))
            .expect("nat_traversal found one");
        let cky_r = nonzero_u64();
        let chosen = Proposal {
            num: proposal.num,
            protocol: protocol::ISAKMP,
            spi: Vec::new(),
            transforms: vec![transform.clone()],
        };
        let payloads =
            [Payload::Sa(vec![chosen]), Payload::VendorId(nat_t.to_vec()), Payload::VendorId(vid::DPD.to_vec())];
        let answer = build_plain(header.cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, &payloads);
        Ok(Self {
            cky_i: header.cky_i,
            cky_r,
            algs,
            life,
            sa_i,
            nat_d_kind,
            step: Step::AwaitKe,
            request: raw.to_vec(),
            answer,
        })
    }

    /// Whether `raw` belongs to this exchange.
    pub fn owns(&self, raw: &[u8]) -> bool {
        raw.len() >= 16 && raw[..8] == self.cky_i.to_be_bytes() && raw[8..16] == self.cky_r.to_be_bytes()
    }

    /// Answers message 3 (`None`), or checks message 5 and answers it with
    /// the new ISAKMP SA. A message failing a check leaves the exchange
    /// where it was: it may be forged.
    pub fn next(&mut self, reauth: &Reauth, raw: &[u8], transport: &Transport) -> anyhow::Result<Option<IsakmpSa>> {
        let (cky_i, cky_r, prf) = (self.cky_i, self.cky_r, self.algs.prf);
        match &self.step {
            Step::AwaitKe => {
                let msg3 = Message::parse_plain(raw)?;
                let gxi = msg3.ke().context("no KE in main mode message 3")?;
                let ni = msg3.nonce().context("no nonce in main mode message 3")?;
                ensure!((8..=256).contains(&ni.len()), "gateway nonce has an invalid length ({} bytes)", ni.len());
                let kx = KeyExchange::generate(self.algs.dh)?;
                let gxy = Zeroizing::new(kx.shared_secret(gxi)?);
                let nr = random_bytes(NONCE_LEN);
                let keys =
                    derive_phase1(prf, self.algs.encr, &reauth.psk, ni, &nr, &gxy, cky_i, cky_r, gxi, kx.public())?;
                let mut payloads = vec![Payload::Ke(kx.public().to_vec()), Payload::Nonce(nr)];
                payloads.extend(nat_d_payloads(prf, self.nat_d_kind, cky_i, cky_r, transport));
                self.answer = build_plain(cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, &payloads);
                self.request = raw.to_vec();
                self.step = Step::AwaitId { keys, gxi: gxi.to_vec(), gxr: kx.public().to_vec() };
                Ok(None)
            }
            Step::AwaitId { keys, gxi, gxr } => {
                let (msg5, iv) = decrypt(&keys.cipher, &keys.iv0, raw)?;
                let idii = msg5.ids().next().context("no IDii in main mode message 5")?;
                let hash_i = msg5.hash().context("no HASH_I in main mode message 5")?;
                let expected = phase1_hash(prf, &keys.skeyid, true, gxi, gxr, cky_i, cky_r, &self.sa_i, &idii.body());
                ensure!(
                    ct_eq(&expected, hash_i),
                    "the gateway's HASH_I does not match (another pre-shared key, or a forged message)"
                );
                check_remote_id(reauth.remote_id.as_deref(), idii)?;
                let hash_r =
                    phase1_hash(prf, &keys.skeyid, false, gxi, gxr, cky_i, cky_r, &self.sa_i, &reauth.id.body());
                let (first, body) = encode_chain(&[Payload::Id(reauth.id.clone()), Payload::Hash(hash_r)]);
                let (msg6, last) =
                    encrypt(&keys.cipher, &iv, cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, first, &body);
                self.answer = msg6;
                self.request = raw.to_vec();
                let Step::AwaitId { keys, .. } = std::mem::replace(&mut self.step, Step::Done) else {
                    unreachable!("matched above")
                };
                // Phase 2 IVs start from the last block of message 6.
                Ok(Some(IsakmpSa::new(cky_i, cky_r, prf, keys, last)))
            }
            Step::Done => bail!("main mode already finished"),
        }
    }
}

/// The first of the gateway's transforms that is one of our proposals,
/// with a pre-shared key.
fn choose<'a>(
    proposals: &'a [Proposal],
    offered: &[Ike1Proposal],
) -> anyhow::Result<(&'a Proposal, &'a Transform, Ike1Proposal)> {
    let mut xauth = false;
    for p in proposals.iter().filter(|p| p.protocol == protocol::ISAKMP) {
        for t in &p.transforms {
            if t.attr(ike_attr::AUTH_METHOD) != Some(ike_attr::AUTH_PSK) {
                xauth |= t.attr(ike_attr::AUTH_METHOD).is_some_and(|m| m >= 65001);
                continue;
            }
            let found = offered.iter().find(|o| {
                t.attr(ike_attr::ENCRYPTION) == Some(phase1_encryption(o.encr))
                    && t.attr(ike_attr::KEY_LENGTH) == o.encr.key_bits().map(u64::from)
                    && t.attr(ike_attr::HASH) == Some(hash_attr(o.prf))
                    && t.attr(ike_attr::GROUP) == Some(u64::from(o.dh.id()))
            });
            if let Some(o) = found {
                return Ok((p, t, *o));
            }
        }
    }
    if xauth {
        bail!("the gateway asks for XAuth, which this client does not answer once connected");
    }
    bail!("the gateway offers no phase 1 transform of ours with a pre-shared key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DhGroup, EncrAlg, PrfAlg};
    use crate::ikev1::consts::{exchange, id_type};
    use crate::ikev1::payload::SaAttr;

    fn reauth() -> Reauth {
        Reauth {
            psk: Zeroizing::new(b"psk".to_vec()),
            offered: vec![crate::proposal::parse_ike1("aes128-sha1-modp2048").unwrap()],
            id: Id { id_type: id_type::IPV4_ADDR, protocol: 0, port: 0, data: vec![10, 0, 0, 2] },
            remote_id: None,
            lifetime: Duration::from_secs(28_800),
        }
    }

    /// The gateway's side of main mode, as the initiator: our answers
    /// must give both ends the same ISAKMP SA.
    #[tokio::test]
    async fn answers_the_gateways_main_mode() {
        let reauth = reauth();
        let transport = Transport::connect("127.0.0.1:4500".parse().unwrap()).await.unwrap();
        let (prf, encr) = (PrfAlg::HmacSha1, EncrAlg::AesCbc { key_bits: 128 });
        let attr = |kind, value| SaAttr { kind, value };
        let transform = |auth| Transform {
            num: 1,
            id: ike_attr::TRANSFORM_KEY_IKE,
            attrs: vec![
                attr(ike_attr::ENCRYPTION, ike_attr::ENCR_AES_CBC),
                attr(ike_attr::KEY_LENGTH, 128),
                attr(ike_attr::HASH, ike_attr::HASH_SHA1),
                attr(ike_attr::AUTH_METHOD, auth),
                attr(ike_attr::GROUP, 14),
                attr(ike_attr::LIFE_TYPE, ike_attr::LIFE_SECONDS),
                attr(ike_attr::LIFE_DURATION, 3600),
            ],
        };
        let sa = |auth| {
            Payload::Sa(vec![Proposal {
                num: 1,
                protocol: protocol::ISAKMP,
                spi: vec![],
                transforms: vec![transform(auth)],
            }])
        };
        let cky_i = 0x0102_0304_0506_0708;
        let nat_t = Payload::VendorId(vid::NAT_T_RFC3947.to_vec());

        // XAuth would need the user: refused.
        let xauth = build_plain(
            cky_i,
            0,
            exchange::IDENTITY_PROTECTION,
            0,
            &[sa(ike_attr::AUTH_XAUTH_INIT_PSK), nat_t.clone()],
        );
        assert!(MainResponder::start(&reauth, &xauth).is_err_and(|e| e.to_string().contains("XAuth")));

        let msg1 = build_plain(cky_i, 0, exchange::IDENTITY_PROTECTION, 0, &[sa(ike_attr::AUTH_PSK), nat_t]);
        let mut r = MainResponder::start(&reauth, &msg1).unwrap();
        assert_eq!(r.life, Duration::from_secs(3600));
        let msg2 = Message::parse_plain(&r.answer).unwrap();
        let cky_r = msg2.header.cky_r;
        assert!(cky_r != 0 && msg2.has_vendor_id(&vid::NAT_T_RFC3947) && msg2.has_vendor_id(&vid::DPD));
        assert_eq!(msg2.sa().unwrap()[0].transforms, vec![transform(ike_attr::AUTH_PSK)]);
        let sa_i = Message::parse_plain(&msg1).unwrap().sa_body().unwrap().to_vec();

        let kx = KeyExchange::generate(DhGroup::Modp2048).unwrap();
        let ni = random_bytes(32);
        let msg3 = build_plain(
            cky_i,
            cky_r,
            exchange::IDENTITY_PROTECTION,
            0,
            &[Payload::Ke(kx.public().to_vec()), Payload::Nonce(ni.clone())],
        );
        assert!(r.next(&reauth, &msg3, &transport).unwrap().is_none());
        assert!(r.owns(&msg3));
        let msg4 = Message::parse_plain(&r.answer).unwrap();
        let (gxr, nr) = (msg4.ke().unwrap().to_vec(), msg4.nonce().unwrap().to_vec());
        assert_eq!(msg4.nat_d().len(), 2);
        let gxy = kx.shared_secret(&gxr).unwrap();
        let keys = derive_phase1(prf, encr, b"psk", &ni, &nr, &gxy, cky_i, cky_r, kx.public(), &gxr).unwrap();

        let idii = Id { id_type: id_type::IPV4_ADDR, protocol: 0, port: 0, data: vec![10, 0, 0, 1] };
        let send5 = |hash: Vec<u8>| {
            let (first, body) = encode_chain(&[Payload::Id(idii.clone()), Payload::Hash(hash)]);
            encrypt(&keys.cipher, &keys.iv0, cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, first, &body)
        };
        // A wrong HASH_I (another PSK) is refused and changes nothing.
        let (forged, _) = send5(vec![0; 20]);
        assert!(r.next(&reauth, &forged, &transport).is_err());
        let hash_i = phase1_hash(prf, &keys.skeyid, true, kx.public(), &gxr, cky_i, cky_r, &sa_i, &idii.body());
        let (msg5, iv) = send5(hash_i);
        let mut ours = r.next(&reauth, &msg5, &transport).unwrap().expect("phase 1 done");

        let (msg6, last) = decrypt(&keys.cipher, &iv, &r.answer).unwrap();
        let idir = msg6.ids().next().unwrap();
        assert_eq!(idir, &reauth.id);
        let hash_r = phase1_hash(prf, &keys.skeyid, false, kx.public(), &gxr, cky_i, cky_r, &sa_i, &idir.body());
        assert_eq!(msg6.hash().unwrap(), hash_r.as_slice());

        // Both ends now share the ISAKMP SA: a Quick Mode message of ours
        // opens on the gateway's side.
        let theirs = IsakmpSa::new(cky_i, cky_r, prf, keys, last);
        let sealed = ours.seal(exchange::QUICK, 7, &[], &[Payload::Nonce(vec![1; 16])]);
        let (msg, _) = theirs.open(&sealed).unwrap();
        theirs.verify(&msg, &[]).unwrap();
    }
}
