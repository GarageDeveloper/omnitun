//! Phase 1 (main or aggressive mode, pre-shared key), XAuth, Mode-Config
//! and the first Quick Mode.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vpn_core::{ExchangeMode, FailureKind, IpsecProfile, Prompt, PromptKind, SessionContext, failure};
use zeroize::{Zeroize, Zeroizing};

use super::consts::{cfg, esp_attr, exchange, id_type, ike_attr, notify, payload as pt, protocol, vid};
use super::isakmp::{IsakmpSa, decrypt, encrypt};
use super::keys::{derive_phase1, keymat, nat_d, phase1_hash};
use super::payload::{
    CfgAttr, CfgValue, Header, Id, Message, Payload, Proposal, SaAttr, Transform, build_plain, decode_sa_attrs,
    encode_chain,
};
use super::responder::Reauth;
use super::{
    Established, Incoming, Info, Phase2, QuickParams, TransportMode, classify_informational, dpd_notify, next_message,
    random_msg_id, send_informational, settings,
};
use crate::crypto::{Cipher, DhGroup, EncrAlg, IntegAlg, KeyExchange, PrfAlg, ct_eq, random_bytes};
use crate::esp::EspSa;
use crate::ikev2::payload::{Identity, TrafficSelector};
use crate::ikev2::{nonzero_u32, nonzero_u64, resolve};
use crate::proposal::{self, EspProposal, Ike1Proposal};
use crate::transport::{NATT_PORT, Transport};

pub(super) const NONCE_LEN: usize = 32;
const MAX_TRIES: u32 = 5;
/// Lifetimes we propose; FortiGate defaults are the same.
/// After an invalid aggressive mode reply, how long a valid one may still
/// arrive (it could have been a forged reply racing the gateway's).
const INVALID_REPLY_GRACE: Duration = Duration::from_secs(3);
/// Shortest phase 1 / phase 2 lifetime we accept from the gateway.
pub(super) const MIN_LIFETIME: Duration = Duration::from_secs(300);
/// How long we wait for the gateway to drive XAuth.
const XAUTH_WAIT: Duration = Duration::from_secs(30);
const MAX_XAUTH_ROUNDS: usize = 3;

pub(crate) async fn establish(profile: &IpsecProfile, ctx: &SessionContext) -> anyhow::Result<Established> {
    establish_with_natt_port(profile, ctx, NATT_PORT, None).await
}

/// Without Mode-Config, an SA pair in transport mode for UDP `port`
/// (L2TP over IPsec).
pub(crate) async fn establish_transport(
    profile: &IpsecProfile,
    ctx: &SessionContext,
    port: u16,
) -> anyhow::Result<Established> {
    establish_with_natt_port(profile, ctx, NATT_PORT, Some(port)).await
}

pub(crate) async fn establish_with_natt_port(
    profile: &IpsecProfile,
    ctx: &SessionContext,
    natt_port: u16,
    transport_port: Option<u16>,
) -> anyhow::Result<Established> {
    let (offered, esp) = proposals(profile)?;
    let gateway = resolve(&profile.gateway, profile.port).await?;
    let main = profile.exchange_mode == ExchangeMode::Main;
    info!(%gateway, "starting IKEv1 {} mode", if main { "main" } else { "aggressive" });
    let psk = Zeroizing::new(
        ctx.prompter.ask(Prompt::new("psk", PromptKind::Secret, format!("Pre-shared key for {}", ctx.name))).await?,
    );

    let mut transport = Transport::connect(gateway).await?;
    let local_ip = *transport.local()?.ip();
    let identity = Identity::parse(&profile.local_id.clone().unwrap_or_else(|| local_ip.to_string()));
    let id = Id { id_type: identity.id_type, protocol: 0, port: 0, data: identity.data };
    // What answering the gateway's own new phase 1 needs (XAuth would
    // ask the user again: not supported).
    let reauth = (!profile.xauth).then(|| Reauth {
        psk: Zeroizing::new(psk.as_bytes().to_vec()),
        offered: offered.clone(),
        id: id.clone(),
        remote_id: profile.remote_id.clone(),
        lifetime: Duration::from_secs(profile.phase1_lifetime.into()),
    });
    let start = Phase1Start {
        profile,
        cancel: &ctx.cancel,
        offered: &offered,
        psk: psk.as_bytes(),
        idii: id,
        lifetime: Duration::from_secs(profile.phase1_lifetime.into()),
        auth_method: if profile.xauth { ike_attr::AUTH_XAUTH_INIT_PSK } else { ike_attr::AUTH_PSK },
        natt_port,
    };
    let Phase1 { mut sa, algs, life: phase1_life, mut encap, dpd } =
        if main { main_mode(&mut transport, start).await? } else { aggressive_mode(&mut transport, start).await? };
    let phase1_expiry = Instant::now() + phase1_life.mul_f32(0.95);
    info!(?algs, "IKEv1 phase 1 established");
    if !profile.dpd {
        info!("dead peer detection is turned off in the profile");
    } else if !dpd {
        warn!("the gateway did not negotiate dead peer detection: a dead tunnel will only be noticed by its users");
    }
    let dpd = dpd && profile.dpd;
    if profile.xauth {
        warn!(
            "XAuth with a group pre-shared key: anyone who knows the PSK can impersonate the gateway and \
             collect passwords; keep the PSK secret"
        );
    }
    let cancel = &ctx.cancel;

    if profile.xauth {
        xauth(&transport, &mut sa, profile, ctx).await?;
    }
    let (settings, mode) = match transport_port {
        None => {
            let attrs = mode_config(&transport, &mut sa, cancel).await?;
            (settings::build(&attrs, *gateway.ip())?, None)
        }
        Some(port) => {
            let rfc = encap == esp_attr::ENCAP_UDP_TUNNEL;
            encap = if rfc { esp_attr::ENCAP_UDP_TRANSPORT } else { esp_attr::ENCAP_UDP_TRANSPORT_DRAFT };
            let mode = TransportMode {
                local: local_ip,
                gateway: *gateway.ip(),
                port,
                nat_oa: if rfc { pt::NAT_OA } else { pt::NAT_OA_DRAFT },
            };
            // Nothing is assigned: the settings come from the layer above.
            (settings::transport(local_ip, *gateway.ip()), Some(mode))
        }
    };

    let quick = QuickParams {
        esp,
        encap,
        local: settings.address,
        transport: mode,
        lifetime: crate::lifetime(profile.phase2_lifetime),
        lifetime_kb: profile.phase2_lifetime_kb,
    };
    let init = QuickInit::start(&mut sa, &quick)?;
    let (child, remote_ts) = quick_request(&transport, &mut sa, cancel, init).await?;
    info!(address = %settings.address, routes = settings.routes.len(), "IKEv1 tunnel negotiated");
    Ok(Established { transport, sa, child, settings, quick, remote_ts, dpd, phase1_expiry, reauth, closed: false })
}

/// The gateway's identity against `remote_id`, if set.
pub(super) fn check_remote_id(remote_id: Option<&str>, idir: &Id) -> anyhow::Result<()> {
    if let Some(remote) = remote_id {
        let want = Identity::parse(remote);
        ensure!(
            want.id_type == idir.id_type && want.data == idir.data,
            "gateway identity {:?} (type {}) does not match remote_id {remote:?}",
            String::from_utf8_lossy(&idir.data),
            idir.id_type
        );
    }
    Ok(())
}

/// What both phase 1 exchanges start from.
struct Phase1Start<'a> {
    profile: &'a IpsecProfile,
    cancel: &'a CancellationToken,
    offered: &'a [Ike1Proposal],
    psk: &'a [u8],
    idii: Id,
    lifetime: Duration,
    auth_method: u64,
    natt_port: u16,
}

impl Phase1Start<'_> {
    fn vendor_ids(&self) -> Vec<Payload> {
        let mut vids =
            vec![&vid::NAT_T_RFC3947[..], &vid::NAT_T_DRAFT03, &vid::NAT_T_DRAFT02N, &vid::DPD, &vid::CISCO_UNITY];
        if self.profile.xauth {
            vids.push(&vid::XAUTH);
        }
        vids.into_iter().map(|v| Payload::VendorId(v.to_vec())).collect()
    }

    /// The gateway's identity against `remote_id`, if set.
    fn check_remote_id(&self, idir: &Id) -> anyhow::Result<()> {
        check_remote_id(self.profile.remote_id.as_deref(), idir)
    }
}

/// An established phase 1.
struct Phase1 {
    sa: IsakmpSa,
    algs: Ike1Proposal,
    life: Duration,
    encap: u64,
    dpd: bool,
}

/// NAT-T as the gateway announced it: the NAT-D payload type and the
/// UDP encapsulation mode.
pub(super) fn nat_traversal(msg: &Message) -> anyhow::Result<(u8, u64)> {
    if msg.has_vendor_id(&vid::NAT_T_RFC3947) {
        Ok((pt::NAT_D, esp_attr::ENCAP_UDP_TUNNEL))
    } else if msg.has_vendor_id(&vid::NAT_T_DRAFT03) || msg.has_vendor_id(&vid::NAT_T_DRAFT02N) {
        Ok((pt::NAT_D_DRAFT, esp_attr::ENCAP_UDP_TUNNEL_DRAFT))
    } else {
        bail!(
            "the gateway does not support NAT traversal, which this client requires \
             (enable nattraversal on the phase1)"
        )
    }
}

/// Our NAT-D payloads: the gateway's address, and a random one for ours
/// so the gateway always detects a NAT and encapsulates ESP in UDP.
pub(super) fn nat_d_payloads(prf: PrfAlg, kind: u8, cky_i: u64, cky_r: u64, transport: &Transport) -> [Payload; 2] {
    let peer = nat_d(prf, cky_i, cky_r, transport.peer());
    let fake = random_bytes(peer.len());
    [Payload::NatD { kind, hash: peer }, Payload::NatD { kind, hash: fake }]
}

/// Aggressive mode (RFC 2409 §5.4): three messages, identities in clear.
async fn aggressive_mode(transport: &mut Transport, start: Phase1Start<'_>) -> anyhow::Result<Phase1> {
    let Phase1Start { offered, psk, ref idii, lifetime: phase1_lifetime, auth_method, .. } = start;
    // A single KE: one DH group per attempt, the next one if the gateway
    // accepts none of this group's proposals.
    let mut groups: Vec<DhGroup> = Vec::new();
    for p in offered {
        if !groups.contains(&p.dh) {
            groups.push(p.dh);
        }
    }
    let mut attempt = 0;
    let (cky_i, kx, sa_i, p2) = loop {
        let group = groups[attempt];
        let ike: Vec<Ike1Proposal> = offered.iter().filter(|p| p.dh == group).copied().collect();
        // Message 1: SA, KE, Ni, IDii and vendor IDs.
        let cky_i = nonzero_u64();
        let kx = KeyExchange::generate(group)?;
        let ni = random_bytes(NONCE_LEN);
        let mut payloads = vec![
            Payload::Sa(vec![phase1_proposal(&ike, auth_method, phase1_lifetime)]),
            Payload::Ke(kx.public().to_vec()),
            Payload::Nonce(ni.clone()),
            Payload::Id(idii.clone()),
        ];
        payloads.extend(start.vendor_ids());
        let msg1 = build_plain(cky_i, 0, exchange::AGGRESSIVE, 0, &payloads);
        let sa_i = Message::parse_plain(&msg1)?.sa_body().expect("we sent an SA").to_vec();

        // Message 2: the gateway's choice, KE, Nr, IDir and HASH_R. A reply
        // failing any check is treated as noise (it may be forged) until the
        // retransmissions run out.
        let expect = Expect { exchange: exchange::AGGRESSIVE, cky_r: None, mode: "aggressive" };
        let reply = phase1_request(transport, start.cancel, &msg1, cky_i, expect, |raw| {
            let msg2 = Message::parse_plain(raw)?;
            let cky_r = msg2.header.cky_r;
            let (algs, life) = chosen_phase1(
                msg2.sa().context("no SA in aggressive mode response")?,
                &ike,
                auth_method,
                phase1_lifetime,
            )?;
            let gxr = msg2.ke().context("no KE in aggressive mode response")?;
            let nr = msg2.nonce().context("no nonce in aggressive mode response")?;
            ensure!((8..=256).contains(&nr.len()), "gateway nonce has an invalid length ({} bytes)", nr.len());
            let idir = msg2.ids().next().context("no IDir in aggressive mode response")?;
            let hash_r = msg2.hash().context("no HASH_R in aggressive mode response")?;
            let (nat_d_kind, encap) = nat_traversal(&msg2)?;
            let gxy = Zeroizing::new(kx.shared_secret(gxr)?);
            let keys = derive_phase1(algs.prf, algs.encr, psk, &ni, nr, &gxy, cky_i, cky_r, kx.public(), gxr)?;
            let expected = phase1_hash(algs.prf, &keys.skeyid, false, kx.public(), gxr, cky_i, cky_r, &sa_i, &idir.body());
            if !ct_eq(&expected, hash_r) {
                return Err(failure(
                    FailureKind::PskRejected,
                    "gateway authentication failed: its HASH_R does not match (the pre-shared key differs from the gateway's)",
                ));
            }
            start.check_remote_id(idir)?;
            Ok(Phase1Reply {
                cky_r,
                algs,
                life,
                gxr: gxr.to_vec(),
                keys,
                nat_d_kind,
                encap,
                dpd: msg2.has_vendor_id(&vid::DPD),
            })
        })
        .await;
        match reply {
            Ok(p2) => break (cky_i, kx, sa_i, p2),
            Err(e) if e.is::<NoProposalChosen>() && attempt + 1 < groups.len() => {
                attempt += 1;
                info!("the gateway refused DH group {}; trying group {}", group.id(), groups[attempt].id());
            }
            Err(e) => return Err(e),
        }
    };
    let Phase1Reply { cky_r, algs, life, gxr, keys, nat_d_kind, encap, dpd } = p2;

    // Message 3: HASH_I and NAT-D, sent unencrypted from port 4500.
    let hash_i = phase1_hash(algs.prf, &keys.skeyid, true, kx.public(), &gxr, cky_i, cky_r, &sa_i, &idii.body());
    let mut payloads = vec![Payload::Hash(hash_i)];
    payloads.extend(nat_d_payloads(algs.prf, nat_d_kind, cky_i, cky_r, transport));
    let msg3 = build_plain(cky_i, cky_r, exchange::AGGRESSIVE, 0, &payloads);
    transport.switch_to_natt(start.natt_port).await?;
    transport.send_ike(&msg3).await?;
    // No phase 1 message was encrypted: phase 2 IVs start from the first.
    let iv0 = keys.iv0.clone();
    Ok(Phase1 { sa: IsakmpSa::new(cky_i, cky_r, algs.prf, keys, iv0), algs, life, encap, dpd })
}

/// Main mode (RFC 2409 §5, identity protection): SA, then the key
/// exchange, then the identities and hashes encrypted, from port 4500.
async fn main_mode(transport: &mut Transport, start: Phase1Start<'_>) -> anyhow::Result<Phase1> {
    let Phase1Start { offered, psk, ref idii, lifetime: ours, auth_method, cancel, .. } = start;
    // Message 1: every proposal, whatever its group (no KE yet).
    let cky_i = nonzero_u64();
    let mut payloads = vec![Payload::Sa(vec![phase1_proposal(offered, auth_method, ours)])];
    payloads.extend(start.vendor_ids());
    let msg1 = build_plain(cky_i, 0, exchange::IDENTITY_PROTECTION, 0, &payloads);
    let sa_i = Message::parse_plain(&msg1)?.sa_body().expect("we sent an SA").to_vec();

    // Message 2: the gateway's choice. It is only authenticated by HASH_R
    // (which covers our offer), so it must be one of our transforms.
    let expect = Expect { exchange: exchange::IDENTITY_PROTECTION, cky_r: None, mode: "main" };
    let (cky_r, algs, life, nat_d_kind, encap, dpd) = phase1_request(transport, cancel, &msg1, cky_i, expect, |raw| {
        let msg2 = Message::parse_plain(raw)?;
        let (algs, life) =
            chosen_phase1(msg2.sa().context("no SA in main mode response")?, offered, auth_method, ours)?;
        let (kind, encap) = nat_traversal(&msg2)?;
        Ok((msg2.header.cky_r, algs, life, kind, encap, msg2.has_vendor_id(&vid::DPD)))
    })
    .await?;

    // Messages 3 and 4: KE, nonces and NAT-D.
    let kx = KeyExchange::generate(algs.dh)?;
    let ni = random_bytes(NONCE_LEN);
    let mut payloads = vec![Payload::Ke(kx.public().to_vec()), Payload::Nonce(ni.clone())];
    payloads.extend(nat_d_payloads(algs.prf, nat_d_kind, cky_i, cky_r, transport));
    let msg3 = build_plain(cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, &payloads);
    let expect = Expect { exchange: exchange::IDENTITY_PROTECTION, cky_r: Some(cky_r), mode: "main" };
    let (gxr, keys) = phase1_request(transport, cancel, &msg3, cky_i, expect, |raw| {
        let msg4 = Message::parse_plain(raw)?;
        let gxr = msg4.ke().context("no KE in main mode message 4")?;
        let nr = msg4.nonce().context("no nonce in main mode message 4")?;
        ensure!((8..=256).contains(&nr.len()), "gateway nonce has an invalid length ({} bytes)", nr.len());
        let gxy = Zeroizing::new(kx.shared_secret(gxr)?);
        let keys = derive_phase1(algs.prf, algs.encr, psk, &ni, nr, &gxy, cky_i, cky_r, kx.public(), gxr)?;
        Ok((gxr.to_vec(), keys))
    })
    .await?;

    // Messages 5 and 6, encrypted: IDii and HASH_I, IDir and HASH_R. The
    // gateway expects them on port 4500 once it saw a NAT.
    let hash_i = phase1_hash(algs.prf, &keys.skeyid, true, kx.public(), &gxr, cky_i, cky_r, &sa_i, &idii.body());
    let (first, body) = encode_chain(&[Payload::Id(idii.clone()), Payload::Hash(hash_i)]);
    let (msg5, iv) = encrypt(&keys.cipher, &keys.iv0, cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, first, &body);
    transport.switch_to_natt(start.natt_port).await?;
    let expect = Expect { exchange: exchange::IDENTITY_PROTECTION, cky_r: Some(cky_r), mode: "main" };
    let reply = phase1_request(transport, cancel, &msg5, cky_i, expect, |raw| {
        let (msg6, next_iv) = decrypt(&keys.cipher, &iv, raw)?;
        let idir = msg6.ids().next().context("no IDir in main mode message 6")?;
        let hash_r = msg6.hash().context("no HASH_R in main mode message 6")?;
        let expected = phase1_hash(algs.prf, &keys.skeyid, false, kx.public(), &gxr, cky_i, cky_r, &sa_i, &idir.body());
        ensure!(ct_eq(&expected, hash_r), "gateway HASH_R does not match");
        start.check_remote_id(idir)?;
        Ok(next_iv)
    })
    .await;
    let phase1_iv = match reply {
        Ok(iv) => iv,
        // A wrong PSK gives keys the gateway cannot decrypt message 5 with.
        Err(e) if vpn_core::failure::kind_of(&e) == FailureKind::Unreachable || format!("{e:#}").contains("HASH_R") => {
            return Err(failure(
                FailureKind::PskRejected,
                format!(
                    "the gateway did not accept our identity (main mode message 5): the pre-shared key probably \
                     differs from the gateway's, or the gateway expects another local ID ({e:#})"
                ),
            ));
        }
        Err(e) => return Err(e),
    };
    // Phase 2 IVs start from the last block of message 6.
    Ok(Phase1 { sa: IsakmpSa::new(cky_i, cky_r, algs.prf, keys, phase1_iv), algs, life, encap, dpd })
}

/// What a valid aggressive mode message 2 established.
struct Phase1Reply {
    cky_r: u64,
    algs: Ike1Proposal,
    life: Duration,
    gxr: Vec<u8>,
    keys: super::keys::Phase1Keys,
    nat_d_kind: u8,
    encap: u64,
    dpd: bool,
}

/// Parses the profile proposals. Quick Mode carries a single PFS KE: keep
/// the ESP proposals using the first group.
fn proposals(profile: &IpsecProfile) -> anyhow::Result<(Vec<Ike1Proposal>, Vec<EspProposal>)> {
    crate::check_legacy(profile)?;
    let ike: Vec<Ike1Proposal> = profile.ike.iter().map(|s| proposal::parse_ike1(s)).collect::<anyhow::Result<_>>()?;
    let mut esp: Vec<EspProposal> =
        profile.esp.iter().map(|s| proposal::parse_esp1(s)).collect::<anyhow::Result<_>>()?;
    ensure!(!ike.is_empty() && !esp.is_empty(), "profile has no IKE or ESP proposal");
    let pfs = esp[0].pfs;
    let n_esp = esp.len();
    esp.retain(|p| p.pfs == pfs);
    if esp.len() != n_esp {
        warn!("Quick Mode sends a single KE: ESP proposals with another PFS group than the first one are ignored");
    }
    Ok((ike, esp))
}

pub(super) fn hash_attr(prf: PrfAlg) -> u64 {
    match prf {
        PrfAlg::HmacSha1 => ike_attr::HASH_SHA1,
        PrfAlg::HmacSha256 => ike_attr::HASH_SHA256,
        PrfAlg::HmacSha384 => ike_attr::HASH_SHA384,
        PrfAlg::HmacSha512 => ike_attr::HASH_SHA512,
    }
}

fn phase1_proposal(offered: &[Ike1Proposal], auth_method: u64, lifetime: Duration) -> Proposal {
    let transforms = offered
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut attrs = vec![SaAttr { kind: ike_attr::ENCRYPTION, value: phase1_encryption(p.encr) }];
            if let Some(bits) = p.encr.key_bits() {
                attrs.push(SaAttr { kind: ike_attr::KEY_LENGTH, value: u64::from(bits) });
            }
            attrs.extend([
                SaAttr { kind: ike_attr::HASH, value: hash_attr(p.prf) },
                SaAttr { kind: ike_attr::AUTH_METHOD, value: auth_method },
                SaAttr { kind: ike_attr::GROUP, value: u64::from(p.dh.id()) },
                SaAttr { kind: ike_attr::LIFE_TYPE, value: ike_attr::LIFE_SECONDS },
                SaAttr { kind: ike_attr::LIFE_DURATION, value: lifetime.as_secs() },
            ]);
            Transform { num: i as u8 + 1, id: ike_attr::TRANSFORM_KEY_IKE, attrs }
        })
        .collect();
    Proposal { num: 1, protocol: protocol::ISAKMP, spi: Vec::new(), transforms }
}

/// Maps the gateway's single transform back to one we offered.
fn chosen_phase1(
    chosen: &[Proposal],
    offered: &[Ike1Proposal],
    auth_method: u64,
    ours: Duration,
) -> anyhow::Result<(Ike1Proposal, Duration)> {
    let [Proposal { transforms, .. }] = chosen else { bail!("gateway returned {} phase 1 proposals", chosen.len()) };
    let [t] = transforms.as_slice() else { bail!("gateway returned {} phase 1 transforms", transforms.len()) };
    ensure!(t.attr(ike_attr::AUTH_METHOD) == Some(auth_method), "gateway chose another authentication method");
    let found = offered
        .iter()
        .find(|p| {
            t.attr(ike_attr::ENCRYPTION) == Some(phase1_encryption(p.encr))
                && t.attr(ike_attr::KEY_LENGTH) == p.encr.key_bits().map(u64::from)
                && t.attr(ike_attr::HASH) == Some(hash_attr(p.prf))
                && t.attr(ike_attr::GROUP) == Some(u64::from(p.dh.id()))
        })
        .copied()
        .context("gateway chose a phase 1 transform we did not offer")?;
    // The lifetime is outside HASH_R: ignore absurdly short values that
    // would force a reconnection loop.
    let life = match (t.attr(ike_attr::LIFE_TYPE), t.attr(ike_attr::LIFE_DURATION)) {
        (Some(ike_attr::LIFE_SECONDS), Some(secs)) if secs >= MIN_LIFETIME.as_secs() => {
            Duration::from_secs(secs).min(ours)
        }
        _ => ours,
    };
    Ok((found, life))
}

/// The gateway answered NO-PROPOSAL-CHOSEN to message 1.
#[derive(Debug)]
struct NoProposalChosen;

impl std::fmt::Display for NoProposalChosen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&notify::describe(notify::NO_PROPOSAL_CHOSEN))
    }
}

impl std::error::Error for NoProposalChosen {}

/// The phase 1 reply awaited.
struct Expect {
    exchange: u8,
    /// The gateway's cookie, once known.
    cky_r: Option<u64>,
    mode: &'static str,
}

/// Sends a phase 1 message and waits for the reply that passes
/// `validate` (given the raw message). Unencrypted error notifications and
/// invalid replies cannot be trusted: they are only reported if no valid
/// response arrives.
async fn phase1_request<T>(
    transport: &Transport,
    cancel: &CancellationToken,
    msg1: &[u8],
    cky_i: u64,
    expect: Expect,
    validate: impl Fn(&[u8]) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut wait = Duration::from_secs(1);
    let mut last_error = None;
    // Once an invalid reply arrived the gateway is reachable: stop
    // retransmitting and give a genuine reply a short grace period.
    let mut give_up: Option<tokio::time::Instant> = None;
    'attempts: for _ in 0..MAX_TRIES {
        transport.send_ike(msg1).await?;
        let mut deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(g) = give_up {
                deadline = deadline.min(g);
            }
            let datagram = tokio::select! {
                _ = cancel.cancelled() => bail!("cancelled"),
                r = tokio::time::timeout_at(deadline, transport.recv()) => match r {
                    Err(_) if give_up.is_some() => break 'attempts,
                    Err(_) => break,
                    Ok(r) => r?,
                },
            };
            let crate::transport::Datagram::Ike(raw) = datagram else { continue };
            let Ok(header) = Header::decode(&raw) else { continue };
            if header.cky_i != cky_i {
                continue;
            }
            let ours = expect.cky_r.map_or(header.cky_r != 0, |c| header.cky_r == c);
            match header.exchange {
                kind if kind == expect.exchange && ours && header.msg_id == 0 => match validate(&raw) {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        debug!("ignoring {} mode reply: {e:#}", expect.mode);
                        last_error = Some(e);
                        give_up.get_or_insert(tokio::time::Instant::now() + INVALID_REPLY_GRACE);
                    }
                },
                exchange::INFORMATIONAL => {
                    let Ok(msg) = Message::parse_plain(&raw) else { continue };
                    if let Some(n) = msg.notifies().find(|n| n.is_error()) {
                        last_error = Some(if n.kind == notify::NO_PROPOSAL_CHOSEN {
                            // Unauthenticated: only acted on if nothing valid follows.
                            give_up.get_or_insert(tokio::time::Instant::now() + INVALID_REPLY_GRACE);
                            anyhow::Error::new(NoProposalChosen)
                        } else {
                            anyhow::anyhow!(notify::describe(n.kind))
                        });
                    }
                }
                _ => {}
            }
        }
        wait = (wait * 2).min(Duration::from_secs(8));
    }
    match last_error {
        Some(e) if e.is::<NoProposalChosen>() => Err(e),
        Some(e) => Err(e.context("phase 1 failed")),
        None => Err(failure(
            FailureKind::Unreachable,
            format!(
                "no response from {} (UDP {} filtered, gateway down, or phase1 not in {} mode?)",
                transport.peer().ip(),
                transport.peer().port(),
                expect.mode
            ),
        )),
    }
}

/// Authenticated Informational received during setup: answers DPD and
/// turns errors and deletes into failures.
async fn handle_info(transport: &Transport, sa: &mut IsakmpSa, inc: Incoming) -> anyhow::Result<()> {
    if sa.verify(&inc.msg, &[]).is_err() {
        debug!("dropping unauthenticated Informational");
        return Ok(());
    }
    sa.forget(inc.msg.header.msg_id);
    for info in classify_informational(&inc.msg) {
        match info {
            Info::RuThere(seq) => {
                let ack = dpd_notify(sa, notify::R_U_THERE_ACK, seq);
                send_informational(transport, sa, ack).await?;
            }
            Info::Error(e) => bail!("gateway reported {e}"),
            Info::DeleteIsakmp(_) => bail!("gateway deleted the IKE SA during setup"),
            _ => {}
        }
    }
    Ok(())
}

fn attr_payload(msg: &Message) -> Option<(u8, u16, &[CfgAttr])> {
    msg.iter().find_map(|p| match p {
        Payload::Attr { cfg_type, identifier, attrs } => Some((*cfg_type, *identifier, attrs.as_slice())),
        _ => None,
    })
}

/// XAuth, driven by the gateway: REQUEST → REPLY, then SET(status) → ACK.
async fn xauth(
    transport: &Transport,
    sa: &mut IsakmpSa,
    profile: &IpsecProfile,
    ctx: &SessionContext,
) -> anyhow::Result<()> {
    let mut rounds = 0;
    // Our last reply, resent if the gateway retransmits its request.
    let mut last: Option<(Vec<u8>, Vec<u8>)> = None;
    // Only messages that move XAuth forward extend the wait, so injected
    // noise cannot stall the setup.
    let mut deadline = tokio::time::Instant::now() + XAUTH_WAIT;
    loop {
        let Some(inc) = next_message(transport, sa, &ctx.cancel, deadline, last.as_ref()).await? else {
            if rounds == 0 {
                bail!("the gateway did not start XAuth (check xauth and the user group on the phase1)");
            }
            bail!("the gateway did not confirm XAuth");
        };
        match inc.msg.header.exchange {
            exchange::INFORMATIONAL => {
                handle_info(transport, sa, inc).await?;
                continue;
            }
            exchange::TRANSACTION => {}
            other => {
                debug!(exchange = other, "ignoring message during XAuth");
                continue;
            }
        }
        if sa.verify(&inc.msg, &[]).is_err() {
            debug!("dropping unauthenticated Transaction");
            continue;
        }
        let msg_id = inc.msg.header.msg_id;
        sa.commit(msg_id, inc.next_iv);
        let Some((cfg_type, identifier, attrs)) = attr_payload(&inc.msg) else { continue };
        deadline = tokio::time::Instant::now() + XAUTH_WAIT;
        match cfg_type {
            cfg::REQUEST => {
                rounds += 1;
                if rounds > MAX_XAUTH_ROUNDS {
                    return Err(failure(FailureKind::AuthFailed, "XAuth: the gateway rejected the credentials"));
                }
                let answers = xauth_answers(attrs, profile, ctx).await?;
                let mut payload = [Payload::Attr { cfg_type: cfg::REPLY, identifier, attrs: answers }];
                let reply = sa.seal(exchange::TRANSACTION, msg_id, &[], &payload);
                // Wipe the password / OTP copies.
                if let Payload::Attr { attrs, .. } = &mut payload[0] {
                    for a in attrs {
                        if let CfgValue::Var(v) = &mut a.value {
                            v.zeroize();
                        }
                    }
                }
                sa.forget(msg_id);
                transport.send_ike(&reply).await?;
                last = Some((inc.raw, reply));
            }
            cfg::SET => {
                let status = attrs.iter().find(|a| a.kind == cfg::XAUTH_STATUS).and_then(CfgAttr::number);
                let message =
                    attrs.iter().find(|a| a.kind == cfg::XAUTH_MESSAGE).map(|a| String::from_utf8_lossy(a.bytes()));
                let ack = Payload::Attr {
                    cfg_type: cfg::ACK,
                    identifier,
                    attrs: vec![CfgAttr {
                        kind: cfg::XAUTH_STATUS,
                        value: CfgValue::Basic(status.unwrap_or(0) as u16),
                    }],
                };
                let bytes = sa.seal(exchange::TRANSACTION, msg_id, &[], &[ack]);
                sa.forget(msg_id);
                transport.send_ike(&bytes).await?;
                if status == Some(1) {
                    info!("XAuth succeeded");
                    return Ok(());
                }
                let detail = message.map(|m| format!(" ({m})")).unwrap_or_default();
                return Err(failure(
                    FailureKind::AuthFailed,
                    format!("XAuth failed{detail}: wrong username or password"),
                ));
            }
            other => debug!(cfg_type = other, "ignoring XAuth message"),
        }
    }
}

async fn xauth_answers(
    attrs: &[CfgAttr],
    profile: &IpsecProfile,
    ctx: &SessionContext,
) -> anyhow::Result<Vec<CfgAttr>> {
    let message = attrs
        .iter()
        .find(|a| a.kind == cfg::XAUTH_MESSAGE)
        .map(|a| String::from_utf8_lossy(a.bytes()).trim().to_owned())
        .filter(|m| !m.is_empty());
    let ask = |key: &str, kind: PromptKind, text: String| ctx.prompter.ask(Prompt::new(key, kind, text));
    let mut out = Vec::new();
    for a in attrs {
        let value = match a.kind {
            cfg::XAUTH_TYPE => {
                out.push(CfgAttr { kind: a.kind, value: CfgValue::Basic(a.number().unwrap_or(0) as u16) });
                continue;
            }
            cfg::XAUTH_USER_NAME => match &profile.username {
                Some(u) => Zeroizing::new(u.clone()),
                None => ask("username", PromptKind::Text, format!("XAuth username for {}", ctx.name)).await?,
            },
            cfg::XAUTH_USER_PASSWORD => {
                let user = profile.username.as_deref().unwrap_or("XAuth");
                ask("password", PromptKind::Secret, format!("Password for {user}@{}", profile.gateway)).await?
            }
            cfg::XAUTH_PASSCODE | cfg::XAUTH_ANSWER | cfg::XAUTH_NEXT_PIN => {
                let text = message.clone().unwrap_or_else(|| "FortiToken / one-time code".into());
                ask("otp", PromptKind::Otp, text).await?
            }
            _ => continue,
        };
        out.push(CfgAttr::var(a.kind, value.as_bytes()));
    }
    Ok(out)
}

/// Mode-Config pull: REQUEST → REPLY. A gateway pushing a SET instead is
/// acknowledged and its attributes used.
async fn mode_config(
    transport: &Transport,
    sa: &mut IsakmpSa,
    cancel: &CancellationToken,
) -> anyhow::Result<Vec<CfgAttr>> {
    let msg_id = random_msg_id();
    let identifier = nonzero_u32() as u16;
    let wanted = [
        cfg::INTERNAL_IP4_ADDRESS,
        cfg::INTERNAL_IP4_NETMASK,
        cfg::INTERNAL_IP4_DNS,
        cfg::INTERNAL_IP4_SUBNET,
        cfg::UNITY_DEF_DOMAIN,
        cfg::UNITY_SPLITDNS_NAME,
        cfg::UNITY_SPLIT_INCLUDE,
    ];
    let request = sa.seal(
        exchange::TRANSACTION,
        msg_id,
        &[],
        &[Payload::Attr {
            cfg_type: cfg::REQUEST,
            identifier,
            attrs: wanted.iter().map(|k| CfgAttr::empty(*k)).collect(),
        }],
    );
    let mut wait = Duration::from_secs(1);
    for _ in 0..MAX_TRIES {
        transport.send_ike(&request).await?;
        let deadline = tokio::time::Instant::now() + wait;
        while let Some(inc) = next_message(transport, sa, cancel, deadline, None).await? {
            match inc.msg.header.exchange {
                exchange::INFORMATIONAL => {
                    handle_info(transport, sa, inc).await?;
                    continue;
                }
                exchange::TRANSACTION => {}
                _ => continue,
            }
            if sa.verify(&inc.msg, &[]).is_err() {
                debug!("dropping unauthenticated Transaction");
                continue;
            }
            let id = inc.msg.header.msg_id;
            sa.commit(id, inc.next_iv);
            let Some((cfg_type, ident, attrs)) = attr_payload(&inc.msg) else { continue };
            match cfg_type {
                cfg::REPLY if id == msg_id => {
                    sa.forget(msg_id);
                    return Ok(attrs.to_vec());
                }
                // A pushed configuration: on its own exchange, carrying an address.
                cfg::SET if id != msg_id && attrs.iter().any(|a| a.kind == cfg::INTERNAL_IP4_ADDRESS) => {
                    let acked = attrs.iter().map(|a| CfgAttr::empty(a.kind)).collect();
                    let ack = sa.seal(
                        exchange::TRANSACTION,
                        id,
                        &[],
                        &[Payload::Attr { cfg_type: cfg::ACK, identifier: ident, attrs: acked }],
                    );
                    sa.forget(id);
                    sa.forget(msg_id);
                    transport.send_ike(&ack).await?;
                    return Ok(attrs.to_vec());
                }
                _ if id != msg_id => sa.forget(id),
                _ => {}
            }
        }
        wait = (wait * 2).min(Duration::from_secs(8));
    }
    bail!("no Mode-Config reply from the gateway (enable mode-cfg on the phase1)")
}

/// A Quick Mode we initiated, waiting for the gateway's HASH(2) message.
pub(super) struct QuickInit {
    pub msg_id: u32,
    pub bytes: Vec<u8>,
    ni: Vec<u8>,
    kx: Option<KeyExchange>,
    spi: u32,
    offered: Vec<EspProposal>,
    lifetime: Duration,
    lifetime_kb: Option<u64>,
}

impl QuickInit {
    /// Builds message 1: HASH(1), SA, Ni, [KE], IDci (our address), IDcr (any).
    pub fn start(sa: &mut IsakmpSa, q: &QuickParams) -> anyhow::Result<Self> {
        let msg_id = random_msg_id();
        let spi = nonzero_u32();
        let ni = random_bytes(NONCE_LEN);
        let kx = q.esp[0].pfs.map(KeyExchange::generate).transpose()?;
        let transforms = q
            .esp
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut attrs = Vec::new();
                if q.lifetime != crate::NO_TIME_LIMIT {
                    attrs.push(SaAttr { kind: esp_attr::LIFE_TYPE, value: esp_attr::LIFE_SECONDS });
                    attrs.push(SaAttr { kind: esp_attr::LIFE_DURATION, value: q.lifetime.as_secs() });
                }
                if let Some(kb) = q.lifetime_kb {
                    attrs.push(SaAttr { kind: esp_attr::LIFE_TYPE, value: esp_attr::LIFE_KILOBYTES });
                    attrs.push(SaAttr { kind: esp_attr::LIFE_DURATION, value: kb });
                }
                attrs.push(SaAttr { kind: esp_attr::ENCAPSULATION, value: q.encap });
                if let Some(integ) = p.integ {
                    attrs.push(SaAttr { kind: esp_attr::AUTH_ALG, value: auth_alg(integ) });
                }
                if let Some(bits) = p.encr.key_bits() {
                    attrs.push(SaAttr { kind: esp_attr::KEY_LENGTH, value: u64::from(bits) });
                }
                if let Some(g) = p.pfs {
                    attrs.push(SaAttr { kind: esp_attr::GROUP, value: u64::from(g.id()) });
                }
                Transform { num: i as u8 + 1, id: esp_transform(p.encr), attrs }
            })
            .collect();
        let mut payloads = vec![
            Payload::Sa(vec![Proposal {
                num: 1,
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms,
            }]),
            Payload::Nonce(ni.clone()),
        ];
        if let Some(kx) = &kx {
            payloads.push(Payload::Ke(kx.public().to_vec()));
        }
        match q.transport {
            None => {
                payloads.push(Payload::Id(Id {
                    id_type: id_type::IPV4_ADDR,
                    protocol: 0,
                    port: 0,
                    data: q.local.octets().to_vec(),
                }));
                payloads.push(Payload::Id(Id {
                    id_type: id_type::IPV4_ADDR_SUBNET,
                    protocol: 0,
                    port: 0,
                    data: vec![0; 8],
                }));
            }
            Some(t) => {
                // Our address and the gateway's, for that UDP port only;
                // NAT-OA lets the gateway undo the NAT on checksums
                // (RFC 3947 §5.2).
                for addr in [t.local, t.gateway] {
                    payloads.push(Payload::Id(Id {
                        id_type: id_type::IPV4_ADDR,
                        protocol: crate::esp::NEXT_HEADER_UDP,
                        port: t.port,
                        data: addr.octets().to_vec(),
                    }));
                }
                for addr in [t.local, t.gateway] {
                    let body = [&[id_type::IPV4_ADDR, 0, 0, 0][..], &addr.octets()].concat();
                    payloads.push(Payload::Unknown { kind: t.nat_oa, body });
                }
            }
        }
        let bytes = sa.seal(exchange::QUICK, msg_id, &[], &payloads);
        Ok(Self {
            msg_id,
            bytes,
            ni,
            kx,
            spi,
            offered: q.esp.clone(),
            lifetime: q.lifetime,
            lifetime_kb: q.lifetime_kb,
        })
    }

    /// Whether `inc` is the authentic HASH(2) answer to this Quick Mode.
    pub fn accepts(&self, sa: &IsakmpSa, inc: &Incoming) -> bool {
        inc.msg.header.exchange == exchange::QUICK
            && inc.msg.header.msg_id == self.msg_id
            && sa.verify(&inc.msg, &self.ni).is_ok()
    }

    /// Processes the (already accepted) answer: returns the new SAs, the
    /// gateway's selectors and HASH(3), to send.
    pub fn finish(self, sa: &mut IsakmpSa, inc: Incoming) -> anyhow::Result<(Phase2, Vec<TrafficSelector>, Vec<u8>)> {
        sa.commit(self.msg_id, inc.next_iv);
        let msg = &inc.msg;
        let nr = msg.nonce().context("Quick Mode response has no nonce")?;
        ensure!((8..=256).contains(&nr.len()), "gateway nonce has an invalid length ({} bytes)", nr.len());
        let (algs, peer_spi, mut lifetime) =
            chosen_phase2(msg.sa().context("Quick Mode response has no SA")?, &self.offered, self.lifetime)?;
        let gxy = match (&self.kx, msg.ke()) {
            (Some(kx), Some(ke)) => Some(Zeroizing::new(kx.shared_secret(ke)?)),
            (Some(_), None) => bail!("gateway refused PFS"),
            (None, _) => None,
        };
        // What the gateway said about the lifetime, for the log: some
        // gateways answer a longer one than offered.
        let answered = msg
            .sa()
            .and_then(|p| p.first())
            .and_then(|p| p.transforms.first())
            .and_then(|t| t.attr(esp_attr::LIFE_DURATION));
        let mut notified = None;
        for n in msg.notifies() {
            if n.kind == notify::RESPONDER_LIFETIME
                && let Ok(attrs) = decode_sa_attrs(&n.data)
                && let Some(secs) = attrs.iter().find(|a| a.kind == esp_attr::LIFE_DURATION).map(|a| a.value)
            {
                notified = Some(secs);
                if secs >= MIN_LIFETIME.as_secs() {
                    lifetime = lifetime.min(Duration::from_secs(secs));
                }
            }
        }
        let remote_ts = match msg.ids().nth(1) {
            Some(id) => vec![selector(id)?],
            None => vec![TrafficSelector::any()],
        };

        let gxy = gxy.as_deref().map(Vec::as_slice);
        let sa_pair = |spi: u32| -> anyhow::Result<EspSa> {
            let (enc, auth) =
                keymat(sa.prf, &sa.skeyid_d, gxy, protocol::ESP, spi, &self.ni, nr, algs.encr, algs.integ);
            Ok(EspSa::new(spi, Cipher::new(algs.encr, algs.integ, &enc, &auth)?))
        };
        let child = Phase2 {
            inbound: sa_pair(self.spi)?,
            outbound: sa_pair(peer_spi)?,
            created: Instant::now(),
            lifetime,
            lifetime_kb: self.lifetime_kb,
        };
        let hash3 = sa.prf.compute(&sa.skeyid_a, &[&[0], &self.msg_id.to_be_bytes(), &self.ni, nr]);
        let msg3 = sa.seal_with_hash(exchange::QUICK, self.msg_id, hash3, pt::NONE, &[]);
        sa.forget(self.msg_id);
        info!(
            ?algs,
            inbound = format_args!("{:08x}", self.spi),
            outbound = format_args!("{peer_spi:08x}"),
            offered_lifetime_s = self.lifetime.as_secs(),
            gateway_lifetime_s = answered,
            responder_lifetime_s = notified,
            lifetime_s = child.lifetime.as_secs(),
            "IPsec SAs established"
        );
        Ok((child, remote_ts, msg3))
    }
}

/// A Quick Mode the gateway started (its own rekey), answered with
/// HASH(2) and waiting for its HASH(3).
pub(super) struct QuickResponse {
    pub msg_id: u32,
    /// The gateway's message 1, and our answer to resend if it repeats it.
    pub request: Vec<u8>,
    pub bytes: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    child: Phase2,
}

impl QuickResponse {
    /// Answers the gateway's message 1 (already decrypted): checks HASH(1),
    /// picks one of its transforms among ours, derives the SAs.
    pub fn answer(sa: &mut IsakmpSa, inc: Incoming, q: &QuickParams) -> anyhow::Result<Self> {
        let msg = &inc.msg;
        let msg_id = msg.header.msg_id;
        sa.verify(msg, &[]).context("invalid HASH(1) in the gateway's Quick Mode")?;
        sa.commit(msg_id, inc.next_iv.clone());
        let ni = msg.nonce().context("Quick Mode without a nonce")?.to_vec();
        ensure!((8..=256).contains(&ni.len()), "gateway nonce has an invalid length ({} bytes)", ni.len());
        let proposals = msg.sa().context("Quick Mode without an SA")?;
        let (proposal, transform, chosen) = proposals
            .iter()
            .filter(|p| p.protocol == protocol::ESP && p.spi.len() == 4)
            .flat_map(|p| p.transforms.iter().map(move |t| (p, t)))
            .find_map(|(p, t)| {
                q.esp
                    .iter()
                    .find(|o| {
                        t.id == esp_transform(o.encr)
                            && t.attr(esp_attr::KEY_LENGTH) == o.encr.key_bits().map(u64::from)
                            && t.attr(esp_attr::AUTH_ALG) == o.integ.map(auth_alg)
                    })
                    .map(|o| (p, t, *o))
            })
            .context("the gateway's rekey offers no transform of ours")?;
        let peer_spi = u32::from_be_bytes(proposal.spi.as_slice().try_into().unwrap());
        ensure!(peer_spi > 255, "gateway chose a reserved ESP SPI");
        // PFS as the gateway asks, with its group.
        let group = transform.attr(esp_attr::GROUP).map(|g| {
            u16::try_from(g)
                .ok()
                .and_then(DhGroup::from_id)
                .with_context(|| format!("the gateway's rekey uses unsupported DH group {g}"))
        });
        let group = group.transpose()?;
        // Never weaker than what we negotiate ourselves: our PFS group when
        // the profile has one; otherwise no PFS, or a group that is not
        // legacy unless we offer it.
        let weak = |g: DhGroup| matches!(g, DhGroup::Modp1024 | DhGroup::Modp1536);
        match (chosen.pfs, group) {
            (Some(ours), Some(g)) if g == ours => {}
            (Some(ours), other) => bail!(
                "the gateway's rekey uses {}, not the profile's PFS group {}",
                other.map_or("no PFS".into(), |g| format!("DH group {}", g.id())),
                ours.id()
            ),
            (None, Some(g)) if weak(g) && !q.esp.iter().any(|o| o.pfs == Some(g)) => {
                bail!("the gateway's rekey uses the weak DH group {}", g.id())
            }
            (None, _) => {}
        }
        let (kx, gxy) = match (group, msg.ke()) {
            (Some(g), Some(ke)) => {
                let kx = KeyExchange::generate(g)?;
                let gxy = Zeroizing::new(kx.shared_secret(ke)?);
                (Some(kx), Some(gxy))
            }
            (Some(_), None) => bail!("the gateway's rekey asks for PFS without a key exchange"),
            (None, _) => (None, None),
        };
        let lifetime = match (transform.attr(esp_attr::LIFE_TYPE), transform.attr(esp_attr::LIFE_DURATION)) {
            // Never longer than ours: a huge value would overflow the
            // rekey deadline.
            (Some(esp_attr::LIFE_SECONDS), Some(secs)) if secs >= MIN_LIFETIME.as_secs() => {
                Duration::from_secs(secs).min(q.lifetime)
            }
            _ => q.lifetime,
        };
        let spi = nonzero_u32();
        let nr = random_bytes(NONCE_LEN);
        let mut payloads = vec![
            Payload::Sa(vec![Proposal {
                num: proposal.num,
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms: vec![transform.clone()],
            }]),
            Payload::Nonce(nr.clone()),
        ];
        if let Some(kx) = &kx {
            payloads.push(Payload::Ke(kx.public().to_vec()));
        }
        // The identities as the gateway sent them.
        payloads.extend(msg.ids().cloned().map(Payload::Id));
        if let Some(t) = q.transport {
            for addr in [t.gateway, t.local] {
                let body = [&[id_type::IPV4_ADDR, 0, 0, 0][..], &addr.octets()].concat();
                payloads.push(Payload::Unknown { kind: t.nat_oa, body });
            }
        }
        let bytes = sa.seal(exchange::QUICK, msg_id, &ni, &payloads);
        let gxy = gxy.as_deref().map(Vec::as_slice);
        let sa_pair = |spi: u32| -> anyhow::Result<EspSa> {
            let (enc, auth) =
                keymat(sa.prf, &sa.skeyid_d, gxy, protocol::ESP, spi, &ni, &nr, chosen.encr, chosen.integ);
            Ok(EspSa::new(spi, Cipher::new(chosen.encr, chosen.integ, &enc, &auth)?))
        };
        let child = Phase2 {
            inbound: sa_pair(spi)?,
            outbound: sa_pair(peer_spi)?,
            created: Instant::now(),
            lifetime,
            lifetime_kb: q.lifetime_kb,
        };
        debug!(
            inbound = format_args!("{spi:08x}"),
            outbound = format_args!("{peer_spi:08x}"),
            "answered the gateway's Quick Mode"
        );
        Ok(Self { msg_id, request: inc.raw, bytes, ni, nr, child })
    }

    /// Whether `msg` is the gateway's authentic HASH(3) for this exchange.
    pub fn completes(&self, sa: &IsakmpSa, msg: &Message) -> bool {
        let expected = sa.prf.compute(&sa.skeyid_a, &[&[0], &self.msg_id.to_be_bytes(), &self.ni, &self.nr]);
        msg.header.exchange == exchange::QUICK
            && msg.header.msg_id == self.msg_id
            && msg.hash().is_some_and(|h| ct_eq(h, &expected))
    }

    pub fn finish(self, sa: &mut IsakmpSa) -> Phase2 {
        sa.forget(self.msg_id);
        self.child
    }
}

fn auth_alg(integ: IntegAlg) -> u64 {
    match integ {
        IntegAlg::HmacSha1Trunc96 => esp_attr::AUTH_HMAC_SHA1,
        IntegAlg::HmacSha256Trunc128 => esp_attr::AUTH_HMAC_SHA256,
        IntegAlg::HmacSha384Trunc192 => esp_attr::AUTH_HMAC_SHA384,
        IntegAlg::HmacSha512Trunc256 => esp_attr::AUTH_HMAC_SHA512,
    }
}

/// The phase 1 Encryption Algorithm attribute (RFC 2409 Appendix A, RFC 3602).
pub(super) fn phase1_encryption(encr: EncrAlg) -> u64 {
    if encr.is_legacy() { ike_attr::ENCR_3DES_CBC } else { ike_attr::ENCR_AES_CBC }
}

/// The ESP transform id; ChaCha20-Poly1305 has none in IKEv1 and
/// `parse_esp1` refuses it.
fn esp_transform(encr: EncrAlg) -> u8 {
    match encr {
        EncrAlg::TripleDesCbc => esp_attr::TRANSFORM_ESP_3DES,
        e if e.is_aead() => esp_attr::TRANSFORM_ESP_AES_GCM_16,
        _ => esp_attr::TRANSFORM_ESP_AES,
    }
}

/// Maps the gateway's ESP transform back to an offered one, refusing a
/// PFS downgrade. Returns the suite, the gateway's SPI and the lifetime.
fn chosen_phase2(
    chosen: &[Proposal],
    offered: &[EspProposal],
    ours: Duration,
) -> anyhow::Result<(EspProposal, u32, Duration)> {
    let [p] = chosen else { bail!("gateway returned {} phase 2 proposals", chosen.len()) };
    ensure!(p.protocol == protocol::ESP, "gateway answered with a non-ESP proposal");
    let spi = u32::from_be_bytes(p.spi.as_slice().try_into().context("gateway ESP SPI is not 4 bytes")?);
    ensure!(spi > 255, "gateway chose a reserved ESP SPI");
    let [t] = p.transforms.as_slice() else { bail!("gateway returned {} phase 2 transforms", p.transforms.len()) };
    let found = offered
        .iter()
        .find(|o| {
            t.id == esp_transform(o.encr)
                && t.attr(esp_attr::KEY_LENGTH) == o.encr.key_bits().map(u64::from)
                && t.attr(esp_attr::AUTH_ALG) == o.integ.map(auth_alg)
                && t.attr(esp_attr::GROUP) == o.pfs.map(|g| u64::from(g.id()))
        })
        .copied()
        .context("gateway chose a phase 2 transform we did not offer (or dropped PFS)")?;
    let lifetime = match (t.attr(esp_attr::LIFE_TYPE), t.attr(esp_attr::LIFE_DURATION)) {
        (Some(esp_attr::LIFE_SECONDS), Some(secs)) if secs >= MIN_LIFETIME.as_secs() => {
            Duration::from_secs(secs).min(ours)
        }
        _ => ours,
    };
    Ok((found, spi, lifetime))
}

/// Quick Mode identity → selector.
fn selector(id: &Id) -> anyhow::Result<TrafficSelector> {
    let d = &id.data;
    let addr = |at: usize| Ipv4Addr::new(d[at], d[at + 1], d[at + 2], d[at + 3]);
    let (start, end) = match (id.id_type, d.len()) {
        (id_type::IPV4_ADDR, 4) => (addr(0), addr(0)),
        (id_type::IPV4_ADDR_SUBNET, 8) => {
            let (net, mask) = (u32::from(addr(0)), u32::from(addr(4)));
            (Ipv4Addr::from(net & mask), Ipv4Addr::from(net | !mask))
        }
        (id_type::IPV4_ADDR_RANGE, 8) => (addr(0), addr(4)),
        _ => bail!("unsupported Quick Mode identity type {}", id.id_type),
    };
    Ok(TrafficSelector { start, end, ..TrafficSelector::any() })
}

/// Runs the first Quick Mode to completion.
async fn quick_request(
    transport: &Transport,
    sa: &mut IsakmpSa,
    cancel: &CancellationToken,
    init: QuickInit,
) -> anyhow::Result<(Phase2, Vec<TrafficSelector>)> {
    let mut wait = Duration::from_secs(1);
    for _ in 0..MAX_TRIES {
        transport.send_ike(&init.bytes).await?;
        let deadline = tokio::time::Instant::now() + wait;
        while let Some(inc) = next_message(transport, sa, cancel, deadline, None).await? {
            if inc.msg.header.exchange == exchange::INFORMATIONAL {
                handle_info(transport, sa, inc).await?;
            } else if init.accepts(sa, &inc) {
                let (child, remote_ts, msg3) = init.finish(sa, inc)?;
                transport.send_ike(&msg3).await?;
                return Ok((child, remote_ts));
            }
        }
        wait = (wait * 2).min(Duration::from_secs(8));
    }
    bail!("no Quick Mode answer from the gateway (check the phase2 proposals and PFS group)")
}
