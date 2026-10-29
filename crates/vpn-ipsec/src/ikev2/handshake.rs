//! IKE_SA_INIT and IKE_AUTH: we authenticate with the PSK, EAP-MSCHAPv2
//! or a Keychain certificate (the client signs), the gateway with the PSK
//! or a certificate.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Instant;

use anyhow::{Context, bail, ensure};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use vpn_core::{FailureKind, GatewayAuth, IpsecProfile, Prompt, PromptKind, SessionContext, SignRequest};
use zeroize::Zeroizing;

use super::consts::{auth_method, cfg, exchange, flags, id_type, notify};
use super::keys::{derive_child_keys, derive_ike_keys, nat_hash, shared_key_auth, signed_octets};
use super::message::{self, Message};
use super::payload::{CpAttr, Identity, Notify, Payload, TrafficSelector};
use super::{ChildSa, Established, IkeSa, check_nonce, request, settings};
use crate::cert::{self, ClientSigner, GatewayTrust};
use crate::crypto::{DhGroup, KeyExchange, ct_eq, random_bytes};
use crate::eap::{EapPeer, EapStep};
use crate::esp::EspSa;
use crate::proposal::{self, EspProposal, IkeProposal};
use crate::transport::{NATT_PORT, Transport};

const NONCE_LEN: usize = 32;
const INIT_ATTEMPTS: u32 = 6;
const MAX_EAP_ROUNDS: usize = 10;

pub(crate) async fn establish(profile: &IpsecProfile, ctx: &SessionContext) -> anyhow::Result<Established> {
    establish_with_natt_port(profile, ctx, NATT_PORT).await
}

pub(crate) async fn establish_with_natt_port(
    profile: &IpsecProfile,
    ctx: &SessionContext,
    natt_port: u16,
) -> anyhow::Result<Established> {
    crate::check_legacy(profile)?;
    let ike_proposals: Vec<IkeProposal> =
        profile.ike.iter().map(|s| proposal::parse_ike(s)).collect::<anyhow::Result<_>>()?;
    let esp_proposals: Vec<EspProposal> =
        profile.esp.iter().map(|s| proposal::parse_esp(s)).collect::<anyhow::Result<_>>()?;
    ensure!(!ike_proposals.is_empty() && !esp_proposals.is_empty(), "profile has no IKE or ESP proposal");

    let gateway = resolve(&profile.gateway, profile.port).await?;
    info!(%gateway, "starting IKEv2");
    let trust = match profile.gateway_auth {
        GatewayAuth::Certificate => Some(GatewayTrust::new(
            profile.ca_pem.as_deref(),
            profile.keychain_ca_pem.as_deref(),
            &profile.trusted_cert,
            &profile.gateway,
            profile.port,
        )?),
        GatewayAuth::Psk => None,
    };
    let client_chain = client_chain(profile)?;
    if profile.username.is_some() && trust.is_none() {
        warn!(
            "EAP with a gateway authenticated by pre-shared key: anyone who knows the PSK can impersonate \
             the gateway and capture MSCHAPv2 responses (crackable offline). Prefer a gateway certificate"
        );
    }
    // A gateway certificate with EAP or our certificate needs no PSK.
    let psk = if trust.is_none() || (profile.username.is_none() && client_chain.is_none()) {
        ctx.prompter.ask(Prompt::new("psk", PromptKind::Secret, format!("Pre-shared key for {}", ctx.name))).await?
    } else {
        Zeroizing::new(String::new())
    };

    let mut transport = Transport::connect(gateway).await?;
    let spi_i = nonzero_u64();
    let ni = random_bytes(NONCE_LEN);
    let init = sa_init(&transport, ctx, spi_i, &ni, &ike_proposals).await?;
    let algs = init.algs;
    let spi_r = init.response.header.spi_r;
    let nr = init.response.nonce().context("IKE_SA_INIT response has no nonce")?.to_vec();
    check_nonce(&nr, algs.prf)?;
    let (ke_group, ke_data) = init.response.ke().context("IKE_SA_INIT response has no KE")?;
    ensure!(ke_group == algs.dh.id(), "KE group does not match the chosen proposal");
    ensure!(init.kx.group() == algs.dh, "the gateway chose a DH group we sent no key for");
    let shared = Zeroizing::new(init.kx.shared_secret(ke_data)?);
    let keys = derive_ike_keys(&algs, &shared, &ni, &nr, spi_i, spi_r)?;
    let mut ike = IkeSa::new(spi_i, spi_r, algs, keys);
    info!(?algs, "IKE SA negotiated");

    // We always signal a NAT (see sa_init), so continue on port 4500.
    transport.switch_to_natt(natt_port).await?;
    let local_ip = transport.local()?.ip().to_owned();

    let id_str = profile.local_id.clone().or_else(|| profile.username.clone()).unwrap_or_else(|| local_ip.to_string());
    let local_id = match &client_chain {
        // The certificate's subject, unless the profile names one of its
        // other identities.
        Some(chain) if profile.local_id.is_none() => {
            Identity { id_type: id_type::DER_ASN1_DN, data: cert::subject(&chain[0])? }
        }
        Some(chain) => {
            let id = Identity::parse(&id_str);
            ensure!(cert::covers(&chain[0], &id)?, "the client certificate is not valid for the local ID {id_str}");
            id
        }
        None => Identity::parse(&id_str),
    };
    let our_auth = |ike: &IkeSa, secret: &[u8]| {
        shared_key_auth(ike.keys.prf, secret, &init.request, &nr, &ike.keys.sk_pi, &local_id.body())
    };
    let verify_peer = |ike: &IkeSa, msg: &Message, secret: &[u8]| -> anyhow::Result<()> {
        let id = msg.id_r().context("gateway sent no IDr")?;
        if let Some(expected) = &profile.remote_id {
            check_remote_id(id, expected)?;
        }
        let (method, data) = msg.auth().context("gateway sent no AUTH payload")?;
        ensure!(
            method == auth_method::SHARED_KEY_MIC,
            "the gateway authenticates with a certificate (method {method}): choose certificate authentication \
             of the gateway in the profile"
        );
        let expected = shared_key_auth(ike.keys.prf, secret, &init.response_raw, &ni, &ike.keys.sk_pr, &id.body());
        if !ct_eq(&expected, data) {
            return Err(vpn_core::failure(
                vpn_core::FailureKind::PskRejected,
                "gateway AUTH is invalid (wrong pre-shared key?)",
            ));
        }
        Ok(())
    };

    let child_spi = nonzero_u32();
    let mut payloads = vec![Payload::IdI(local_id.clone())];
    for cert in client_chain.iter().flatten() {
        payloads.push(Payload::Cert { encoding: cert::X509_SIGNATURE, data: cert.clone() });
    }
    if let Some(trust) = &trust {
        payloads.push(Payload::CertReq(trust.certreq()));
    }
    if let Some(r) = &profile.remote_id {
        payloads.push(Payload::IdR(Identity::parse(r)));
    }
    let eap_identity = profile.username.clone();
    if let Some(chain) = &client_chain {
        let hashes = init.response.notify(notify::SIGNATURE_HASH_ALGORITHMS).map(|n| hash_list(&n.data));
        let signed = signed_octets(ike.keys.prf, &init.request, &nr, &ike.keys.sk_pi, &local_id.body());
        payloads.push(sign(ctx, &chain[0], hashes.as_deref().unwrap_or_default(), &signed).await?);
    } else if eap_identity.is_none() {
        payloads.push(Payload::Auth { method: auth_method::SHARED_KEY_MIC, data: our_auth(&ike, psk.as_bytes()) });
    }
    payloads.extend([
        Payload::Notify(Notify::new(notify::INITIAL_CONTACT, Vec::new())),
        Payload::Cp {
            cfg_type: cfg::REQUEST,
            attrs: [cfg::INTERNAL_IP4_ADDRESS, cfg::INTERNAL_IP4_DNS, cfg::INTERNAL_DNS_DOMAIN]
                .into_iter()
                .map(|kind| CpAttr { kind, value: Vec::new() })
                .collect(),
        },
        Payload::Sa(
            esp_proposals.iter().enumerate().map(|(i, p)| p.sa_proposal(i as u8 + 1, child_spi, None)).collect(),
        ),
        Payload::TsI(vec![TrafficSelector::any()]),
        Payload::TsR(vec![TrafficSelector::any()]),
    ]);
    let mut response = auth_request(&mut ike, &transport, ctx, payloads).await?;
    match &trust {
        Some(trust) => {
            let signed =
                |id: &Identity| signed_octets(ike.keys.prf, &init.response_raw, &ni, &ike.keys.sk_pr, &id.body());
            verify_certificate(profile, ctx, trust, &response, signed).await?;
        }
        None => verify_peer(&ike, &response, psk.as_bytes())?,
    }
    let peer_id = response.id_r().cloned().context("gateway sent no IDr")?;

    if let Some(identity) = eap_identity {
        let mut password = Zeroizing::new(
            ctx.prompter
                .ask(Prompt::new("password", PromptKind::Secret, format!("Password for {identity} on {}", ctx.name)))
                .await?,
        );
        let mut eap = EapPeer::new(identity, std::mem::take(&mut *password));
        for round in 0.. {
            ensure!(round < MAX_EAP_ROUNDS, "EAP did not converge");
            let packet = response.eap().context("gateway did not start EAP (is EAP enabled on the phase1?)")?;
            match eap.process(packet)? {
                EapStep::Respond(reply) => {
                    response = auth_request(&mut ike, &transport, ctx, vec![Payload::Eap(reply)]).await?;
                }
                EapStep::Success => break,
                EapStep::Failure(reason) => bail!("EAP authentication failed: {reason}"),
            }
        }
        let msk = Zeroizing::new(eap.msk().context("EAP method produced no MSK")?.to_vec());
        let auth = Payload::Auth { method: auth_method::SHARED_KEY_MIC, data: our_auth(&ike, &msk) };
        response = auth_request(&mut ike, &transport, ctx, vec![auth]).await?;
        // The final response carries AUTH but no IDr: the identity is the
        // one from the first IKE_AUTH response.
        let (method, data) = response.auth().context("gateway sent no final AUTH")?;
        let expected = shared_key_auth(ike.keys.prf, &msk, &init.response_raw, &ni, &ike.keys.sk_pr, &peer_id.body());
        ensure!(method == auth_method::SHARED_KEY_MIC && ct_eq(&expected, data), "gateway final AUTH is invalid");
    }

    let (esp, peer_spi) = proposal::accept_esp(response.sa().context("gateway created no CHILD SA")?, &esp_proposals)?;
    let (out, inbound) = derive_child_keys(ike.keys.prf, &ike.keys.sk_d, None, &ni, &nr, esp.encr, esp.integ, true)?;
    let child = ChildSa {
        inbound: EspSa::new(child_spi, inbound),
        outbound: EspSa::new(peer_spi, out),
        created: Instant::now(),
    };
    ensure!(!response.ts_i().is_empty() && !response.ts_r().is_empty(), "gateway sent no IPv4 traffic selectors");
    let settings = settings::build(&response, *gateway.ip())?;
    info!(address = %settings.address, routes = settings.routes.len(), full = settings.full_tunnel, ?esp, "IKEv2 established");
    Ok(Established {
        transport,
        child,
        settings,
        local_ts: response.ts_i().to_vec(),
        remote_ts: response.ts_r().to_vec(),
        esp_proposals,
        limits: super::Limits::new(profile),
        closed: false,
        ike,
    })
}

/// The gateway's certificate AUTH: its signature, then its chain and
/// identity; an untrusted certificate is shown to the user, who may trust
/// it (the client then pins it).
async fn verify_certificate(
    profile: &IpsecProfile,
    ctx: &SessionContext,
    trust: &GatewayTrust,
    msg: &Message,
    signed: impl Fn(&Identity) -> Vec<u8>,
) -> anyhow::Result<()> {
    let id = msg.id_r().context("gateway sent no IDr")?;
    if let Some(expected) = &profile.remote_id {
        check_remote_id(id, expected)?;
    }
    let (method, data) = msg.auth().context("gateway sent no AUTH payload")?;
    ensure!(
        method != auth_method::SHARED_KEY_MIC,
        "the gateway authenticated with the pre-shared key, but the profile expects a certificate"
    );
    let chain = msg.certificates();
    let leaf = chain.first().context("gateway sent no certificate (CERT payload)")?;
    cert::verify_auth(leaf, method, data, &signed(id))?;
    let expected = Identity::parse(profile.remote_id.as_deref().unwrap_or(&profile.gateway));
    let Err(error) = trust.check(&chain, &expected, id) else {
        return Ok(());
    };
    let FailureKind::CertificateUntrusted { certificate } = vpn_core::failure::kind_of(&error) else {
        return Err(error);
    };
    // A cached answer is the fingerprint accepted earlier in this session:
    // it only matches the same certificate.
    match ctx.prompter.ask(Prompt::trust(certificate.clone())).await {
        Ok(answer) if answer.trim().eq_ignore_ascii_case(&certificate.sha256) => {
            info!(session = ctx.name, sha256 = certificate.sha256, "gateway certificate trusted by the user");
            Ok(())
        }
        _ => Err(error),
    }
}

/// The client certificate chain the client added, if the profile has one.
fn client_chain(profile: &IpsecProfile) -> anyhow::Result<Option<Vec<Vec<u8>>>> {
    let Some(sha256) = &profile.client_certificate else { return Ok(None) };
    let pem = profile.client_chain_pem.as_deref().context("the client certificate is not in the Keychain")?;
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.map(|c| c.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .context("invalid client certificate")?;
    let leaf = chain.first().context("no client certificate")?;
    ensure!(hex::encode(Sha256::digest(leaf)).eq_ignore_ascii_case(sha256), "the client sent another certificate");
    Ok(Some(chain))
}

fn hash_list(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>().0.iter().map(|h| u16::from_be_bytes(*h)).collect()
}

/// Our AUTH, signed by the client with the certificate's key; checked
/// against the certificate before it is sent.
async fn sign(ctx: &SessionContext, leaf: &[u8], gateway_hashes: &[u16], signed: &[u8]) -> anyhow::Result<Payload> {
    let signer = ClientSigner::new(leaf, gateway_hashes)?;
    let request = SignRequest {
        certificate: hex::encode(Sha256::digest(leaf)),
        algorithm: signer.algorithm,
        data: hex::encode(signed),
    };
    let answer = ctx.prompter.ask(Prompt::sign(request, format!("Signature for {}", ctx.name))).await?;
    let data = signer.auth_data(&hex::decode(answer.trim()).context("malformed signature from the client")?)?;
    cert::verify_auth(leaf, signer.method, &data, signed)
        .context("the Keychain key does not match the client certificate")?;
    Ok(Payload::Auth { method: signer.method, data })
}

struct InitResult {
    algs: IkeProposal,
    kx: KeyExchange,
    request: Vec<u8>,
    response_raw: Vec<u8>,
    response: Message,
}

/// IKE_SA_INIT, handling COOKIE (§2.6) and INVALID_KE_PAYLOAD (§1.2).
async fn sa_init(
    transport: &Transport,
    ctx: &SessionContext,
    spi_i: u64,
    ni: &[u8],
    proposals: &[IkeProposal],
) -> anyhow::Result<InitResult> {
    let mut kx = KeyExchange::generate(proposals[0].dh)?;
    let mut cookie: Option<Vec<u8>> = None;
    for _ in 0..4 {
        let mut payloads = Vec::new();
        if let Some(c) = &cookie {
            payloads.push(Payload::Notify(Notify::new(notify::COOKIE, c.clone())));
        }
        payloads.extend([
            Payload::Sa(proposals.iter().enumerate().map(|(i, p)| p.sa_proposal(i as u8 + 1)).collect()),
            Payload::Ke { group: kx.group().id(), data: kx.public().to_vec() },
            Payload::Nonce(ni.to_vec()),
            // A random source hash makes the gateway believe we are behind
            // a NAT, so ESP is always UDP-encapsulated (no raw sockets).
            Payload::Notify(Notify::new(notify::NAT_DETECTION_SOURCE_IP, random_bytes(20))),
            Payload::Notify(Notify::new(notify::NAT_DETECTION_DESTINATION_IP, nat_hash(spi_i, 0, transport.peer()))),
            Payload::Notify(Notify::new(
                notify::SIGNATURE_HASH_ALGORITHMS,
                cert::SIGNATURE_HASHES.iter().flat_map(|h| h.to_be_bytes()).collect(),
            )),
        ]);
        let request_bytes = message::build_plain(spi_i, 0, exchange::IKE_SA_INIT, flags::INITIATOR, 0, &payloads);
        let (raw, response) =
            request(transport, &ctx.cancel, &request_bytes, 0, spi_i, INIT_ATTEMPTS, |r| message::parse(r, None))
                .await?;
        if let Some(n) = response.notify(notify::COOKIE) {
            debug!("gateway requested a cookie");
            cookie = Some(n.data.clone());
            continue;
        }
        if let Some(n) = response.notify(notify::INVALID_KE_PAYLOAD) {
            ensure!(n.data.len() >= 2, "malformed INVALID_KE_PAYLOAD");
            let wanted = u16::from_be_bytes([n.data[0], n.data[1]]);
            let group = DhGroup::from_id(wanted)
                .filter(|g| proposals.iter().any(|p| p.dh == *g))
                .with_context(|| format!("gateway wants DH group {wanted}, which the profile does not offer"))?;
            ensure!(group != kx.group(), "gateway rejected the DH group it asked for");
            debug!(?group, "gateway asked for another DH group");
            kx = KeyExchange::generate(group)?;
            continue;
        }
        response.check_errors()?;
        ensure!(response.header.spi_r != 0, "gateway sent no responder SPI");
        ensure!(
            response.notify(notify::NAT_DETECTION_SOURCE_IP).is_some(),
            "gateway does not support NAT traversal, which this client requires"
        );
        let algs = proposal::accept_ike(response.sa().context("IKE_SA_INIT response has no SA")?, proposals)?;
        return Ok(InitResult { algs, kx, request: request_bytes, response_raw: raw, response });
    }
    bail!("IKE_SA_INIT did not converge")
}

async fn auth_request(
    ike: &mut IkeSa,
    transport: &Transport,
    ctx: &SessionContext,
    payloads: Vec<Payload>,
) -> anyhow::Result<Message> {
    let (id, bytes) = ike.build_request(exchange::IKE_AUTH, &payloads);
    let (_, msg) = request(transport, &ctx.cancel, &bytes, id, ike.spi_i, INIT_ATTEMPTS, |r| ike.parse(r)).await?;
    msg.check_errors()?;
    Ok(msg)
}

pub(crate) async fn resolve(host: &str, port: u16) -> anyhow::Result<SocketAddrV4> {
    let addrs =
        vpn_core::FailureExt::kind(tokio::net::lookup_host((host, port)).await, vpn_core::FailureKind::Unreachable)
            .with_context(|| format!("cannot resolve {host}"))?;
    addrs
        .filter_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .next()
        .with_context(|| format!("{host} has no IPv4 address"))
}

pub(crate) fn nonzero_u64() -> u64 {
    loop {
        let v = u64::from_be_bytes(random_bytes(8).try_into().unwrap());
        if v != 0 {
            return v;
        }
    }
}

pub(crate) fn nonzero_u32() -> u32 {
    loop {
        let v = u32::from_be_bytes(random_bytes(4).try_into().unwrap());
        // SPIs 1..=255 are reserved (RFC 4303 §2.1).
        if v > 255 {
            return v;
        }
    }
}

/// The gateway's IDr must match the configured `remote_id` in type and value.
fn check_remote_id(got: &Identity, expected: &str) -> anyhow::Result<()> {
    let expected = Identity::parse(expected);
    ensure!(
        got.id_type == expected.id_type && got.data == expected.data,
        "gateway identity (type {}, {:?}) does not match remote_id (type {}, {:?})",
        got.id_type,
        String::from_utf8_lossy(&got.data),
        expected.id_type,
        String::from_utf8_lossy(&expected.data),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_id_compares_type_and_value() {
        let fqdn = Identity::parse("vpn.corp.test");
        assert!(check_remote_id(&fqdn, "vpn.corp.test").is_ok());
        assert!(check_remote_id(&fqdn, "fqdn:vpn.corp.test").is_ok());
        // Same bytes, different type.
        assert!(check_remote_id(&fqdn, "keyid:vpn.corp.test").is_err());
        assert!(check_remote_id(&Identity::parse("keyid:vpn.corp.test"), "vpn.corp.test").is_err());
        // Different value.
        assert!(check_remote_id(&fqdn, "other.corp.test").is_err());
        let ip = Identity::parse("203.0.113.1");
        assert!(check_remote_id(&ip, "203.0.113.1").is_ok());
        assert!(check_remote_id(&Identity { id_type: 2, data: vec![203, 0, 113, 1] }, "203.0.113.1").is_err());
    }
}
