//! Loopback test against a fake FortiGate-like IKEv1 responder: aggressive
//! or main mode PSK, XAuth, Mode-Config (Unity split include), Quick Mode with PFS,
//! ESP both ways, DPD and delete.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use vpn_core::{ExchangeMode, IpsecProfile, PacketIo, Prompt, Prompter, SessionContext};

use super::consts::{cfg, esp_attr, exchange, id_type, ike_attr, notify, protocol, vid};
use super::handshake::establish_with_natt_port;
use super::isakmp::{IsakmpSa, decrypt, encrypt};
use super::keys::{derive_phase1, keymat, phase1_hash};
use super::payload::{CfgAttr, CfgValue, Id, Message, Payload, Proposal, build_plain, encode_chain};
use super::{dpd_notify, random_msg_id};
use crate::crypto::{Cipher, DhGroup, EncrAlg, IntegAlg, KeyExchange, PrfAlg, random_bytes};
use crate::esp::EspSa;

const PSK: &str = "group-secret";

struct StaticPrompter;

#[async_trait]
impl Prompter for StaticPrompter {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<String> {
        Ok(match prompt.key.as_str() {
            "psk" => PSK.into(),
            "password" => "correct horse".into(),
            other => anyhow::bail!("unexpected prompt {other}"),
        })
    }

    async fn open_url(&self, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("no browser")
    }
}

#[derive(Clone, Copy)]
struct Behaviour {
    psk: &'static str,
    accept_password: bool,
    /// Race a forged message 2 (right cookie, bogus HASH_R) before the real one.
    forged_reply_first: bool,
    /// Answer NO-PROPOSAL-CHOSEN to a message 1 without DH group 5.
    only_group_5: bool,
    main_mode: bool,
}

const GOOD: Behaviour =
    Behaviour { psk: PSK, accept_password: true, forged_reply_first: false, only_group_5: false, main_mode: false };

struct Gateway {
    sock: UdpSocket,
    client: SocketAddr,
    sa: IsakmpSa,
    esp_in: EspSa,
    esp_out: EspSa,
}

fn profile(init_port: u16) -> IpsecProfile {
    IpsecProfile {
        gateway: "127.0.0.1".into(),
        port: init_port,
        ike_version: 1,
        exchange_mode: ExchangeMode::Aggressive,
        xauth: true,
        local_id: None,
        remote_id: Some("fqdn:gw.test".into()),
        username: Some("alice".into()),
        ike: vec!["aes128-sha1-modp1536".into(), "aes256-sha256-modp1536".into()],
        esp: vec!["aes128-sha1-modp1536".into(), "aes256-sha1-modp1536".into()],
        phase1_lifetime: 86_400,
        phase2_lifetime: 43_200,
        phase2_lifetime_kb: None,
        dpd: true,
        legacy_algorithms: false,
        gateway_auth: Default::default(),
        ca_pem: None,
        trusted_cert: Vec::new(),
        keychain_ca_pem: None,
        client_certificate: None,
        client_chain_pem: None,
    }
}

fn context() -> SessionContext {
    SessionContext {
        name: "hq".into(),
        prompter: Arc::new(StaticPrompter),
        cancel: CancellationToken::new(),
        stats: Arc::default(),
    }
}

async fn recv_natt(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 16384];
    loop {
        let (n, from) =
            timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await.expect("gateway timed out").unwrap();
        match &buf[..n] {
            [0, 0, 0, 0, rest @ ..] => return (rest.to_vec(), from),
            [0xff] => continue,
            other => return (other.to_vec(), from),
        }
    }
}

async fn send_ike(sock: &UdpSocket, to: SocketAddr, msg: &[u8]) {
    sock.send_to(&[&[0u8; 4][..], msg].concat(), to).await.unwrap();
}

fn attrs_of(msg: &Message) -> (u8, u16, Vec<CfgAttr>) {
    msg.iter()
        .find_map(|p| match p {
            Payload::Attr { cfg_type, identifier, attrs } => Some((*cfg_type, *identifier, attrs.clone())),
            _ => None,
        })
        .expect("attribute payload")
}

/// Receives the next ISAKMP message of `sa` on the NAT-T socket, checks its
/// leading HASH (with `prefix`) and commits the IV.
async fn recv_sealed(sock: &UdpSocket, sa: &mut IsakmpSa, prefix: &[u8]) -> Message {
    let (raw, _) = recv_natt(sock).await;
    let (msg, iv) = sa.open(&raw).unwrap();
    sa.verify(&msg, prefix).unwrap();
    sa.commit(msg.header.msg_id, iv);
    msg
}

async fn fake_gateway(init: UdpSocket, natt: UdpSocket, b: Behaviour) -> Option<Gateway> {
    let (mut sa, client) =
        if b.main_mode { main_mode(&init, &natt, b).await? } else { aggressive_mode(&init, &natt, b).await? };
    gateway_after_phase1(natt, client, &mut sa, b).await.map(|(sock, esp_in, esp_out)| Gateway {
        sock,
        client,
        sa,
        esp_in,
        esp_out,
    })
}

/// The transform a FortiGate preferring them would choose: 3DES/SHA-256
/// if offered (an old gateway), else AES-256/SHA-256.
fn choose_phase1(offered: &Proposal) -> (super::payload::Transform, EncrAlg) {
    let sha256 = |t: &&super::payload::Transform| t.attr(ike_attr::HASH) == Some(ike_attr::HASH_SHA256);
    let chosen = offered
        .transforms
        .iter()
        .filter(sha256)
        .filter(|t| t.attr(ike_attr::GROUP) == Some(5))
        .find(|t| t.attr(ike_attr::ENCRYPTION) == Some(ike_attr::ENCR_3DES_CBC))
        .or_else(|| {
            offered
                .transforms
                .iter()
                .filter(sha256)
                .filter(|t| t.attr(ike_attr::GROUP) == Some(5))
                .find(|t| t.attr(ike_attr::KEY_LENGTH) == Some(256))
        })
        .unwrap()
        .clone();
    assert_eq!(chosen.attr(ike_attr::AUTH_METHOD), Some(ike_attr::AUTH_XAUTH_INIT_PSK));
    let encr = if chosen.attr(ike_attr::ENCRYPTION) == Some(ike_attr::ENCR_3DES_CBC) {
        assert_eq!(chosen.attr(ike_attr::KEY_LENGTH), None, "3DES has a fixed key length");
        EncrAlg::TripleDesCbc
    } else {
        EncrAlg::AesCbc { key_bits: 256 }
    };
    (chosen, encr)
}

fn chosen_sa(chosen: super::payload::Transform) -> Payload {
    Payload::Sa(vec![Proposal { num: 1, protocol: protocol::ISAKMP, spi: vec![], transforms: vec![chosen] }])
}

/// Main mode: SA, KE and nonces in clear, then the identities encrypted
/// (message 5 on the NAT-T port).
async fn main_mode(init: &UdpSocket, natt: &UdpSocket, b: Behaviour) -> Option<(IsakmpSa, SocketAddr)> {
    let mut buf = vec![0u8; 16384];
    let (n, client500) = init.recv_from(&mut buf).await.unwrap();
    let m1 = Message::parse_plain(&buf[..n]).unwrap();
    assert_eq!(m1.header.exchange, exchange::IDENTITY_PROTECTION);
    assert!(m1.ke().is_none() && m1.ids().next().is_none(), "message 1 carries the SA only");
    let offered = &m1.sa().unwrap()[0];
    let groups: Vec<u64> = offered.transforms.iter().filter_map(|t| t.attr(ike_attr::GROUP)).collect();
    assert!(groups.contains(&5) && groups.contains(&14), "every group in one SA: {groups:?}");
    let (chosen, encr) = choose_phase1(offered);
    let (prf, cky_i, cky_r) = (PrfAlg::HmacSha256, m1.header.cky_i, 0x1122_3344_5566_7788);
    let sa_i = m1.sa_body().unwrap().to_vec();
    let vids = [&vid::NAT_T_RFC3947[..], &vid::DPD, &vid::XAUTH].map(|v| Payload::VendorId(v.to_vec()));
    let m2 = build_plain(cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, &[&[chosen_sa(chosen)][..], &vids].concat());
    init.send_to(&m2, client500).await.unwrap();

    let (n, _) = init.recv_from(&mut buf).await.unwrap();
    let m3 = Message::parse_plain(&buf[..n]).unwrap();
    assert_eq!((m3.header.cky_r, m3.nat_d().len()), (cky_r, 2));
    let (gxi, ni) = (m3.ke().unwrap().to_vec(), m3.nonce().unwrap().to_vec());
    let kx = KeyExchange::generate(DhGroup::Modp1536).unwrap();
    let nr = random_bytes(32);
    let nat_d = Payload::NatD { kind: super::consts::payload::NAT_D, hash: random_bytes(32) };
    let m4 = build_plain(
        cky_i,
        cky_r,
        exchange::IDENTITY_PROTECTION,
        0,
        &[Payload::Ke(kx.public().to_vec()), Payload::Nonce(nr.clone()), nat_d.clone(), nat_d],
    );
    let gxy = kx.shared_secret(&gxi).unwrap();
    let keys = derive_phase1(prf, encr, b.psk.as_bytes(), &ni, &nr, &gxy, cky_i, cky_r, &gxi, kx.public()).unwrap();
    init.send_to(&m4, client500).await.unwrap();

    // Message 5, encrypted, on the NAT-T port.
    let (raw, client) = recv_natt(natt).await;
    let (m5, iv) = decrypt(&keys.cipher, &keys.iv0, &raw).unwrap();
    let idii = m5.ids().next().unwrap();
    let hash_i = phase1_hash(prf, &keys.skeyid, true, &gxi, kx.public(), cky_i, cky_r, &sa_i, &idii.body());
    assert_eq!(m5.hash().unwrap(), hash_i.as_slice(), "HASH_I");
    let idir = Id { id_type: id_type::FQDN, protocol: 0, port: 0, data: b"gw.test".to_vec() };
    let hash_r = phase1_hash(prf, &keys.skeyid, false, &gxi, kx.public(), cky_i, cky_r, &sa_i, &idir.body());
    let (first, body) = encode_chain(&[Payload::Id(idir), Payload::Hash(hash_r)]);
    let (m6, last) = encrypt(&keys.cipher, &iv, cky_i, cky_r, exchange::IDENTITY_PROTECTION, 0, first, &body);
    send_ike(natt, client, &m6).await;
    Some((IsakmpSa::new(cky_i, cky_r, prf, keys, last), client))
}

async fn aggressive_mode(init: &UdpSocket, natt: &UdpSocket, b: Behaviour) -> Option<(IsakmpSa, SocketAddr)> {
    // Aggressive mode message 1.
    let mut buf = vec![0u8; 16384];
    let (m1, client500) = loop {
        let (n, client500) = init.recv_from(&mut buf).await.unwrap();
        let m1 = Message::parse_plain(&buf[..n]).unwrap();
        let groups: Vec<u64> = m1.sa().unwrap()[0].transforms.iter().filter_map(|t| t.attr(ike_attr::GROUP)).collect();
        if b.only_group_5 && !groups.contains(&5) {
            assert_eq!(m1.ke().unwrap().len(), 256, "the KE is for the offered group 14");
            let refusal = build_plain(
                m1.header.cky_i,
                0,
                exchange::INFORMATIONAL,
                0,
                &[Payload::Notify(super::payload::Notify {
                    protocol: protocol::ISAKMP,
                    spi: Vec::new(),
                    kind: notify::NO_PROPOSAL_CHOSEN,
                    data: Vec::new(),
                })],
            );
            init.send_to(&refusal, client500).await.unwrap();
            continue;
        }
        assert!(groups.iter().all(|g| *g == 5), "one DH group per message 1");
        break (m1, client500);
    };
    assert_eq!(m1.header.exchange, exchange::AGGRESSIVE);
    assert!(m1.has_vendor_id(&vid::XAUTH) && m1.has_vendor_id(&vid::NAT_T_RFC3947));
    let offered = &m1.sa().unwrap()[0];
    let (chosen, encr) = choose_phase1(offered);
    let prf = PrfAlg::HmacSha256;
    let cky_i = m1.header.cky_i;
    let cky_r = 0x1122_3344_5566_7788;
    let kx = KeyExchange::generate(DhGroup::Modp1536).unwrap();
    let gxi = m1.ke().unwrap().to_vec();
    let ni = m1.nonce().unwrap().to_vec();
    let idii = m1.ids().next().unwrap().clone();
    let sa_i = m1.sa_body().unwrap().to_vec();
    let nr = random_bytes(32);
    let gxy = kx.shared_secret(&gxi).unwrap();
    let keys = derive_phase1(prf, encr, b.psk.as_bytes(), &ni, &nr, &gxy, cky_i, cky_r, &gxi, kx.public()).unwrap();
    let idir = Id { id_type: id_type::FQDN, protocol: 0, port: 0, data: b"gw.test".to_vec() };
    let hash_r = phase1_hash(prf, &keys.skeyid, false, &gxi, kx.public(), cky_i, cky_r, &sa_i, &idir.body());
    let m2 = build_plain(
        cky_i,
        cky_r,
        exchange::AGGRESSIVE,
        0,
        &[
            chosen_sa(chosen),
            Payload::Ke(kx.public().to_vec()),
            Payload::Nonce(nr.clone()),
            Payload::Id(idir),
            Payload::Hash(hash_r),
            Payload::VendorId(vid::NAT_T_RFC3947.to_vec()),
            Payload::VendorId(vid::DPD.to_vec()),
            Payload::VendorId(vid::XAUTH.to_vec()),
        ],
    );
    if b.forged_reply_first {
        let forged = build_plain(
            cky_i,
            0x0bad_0bad_0bad_0bad,
            exchange::AGGRESSIVE,
            0,
            &[Payload::Ke(vec![2; 192]), Payload::Nonce(vec![0; 16]), Payload::Hash(vec![0; 32])],
        );
        init.send_to(&forged, client500).await.unwrap();
    }
    init.send_to(&m2, client500).await.unwrap();
    if b.psk != PSK {
        return None; // the client must reject HASH_R
    }

    // Message 3 arrives on the NAT-T port.
    let (raw, client) = recv_natt(natt).await;
    let m3 = Message::parse_plain(&raw).unwrap();
    let hash_i = phase1_hash(prf, &keys.skeyid, true, &gxi, kx.public(), cky_i, cky_r, &sa_i, &idii.body());
    assert_eq!(m3.hash().unwrap(), hash_i.as_slice(), "HASH_I");
    assert_eq!(m3.nat_d().len(), 2);
    let iv0 = keys.iv0.clone();
    Some((IsakmpSa::new(cky_i, cky_r, prf, keys, iv0), client))
}

/// XAuth, Mode-Config and Quick Mode; returns the ESP SAs.
async fn gateway_after_phase1(
    natt: UdpSocket,
    client: SocketAddr,
    sa: &mut IsakmpSa,
    b: Behaviour,
) -> Option<(UdpSocket, EspSa, EspSa)> {
    let prf = sa.prf;
    // XAuth: REQUEST → REPLY, SET → ACK.
    let mid = random_msg_id();
    let request = Payload::Attr {
        cfg_type: cfg::REQUEST,
        identifier: 7,
        attrs: vec![
            CfgAttr { kind: cfg::XAUTH_TYPE, value: CfgValue::Basic(0) },
            CfgAttr::empty(cfg::XAUTH_USER_NAME),
            CfgAttr::empty(cfg::XAUTH_USER_PASSWORD),
        ],
    };
    let bytes = sa.seal(exchange::TRANSACTION, mid, &[], &[request]);
    send_ike(&natt, client, &bytes).await;
    let reply = recv_sealed(&natt, sa, &[]).await;
    sa.forget(mid);
    let (kind, ident, attrs) = attrs_of(&reply);
    assert_eq!((kind, ident), (cfg::REPLY, 7));
    let get = |k| attrs.iter().find(|a| a.kind == k).unwrap().bytes().to_vec();
    assert_eq!(get(cfg::XAUTH_USER_NAME), b"alice");
    assert_eq!(get(cfg::XAUTH_USER_PASSWORD), b"correct horse");
    let mid = random_msg_id();
    let status = u16::from(b.accept_password);
    let set = Payload::Attr {
        cfg_type: cfg::SET,
        identifier: 8,
        attrs: vec![CfgAttr { kind: cfg::XAUTH_STATUS, value: CfgValue::Basic(status) }],
    };
    let bytes = sa.seal(exchange::TRANSACTION, mid, &[], &[set]);
    send_ike(&natt, client, &bytes).await;
    let ack = recv_sealed(&natt, sa, &[]).await;
    sa.forget(mid);
    assert_eq!(attrs_of(&ack).0, cfg::ACK);
    if !b.accept_password {
        return None;
    }

    // Mode-Config pull.
    let req = recv_sealed(&natt, sa, &[]).await;
    let (kind, ident, _) = attrs_of(&req);
    assert_eq!(kind, cfg::REQUEST);
    let mut split = vec![10, 0, 0, 0, 255, 0, 0, 0];
    split.extend_from_slice(&[0; 6]);
    let reply = Payload::Attr {
        cfg_type: cfg::REPLY,
        identifier: ident,
        attrs: vec![
            CfgAttr::var(cfg::INTERNAL_IP4_ADDRESS, [10, 9, 0, 2]),
            CfgAttr::var(cfg::INTERNAL_IP4_DNS, [10, 0, 0, 53]),
            CfgAttr::var(cfg::UNITY_SPLIT_INCLUDE, split),
            CfgAttr::var(cfg::UNITY_DEF_DOMAIN, *b"corp.test"),
        ],
    };
    let bytes = sa.seal(exchange::TRANSACTION, req.header.msg_id, &[], &[reply]);
    sa.forget(req.header.msg_id);
    send_ike(&natt, client, &bytes).await;

    // Quick Mode with PFS.
    let qm1 = recv_sealed(&natt, sa, &[]).await;
    assert_eq!(qm1.header.exchange, exchange::QUICK);
    let qm_id = qm1.header.msg_id;
    let p = &qm1.sa().unwrap()[0];
    let client_spi = u32::from_be_bytes(p.spi.as_slice().try_into().unwrap());
    let t = p
        .transforms
        .iter()
        .find(|t| t.id == esp_attr::TRANSFORM_ESP_3DES)
        .or_else(|| p.transforms.iter().find(|t| t.attr(esp_attr::KEY_LENGTH) == Some(256)))
        .unwrap()
        .clone();
    let chosen_esp = t.id;
    if chosen_esp == esp_attr::TRANSFORM_ESP_AES_GCM_16 {
        assert_eq!(t.attr(esp_attr::AUTH_ALG), None, "AES-GCM has no separate authentication");
    }
    assert_eq!(t.attr(esp_attr::ENCAPSULATION), Some(esp_attr::ENCAP_UDP_TUNNEL));
    assert_eq!(t.attr(esp_attr::GROUP), Some(5));
    let ni2 = qm1.nonce().unwrap().to_vec();
    let kx2 = KeyExchange::generate(DhGroup::Modp1536).unwrap();
    let gxy2 = kx2.shared_secret(qm1.ke().unwrap()).unwrap();
    let ids: Vec<Id> = qm1.ids().cloned().collect();
    assert_eq!(ids[0].data, [10, 9, 0, 2]);
    let nr2 = random_bytes(32);
    let gw_spi = 0x0a0b_0c0d_u32;
    let payloads = [
        Payload::Sa(vec![Proposal {
            num: 1,
            protocol: protocol::ESP,
            spi: gw_spi.to_be_bytes().to_vec(),
            transforms: vec![t],
        }]),
        Payload::Nonce(nr2.clone()),
        Payload::Ke(kx2.public().to_vec()),
        Payload::Id(ids[0].clone()),
        Payload::Id(ids[1].clone()),
    ];
    let bytes = sa.seal(exchange::QUICK, qm_id, &ni2, &payloads);
    send_ike(&natt, client, &bytes).await;
    let (raw, _) = recv_natt(&natt).await;
    let (qm3, iv) = sa.open(&raw).unwrap();
    sa.commit(qm_id, iv);
    let hash3 = prf.compute(&sa.skeyid_a, &[&[0], &qm_id.to_be_bytes(), &ni2, &nr2]);
    assert_eq!(qm3.hash().unwrap(), hash3.as_slice(), "HASH(3)");
    sa.forget(qm_id);

    let (encr, integ) = match chosen_esp {
        esp_attr::TRANSFORM_ESP_AES_GCM_16 => (EncrAlg::AesGcm16 { key_bits: 256 }, None),
        esp_attr::TRANSFORM_ESP_3DES => (EncrAlg::TripleDesCbc, Some(IntegAlg::HmacSha1Trunc96)),
        _ => (EncrAlg::AesCbc { key_bits: 256 }, Some(IntegAlg::HmacSha1Trunc96)),
    };
    let esp = |spi: u32| {
        let (e, a) = keymat(prf, &sa.skeyid_d, Some(&gxy2), protocol::ESP, spi, &ni2, &nr2, encr, integ);
        EspSa::new(spi, Cipher::new(encr, integ, &e, &a).unwrap())
    };
    let (esp_in, esp_out) = (esp(gw_spi), esp(client_spi));
    Some((natt, esp_in, esp_out))
}

fn ip_packet(src: [u8; 4], dst: [u8; 4], tag: u8) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 21, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.push(tag);
    p
}

async fn sockets() -> (UdpSocket, UdpSocket, u16, u16) {
    let init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let natt = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ports = (init.local_addr().unwrap().port(), natt.local_addr().unwrap().port());
    (init, natt, ports.0, ports.1)
}

#[tokio::test]
async fn aggressive_xauth_modecfg_quick_mode_esp_dpd_and_delete() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, GOOD));
    let ctx = context();
    let mut est = establish_with_natt_port(&profile(init_port), &ctx, natt_port, None).await.unwrap();
    let mut gw = gateway.await.unwrap().unwrap();

    let s = &est.settings;
    assert_eq!(s.address, Ipv4Addr::new(10, 9, 0, 2));
    assert_eq!(s.routes, ["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]);
    assert!(!s.full_tunnel);
    assert_eq!(s.dns.match_domains, ["corp.test"]);
    assert!(est.dpd);

    let (to_tun, mut tun_rx) = mpsc::channel(8);
    let (tun_tx, from_tun) = mpsc::channel(8);
    let run_ctx = ctx.clone();
    let runner = tokio::spawn(async move {
        let result = est.run(&run_ctx, PacketIo { to_tun, from_tun }).await;
        (est, result)
    });

    // Gateway → tun; a packet to another destination is dropped first.
    let spoofed = gw.esp_out.encapsulate(&ip_packet([10, 0, 0, 1], [10, 9, 0, 99], 9), 4).unwrap();
    gw.sock.send_to(&spoofed, gw.client).await.unwrap();
    let packet = ip_packet([10, 0, 0, 1], [10, 9, 0, 2], 1);
    let esp = gw.esp_out.encapsulate(&packet, 4).unwrap();
    gw.sock.send_to(&esp, gw.client).await.unwrap();
    let got = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
    assert_eq!(&got[..], &packet[..]);

    // tun → gateway.
    let out = ip_packet([10, 9, 0, 2], [10, 0, 0, 1], 2);
    tun_tx.send(out.clone().into()).await.unwrap();
    let (raw, _) = timeout(Duration::from_secs(2), async {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = gw.sock.recv_from(&mut buf).await.unwrap();
            if n > 8 && buf[..4] != [0; 4] {
                return (buf[..n].to_vec(), from);
            }
        }
    })
    .await
    .unwrap();
    let (nh, inner) = gw.esp_in.decapsulate(&raw).unwrap();
    assert_eq!((nh, inner), (4, out));

    // The gateway rekeys (Quick Mode as initiator, with PFS): the client
    // answers, then both use the new SAs.
    let qm_id = random_msg_id();
    let ni = random_bytes(32);
    let kx = KeyExchange::generate(DhGroup::Modp1536).unwrap();
    let gw_spi = 0x0e0f_1011_u32;
    let transform = super::payload::Transform {
        num: 1,
        id: esp_attr::TRANSFORM_ESP_AES,
        attrs: vec![
            super::payload::SaAttr { kind: esp_attr::LIFE_TYPE, value: esp_attr::LIFE_SECONDS },
            super::payload::SaAttr { kind: esp_attr::LIFE_DURATION, value: 3600 },
            super::payload::SaAttr { kind: esp_attr::ENCAPSULATION, value: esp_attr::ENCAP_UDP_TUNNEL },
            super::payload::SaAttr { kind: esp_attr::AUTH_ALG, value: esp_attr::AUTH_HMAC_SHA1 },
            super::payload::SaAttr { kind: esp_attr::KEY_LENGTH, value: 256 },
            super::payload::SaAttr { kind: esp_attr::GROUP, value: 5 },
        ],
    };
    let ids = [
        Id { id_type: id_type::IPV4_ADDR_SUBNET, protocol: 0, port: 0, data: vec![0; 8] },
        Id { id_type: id_type::IPV4_ADDR, protocol: 0, port: 0, data: vec![10, 9, 0, 2] },
    ];
    let qm1 = [
        Payload::Sa(vec![Proposal {
            num: 1,
            protocol: protocol::ESP,
            spi: gw_spi.to_be_bytes().to_vec(),
            transforms: vec![transform],
        }]),
        Payload::Nonce(ni.clone()),
        Payload::Ke(kx.public().to_vec()),
        Payload::Id(ids[0].clone()),
        Payload::Id(ids[1].clone()),
    ];
    let bytes = gw.sa.seal(exchange::QUICK, qm_id, &[], &qm1);
    send_ike(&gw.sock, gw.client, &bytes).await;
    let (raw, _) = timeout(Duration::from_secs(2), recv_natt(&gw.sock)).await.unwrap();
    let (qm2, iv) = gw.sa.open(&raw).unwrap();
    gw.sa.commit(qm_id, iv);
    gw.sa.verify(&qm2, &ni).expect("HASH(2)");
    let nr = qm2.nonce().unwrap().to_vec();
    let client_spi = u32::from_be_bytes(qm2.sa().unwrap()[0].spi.as_slice().try_into().unwrap());
    let gxy = kx.shared_secret(qm2.ke().expect("PFS answered")).unwrap();
    assert_eq!(qm2.ids().cloned().collect::<Vec<_>>(), ids, "identities echoed");
    let hash3 = gw.sa.prf.compute(&gw.sa.skeyid_a, &[&[0], &qm_id.to_be_bytes(), &ni, &nr]);
    let msg3 = gw.sa.seal_with_hash(exchange::QUICK, qm_id, hash3, super::consts::payload::NONE, &[]);
    gw.sa.forget(qm_id);
    send_ike(&gw.sock, gw.client, &msg3).await;
    let (encr, integ) = (EncrAlg::AesCbc { key_bits: 256 }, Some(IntegAlg::HmacSha1Trunc96));
    let esp = |spi: u32| {
        let (e, a) = keymat(gw.sa.prf, &gw.sa.skeyid_d, Some(&gxy), protocol::ESP, spi, &ni, &nr, encr, integ);
        EspSa::new(spi, Cipher::new(encr, integ, &e, &a).unwrap())
    };
    let (mut new_in, mut new_out) = (esp(gw_spi), esp(client_spi));
    let packet = ip_packet([10, 0, 0, 1], [10, 9, 0, 2], 3);
    let esp_packet = new_out.encapsulate(&packet, 4).unwrap();
    gw.sock.send_to(&esp_packet, gw.client).await.unwrap();
    let got = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
    assert_eq!(&got[..], &packet[..], "received on the new SA");
    let out = ip_packet([10, 9, 0, 2], [10, 0, 0, 1], 4);
    tun_tx.send(out.clone().into()).await.unwrap();
    let raw = timeout(Duration::from_secs(2), async {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, _) = gw.sock.recv_from(&mut buf).await.unwrap();
            if n > 8 && buf[..4] != [0; 4] {
                return buf[..n].to_vec();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(new_in.decapsulate(&raw).unwrap(), (4, out), "sent on the new SA");

    // Gateway DPD probe → ACK with the same sequence number.
    let probe = dpd_notify(&gw.sa, notify::R_U_THERE, 4242);
    let mid = random_msg_id();
    let bytes = gw.sa.seal(exchange::INFORMATIONAL, mid, &[], &[probe]);
    gw.sa.forget(mid);
    send_ike(&gw.sock, gw.client, &bytes).await;
    let ack = recv_sealed(&gw.sock, &mut gw.sa, &[]).await;
    gw.sa.forget(ack.header.msg_id);
    let n = ack.notifies().next().unwrap();
    assert_eq!((n.kind, n.data.as_slice()), (notify::R_U_THERE_ACK, &4242u32.to_be_bytes()[..]));
    // The same probe replayed is refused: no second ACK.
    send_ike(&gw.sock, gw.client, &bytes).await;
    let mut buf = [0u8; 2048];
    let more = timeout(Duration::from_millis(300), async {
        loop {
            let (n, _) = gw.sock.recv_from(&mut buf).await.unwrap();
            if n > 4 && buf[..4] == [0; 4] {
                return;
            }
        }
    })
    .await;
    assert!(more.is_err(), "a replayed probe must not be answered");

    // A forged Informational (wrong keys) is ignored; a real delete ends the run.
    let mut forged = gw.sa.seal(
        exchange::INFORMATIONAL,
        99,
        &[],
        &[Payload::Delete { protocol: protocol::ISAKMP, spi_size: 16, spis: vec![vec![0; 16]] }],
    );
    let last = forged.len() - 1;
    forged[last] ^= 0xff;
    send_ike(&gw.sock, gw.client, &forged).await;
    // An authentic Delete of another ISAKMP SA (an earlier one, after a
    // re-authentication) leaves this one alone.
    let other = Payload::Delete { protocol: protocol::ISAKMP, spi_size: 16, spis: vec![vec![7; 16]] };
    let bytes = gw.sa.seal(exchange::INFORMATIONAL, random_msg_id(), &[], &[other]);
    send_ike(&gw.sock, gw.client, &bytes).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!runner.is_finished(), "the Delete names another SA");
    let mid = random_msg_id();
    let delete = Payload::Delete {
        protocol: protocol::ISAKMP,
        spi_size: 16,
        spis: vec![[gw.sa.cky_i.to_be_bytes(), gw.sa.cky_r.to_be_bytes()].concat()],
    };
    let bytes = gw.sa.seal(exchange::INFORMATIONAL, mid, &[], &[delete]);
    send_ike(&gw.sock, gw.client, &bytes).await;
    let (mut est, result) = timeout(Duration::from_secs(3), runner).await.unwrap().unwrap();
    assert!(result.unwrap_err().to_string().contains("deleted the IKE SA"));
    assert_eq!(ctx.stats.rx_packets.load(std::sync::atomic::Ordering::Relaxed), 2);
    est.close().await; // already closed: no-op
}

#[tokio::test]
async fn close_sends_deletes() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, GOOD));
    let mut est = establish_with_natt_port(&profile(init_port), &context(), natt_port, None).await.unwrap();
    let mut gw = gateway.await.unwrap().unwrap();
    est.close().await;
    let mut deleted = Vec::new();
    for _ in 0..2 {
        let msg = recv_sealed(&gw.sock, &mut gw.sa, &[]).await;
        deleted.extend(msg.iter().filter_map(|p| match p {
            Payload::Delete { protocol, .. } => Some(*protocol),
            _ => None,
        }));
    }
    assert_eq!(deleted, [protocol::ESP, protocol::ISAKMP]);
}

#[tokio::test]
async fn wrong_psk_is_detected() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, Behaviour { psk: "other", ..GOOD }));
    let err = establish_with_natt_port(&profile(init_port), &context(), natt_port, None).await.err().unwrap();
    assert!(format!("{err:#}").contains("pre-shared key"), "{err:#}");
    assert_eq!(vpn_core::failure::kind_of(&err), vpn_core::FailureKind::PskRejected);
    gateway.await.unwrap();
}

#[tokio::test]
async fn xauth_rejection_is_reported() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, Behaviour { accept_password: false, ..GOOD }));
    let err = establish_with_natt_port(&profile(init_port), &context(), natt_port, None).await.err().unwrap();
    assert!(err.to_string().contains("XAuth failed"), "{err:#}");
    assert_eq!(vpn_core::failure::kind_of(&err), vpn_core::FailureKind::AuthFailed);
    gateway.await.unwrap();
}

#[tokio::test]
async fn forged_first_reply_is_ignored() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, Behaviour { forged_reply_first: true, ..GOOD }));
    let est = establish_with_natt_port(&profile(init_port), &context(), natt_port, None).await.unwrap();
    assert_eq!(est.settings.address, Ipv4Addr::new(10, 9, 0, 2));
    gateway.await.unwrap().unwrap();
}

/// AES-GCM in phase 2 (FortiOS offers it with IKEv1 too): ESP both ways.
#[tokio::test]
async fn ikev1_esp_aes_gcm() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, GOOD));
    let mut p = profile(init_port);
    p.esp = vec!["aes256gcm16-modp1536".into()];
    esp_both_ways(&p, natt_port, gateway).await;
}

/// Main mode: every DH group offered at once, identities encrypted, and
/// phase 2 IVs chained from message 6.
#[tokio::test]
async fn main_mode_xauth_quick_mode_and_esp() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, Behaviour { main_mode: true, ..GOOD }));
    let mut p = profile(init_port);
    p.exchange_mode = ExchangeMode::Main;
    p.ike = vec!["aes256-sha256-modp2048".into(), "aes256-sha256-modp1536".into()];
    esp_both_ways(&p, natt_port, gateway).await;
}

/// An old gateway: 3DES in both phases (8-byte blocks and IVs), once the
/// profile allows legacy algorithms.
#[tokio::test]
async fn ikev1_legacy_3des() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let mut p = profile(init_port);
    p.ike = vec!["3des-sha256-modp1536".into()];
    p.esp = vec!["3des-sha1-modp1536".into()];
    let Err(refused) = establish_with_natt_port(&p, &context(), natt_port, None).await else { panic!("3DES accepted") };
    let refused = refused.to_string();
    assert!(refused.contains("legacy"), "{refused}");
    p.legacy_algorithms = true;
    let gateway = tokio::spawn(fake_gateway(init, natt, GOOD));
    esp_both_ways(&p, natt_port, gateway).await;
}

async fn esp_both_ways(p: &IpsecProfile, natt_port: u16, gateway: tokio::task::JoinHandle<Option<Gateway>>) {
    let ctx = context();
    let est = establish_with_natt_port(p, &ctx, natt_port, None).await.unwrap();
    let mut gw = gateway.await.unwrap().unwrap();
    let (to_tun, mut tun_rx) = mpsc::channel(8);
    let (tun_tx, from_tun) = mpsc::channel(8);
    let run_ctx = ctx.clone();
    let mut est = est;
    let runner = tokio::spawn(async move { est.run(&run_ctx, PacketIo { to_tun, from_tun }).await });

    let packet = ip_packet([10, 0, 0, 1], [10, 9, 0, 2], 1);
    let esp = gw.esp_out.encapsulate(&packet, 4).unwrap();
    gw.sock.send_to(&esp, gw.client).await.unwrap();
    let got = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
    assert_eq!(&got[..], &packet[..]);

    let out = ip_packet([10, 9, 0, 2], [10, 0, 0, 1], 2);
    tun_tx.send(out.clone().into()).await.unwrap();
    let raw = timeout(Duration::from_secs(2), async {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, _) = gw.sock.recv_from(&mut buf).await.unwrap();
            if n > 8 && buf[..4] != [0; 4] {
                return buf[..n].to_vec();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(gw.esp_in.decapsulate(&raw).unwrap(), (4, out));
    ctx.cancel.cancel();
    runner.await.unwrap().unwrap();
}

/// Several phase 1 DH groups: the first one refused, the next one tried
/// right away.
#[tokio::test]
async fn next_dh_group_after_no_proposal_chosen() {
    let (init, natt, init_port, natt_port) = sockets().await;
    let gateway = tokio::spawn(fake_gateway(init, natt, Behaviour { only_group_5: true, ..GOOD }));
    let mut p = profile(init_port);
    p.ike = vec!["aes256-sha256-modp2048".into(), "aes128-sha1-modp1536".into(), "aes256-sha256-modp1536".into()];
    let started = std::time::Instant::now();
    let est = establish_with_natt_port(&p, &context(), natt_port, None).await.unwrap();
    assert_eq!(est.settings.address, Ipv4Addr::new(10, 9, 0, 2));
    assert!(started.elapsed() < Duration::from_secs(6), "the fallback waits for the grace period only");
    gateway.await.unwrap().unwrap();
}
