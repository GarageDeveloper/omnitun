//! Loopback tests: the real initiator against a minimal scripted responder
//! built from the same primitives.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use vpn_core::{IpsecProfile, PacketIo, Prompt, Prompter, SessionContext};

use super::consts::{auth_method, cfg, exchange, flags, notify, protocol};
use super::handshake::establish_with_natt_port;
use super::keys::{IkeKeys, derive_child_keys, derive_ike_keys, shared_key_auth};
use super::message::{self, Message};
use super::payload::{CpAttr, Identity, Notify, Payload, TrafficSelector};
use crate::crypto::{KeyExchange, random_bytes};
use crate::esp::EspSa;
use crate::proposal::{EspProposal, parse_esp, parse_ike};

const PSK: &str = "secret";
const GATEWAY_ID: &str = "203.0.113.1";

struct StaticPrompter;

#[async_trait]
impl Prompter for StaticPrompter {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<zeroize::Zeroizing<String>> {
        // The test answers, erased like real ones.
        let answer: anyhow::Result<String> =
            async { Ok(if prompt.key == "psk" { PSK.into() } else { String::new() }) }.await;
        answer.map(zeroize::Zeroizing::new)
    }

    async fn open_url(&self, _url: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

struct Gateway {
    sock: UdpSocket,
    client: SocketAddr,
    keys: IkeKeys,
    spi_i: u64,
    spi_r: u64,
    esp: EspProposal,
    esp_out: EspSa,
    esp_in: EspSa,
    next_request_id: u32,
    iv: u64,
}

impl Gateway {
    async fn recv_raw(&self, want_ike: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, _) = self.sock.recv_from(&mut buf).await.unwrap();
            match &buf[..n] {
                [0xff] => continue,
                [0, 0, 0, 0, rest @ ..] if want_ike => return rest.to_vec(),
                data if !want_ike && data[..4] != [0, 0, 0, 0] => return data.to_vec(),
                _ => continue,
            }
        }
    }

    async fn recv_ike(&self) -> Message {
        let raw = timeout(Duration::from_secs(5), self.recv_raw(true)).await.unwrap();
        message::parse(&raw, Some(&self.keys.out)).unwrap()
    }

    async fn send_ike(&mut self, exchange: u8, flags: u8, msg_id: u32, payloads: &[Payload]) {
        self.iv += 1;
        let iv = self.keys.inbound.make_iv(self.iv);
        let bytes = message::build_encrypted(
            self.spi_i,
            self.spi_r,
            exchange,
            flags,
            msg_id,
            payloads,
            &self.keys.inbound,
            &iv,
        );
        self.sock.send_to(&[&[0u8; 4][..], &bytes].concat(), self.client).await.unwrap();
    }

    async fn request(&mut self, exchange: u8, payloads: &[Payload]) -> Message {
        let id = self.next_request_id;
        self.next_request_id += 1;
        self.send_ike(exchange, 0, id, payloads).await;
        let resp = self.recv_ike().await;
        assert!(resp.header.is_response());
        assert_eq!(resp.header.msg_id, id);
        resp
    }
}

/// Scripted IKE_SA_INIT + IKE_AUTH responder (PSK).
async fn fake_gateway(init: UdpSocket, natt: UdpSocket, ike_spec: &str, esp_spec: &str) -> Gateway {
    let algs = parse_ike(ike_spec).unwrap();
    let esp = parse_esp(esp_spec).unwrap();
    let mut buf = vec![0u8; 65536];

    let (n, client) = init.recv_from(&mut buf).await.unwrap();
    let req_raw = buf[..n].to_vec();
    let req = message::parse(&req_raw, None).unwrap();
    assert!(req.notify(notify::NAT_DETECTION_SOURCE_IP).is_some());
    let (group, ke) = req.ke().unwrap();
    assert_eq!(group, algs.dh.id());
    let kx = KeyExchange::generate(algs.dh).unwrap();
    let shared = kx.shared_secret(ke).unwrap();
    let ni = req.nonce().unwrap().to_vec();
    let nr = random_bytes(32);
    let (spi_i, spi_r) = (req.header.spi_i, 0x1122_3344_5566_7788);
    let payloads = [
        Payload::Sa(vec![algs.sa_proposal(1)]),
        Payload::Ke { group, data: kx.public().to_vec() },
        Payload::Nonce(nr.clone()),
        Payload::Notify(Notify::new(notify::NAT_DETECTION_SOURCE_IP, vec![1; 20])),
        Payload::Notify(Notify::new(notify::NAT_DETECTION_DESTINATION_IP, vec![2; 20])),
    ];
    let resp_raw = message::build_plain(spi_i, spi_r, exchange::IKE_SA_INIT, flags::RESPONSE, 0, &payloads);
    init.send_to(&resp_raw, client).await.unwrap();
    let keys = derive_ike_keys(&algs, &shared, &ni, &nr, spi_i, spi_r).unwrap();

    let (n, client) = natt.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..4], &[0, 0, 0, 0], "IKE on 4500 needs the non-ESP marker");
    let auth_req = message::parse(&buf[4..n], Some(&keys.out)).unwrap();
    let idi = auth_req
        .payloads
        .iter()
        .find_map(|p| match p {
            Payload::IdI(id) => Some(id.clone()),
            _ => None,
        })
        .unwrap();
    let (method, data) = auth_req.auth().unwrap();
    assert_eq!(method, auth_method::SHARED_KEY_MIC);
    let expected = shared_key_auth(keys.prf, PSK.as_bytes(), &req_raw, &nr, &keys.sk_pi, &idi.body());
    assert_eq!(data, expected.as_slice(), "initiator AUTH");
    let client_spi = u32::from_be_bytes(auth_req.sa().unwrap()[0].spi.as_slice().try_into().unwrap());

    let our_spi = 0xabcd_ef01;
    let idr = Identity::parse(GATEWAY_ID);
    let auth = shared_key_auth(keys.prf, PSK.as_bytes(), &resp_raw, &ni, &keys.sk_pr, &idr.body());
    let assigned = Ipv4Addr::new(10, 9, 0, 2);
    let payloads = [
        Payload::IdR(idr),
        Payload::Auth { method: auth_method::SHARED_KEY_MIC, data: auth },
        Payload::Cp {
            cfg_type: cfg::REPLY,
            attrs: vec![
                CpAttr { kind: cfg::INTERNAL_IP4_ADDRESS, value: assigned.octets().to_vec() },
                CpAttr { kind: cfg::INTERNAL_IP4_DNS, value: vec![10, 0, 0, 53] },
                CpAttr { kind: cfg::INTERNAL_DNS_DOMAIN, value: b"corp.test".to_vec() },
            ],
        },
        Payload::Sa(vec![esp.sa_proposal(1, our_spi, None)]),
        Payload::TsI(vec![TrafficSelector { start: assigned, end: assigned, ..TrafficSelector::any() }]),
        Payload::TsR(vec![TrafficSelector {
            start: Ipv4Addr::new(10, 0, 0, 0),
            end: Ipv4Addr::new(10, 255, 255, 255),
            ..TrafficSelector::any()
        }]),
    ];
    let (out, inbound) = derive_child_keys(keys.prf, &keys.sk_d, None, &ni, &nr, esp.encr, esp.integ, false).unwrap();
    let mut gw = Gateway {
        sock: natt,
        client,
        keys,
        spi_i,
        spi_r,
        esp,
        esp_out: EspSa::new(client_spi, out),
        esp_in: EspSa::new(our_spi, inbound),
        next_request_id: 0,
        iv: 0,
    };
    gw.send_ike(exchange::IKE_AUTH, flags::RESPONSE, auth_req.header.msg_id, &payloads).await;
    gw
}

fn ip_packet(src: [u8; 4], dst: [u8; 4], tag: u8) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[tag; 8]);
    p
}

/// Client → corporate network.
fn ipv4_packet(tag: u8) -> Vec<u8> {
    ip_packet([10, 9, 0, 2], [10, 0, 0, 1], tag)
}

/// Corporate network → client.
fn inbound_packet(tag: u8) -> Vec<u8> {
    ip_packet([10, 0, 0, 1], [10, 9, 0, 2], tag)
}

fn profile(port: u16, ike_spec: &str, esp_spec: &str) -> IpsecProfile {
    IpsecProfile {
        gateway: "127.0.0.1".into(),
        port,
        ike_version: 2,
        exchange_mode: Default::default(),
        xauth: false,
        local_id: Some("roadwarrior@corp.test".into()),
        remote_id: Some(GATEWAY_ID.into()),
        username: None,
        ike: vec![ike_spec.into()],
        esp: vec![esp_spec.into()],
        phase1_lifetime: 86_400,
        phase2_lifetime: 43_200,
        phase2_lifetime_kb: None,
        dpd: true,
        legacy_algorithms: ike_spec.starts_with("3des"),
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
        name: "test".into(),
        prompter: Arc::new(StaticPrompter),
        cancel: CancellationToken::new(),
        stats: Arc::default(),
    }
}

#[tokio::test]
async fn handshake_esp_rekey_and_delete_over_loopback() {
    let cases = [
        ("aes256gcm16-prfsha256-ecp256", "aes256gcm16"),
        ("aes128-sha256-modp2048", "aes256-sha256"),
        ("aes256gcm16-prfsha384-x25519", "aes128gcm16"),
        ("chacha20poly1305-prfsha256-x25519", "chacha20poly1305"),
        ("3des-sha1-modp1024", "3des-sha1"),
    ];
    for (ike_spec, esp_spec) in cases {
        let init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let natt = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (init_port, natt_port) = (init.local_addr().unwrap().port(), natt.local_addr().unwrap().port());
        let profile = profile(init_port, ike_spec, esp_spec);
        let ctx = context();
        let gateway = tokio::spawn(fake_gateway(init, natt, ike_spec, esp_spec));
        let mut est = establish_with_natt_port(&profile, &ctx, natt_port).await.unwrap();
        let mut gw = gateway.await.unwrap();

        let s = &est.settings;
        assert_eq!(s.address, Ipv4Addr::new(10, 9, 0, 2));
        assert_eq!(s.routes, vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]);
        assert!(!s.full_tunnel);
        assert_eq!(s.dns.match_domains, vec!["corp.test".to_string()]);

        let (to_tun, mut tun_rx) = mpsc::channel(8);
        let (tun_tx, from_tun) = mpsc::channel(8);
        let run_ctx = ctx.clone();
        let runner = tokio::spawn(async move {
            let result = est.run(&run_ctx, PacketIo { to_tun, from_tun }).await;
            (est, result)
        });

        // Gateway → tun. Spoofed packets (source outside TSr, destination
        // not our address) are dropped before the valid one.
        for spoofed in [ip_packet([192, 168, 1, 1], [10, 9, 0, 2], 9), ip_packet([10, 0, 0, 1], [10, 9, 0, 99], 9)] {
            let esp = gw.esp_out.encapsulate(&spoofed, 4).unwrap();
            gw.sock.send_to(&esp, gw.client).await.unwrap();
        }
        let packet = inbound_packet(1);
        let esp = gw.esp_out.encapsulate(&packet, 4).unwrap();
        gw.sock.send_to(&esp, gw.client).await.unwrap();
        let got = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        assert_eq!(got.as_ref(), packet.as_slice());

        // tun → gateway.
        tun_tx.send(Bytes::from(ipv4_packet(2))).await.unwrap();
        let raw = timeout(Duration::from_secs(2), gw.recv_raw(false)).await.unwrap();
        assert_eq!(gw.esp_in.decapsulate(&raw).unwrap(), (4, ipv4_packet(2)));

        // Gateway-initiated CHILD SA rekey with selectors outside the tunnel's.
        let mut rekey = Notify::new(notify::REKEY_SA, Vec::new());
        rekey.protocol = protocol::ESP;
        rekey.spi = gw.esp_in.spi.to_be_bytes().to_vec();
        let foreign = TrafficSelector {
            start: Ipv4Addr::new(192, 168, 0, 0),
            end: Ipv4Addr::new(192, 168, 255, 255),
            ..TrafficSelector::any()
        };
        let resp = gw
            .request(
                exchange::CREATE_CHILD_SA,
                &[
                    Payload::Notify(rekey.clone()),
                    Payload::Sa(vec![gw.esp.sa_proposal(1, 0x0bad_f00d, None)]),
                    Payload::Nonce(random_bytes(32)),
                    Payload::TsI(vec![foreign]),
                    Payload::TsR(vec![TrafficSelector::any()]),
                ],
            )
            .await;
        assert!(resp.notify(notify::TS_UNACCEPTABLE).is_some());

        // Rekey with a too short nonce.
        let resp = gw
            .request(
                exchange::CREATE_CHILD_SA,
                &[
                    Payload::Notify(rekey.clone()),
                    Payload::Sa(vec![gw.esp.sa_proposal(1, 0x0bad_f00d, None)]),
                    Payload::Nonce(random_bytes(8)),
                    Payload::TsI(vec![TrafficSelector::any()]),
                    Payload::TsR(vec![TrafficSelector::any()]),
                ],
            )
            .await;
        assert!(resp.notify(notify::INVALID_SYNTAX).is_some());

        // Valid gateway-initiated CHILD SA rekey (no PFS); the client narrows
        // the "any" selectors to the tunnel's.
        let new_gw_spi = 0x0bad_cafe;
        let ni = random_bytes(32);
        let resp = gw
            .request(
                exchange::CREATE_CHILD_SA,
                &[
                    Payload::Notify(rekey),
                    Payload::Sa(vec![gw.esp.sa_proposal(1, new_gw_spi, None)]),
                    Payload::Nonce(ni.clone()),
                    Payload::TsI(vec![TrafficSelector::any()]),
                    Payload::TsR(vec![TrafficSelector::any()]),
                ],
            )
            .await;
        resp.check_errors().unwrap();
        assert_eq!(
            resp.ts_i(),
            &[TrafficSelector {
                start: Ipv4Addr::new(10, 0, 0, 0),
                end: Ipv4Addr::new(10, 255, 255, 255),
                ..TrafficSelector::any()
            }]
        );
        let client_spi = u32::from_be_bytes(resp.sa().unwrap()[0].spi.as_slice().try_into().unwrap());
        let (out, inbound) = derive_child_keys(
            gw.keys.prf,
            &gw.keys.sk_d,
            None,
            &ni,
            resp.nonce().unwrap(),
            gw.esp.encr,
            gw.esp.integ,
            true,
        )
        .unwrap();
        let mut new_out = EspSa::new(client_spi, out);
        gw.esp_in = EspSa::new(new_gw_spi, inbound);
        let packet = inbound_packet(3);
        gw.sock.send_to(&new_out.encapsulate(&packet, 4).unwrap(), gw.client).await.unwrap();
        let got = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        assert_eq!(got.as_ref(), packet.as_slice());
        tun_tx.send(Bytes::from(ipv4_packet(4))).await.unwrap();
        let raw = timeout(Duration::from_secs(2), gw.recv_raw(false)).await.unwrap();
        assert_eq!(gw.esp_in.decapsulate(&raw).unwrap(), (4, ipv4_packet(4)));

        // Gateway deletes the current CHILD SA: the session must end.
        let delete =
            Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis: vec![new_gw_spi.to_be_bytes().to_vec()] };
        let resp = gw.request(exchange::INFORMATIONAL, &[delete]).await;
        let deleted = resp.payloads.iter().any(|p| {
            matches!(p, Payload::Delete { protocol: protocol::ESP, spis, .. } if spis[0] == client_spi.to_be_bytes())
        });
        assert!(deleted, "client must answer with its own inbound SPI");
        let (mut est, result) = timeout(Duration::from_secs(2), runner).await.unwrap().unwrap();
        assert!(result.unwrap_err().to_string().contains("deleted"));

        // Disconnect deletes the IKE SA.
        let closer = tokio::spawn(async move {
            est.close().await;
            est.closed
        });
        let req = gw.recv_ike().await;
        assert!(!req.header.is_response());
        assert!(req.payloads.iter().any(|p| matches!(p, Payload::Delete { protocol: protocol::IKE, .. })));
        gw.send_ike(exchange::INFORMATIONAL, flags::RESPONSE, req.header.msg_id, &[]).await;
        assert!(closer.await.unwrap());
        assert_eq!(ctx.stats.rx_packets.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}

/// A refused rekey is retried later, not at every tick, whatever triggered
/// it; the SA still ends at its lifetime.
#[tokio::test]
async fn refused_rekey_waits_then_the_sa_expires() {
    let (ike_spec, esp_spec) = ("aes256gcm16-prfsha256-ecp256", "aes256gcm16");
    let init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let natt = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (init_port, natt_port) = (init.local_addr().unwrap().port(), natt.local_addr().unwrap().port());
    let ctx = context();
    let gateway = tokio::spawn(fake_gateway(init, natt, ike_spec, esp_spec));
    let mut est = establish_with_natt_port(&profile(init_port, ike_spec, esp_spec), &ctx, natt_port).await.unwrap();
    let mut gw = gateway.await.unwrap();
    // Rekey due by volume at once; the SA ends 3 s after its creation.
    est.limits.child_rekey_kb = Some(0);
    est.limits.child_lifetime = Duration::from_secs(3);

    let (to_tun, _tun_rx) = mpsc::channel(8);
    let (_tun_tx, from_tun) = mpsc::channel(8);
    let run_ctx = ctx.clone();
    let runner = tokio::spawn(async move { est.run(&run_ctx, PacketIo { to_tun, from_tun }).await });

    let rekey = gw.recv_ike().await;
    assert_eq!(rekey.header.exchange, exchange::CREATE_CHILD_SA);
    let refused = Payload::Notify(Notify::new(notify::NO_PROPOSAL_CHOSEN, Vec::new()));
    gw.send_ike(exchange::CREATE_CHILD_SA, flags::RESPONSE, rekey.header.msg_id, &[refused]).await;

    let result = timeout(Duration::from_secs(6), runner).await.unwrap().unwrap();
    assert!(result.unwrap_err().to_string().contains("expired"));
    // Before the fix, a new CREATE_CHILD_SA went out every second.
    let again = timeout(Duration::from_millis(100), gw.recv_raw(true)).await;
    assert!(again.is_err(), "no second rekey before the retry delay");
}

#[tokio::test]
async fn request_ignores_forged_responses() {
    use crate::crypto::{Cipher, EncrAlg};
    use crate::transport::Transport;

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(addr) = server.local_addr().unwrap() else { unreachable!() };
    let transport = Transport::connect(addr).await.unwrap();
    let key = [7u8; 36];
    let cipher = || Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &key, &[]).unwrap();
    let (gw_cipher, client_cipher) = (cipher(), cipher());

    let responder = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (_, client) = server.recv_from(&mut buf).await.unwrap();
        let reply = |payloads: &[Payload], c: &crate::crypto::Cipher, iv: u64| {
            message::build_encrypted(1, 2, exchange::INFORMATIONAL, flags::RESPONSE, 5, payloads, c, &c.make_iv(iv))
        };
        // Same header, but encrypted with another key: fails integrity.
        let wrong = Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &[9u8; 36], &[]).unwrap();
        server.send_to(&reply(&[], &wrong, 1), client).await.unwrap();
        // Same header, truncated garbage.
        let mut garbage = reply(&[], &gw_cipher, 2);
        garbage.truncate(30);
        server.send_to(&garbage, client).await.unwrap();
        // The genuine response.
        let genuine = [Payload::Notify(Notify::new(notify::INITIAL_CONTACT, Vec::new()))];
        server.send_to(&reply(&genuine, &gw_cipher, 3), client).await.unwrap();
    });
    let request_bytes = message::build_plain(1, 2, exchange::INFORMATIONAL, flags::INITIATOR, 5, &[]);
    let (_, msg) = super::request(&transport, &CancellationToken::new(), &request_bytes, 5, 1, 2, |r| {
        message::parse(r, Some(&client_cipher))
    })
    .await
    .unwrap();
    assert!(msg.notify(notify::INITIAL_CONTACT).is_some());
    responder.await.unwrap();
}

/// What the client agrees to sign: our real AUTH octets pass, other data
/// (a TLS 1.3 CertificateVerify, a responder's message) does not.
#[test]
fn signed_octets_look_like_ike() {
    use super::keys::signed_octets;
    use vpn_core::prompt::is_ike_auth_octets;
    let payloads =
        [Payload::Nonce(random_bytes(32)), Payload::Notify(Notify::new(notify::INITIAL_CONTACT, Vec::new()))];
    let init = message::build_plain(7, 0, exchange::IKE_SA_INIT, flags::INITIATOR, 0, &payloads);
    let prf = crate::crypto::PrfAlg::HmacSha256;
    let ours = signed_octets(prf, &init, &random_bytes(32), &[1; 32], b"id");
    assert!(is_ike_auth_octets(&ours));
    let response = message::build_plain(7, 9, exchange::IKE_SA_INIT, flags::RESPONSE, 0, &payloads);
    assert!(!is_ike_auth_octets(&signed_octets(prf, &response, &random_bytes(32), &[1; 32], b"id")));
    let tls13 = [&[0x20; 64][..], b"TLS 1.3, client CertificateVerify\0", &[0; 32]].concat();
    assert!(!is_ike_auth_octets(&tls13));
    assert!(!is_ike_auth_octets(&init), "no nonce or PRF output");
    assert!(!is_ike_auth_octets(&[&ours[..], &[0; 400]].concat()), "trailing data");
}
