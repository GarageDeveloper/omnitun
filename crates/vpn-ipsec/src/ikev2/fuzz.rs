//! Robustness tests for everything parsed from the gateway: IKE headers and
//! payload chains (plain and inside an authenticated SK payload), proposal
//! selection, configuration payloads, DH public values, EAP and ESP.
//! Deterministic seeded inputs; the main assertion is "no panic".

use std::net::Ipv4Addr;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::consts::{cfg, exchange, flags, notify, payload as pt, protocol, transform};
use super::message::{self, HEADER_LEN, Header, Message};
use super::payload::{
    CpAttr, Identity, Notify, Payload, Proposal, TrafficSelector, Transform, decode_chain, encode_chain,
};
use super::settings;
use crate::crypto::{Cipher, DhGroup, EncrAlg, IntegAlg, KeyExchange};
use crate::eap::EapPeer;
use crate::esp::EspSa;
use crate::proposal::{accept_esp, accept_ike, choose_esp, parse_esp, parse_ike};

const ROUNDS: usize = 3000;

fn random_bytes(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let len = rng.random_range(0..=max);
    (0..len).map(|_| rng.random()).collect()
}

fn mutate(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..rng.random_range(1..=4) {
        match rng.random_range(0..5) {
            0 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] = rng.random();
            }
            1 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] ^= 1 << rng.random_range(0..8);
            }
            2 => {
                let i = rng.random_range(0..=v.len());
                v.insert(i, rng.random());
            }
            3 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v.remove(i);
            }
            _ => {
                let i = rng.random_range(0..=v.len());
                v.truncate(i);
            }
        }
    }
    v
}

fn sample_payloads() -> Vec<Payload> {
    vec![
        Payload::Sa(vec![
            Proposal {
                num: 1,
                protocol: protocol::IKE,
                spi: vec![],
                transforms: vec![
                    Transform { kind: transform::ENCR, id: 20, key_len: Some(256) },
                    Transform { kind: transform::PRF, id: 5, key_len: None },
                    Transform { kind: transform::DH, id: 19, key_len: None },
                ],
            },
            Proposal {
                num: 2,
                protocol: protocol::ESP,
                spi: vec![1, 2, 3, 4],
                transforms: vec![Transform { kind: transform::ESN, id: 0, key_len: None }],
            },
        ]),
        Payload::Ke { group: 19, data: vec![9; 64] },
        Payload::Nonce(vec![1; 32]),
        Payload::Notify(Notify::new(notify::COOKIE, vec![5; 8])),
        Payload::IdR(Identity::parse("203.0.113.1")),
        Payload::Auth { method: 2, data: vec![3; 32] },
        Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis: vec![vec![1, 2, 3, 4]] },
        Payload::TsI(vec![TrafficSelector::any()]),
        Payload::TsR(vec![TrafficSelector {
            start: Ipv4Addr::new(10, 0, 0, 0),
            end: Ipv4Addr::new(10, 255, 255, 255),
            ..TrafficSelector::any()
        }]),
        Payload::Cp {
            cfg_type: cfg::REPLY,
            attrs: vec![
                CpAttr { kind: cfg::INTERNAL_IP4_ADDRESS, value: vec![10, 9, 0, 2] },
                CpAttr { kind: cfg::INTERNAL_IP4_DNS, value: vec![10, 0, 0, 53] },
                CpAttr { kind: cfg::INTERNAL_DNS_DOMAIN, value: b"corp.test".to_vec() },
            ],
        },
        Payload::Eap(vec![1, 1, 0, 5, 1]),
    ]
}

fn ciphers() -> Vec<Cipher> {
    vec![
        Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &[1u8; 36], &[]).unwrap(),
        Cipher::new(EncrAlg::AesCbc { key_bits: 128 }, Some(IntegAlg::HmacSha256Trunc128), &[1u8; 16], &[2u8; 32])
            .unwrap(),
    ]
}

/// Exercises every accessor of a parsed message.
fn touch(msg: &Message) {
    let _ = msg.check_errors();
    let _ = (msg.sa(), msg.ke(), msg.nonce(), msg.id_r(), msg.auth(), msg.eap(), msg.cp_attrs());
    let _ = (msg.ts_i(), msg.ts_r(), msg.notify(notify::COOKIE), msg.header.is_response());
    let _ = settings::build(msg, Ipv4Addr::new(203, 0, 113, 1));
}

#[test]
fn plain_messages() {
    let mut rng = StdRng::seed_from_u64(0x494b_4532);
    let seed = message::build_plain(1, 2, exchange::IKE_SA_INIT, flags::RESPONSE, 0, &sample_payloads());
    for cut in 0..=seed.len() {
        let _ = message::parse(&seed[..cut], None);
    }
    for i in 0..ROUNDS * 3 {
        let mut input = if i % 4 == 0 { random_bytes(&mut rng, 120) } else { mutate(&mut rng, &seed) };
        if i % 2 == 0 && input.len() >= HEADER_LEN {
            // Keep a valid version and total length so the chain is reached.
            input[17] = 0x20;
            let len = input.len() as u32;
            input[24..28].copy_from_slice(&len.to_be_bytes());
        }
        let _ = Header::decode(&input);
        if let Ok(msg) = message::parse(&input, None) {
            touch(&msg);
        }
        for c in &ciphers() {
            let _ = message::parse(&input, Some(c));
        }
    }
}

#[test]
fn payload_chains() {
    let mut rng = StdRng::seed_from_u64(0x0043_4841_494e);
    let (first, seed) = encode_chain(&sample_payloads());
    let kinds = [
        pt::SA,
        pt::KE,
        pt::IDI,
        pt::IDR,
        pt::AUTH,
        pt::NONCE,
        pt::NOTIFY,
        pt::DELETE,
        pt::TSI,
        pt::TSR,
        pt::SK,
        pt::CP,
        pt::EAP,
        200,
    ];
    for i in 0..ROUNDS * 3 {
        let kind = if i % 3 == 0 { first } else { kinds[rng.random_range(0..kinds.len())] };
        let data = match i % 4 {
            0 => random_bytes(&mut rng, 80),
            1 => {
                // One payload of `kind` with a correct generic header and a
                // random body, followed by a random next type.
                let body = random_bytes(&mut rng, 60);
                let mut d = vec![kinds[rng.random_range(0..kinds.len())], 0];
                d.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
                d.extend_from_slice(&body);
                d
            }
            _ => mutate(&mut rng, &seed),
        };
        if let Ok(payloads) = decode_chain(kind, &data) {
            // Whatever decodes must re-encode without panicking.
            let encodable: Vec<_> = payloads.into_iter().filter(|p| !matches!(p, Payload::Sk { .. })).collect();
            let _ = encode_chain(&encodable);
        }
    }
}

/// SK payloads that pass authentication but carry garbage: the inner chain
/// and padding come straight from the (authenticated) peer.
#[test]
fn authenticated_garbage_inside_sk() {
    let mut rng = StdRng::seed_from_u64(0x534b);
    let cipher = &ciphers()[0];
    let (_, inner_seed) = encode_chain(&sample_payloads());
    for i in 0..ROUNDS {
        let plain = if i % 2 == 0 { random_bytes(&mut rng, 100) } else { mutate(&mut rng, &inner_seed) };
        let sk_len = 4 + cipher.iv_len() + plain.len() + cipher.icv_len();
        let header = Header {
            spi_i: 1,
            spi_r: 2,
            next: pt::SK,
            exchange: exchange::INFORMATIONAL,
            flags: flags::RESPONSE,
            msg_id: 7,
            length: (HEADER_LEN + sk_len) as u32,
        };
        let mut out = message::build_plain(1, 2, exchange::INFORMATIONAL, flags::RESPONSE, 7, &[]);
        out.truncate(HEADER_LEN);
        out[16] = header.next;
        out[24..28].copy_from_slice(&header.length.to_be_bytes());
        let inner_first =
            [pt::NONCE, pt::CP, pt::NOTIFY, pt::SA, pt::TSR, pt::SK, rng.random()][rng.random_range(0..7)];
        out.extend_from_slice(&[inner_first, 0]);
        out.extend_from_slice(&(sk_len as u16).to_be_bytes());
        let iv = cipher.make_iv(i as u64);
        let sealed = cipher.seal(&iv, &out, &plain);
        out.extend_from_slice(&sealed);
        if let Ok(msg) = message::parse(&out, Some(cipher)) {
            touch(&msg);
        }
    }
}

#[test]
fn proposal_selection() {
    let mut rng = StdRng::seed_from_u64(0x5341);
    let ike = [parse_ike("aes256gcm16-prfsha256-ecp256").unwrap(), parse_ike("aes128-sha256-modp2048").unwrap()];
    let esp = [parse_esp("aes256gcm16").unwrap(), parse_esp("aes256-sha256-modp2048").unwrap()];
    let ids = [0u16, 1, 2, 5, 12, 14, 19, 20, 31, 12345];
    let key_lens = [None, Some(128), Some(192), Some(256), Some(0)];
    for _ in 0..ROUNDS {
        let proposals: Vec<Proposal> = (0..rng.random_range(0..3))
            .map(|_| Proposal {
                num: rng.random(),
                protocol: [protocol::IKE, protocol::ESP, 0][rng.random_range(0..3)],
                spi: random_bytes(&mut rng, 8),
                transforms: (0..rng.random_range(0..6))
                    .map(|_| Transform {
                        kind: rng.random_range(0..7),
                        id: ids[rng.random_range(0..ids.len())],
                        key_len: key_lens[rng.random_range(0..key_lens.len())],
                    })
                    .collect(),
            })
            .collect();
        if let Ok(p) = accept_ike(&proposals, &ike) {
            assert!(ike.contains(&p));
        }
        if let Ok((p, _)) = accept_esp(&proposals, &esp) {
            assert!(esp.iter().any(|o| o.encr == p.encr && o.integ == p.integ));
        }
        let group = [None, Some(14), Some(19), Some(0), Some(999)][rng.random_range(0..5)];
        if let Some((_, _, p)) = choose_esp(&proposals, &esp, group) {
            assert!(esp.iter().any(|o| o.encr == p.encr && o.integ == p.integ));
        }
    }
}

#[test]
fn configuration_payloads() {
    let mut rng = StdRng::seed_from_u64(0x4350);
    let kinds =
        [cfg::INTERNAL_IP4_ADDRESS, cfg::INTERNAL_IP4_DNS, cfg::INTERNAL_IP4_SUBNET, cfg::INTERNAL_DNS_DOMAIN, 99];
    for _ in 0..ROUNDS {
        let attrs = (0..rng.random_range(0..5))
            .map(|_| CpAttr { kind: kinds[rng.random_range(0..kinds.len())], value: random_bytes(&mut rng, 10) })
            .collect();
        let ts = |rng: &mut StdRng| -> Vec<TrafficSelector> {
            (0..rng.random_range(0..3))
                .map(|_| TrafficSelector {
                    ip_proto: 0,
                    start_port: 0,
                    end_port: 65535,
                    start: Ipv4Addr::from(rng.random::<u32>()),
                    end: Ipv4Addr::from(rng.random::<u32>()),
                })
                .collect()
        };
        let msg = Message {
            header: Header::decode(&message::build_plain(1, 2, exchange::IKE_AUTH, flags::RESPONSE, 1, &[])).unwrap(),
            payloads: vec![
                Payload::Cp { cfg_type: cfg::REPLY, attrs },
                Payload::TsI(ts(&mut rng)),
                Payload::TsR(ts(&mut rng)),
            ],
        };
        let _ = settings::build(&msg, Ipv4Addr::new(203, 0, 113, 1));
    }
}

#[test]
fn range_to_cidrs_covers_exactly() {
    let mut rng = StdRng::seed_from_u64(0x4349_4452);
    let mut cases = vec![(0, u32::MAX), (0, 0), (u32::MAX, u32::MAX), (1, 0), (5, 4), (u32::MAX - 1, u32::MAX)];
    for _ in 0..ROUNDS {
        let a: u32 = rng.random();
        let bits = rng.random_range(0..32);
        let span = rng.random_range(0..1u32 << bits);
        cases.push((a, a.saturating_add(span)));
        cases.push((rng.random(), rng.random()));
    }
    for (start, end) in cases {
        let nets = settings::range_to_cidrs(start, end);
        if start > end {
            assert!(nets.is_empty());
            continue;
        }
        // Contiguous, aligned blocks exactly covering start..=end.
        let mut next = u64::from(start);
        for n in &nets {
            assert_eq!(u64::from(u32::from(n.network())), next, "{start}..{end}: {nets:?}");
            next += 1u64 << (32 - n.prefix_len());
        }
        assert_eq!(next, u64::from(end) + 1, "{start}..{end}: {nets:?}");
        assert!(nets.len() <= 62);
    }
}

#[test]
fn dh_public_values() {
    let mut rng = StdRng::seed_from_u64(0x4448);
    for group in [DhGroup::Ecp256, DhGroup::Curve25519, DhGroup::Modp2048] {
        let kx = KeyExchange::generate(group).unwrap();
        let n = if group == DhGroup::Modp2048 { 20 } else { 300 };
        let len = kx.public().len();
        for i in 0..n {
            let peer = match i % 3 {
                0 => random_bytes(&mut rng, 300),
                1 => (0..len).map(|_| rng.random()).collect(),
                _ => mutate(&mut rng, kx.public()),
            };
            let _ = kx.shared_secret(&peer);
        }
        for peer in [vec![], vec![0; len], vec![0xff; len], vec![1; len]] {
            let _ = kx.shared_secret(&peer);
        }
    }
    let modp = KeyExchange::generate(DhGroup::Modp2048).unwrap();
    let mut one = vec![0u8; 256];
    one[255] = 1;
    assert!(modp.shared_secret(&one).is_err(), "y = 1 must be refused");
    assert!(KeyExchange::generate(DhGroup::Curve25519).unwrap().shared_secret(&[0; 32]).is_err(), "low-order point");
}

#[test]
fn eap_packets() {
    let mut rng = StdRng::seed_from_u64(0x0045_4150);
    let mut challenge = vec![1, 7, 0, 0, 26, 1, 7, 0, 0, 16];
    challenge.extend_from_slice(&[0x5b; 16]);
    challenge.extend_from_slice(b"gateway");
    let len = challenge.len() as u16;
    challenge[2..4].copy_from_slice(&len.to_be_bytes());
    let seeds = [
        vec![1, 1, 0, 5, 1],
        vec![1, 2, 0, 5, 2],
        vec![1, 3, 0, 6, 4, 26],
        challenge,
        b"\x01\x08\x00\x2f\x1a\x03\x07\x00\x2aS=0123456789ABCDEF0123456789ABCDEF01234567 M=ok".to_vec(),
        b"\x01\x09\x00\x1d\x1a\x04\x07\x00\x18E=691 R=0 C=00 V=3 M=x".to_vec(),
        vec![3, 1, 0, 4],
        vec![4, 1, 0, 4],
    ];
    for i in 0..ROUNDS {
        let mut peer = EapPeer::new("DOMAIN\\alice".into(), "pässword".into());
        for _ in 0..4 {
            let packet = if i % 3 == 0 {
                random_bytes(&mut rng, 70)
            } else {
                let seed = &seeds[rng.random_range(0..seeds.len())];
                mutate(&mut rng, seed)
            };
            let _ = peer.process(&packet);
        }
        // Success is never accepted without the server's proof.
        let mut fresh = EapPeer::new("alice".into(), "x".into());
        assert!(fresh.process(&[3, 1, 0, 4]).is_err());
        assert!(fresh.msk().is_none());
    }
}

#[test]
fn esp_packets() {
    let mut rng = StdRng::seed_from_u64(0x0045_5350);
    let spi = 0x1234_5678u32;
    let make = |gcm: bool| {
        if gcm {
            Cipher::new(EncrAlg::AesGcm16 { key_bits: 128 }, None, &[3u8; 20], &[]).unwrap()
        } else {
            Cipher::new(EncrAlg::AesCbc { key_bits: 256 }, Some(IntegAlg::HmacSha256Trunc128), &[3u8; 32], &[4u8; 32])
                .unwrap()
        }
    };
    for gcm in [true, false] {
        let mut tx = EspSa::new(spi, make(gcm));
        let mut rx = EspSa::new(spi, make(gcm));
        let seal = make(gcm);
        for i in 0..ROUNDS {
            let packet = match i % 4 {
                0 => {
                    let mut p = spi.to_be_bytes().to_vec();
                    p.extend(random_bytes(&mut rng, 80));
                    p
                }
                1 => {
                    let valid = tx.encapsulate(&random_bytes(&mut rng, 60), 4).unwrap();
                    mutate(&mut rng, &valid)
                }
                2 => {
                    // Authenticated packet with an arbitrary trailer.
                    let seq = (i as u32) + 1;
                    let mut header = spi.to_be_bytes().to_vec();
                    header.extend_from_slice(&seq.to_be_bytes());
                    let block = seal.block_len();
                    let mut plain = random_bytes(&mut rng, 40);
                    plain.resize(plain.len().div_ceil(block) * block, 0xff);
                    let sealed = seal.seal(&seal.make_iv(u64::from(seq)), &header, &plain);
                    [header, sealed].concat()
                }
                _ => random_bytes(&mut rng, 40),
            };
            if let Ok((_, inner)) = rx.decapsulate(&packet) {
                assert!(inner.len() + 2 <= packet.len());
            }
        }
    }
}
