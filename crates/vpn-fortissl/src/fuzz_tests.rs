//! Robustness tests for everything parsed from the network: HTTP responses,
//! the XML configuration, tunnel frame headers and PPP. Deterministic
//! (seeded) random and mutated inputs; the only assertion is "no panic"
//! plus a few invariants on what is accepted.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::ppp::{PROTO_IPCP, PROTO_LCP, Ppp};
use crate::{config, http, tunnel};

const ROUNDS: usize = 3000;

fn random_bytes(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let len = rng.random_range(0..=max);
    (0..len).map(|_| rng.random()).collect()
}

/// Flips, inserts, deletes or truncates bytes of a valid input.
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

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
}

#[test]
fn http_responses() {
    let seeds: [&[u8]; 4] = [
        b"HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc; path=/\r\nContent-Length: 5\r\n\r\nret=1",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<a/>\r\n3;x=y\r\nabc\r\n0\r\n\r\n",
        b"HTTP/1.1 401 Unauthorized\r\n\r\nret=0,redir=/remote/login",
        b"HTTP/1.0 302\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
    ];
    let mut rng = StdRng::seed_from_u64(0x4854_5450);
    block_on(async {
        for seed in seeds {
            for cut in 0..=seed.len() {
                let _ = http::read_response(&mut &seed[..cut]).await;
            }
        }
        for i in 0..ROUNDS {
            let input = if i % 4 == 0 { random_bytes(&mut rng, 300) } else { mutate(&mut rng, seeds[i % seeds.len()]) };
            if let Ok(resp) = http::read_response(&mut &input[..]).await {
                assert!(resp.body.len() <= input.len());
                let _ = resp.text();
            }
        }
        // Hostile sizes: huge chunk / content length, oversized headers.
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
            b"HTTP/1.1 abc\r\n\r\n",
            b"\r\n\r\n",
        ] {
            assert!(http::read_response(&mut &raw[..]).await.is_err(), "{}", String::from_utf8_lossy(raw));
        }
        let big = [b"HTTP/1.1 200 OK\r\nX: ".to_vec(), vec![b'a'; 70_000]].concat();
        assert!(http::read_response(&mut &big[..]).await.is_err());
    });
}

#[test]
fn xml_config() {
    let seed = br#"<?xml version='1.0' encoding='utf-8'?>
<sslvpn-tunnel ver='2'><ipv4><dns ip='10.1.1.53' domain='a.example'/><dns-suffix val='corp.example;lab.example'/>
<assigned-addr ipv4='10.212.134.200'/><split-tunnel-info><addr ip='10.1.0.0' mask='255.255.0.0'/></split-tunnel-info>
<split-tunnel-info negate='1'><addr ip='10.1.99.0' mask='255.255.255.0'/></split-tunnel-info></ipv4>
<ipv6><dns ipv6='fd00::53'/></ipv6><idle-timeout val='3600'/><auth-timeout val='28800'/></sslvpn-tunnel>"#;
    let mut rng = StdRng::seed_from_u64(0x0058_4d4c);
    for cut in 0..=seed.len() {
        let _ = config::parse(&String::from_utf8_lossy(&seed[..cut]));
    }
    for i in 0..ROUNDS {
        let input = if i % 5 == 0 { random_bytes(&mut rng, 200) } else { mutate(&mut rng, seed) };
        let _ = config::parse(&String::from_utf8_lossy(&input));
    }
    // Odd but well-formed values must be ignored, not trusted.
    let cfg = config::parse(
        "<sslvpn-tunnel><addr ip='10.0.0.1' mask='255.0.255.0'/><addr ip='x' mask='y'/>\
         <assigned-addr ipv4='999.1.1.1'/><dns ip='::1'/><idle-timeout val='-1'/></sslvpn-tunnel>",
    )
    .unwrap();
    assert_eq!(cfg, config::GatewayConfig::default());
}

#[test]
fn tunnel_frames() {
    let mut rng = StdRng::seed_from_u64(0x5050);
    let seed = tunnel::encode_frame(&[0xc0, 0x21, 1, 1, 0, 4]).unwrap();
    block_on(async {
        for i in 0..ROUNDS {
            let input = if i % 2 == 0 { random_bytes(&mut rng, 40) } else { mutate(&mut rng, &seed) };
            if let Ok(payload) = tunnel::read_frame(&mut &input[..]).await {
                // Accepted frames are self-consistent.
                assert!(!payload.is_empty());
                assert_eq!(tunnel::encode_frame(&payload).unwrap(), input[..payload.len() + 6]);
            }
        }
    });
    assert!(tunnel::encode_frame(&vec![0; 65530]).is_err());
    assert!(tunnel::encode_frame(&vec![0; 65529]).is_ok());
}

fn cp(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut f = proto.to_be_bytes().to_vec();
    f.extend_from_slice(&[code, id]);
    f.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// Brings a PPP instance to the up state against a well-behaved peer.
fn opened_ppp() -> Ppp {
    let mut ppp = Ppp::new(1354);
    ppp.start();
    let lcp_id = ppp.drain()[0][3];
    ppp.input(&cp(PROTO_LCP, 1, 1, &[1, 4, 5, 0x4a])).unwrap();
    ppp.input(&cp(PROTO_LCP, 2, lcp_id, &[])).unwrap();
    let ipcp_id = ppp.drain().last().unwrap()[3];
    ppp.input(&cp(PROTO_IPCP, 1, 1, &[3, 6, 1, 2, 3, 4])).unwrap();
    ppp.input(&cp(PROTO_IPCP, 2, ipcp_id, &[])).unwrap();
    assert!(ppp.is_up());
    ppp.drain();
    ppp
}

#[test]
fn ppp_input() {
    let mut rng = StdRng::seed_from_u64(0x0050_5050);
    let seeds = [
        cp(PROTO_LCP, 1, 7, &[1, 4, 0x05, 0x4a, 5, 6, 1, 2, 3, 4, 3, 4, 0xc0, 0x23]),
        cp(PROTO_LCP, 3, 1, &[1, 4, 0x05, 0xdc, 5, 6, 9, 9, 9, 9]),
        cp(PROTO_LCP, 4, 1, &[1, 4, 0x05, 0xdc]),
        cp(PROTO_LCP, 9, 3, &[0, 0, 0, 1, 0xaa]),
        cp(PROTO_LCP, 8, 3, &[0x80, 0x21, 1, 2]),
        cp(PROTO_IPCP, 1, 2, &[3, 6, 169, 254, 2, 1]),
        cp(PROTO_IPCP, 3, 2, &[3, 6, 10, 0, 0, 1, 129, 6, 10, 0, 0, 53, 131, 6, 10, 0, 0, 54]),
        cp(PROTO_IPCP, 4, 2, &[129, 6, 0, 0, 0, 0]),
        cp(0x8057, 1, 1, &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1]),
        vec![0x00, 0x21, 0x45, 0, 0, 20],
        vec![0xff, 0x03, 0xc0, 0x21, 9, 1, 0, 8, 0, 0, 0, 0],
    ];
    for round in 0..ROUNDS {
        // Alternate between a fresh, a negotiating and an opened link.
        let mut ppp = match round % 3 {
            0 => Ppp::new(1354),
            1 => {
                let mut p = Ppp::new(1354);
                p.start();
                p
            }
            _ => opened_ppp(),
        };
        for _ in 0..8 {
            let frame = match rng.random_range(0..4) {
                0 => random_bytes(&mut rng, 64),
                1 => {
                    // Random control packet with a valid outer structure.
                    let proto = [PROTO_LCP, PROTO_IPCP][rng.random_range(0..2)];
                    let data = random_bytes(&mut rng, 40);
                    cp(proto, rng.random_range(0..16), rng.random(), &data)
                }
                _ => {
                    let seed = &seeds[rng.random_range(0..seeds.len())];
                    mutate(&mut rng, seed)
                }
            };
            let _ = ppp.input(&frame);
            let _ = ppp.retransmit();
            let _ = ppp.keepalive();
            for out in ppp.drain() {
                // Every frame we emit has a consistent control length.
                if out.len() >= 6 && out[..2] != [0x00, 0x21] {
                    assert_eq!(u16::from_be_bytes([out[4], out[5]]) as usize, out.len() - 2, "{out:02x?}");
                }
            }
        }
        let _ = (ppp.address(), ppp.dns(), ppp.peer_address(), ppp.peer_mru());
    }
}

#[test]
fn ppp_protocol_reject_is_bounded_by_peer_mru() {
    let mut ppp = opened_ppp();
    let big = [vec![0x80, 0x57], vec![0xaa; 60_000]].concat();
    ppp.input(&big).unwrap();
    let out = ppp.drain();
    assert_eq!(out.len(), 1);
    assert!(out[0].len() <= 2 + ppp.peer_mru() as usize, "{}", out[0].len());
}
