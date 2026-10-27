//! Robustness tests for everything IKEv1 parses from the gateway: plain
//! messages, payload chains inside an authenticated encrypted message, SA
//! attributes and Mode-Config attributes. Seeded; the assertion is "no panic".

use std::net::Ipv4Addr;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::consts::exchange;
use super::isakmp::IsakmpSa;
use super::keys::derive_phase1;
use super::payload::{CfgAttr, Message, Payload, decode_chain, decode_sa_attrs};
use super::settings;
use crate::crypto::{EncrAlg, PrfAlg};

const ROUNDS: usize = 3000;

fn noise(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let len = rng.random_range(0..=max);
    (0..len).map(|_| rng.random()).collect()
}

fn mutate(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..rng.random_range(1..=4) {
        if v.is_empty() {
            break;
        }
        let i = rng.random_range(0..v.len());
        match rng.random_range(0..3) {
            0 => v[i] = rng.random(),
            1 => v.truncate(i),
            _ => v.insert(i, rng.random()),
        }
    }
    v
}

fn isakmp_sa() -> IsakmpSa {
    let keys = derive_phase1(
        PrfAlg::HmacSha1,
        EncrAlg::AesCbc { key_bits: 128 },
        b"psk",
        b"ni",
        b"nr",
        b"g",
        1,
        2,
        b"a",
        b"b",
    )
    .unwrap();
    let iv = keys.iv0.clone();
    IsakmpSa::new(1, 2, PrfAlg::HmacSha1, keys, iv)
}

#[test]
fn plain_messages_and_chains() {
    let mut rng = StdRng::seed_from_u64(1);
    let seed = super::payload::build_plain(
        1,
        2,
        exchange::AGGRESSIVE,
        0,
        &[
            Payload::Nonce(vec![7; 16]),
            Payload::Attr { cfg_type: 1, identifier: 3, attrs: vec![CfgAttr::var(1, [10, 0, 0, 1])] },
            Payload::Delete { protocol: 3, spi_size: 4, spis: vec![vec![1, 2, 3, 4]] },
        ],
    );
    for _ in 0..ROUNDS {
        let _ = Message::parse_plain(&mutate(&mut rng, &seed));
        let _ = Message::parse_plain(&noise(&mut rng, 200));
        let kind = rng.random();
        let _ = decode_chain(kind, &noise(&mut rng, 120));
        let _ = decode_sa_attrs(&noise(&mut rng, 40));
    }
}

/// Authentic encrypted messages with garbage inside must be rejected
/// cleanly, and random ciphertexts never panic the decryptor.
#[test]
fn encrypted_messages() {
    let mut rng = StdRng::seed_from_u64(2);
    let (mut gw, client) = (isakmp_sa(), isakmp_sa());
    for round in 0..ROUNDS {
        let body = noise(&mut rng, 96);
        let msg_id = rng.random_range(1..u32::MAX);
        let raw = gw.seal(exchange::TRANSACTION, msg_id, &[], &[Payload::Unknown { kind: 200, body }]);
        gw.forget(msg_id);
        let raw = if round % 2 == 0 { mutate(&mut rng, &raw) } else { raw };
        if let Ok((msg, _)) = client.open(&raw) {
            let _ = client.verify(&msg, &[]);
            let _ = msg.after_hash();
        }
    }
}

#[test]
fn mode_config_attributes() {
    let mut rng = StdRng::seed_from_u64(3);
    for _ in 0..ROUNDS {
        let attrs: Vec<CfgAttr> = (0..rng.random_range(0..12))
            .map(|_| CfgAttr::var(rng.random_range(0..30000), noise(&mut rng, 60)))
            .collect();
        let _ = settings::build(&attrs, Ipv4Addr::LOCALHOST);
    }
}
