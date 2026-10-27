//! Key derivation (RFC 7296 §2.13–2.17) and AUTH computation (§2.15).

use std::net::SocketAddrV4;

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::crypto::{Cipher, EncrAlg, IntegAlg, PrfAlg};
use crate::proposal::IkeProposal;

/// Keys of an IKE SA. We are always the original initiator, so `out` uses
/// SK_ei/SK_ai and `inbound` SK_er/SK_ar.
/// Secret material is wiped on drop; the ciphers wipe their own keys.
pub struct IkeKeys {
    pub prf: PrfAlg,
    pub sk_d: Zeroizing<Vec<u8>>,
    pub sk_pi: Zeroizing<Vec<u8>>,
    pub sk_pr: Zeroizing<Vec<u8>>,
    pub out: Cipher,
    pub inbound: Cipher,
}

pub fn derive_ike_keys(
    algs: &IkeProposal,
    shared: &[u8],
    ni: &[u8],
    nr: &[u8],
    spi_i: u64,
    spi_r: u64,
) -> anyhow::Result<IkeKeys> {
    let prf = algs.prf;
    let skeyseed = Zeroizing::new(prf.compute(&[ni, nr].concat(), &[shared]));
    let seed = [ni, nr, &spi_i.to_be_bytes(), &spi_r.to_be_bytes()].concat();
    let (prf_len, integ_len, encr_len) =
        (prf.output_len(), algs.integ.map_or(0, IntegAlg::key_len), algs.encr.key_material_len());
    let material = Zeroizing::new(prf.prf_plus(&skeyseed, &seed, 3 * prf_len + 2 * integ_len + 2 * encr_len));
    let mut rest = material.as_slice();
    let mut take = |n: usize| {
        let (head, tail) = rest.split_at(n);
        rest = tail;
        Zeroizing::new(head.to_vec())
    };
    let sk_d = take(prf_len);
    let sk_ai = take(integ_len);
    let sk_ar = take(integ_len);
    let sk_ei = take(encr_len);
    let sk_er = take(encr_len);
    let sk_pi = take(prf_len);
    let sk_pr = take(prf_len);
    Ok(IkeKeys {
        prf,
        sk_d,
        sk_pi,
        sk_pr,
        out: Cipher::new(algs.encr, algs.integ, &sk_ei, &sk_ai)?,
        inbound: Cipher::new(algs.encr, algs.integ, &sk_er, &sk_ar)?,
    })
}

/// CHILD_SA keys (§2.17). `ni`/`nr` are the nonces of the exchange's
/// initiator and responder; `we_initiated` tells which direction is ours.
/// Returns (outbound, inbound).
#[allow(clippy::too_many_arguments)]
pub fn derive_child_keys(
    prf: PrfAlg,
    sk_d: &[u8],
    shared: Option<&[u8]>,
    ni: &[u8],
    nr: &[u8],
    encr: EncrAlg,
    integ: Option<IntegAlg>,
    we_initiated: bool,
) -> anyhow::Result<(Cipher, Cipher)> {
    let (encr_len, integ_len) = (encr.key_material_len(), integ.map_or(0, IntegAlg::key_len));
    let seed = [shared.unwrap_or(&[]), ni, nr].concat();
    let seed = Zeroizing::new(seed);
    let material = Zeroizing::new(prf.prf_plus(sk_d, &seed, 2 * (encr_len + integ_len)));
    let (i_to_r, r_to_i) = material.split_at(encr_len + integ_len);
    let make = |m: &[u8]| Cipher::new(encr, integ, &m[..encr_len], &m[encr_len..]);
    let (a, b) = (make(i_to_r)?, make(r_to_i)?);
    Ok(if we_initiated { (a, b) } else { (b, a) })
}

/// AUTH payload data for shared-key authentication: `secret` is the PSK,
/// or the EAP MSK after EAP. `real_message` is the sender's IKE_SA_INIT
/// message, `nonce` the peer's nonce, `sk_p` the sender's SK_p.
pub fn shared_key_auth(
    prf: PrfAlg,
    secret: &[u8],
    real_message: &[u8],
    nonce: &[u8],
    sk_p: &[u8],
    id_body: &[u8],
) -> Vec<u8> {
    let key = Zeroizing::new(prf.compute(secret, &[b"Key Pad for IKEv2"]));
    let maced_id = prf.compute(sk_p, &[id_body]);
    prf.compute(&key, &[real_message, nonce, &maced_id])
}

/// The octets a signature AUTH covers (§2.15): the sender's IKE_SA_INIT
/// message, the peer's nonce and prf(SK_p, ID).
pub fn signed_octets(prf: PrfAlg, real_message: &[u8], nonce: &[u8], sk_p: &[u8], id_body: &[u8]) -> Vec<u8> {
    [real_message, nonce, &prf.compute(sk_p, &[id_body])].concat()
}

/// NAT_DETECTION_*_IP data (§2.23).
pub fn nat_hash(spi_i: u64, spi_r: u64, addr: SocketAddrV4) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(spi_i.to_be_bytes());
    h.update(spi_r.to_be_bytes());
    h.update(addr.ip().octets());
    h.update(addr.port().to_be_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::proposal::parse_ike;

    #[test]
    fn ike_keys_are_directional() {
        for spec in ["aes256gcm16-prfsha384-ecp256", "aes128-sha256-modp2048"] {
            let algs: IkeProposal = parse_ike(spec).unwrap();
            assert!(matches!(algs.dh, DhGroup::Ecp256 | DhGroup::Modp2048));
            let a = derive_ike_keys(&algs, b"shared", b"ni", b"nr", 1, 2).unwrap();
            let b = derive_ike_keys(&algs, b"shared", b"ni", b"nr", 1, 2).unwrap();
            assert_eq!(a.sk_d, b.sk_d);
            assert_eq!(a.sk_d.len(), algs.prf.output_len());
            assert_ne!(a.sk_pi, a.sk_pr);
            let iv = a.out.make_iv(1);
            let sealed = a.out.seal(&iv, b"aad", &[0u8; 16]);
            assert!(b.out.open(b"aad", &sealed).is_ok());
            assert!(b.inbound.open(b"aad", &sealed).is_err());
        }
    }

    #[test]
    fn child_keys_mirror_between_peers() {
        let encr = EncrAlg::AesCbc { key_bits: 256 };
        let integ = Some(IntegAlg::HmacSha256Trunc128);
        let prf = PrfAlg::HmacSha256;
        let (i_out, i_in) = derive_child_keys(prf, b"skd", Some(b"g"), b"ni", b"nr", encr, integ, true).unwrap();
        let (r_out, r_in) = derive_child_keys(prf, b"skd", Some(b"g"), b"ni", b"nr", encr, integ, false).unwrap();
        let iv = i_out.make_iv(0);
        assert!(r_in.open(b"x", &i_out.seal(&iv, b"x", &[1u8; 16])).is_ok());
        let iv = r_out.make_iv(0);
        assert!(i_in.open(b"x", &r_out.seal(&iv, b"x", &[1u8; 16])).is_ok());
        assert!(i_in.open(b"x", &i_out.seal(&iv, b"x", &[1u8; 16])).is_err());
    }

    #[test]
    fn auth_depends_on_every_input() {
        let prf = PrfAlg::HmacSha256;
        let base = shared_key_auth(prf, b"psk", b"msg", b"nonce", b"skp", b"id");
        assert_eq!(base.len(), 32);
        assert_ne!(base, shared_key_auth(prf, b"psk2", b"msg", b"nonce", b"skp", b"id"));
        assert_ne!(base, shared_key_auth(prf, b"psk", b"msg", b"nonce", b"skp", b"id2"));
        assert_eq!(base, shared_key_auth(prf, b"psk", b"msg", b"nonce", b"skp", b"id"));
    }
}
