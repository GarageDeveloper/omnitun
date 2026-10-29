//! IKEv1 key material for pre-shared key authentication (RFC 2409 §5,
//! §5.5 and Appendix B) and NAT-D hashes (RFC 3947 §3.2).

use std::net::SocketAddrV4;

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::crypto::{CbcCipher, EncrAlg, IntegAlg, PrfAlg};

/// The plain hash underlying an IKEv1 PRF.
pub fn hash(prf: PrfAlg, parts: &[&[u8]]) -> Vec<u8> {
    fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = D::new();
        for p in parts {
            d.update(p);
        }
        d.finalize().to_vec()
    }
    match prf {
        PrfAlg::HmacSha1 => run::<Sha1>(parts),
        PrfAlg::HmacSha256 => run::<Sha256>(parts),
        PrfAlg::HmacSha384 => run::<Sha384>(parts),
        PrfAlg::HmacSha512 => run::<Sha512>(parts),
    }
}

/// Phase 1 keys. Secret values are wiped on drop.
pub struct Phase1Keys {
    pub skeyid: Zeroizing<Vec<u8>>,
    pub skeyid_d: Zeroizing<Vec<u8>>,
    pub skeyid_a: Zeroizing<Vec<u8>>,
    pub cipher: CbcCipher,
    /// IV for the first encrypted phase 1 message: hash(g^xi | g^xr).
    pub iv0: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn derive_phase1(
    prf: PrfAlg,
    encr: EncrAlg,
    psk: &[u8],
    ni: &[u8],
    nr: &[u8],
    gxy: &[u8],
    cky_i: u64,
    cky_r: u64,
    gxi: &[u8],
    gxr: &[u8],
) -> anyhow::Result<Phase1Keys> {
    let skeyid = Zeroizing::new(prf.compute(psk, &[ni, nr]));
    let (ci, cr) = (cky_i.to_be_bytes(), cky_r.to_be_bytes());
    let skeyid_d = Zeroizing::new(prf.compute(&skeyid, &[gxy, &ci, &cr, &[0]]));
    let skeyid_a = Zeroizing::new(prf.compute(&skeyid, &[&skeyid_d, gxy, &ci, &cr, &[1]]));
    let skeyid_e = Zeroizing::new(prf.compute(&skeyid, &[&skeyid_a, gxy, &ci, &cr, &[2]]));
    let key_len = encr.key_material_len();
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + prf.output_len()));
    if skeyid_e.len() >= key_len {
        key.extend_from_slice(&skeyid_e[..key_len]);
    } else {
        // Appendix B: Ka = K1 | K2 | ..., K1 = prf(SKEYID_e, 0), Kn = prf(SKEYID_e, Kn-1).
        let mut block = Zeroizing::new(prf.compute(&skeyid_e, &[&[0]]));
        while key.len() < key_len {
            key.extend_from_slice(&block);
            block = Zeroizing::new(prf.compute(&skeyid_e, &[&block]));
        }
        key.truncate(key_len);
    }
    let cipher = CbcCipher::new(encr, &key)?;
    let iv0 = hash(prf, &[gxi, gxr])[..cipher.block_len()].to_vec();
    Ok(Phase1Keys { cipher, skeyid, skeyid_d, skeyid_a, iv0 })
}

/// HASH_I (`initiator = true`) or HASH_R (RFC 2409 §5). `sa_i` is the
/// initiator's SA payload body, `id` the sender's ID payload body.
#[allow(clippy::too_many_arguments)]
pub fn phase1_hash(
    prf: PrfAlg,
    skeyid: &[u8],
    initiator: bool,
    gxi: &[u8],
    gxr: &[u8],
    cky_i: u64,
    cky_r: u64,
    sa_i: &[u8],
    id: &[u8],
) -> Vec<u8> {
    let (ci, cr) = (cky_i.to_be_bytes(), cky_r.to_be_bytes());
    if initiator {
        prf.compute(skeyid, &[gxi, gxr, &ci, &cr, sa_i, id])
    } else {
        prf.compute(skeyid, &[gxr, gxi, &cr, &ci, sa_i, id])
    }
}

/// IPsec SA key material for one direction (RFC 2409 §5.5): `spi` is the
/// SPI of the receiving side. Returns (encryption key, integrity key).
#[allow(clippy::too_many_arguments)]
pub fn keymat(
    prf: PrfAlg,
    skeyid_d: &[u8],
    gxy: Option<&[u8]>,
    protocol: u8,
    spi: u32,
    ni: &[u8],
    nr: &[u8],
    encr: EncrAlg,
    integ: Option<IntegAlg>,
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let (enc_len, auth_len) = (encr.key_material_len(), integ.map_or(0, IntegAlg::key_len));
    let seed = Zeroizing::new([gxy.unwrap_or(&[]), &[protocol], &spi.to_be_bytes(), ni, nr].concat());
    let mut material = Zeroizing::new(Vec::with_capacity(enc_len + auth_len + prf.output_len()));
    let mut block: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    while material.len() < enc_len + auth_len {
        block = Zeroizing::new(prf.compute(skeyid_d, &[&block, &seed]));
        material.extend_from_slice(&block);
    }
    let enc = Zeroizing::new(material[..enc_len].to_vec());
    let auth = Zeroizing::new(material[enc_len..enc_len + auth_len].to_vec());
    (enc, auth)
}

/// NAT-D payload data: HASH(CKY-I | CKY-R | IP | Port).
pub fn nat_d(prf: PrfAlg, cky_i: u64, cky_r: u64, addr: SocketAddrV4) -> Vec<u8> {
    hash(prf, &[&cky_i.to_be_bytes(), &cky_r.to_be_bytes(), &addr.ip().octets(), &addr.port().to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_digests() {
        assert_eq!(hex::encode(hash(PrfAlg::HmacSha1, &[b"a", b"bc"])), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex::encode(hash(PrfAlg::HmacSha256, &[b"abc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn phase1_derivation_matches_rfc2409_formulas() {
        let prf = PrfAlg::HmacSha1;
        let k =
            derive_phase1(prf, EncrAlg::AesCbc { key_bits: 256 }, b"psk", b"ni", b"nr", b"gxy", 1, 2, b"gxi", b"gxr")
                .unwrap();
        let skeyid = prf.compute(b"psk", &[b"ninr"]);
        assert_eq!(&k.skeyid[..], &skeyid[..]);
        let d = prf.compute(&skeyid, &[b"gxy", &1u64.to_be_bytes(), &2u64.to_be_bytes(), &[0]]);
        assert_eq!(&k.skeyid_d[..], &d[..]);
        let a = prf.compute(&skeyid, &[&d, b"gxy", &1u64.to_be_bytes(), &2u64.to_be_bytes(), &[1]]);
        assert_eq!(&k.skeyid_a[..], &a[..]);
        // AES-256 needs 32 bytes from a 20-byte SKEYID_e: expanded key.
        let e = prf.compute(&skeyid, &[&a, b"gxy", &1u64.to_be_bytes(), &2u64.to_be_bytes(), &[2]]);
        let k1 = prf.compute(&e, &[&[0]]);
        let k2 = prf.compute(&e, &[&k1]);
        let expected = CbcCipher::new(EncrAlg::AesCbc { key_bits: 256 }, &[k1, k2].concat()[..32]).unwrap();
        let (mut x, mut y) = ([7u8; 32], [7u8; 32]);
        k.cipher.encrypt(&[0; 16], &mut x);
        expected.encrypt(&[0; 16], &mut y);
        assert_eq!(x, y);
        assert_eq!(&k.iv0[..], &hash(prf, &[b"gxigxr"])[..16]);
    }

    #[test]
    fn hashes_are_asymmetric() {
        let prf = PrfAlg::HmacSha256;
        let hi = phase1_hash(prf, b"k", true, b"gi", b"gr", 1, 2, b"sa", b"id");
        let hr = phase1_hash(prf, b"k", false, b"gi", b"gr", 1, 2, b"sa", b"id");
        assert_ne!(hi, hr);
        assert_eq!(hi, prf.compute(b"k", &[b"gigr", &1u64.to_be_bytes(), &2u64.to_be_bytes(), b"said"]));
    }

    #[test]
    fn keymat_expands_and_depends_on_spi() {
        let prf = PrfAlg::HmacSha1;
        let (e1, a1) = keymat(
            prf,
            b"d",
            Some(b"g"),
            3,
            0x1000,
            b"ni",
            b"nr",
            EncrAlg::AesCbc { key_bits: 256 },
            Some(IntegAlg::HmacSha1Trunc96),
        );
        assert_eq!((e1.len(), a1.len()), (32, 20));
        let k1 = prf.compute(b"d", &[b"g", &[3], &0x1000u32.to_be_bytes(), b"ni", b"nr"]);
        let k2 = prf.compute(b"d", &[&k1, b"g", &[3], &0x1000u32.to_be_bytes(), b"ni", b"nr"]);
        let k3 = prf.compute(b"d", &[&k2, b"g", &[3], &0x1000u32.to_be_bytes(), b"ni", b"nr"]);
        assert_eq!([&e1[..], &a1[..]].concat(), [k1, k2, k3].concat()[..52].to_vec());
        let (e2, _) = keymat(
            prf,
            b"d",
            Some(b"g"),
            3,
            0x1001,
            b"ni",
            b"nr",
            EncrAlg::AesCbc { key_bits: 256 },
            Some(IntegAlg::HmacSha1Trunc96),
        );
        assert_ne!(e1, e2);
    }
}
