//! Cryptographic building blocks shared by IKEv2 and ESP: PRFs (RFC 7296
//! §2.13), the encrypt-then-MAC / AEAD envelope used by both the SK payload
//! and ESP (AES-CBC, AES-GCM, ChaCha20-Poly1305, legacy 3DES-CBC), and
//! Diffie-Hellman groups 2, 5 and 14 to 18 (MODP), 19 to 21
//! (RFC 5903) and 31 (RFC 8031).

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use anyhow::{Context, anyhow, bail, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use des::TdesEde3;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn hmac<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfAlg {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl PrfAlg {
    pub const fn id(self) -> u16 {
        match self {
            Self::HmacSha1 => 2,
            Self::HmacSha256 => 5,
            Self::HmacSha384 => 6,
            Self::HmacSha512 => 7,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            2 => Some(Self::HmacSha1),
            5 => Some(Self::HmacSha256),
            6 => Some(Self::HmacSha384),
            7 => Some(Self::HmacSha512),
            _ => None,
        }
    }

    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }

    pub fn compute(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::HmacSha1 => hmac::<Hmac<Sha1>>(key, parts),
            Self::HmacSha256 => hmac::<Hmac<Sha256>>(key, parts),
            Self::HmacSha384 => hmac::<Hmac<Sha384>>(key, parts),
            Self::HmacSha512 => hmac::<Hmac<Sha512>>(key, parts),
        }
    }

    /// `prf+` from RFC 7296 §2.13.
    pub fn prf_plus(self, key: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        // Sized up front: the output (key material) is never reallocated.
        let mut out = Vec::with_capacity(len + self.output_len());
        let mut block = Zeroizing::new(Vec::new());
        let mut counter = 1u8;
        while out.len() < len {
            block = Zeroizing::new(self.compute(key, &[&block, seed, &[counter]]));
            out.extend_from_slice(&block);
            counter = counter.checked_add(1).expect("prf+ output limited to 255 blocks");
        }
        out.truncate(len);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegAlg {
    /// AUTH_HMAC_SHA1_96 (RFC 2404).
    HmacSha1Trunc96,
    /// AUTH_HMAC_SHA2_256_128 (RFC 4868).
    HmacSha256Trunc128,
    /// AUTH_HMAC_SHA2_384_192 (RFC 4868).
    HmacSha384Trunc192,
    /// AUTH_HMAC_SHA2_512_256 (RFC 4868).
    HmacSha512Trunc256,
}

impl IntegAlg {
    pub const fn id(self) -> u16 {
        match self {
            Self::HmacSha1Trunc96 => 2,
            Self::HmacSha256Trunc128 => 12,
            Self::HmacSha384Trunc192 => 13,
            Self::HmacSha512Trunc256 => 14,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            2 => Some(Self::HmacSha1Trunc96),
            12 => Some(Self::HmacSha256Trunc128),
            13 => Some(Self::HmacSha384Trunc192),
            14 => Some(Self::HmacSha512Trunc256),
            _ => None,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::HmacSha1Trunc96 => 20,
            Self::HmacSha256Trunc128 => 32,
            Self::HmacSha384Trunc192 => 48,
            Self::HmacSha512Trunc256 => 64,
        }
    }

    pub const fn icv_len(self) -> usize {
        match self {
            Self::HmacSha1Trunc96 => 12,
            Self::HmacSha256Trunc128 => 16,
            Self::HmacSha384Trunc192 => 24,
            Self::HmacSha512Trunc256 => 32,
        }
    }

    /// The PRF built on the same hash.
    pub const fn prf(self) -> PrfAlg {
        match self {
            Self::HmacSha1Trunc96 => PrfAlg::HmacSha1,
            Self::HmacSha256Trunc128 => PrfAlg::HmacSha256,
            Self::HmacSha384Trunc192 => PrfAlg::HmacSha384,
            Self::HmacSha512Trunc256 => PrfAlg::HmacSha512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncrAlg {
    AesCbc {
        key_bits: u16,
    },
    /// AES-GCM with a 16-byte ICV (RFC 4106 / RFC 5282).
    AesGcm16 {
        key_bits: u16,
    },
    /// ChaCha20-Poly1305 (RFC 7634). IKEv2 only: IKEv1 has no identifier
    /// for it.
    ChaCha20Poly1305,
    /// 3DES-CBC: 64-bit blocks, kept for old gateways and only offered
    /// when the profile allows legacy algorithms.
    TripleDesCbc,
}

impl EncrAlg {
    pub const fn id(self) -> u16 {
        match self {
            Self::AesCbc { .. } => 12,
            Self::AesGcm16 { .. } => 20,
            Self::ChaCha20Poly1305 => 28,
            Self::TripleDesCbc => 3,
        }
    }

    /// From an IKEv2 transform id and its key length attribute, which only
    /// AES carries.
    pub fn from_id(id: u16, key_bits: Option<u16>) -> Option<Self> {
        match (id, key_bits) {
            (12, Some(key_bits @ (128 | 192 | 256))) => Some(Self::AesCbc { key_bits }),
            (20, Some(key_bits @ (128 | 256))) => Some(Self::AesGcm16 { key_bits }),
            (28, None) => Some(Self::ChaCha20Poly1305),
            (3, None) => Some(Self::TripleDesCbc),
            _ => None,
        }
    }

    /// The key length attribute: none for the fixed-key ciphers.
    pub const fn key_bits(self) -> Option<u16> {
        match self {
            Self::AesCbc { key_bits } | Self::AesGcm16 { key_bits } => Some(key_bits),
            Self::ChaCha20Poly1305 | Self::TripleDesCbc => None,
        }
    }

    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AesGcm16 { .. } | Self::ChaCha20Poly1305)
    }

    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::TripleDesCbc)
    }

    /// Block size the plaintext is padded to (1 for the AEAD ciphers).
    pub const fn block_len(self) -> usize {
        match self {
            Self::AesCbc { .. } => 16,
            Self::TripleDesCbc => 8,
            Self::AesGcm16 { .. } | Self::ChaCha20Poly1305 => 1,
        }
    }

    /// Keying material length, including the 4-byte salt of the AEAD
    /// ciphers.
    pub const fn key_material_len(self) -> usize {
        match self {
            Self::AesCbc { key_bits } => key_bits as usize / 8,
            Self::AesGcm16 { key_bits } => key_bits as usize / 8 + 4,
            Self::ChaCha20Poly1305 => 36,
            Self::TripleDesCbc => 24,
        }
    }
}

enum CipherImpl {
    Cbc128(Box<Aes128>),
    Cbc192(Box<Aes192>),
    Cbc256(Box<Aes256>),
    Gcm128(Box<Aes128Gcm>),
    Gcm256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
    Des3(Box<TdesEde3>),
}

/// One direction of an SK payload or ESP SA. Both use the same layout:
/// `IV || ciphertext || ICV`, where the ICV covers `aad || IV || ciphertext`
/// (HMAC, encrypt-then-MAC) or is the GCM tag with `aad` as AAD.
/// The AES key schedules wipe themselves on drop (`zeroize` feature of
/// `aes`/`aes-gcm`), as do the ChaCha20-Poly1305 and 3DES keys; salt and
/// the keyed HMAC are wiped by `Drop` below.
pub struct Cipher {
    encr: EncrAlg,
    integ: Option<IntegAlg>,
    imp: CipherImpl,
    salt: [u8; 4],
    /// The HMAC keyed once: each packet clones it instead of hashing the
    /// key again.
    mac: Option<Box<KeyedMac>>,
}

/// An HMAC whose key is already absorbed (its inner and outer pads).
#[derive(Clone)]
enum KeyedMac {
    Sha1(Hmac<Sha1>),
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl Drop for KeyedMac {
    fn drop(&mut self) {
        // The pads stand for the integrity key; hmac 0.12 does not erase
        // them. SAFETY: the HMAC states are plain arrays and integers, with
        // no heap data and no Drop of their own, and are not used again.
        unsafe { zeroize::zeroize_flat_type(self as *mut Self) }
    }
}

impl KeyedMac {
    fn new(prf: PrfAlg, key: &[u8]) -> Self {
        const ANY: &str = "HMAC accepts keys of any length";
        match prf {
            PrfAlg::HmacSha1 => Self::Sha1(Mac::new_from_slice(key).expect(ANY)),
            PrfAlg::HmacSha256 => Self::Sha256(Mac::new_from_slice(key).expect(ANY)),
            PrfAlg::HmacSha384 => Self::Sha384(Mac::new_from_slice(key).expect(ANY)),
            PrfAlg::HmacSha512 => Self::Sha512(Mac::new_from_slice(key).expect(ANY)),
        }
    }

    /// The MAC of `parts`, truncated to `len` bytes, into `out`.
    fn compute(&self, parts: &[&[u8]], out: &mut Vec<u8>) {
        fn run<M: Mac + Clone>(mac: &M, parts: &[&[u8]], out: &mut Vec<u8>) {
            let mut mac = mac.clone();
            for part in parts {
                mac.update(part);
            }
            out.extend_from_slice(&mac.finalize().into_bytes());
        }
        match self {
            Self::Sha1(m) => run(m, parts, out),
            Self::Sha256(m) => run(m, parts, out),
            Self::Sha384(m) => run(m, parts, out),
            Self::Sha512(m) => run(m, parts, out),
        }
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

impl Cipher {
    pub fn new(encr: EncrAlg, integ: Option<IntegAlg>, enc_key: &[u8], integ_key: &[u8]) -> anyhow::Result<Self> {
        ensure!(enc_key.len() == encr.key_material_len(), "bad encryption key length");
        ensure!(encr.is_aead() == integ.is_none(), "AEAD ciphers take no integrity algorithm");
        ensure!(integ_key.len() == integ.map_or(0, IntegAlg::key_len), "bad integrity key length");
        let mut salt = [0u8; 4];
        let imp = match encr {
            EncrAlg::AesCbc { key_bits: 128 } => CipherImpl::Cbc128(Box::new(Aes128::new_from_slice(enc_key)?)),
            EncrAlg::AesCbc { key_bits: 192 } => CipherImpl::Cbc192(Box::new(Aes192::new_from_slice(enc_key)?)),
            EncrAlg::AesCbc { key_bits: 256 } => CipherImpl::Cbc256(Box::new(Aes256::new_from_slice(enc_key)?)),
            EncrAlg::AesGcm16 { key_bits } => {
                let (key, s) = enc_key.split_at(enc_key.len() - 4);
                salt.copy_from_slice(s);
                match key_bits {
                    128 => CipherImpl::Gcm128(Box::new(Aes128Gcm::new_from_slice(key)?)),
                    256 => CipherImpl::Gcm256(Box::new(Aes256Gcm::new_from_slice(key)?)),
                    _ => bail!("unsupported AES key size"),
                }
            }
            EncrAlg::ChaCha20Poly1305 => {
                let (key, s) = enc_key.split_at(32);
                salt.copy_from_slice(s);
                CipherImpl::ChaCha(Box::new(ChaCha20Poly1305::new_from_slice(key)?))
            }
            EncrAlg::TripleDesCbc => CipherImpl::Des3(Box::new(TdesEde3::new_from_slice(enc_key)?)),
            EncrAlg::AesCbc { .. } => bail!("unsupported AES key size"),
        };
        let mac = integ.map(|integ| Box::new(KeyedMac::new(integ.prf(), integ_key)));
        Ok(Self { encr, integ, imp, salt, mac })
    }

    pub fn iv_len(&self) -> usize {
        if self.encr.is_aead() { 8 } else { self.encr.block_len() }
    }

    pub fn icv_len(&self) -> usize {
        self.integ.map_or(16, IntegAlg::icv_len)
    }

    /// Block size the plaintext must be padded to.
    pub fn block_len(&self) -> usize {
        self.encr.block_len()
    }

    /// A fresh IV: the counter for the AEAD ciphers (must never repeat
    /// under one key), random for CBC (must be unpredictable).
    pub fn make_iv(&self, counter: u64) -> Vec<u8> {
        if self.encr.is_aead() { counter.to_be_bytes().to_vec() } else { random_bytes(self.iv_len()) }
    }

    /// Encrypts already padded `plain`, returning `IV || ciphertext || ICV`.
    pub fn seal(&self, iv: &[u8], aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(iv.len() + plain.len() + self.icv_len());
        out.extend_from_slice(iv);
        out.extend_from_slice(plain);
        self.seal_in_place(&mut out, 0, aad);
        out
    }

    /// Encrypts in place `IV || padded plaintext`, which starts at `start`
    /// in `out` (what comes before, an ESP header, is left as is), and
    /// appends the ICV: one buffer from the packet to the wire.
    pub fn seal_in_place(&self, out: &mut Vec<u8>, start: usize, aad: &[u8]) {
        let iv_len = self.iv_len();
        assert!(out.len() >= start + iv_len);
        assert_eq!((out.len() - start - iv_len) % self.block_len(), 0);
        let (head, body) = out.split_at_mut(start + iv_len);
        let iv = &head[start..];
        let tag = match &self.imp {
            CipherImpl::Gcm128(c) => c
                .encrypt_in_place_detached(&self.nonce(iv), aad, body)
                .expect("GCM encryption cannot fail for IKE/ESP sizes")
                .to_vec(),
            CipherImpl::Gcm256(c) => c
                .encrypt_in_place_detached(&self.nonce(iv), aad, body)
                .expect("GCM encryption cannot fail for IKE/ESP sizes")
                .to_vec(),
            CipherImpl::ChaCha(c) => c
                .encrypt_in_place_detached(&self.nonce(iv), aad, body)
                .expect("ChaCha20-Poly1305 encryption cannot fail for IKE/ESP sizes")
                .to_vec(),
            CipherImpl::Des3(c) => {
                cbc_encrypt(c.as_ref(), iv, body);
                self.mac(aad, &out[start..])
            }
            CipherImpl::Cbc128(c) => {
                cbc_encrypt(c.as_ref(), iv, body);
                self.mac(aad, &out[start..])
            }
            CipherImpl::Cbc192(c) => {
                cbc_encrypt(c.as_ref(), iv, body);
                self.mac(aad, &out[start..])
            }
            CipherImpl::Cbc256(c) => {
                cbc_encrypt(c.as_ref(), iv, body);
                self.mac(aad, &out[start..])
            }
        };
        out.extend_from_slice(&tag);
    }

    /// Verifies and decrypts `IV || ciphertext || ICV`, returning the
    /// padded plaintext.
    pub fn open(&self, aad: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (iv_len, icv_len) = (self.iv_len(), self.icv_len());
        ensure!(data.len() >= iv_len + icv_len, "encrypted data too short");
        let (body, icv) = data.split_at(data.len() - icv_len);
        let (iv, ct) = body.split_at(iv_len);
        ensure!(ct.len() % self.block_len() == 0, "ciphertext not block aligned");
        let mut plain = ct.to_vec();
        match &self.imp {
            CipherImpl::Gcm128(c) => c
                .decrypt_in_place_detached(&self.nonce(iv), aad, &mut plain, Tag::from_slice(icv))
                .map_err(|_| anyhow!("integrity check failed"))?,
            CipherImpl::Gcm256(c) => c
                .decrypt_in_place_detached(&self.nonce(iv), aad, &mut plain, Tag::from_slice(icv))
                .map_err(|_| anyhow!("integrity check failed"))?,
            CipherImpl::ChaCha(c) => c
                .decrypt_in_place_detached(&self.nonce(iv), aad, &mut plain, Tag::from_slice(icv))
                .map_err(|_| anyhow!("integrity check failed"))?,
            CipherImpl::Des3(c) => {
                self.verify_mac(aad, body, icv)?;
                cbc_decrypt(c.as_ref(), iv, &mut plain);
            }
            CipherImpl::Cbc128(c) => {
                self.verify_mac(aad, body, icv)?;
                cbc_decrypt(c.as_ref(), iv, &mut plain);
            }
            CipherImpl::Cbc192(c) => {
                self.verify_mac(aad, body, icv)?;
                cbc_decrypt(c.as_ref(), iv, &mut plain);
            }
            CipherImpl::Cbc256(c) => {
                self.verify_mac(aad, body, icv)?;
                cbc_decrypt(c.as_ref(), iv, &mut plain);
            }
        }
        Ok(plain)
    }

    fn nonce(&self, iv: &[u8]) -> Nonce<aes_gcm::aead::consts::U12> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(iv);
        *Nonce::from_slice(&nonce)
    }

    fn mac(&self, aad: &[u8], body: &[u8]) -> Vec<u8> {
        let mac = self.mac.as_ref().expect("MAC only used with an integrity algorithm");
        let mut full = Vec::with_capacity(PrfAlg::HmacSha512.output_len());
        mac.compute(&[aad, body], &mut full);
        full.truncate(self.icv_len());
        full
    }

    fn verify_mac(&self, aad: &[u8], body: &[u8], icv: &[u8]) -> anyhow::Result<()> {
        ensure!(ct_eq(&self.mac(aad, body), icv), "integrity check failed");
        Ok(())
    }
}

/// Constant-time comparison for MACs and authentication hashes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

enum CbcImpl {
    Aes128(Box<Aes128>),
    Aes192(Box<Aes192>),
    Aes256(Box<Aes256>),
    Des3(Box<TdesEde3>),
}

/// Bare CBC (AES or 3DES) without padding, IV or MAC handling: IKEv1
/// encrypts its messages this way and chains IVs across messages
/// (RFC 2409 Appendix B).
pub struct CbcCipher(CbcImpl);

impl CbcCipher {
    pub fn new(encr: EncrAlg, key: &[u8]) -> anyhow::Result<Self> {
        ensure!(key.len() == encr.key_material_len(), "bad encryption key length");
        Ok(Self(match encr {
            EncrAlg::AesCbc { key_bits: 128 } => CbcImpl::Aes128(Box::new(Aes128::new_from_slice(key)?)),
            EncrAlg::AesCbc { key_bits: 192 } => CbcImpl::Aes192(Box::new(Aes192::new_from_slice(key)?)),
            EncrAlg::AesCbc { key_bits: 256 } => CbcImpl::Aes256(Box::new(Aes256::new_from_slice(key)?)),
            EncrAlg::TripleDesCbc => CbcImpl::Des3(Box::new(TdesEde3::new_from_slice(key)?)),
            other => bail!("{other:?} is not a CBC cipher"),
        }))
    }

    pub fn block_len(&self) -> usize {
        if matches!(self.0, CbcImpl::Des3(_)) { 8 } else { 16 }
    }

    pub fn encrypt(&self, iv: &[u8], buf: &mut [u8]) {
        let n = self.block_len();
        assert!(iv.len() == n && buf.len().is_multiple_of(n));
        match &self.0 {
            CbcImpl::Aes128(c) => cbc_encrypt(c.as_ref(), iv, buf),
            CbcImpl::Aes192(c) => cbc_encrypt(c.as_ref(), iv, buf),
            CbcImpl::Aes256(c) => cbc_encrypt(c.as_ref(), iv, buf),
            CbcImpl::Des3(c) => cbc_encrypt(c.as_ref(), iv, buf),
        }
    }

    pub fn decrypt(&self, iv: &[u8], buf: &mut [u8]) {
        let n = self.block_len();
        assert!(iv.len() == n && buf.len().is_multiple_of(n));
        match &self.0 {
            CbcImpl::Aes128(c) => cbc_decrypt(c.as_ref(), iv, buf),
            CbcImpl::Aes192(c) => cbc_decrypt(c.as_ref(), iv, buf),
            CbcImpl::Aes256(c) => cbc_decrypt(c.as_ref(), iv, buf),
            CbcImpl::Des3(c) => cbc_decrypt(c.as_ref(), iv, buf),
        }
    }
}

/// CBC over the cipher's own block size (16 for AES, 8 for 3DES); `iv`
/// is one block.
/// Largest block of the CBC ciphers (AES).
const MAX_BLOCK: usize = 16;

fn cbc_encrypt<C: BlockEncrypt>(cipher: &C, iv: &[u8], buf: &mut [u8]) {
    let n = C::block_size();
    let mut prev = [0u8; MAX_BLOCK];
    prev[..n].copy_from_slice(iv);
    for block in buf.chunks_exact_mut(n) {
        for (b, p) in block.iter_mut().zip(&prev) {
            *b ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        prev[..n].copy_from_slice(block);
    }
}

fn cbc_decrypt<C: BlockDecrypt>(cipher: &C, iv: &[u8], buf: &mut [u8]) {
    let n = C::block_size();
    let (mut prev, mut current) = ([0u8; MAX_BLOCK], [0u8; MAX_BLOCK]);
    prev[..n].copy_from_slice(iv);
    for block in buf.chunks_exact_mut(n) {
        current[..n].copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (b, p) in block.iter_mut().zip(&prev) {
            *b ^= p;
        }
        prev = current;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    /// Group 2 (RFC 2409), 1024-bit: weak, only for legacy IKEv1 gateways.
    Modp1024,
    /// Group 5 (RFC 3526), 1536-bit.
    Modp1536,
    Modp2048,
    Modp3072,
    Modp4096,
    Modp6144,
    Modp8192,
    Ecp256,
    Ecp384,
    Ecp521,
    Curve25519,
}

impl DhGroup {
    pub const fn id(self) -> u16 {
        match self {
            Self::Modp1024 => 2,
            Self::Modp1536 => 5,
            Self::Modp2048 => 14,
            Self::Modp3072 => 15,
            Self::Modp4096 => 16,
            Self::Modp6144 => 17,
            Self::Modp8192 => 18,
            Self::Ecp256 => 19,
            Self::Ecp384 => 20,
            Self::Ecp521 => 21,
            Self::Curve25519 => 31,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            2 => Some(Self::Modp1024),
            5 => Some(Self::Modp1536),
            14 => Some(Self::Modp2048),
            15 => Some(Self::Modp3072),
            16 => Some(Self::Modp4096),
            17 => Some(Self::Modp6144),
            18 => Some(Self::Modp8192),
            19 => Some(Self::Ecp256),
            20 => Some(Self::Ecp384),
            21 => Some(Self::Ecp521),
            31 => Some(Self::Curve25519),
            _ => None,
        }
    }
}

/// RFC 2409 §6.2 group 2 prime.
const MODP1024_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
/// RFC 3526 group 5 prime.
const MODP1536_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
/// RFC 3526 group 14 prime.
const MODP2048_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
/// RFC 3526 group 15 prime.
const MODP3072_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
/// RFC 3526 group 16 prime.
const MODP4096_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";
/// RFC 3526 group 17 prime.
const MODP6144_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";
/// RFC 3526 group 18 prime.
const MODP8192_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF";

enum DhSecret {
    Modp(BigUint, BigUint),
    Ecp256(p256::SecretKey),
    Ecp384(p384::SecretKey),
    Ecp521(p521::SecretKey),
    X25519(x25519_dalek::StaticSecret),
}

/// A NIST curve key pair; the public value is `x || y` (RFC 5903 §7).
macro_rules! ecp_generate {
    ($curve:ident, $len:expr) => {{
        use $curve::elliptic_curve::sec1::ToEncodedPoint;
        let secret = loop {
            if let Ok(k) = $curve::SecretKey::from_slice(&Zeroizing::new(random_bytes($len))) {
                break k;
            }
        };
        let point = secret.public_key().to_encoded_point(false);
        let public = point.as_bytes()[1..].to_vec();
        (secret, public)
    }};
}

/// The shared secret is the x coordinate (RFC 5903 §7).
macro_rules! ecp_shared {
    ($curve:ident, $len:expr, $secret:expr, $peer:expr) => {{
        use $curve::elliptic_curve::sec1::FromEncodedPoint;
        let peer: &[u8] = $peer;
        ensure!(peer.len() == 2 * $len, "bad {} public value length", stringify!($curve));
        let point = $curve::EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&peer[..$len]),
            GenericArray::from_slice(&peer[$len..]),
            false,
        );
        let public: $curve::PublicKey = Option::from($curve::PublicKey::from_encoded_point(&point))
            .with_context(|| format!("{} public value is not on the curve", stringify!($curve)))?;
        let shared = $curve::ecdh::diffie_hellman($secret.to_nonzero_scalar(), public.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }};
}

/// An ephemeral key pair for one KE payload.
pub struct KeyExchange {
    group: DhGroup,
    secret: DhSecret,
    public: Vec<u8>,
}

impl KeyExchange {
    pub fn generate(group: DhGroup) -> anyhow::Result<Self> {
        let (secret, public) = match group {
            DhGroup::Modp1024
            | DhGroup::Modp1536
            | DhGroup::Modp2048
            | DhGroup::Modp3072
            | DhGroup::Modp4096
            | DhGroup::Modp6144
            | DhGroup::Modp8192 => {
                let p = modp_prime(group);
                // 512-bit exponent: well above the strength of these groups.
                // (num-bigint cannot erase x itself; its source bytes are.)
                let x = BigUint::from_bytes_be(&Zeroizing::new(random_bytes(64)));
                let y = BigUint::from(2u32).modpow(&x, &p);
                let len = modp_len(&p);
                (DhSecret::Modp(x, p), pad_left(&y.to_bytes_be(), len))
            }
            DhGroup::Ecp256 => {
                let (secret, public) = ecp_generate!(p256, 32);
                (DhSecret::Ecp256(secret), public)
            }
            DhGroup::Ecp384 => {
                let (secret, public) = ecp_generate!(p384, 48);
                (DhSecret::Ecp384(secret), public)
            }
            DhGroup::Ecp521 => {
                let (secret, public) = ecp_generate!(p521, 66);
                (DhSecret::Ecp521(secret), public)
            }
            DhGroup::Curve25519 => {
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                let secret = x25519_dalek::StaticSecret::from(bytes);
                bytes.zeroize();
                let public = x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec();
                (DhSecret::X25519(secret), public)
            }
        };
        Ok(Self { group, secret, public })
    }

    pub fn group(&self) -> DhGroup {
        self.group
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// `g^ir`, encoded as RFC 7296 §2.14 / RFC 5903 / RFC 8031 require.
    pub fn shared_secret(&self, peer: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &self.secret {
            DhSecret::Modp(x, p) => {
                let len = modp_len(p);
                ensure!(peer.len() == len, "bad MODP public value length");
                let y = BigUint::from_bytes_be(peer);
                let one = BigUint::from(1u32);
                ensure!(y > one && y < p - &one, "invalid MODP public value");
                Ok(pad_left(&Zeroizing::new(y.modpow(x, p).to_bytes_be()), len))
            }
            DhSecret::Ecp256(secret) => ecp_shared!(p256, 32, secret, peer),
            DhSecret::Ecp384(secret) => ecp_shared!(p384, 48, secret, peer),
            DhSecret::Ecp521(secret) => ecp_shared!(p521, 66, secret, peer),
            DhSecret::X25519(secret) => {
                let bytes: [u8; 32] = peer.try_into().context("bad X25519 public value length")?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
                ensure!(shared.was_contributory(), "X25519 public value is a low-order point");
                Ok(shared.as_bytes().to_vec())
            }
        }
    }
}

fn modp_prime(group: DhGroup) -> BigUint {
    let hex = match group {
        DhGroup::Modp1024 => MODP1024_PRIME,
        DhGroup::Modp1536 => MODP1536_PRIME,
        DhGroup::Modp2048 => MODP2048_PRIME,
        DhGroup::Modp3072 => MODP3072_PRIME,
        DhGroup::Modp4096 => MODP4096_PRIME,
        DhGroup::Modp6144 => MODP6144_PRIME,
        DhGroup::Modp8192 => MODP8192_PRIME,
        _ => unreachable!("not a MODP group"),
    };
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid constant")
}

fn modp_len(p: &BigUint) -> usize {
    p.bits().div_ceil(8) as usize
}

fn pad_left(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.max(bytes.len()));
    out.resize(len.saturating_sub(bytes.len()), 0);
    out.extend_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let out = PrfAlg::HmacSha256.compute(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(hex::encode(out), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn prf_plus_chains_blocks() {
        let prf = PrfAlg::HmacSha256;
        let out = prf.prf_plus(b"key", b"seed", 80);
        let t1 = prf.compute(b"key", &[b"seed", &[1]]);
        let t2 = prf.compute(b"key", &[&t1, b"seed", &[2]]);
        assert_eq!(out.len(), 80);
        assert_eq!(&out[..32], &t1[..]);
        assert_eq!(&out[32..64], &t2[..]);
    }

    #[test]
    fn dh_groups_agree() {
        for id in [2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 31] {
            let group = DhGroup::from_id(id).unwrap();
            assert_eq!(group.id(), id);
            let a = KeyExchange::generate(group).unwrap();
            let b = KeyExchange::generate(group).unwrap();
            let s1 = a.shared_secret(b.public()).unwrap();
            let s2 = b.shared_secret(a.public()).unwrap();
            assert_eq!(s1, s2, "{group:?}");
        }
    }

    #[test]
    fn modp_sizes() {
        assert_eq!(modp_len(&modp_prime(DhGroup::Modp1024)), 128);
        assert_eq!(modp_len(&modp_prime(DhGroup::Modp1536)), 192);
        assert_eq!(modp_len(&modp_prime(DhGroup::Modp2048)), 256);
        assert_eq!(modp_len(&modp_prime(DhGroup::Modp8192)), 1024);
        // Safe primes: (p-1)/2 passes a Fermat test to base 2.
        for g in [DhGroup::Modp1024, DhGroup::Modp1536, DhGroup::Modp2048, DhGroup::Modp3072, DhGroup::Modp4096] {
            let p = modp_prime(g);
            let one = BigUint::from(1u32);
            assert_eq!(BigUint::from(2u32).modpow(&(&p - &one), &p), one, "{g:?}");
            let q = (&p - &one) >> 1;
            assert_eq!(BigUint::from(2u32).modpow(&(&q - &one), &q), one, "{g:?}");
        }
    }

    /// RFC 3526 defines its primes from the binary expansion of pi; check
    /// the tails, which differ for each size.
    #[test]
    fn modp_primes_end_like_rfc3526() {
        for (g, tail) in [
            (DhGroup::Modp3072, "A93AD2CAFFFFFFFFFFFFFFFF"),
            (DhGroup::Modp4096, "34063199FFFFFFFFFFFFFFFF"),
            (DhGroup::Modp6144, "6DCC4024FFFFFFFFFFFFFFFF"),
            (DhGroup::Modp8192, "98EDD3DFFFFFFFFFFFFFFFFF"),
        ] {
            let hex = format!("{:X}", modp_prime(g));
            assert!(hex.starts_with("FFFFFFFFFFFFFFFFC90FDAA22168C234") && hex.ends_with(tail), "{g:?}");
        }
    }

    /// RFC 4231 test case 2 for the SHA-384 and SHA-512 PRFs, and the
    /// RFC 4868 truncation lengths.
    #[test]
    fn hmac_sha384_sha512_rfc4231_case2() {
        let data: [&[u8]; 1] = [b"what do ya want for nothing?"];
        assert_eq!(
            hex::encode(PrfAlg::HmacSha384.compute(b"Jefe", &data)),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
        assert_eq!(
            hex::encode(PrfAlg::HmacSha512.compute(b"Jefe", &data)),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!((IntegAlg::HmacSha384Trunc192.icv_len(), IntegAlg::HmacSha512Trunc256.icv_len()), (24, 32));
    }

    #[test]
    fn hmac_sha1_rfc2202_case2() {
        let out = PrfAlg::HmacSha1.compute(b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(hex::encode(out), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn dh_rejects_bad_values() {
        let a = KeyExchange::generate(DhGroup::Modp2048).unwrap();
        assert!(a.shared_secret(&[0u8; 256]).is_err());
        let b = KeyExchange::generate(DhGroup::Ecp256).unwrap();
        assert!(b.shared_secret(&[1u8; 64]).is_err());
        let c = KeyExchange::generate(DhGroup::Curve25519).unwrap();
        assert!(c.shared_secret(&[0u8; 32]).is_err());
    }

    fn ciphers() -> Vec<Cipher> {
        vec![
            Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &[7u8; 36], &[]).unwrap(),
            Cipher::new(EncrAlg::AesGcm16 { key_bits: 128 }, None, &[7u8; 20], &[]).unwrap(),
            Cipher::new(EncrAlg::ChaCha20Poly1305, None, &[7u8; 36], &[]).unwrap(),
            Cipher::new(EncrAlg::TripleDesCbc, Some(IntegAlg::HmacSha1Trunc96), &[7u8; 24], &[9u8; 20]).unwrap(),
            Cipher::new(EncrAlg::AesCbc { key_bits: 256 }, Some(IntegAlg::HmacSha256Trunc128), &[7u8; 32], &[9u8; 32])
                .unwrap(),
            Cipher::new(EncrAlg::AesCbc { key_bits: 128 }, Some(IntegAlg::HmacSha256Trunc128), &[7u8; 16], &[9u8; 32])
                .unwrap(),
            Cipher::new(EncrAlg::AesCbc { key_bits: 192 }, Some(IntegAlg::HmacSha384Trunc192), &[7u8; 24], &[9u8; 48])
                .unwrap(),
            Cipher::new(EncrAlg::AesCbc { key_bits: 256 }, Some(IntegAlg::HmacSha512Trunc256), &[7u8; 32], &[9u8; 64])
                .unwrap(),
        ]
    }

    /// Reference values computed with OpenSSL (3DES-CBC) and pyca
    /// cryptography (ChaCha20-Poly1305, nonce = salt | IV as RFC 7634 §2).
    #[test]
    fn chacha_and_3des_match_other_implementations() {
        let cbc = CbcCipher::new(
            EncrAlg::TripleDesCbc,
            &hex::decode("0123456789abcdeff1e0d3c2b5a49786fedcba9876543210").unwrap(),
        )
        .unwrap();
        let mut buf = b"0123456789abcdef0123456789abcdef".to_vec();
        cbc.encrypt(&hex::decode("1234567890abcdef").unwrap(), &mut buf);
        assert_eq!(hex::encode(&buf), "6e359c11fb6677e9b605e4b2fad608151ea8c57bcf4ecf1b858406dd4b97818c");

        let chacha = Cipher::new(EncrAlg::ChaCha20Poly1305, None, &[7u8; 36], &[]).unwrap();
        let sealed = chacha.seal(&chacha.make_iv(5), b"header", &[0x42; 32]);
        assert_eq!(
            hex::encode(&sealed[8..]),
            "7370700b672123097bc540fca7bff35955e4ba8baf154b0a3790c15dd68e91dc90f9de2db1ded4b6eb770c1882638d23"
        );
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        for c in ciphers() {
            let plain = vec![0x42u8; 32];
            let iv = c.make_iv(5);
            let sealed = c.seal(&iv, b"header", &plain);
            assert_eq!(c.open(b"header", &sealed).unwrap(), plain);
            assert!(c.open(b"other!", &sealed).is_err());
            let mut bad = sealed.clone();
            bad[iv.len() + 1] ^= 1;
            assert!(c.open(b"header", &bad).is_err());
        }
    }
}
