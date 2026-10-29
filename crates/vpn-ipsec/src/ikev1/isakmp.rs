//! An established ISAKMP SA: message encryption with IVs chained per
//! exchange (RFC 2409 Appendix B) and the phase 2 HASH(1)-style
//! authentication shared by Informational, Transaction and Quick Mode.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, ensure};
use zeroize::Zeroizing;

use super::consts::{flags, payload as pt};
use super::keys::{Phase1Keys, hash};
use super::payload::{HEADER_LEN, Header, Message, Payload, decode_chain, encode_chain};
use crate::crypto::{CbcCipher, PrfAlg, ct_eq};

/// Encrypts `payloads` into a message with the E flag set; returns the
/// message and the last ciphertext block (the next IV).
#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    cipher: &CbcCipher,
    iv: &[u8],
    cky_i: u64,
    cky_r: u64,
    exchange: u8,
    msg_id: u32,
    next: u8,
    body: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let block = cipher.block_len();
    // Encrypted in place: only ciphertext remains in it afterwards. Sized
    // for the padding first, so the plaintext is never reallocated.
    let mut plain = Vec::with_capacity(body.len().div_ceil(block).max(1) * block);
    plain.extend_from_slice(body);
    plain.resize(plain.capacity(), 0);
    cipher.encrypt(iv, &mut plain);
    let header = Header {
        cky_i,
        cky_r,
        next,
        exchange,
        flags: flags::ENCRYPTION,
        msg_id,
        length: (HEADER_LEN + plain.len()) as u32,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + plain.len());
    header.encode(&mut out);
    out.extend_from_slice(&plain);
    let last = last_block(&out, block);
    (out, last)
}

/// Decrypts an encrypted message with `iv`; returns it and the next IV.
pub fn decrypt(cipher: &CbcCipher, iv: &[u8], raw: &[u8]) -> anyhow::Result<(Message, Vec<u8>)> {
    let header = Header::decode(raw)?;
    ensure!(header.flags & flags::ENCRYPTION != 0, "message is not encrypted");
    let len = header.length as usize;
    ensure!(len <= raw.len() && len > HEADER_LEN, "bad ISAKMP message length");
    let mut body = raw[HEADER_LEN..len].to_vec();
    let block = cipher.block_len();
    ensure!(!body.is_empty() && body.len().is_multiple_of(block), "ciphertext is not block aligned");
    let next_iv = last_block(&raw[..len], block);
    cipher.decrypt(iv, &mut body);
    let payloads = decode_chain(header.next, &body)?;
    Ok((Message { header, body, payloads }, next_iv))
}

fn last_block(data: &[u8], block: usize) -> Vec<u8> {
    data[data.len() - block..].to_vec()
}

pub struct IsakmpSa {
    pub cky_i: u64,
    pub cky_r: u64,
    pub prf: PrfAlg,
    pub skeyid_d: Zeroizing<Vec<u8>>,
    pub skeyid_a: Zeroizing<Vec<u8>>,
    cipher: CbcCipher,
    /// Last CBC block of phase 1, base of every phase 2 IV.
    phase1_iv: Vec<u8>,
    /// Current IV of ongoing exchanges, by message ID.
    ivs: HashMap<u32, Vec<u8>>,
    /// Finished exchanges: their messages must not be accepted again.
    closed: Recent<u32>,
    /// Digests of the messages we sent, so a peer (or attacker) reflecting
    /// them back cannot pass them off as the gateway's: both directions
    /// share SKEYID_a and the IV formula.
    sent: Recent<Vec<u8>>,
}

/// The last entries of a set: a session of DPD probes adds one per
/// exchange, for days.
struct Recent<T> {
    set: HashSet<T>,
    order: VecDeque<T>,
}

impl<T: std::hash::Hash + Eq + Clone> Recent<T> {
    /// Several hours of exchanges at one per second.
    const KEEP: usize = 16384;

    fn new() -> Self {
        Self { set: HashSet::new(), order: VecDeque::new() }
    }

    fn insert(&mut self, value: T) {
        if self.set.insert(value.clone()) {
            self.order.push_back(value);
            if self.order.len() > Self::KEEP
                && let Some(old) = self.order.pop_front()
            {
                self.set.remove(&old);
            }
        }
    }

    fn contains(&self, value: &T) -> bool {
        self.set.contains(value)
    }
}

impl IsakmpSa {
    pub fn new(cky_i: u64, cky_r: u64, prf: PrfAlg, keys: Phase1Keys, phase1_iv: Vec<u8>) -> Self {
        Self {
            cky_i,
            cky_r,
            prf,
            skeyid_d: keys.skeyid_d,
            skeyid_a: keys.skeyid_a,
            cipher: keys.cipher,
            phase1_iv,
            ivs: HashMap::new(),
            closed: Recent::new(),
            sent: Recent::new(),
        }
    }

    fn iv(&self, msg_id: u32) -> Vec<u8> {
        self.ivs.get(&msg_id).cloned().unwrap_or_else(|| {
            hash(self.prf, &[&self.phase1_iv, &msg_id.to_be_bytes()])[..self.cipher.block_len()].to_vec()
        })
    }

    /// `prf(SKEYID_a, M-ID | prefix | rest)` (RFC 2409 §5.5, §5.7; mode-cfg §3.2).
    pub fn auth_hash(&self, msg_id: u32, prefix: &[u8], rest: &[u8]) -> Vec<u8> {
        self.prf.compute(&self.skeyid_a, &[&msg_id.to_be_bytes(), prefix, rest])
    }

    /// Builds `HASH, payloads...` with HASH = auth_hash(prefix), encrypted
    /// in the exchange `msg_id`.
    pub fn seal(&mut self, exchange: u8, msg_id: u32, prefix: &[u8], payloads: &[Payload]) -> Vec<u8> {
        let (first, rest) = encode_chain(payloads);
        let rest = Zeroizing::new(rest); // may carry XAuth credentials
        let digest = self.auth_hash(msg_id, prefix, &rest);
        self.seal_with_hash(exchange, msg_id, digest, first, &rest)
    }

    /// Builds `HASH, <rest>` with an explicit hash value.
    pub fn seal_with_hash(&mut self, exchange: u8, msg_id: u32, digest: Vec<u8>, first: u8, rest: &[u8]) -> Vec<u8> {
        let mut body = Zeroizing::new(Vec::with_capacity(4 + digest.len() + rest.len()));
        body.extend_from_slice(&[first, 0]);
        body.extend_from_slice(&((4 + digest.len()) as u16).to_be_bytes());
        body.extend_from_slice(&digest);
        body.extend_from_slice(rest);
        let iv = self.iv(msg_id);
        let (out, next) = encrypt(&self.cipher, &iv, self.cky_i, self.cky_r, exchange, msg_id, pt::HASH, &body);
        self.ivs.insert(msg_id, next);
        self.sent.insert(hash(self.prf, &[&out]));
        out
    }

    /// Decrypts a message of this SA without committing its IV: call
    /// `commit` once it is authenticated, so that forged messages cannot
    /// desynchronise the IV chain.
    pub fn open(&self, raw: &[u8]) -> anyhow::Result<(Message, Vec<u8>)> {
        let header = Header::decode(raw)?;
        ensure!(header.cky_i == self.cky_i && header.cky_r == self.cky_r, "message for another ISAKMP SA");
        ensure!(header.msg_id != 0, "phase 1 message after phase 1");
        // Every phase 2 message starts with HASH; the cleartext header
        // must not be able to announce an empty (unverifiable) chain.
        ensure!(header.next == pt::HASH, "encrypted message does not start with HASH");
        ensure!(!self.closed.contains(&header.msg_id), "message of a finished exchange (replay)");
        // Bytes past the announced length are ignored by `decrypt`: so
        // here.
        let len = (header.length as usize).min(raw.len());
        ensure!(!self.sent.contains(&hash(self.prf, &[&raw[..len]])), "one of our own messages (reflection)");
        decrypt(&self.cipher, &self.iv(header.msg_id), raw)
    }

    pub fn commit(&mut self, msg_id: u32, iv: Vec<u8>) {
        self.ivs.insert(msg_id, iv);
    }

    /// Ends an exchange: its IV state is dropped and later messages with
    /// its ID are refused.
    pub fn forget(&mut self, msg_id: u32) {
        self.ivs.remove(&msg_id);
        self.closed.insert(msg_id);
    }

    /// Checks a leading HASH equal to `auth_hash(prefix)`.
    pub fn verify(&self, msg: &Message, prefix: &[u8]) -> anyhow::Result<()> {
        let got = match msg.payloads.first().map(|d| &d.payload) {
            Some(Payload::Hash(h)) => h,
            _ => anyhow::bail!("message does not start with a HASH payload"),
        };
        let rest = msg.after_hash().context("HASH payload missing")?;
        ensure!(ct_eq(&self.auth_hash(msg.header.msg_id, prefix, rest), got), "message HASH is invalid");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncrAlg;
    use crate::ikev1::consts::exchange;
    use crate::ikev1::keys::derive_phase1;

    fn pair() -> (IsakmpSa, IsakmpSa) {
        let make = || {
            let keys = derive_phase1(
                PrfAlg::HmacSha1,
                EncrAlg::AesCbc { key_bits: 128 },
                b"psk",
                b"ni",
                b"nr",
                b"gxy",
                1,
                2,
                b"gxi",
                b"gxr",
            )
            .unwrap();
            let iv = keys.iv0.clone();
            IsakmpSa::new(1, 2, PrfAlg::HmacSha1, keys, iv)
        };
        (make(), make())
    }

    #[test]
    fn iv_chain_and_hash() {
        let (mut a, mut b) = pair();
        let payloads = [Payload::Nonce(vec![1; 16])];
        // Request then response in the same exchange.
        let m1 = a.seal(exchange::TRANSACTION, 77, &[], &payloads);
        let (msg, iv) = b.open(&m1).unwrap();
        b.verify(&msg, &[]).unwrap();
        b.commit(77, iv);
        let m2 = b.seal(exchange::TRANSACTION, 77, b"pre", &payloads);
        let (msg, iv) = a.open(&m2).unwrap();
        a.verify(&msg, b"pre").unwrap();
        assert!(a.verify(&msg, b"other").is_err());
        a.commit(77, iv);
        // A replay of m2 no longer decrypts to a valid message.
        let (msg, _) = a.open(&m2).map_or((None, None), |(m, i)| (Some(m), Some(i)));
        assert!(msg.is_none_or(|m| a.verify(&m, b"pre").is_err()));
        // A forged message does not move the IV.
        let mut forged = a.seal(exchange::INFORMATIONAL, 5, &[], &payloads);
        forged[40] ^= 1;
        assert!(b.open(&forged).is_err_and(|_| true) || b.open(&forged).is_ok_and(|(m, _)| b.verify(&m, &[]).is_err()));
    }

    #[test]
    fn replays_and_reflections_are_refused() {
        let (mut a, mut b) = pair();
        let payloads = [Payload::Nonce(vec![1; 16])];
        let m = a.seal(exchange::INFORMATIONAL, 9, &[], &payloads);
        a.forget(9);
        // Our own message reflected back to us.
        assert!(a.open(&m).is_err());
        // The peer accepts it once; after the exchange ends, never again.
        let (msg, _) = b.open(&m).unwrap();
        b.verify(&msg, &[]).unwrap();
        b.forget(9);
        assert!(b.open(&m).is_err());
        // A header announcing no payload (unverifiable) is refused.
        let mut empty = a.seal(exchange::INFORMATIONAL, 10, &[], &payloads);
        empty[16] = 0;
        assert!(b.open(&empty).is_err());
    }
}
