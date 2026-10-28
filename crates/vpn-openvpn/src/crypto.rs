//! Key material: the OpenVPN PRF (key method 2) or the TLS exporter, the
//! AEAD data channel, and the static keys of `tls-auth` and `tls-crypt`.

use anyhow::{Context, bail, ensure};
use hmac::{Hmac, Mac};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::{Zeroize, Zeroizing};

/// Two keys, each 64 cipher then 64 HMAC bytes: OpenVPN's `struct key2`,
/// as in a static key file or the expanded key block.
pub type Key2 = [u8; 256];

/// One direction of a `Key2`.
pub fn cipher_part(key: &Key2, index: usize) -> &[u8] {
    &key[index * 128..index * 128 + 64]
}

pub fn hmac_part(key: &Key2, index: usize) -> &[u8] {
    &key[index * 128 + 64..index * 128 + 128]
}

/// TLS 1.0 PRF (RFC 2246 §5): P_MD5 over the first half of the secret
/// XOR P_SHA1 over the second; `seed` includes the label.
pub fn tls1_prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let half = secret.len().div_ceil(2);
    let (s1, s2) = (&secret[..half], &secret[secret.len() - half..]);
    p_hash::<Hmac<md5::Md5>>(s1, seed, out, false);
    p_hash::<Hmac<sha1::Sha1>>(s2, seed, out, true);
}

fn p_hash<M: Mac + hmac::digest::KeyInit + Clone>(secret: &[u8], seed: &[u8], out: &mut [u8], xor: bool) {
    let base = <M as hmac::digest::KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    let mut a = {
        let mut m = base.clone();
        m.update(seed);
        m.finalize().into_bytes().to_vec()
    };
    let mut done = 0;
    while done < out.len() {
        let mut m = base.clone();
        m.update(&a);
        m.update(seed);
        let block = m.finalize().into_bytes();
        for (o, b) in out[done..].iter_mut().zip(block.iter()) {
            if xor { *o ^= b } else { *o = *b }
        }
        done += block.len();
        let mut m = base.clone();
        m.update(&a);
        a.zeroize();
        a = m.finalize().into_bytes().to_vec();
    }
    a.zeroize();
}

/// What each side contributes to the data channel keys (key method 2).
pub struct KeySource {
    pub pre_master: [u8; 48],
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

impl Drop for KeySource {
    fn drop(&mut self) {
        self.pre_master.zeroize();
        self.random1.zeroize();
        self.random2.zeroize();
    }
}

/// The key block of the OpenVPN PRF: a master secret from the client's
/// pre-master and both first randoms, expanded with both second randoms
/// and the session ids.
pub fn prf_key_block(
    client: &KeySource,
    server_random1: &[u8; 32],
    server_random2: &[u8; 32],
    client_sid: &[u8; 8],
    server_sid: &[u8; 8],
) -> Zeroizing<Key2> {
    let mut seed = Vec::new();
    seed.extend_from_slice(b"OpenVPN master secret");
    seed.extend_from_slice(&client.random1);
    seed.extend_from_slice(server_random1);
    let mut master = Zeroizing::new([0u8; 48]);
    tls1_prf(&client.pre_master, &seed, &mut *master);

    seed.clear();
    seed.extend_from_slice(b"OpenVPN key expansion");
    seed.extend_from_slice(&client.random2);
    seed.extend_from_slice(server_random2);
    seed.extend_from_slice(client_sid);
    seed.extend_from_slice(server_sid);
    let mut block = Zeroizing::new([0u8; 256]);
    tls1_prf(&*master, &seed, &mut *block);
    block
}

/// TLS exporter label of `key-derivation tls-ekm`.
pub const EKM_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl DataCipher {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Some(Self::Aes128Gcm),
            "AES-256-GCM" => Some(Self::Aes256Gcm),
            "CHACHA20-POLY1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305",
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

pub const TAG_LEN: usize = 16;

/// The data channel keys of one key state: we encrypt with key 0 and
/// decrypt with key 1 of the block (the server does the reverse); the
/// 8 first HMAC bytes are the implicit part of the nonce.
pub struct DataKeys {
    encrypt: LessSafeKey,
    decrypt: LessSafeKey,
    encrypt_iv: [u8; 8],
    decrypt_iv: [u8; 8],
    /// Last packet id sent.
    sent: u32,
    replay: ReplayWindow,
}

impl DataKeys {
    pub fn new(cipher: DataCipher, block: &Key2) -> anyhow::Result<Self> {
        let algorithm = cipher.algorithm();
        let key = |index: usize| -> anyhow::Result<LessSafeKey> {
            let bytes = &cipher_part(block, index)[..algorithm.key_len()];
            Ok(LessSafeKey::new(UnboundKey::new(algorithm, bytes).map_err(|_| anyhow::anyhow!("bad key"))?))
        };
        let iv = |index: usize| -> [u8; 8] { hmac_part(block, index)[..8].try_into().unwrap() };
        Ok(Self {
            encrypt: key(0)?,
            decrypt: key(1)?,
            encrypt_iv: iv(0),
            decrypt_iv: iv(1),
            sent: 0,
            replay: ReplayWindow::default(),
        })
    }

    /// Whether this key's packet ids are nearly used up: renegotiate.
    pub fn worn_out(&self) -> bool {
        self.sent > 0xff00_0000
    }

    /// `header` is the opcode byte, plus the peer id for P_DATA_V2.
    /// Returns header, packet id, tag, ciphertext.
    pub fn seal(&mut self, header: &[u8], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        ensure!(self.sent < u32::MAX, "data channel packet ids exhausted");
        self.sent += 1;
        let pid = self.sent.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&pid);
        nonce[4..].copy_from_slice(&self.encrypt_iv);
        // P_DATA_V2 authenticates its 4-byte header, P_DATA_V1 only the id.
        let mut aad = Vec::with_capacity(8);
        if header.len() == 4 {
            aad.extend_from_slice(header);
        }
        aad.extend_from_slice(&pid);
        let mut body = payload.to_vec();
        let tag = self
            .encrypt
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut body)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut out = Vec::with_capacity(header.len() + 4 + TAG_LEN + body.len());
        out.extend_from_slice(header);
        out.extend_from_slice(&pid);
        out.extend_from_slice(tag.as_ref());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// `packet` without its header: packet id, tag, ciphertext.
    pub fn open(&mut self, header: &[u8], packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        ensure!(packet.len() >= 4 + TAG_LEN, "data packet too short");
        let pid: [u8; 4] = packet[..4].try_into().unwrap();
        let id = u32::from_be_bytes(pid);
        ensure!(self.replay.fresh(id), "replayed data packet");
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&pid);
        nonce[4..].copy_from_slice(&self.decrypt_iv);
        let mut aad = Vec::with_capacity(8);
        if header.len() == 4 {
            aad.extend_from_slice(header);
        }
        aad.extend_from_slice(&pid);
        let mut body = Vec::with_capacity(packet.len() - 4);
        body.extend_from_slice(&packet[4 + TAG_LEN..]);
        body.extend_from_slice(&packet[4..4 + TAG_LEN]);
        let plain = self
            .decrypt
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut body)
            .map_err(|_| anyhow::anyhow!("data packet authentication failed"))?
            .len();
        self.replay.accept(id);
        body.truncate(plain);
        Ok(body)
    }
}

/// Accepts each packet id once, within 64 of the highest seen.
#[derive(Default)]
pub struct ReplayWindow {
    highest: u64,
    seen: u64,
}

impl ReplayWindow {
    pub fn fresh(&self, id: u32) -> bool {
        let id = u64::from(id);
        if id == 0 {
            return false;
        }
        if id > self.highest {
            return true;
        }
        let back = self.highest - id;
        back < 64 && self.seen & (1 << back) == 0
    }

    pub fn accept(&mut self, id: u32) {
        let id = u64::from(id);
        if id > self.highest {
            let shift = id - self.highest;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = id;
        } else {
            self.seen |= 1 << (self.highest - id);
        }
    }
}

/// HMAC digest of `tls-auth`.
fn hmac_algorithm(name: &str) -> anyhow::Result<ring::hmac::Algorithm> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "SHA1" => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => ring::hmac::HMAC_SHA256,
        "SHA384" => ring::hmac::HMAC_SHA384,
        "SHA512" => ring::hmac::HMAC_SHA512,
        other => bail!("unsupported tls-auth digest {other}"),
    })
}

/// Protection of the control channel by the shared static key.
pub enum Wrap {
    None,
    /// `tls-auth`: HMAC over replay id, time, header and contents.
    Auth {
        send: ring::hmac::Key,
        receive: ring::hmac::Key,
        len: usize,
        ids: PacketIds,
    },
    /// `tls-crypt`: HMAC-SHA256 tag, AES-256-CTR with the tag as IV.
    Crypt {
        send: CryptKey,
        receive: CryptKey,
        ids: PacketIds,
    },
}

pub struct CryptKey {
    cipher: Zeroizing<[u8; 32]>,
    mac: ring::hmac::Key,
}

/// Replay protection of wrapped control packets: our counter, and the
/// window of the server's.
#[derive(Default)]
pub struct PacketIds {
    sent: u32,
    received: ReplayWindow,
    /// The time of the server's ids in the window: its ids restart with
    /// a new time, and those of an earlier time are replays.
    received_time: u32,
}

/// A wrapped packet's replay id: counter and time.
#[derive(Debug, Clone, Copy)]
pub struct PacketId {
    id: u32,
    time: u32,
}

impl PacketId {
    fn parse(pid: &[u8]) -> Self {
        Self {
            id: u32::from_be_bytes(pid[..4].try_into().unwrap()),
            time: u32::from_be_bytes(pid[4..8].try_into().unwrap()),
        }
    }
}

impl PacketIds {
    fn fresh(&self, pid: PacketId) -> bool {
        match pid.time.cmp(&self.received_time) {
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Greater => pid.id != 0,
            std::cmp::Ordering::Equal => self.received.fresh(pid.id),
        }
    }

    fn accept(&mut self, pid: PacketId) {
        if pid.time > self.received_time {
            self.received = ReplayWindow::default();
            self.received_time = pid.time;
        }
        self.received.accept(pid.id);
    }

    fn next(&mut self) -> [u8; 8] {
        self.sent += 1;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or_default();
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.sent.to_be_bytes());
        out[4..].copy_from_slice(&time.to_be_bytes());
        out
    }
}

/// Header of a control packet: opcode byte and our or the server's
/// session id.
pub const HEADER_LEN: usize = 9;

impl Wrap {
    /// `direction`: `tls-auth`'s key-direction; `tls-crypt` always uses
    /// key 1 to send, as an OpenVPN client.
    pub fn new(profile: &vpn_core::OpenVpnProfile) -> anyhow::Result<Self> {
        use vpn_core::ControlChannel;
        if profile.control_channel == ControlChannel::None {
            return Ok(Self::None);
        }
        let key = Zeroizing::new(vpn_core::openvpn::parse_static_key(
            profile.static_key.as_deref().context("missing static key")?,
        )?);
        Ok(match profile.control_channel {
            ControlChannel::None => unreachable!(),
            ControlChannel::TlsAuth => {
                let algorithm = hmac_algorithm(&profile.auth_digest)?;
                let len = algorithm.digest_algorithm().output_len();
                let (send, receive) = match profile.key_direction {
                    None => (0, 0),
                    Some(0) => (0, 1),
                    Some(_) => (1, 0),
                };
                let mac = |index: usize| ring::hmac::Key::new(algorithm, &hmac_part(&key, index)[..len]);
                Self::Auth { send: mac(send), receive: mac(receive), len, ids: PacketIds::default() }
            }
            ControlChannel::TlsCrypt => {
                let crypt = |index: usize| CryptKey {
                    cipher: Zeroizing::new(cipher_part(&key, index)[..32].try_into().unwrap()),
                    mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_part(&key, index)[..32]),
                };
                Self::Crypt { send: crypt(1), receive: crypt(0), ids: PacketIds::default() }
            }
        })
    }

    /// Wraps `header` (opcode byte and session id) and `body` (acks,
    /// message id, payload) into a packet.
    pub fn seal(&mut self, header: &[u8; HEADER_LEN], body: &[u8]) -> Vec<u8> {
        match self {
            Self::None => [header.as_slice(), body].concat(),
            Self::Auth { send, ids, .. } => {
                let pid = ids.next();
                let mut ctx = ring::hmac::Context::with_key(send);
                ctx.update(&pid);
                ctx.update(header);
                ctx.update(body);
                [header.as_slice(), ctx.sign().as_ref(), &pid, body].concat()
            }
            Self::Crypt { send, ids, .. } => {
                let pid = ids.next();
                let mut ctx = ring::hmac::Context::with_key(&send.mac);
                ctx.update(header);
                ctx.update(&pid);
                ctx.update(body);
                let tag = ctx.sign();
                let mut encrypted = body.to_vec();
                ctr(&send.cipher, tag.as_ref()[..16].try_into().unwrap(), &mut encrypted);
                [header.as_slice(), &pid, tag.as_ref(), &encrypted].concat()
            }
        }
    }

    /// Checks and unwraps a control packet; returns its body and its id,
    /// to `accept` once the packet is known to belong to the session (a
    /// replay from another one must not move the window).
    pub fn open(&mut self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, Option<PacketId>)> {
        ensure!(packet.len() >= HEADER_LEN, "control packet too short");
        let header = &packet[..HEADER_LEN];
        match self {
            Self::None => Ok((packet[HEADER_LEN..].to_vec(), None)),
            Self::Auth { receive, len, ids, .. } => {
                let rest = &packet[HEADER_LEN..];
                ensure!(rest.len() >= *len + 8, "control packet too short");
                let (mac, rest) = rest.split_at(*len);
                let (pid, body) = rest.split_at(8);
                let id = PacketId::parse(pid);
                ensure!(ids.fresh(id), "replayed control packet");
                let signed = [pid, header, body].concat();
                ring::hmac::verify(receive, &signed, mac)
                    .map_err(|_| anyhow::anyhow!("control packet authentication failed (tls-auth key)"))?;
                Ok((body.to_vec(), Some(id)))
            }
            Self::Crypt { receive, ids, .. } => {
                let rest = &packet[HEADER_LEN..];
                ensure!(rest.len() >= 8 + 32, "control packet too short");
                let (pid, rest) = rest.split_at(8);
                let (tag, encrypted) = rest.split_at(32);
                let id = PacketId::parse(pid);
                ensure!(ids.fresh(id), "replayed control packet");
                let mut body = encrypted.to_vec();
                ctr(&receive.cipher, tag[..16].try_into().unwrap(), &mut body);
                let signed = [header, pid, &body].concat();
                ring::hmac::verify(&receive.mac, &signed, tag)
                    .map_err(|_| anyhow::anyhow!("control packet authentication failed (tls-crypt key)"))?;
                Ok((body, Some(id)))
            }
        }
    }

    /// Moves the replay window past a packet `open` returned.
    pub fn accept(&mut self, pid: Option<PacketId>) {
        if let (Some(pid), Self::Auth { ids, .. } | Self::Crypt { ids, .. }) = (pid, self) {
            ids.accept(pid);
        }
    }
}

fn ctr(key: &[u8; 32], iv: [u8; 16], data: &mut [u8]) {
    use aes::cipher::{KeyIvInit, StreamCipher};
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(key.into(), &iv.into());
    cipher.apply_keystream(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2246 has no vectors; this one comes from OpenSSL: `openssl kdf
    /// -keylen 32 -kdfopt digest:MD5-SHA1 -kdfopt secret:secret -kdfopt
    /// seed:"label and seed" TLS1-PRF`.
    #[test]
    fn tls1_prf_matches_openssl() {
        let mut out = [0u8; 32];
        tls1_prf(b"secret", b"label and seed", &mut out);
        assert_eq!(hex::encode(out), PRF_VECTOR);
    }

    const PRF_VECTOR: &str = include_str!("../tests/data/prf-vector.txt").trim_ascii();

    #[test]
    fn data_channel_round_trip() {
        let block = [7u8; 256];
        let mut ours = DataKeys::new(DataCipher::Aes256Gcm, &block).unwrap();
        // The server's view: the two halves swapped.
        let mut swapped = [0u8; 256];
        swapped[..128].copy_from_slice(&block[128..]);
        swapped[128..].copy_from_slice(&block[..128]);
        let mut block2 = block;
        block2[0] = 9;
        let mut theirs = DataKeys::new(DataCipher::Aes256Gcm, &swapped).unwrap();
        let header = [9 << 3, 0, 0, 1];
        let packet = ours.seal(&header, b"hello").unwrap();
        assert_eq!(theirs.open(&header, &packet[4..]).unwrap(), b"hello");
        assert!(theirs.open(&header, &packet[4..]).is_err(), "replay");
        let mut tampered = packet.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(DataKeys::new(DataCipher::Aes256Gcm, &swapped).unwrap().open(&header, &tampered[4..]).is_err());
        assert!(DataKeys::new(DataCipher::Aes256Gcm, &block2).is_ok());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        for id in [1, 3, 2, 70] {
            assert!(w.fresh(id));
            w.accept(id);
        }
        assert!(!w.fresh(3) && !w.fresh(5) && w.fresh(69) && !w.fresh(0));
    }

    /// Our wrap and the server's, from one static key.
    fn wraps(crypt: bool) -> (Wrap, Wrap) {
        let key: Key2 = std::array::from_fn(|i| i as u8);
        if crypt {
            let part = |index: usize| CryptKey {
                cipher: Zeroizing::new(cipher_part(&key, index)[..32].try_into().unwrap()),
                mac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_part(&key, index)[..32]),
            };
            let ids = PacketIds::default;
            (
                Wrap::Crypt { send: part(1), receive: part(0), ids: ids() },
                Wrap::Crypt { send: part(0), receive: part(1), ids: ids() },
            )
        } else {
            let mac = |index: usize| {
                ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &hmac_part(&key, index)[..20])
            };
            let auth = |send, receive| Wrap::Auth {
                send: mac(send),
                receive: mac(receive),
                len: 20,
                ids: PacketIds::default(),
            };
            (auth(1, 0), auth(0, 1))
        }
    }

    #[test]
    fn control_wrap_round_trip() {
        for crypt in [false, true] {
            let (mut ours, mut theirs) = wraps(crypt);
            let mut header = [3; HEADER_LEN];
            header[0] = crate::wire::header_byte(crate::wire::CONTROL_V1, 0);
            let packet = ours.seal(&header, b"body");
            let (body, pid) = theirs.open(&packet).unwrap();
            assert_eq!(body, b"body", "crypt: {crypt}");
            theirs.accept(pid);
            assert!(theirs.open(&packet).is_err(), "replay, crypt: {crypt}");

            let packet = ours.seal(&header, b"body");
            let mut tampered = packet.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(theirs.open(&tampered).is_err(), "tampered body, crypt: {crypt}");
            let mut tampered = packet.clone();
            tampered[1] ^= 1;
            assert!(theirs.open(&tampered).is_err(), "tampered header, crypt: {crypt}");
            // Not accepted: an unauthenticated packet does not move the window.
            assert!(theirs.open(&packet).is_ok(), "crypt: {crypt}");
            assert!(ours.open(&packet).is_err(), "our own packet, crypt: {crypt}");
        }
    }
}
