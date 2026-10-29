//! EAP peer with EAP-MSCHAPv2 (RFC 3748, draft-kamath-pppext-eap-mschapv2,
//! RFC 2759 for the challenge/response, RFC 3079 for the MSK).

use anyhow::{Context, bail, ensure};
use des::Des;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use md4::Md4;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::random_bytes;

const CODE_REQUEST: u8 = 1;
const CODE_RESPONSE: u8 = 2;
const CODE_SUCCESS: u8 = 3;
const CODE_FAILURE: u8 = 4;
const TYPE_IDENTITY: u8 = 1;
const TYPE_NOTIFICATION: u8 = 2;
const TYPE_NAK: u8 = 3;
const TYPE_MSCHAPV2: u8 = 26;
const OP_CHALLENGE: u8 = 1;
const OP_RESPONSE: u8 = 2;
const OP_SUCCESS: u8 = 3;
const OP_FAILURE: u8 = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum EapStep {
    /// Send this EAP packet back.
    Respond(Vec<u8>),
    Success,
    Failure(String),
}

pub struct EapPeer {
    identity: String,
    password: Zeroizing<String>,
    /// (authenticator response we expect, MSK) once the challenge is answered.
    pending: Option<(String, Zeroizing<Vec<u8>>)>,
    verified: bool,
    msk: Option<Zeroizing<Vec<u8>>>,
}

impl EapPeer {
    /// Takes ownership of `password`; it is wiped when the peer is dropped.
    pub fn new(identity: String, password: String) -> Self {
        Self { identity, password: Zeroizing::new(password), pending: None, verified: false, msk: None }
    }

    pub fn msk(&self) -> Option<&[u8]> {
        self.msk.as_ref().map(|m| m.as_slice())
    }

    pub fn process(&mut self, packet: &[u8]) -> anyhow::Result<EapStep> {
        ensure!(packet.len() >= 4, "EAP packet too short");
        let (code, id) = (packet[0], packet[1]);
        let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        ensure!(len >= 4 && len <= packet.len(), "bad EAP length");
        let packet = &packet[..len];
        match code {
            CODE_SUCCESS => {
                ensure!(self.verified, "EAP success before the server proved knowledge of the password");
                self.msk = self.pending.take().map(|(_, msk)| msk);
                Ok(EapStep::Success)
            }
            CODE_FAILURE => Ok(EapStep::Failure("EAP failure".into())),
            CODE_REQUEST => {
                ensure!(len >= 5, "EAP request without type");
                let data = &packet[5..];
                match packet[4] {
                    TYPE_IDENTITY => Ok(EapStep::Respond(response(id, TYPE_IDENTITY, self.identity.as_bytes()))),
                    TYPE_NOTIFICATION => Ok(EapStep::Respond(response(id, TYPE_NOTIFICATION, &[]))),
                    TYPE_MSCHAPV2 => self.mschapv2(id, data),
                    _ => Ok(EapStep::Respond(response(id, TYPE_NAK, &[TYPE_MSCHAPV2]))),
                }
            }
            _ => bail!("unexpected EAP code {code}"),
        }
    }

    fn mschapv2(&mut self, id: u8, data: &[u8]) -> anyhow::Result<EapStep> {
        ensure!(data.len() >= 4, "EAP-MSCHAPv2 packet too short");
        let (op, ms_id) = (data[0], data[1]);
        match op {
            OP_CHALLENGE => {
                ensure!(data.len() >= 5 + 16 && data[4] == 16, "bad MSCHAPv2 challenge");
                let auth_challenge: [u8; 16] = data[5..21].try_into().unwrap();
                let peer_challenge: [u8; 16] = random_bytes(16).try_into().unwrap();
                let username = mschap_username(&self.identity);
                let nt = nt_response(&auth_challenge, &peer_challenge, username.as_bytes(), &self.password);
                let password_hash = nt_password_hash(&self.password);
                let expected =
                    authenticator_response(&password_hash, &nt, &peer_challenge, &auth_challenge, username.as_bytes());
                self.pending = Some((expected, msk(&password_hash, &nt)));
                self.verified = false;

                let mut body = vec![OP_RESPONSE, ms_id, 0, 0, 49];
                body.extend_from_slice(&peer_challenge);
                body.extend_from_slice(&[0u8; 8]);
                body.extend_from_slice(&nt);
                body.push(0);
                body.extend_from_slice(self.identity.as_bytes());
                let ms_len = body.len() as u16;
                body[2..4].copy_from_slice(&ms_len.to_be_bytes());
                Ok(EapStep::Respond(response(id, TYPE_MSCHAPV2, &body)))
            }
            OP_SUCCESS => {
                let (expected, _) = self.pending.as_ref().context("MSCHAPv2 success without challenge")?;
                let message = String::from_utf8_lossy(&data[4..]);
                let got = message.split_whitespace().find(|t| t.starts_with("S=")).unwrap_or("");
                ensure!(
                    got.eq_ignore_ascii_case(expected),
                    "gateway's MSCHAPv2 authenticator response is wrong (possible impostor)"
                );
                self.verified = true;
                Ok(EapStep::Respond(response(id, TYPE_MSCHAPV2, &[OP_SUCCESS])))
            }
            OP_FAILURE => {
                let message = String::from_utf8_lossy(&data[4..]).into_owned();
                let reason = if message.contains("E=691") {
                    "wrong username or password".to_string()
                } else if message.contains("E=648") {
                    "password expired".to_string()
                } else {
                    message
                };
                Ok(EapStep::Failure(reason))
            }
            _ => bail!("unexpected MSCHAPv2 opcode {op}"),
        }
    }
}

fn response(id: u8, eap_type: u8, data: &[u8]) -> Vec<u8> {
    let len = (5 + data.len()) as u16;
    let mut out = vec![CODE_RESPONSE, id];
    out.extend_from_slice(&len.to_be_bytes());
    out.push(eap_type);
    out.extend_from_slice(data);
    out
}

/// MSCHAPv2 hashes the user name without any `DOMAIN\` prefix.
pub fn mschap_username(identity: &str) -> &str {
    identity.rsplit_once('\\').map_or(identity, |(_, user)| user)
}

/// The NT hash stands for the password: it and the password's UTF-16
/// copy (sized up front, never reallocated) are erased after use.
pub fn nt_password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let mut utf16 = Zeroizing::new(Vec::with_capacity(2 * password.encode_utf16().count()));
    utf16.extend(password.encode_utf16().flat_map(u16::to_le_bytes));
    Zeroizing::new(Md4::digest(&*utf16).into())
}

fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], username: &[u8]) -> [u8; 8] {
    let digest = Sha1::new().chain_update(peer).chain_update(auth).chain_update(username).finalize();
    digest[..8].try_into().unwrap()
}

fn des_encrypt(key7: &[u8], data: &[u8; 8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = key7[0] >> 1;
    for i in 1..7 {
        key[i] = ((key7[i - 1] & ((1 << i) - 1)) << (7 - i)) | (key7[i] >> (i + 1));
    }
    key[7] = key7[6] & 0x7f;
    for k in &mut key {
        *k <<= 1;
    }
    let cipher = Des::new_from_slice(&key).expect("8-byte DES key");
    key.zeroize();
    let mut block = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    block.into()
}

pub fn nt_response(auth: &[u8; 16], peer: &[u8; 16], username: &[u8], password: &str) -> [u8; 24] {
    let challenge = challenge_hash(peer, auth, username);
    let mut hash = Zeroizing::new([0u8; 21]);
    hash[..16].copy_from_slice(&*nt_password_hash(password));
    let mut out = [0u8; 24];
    for i in 0..3 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&des_encrypt(&hash[i * 7..(i + 1) * 7], &challenge));
    }
    out
}

const MAGIC_SIGN_1: &[u8] = b"Magic server to client signing constant";
const MAGIC_SIGN_2: &[u8] = b"Pad to make it do more than one iteration";

pub fn authenticator_response(
    password_hash: &[u8; 16],
    nt: &[u8; 24],
    peer: &[u8; 16],
    auth: &[u8; 16],
    username: &[u8],
) -> String {
    let hash_hash = Md4::digest(password_hash);
    let digest = Sha1::new().chain_update(hash_hash).chain_update(nt).chain_update(MAGIC_SIGN_1).finalize();
    let challenge = challenge_hash(peer, auth, username);
    let digest = Sha1::new().chain_update(digest).chain_update(challenge).chain_update(MAGIC_SIGN_2).finalize();
    format!("S={}", hex::encode_upper(digest))
}

const MAGIC_MASTER: &[u8] = b"This is the MPPE Master Key";
const MAGIC_CLIENT_SEND: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MAGIC_CLIENT_RECV: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

fn master_key(password_hash: &[u8; 16], nt: &[u8; 24]) -> Zeroizing<[u8; 16]> {
    let hash_hash = Md4::digest(password_hash);
    let digest = Sha1::new().chain_update(hash_hash).chain_update(nt).chain_update(MAGIC_MASTER).finalize();
    Zeroizing::new(digest[..16].try_into().unwrap())
}

fn asymmetric_start_key(master: &[u8; 16], magic: &[u8]) -> Zeroizing<[u8; 16]> {
    let digest = Sha1::new()
        .chain_update(master)
        .chain_update([0u8; 40])
        .chain_update(magic)
        .chain_update([0xf2u8; 40])
        .finalize();
    Zeroizing::new(digest[..16].try_into().unwrap())
}

/// MSK as used by IKEv2 with EAP-MSCHAPv2: the two RFC 3079 start keys,
/// "client send" first, padded to 64 bytes. Both ends derive the same
/// value whichever side they are on.
fn msk(password_hash: &[u8; 16], nt: &[u8; 24]) -> Zeroizing<Vec<u8>> {
    let master = master_key(password_hash, nt);
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(&*asymmetric_start_key(&master, MAGIC_CLIENT_SEND));
    out.extend_from_slice(&*asymmetric_start_key(&master, MAGIC_CLIENT_RECV));
    out.resize(64, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2759 §9.2.
    const AUTH_CHALLENGE: [u8; 16] =
        [0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28];
    const PEER_CHALLENGE: [u8; 16] =
        [0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E];

    #[test]
    fn rfc2759_vectors() {
        assert_eq!(hex::encode(challenge_hash(&PEER_CHALLENGE, &AUTH_CHALLENGE, b"User")), "d02e4386bce91226");
        let hash = nt_password_hash("clientPass");
        assert_eq!(hex::encode(*hash), "44ebba8d5312b8d611474411f56989ae");
        let nt = nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, b"User", "clientPass");
        assert_eq!(hex::encode(nt), "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df");
        assert_eq!(hex::encode(Md4::digest(*hash)), "41c00c584bd2d91c4017a2a12fa59f3f");
        assert_eq!(
            authenticator_response(&hash, &nt, &PEER_CHALLENGE, &AUTH_CHALLENGE, b"User"),
            "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
    }

    #[test]
    fn rfc3079_master_and_send_key() {
        let hash = nt_password_hash("clientPass");
        let nt = nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, b"User", "clientPass");
        let master = master_key(&hash, &nt);
        assert_eq!(hex::encode(*master), "fdece3717a8c838cb388e527ae3cdd31");
        // RFC 3079 §3.5.3 shows the server's send key, i.e. the client's receive key.
        assert_eq!(hex::encode(asymmetric_start_key(&master, MAGIC_CLIENT_RECV)), "8b7cdc149b993a1ba118cb153f56dccb");
        assert_eq!(msk(&hash, &nt).len(), 64);
    }

    #[test]
    fn full_exchange() {
        let mut peer = EapPeer::new("CORP\\User".into(), "clientPass".into());
        // Identity request.
        let step = peer.process(&[CODE_REQUEST, 1, 0, 5, TYPE_IDENTITY]).unwrap();
        assert_eq!(step, EapStep::Respond(response(1, TYPE_IDENTITY, b"CORP\\User")));
        // Challenge.
        let mut chal = vec![CODE_REQUEST, 2, 0, 0, TYPE_MSCHAPV2, OP_CHALLENGE, 7, 0, 0, 16];
        chal.extend_from_slice(&AUTH_CHALLENGE);
        chal.extend_from_slice(b"fortigate");
        let len = chal.len() as u16;
        chal[2..4].copy_from_slice(&len.to_be_bytes());
        let EapStep::Respond(resp) = peer.process(&chal).unwrap() else { panic!() };
        assert_eq!(&resp[..2], &[CODE_RESPONSE, 2]);
        assert_eq!(resp[5], OP_RESPONSE);
        assert_eq!(resp[6], 7);
        assert_eq!(u16::from_be_bytes([resp[7], resp[8]]) as usize, resp.len() - 5);
        let peer_challenge: [u8; 16] = resp[10..26].try_into().unwrap();
        let nt: [u8; 24] = resp[34..58].try_into().unwrap();
        let hash = nt_password_hash("clientPass");
        assert_eq!(nt, nt_response(&AUTH_CHALLENGE, &peer_challenge, b"User", "clientPass"));
        // EAP success before the authenticator response is refused.
        assert!(EapPeer::new("u".into(), "p".into()).process(&[CODE_SUCCESS, 3, 0, 4]).is_err());
        // Wrong authenticator response.
        let mut bad = vec![CODE_REQUEST, 3, 0, 0, TYPE_MSCHAPV2, OP_SUCCESS, 7, 0, 0];
        bad.extend_from_slice(b"S=0000000000000000000000000000000000000000 M=ok");
        let len = bad.len() as u16;
        bad[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(peer.process(&bad).is_err());
        // Right one.
        let auth = authenticator_response(&hash, &nt, &peer_challenge, &AUTH_CHALLENGE, b"User");
        let mut ok = vec![CODE_REQUEST, 3, 0, 0, TYPE_MSCHAPV2, OP_SUCCESS, 7, 0, 0];
        ok.extend_from_slice(format!("{auth} M=Welcome").as_bytes());
        let len = ok.len() as u16;
        ok[2..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(peer.process(&ok).unwrap(), EapStep::Respond(response(3, TYPE_MSCHAPV2, &[OP_SUCCESS])));
        assert_eq!(peer.process(&[CODE_SUCCESS, 3, 0, 4]).unwrap(), EapStep::Success);
        assert_eq!(peer.msk().unwrap(), msk(&hash, &nt).as_slice());
    }
}
