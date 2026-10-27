//! IKEv2 message framing and the SK (encrypted) payload (RFC 7296 §3.1,
//! §3.14; RFC 5282 for AES-GCM).

use anyhow::{Context, bail, ensure};

use super::consts::{flags, notify, payload as pt};
use super::payload::{CpAttr, Identity, Notify, Payload, Proposal, TrafficSelector, decode_chain, encode_chain};
use crate::crypto::Cipher;

pub const HEADER_LEN: usize = 28;
const VERSION: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub spi_i: u64,
    pub spi_r: u64,
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

impl Header {
    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        ensure!(buf.len() >= HEADER_LEN, "IKE message too short");
        ensure!(buf[17] >> 4 == 2, "not an IKEv2 message (version {:#x})", buf[17]);
        let u32_at = |at: usize| u32::from_be_bytes(buf[at..at + 4].try_into().unwrap());
        Ok(Self {
            spi_i: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            spi_r: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            next: buf[16],
            exchange: buf[18],
            flags: buf[19],
            msg_id: u32_at(20),
            length: u32_at(24),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.spi_i.to_be_bytes());
        out.extend_from_slice(&self.spi_r.to_be_bytes());
        out.extend_from_slice(&[self.next, VERSION, self.exchange, self.flags]);
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }

    pub fn is_response(&self) -> bool {
        self.flags & flags::RESPONSE != 0
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub payloads: Vec<Payload>,
}

pub fn build_plain(spi_i: u64, spi_r: u64, exchange: u8, flags: u8, msg_id: u32, payloads: &[Payload]) -> Vec<u8> {
    let (next, body) = encode_chain(payloads);
    let header = Header { spi_i, spi_r, next, exchange, flags, msg_id, length: (HEADER_LEN + body.len()) as u32 };
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// Builds a message whose payloads are all inside one SK payload.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted(
    spi_i: u64,
    spi_r: u64,
    exchange: u8,
    flags: u8,
    msg_id: u32,
    payloads: &[Payload],
    cipher: &Cipher,
    iv: &[u8],
) -> Vec<u8> {
    let (inner_first, mut plain) = encode_chain(payloads);
    let block = cipher.block_len();
    let pad = (block - (plain.len() + 1) % block) % block;
    plain.resize(plain.len() + pad, 0);
    plain.push(pad as u8);
    let sk_len = 4 + cipher.iv_len() + plain.len() + cipher.icv_len();
    let header = Header { spi_i, spi_r, next: pt::SK, exchange, flags, msg_id, length: (HEADER_LEN + sk_len) as u32 };
    let mut out = Vec::with_capacity(HEADER_LEN + sk_len);
    header.encode(&mut out);
    out.extend_from_slice(&[inner_first, 0]);
    out.extend_from_slice(&(sk_len as u16).to_be_bytes());
    let sealed = cipher.seal(iv, &out, &plain);
    out.extend_from_slice(&sealed);
    out
}

/// Parses a message, decrypting the SK payload when `cipher` is given.
pub fn parse(buf: &[u8], cipher: Option<&Cipher>) -> anyhow::Result<Message> {
    let header = Header::decode(buf)?;
    let len = header.length as usize;
    ensure!(len >= HEADER_LEN && len <= buf.len(), "bad IKE message length");
    let buf = &buf[..len];
    let mut payloads = decode_chain(header.next, &buf[HEADER_LEN..])?;
    if let Some(Payload::Sk { inner_first, offset }) = payloads.last().cloned() {
        payloads.pop();
        let cipher = cipher.context("encrypted payload before keys are established")?;
        let sk_start = HEADER_LEN + offset;
        let sk_len = u16::from_be_bytes([buf[sk_start + 2], buf[sk_start + 3]]) as usize;
        ensure!(sk_start + sk_len == len, "SK payload must be the last payload");
        let plain = cipher.open(&buf[..sk_start + 4], &buf[sk_start + 4..len])?;
        let pad = *plain.last().context("empty SK plaintext")? as usize;
        ensure!(pad < plain.len(), "bad SK padding");
        payloads.extend(decode_chain(inner_first, &plain[..plain.len() - 1 - pad])?);
    } else if cipher.is_some() {
        bail!("expected an encrypted message");
    }
    Ok(Message { header, payloads })
}

impl Message {
    pub fn notifies(&self) -> impl Iterator<Item = &Notify> {
        self.payloads.iter().filter_map(|p| match p {
            Payload::Notify(n) => Some(n),
            _ => None,
        })
    }

    pub fn notify(&self, kind: u16) -> Option<&Notify> {
        self.notifies().find(|n| n.kind == kind)
    }

    /// Fails on the first error notification.
    pub fn check_errors(&self) -> anyhow::Result<()> {
        if let Some(n) = self.notifies().find(|n| n.is_error()) {
            bail!("gateway returned {}", notify::describe(n.kind));
        }
        Ok(())
    }

    pub fn sa(&self) -> Option<&[Proposal]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Sa(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    pub fn ke(&self) -> Option<(u16, &[u8])> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Ke { group, data } => Some((*group, data.as_slice())),
            _ => None,
        })
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Nonce(n) => Some(n.as_slice()),
            _ => None,
        })
    }

    pub fn id_r(&self) -> Option<&Identity> {
        self.payloads.iter().find_map(|p| match p {
            Payload::IdR(id) => Some(id),
            _ => None,
        })
    }

    pub fn auth(&self) -> Option<(u8, &[u8])> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Auth { method, data } => Some((*method, data.as_slice())),
            _ => None,
        })
    }

    /// X.509 certificates, end entity first.
    pub fn certificates(&self) -> Vec<Vec<u8>> {
        self.payloads
            .iter()
            .filter_map(|p| match p {
                Payload::Cert { encoding: crate::cert::X509_SIGNATURE, data } => Some(data.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn eap(&self) -> Option<&[u8]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Eap(d) => Some(d.as_slice()),
            _ => None,
        })
    }

    pub fn cp_attrs(&self) -> &[CpAttr] {
        self.payloads
            .iter()
            .find_map(|p| match p {
                Payload::Cp { attrs, .. } => Some(attrs.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    pub fn ts_i(&self) -> &[TrafficSelector] {
        self.payloads
            .iter()
            .find_map(|p| match p {
                Payload::TsI(t) => Some(t.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    pub fn ts_r(&self) -> &[TrafficSelector] {
        self.payloads
            .iter()
            .find_map(|p| match p {
                Payload::TsR(t) => Some(t.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EncrAlg, IntegAlg};
    use crate::ikev2::consts::exchange;

    #[test]
    fn encrypted_roundtrip() {
        let ciphers = [
            Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &[1u8; 36], &[]).unwrap(),
            Cipher::new(EncrAlg::AesCbc { key_bits: 128 }, Some(IntegAlg::HmacSha256Trunc128), &[1u8; 16], &[2u8; 32])
                .unwrap(),
        ];
        let payloads = vec![Payload::Nonce(vec![7; 17]), Payload::Notify(Notify::new(notify::INITIAL_CONTACT, vec![]))];
        for c in &ciphers {
            let iv = c.make_iv(3);
            let msg = build_encrypted(1, 2, exchange::IKE_AUTH, flags::INITIATOR, 1, &payloads, c, &iv);
            let parsed = parse(&msg, Some(c)).unwrap();
            assert_eq!(parsed.payloads, payloads);
            assert_eq!(parsed.header.msg_id, 1);
            let mut bad = msg.clone();
            bad[20] ^= 1; // message ID is authenticated
            assert!(parse(&bad, Some(c)).is_err());
            assert!(parse(&msg, None).is_err());
        }
    }

    #[test]
    fn plain_roundtrip() {
        let payloads = vec![Payload::Nonce(vec![1; 32])];
        let msg = build_plain(9, 0, exchange::IKE_SA_INIT, flags::INITIATOR, 0, &payloads);
        let parsed = parse(&msg, None).unwrap();
        assert_eq!(parsed.header.spi_i, 9);
        assert_eq!(parsed.payloads, payloads);
        assert!(!parsed.header.is_response());
    }
}
