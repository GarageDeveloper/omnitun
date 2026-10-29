//! ISAKMP header and payloads (RFC 2408 §3, RFC 2407 §4.6, RFC 3947,
//! draft-dukes-ike-mode-cfg-02).

use anyhow::{Context, bail, ensure};

use super::consts::{cfg, payload as pt};

pub const HEADER_LEN: usize = 28;
const VERSION: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub cky_i: u64,
    pub cky_r: u64,
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

impl Header {
    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        ensure!(buf.len() >= HEADER_LEN, "ISAKMP message too short");
        ensure!(buf[17] >> 4 == 1, "not an IKEv1 message (version {:#x})", buf[17]);
        Ok(Self {
            cky_i: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            cky_r: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
            next: buf[16],
            exchange: buf[18],
            flags: buf[19],
            msg_id: u32::from_be_bytes(buf[20..24].try_into().unwrap()),
            length: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.cky_i.to_be_bytes());
        out.extend_from_slice(&self.cky_r.to_be_bytes());
        out.extend_from_slice(&[self.next, VERSION, self.exchange, self.flags]);
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }
}

/// SA attribute (RFC 2408 §3.3): basic (TV) when the value fits 16 bits,
/// variable (TLV) otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaAttr {
    pub kind: u16,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub num: u8,
    pub id: u8,
    pub attrs: Vec<SaAttr>,
}

impl Transform {
    pub fn attr(&self, kind: u16) -> Option<u64> {
        self.attrs.iter().find(|a| a.kind == kind).map(|a| a.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgValue {
    Basic(u16),
    Var(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgAttr {
    pub kind: u16,
    pub value: CfgValue,
}

impl CfgAttr {
    pub fn var(kind: u16, value: impl Into<Vec<u8>>) -> Self {
        Self { kind, value: CfgValue::Var(value.into()) }
    }

    pub fn empty(kind: u16) -> Self {
        if cfg::is_basic(kind) { Self { kind, value: CfgValue::Basic(0) } } else { Self::var(kind, Vec::new()) }
    }

    pub fn bytes(&self) -> &[u8] {
        match &self.value {
            CfgValue::Var(v) => v,
            CfgValue::Basic(_) => &[],
        }
    }

    pub fn number(&self) -> Option<u64> {
        match &self.value {
            CfgValue::Basic(v) => Some(u64::from(*v)),
            CfgValue::Var(v) if !v.is_empty() && v.len() <= 8 => {
                Some(v.iter().fold(0, |acc, b| acc << 8 | u64::from(*b)))
            }
            CfgValue::Var(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id {
    pub id_type: u8,
    pub protocol: u8,
    pub port: u16,
    pub data: Vec<u8>,
}

impl Id {
    /// Payload body, as covered by HASH_I/HASH_R (RFC 2409 §5).
    pub fn body(&self) -> Vec<u8> {
        let mut out = vec![self.id_type, self.protocol];
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub kind: u16,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn is_error(&self) -> bool {
        self.kind < super::consts::notify::FIRST_STATUS
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(Vec<Proposal>),
    Ke(Vec<u8>),
    Id(Id),
    Hash(Vec<u8>),
    Nonce(Vec<u8>),
    Notify(Notify),
    Delete {
        protocol: u8,
        spi_size: u8,
        spis: Vec<Vec<u8>>,
    },
    VendorId(Vec<u8>),
    Attr {
        cfg_type: u8,
        identifier: u16,
        attrs: Vec<CfgAttr>,
    },
    /// NAT-D, with its payload type (RFC 3947 or draft numbering).
    NatD {
        kind: u8,
        hash: Vec<u8>,
    },
    Unknown {
        kind: u8,
        body: Vec<u8>,
    },
}

impl Payload {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Sa(_) => pt::SA,
            Self::Ke(_) => pt::KE,
            Self::Id(_) => pt::ID,
            Self::Hash(_) => pt::HASH,
            Self::Nonce(_) => pt::NONCE,
            Self::Notify(_) => pt::NOTIFY,
            Self::Delete { .. } => pt::DELETE,
            Self::VendorId(_) => pt::VENDOR_ID,
            Self::Attr { .. } => pt::ATTRIBUTE,
            Self::NatD { kind, .. } | Self::Unknown { kind, .. } => *kind,
        }
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Sa(proposals) => encode_sa(proposals, out),
            Self::Ke(d) | Self::Hash(d) | Self::Nonce(d) | Self::VendorId(d) => out.extend_from_slice(d),
            Self::NatD { hash, .. } => out.extend_from_slice(hash),
            Self::Id(id) => out.extend_from_slice(&id.body()),
            Self::Notify(n) => {
                out.extend_from_slice(&super::consts::DOI_IPSEC.to_be_bytes());
                out.extend_from_slice(&[n.protocol, n.spi.len() as u8]);
                out.extend_from_slice(&n.kind.to_be_bytes());
                out.extend_from_slice(&n.spi);
                out.extend_from_slice(&n.data);
            }
            Self::Delete { protocol, spi_size, spis } => {
                out.extend_from_slice(&super::consts::DOI_IPSEC.to_be_bytes());
                out.extend_from_slice(&[*protocol, *spi_size]);
                out.extend_from_slice(&(spis.len() as u16).to_be_bytes());
                for spi in spis {
                    out.extend_from_slice(spi);
                }
            }
            Self::Attr { cfg_type, identifier, attrs } => {
                out.extend_from_slice(&[*cfg_type, 0]);
                out.extend_from_slice(&identifier.to_be_bytes());
                for a in attrs {
                    match &a.value {
                        CfgValue::Basic(v) => {
                            out.extend_from_slice(&(0x8000 | a.kind).to_be_bytes());
                            out.extend_from_slice(&v.to_be_bytes());
                        }
                        CfgValue::Var(v) => {
                            out.extend_from_slice(&(a.kind & 0x7fff).to_be_bytes());
                            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                            out.extend_from_slice(v);
                        }
                    }
                }
            }
            Self::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    fn decode_body(kind: u8, body: &[u8]) -> anyhow::Result<Self> {
        Ok(match kind {
            pt::SA => Self::Sa(decode_sa(body)?),
            pt::KE => Self::Ke(body.to_vec()),
            pt::HASH => Self::Hash(body.to_vec()),
            pt::NONCE => Self::Nonce(body.to_vec()),
            pt::VENDOR_ID => Self::VendorId(body.to_vec()),
            pt::NAT_D | pt::NAT_D_DRAFT => Self::NatD { kind, hash: body.to_vec() },
            pt::ID => {
                ensure!(body.len() >= 4, "ID payload too short");
                Self::Id(Id { id_type: body[0], protocol: body[1], port: be16(body, 2), data: body[4..].to_vec() })
            }
            pt::NOTIFY => {
                ensure!(body.len() >= 8, "Notify payload too short");
                let spi_len = body[5] as usize;
                ensure!(body.len() >= 8 + spi_len, "Notify SPI truncated");
                Self::Notify(Notify {
                    protocol: body[4],
                    spi: body[8..8 + spi_len].to_vec(),
                    kind: be16(body, 6),
                    data: body[8 + spi_len..].to_vec(),
                })
            }
            pt::DELETE => {
                ensure!(body.len() >= 8, "Delete payload too short");
                let spi_size = body[5] as usize;
                let count = be16(body, 6) as usize;
                ensure!(body.len() >= 8 + spi_size * count, "Delete SPIs truncated");
                let spis = (0..count).map(|i| body[8 + i * spi_size..8 + (i + 1) * spi_size].to_vec()).collect();
                Self::Delete { protocol: body[4], spi_size: spi_size as u8, spis }
            }
            pt::ATTRIBUTE => {
                ensure!(body.len() >= 4, "Attribute payload too short");
                Self::Attr { cfg_type: body[0], identifier: be16(body, 2), attrs: decode_cfg_attrs(&body[4..])? }
            }
            _ => Self::Unknown { kind, body: body.to_vec() },
        })
    }
}

fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn set_len(out: &mut [u8], start: usize) {
    let len = (out.len() - start) as u16;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

fn encode_sa(proposals: &[Proposal], out: &mut Vec<u8>) {
    out.extend_from_slice(&super::consts::DOI_IPSEC.to_be_bytes());
    out.extend_from_slice(&super::consts::SIT_IDENTITY_ONLY.to_be_bytes());
    for (i, p) in proposals.iter().enumerate() {
        let start = out.len();
        let more = if i + 1 < proposals.len() { pt::PROPOSAL } else { 0 };
        out.extend_from_slice(&[more, 0, 0, 0, p.num, p.protocol, p.spi.len() as u8, p.transforms.len() as u8]);
        out.extend_from_slice(&p.spi);
        for (j, t) in p.transforms.iter().enumerate() {
            let tstart = out.len();
            let more = if j + 1 < p.transforms.len() { pt::TRANSFORM } else { 0 };
            out.extend_from_slice(&[more, 0, 0, 0, t.num, t.id, 0, 0]);
            for a in &t.attrs {
                if a.value <= 0xffff {
                    out.extend_from_slice(&(0x8000 | a.kind).to_be_bytes());
                    out.extend_from_slice(&(a.value as u16).to_be_bytes());
                } else {
                    let bytes = if a.value <= u64::from(u32::MAX) {
                        (a.value as u32).to_be_bytes().to_vec()
                    } else {
                        a.value.to_be_bytes().to_vec()
                    };
                    out.extend_from_slice(&(a.kind & 0x7fff).to_be_bytes());
                    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(&bytes);
                }
            }
            set_len(out, tstart);
        }
        set_len(out, start);
    }
}

fn decode_sa(body: &[u8]) -> anyhow::Result<Vec<Proposal>> {
    ensure!(body.len() >= 8, "SA payload too short");
    let mut rest = &body[8..];
    let mut proposals = Vec::new();
    while !rest.is_empty() {
        ensure!(rest.len() >= 8, "proposal truncated");
        let len = be16(rest, 2) as usize;
        ensure!(len >= 8 && len <= rest.len(), "bad proposal length");
        let p = &rest[..len];
        let spi_len = p[6] as usize;
        ensure!(p.len() >= 8 + spi_len, "proposal SPI truncated");
        let mut trest = &p[8 + spi_len..];
        let mut transforms = Vec::new();
        for _ in 0..p[7] {
            ensure!(trest.len() >= 8, "transform truncated");
            let tlen = be16(trest, 2) as usize;
            ensure!(tlen >= 8 && tlen <= trest.len(), "bad transform length");
            transforms.push(Transform { num: trest[4], id: trest[5], attrs: decode_sa_attrs(&trest[8..tlen])? });
            trest = &trest[tlen..];
        }
        proposals.push(Proposal { num: p[4], protocol: p[5], spi: p[8..8 + spi_len].to_vec(), transforms });
        let last = rest[0] == 0;
        rest = &rest[len..];
        if last {
            break;
        }
    }
    Ok(proposals)
}

/// Decodes SA attributes (also used for RESPONDER-LIFETIME data).
pub fn decode_sa_attrs(mut buf: &[u8]) -> anyhow::Result<Vec<SaAttr>> {
    let mut attrs = Vec::new();
    while !buf.is_empty() {
        ensure!(buf.len() >= 4, "attribute truncated");
        let ty = be16(buf, 0);
        if ty & 0x8000 != 0 {
            attrs.push(SaAttr { kind: ty & 0x7fff, value: u64::from(be16(buf, 2)) });
            buf = &buf[4..];
        } else {
            let len = be16(buf, 2) as usize;
            ensure!(buf.len() >= 4 + len, "attribute value truncated");
            ensure!(len <= 8, "attribute value too long for a number");
            let value = buf[4..4 + len].iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b));
            attrs.push(SaAttr { kind: ty, value });
            buf = &buf[4 + len..];
        }
    }
    Ok(attrs)
}

fn decode_cfg_attrs(mut buf: &[u8]) -> anyhow::Result<Vec<CfgAttr>> {
    let mut attrs = Vec::new();
    while !buf.is_empty() {
        ensure!(buf.len() >= 4, "attribute truncated");
        let ty = be16(buf, 0);
        if ty & 0x8000 != 0 {
            attrs.push(CfgAttr { kind: ty & 0x7fff, value: CfgValue::Basic(be16(buf, 2)) });
            buf = &buf[4..];
        } else {
            let len = be16(buf, 2) as usize;
            ensure!(buf.len() >= 4 + len, "attribute value truncated");
            attrs.push(CfgAttr::var(ty, &buf[4..4 + len]));
            buf = &buf[4 + len..];
        }
    }
    Ok(attrs)
}

/// Encodes a payload chain; returns the first payload type and the bytes.
pub fn encode_chain(payloads: &[Payload]) -> (u8, Vec<u8>) {
    // Room for the largest ISAKMP message: the chain may carry XAuth
    // credentials, and a reallocation would leave a copy behind.
    let mut out = Vec::with_capacity(usize::from(u16::MAX));
    for (i, p) in payloads.iter().enumerate() {
        let start = out.len();
        let next = payloads.get(i + 1).map_or(pt::NONE, Payload::kind);
        out.extend_from_slice(&[next, 0, 0, 0]);
        p.encode_body(&mut out);
        set_len(&mut out, start);
    }
    (payloads.first().map_or(pt::NONE, Payload::kind), out)
}

/// A decoded payload with its position in the chain (for HASH coverage).
#[derive(Debug, Clone)]
pub struct Decoded {
    pub payload: Payload,
    pub start: usize,
    pub end: usize,
}

/// Decodes a payload chain; trailing bytes (encryption padding) are ignored.
pub fn decode_chain(first: u8, data: &[u8]) -> anyhow::Result<Vec<Decoded>> {
    let mut out = Vec::new();
    let mut kind = first;
    let mut offset = 0;
    while kind != pt::NONE {
        ensure!(out.len() < 64, "too many payloads");
        let rest = &data[offset..];
        ensure!(rest.len() >= 4, "payload header truncated");
        let len = be16(rest, 2) as usize;
        ensure!(len >= 4 && len <= rest.len(), "bad payload length");
        if matches!(kind, pt::PROPOSAL | pt::TRANSFORM) {
            bail!("proposal/transform outside an SA payload");
        }
        let payload = Payload::decode_body(kind, &rest[4..len]).with_context(|| format!("payload type {kind}"))?;
        out.push(Decoded { payload, start: offset, end: offset + len });
        offset += len;
        kind = rest[0];
    }
    Ok(out)
}

/// Builds an unencrypted message.
pub fn build_plain(cky_i: u64, cky_r: u64, exchange: u8, msg_id: u32, payloads: &[Payload]) -> Vec<u8> {
    let (next, body) = encode_chain(payloads);
    let header = Header { cky_i, cky_r, next, exchange, flags: 0, msg_id, length: (HEADER_LEN + body.len()) as u32 };
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    header.encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// A parsed message. `body` is the (decrypted) payload area; `payloads`
/// index into it.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub body: Vec<u8>,
    pub payloads: Vec<Decoded>,
}

impl Message {
    pub fn parse_plain(raw: &[u8]) -> anyhow::Result<Self> {
        let header = Header::decode(raw)?;
        let len = header.length as usize;
        ensure!(len >= HEADER_LEN && len <= raw.len(), "bad ISAKMP message length");
        ensure!(header.flags & super::consts::flags::ENCRYPTION == 0, "message is encrypted");
        let body = raw[HEADER_LEN..len].to_vec();
        let payloads = decode_chain(header.next, &body)?;
        Ok(Self { header, body, payloads })
    }

    pub fn iter(&self) -> impl Iterator<Item = &Payload> {
        self.payloads.iter().map(|d| &d.payload)
    }

    pub fn sa(&self) -> Option<&[Proposal]> {
        self.iter().find_map(|p| match p {
            Payload::Sa(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    /// Raw body of the first SA payload (SAi_b in HASH_I/HASH_R).
    pub fn sa_body(&self) -> Option<&[u8]> {
        self.payloads.iter().find(|d| matches!(d.payload, Payload::Sa(_))).map(|d| &self.body[d.start + 4..d.end])
    }

    pub fn ke(&self) -> Option<&[u8]> {
        self.iter().find_map(|p| match p {
            Payload::Ke(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.iter().find_map(|p| match p {
            Payload::Nonce(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        self.iter().find_map(|p| match p {
            Payload::Hash(v) => Some(v.as_slice()),
            _ => None,
        })
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.iter().filter_map(|p| match p {
            Payload::Id(id) => Some(id),
            _ => None,
        })
    }

    pub fn notifies(&self) -> impl Iterator<Item = &Notify> {
        self.iter().filter_map(|p| match p {
            Payload::Notify(n) => Some(n),
            _ => None,
        })
    }

    pub fn has_vendor_id(&self, vid: &[u8]) -> bool {
        self.iter().any(|p| matches!(p, Payload::VendorId(v) if v.starts_with(vid)))
    }

    #[cfg(test)]
    pub fn nat_d(&self) -> Vec<(u8, &[u8])> {
        self.iter()
            .filter_map(|p| match p {
                Payload::NatD { kind, hash } => Some((*kind, hash.as_slice())),
                _ => None,
            })
            .collect()
    }

    /// Bytes covered by a phase 2 HASH: everything after a leading HASH
    /// payload, up to the end of the last payload.
    pub fn after_hash(&self) -> Option<&[u8]> {
        let first = self.payloads.first()?;
        if !matches!(first.payload, Payload::Hash(_)) {
            return None;
        }
        let end = self.payloads.last().map_or(first.end, |d| d.end);
        Some(&self.body[first.end..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev1::consts::{exchange, ike_attr, protocol};

    pub(crate) fn sample_payloads() -> Vec<Payload> {
        vec![
            Payload::Sa(vec![Proposal {
                num: 1,
                protocol: protocol::ISAKMP,
                spi: vec![],
                transforms: vec![
                    Transform {
                        num: 1,
                        id: ike_attr::TRANSFORM_KEY_IKE,
                        attrs: vec![
                            SaAttr { kind: ike_attr::ENCRYPTION, value: 7 },
                            SaAttr { kind: ike_attr::LIFE_DURATION, value: 86400 },
                            SaAttr { kind: ike_attr::AUTH_METHOD, value: 65001 },
                        ],
                    },
                    Transform { num: 2, id: 1, attrs: vec![] },
                ],
            }]),
            Payload::Ke(vec![1; 192]),
            Payload::Nonce(vec![2; 16]),
            Payload::Id(Id { id_type: 1, protocol: 17, port: 500, data: vec![10, 0, 0, 1] }),
            Payload::Hash(vec![3; 20]),
            Payload::Notify(Notify { protocol: 1, spi: vec![4; 16], kind: 36136, data: vec![0, 0, 0, 1] }),
            Payload::Delete { protocol: 3, spi_size: 4, spis: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]] },
            Payload::VendorId(crate::ikev1::consts::vid::DPD.to_vec()),
            Payload::Attr {
                cfg_type: cfg::REQUEST,
                identifier: 7,
                attrs: vec![
                    CfgAttr { kind: cfg::XAUTH_TYPE, value: CfgValue::Basic(0) },
                    CfgAttr::var(cfg::XAUTH_USER_NAME, b"alice".to_vec()),
                    CfgAttr::empty(cfg::INTERNAL_IP4_ADDRESS),
                ],
            },
            Payload::NatD { kind: pt::NAT_D, hash: vec![5; 20] },
            Payload::NatD { kind: pt::NAT_D_DRAFT, hash: vec![6; 20] },
            Payload::Unknown { kind: 200, body: vec![9, 9] },
        ]
    }

    #[test]
    fn chain_roundtrip() {
        let payloads = sample_payloads();
        let (first, bytes) = encode_chain(&payloads);
        let decoded = decode_chain(first, &bytes).unwrap();
        assert_eq!(decoded.into_iter().map(|d| d.payload).collect::<Vec<_>>(), payloads);
        // Trailing padding is ignored.
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0; 11]);
        assert_eq!(decode_chain(first, &padded).unwrap().len(), payloads.len());
    }

    #[test]
    fn plain_message_and_hash_coverage() {
        let payloads = vec![Payload::Hash(vec![1; 20]), Payload::Nonce(vec![2; 16])];
        let raw = build_plain(1, 2, exchange::INFORMATIONAL, 9, &payloads);
        let msg = Message::parse_plain(&raw).unwrap();
        assert_eq!(msg.header.msg_id, 9);
        let (_, nonce_bytes) = encode_chain(&payloads[1..]);
        assert_eq!(msg.after_hash().unwrap(), nonce_bytes.as_slice());
        assert!(Message::parse_plain(&raw[..30]).is_err());
    }

    #[test]
    fn large_attribute_values_use_tlv() {
        let sa = Payload::Sa(vec![Proposal {
            num: 1,
            protocol: 1,
            spi: vec![],
            transforms: vec![Transform { num: 1, id: 1, attrs: vec![SaAttr { kind: 12, value: 86400 }] }],
        }]);
        let (_, bytes) = encode_chain(std::slice::from_ref(&sa));
        // Generic(4) + DOI/SIT(8) + proposal(8) + transform(8) + TLV(4+4).
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[28..32], &[0, 12, 0, 4]);
    }
}
