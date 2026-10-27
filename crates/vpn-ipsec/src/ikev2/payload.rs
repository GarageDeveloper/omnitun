//! IKEv2 payload encoding (RFC 7296 §3.2–3.16).

use std::net::Ipv4Addr;

use anyhow::{Context, bail, ensure};

use super::consts::{id_type, payload as pt, transform, ts_type};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub kind: u8,
    pub id: u16,
    pub key_len: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    pub fn transforms_of(&self, kind: u8) -> impl Iterator<Item = &Transform> {
        self.transforms.iter().filter(move |t| t.kind == kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id_type: u8,
    pub data: Vec<u8>,
}

impl Identity {
    /// Parses a profile identity. An optional `ip:`, `fqdn:`, `email:` or
    /// `keyid:` prefix forces the type; otherwise it is inferred.
    pub fn parse(s: &str) -> Self {
        let (forced, value) = match s.split_once(':') {
            Some(("ip", v)) => (Some(id_type::IPV4_ADDR), v),
            Some(("fqdn", v)) => (Some(id_type::FQDN), v),
            Some(("email", v)) => (Some(id_type::RFC822_ADDR), v),
            Some(("keyid", v)) => (Some(id_type::KEY_ID), v),
            _ => (None, s),
        };
        let ip = value.parse::<Ipv4Addr>().ok();
        let id_type = forced.unwrap_or(if ip.is_some() {
            id_type::IPV4_ADDR
        } else if value.contains('@') {
            id_type::RFC822_ADDR
        } else if value.contains('.') {
            id_type::FQDN
        } else {
            id_type::KEY_ID
        });
        let data = match (id_type, ip) {
            (id_type::IPV4_ADDR, Some(ip)) => ip.octets().to_vec(),
            _ => value.as_bytes().to_vec(),
        };
        Self { id_type, data }
    }

    /// For messages: an address, a name, or the type of a binary identity.
    pub fn display(&self) -> String {
        match (self.id_type, <[u8; 4]>::try_from(self.data.as_slice())) {
            (id_type::IPV4_ADDR, Ok(octets)) => Ipv4Addr::from(octets).to_string(),
            (id_type::FQDN | id_type::RFC822_ADDR | id_type::KEY_ID, _) => {
                // Gateway-supplied: no terminal escapes.
                String::from_utf8_lossy(&self.data).chars().filter(|c| !c.is_control()).collect()
            }
            (id_type::DER_ASN1_DN, _) => "(distinguished name)".into(),
            (other, _) => format!("(identity of type {other})"),
        }
    }

    /// Payload body as covered by the AUTH computation (RFC 7296 §2.15).
    pub fn body(&self) -> Vec<u8> {
        let mut out = vec![self.id_type, 0, 0, 0];
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
    pub fn new(kind: u16, data: Vec<u8>) -> Self {
        Self { protocol: 0, spi: Vec::new(), kind, data }
    }

    pub fn is_error(&self) -> bool {
        self.kind < super::consts::notify::FIRST_STATUS
    }
}

/// IPv4 address range selector (type 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ip_proto: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl TrafficSelector {
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.start <= addr && addr <= self.end
    }

    /// Intersection of two selectors, if not empty (protocol 0 = any).
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let ip_proto = match (self.ip_proto, other.ip_proto) {
            (0, p) | (p, 0) => p,
            (a, b) if a == b => a,
            _ => return None,
        };
        let sel = Self {
            ip_proto,
            start_port: self.start_port.max(other.start_port),
            end_port: self.end_port.min(other.end_port),
            start: self.start.max(other.start),
            end: self.end.min(other.end),
        };
        (sel.start <= sel.end && sel.start_port <= sel.end_port).then_some(sel)
    }

    /// Pairwise intersections of two selector lists (responder narrowing,
    /// RFC 7296 §2.9).
    pub fn narrow(requested: &[Self], allowed: &[Self]) -> Vec<Self> {
        let mut out: Vec<Self> = requested.iter().flat_map(|r| allowed.iter().filter_map(|a| r.intersect(a))).collect();
        out.dedup();
        out
    }

    pub fn any() -> Self {
        Self { ip_proto: 0, start_port: 0, end_port: 65535, start: Ipv4Addr::UNSPECIFIED, end: Ipv4Addr::BROADCAST }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpAttr {
    pub kind: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(Vec<Proposal>),
    Ke {
        group: u16,
        data: Vec<u8>,
    },
    IdI(Identity),
    IdR(Identity),
    Auth {
        method: u8,
        data: Vec<u8>,
    },
    Nonce(Vec<u8>),
    Notify(Notify),
    Delete {
        protocol: u8,
        spi_size: u8,
        spis: Vec<Vec<u8>>,
    },
    TsI(Vec<TrafficSelector>),
    TsR(Vec<TrafficSelector>),
    Cp {
        cfg_type: u8,
        attrs: Vec<CpAttr>,
    },
    Eap(Vec<u8>),
    Cert {
        encoding: u8,
        data: Vec<u8>,
    },
    /// Encoding and the CAs' key hashes.
    CertReq(Vec<u8>),
    /// Encrypted payload; only produced by the decoder. `offset` is the
    /// position of its generic header within the decoded chain.
    Sk {
        inner_first: u8,
        offset: usize,
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
            Self::Ke { .. } => pt::KE,
            Self::IdI(_) => pt::IDI,
            Self::IdR(_) => pt::IDR,
            Self::Auth { .. } => pt::AUTH,
            Self::Nonce(_) => pt::NONCE,
            Self::Notify(_) => pt::NOTIFY,
            Self::Delete { .. } => pt::DELETE,
            Self::TsI(_) => pt::TSI,
            Self::TsR(_) => pt::TSR,
            Self::Cp { .. } => pt::CP,
            Self::Eap(_) => pt::EAP,
            Self::Cert { .. } => pt::CERT,
            Self::CertReq(_) => pt::CERTREQ,
            Self::Sk { .. } => pt::SK,
            Self::Unknown { kind, .. } => *kind,
        }
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Sa(proposals) => {
                for (i, p) in proposals.iter().enumerate() {
                    let start = out.len();
                    let more = if i + 1 < proposals.len() { 2 } else { 0 };
                    out.extend_from_slice(&[more, 0, 0, 0, p.num, p.protocol, p.spi.len() as u8]);
                    out.push(p.transforms.len() as u8);
                    out.extend_from_slice(&p.spi);
                    for (j, t) in p.transforms.iter().enumerate() {
                        let tstart = out.len();
                        let more = if j + 1 < p.transforms.len() { 3 } else { 0 };
                        out.extend_from_slice(&[more, 0, 0, 0, t.kind, 0]);
                        out.extend_from_slice(&t.id.to_be_bytes());
                        if let Some(bits) = t.key_len {
                            out.extend_from_slice(&(0x8000 | transform::ATTR_KEY_LENGTH).to_be_bytes());
                            out.extend_from_slice(&bits.to_be_bytes());
                        }
                        set_len(out, tstart);
                    }
                    set_len(out, start);
                }
            }
            Self::Ke { group, data } => {
                out.extend_from_slice(&group.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(data);
            }
            Self::IdI(id) | Self::IdR(id) => out.extend_from_slice(&id.body()),
            Self::Auth { method, data } => {
                out.extend_from_slice(&[*method, 0, 0, 0]);
                out.extend_from_slice(data);
            }
            Self::Nonce(data) | Self::Eap(data) | Self::CertReq(data) => out.extend_from_slice(data),
            Self::Cert { encoding, data } => {
                out.push(*encoding);
                out.extend_from_slice(data);
            }
            Self::Notify(n) => {
                out.extend_from_slice(&[n.protocol, n.spi.len() as u8]);
                out.extend_from_slice(&n.kind.to_be_bytes());
                out.extend_from_slice(&n.spi);
                out.extend_from_slice(&n.data);
            }
            Self::Delete { protocol, spi_size, spis } => {
                out.extend_from_slice(&[*protocol, *spi_size]);
                out.extend_from_slice(&(spis.len() as u16).to_be_bytes());
                for spi in spis {
                    out.extend_from_slice(spi);
                }
            }
            Self::TsI(ts) | Self::TsR(ts) => {
                out.extend_from_slice(&[ts.len() as u8, 0, 0, 0]);
                for t in ts {
                    out.extend_from_slice(&[ts_type::IPV4_ADDR_RANGE, t.ip_proto, 0, 16]);
                    out.extend_from_slice(&t.start_port.to_be_bytes());
                    out.extend_from_slice(&t.end_port.to_be_bytes());
                    out.extend_from_slice(&t.start.octets());
                    out.extend_from_slice(&t.end.octets());
                }
            }
            Self::Cp { cfg_type, attrs } => {
                out.extend_from_slice(&[*cfg_type, 0, 0, 0]);
                for a in attrs {
                    out.extend_from_slice(&(a.kind & 0x7fff).to_be_bytes());
                    out.extend_from_slice(&(a.value.len() as u16).to_be_bytes());
                    out.extend_from_slice(&a.value);
                }
            }
            Self::Sk { .. } => unreachable!("SK payloads are built by message::build_encrypted"),
            Self::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    fn decode_body(kind: u8, body: &[u8]) -> anyhow::Result<Self> {
        Ok(match kind {
            pt::SA => Self::Sa(decode_proposals(body)?),
            pt::KE => {
                ensure!(body.len() >= 4, "KE payload too short");
                Self::Ke { group: be16(body, 0), data: body[4..].to_vec() }
            }
            pt::IDI | pt::IDR => {
                ensure!(body.len() >= 4, "ID payload too short");
                let id = Identity { id_type: body[0], data: body[4..].to_vec() };
                if kind == pt::IDI { Self::IdI(id) } else { Self::IdR(id) }
            }
            pt::AUTH => {
                ensure!(body.len() >= 4, "AUTH payload too short");
                Self::Auth { method: body[0], data: body[4..].to_vec() }
            }
            pt::NONCE => Self::Nonce(body.to_vec()),
            pt::EAP => Self::Eap(body.to_vec()),
            pt::CERT => {
                let (&encoding, data) = body.split_first().context("CERT payload too short")?;
                Self::Cert { encoding, data: data.to_vec() }
            }
            pt::CERTREQ => {
                ensure!(!body.is_empty(), "CERTREQ payload too short");
                Self::CertReq(body.to_vec())
            }
            pt::NOTIFY => {
                ensure!(body.len() >= 4, "Notify payload too short");
                let spi_len = body[1] as usize;
                ensure!(body.len() >= 4 + spi_len, "Notify SPI truncated");
                Self::Notify(Notify {
                    protocol: body[0],
                    spi: body[4..4 + spi_len].to_vec(),
                    kind: be16(body, 2),
                    data: body[4 + spi_len..].to_vec(),
                })
            }
            pt::DELETE => {
                ensure!(body.len() >= 4, "Delete payload too short");
                let spi_size = body[1] as usize;
                let count = be16(body, 2) as usize;
                ensure!(body.len() >= 4 + spi_size * count, "Delete SPIs truncated");
                let spis = (0..count).map(|i| body[4 + i * spi_size..4 + (i + 1) * spi_size].to_vec()).collect();
                Self::Delete { protocol: body[0], spi_size: spi_size as u8, spis }
            }
            pt::TSI | pt::TSR => {
                let ts = decode_selectors(body)?;
                if kind == pt::TSI { Self::TsI(ts) } else { Self::TsR(ts) }
            }
            pt::CP => {
                ensure!(body.len() >= 4, "CP payload too short");
                let mut attrs = Vec::new();
                let mut rest = &body[4..];
                while !rest.is_empty() {
                    ensure!(rest.len() >= 4, "CP attribute truncated");
                    let len = be16(rest, 2) as usize;
                    ensure!(rest.len() >= 4 + len, "CP attribute truncated");
                    attrs.push(CpAttr { kind: be16(rest, 0) & 0x7fff, value: rest[4..4 + len].to_vec() });
                    rest = &rest[4 + len..];
                }
                Self::Cp { cfg_type: body[0], attrs }
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

fn decode_proposals(mut body: &[u8]) -> anyhow::Result<Vec<Proposal>> {
    let mut proposals = Vec::new();
    while !body.is_empty() {
        ensure!(body.len() >= 8, "proposal truncated");
        let len = be16(body, 2) as usize;
        ensure!(len >= 8 && len <= body.len(), "bad proposal length");
        let p = &body[..len];
        let spi_len = p[6] as usize;
        let count = p[7] as usize;
        ensure!(p.len() >= 8 + spi_len, "proposal SPI truncated");
        let mut rest = &p[8 + spi_len..];
        let mut transforms = Vec::with_capacity(count);
        for _ in 0..count {
            ensure!(rest.len() >= 8, "transform truncated");
            let tlen = be16(rest, 2) as usize;
            ensure!(tlen >= 8 && tlen <= rest.len(), "bad transform length");
            let mut key_len = None;
            let mut attrs = &rest[8..tlen];
            while attrs.len() >= 4 {
                let ty = be16(attrs, 0);
                if ty & 0x8000 != 0 {
                    if ty & 0x7fff == transform::ATTR_KEY_LENGTH {
                        key_len = Some(be16(attrs, 2));
                    }
                    attrs = &attrs[4..];
                } else {
                    let alen = be16(attrs, 2) as usize;
                    ensure!(attrs.len() >= 4 + alen, "transform attribute truncated");
                    attrs = &attrs[4 + alen..];
                }
            }
            transforms.push(Transform { kind: rest[4], id: be16(rest, 6), key_len });
            rest = &rest[tlen..];
        }
        proposals.push(Proposal { num: p[4], protocol: p[5], spi: p[8..8 + spi_len].to_vec(), transforms });
        let last = body[0] == 0;
        body = &body[len..];
        if last {
            break;
        }
    }
    Ok(proposals)
}

fn decode_selectors(body: &[u8]) -> anyhow::Result<Vec<TrafficSelector>> {
    ensure!(body.len() >= 4, "TS payload too short");
    let count = body[0] as usize;
    let mut rest = &body[4..];
    let mut out = Vec::new();
    for _ in 0..count {
        ensure!(rest.len() >= 4, "selector truncated");
        let len = be16(rest, 2) as usize;
        ensure!(len >= 8 && len <= rest.len(), "bad selector length");
        if rest[0] == ts_type::IPV4_ADDR_RANGE {
            ensure!(len == 16, "bad IPv4 selector length");
            let addr = |at: usize| Ipv4Addr::new(rest[at], rest[at + 1], rest[at + 2], rest[at + 3]);
            out.push(TrafficSelector {
                ip_proto: rest[1],
                start_port: be16(rest, 4),
                end_port: be16(rest, 6),
                start: addr(8),
                end: addr(12),
            });
        }
        // IPv6 selectors are skipped: the tunnel carries IPv4 only.
        rest = &rest[len..];
    }
    Ok(out)
}

/// Encodes a payload chain; returns the first payload type and the bytes.
pub fn encode_chain(payloads: &[Payload]) -> (u8, Vec<u8>) {
    let mut out = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let start = out.len();
        let next = payloads.get(i + 1).map_or(pt::NONE, Payload::kind);
        out.extend_from_slice(&[next, 0, 0, 0]);
        p.encode_body(&mut out);
        set_len(&mut out, start);
    }
    (payloads.first().map_or(pt::NONE, Payload::kind), out)
}

/// Decodes a payload chain. An SK payload ends the chain (it must be last).
pub fn decode_chain(first: u8, data: &[u8]) -> anyhow::Result<Vec<Payload>> {
    let mut out = Vec::new();
    let mut kind = first;
    let mut offset = 0;
    while kind != pt::NONE {
        let rest = &data[offset..];
        ensure!(rest.len() >= 4, "payload header truncated");
        let len = be16(rest, 2) as usize;
        ensure!(len >= 4 && len <= rest.len(), "bad payload length");
        let next = rest[0];
        let critical = rest[1] & 0x80 != 0;
        if kind == pt::SK {
            out.push(Payload::Sk { inner_first: next, offset });
            return Ok(out);
        }
        let payload = Payload::decode_body(kind, &rest[4..len]).with_context(|| format!("payload type {kind}"))?;
        if critical && matches!(payload, Payload::Unknown { .. }) {
            bail!("unsupported critical payload type {kind}");
        }
        out.push(payload);
        offset += len;
        kind = next;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::consts::{cfg, notify, protocol};

    #[test]
    fn chain_roundtrip() {
        let payloads = vec![
            Payload::Sa(vec![
                Proposal {
                    num: 1,
                    protocol: protocol::IKE,
                    spi: vec![],
                    transforms: vec![
                        Transform { kind: transform::ENCR, id: 20, key_len: Some(256) },
                        Transform { kind: transform::PRF, id: 5, key_len: None },
                        Transform { kind: transform::DH, id: 19, key_len: None },
                    ],
                },
                Proposal {
                    num: 2,
                    protocol: protocol::ESP,
                    spi: vec![1, 2, 3, 4],
                    transforms: vec![Transform { kind: transform::ESN, id: 0, key_len: None }],
                },
            ]),
            Payload::Ke { group: 19, data: vec![9; 64] },
            Payload::Nonce(vec![1; 32]),
            Payload::Notify(Notify::new(notify::COOKIE, vec![5; 8])),
            Payload::IdI(Identity::parse("vpn@example.com")),
            Payload::IdR(Identity::parse("203.0.113.1")),
            Payload::Auth { method: 2, data: vec![3; 32] },
            Payload::Delete { protocol: protocol::ESP, spi_size: 4, spis: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]] },
            Payload::TsI(vec![TrafficSelector::any()]),
            Payload::TsR(vec![
                TrafficSelector {
                    start: Ipv4Addr::new(10, 0, 0, 1),
                    end: Ipv4Addr::new(10, 0, 0, 1),
                    ..TrafficSelector::any()
                },
                TrafficSelector::any(),
            ]),
            Payload::Cp {
                cfg_type: cfg::REQUEST,
                attrs: vec![
                    CpAttr { kind: cfg::INTERNAL_IP4_ADDRESS, value: vec![] },
                    CpAttr { kind: cfg::INTERNAL_DNS_DOMAIN, value: b"corp.example".to_vec() },
                ],
            },
            Payload::Eap(vec![2, 1, 0, 5, 1]),
        ];
        let (first, bytes) = encode_chain(&payloads);
        assert_eq!(first, pt::SA);
        assert_eq!(decode_chain(first, &bytes).unwrap(), payloads);
    }

    #[test]
    fn selector_narrowing() {
        let net = |a: [u8; 4], b: [u8; 4]| TrafficSelector {
            start: Ipv4Addr::from(a),
            end: Ipv4Addr::from(b),
            ..TrafficSelector::any()
        };
        let allowed = [net([10, 0, 0, 0], [10, 255, 255, 255])];
        assert_eq!(TrafficSelector::narrow(&[TrafficSelector::any()], &allowed), allowed.to_vec());
        assert_eq!(
            TrafficSelector::narrow(&[net([10, 1, 0, 0], [11, 0, 0, 0])], &allowed),
            vec![net([10, 1, 0, 0], [10, 255, 255, 255])]
        );
        assert!(TrafficSelector::narrow(&[net([192, 168, 0, 0], [192, 168, 255, 255])], &allowed).is_empty());
        let tcp = TrafficSelector { ip_proto: 6, ..TrafficSelector::any() };
        let udp = TrafficSelector { ip_proto: 17, ..TrafficSelector::any() };
        assert!(tcp.intersect(&udp).is_none());
        assert_eq!(tcp.intersect(&TrafficSelector::any()), Some(tcp));
        assert!(allowed[0].contains(Ipv4Addr::new(10, 2, 3, 4)));
        assert!(!allowed[0].contains(Ipv4Addr::new(11, 0, 0, 0)));
    }

    #[test]
    fn identity_types() {
        assert_eq!(Identity::parse("10.1.2.3").id_type, id_type::IPV4_ADDR);
        assert_eq!(Identity::parse("10.1.2.3").data, vec![10, 1, 2, 3]);
        assert_eq!(Identity::parse("a@b.c").id_type, id_type::RFC822_ADDR);
        assert_eq!(Identity::parse("vpn.example.com").id_type, id_type::FQDN);
        assert_eq!(Identity::parse("roadwarrior").id_type, id_type::KEY_ID);
        assert_eq!(Identity::parse("keyid:a.b").id_type, id_type::KEY_ID);
        assert_eq!(Identity::parse("keyid:a.b").data, b"a.b");
    }

    #[test]
    fn rejects_truncated_and_critical_unknown() {
        assert!(decode_chain(pt::NONCE, &[0, 0, 0, 9, 1]).is_err());
        assert!(decode_chain(200, &[0, 0x80, 0, 4]).is_err());
        assert!(decode_chain(200, &[0, 0, 0, 4]).is_ok());
    }
}
