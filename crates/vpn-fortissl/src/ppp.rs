//! Minimal PPP (RFC 1661) with LCP and IPCP (RFC 1332, RFC 1877 DNS), as
//! needed inside the Fortinet TLS tunnel. Sans-IO: frames go in through
//! `input`, outgoing frames are queued and collected with `drain`.
//!
//! Frames carry the protocol field first; HDLC address/control bytes are
//! accepted on input but never sent.

use std::net::Ipv4Addr;

use anyhow::bail;
use bytes::Bytes;

pub const PROTO_IP: u16 = 0x0021;
pub const PROTO_LCP: u16 = 0xc021;
pub const PROTO_IPCP: u16 = 0x8021;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const CODE_REJ: u8 = 7;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;
const DISCARD_REQ: u8 = 11;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;
const LCP_PFC: u8 = 7;
const LCP_ACFC: u8 = 8;

const IPCP_ADDR: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

const MAX_CONF_RETRIES: u32 = 10;
const MAX_MISSED_ECHOES: u32 = 4;

/// Negotiation state of one control protocol (LCP or IPCP).
#[derive(Debug, Default)]
struct Cp {
    req_id: u8,
    /// Our Configure-Request was acknowledged.
    ours_acked: bool,
    /// We acknowledged the peer's Configure-Request.
    peer_acked: bool,
    retries: u32,
}

impl Cp {
    fn opened(&self) -> bool {
        self.ours_acked && self.peer_acked
    }
}

#[derive(Debug)]
pub struct Ppp {
    lcp: Cp,
    ipcp: Cp,
    next_id: u8,
    mru: u16,
    peer_mru: u16,
    magic: u32,
    send_mru: bool,
    send_magic: bool,
    address: Ipv4Addr,
    dns: [Option<Ipv4Addr>; 2],
    ask_dns: [bool; 2],
    peer_address: Option<Ipv4Addr>,
    missed_echoes: u32,
    out: Vec<Vec<u8>>,
}

impl Ppp {
    pub fn new(mru: u16) -> Self {
        Self {
            lcp: Cp::default(),
            ipcp: Cp::default(),
            next_id: 1,
            mru,
            peer_mru: 1500,
            magic: nonzero_random(),
            send_mru: true,
            send_magic: true,
            address: Ipv4Addr::UNSPECIFIED,
            dns: [None, None],
            ask_dns: [true, true],
            peer_address: None,
            missed_echoes: 0,
            out: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        self.lcp.req_id = self.fresh_id();
        self.send_lcp_request();
    }

    pub fn is_up(&self) -> bool {
        self.lcp.opened() && self.ipcp.opened()
    }

    /// Address assigned by IPCP, if any.
    pub fn address(&self) -> Option<Ipv4Addr> {
        Some(self.address).filter(|a| !a.is_unspecified())
    }

    /// IPCP peer address. FortiGate sends its public address here, so it is
    /// never used as the tun destination: that would route the TLS
    /// connection carrying the tunnel into the tunnel itself.
    #[cfg(test)]
    pub fn peer_address(&self) -> Option<Ipv4Addr> {
        self.peer_address
    }

    pub fn dns(&self) -> Vec<Ipv4Addr> {
        self.dns.iter().flatten().copied().filter(|a| !a.is_unspecified()).collect()
    }

    pub fn peer_mru(&self) -> u16 {
        self.peer_mru
    }

    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// Retransmits unacknowledged Configure-Requests. Call every few
    /// seconds while negotiating.
    pub fn retransmit(&mut self) -> anyhow::Result<()> {
        if !self.lcp.ours_acked {
            self.lcp.retries += 1;
            if self.lcp.retries > MAX_CONF_RETRIES {
                bail!("PPP: gateway does not answer LCP negotiation");
            }
            self.send_lcp_request();
        } else if self.lcp.opened() && !self.ipcp.ours_acked {
            self.ipcp.retries += 1;
            if self.ipcp.retries > MAX_CONF_RETRIES {
                bail!("PPP: gateway does not answer IPCP negotiation");
            }
            self.send_ipcp_request();
        }
        Ok(())
    }

    /// Sends an LCP Echo-Request; fails when too many went unanswered.
    pub fn keepalive(&mut self) -> anyhow::Result<()> {
        if self.missed_echoes >= MAX_MISSED_ECHOES {
            bail!("PPP: gateway stopped answering keepalives");
        }
        self.missed_echoes += 1;
        let id = self.fresh_id();
        let magic = self.magic.to_be_bytes();
        self.send(PROTO_LCP, ECHO_REQ, id, &magic);
        Ok(())
    }

    /// Asks the peer to close the link.
    pub fn terminate(&mut self) {
        let id = self.fresh_id();
        self.send(PROTO_LCP, TERM_REQ, id, b"");
    }

    /// Processes one frame from the gateway. Returns an IPv4 packet when
    /// the frame carries one.
    pub fn input(&mut self, frame: &[u8]) -> anyhow::Result<Option<Bytes>> {
        let frame = frame.strip_prefix(&[0xff, 0x03]).unwrap_or(frame);
        let (proto, info) = match frame {
            [b, rest @ ..] if b & 1 == 1 => (*b as u16, rest),
            [a, b, rest @ ..] => (u16::from_be_bytes([*a, *b]), rest),
            _ => return Ok(None),
        };
        match proto {
            PROTO_IP => return Ok(Some(Bytes::copy_from_slice(info))),
            PROTO_LCP => self.lcp_input(info)?,
            PROTO_IPCP => self.ipcp_input(info)?,
            p if p & 0x8000 != 0 && self.lcp.opened() => {
                tracing::debug!("PPP: rejecting protocol {p:#06x}");
                let mut data = p.to_be_bytes().to_vec();
                let max = (self.peer_mru as usize).saturating_sub(6);
                data.extend_from_slice(&info[..info.len().min(max)]);
                let id = self.fresh_id();
                self.send(PROTO_LCP, PROTO_REJ, id, &data);
            }
            p => tracing::trace!("PPP: dropping protocol {p:#06x}"),
        }
        Ok(None)
    }

    fn lcp_input(&mut self, info: &[u8]) -> anyhow::Result<()> {
        let Some((code, id, data)) = parse_packet(info) else { return Ok(()) };
        match code {
            CONF_REQ => {
                let Some(opts) = parse_options(data) else { return Ok(()) };
                let mut rejected = Vec::new();
                for (ty, val) in &opts {
                    match (*ty, val.len()) {
                        (LCP_MRU, 2) => self.peer_mru = u16::from_be_bytes([val[0], val[1]]).clamp(576, 1500),
                        (LCP_ACCM, 4) | (LCP_PFC, 0) | (LCP_ACFC, 0) => {}
                        (LCP_MAGIC, 4) => {}
                        _ => push_option(&mut rejected, *ty, val),
                    }
                }
                if rejected.is_empty() {
                    self.send(PROTO_LCP, CONF_ACK, id, data);
                    self.lcp.peer_acked = true;
                    self.maybe_start_ipcp();
                } else {
                    self.send(PROTO_LCP, CONF_REJ, id, &rejected);
                }
            }
            CONF_ACK if id == self.lcp.req_id => {
                self.lcp.ours_acked = true;
                self.maybe_start_ipcp();
            }
            CONF_NAK if id == self.lcp.req_id => {
                for (ty, val) in parse_options(data).unwrap_or_default() {
                    match (ty, val.len()) {
                        (LCP_MRU, 2) => self.mru = u16::from_be_bytes([val[0], val[1]]).clamp(576, 1500),
                        (LCP_MAGIC, 4) => self.magic = nonzero_random(),
                        _ => {}
                    }
                }
                self.lcp.req_id = self.fresh_id();
                self.send_lcp_request();
            }
            CONF_REJ if id == self.lcp.req_id => {
                for (ty, _) in parse_options(data).unwrap_or_default() {
                    match ty {
                        LCP_MRU => self.send_mru = false,
                        LCP_MAGIC => self.send_magic = false,
                        _ => {}
                    }
                }
                self.lcp.req_id = self.fresh_id();
                self.send_lcp_request();
            }
            TERM_REQ => {
                self.send(PROTO_LCP, TERM_ACK, id, b"");
                bail!("PPP: link terminated by gateway");
            }
            ECHO_REQ => {
                let mut reply = self.magic.to_be_bytes().to_vec();
                reply.extend_from_slice(data.get(4..).unwrap_or_default());
                self.send(PROTO_LCP, ECHO_REP, id, &reply);
            }
            ECHO_REP => self.missed_echoes = 0,
            PROTO_REJ => {
                let proto = data.get(..2).map(|p| u16::from_be_bytes([p[0], p[1]]));
                if proto == Some(PROTO_IPCP) {
                    bail!("PPP: gateway rejected IPCP");
                }
                tracing::debug!("PPP: gateway rejected protocol {proto:?}");
            }
            CONF_ACK | CONF_NAK | CONF_REJ | TERM_ACK | CODE_REJ | DISCARD_REQ => {}
            // Within the peer's MRU, as for a protocol reject: an oversized
            // frame would close the tunnel.
            _ => {
                let max = (self.peer_mru as usize).saturating_sub(4);
                self.send(PROTO_LCP, CODE_REJ, id, &info[..info.len().min(max)]);
            }
        }
        Ok(())
    }

    fn ipcp_input(&mut self, info: &[u8]) -> anyhow::Result<()> {
        let Some((code, id, data)) = parse_packet(info) else { return Ok(()) };
        match code {
            CONF_REQ => {
                let Some(opts) = parse_options(data) else { return Ok(()) };
                let mut rejected = Vec::new();
                for (ty, val) in &opts {
                    match (*ty, val.len()) {
                        (IPCP_ADDR, 4) => self.peer_address = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3])),
                        _ => push_option(&mut rejected, *ty, val),
                    }
                }
                if rejected.is_empty() {
                    self.send(PROTO_IPCP, CONF_ACK, id, data);
                    self.ipcp.peer_acked = true;
                } else {
                    self.send(PROTO_IPCP, CONF_REJ, id, &rejected);
                }
            }
            CONF_ACK if id == self.ipcp.req_id => self.ipcp.ours_acked = true,
            CONF_NAK if id == self.ipcp.req_id => {
                for (ty, val) in parse_options(data).unwrap_or_default() {
                    if val.len() != 4 {
                        continue;
                    }
                    let addr = Ipv4Addr::new(val[0], val[1], val[2], val[3]);
                    match ty {
                        IPCP_ADDR => self.address = addr,
                        IPCP_DNS1 => self.dns[0] = Some(addr),
                        IPCP_DNS2 => self.dns[1] = Some(addr),
                        _ => {}
                    }
                }
                self.ipcp.req_id = self.fresh_id();
                self.send_ipcp_request();
            }
            CONF_REJ if id == self.ipcp.req_id => {
                for (ty, _) in parse_options(data).unwrap_or_default() {
                    match ty {
                        IPCP_ADDR => bail!("PPP: gateway refuses to assign an IP address"),
                        IPCP_DNS1 => self.ask_dns[0] = false,
                        IPCP_DNS2 => self.ask_dns[1] = false,
                        _ => {}
                    }
                }
                self.ipcp.req_id = self.fresh_id();
                self.send_ipcp_request();
            }
            TERM_REQ => {
                self.send(PROTO_IPCP, TERM_ACK, id, b"");
                bail!("PPP: IPCP terminated by gateway");
            }
            CONF_ACK | CONF_NAK | CONF_REJ | TERM_ACK | CODE_REJ => {}
            _ => self.send(PROTO_IPCP, CODE_REJ, id, info),
        }
        Ok(())
    }

    fn maybe_start_ipcp(&mut self) {
        if self.lcp.opened() && self.ipcp.req_id == 0 {
            self.ipcp.req_id = self.fresh_id();
            self.send_ipcp_request();
        }
    }

    fn send_lcp_request(&mut self) {
        let mut opts = Vec::new();
        if self.send_mru {
            push_option(&mut opts, LCP_MRU, &self.mru.to_be_bytes());
        }
        if self.send_magic {
            push_option(&mut opts, LCP_MAGIC, &self.magic.to_be_bytes());
        }
        self.send(PROTO_LCP, CONF_REQ, self.lcp.req_id, &opts);
    }

    fn send_ipcp_request(&mut self) {
        let mut opts = Vec::new();
        push_option(&mut opts, IPCP_ADDR, &self.address.octets());
        for (i, ty) in [IPCP_DNS1, IPCP_DNS2].into_iter().enumerate() {
            if self.ask_dns[i] {
                push_option(&mut opts, ty, &self.dns[i].unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
            }
        }
        self.send(PROTO_IPCP, CONF_REQ, self.ipcp.req_id, &opts);
    }

    fn send(&mut self, proto: u16, code: u8, id: u8, data: &[u8]) {
        let len = (data.len() + 4) as u16;
        let mut frame = Vec::with_capacity(data.len() + 6);
        frame.extend_from_slice(&proto.to_be_bytes());
        frame.extend_from_slice(&[code, id]);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        self.out.push(frame);
    }

    fn fresh_id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }
}

fn nonzero_random() -> u32 {
    loop {
        let v: u32 = rand::random();
        if v != 0 {
            return v;
        }
    }
}

/// Splits a control packet into (code, identifier, data), honouring the
/// length field (trailing padding is ignored).
fn parse_packet(info: &[u8]) -> Option<(u8, u8, &[u8])> {
    let [code, id, l1, l2, ..] = *info else { return None };
    let len = u16::from_be_bytes([l1, l2]) as usize;
    if len < 4 || len > info.len() {
        return None;
    }
    Some((code, id, &info[4..len]))
}

fn parse_options(mut data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut opts = Vec::new();
    while !data.is_empty() {
        let [ty, len, ..] = *data else { return None };
        let len = len as usize;
        if len < 2 || len > data.len() {
            return None;
        }
        opts.push((ty, &data[2..len]));
        data = &data[len..];
    }
    Some(opts)
}

fn push_option(buf: &mut Vec<u8>, ty: u8, val: &[u8]) {
    buf.push(ty);
    buf.push((val.len() + 2) as u8);
    buf.extend_from_slice(val);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
        let mut f = proto.to_be_bytes().to_vec();
        f.extend_from_slice(&[code, id]);
        f.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
        f.extend_from_slice(data);
        f
    }

    fn header(frame: &[u8]) -> (u16, u8, u8) {
        (u16::from_be_bytes([frame[0], frame[1]]), frame[2], frame[3])
    }

    #[test]
    fn full_negotiation() {
        let mut ppp = Ppp::new(1354);
        ppp.start();
        let out = ppp.drain();
        let (proto, code, lcp_id) = header(&out[0]);
        assert_eq!((proto, code), (PROTO_LCP, CONF_REQ));

        // Gateway requests MRU + magic + an auth protocol we refuse.
        let req = [1, 4, 0x05, 0x4a, 5, 6, 1, 2, 3, 4, 3, 4, 0xc0, 0x23];
        ppp.input(&packet(PROTO_LCP, CONF_REQ, 7, &req)).unwrap();
        let out = ppp.drain();
        assert_eq!(header(&out[0]), (PROTO_LCP, CONF_REJ, 7));
        assert_eq!(&out[0][6..], &[3, 4, 0xc0, 0x23]);

        ppp.input(&packet(PROTO_LCP, CONF_REQ, 8, &req[..10])).unwrap();
        assert_eq!(header(&ppp.drain()[0]), (PROTO_LCP, CONF_ACK, 8));
        assert_eq!(ppp.peer_mru(), 1354);

        // Our request acked: LCP opens and IPCP starts.
        ppp.input(&packet(PROTO_LCP, CONF_ACK, lcp_id, &[])).unwrap();
        let out = ppp.drain();
        let (proto, code, ipcp_id) = header(&out[0]);
        assert_eq!((proto, code), (PROTO_IPCP, CONF_REQ));

        // Gateway naks with the assigned address and DNS.
        let nak = [3, 6, 10, 212, 134, 200, 129, 6, 10, 1, 1, 53, 131, 6, 10, 1, 2, 53];
        ppp.input(&packet(PROTO_IPCP, CONF_NAK, ipcp_id, &nak)).unwrap();
        let out = ppp.drain();
        let (_, code, ipcp_id) = header(&out[0]);
        assert_eq!(code, CONF_REQ);
        assert_eq!(&out[0][6..], &nak);

        ppp.input(&packet(PROTO_IPCP, CONF_REQ, 3, &[3, 6, 169, 254, 2, 1])).unwrap();
        assert_eq!(header(&ppp.drain()[0]), (PROTO_IPCP, CONF_ACK, 3));
        assert!(!ppp.is_up());
        ppp.input(&packet(PROTO_IPCP, CONF_ACK, ipcp_id, &nak)).unwrap();
        assert!(ppp.is_up());
        assert_eq!(ppp.address(), Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(ppp.dns(), vec![Ipv4Addr::new(10, 1, 1, 53), Ipv4Addr::new(10, 1, 2, 53)]);
        assert_eq!(ppp.peer_address(), Some(Ipv4Addr::new(169, 254, 2, 1)));

        // IP data and compressed protocol field.
        let ip = ppp.input(&[0x00, 0x21, 0x45, 0x00]).unwrap().unwrap();
        assert_eq!(&ip[..], &[0x45, 0x00]);
        let ip = ppp.input(&[0x21, 0x45, 0x01]).unwrap().unwrap();
        assert_eq!(&ip[..], &[0x45, 0x01]);
        let ip = ppp.input(&[0xff, 0x03, 0x00, 0x21, 0x45]).unwrap().unwrap();
        assert_eq!(&ip[..], &[0x45]);
    }

    #[test]
    fn echo_and_keepalive() {
        let mut ppp = Ppp::new(1354);
        ppp.input(&packet(PROTO_LCP, ECHO_REQ, 9, &[0, 0, 0, 1, 0xaa])).unwrap();
        let out = ppp.drain();
        assert_eq!(header(&out[0]), (PROTO_LCP, ECHO_REP, 9));
        assert_eq!(out[0][10], 0xaa);

        for _ in 0..MAX_MISSED_ECHOES {
            ppp.keepalive().unwrap();
        }
        assert!(ppp.keepalive().is_err());
        ppp.input(&packet(PROTO_LCP, ECHO_REP, 1, &[0, 0, 0, 2])).unwrap();
        assert!(ppp.keepalive().is_ok());
    }

    #[test]
    fn terminate_request_ends_link() {
        let mut ppp = Ppp::new(1354);
        assert!(ppp.input(&packet(PROTO_LCP, TERM_REQ, 4, &[])).is_err());
        assert_eq!(header(&ppp.drain()[0]), (PROTO_LCP, TERM_ACK, 4));
    }

    #[test]
    fn rejects_unknown_control_protocol_once_open() {
        let mut ppp = Ppp::new(1354);
        ppp.start();
        ppp.input(&packet(PROTO_LCP, CONF_REQ, 1, &[])).unwrap();
        ppp.input(&packet(PROTO_LCP, CONF_ACK, 1, &[])).unwrap();
        ppp.drain();
        ppp.input(&packet(0x8057, CONF_REQ, 1, &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1])).unwrap();
        let out = ppp.drain();
        assert_eq!((header(&out[0]).0, header(&out[0]).1), (PROTO_LCP, PROTO_REJ));
        assert_eq!(&out[0][6..8], &[0x80, 0x57]);

        // An unknown LCP code is rejected within the gateway's MRU.
        ppp.input(&packet(PROTO_LCP, 0x7f, 9, &vec![0; 4000])).unwrap();
        let out = ppp.drain();
        assert_eq!((header(&out[0]).0, header(&out[0]).1), (PROTO_LCP, CODE_REJ));
        assert_eq!(out[0].len() - 2, 1500, "LCP packet as long as the gateway's MRU (default)");
    }
}
