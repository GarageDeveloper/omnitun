//! PPP client (RFC 1661) above L2TP: LCP, then the authentication the
//! server asks for (PAP RFC 1334, CHAP-MD5 RFC 1994, MS-CHAPv2 RFC 2759),
//! then IPCP (RFC 1332, DNS RFC 1877) for our address. Sans I/O: frames
//! in, frames out, timers ticked by the caller.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::bail;
use md5::{Digest, Md5};
use tracing::{debug, info, warn};
use vpn_core::{FailureKind, PppAuth, failure};
use zeroize::Zeroizing;

pub const LCP: u16 = 0xc021;
pub const PAP: u16 = 0xc023;
pub const CHAP: u16 = 0xc223;
pub const IPCP: u16 = 0x8021;
pub const IP: u16 = 0x0021;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const PROT_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

const LCP_MRU: u8 = 1;
const LCP_AUTH: u8 = 3;
const LCP_MAGIC: u8 = 5;
const LCP_ACCM: u8 = 2;
const IPCP_ADDRESS: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

const CHAP_MD5: u8 = 5;
const CHAP_MSCHAPV2: u8 = 0x81;

/// Our MRU: room for L2TP, UDP and ESP in a 1500-byte path.
pub const MRU: u16 = 1400;
const RESTART: Duration = Duration::from_secs(3);
const MAX_CONFIGURE: u32 = 10;
const ECHO_EVERY: Duration = Duration::from_secs(20);
const MAX_ECHO_MISSED: u32 = 5;

/// What the session got from IPCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Pap,
    Chap,
    MsChapV2,
}

/// One control protocol's configure exchange (LCP or IPCP).
#[derive(Default)]
struct Negotiation {
    id: u8,
    /// Our request, as last sent.
    request: Vec<(u8, Vec<u8>)>,
    acked: bool,
    peer_acked: bool,
    sent: Option<Instant>,
    tries: u32,
}

impl Negotiation {
    fn opened(&self) -> bool {
        self.acked && self.peer_acked
    }
}

/// `refused_auth` of a server that asked for no authentication.
const NO_AUTH: &str = "no";

pub struct Ppp {
    username: String,
    password: Zeroizing<String>,
    allowed: Vec<PppAuth>,
    magic: u32,
    lcp: Negotiation,
    ipcp: Negotiation,
    auth: Option<Auth>,
    authenticated: bool,
    /// The authentication the server asked for and the profile refuses.
    refused_auth: Option<&'static str>,
    pap: Option<(u8, Instant, u32)>,
    /// MS-CHAPv2: our challenge and response, to check the server's.
    mschap: Option<([u8; 16], [u8; 16], [u8; 24])>,
    /// CHAP: the id of the challenge we answered.
    chap: Option<u8>,
    pub up: Option<Assigned>,
    echo: Option<(Instant, u32)>,
    echo_id: u8,
    last_echo: Instant,
    out: Vec<(u16, Vec<u8>)>,
}

/// A configure packet: code, id, options.
fn packet(code: u8, id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![code, id];
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn options(list: &[(u8, Vec<u8>)]) -> Vec<u8> {
    list.iter().flat_map(|(kind, value)| [&[*kind, value.len() as u8 + 2][..], value].concat()).collect()
}

fn parse_options(data: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (kind, len) = (*rest.first()?, usize::from(*rest.get(1)?));
        if len < 2 || len > rest.len() {
            return None;
        }
        out.push((kind, rest[2..len].to_vec()));
        rest = &rest[len..];
    }
    Some(out)
}

impl Ppp {
    pub fn new(username: String, password: Zeroizing<String>, allowed: Vec<PppAuth>) -> Self {
        let now = Instant::now();
        let mut ppp = Self {
            username,
            password,
            allowed,
            magic: rand::random::<u32>() | 1,
            lcp: Negotiation::default(),
            ipcp: Negotiation::default(),
            auth: None,
            authenticated: false,
            refused_auth: None,
            pap: None,
            mschap: None,
            chap: None,
            up: None,
            echo: None,
            echo_id: 0,
            last_echo: now,
            out: Vec::new(),
        };
        ppp.lcp.request = vec![(LCP_MRU, MRU.to_be_bytes().to_vec()), (LCP_MAGIC, ppp.magic.to_be_bytes().to_vec())];
        ppp.ipcp.request = vec![(IPCP_ADDRESS, vec![0; 4]), (IPCP_DNS1, vec![0; 4]), (IPCP_DNS2, vec![0; 4])];
        ppp
    }

    /// Opens LCP, once the L2TP session is up.
    pub fn start(&mut self, now: Instant) {
        if self.lcp.sent.is_none() {
            self.send_request(LCP, now);
        }
    }

    /// Frames to send: protocol and contents.
    pub fn take_output(&mut self) -> Vec<(u16, Vec<u8>)> {
        std::mem::take(&mut self.out)
    }

    fn negotiation(&mut self, protocol: u16) -> &mut Negotiation {
        if protocol == LCP { &mut self.lcp } else { &mut self.ipcp }
    }

    fn send_request(&mut self, protocol: u16, now: Instant) {
        let n = self.negotiation(protocol);
        n.id = n.id.wrapping_add(1);
        n.sent = Some(now);
        n.tries += 1;
        let frame = packet(CONF_REQ, n.id, &options(&n.request));
        self.out.push((protocol, frame));
    }

    /// Retransmissions and keepalives.
    pub fn tick(&mut self, now: Instant) -> anyhow::Result<()> {
        for protocol in [LCP, IPCP] {
            let started = protocol == LCP || (self.lcp.opened() && self.authenticated);
            let n = self.negotiation(protocol);
            if started && !n.acked && n.sent.is_some_and(|t| now.duration_since(t) >= RESTART) {
                if n.tries >= MAX_CONFIGURE {
                    let what = if protocol == LCP { "LCP" } else { "IPCP" };
                    bail!("the server did not complete the PPP {what} negotiation");
                }
                self.send_request(protocol, now);
            }
        }
        if let Some((id, sent, tries)) = self.pap
            && !self.authenticated
            && now.duration_since(sent) >= RESTART
        {
            if tries >= MAX_CONFIGURE {
                bail!("the server did not answer the PAP authentication");
            }
            self.send_pap(id.wrapping_add(1), now, tries + 1);
        }
        if self.up.is_some() && now.duration_since(self.last_echo) >= ECHO_EVERY {
            let missed = self.echo.map_or(0, |(_, m)| m);
            if missed >= MAX_ECHO_MISSED {
                return Err(failure(FailureKind::Unreachable, "the L2TP server stopped answering (PPP echo)"));
            }
            self.echo_id = self.echo_id.wrapping_add(1);
            self.echo = Some((now, missed + 1));
            self.last_echo = now;
            let frame = packet(ECHO_REQ, self.echo_id, &self.magic.to_be_bytes());
            self.out.push((LCP, frame));
        }
        Ok(())
    }

    /// Handles a received frame; returns an IP packet for the tunnel.
    pub fn input(&mut self, protocol: u16, data: &[u8], now: Instant) -> anyhow::Result<Option<Vec<u8>>> {
        // Anything received proves the link alive.
        self.echo = None;
        match protocol {
            IP if let Some(up) = &self.up => {
                return Ok(match inner_ok(data, up.address) {
                    Ok(()) => Some(data.to_vec()),
                    Err(why) => {
                        debug!("dropping a packet from the L2TP server: {why}");
                        None
                    }
                });
            }
            IP => {}
            LCP => self.lcp_input(data, now)?,
            IPCP if self.lcp.opened() => self.ipcp_input(data, now)?,
            PAP => self.pap_input(data)?,
            CHAP => self.chap_input(data)?,
            other => {
                // CCP, IPv6CP…: refused (RFC 1661 §5.7).
                debug!(protocol = format_args!("{other:#06x}"), "PPP protocol rejected");
                if self.lcp.opened() {
                    let mut body = other.to_be_bytes().to_vec();
                    body.extend_from_slice(&data[..data.len().min(MRU as usize - 8)]);
                    self.lcp.id = self.lcp.id.wrapping_add(1);
                    self.out.push((LCP, packet(PROT_REJ, self.lcp.id, &body)));
                }
            }
        }
        Ok(None)
    }

    fn header(data: &[u8]) -> Option<(u8, u8, &[u8])> {
        let len = usize::from(u16::from_be_bytes([*data.get(2)?, *data.get(3)?]));
        (len >= 4 && len <= data.len()).then(|| (data[0], data[1], &data[4..len]))
    }

    fn lcp_input(&mut self, data: &[u8], now: Instant) -> anyhow::Result<()> {
        let Some((code, id, body)) = Self::header(data) else { return Ok(()) };
        match code {
            CONF_REQ => self.peer_request(LCP, id, body, now)?,
            CONF_ACK | CONF_NAK | CONF_REJ => self.answer(LCP, code, id, body, now)?,
            TERM_REQ => {
                self.out.push((LCP, packet(TERM_ACK, id, &[])));
                // The server gave up after our Nak: it only accepts the
                // authentication it asked for.
                if let (None, Some(method)) = (self.auth, self.refused_auth) {
                    return Err(Self::unacceptable(method));
                }
                bail!("the L2TP server ended the PPP link");
            }
            ECHO_REQ => {
                let frame = packet(ECHO_REP, id, &self.magic.to_be_bytes());
                self.out.push((LCP, frame));
            }
            ECHO_REP | TERM_ACK => {}
            PROT_REJ => debug!("the server rejected a PPP protocol"),
            other => debug!(code = other, "LCP code ignored"),
        }
        Ok(())
    }

    fn ipcp_input(&mut self, data: &[u8], now: Instant) -> anyhow::Result<()> {
        let Some((code, id, body)) = Self::header(data) else { return Ok(()) };
        match code {
            CONF_REQ => self.peer_request(IPCP, id, body, now)?,
            CONF_ACK | CONF_NAK | CONF_REJ => self.answer(IPCP, code, id, body, now)?,
            TERM_REQ => {
                self.out.push((IPCP, packet(TERM_ACK, id, &[])));
                bail!("the L2TP server closed IP on the PPP link");
            }
            _ => {}
        }
        self.check_up();
        Ok(())
    }

    /// Which of the server's authentication protocol options we accept.
    fn acceptable(&self, value: &[u8]) -> Option<Auth> {
        let auth = match value {
            [0xc0, 0x23] => Auth::Pap,
            [0xc2, 0x23, CHAP_MD5] => Auth::Chap,
            [0xc2, 0x23, CHAP_MSCHAPV2] => Auth::MsChapV2,
            _ => return None,
        };
        let allowed = match auth {
            Auth::Pap => PppAuth::Pap,
            Auth::Chap => PppAuth::Chap,
            Auth::MsChapV2 => PppAuth::MsChapV2,
        };
        self.allowed.contains(&allowed).then_some(auth)
    }

    /// Our preferred authentication, as an LCP option value.
    fn preferred(&self) -> Option<Vec<u8>> {
        self.allowed.first().map(|a| match a {
            PppAuth::MsChapV2 => vec![0xc2, 0x23, CHAP_MSCHAPV2],
            PppAuth::Chap => vec![0xc2, 0x23, CHAP_MD5],
            PppAuth::Pap => vec![0xc0, 0x23],
        })
    }

    fn unacceptable(method: &str) -> anyhow::Error {
        if method == NO_AUTH {
            return failure(
                FailureKind::AuthFailed,
                "the L2TP server asks for no authentication, so it cannot be told from someone else who has the \
                 pre-shared key: not trusted",
            );
        }
        failure(
            FailureKind::AuthFailed,
            format!(
                "the L2TP server only accepts {method} authentication, which this profile does not allow: allow it \
                 in the PPP options"
            ),
        )
    }

    fn peer_request(&mut self, protocol: u16, id: u8, body: &[u8], now: Instant) -> anyhow::Result<()> {
        let Some(opts) = parse_options(body) else { return Ok(()) };
        let (mut nak, mut rej) = (Vec::new(), Vec::new());
        let mut auth = None;
        for (kind, value) in &opts {
            match (protocol, *kind) {
                (LCP, LCP_MRU | LCP_ACCM | LCP_MAGIC) => {}
                (LCP, LCP_AUTH) => match self.acceptable(value) {
                    Some(a) => auth = Some(a),
                    None => {
                        self.refused_auth = Some(match value.as_slice() {
                            [0xc0, 0x23] => "PAP",
                            [0xc2, 0x23, CHAP_MD5] => "CHAP",
                            [0xc2, 0x23, CHAP_MSCHAPV2] => "MS-CHAPv2",
                            _ => "an unsupported",
                        });
                        match self.preferred() {
                            Some(preferred) if preferred != *value => nak.push((LCP_AUTH, preferred)),
                            _ => rej.push((*kind, value.clone())),
                        }
                    }
                },
                (IPCP, IPCP_ADDRESS) => {}
                _ => rej.push((*kind, value.clone())),
            }
        }
        // A server that asks for no authentication proves nothing: anyone
        // with the group's pre-shared key could pose as it.
        if protocol == LCP && auth.is_none() && nak.is_empty() && !opts.iter().any(|(k, _)| *k == LCP_AUTH) {
            match self.refused_auth {
                // It dropped the method we refused (pppd does): it has no
                // other.
                Some(method) => return Err(Self::unacceptable(method)),
                None => {
                    self.refused_auth = Some(NO_AUTH);
                    if let Some(preferred) = self.preferred() {
                        nak.push((LCP_AUTH, preferred));
                    }
                }
            }
        }
        let reply = if !rej.is_empty() {
            packet(CONF_REJ, id, &options(&rej))
        } else if !nak.is_empty() {
            packet(CONF_NAK, id, &options(&nak))
        } else {
            if protocol == LCP {
                self.auth = auth;
            }
            self.negotiation(protocol).peer_acked = true;
            packet(CONF_ACK, id, body)
        };
        if !nak.is_empty() && rej.is_empty() {
            debug!("asking the server for another PPP authentication");
        }
        self.out.push((protocol, reply));
        if protocol == LCP && self.lcp.opened() {
            self.lcp_up(now);
        }
        Ok(())
    }

    fn answer(&mut self, protocol: u16, code: u8, id: u8, body: &[u8], now: Instant) -> anyhow::Result<()> {
        if id != self.negotiation(protocol).id {
            return Ok(());
        }
        let Some(opts) = parse_options(body) else { return Ok(()) };
        match code {
            CONF_ACK => {
                self.negotiation(protocol).acked = true;
                if protocol == LCP && self.lcp.opened() {
                    self.lcp_up(now);
                }
                return Ok(());
            }
            CONF_NAK => {
                for (kind, value) in opts {
                    let n = self.negotiation(protocol);
                    if let Some(slot) = n.request.iter_mut().find(|(k, _)| *k == kind) {
                        slot.1 = value;
                    }
                }
            }
            _ => {
                if protocol == IPCP && opts.iter().any(|(k, _)| *k == IPCP_ADDRESS) {
                    bail!("the L2TP server refused to assign an address");
                }
                self.negotiation(protocol).request.retain(|(k, _)| !opts.iter().any(|(r, _)| r == k));
            }
        }
        self.send_request(protocol, now);
        Ok(())
    }

    fn lcp_up(&mut self, now: Instant) {
        if self.authenticated || (self.auth.is_some() && (self.pap.is_some() || self.mschap.is_some())) {
            return;
        }
        match self.auth {
            // Never acknowledged without one (peer_request).
            None => {}
            Some(Auth::Pap) => self.send_pap(1, now, 1),
            // CHAP: the server sends its challenge.
            Some(_) => {}
        }
    }

    fn send_pap(&mut self, id: u8, now: Instant, tries: u32) {
        let mut body = vec![self.username.len() as u8];
        body.extend_from_slice(self.username.as_bytes());
        body.push(self.password.len() as u8);
        body.extend_from_slice(self.password.as_bytes());
        self.out.push((PAP, packet(1, id, &body)));
        body.fill(0);
        self.pap = Some((id, now, tries));
    }

    fn pap_input(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let Some((code, id, body)) = Self::header(data) else { return Ok(()) };
        if self.pap.is_none_or(|(sent, ..)| sent != id) {
            return Ok(());
        }
        let message = || body.get(1..).map(|m| printable(&String::from_utf8_lossy(m)));
        match code {
            2 => self.authenticated_now(),
            3 => return Err(refused(message())),
            _ => {}
        }
        Ok(())
    }

    fn chap_input(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let Some((code, id, body)) = Self::header(data) else { return Ok(()) };
        match (code, self.auth) {
            (1, Some(Auth::Chap)) => {
                let Some(challenge) = body.get(1..1 + usize::from(*body.first().unwrap_or(&0))) else { return Ok(()) };
                let mut digest = Md5::new();
                digest.update([id]);
                digest.update(self.password.as_bytes());
                digest.update(challenge);
                let value = digest.finalize();
                self.chap_response(id, &value);
            }
            (1, Some(Auth::MsChapV2)) => {
                let Some(auth) = body.get(1..17).filter(|_| body[0] == 16) else { return Ok(()) };
                let auth: [u8; 16] = auth.try_into().unwrap();
                let peer: [u8; 16] = rand::random();
                let user = vpn_ipsec::mschapv2::mschap_username(&self.username).as_bytes();
                let nt = vpn_ipsec::mschapv2::nt_response(&auth, &peer, user, &self.password);
                let mut value = peer.to_vec();
                value.extend_from_slice(&[0; 8]);
                value.extend_from_slice(&nt);
                value.push(0);
                self.mschap = Some((auth, peer, nt));
                self.chap_response(id, &value);
            }
            // Only the success of the challenge we answered.
            (3, Some(Auth::Chap)) if self.chap == Some(id) => self.authenticated_now(),
            (3, Some(Auth::MsChapV2)) => {
                let Some((auth, peer, nt)) = self.mschap else { return Ok(()) };
                let user = vpn_ipsec::mschapv2::mschap_username(&self.username).as_bytes();
                let hash = vpn_ipsec::mschapv2::nt_password_hash(&self.password);
                let expected = vpn_ipsec::mschapv2::authenticator_response(&hash, &nt, &peer, &auth, user);
                let text = String::from_utf8_lossy(body);
                if !text.split_whitespace().next().is_some_and(|s| s.eq_ignore_ascii_case(&expected)) {
                    bail!("the L2TP server could not prove it knows the password (MS-CHAPv2): not trusted");
                }
                self.authenticated_now();
            }
            (4, _) => {
                let text = String::from_utf8_lossy(body);
                let message = text.split_once("M=").map(|(_, m)| m.to_owned()).or(Some(text.into_owned()));
                return Err(refused(message.map(|m| printable(&m))));
            }
            _ => {}
        }
        Ok(())
    }

    fn chap_response(&mut self, id: u8, value: &[u8]) {
        self.chap = Some(id);
        let mut body = vec![value.len() as u8];
        body.extend_from_slice(value);
        body.extend_from_slice(self.username.as_bytes());
        self.out.push((CHAP, packet(2, id, &body)));
    }

    fn authenticated_now(&mut self) {
        if self.authenticated {
            return;
        }
        info!(method = ?self.auth, "PPP authentication accepted");
        self.authenticated = true;
        self.send_request(IPCP, Instant::now());
    }

    fn check_up(&mut self) {
        if self.up.is_some() || !self.ipcp.opened() {
            return;
        }
        let value = |kind: u8| {
            self.ipcp
                .request
                .iter()
                .find(|(k, _)| *k == kind)
                .and_then(|(_, v)| <[u8; 4]>::try_from(v.as_slice()).ok())
                .map(Ipv4Addr::from)
                .filter(|a| !a.is_unspecified())
        };
        let Some(address) = value(IPCP_ADDRESS) else {
            warn!("IPCP opened without an address");
            return;
        };
        let dns = [IPCP_DNS1, IPCP_DNS2].into_iter().filter_map(value).collect();
        self.up = Some(Assigned { address, dns });
    }
}

/// Server text, made safe to show.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() && !vpn_core::is_invisible(*c)).take(200).collect()
}

fn refused(message: Option<String>) -> anyhow::Error {
    let detail = message.filter(|m| !m.trim().is_empty()).map(|m| format!(": {}", m.trim())).unwrap_or_default();
    failure(FailureKind::AuthFailed, format!("the L2TP server refused the user name or password{detail}"))
}

/// A packet from the server goes to the tunnel only if it is a well-formed
/// IPv4 packet to our address.
fn inner_ok(packet: &[u8], address: Ipv4Addr) -> Result<(), &'static str> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err("not an IPv4 packet");
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total < ihl || total != packet.len() {
        return Err("inconsistent IPv4 header lengths");
    }
    if packet[16..20] != address.octets() {
        return Err("destination is not our tunnel address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the server: acks our LCP request, asks for CHAP-MD5, then
    /// assigns an address and DNS servers.
    #[test]
    fn chap_then_ipcp() {
        let now = Instant::now();
        let mut ppp = Ppp::new("alice".into(), Zeroizing::new("secret".into()), vec![PppAuth::Chap]);
        ppp.start(now);
        let out = ppp.take_output();
        let (protocol, request) = &out[0];
        assert_eq!(*protocol, LCP);
        let id = request[1];
        ppp.input(LCP, &packet(CONF_ACK, id, &request[4..]), now).unwrap();
        // The server wants MS-CHAPv2, which the profile refuses: Nak with CHAP.
        let server = options(&[(LCP_AUTH, vec![0xc2, 0x23, CHAP_MSCHAPV2]), (LCP_MAGIC, vec![1, 2, 3, 4])]);
        ppp.input(LCP, &packet(CONF_REQ, 7, &server), now).unwrap();
        let out = ppp.take_output();
        assert_eq!((out[0].1[0], &out[0].1[4..]), (CONF_NAK, &[LCP_AUTH, 5, 0xc2, 0x23, CHAP_MD5][..]));
        let server = options(&[(LCP_AUTH, vec![0xc2, 0x23, CHAP_MD5]), (LCP_MAGIC, vec![1, 2, 3, 4])]);
        ppp.input(LCP, &packet(CONF_REQ, 8, &server), now).unwrap();
        assert_eq!(ppp.take_output()[0].1[0], CONF_ACK);

        ppp.input(CHAP, &packet(1, 42, &[[4u8].as_slice(), b"abcd", b"server"].concat()), now).unwrap();
        let out = ppp.take_output();
        let mut expected = Md5::new();
        expected.update([42u8]);
        expected.update(b"secret");
        expected.update(b"abcd");
        assert_eq!(&out[0].1[5..21], expected.finalize().as_slice());
        assert_eq!(&out[0].1[21..], b"alice");
        ppp.input(CHAP, &packet(3, 42, b""), now).unwrap();

        let ipcp = ppp.take_output();
        assert_eq!(ipcp[0].0, IPCP);
        let id = ipcp[0].1[1];
        let nak = options(&[(IPCP_ADDRESS, vec![10, 9, 0, 2]), (IPCP_DNS1, vec![10, 9, 0, 1])]);
        ppp.input(IPCP, &packet(CONF_NAK, id, &nak), now).unwrap();
        let again = ppp.take_output();
        let id = again[0].1[1];
        ppp.input(IPCP, &packet(CONF_REJ, id, &options(&[(IPCP_DNS2, vec![0; 4])])), now).unwrap();
        let again = ppp.take_output();
        ppp.input(IPCP, &packet(CONF_ACK, again[0].1[1], &again[0].1[4..]), now).unwrap();
        ppp.input(IPCP, &packet(CONF_REQ, 3, &options(&[(IPCP_ADDRESS, vec![10, 9, 0, 1])])), now).unwrap();
        assert_eq!(
            ppp.up,
            Some(Assigned { address: Ipv4Addr::new(10, 9, 0, 2), dns: vec![Ipv4Addr::new(10, 9, 0, 1)] })
        );
        let ip = |dst: [u8; 4]| [&[0x45, 0, 0, 20][..], &[0; 12], &dst].concat();
        assert_eq!(ppp.input(IP, &ip([10, 9, 0, 2]), now).unwrap(), Some(ip([10, 9, 0, 2])));
        assert_eq!(ppp.input(IP, &ip([10, 9, 0, 3]), now).unwrap(), None, "not to us");
        assert_eq!(ppp.input(IP, &[0x45, 0], now).unwrap(), None, "malformed");
    }

    /// A server that asks for no authentication is asked for one, and a
    /// CHAP success without our answer is ignored.
    #[test]
    fn authentication_is_required() {
        let now = Instant::now();
        let mut ppp = Ppp::new("alice".into(), Zeroizing::new("secret".into()), vec![PppAuth::Chap]);
        ppp.start(now);
        let request = ppp.take_output().remove(0).1;
        ppp.input(LCP, &packet(CONF_ACK, request[1], &request[4..]), now).unwrap();
        ppp.input(LCP, &packet(CONF_REQ, 1, &options(&[(LCP_MAGIC, vec![1, 2, 3, 4])])), now).unwrap();
        let out = ppp.take_output();
        assert_eq!((out[0].1[0], &out[0].1[4..]), (CONF_NAK, &[LCP_AUTH, 5, 0xc2, 0x23, CHAP_MD5][..]));
        assert!(!out.iter().any(|(p, _)| *p == IPCP), "no IPCP before authentication");
        let chap = options(&[(LCP_AUTH, vec![0xc2, 0x23, CHAP_MD5])]);
        ppp.input(LCP, &packet(CONF_REQ, 2, &chap), now).unwrap();
        ppp.take_output();
        ppp.input(CHAP, &packet(3, 9, b""), now).unwrap();
        assert!(!ppp.take_output().iter().any(|(p, _)| *p == IPCP), "success without a challenge");
    }

    #[test]
    fn refused_password() {
        let now = Instant::now();
        let mut ppp = Ppp::new("alice".into(), Zeroizing::new("x".into()), vec![PppAuth::Pap]);
        ppp.start(now);
        let request = ppp.take_output().remove(0).1;
        ppp.input(LCP, &packet(CONF_ACK, request[1], &request[4..]), now).unwrap();
        ppp.input(LCP, &packet(CONF_REQ, 1, &options(&[(LCP_AUTH, vec![0xc0, 0x23])])), now).unwrap();
        let out = ppp.take_output();
        let pap = out.iter().find(|(p, _)| *p == PAP).unwrap();
        assert_eq!(&pap.1[4..], [&[5u8][..], b"alice", &[1], b"x"].concat());
        let err = ppp.input(PAP, &packet(3, pap.1[1], &[[11u8].as_slice(), b"Bad account"].concat()), now).unwrap_err();
        assert!(err.to_string().contains("Bad account"), "{err}");
    }
}
