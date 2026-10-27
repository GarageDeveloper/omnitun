//! L2TP (RFC 2661), the LAC side: one tunnel, one session, carrying PPP.
//! Control messages are numbered (Ns/Nr), acknowledged (explicitly by a
//! ZLB when nothing else goes back) and resent until acknowledged. Sans
//! I/O: messages in, messages out, timers ticked by the caller.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tracing::{debug, info};

// Control message types (§3.2).
const SCCRQ: u16 = 1;
const SCCRP: u16 = 2;
const SCCCN: u16 = 3;
const STOP_CCN: u16 = 4;
const HELLO: u16 = 6;
const ICRQ: u16 = 10;
const ICRP: u16 = 11;
const ICCN: u16 = 12;
const CDN: u16 = 14;

// AVP types (§4.4).
const AVP_MESSAGE_TYPE: u16 = 0;
const AVP_RESULT_CODE: u16 = 1;
const AVP_PROTOCOL_VERSION: u16 = 2;
const AVP_FRAMING_CAPABILITIES: u16 = 3;
const AVP_BEARER_CAPABILITIES: u16 = 4;
const AVP_FIRMWARE_REVISION: u16 = 6;
const AVP_HOST_NAME: u16 = 7;
const AVP_VENDOR_NAME: u16 = 8;
const AVP_ASSIGNED_TUNNEL_ID: u16 = 9;
const AVP_RECEIVE_WINDOW: u16 = 10;
const AVP_ASSIGNED_SESSION_ID: u16 = 14;
const AVP_CALL_SERIAL_NUMBER: u16 = 15;
const AVP_FRAMING_TYPE: u16 = 19;
const AVP_TX_CONNECT_SPEED: u16 = 24;

const FLAG_TYPE: u16 = 0x8000;
const FLAG_LENGTH: u16 = 0x4000;
const FLAG_SEQUENCE: u16 = 0x0800;
const FLAG_OFFSET: u16 = 0x0200;
const VERSION: u16 = 2;

const RETRANSMIT: Duration = Duration::from_secs(1);
const MAX_RETRANSMIT: Duration = Duration::from_secs(8);
const MAX_TRIES: u32 = 6;
/// Receive window we announce.
const WINDOW: u16 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    WaitSccrp,
    WaitIcrp,
    Established,
    Closed,
}

struct Unacked {
    ns: u16,
    bytes: Vec<u8>,
    sent: Instant,
    wait: Duration,
    tries: u32,
}

pub struct Tunnel {
    local_tunnel: u16,
    peer_tunnel: u16,
    local_session: u16,
    peer_session: u16,
    ns: u16,
    nr: u16,
    unacked: VecDeque<Unacked>,
    state: State,
    /// A ZLB acknowledgment is owed.
    owe_ack: bool,
    out: Vec<Vec<u8>>,
}

/// What a received datagram brought.
pub enum Received {
    Nothing,
    /// The session is up: PPP can start.
    SessionUp,
    /// A PPP frame (address and control fields removed).
    Ppp(Vec<u8>),
}

fn avp(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = (0x8000 | (6 + value.len() as u16)).to_be_bytes().to_vec(); // mandatory
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(value);
    out
}

fn optional_avp(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = avp(kind, value);
    out[0] &= 0x7f;
    out
}

struct Avp<'a> {
    mandatory: bool,
    hidden: bool,
    vendor: u16,
    kind: u16,
    value: &'a [u8],
}

fn parse_avps(mut data: &[u8]) -> anyhow::Result<Vec<Avp<'_>>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        ensure!(data.len() >= 6, "truncated L2TP attribute");
        let head = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(head & 0x03ff);
        ensure!(len >= 6 && len <= data.len(), "invalid L2TP attribute length");
        out.push(Avp {
            mandatory: head & 0x8000 != 0,
            hidden: head & 0x4000 != 0,
            vendor: u16::from_be_bytes([data[2], data[3]]),
            kind: u16::from_be_bytes([data[4], data[5]]),
            value: &data[6..len],
        });
        data = &data[len..];
    }
    Ok(out)
}

fn u16_value(avps: &[Avp<'_>], kind: u16) -> Option<u16> {
    avps.iter()
        .find(|a| a.vendor == 0 && a.kind == kind && !a.hidden)
        .and_then(|a| a.value.get(..2))
        .map(|v| u16::from_be_bytes([v[0], v[1]]))
}

/// The Result Code AVP of StopCCN or CDN, as text.
fn result(avps: &[Avp<'_>]) -> String {
    let Some(a) = avps.iter().find(|a| a.vendor == 0 && a.kind == AVP_RESULT_CODE) else { return String::new() };
    let code = a.value.get(..2).map(|v| u16::from_be_bytes([v[0], v[1]])).unwrap_or_default();
    let message: String = a
        .value
        .get(4..)
        .map(|m| String::from_utf8_lossy(m).chars().filter(|c| !c.is_control()).take(200).collect())
        .unwrap_or_default();
    if message.is_empty() { format!("result {code}") } else { format!("result {code}: {message}") }
}

impl Tunnel {
    /// Starts by asking for a tunnel (SCCRQ).
    pub fn new(now: Instant) -> Self {
        let mut tunnel = Self {
            local_tunnel: rand::random::<u16>().max(1),
            peer_tunnel: 0,
            local_session: rand::random::<u16>().max(1),
            peer_session: 0,
            ns: 0,
            nr: 0,
            unacked: VecDeque::new(),
            state: State::WaitSccrp,
            owe_ack: false,
            out: Vec::new(),
        };
        let host = vpn_core::brand::PRODUCT.to_ascii_lowercase();
        let avps = [
            avp(AVP_PROTOCOL_VERSION, &[1, 0]),
            avp(AVP_HOST_NAME, host.as_bytes()),
            avp(AVP_FRAMING_CAPABILITIES, &3u32.to_be_bytes()),
            avp(AVP_ASSIGNED_TUNNEL_ID, &tunnel.local_tunnel.to_be_bytes()),
            optional_avp(AVP_BEARER_CAPABILITIES, &0u32.to_be_bytes()),
            optional_avp(AVP_FIRMWARE_REVISION, &0x0100u16.to_be_bytes()),
            optional_avp(AVP_VENDOR_NAME, vpn_core::brand::PRODUCT.as_bytes()),
            avp(AVP_RECEIVE_WINDOW, &WINDOW.to_be_bytes()),
        ]
        .concat();
        tunnel.send_control(SCCRQ, 0, &avps, now);
        tunnel
    }

    pub fn is_up(&self) -> bool {
        self.state == State::Established
    }

    /// L2TP datagrams to send.
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        if self.owe_ack {
            self.owe_ack = false;
            let zlb = self.header(0, 0);
            self.out.push(zlb);
        }
        std::mem::take(&mut self.out)
    }

    /// A control header with `body_len` bytes of AVPs after it.
    fn header(&self, session: u16, body_len: usize) -> Vec<u8> {
        let mut out = (FLAG_TYPE | FLAG_LENGTH | FLAG_SEQUENCE | VERSION).to_be_bytes().to_vec();
        out.extend_from_slice(&((12 + body_len) as u16).to_be_bytes());
        out.extend_from_slice(&self.peer_tunnel.to_be_bytes());
        out.extend_from_slice(&session.to_be_bytes());
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out
    }

    fn send_control(&mut self, message: u16, session: u16, avps: &[u8], now: Instant) {
        let body = [avp(AVP_MESSAGE_TYPE, &message.to_be_bytes()), avps.to_vec()].concat();
        let mut bytes = self.header(session, body.len());
        bytes.extend_from_slice(&body);
        self.out.push(bytes.clone());
        self.unacked.push_back(Unacked { ns: self.ns, bytes, sent: now, wait: RETRANSMIT, tries: 1 });
        self.ns = self.ns.wrapping_add(1);
        // The message carries our Nr: no separate acknowledgment.
        self.owe_ack = false;
    }

    /// Resends unacknowledged control messages.
    pub fn tick(&mut self, now: Instant) -> anyhow::Result<()> {
        for m in &mut self.unacked {
            if now.duration_since(m.sent) >= m.wait {
                ensure!(m.tries < MAX_TRIES, "the L2TP server stopped answering");
                m.tries += 1;
                m.sent = now;
                m.wait = (m.wait * 2).min(MAX_RETRANSMIT);
                // Refresh Nr: it may have moved since.
                m.bytes[10..12].copy_from_slice(&self.nr.to_be_bytes());
                self.out.push(m.bytes.clone());
            }
        }
        Ok(())
    }

    /// Wraps a PPP frame (protocol and contents) in a data message.
    pub fn data(&self, protocol: u16, contents: &[u8]) -> Vec<u8> {
        let mut out = VERSION.to_be_bytes().to_vec();
        out.extend_from_slice(&self.peer_tunnel.to_be_bytes());
        out.extend_from_slice(&self.peer_session.to_be_bytes());
        out.extend_from_slice(&[0xff, 0x03]);
        out.extend_from_slice(&protocol.to_be_bytes());
        out.extend_from_slice(contents);
        out
    }

    /// Asks the server to end the session and the tunnel.
    pub fn close(&mut self, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        let code = avp(AVP_RESULT_CODE, &[0, 1]);
        if self.state == State::Established {
            let avps = [code.clone(), avp(AVP_ASSIGNED_SESSION_ID, &self.local_session.to_be_bytes())].concat();
            self.send_control(CDN, self.peer_session, &avps, now);
        }
        let avps = [avp(AVP_ASSIGNED_TUNNEL_ID, &self.local_tunnel.to_be_bytes()), code].concat();
        self.send_control(STOP_CCN, 0, &avps, now);
        self.state = State::Closed;
    }

    pub fn receive(&mut self, datagram: &[u8], now: Instant) -> anyhow::Result<Received> {
        ensure!(datagram.len() >= 6, "truncated L2TP message");
        let flags = u16::from_be_bytes([datagram[0], datagram[1]]);
        ensure!(flags & 0x000f == VERSION, "not L2TP version 2");
        if flags & FLAG_TYPE == 0 {
            return self.receive_data(flags, datagram);
        }
        ensure!(datagram.len() >= 12 && flags & FLAG_LENGTH != 0, "malformed L2TP control message");
        let len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
        ensure!(len >= 12 && len <= datagram.len(), "invalid L2TP length");
        let tunnel = u16::from_be_bytes([datagram[4], datagram[5]]);
        let ns = u16::from_be_bytes([datagram[8], datagram[9]]);
        let nr = u16::from_be_bytes([datagram[10], datagram[11]]);
        if tunnel != self.local_tunnel {
            debug!(tunnel, "L2TP message for another tunnel ignored");
            return Ok(Received::Nothing);
        }
        // Nr acknowledges everything before it.
        self.unacked.retain(|m| nr.wrapping_sub(m.ns).wrapping_sub(1) >= 0x8000);
        let body = &datagram[12..len];
        if body.is_empty() {
            return Ok(Received::Nothing); // ZLB
        }
        if ns != self.nr {
            // Already seen (our acknowledgment was lost) or out of order.
            debug!(ns, expected = self.nr, "L2TP control message out of sequence");
            self.owe_ack = true;
            return Ok(Received::Nothing);
        }
        self.nr = self.nr.wrapping_add(1);
        self.owe_ack = true;
        let avps = parse_avps(body)?;
        let first = avps.first().context("L2TP control message without a type")?;
        ensure!(first.kind == AVP_MESSAGE_TYPE && first.vendor == 0, "L2TP message type missing");
        let message = u16_value(&avps, AVP_MESSAGE_TYPE).context("invalid L2TP message type")?;
        if let Some(a) = avps.iter().skip(1).find(|a| a.mandatory && (a.hidden || a.vendor != 0)) {
            bail!("the L2TP server sent an attribute this client cannot read ({}:{})", a.vendor, a.kind);
        }
        match (message, self.state) {
            (SCCRP, State::WaitSccrp) => {
                self.peer_tunnel = u16_value(&avps, AVP_ASSIGNED_TUNNEL_ID).context("SCCRP without a tunnel id")?;
                self.send_control(SCCCN, 0, &[], now);
                let avps = [
                    avp(AVP_ASSIGNED_SESSION_ID, &self.local_session.to_be_bytes()),
                    avp(AVP_CALL_SERIAL_NUMBER, &1u32.to_be_bytes()),
                ]
                .concat();
                self.send_control(ICRQ, 0, &avps, now);
                self.state = State::WaitIcrp;
                debug!(peer_tunnel = self.peer_tunnel, "L2TP tunnel set up");
            }
            (ICRP, State::WaitIcrp) => {
                self.peer_session = u16_value(&avps, AVP_ASSIGNED_SESSION_ID).context("ICRP without a session id")?;
                let avps = [
                    avp(AVP_TX_CONNECT_SPEED, &100_000_000u32.to_be_bytes()),
                    avp(AVP_FRAMING_TYPE, &1u32.to_be_bytes()),
                ]
                .concat();
                self.send_control(ICCN, self.peer_session, &avps, now);
                self.state = State::Established;
                info!("L2TP session up");
                return Ok(Received::SessionUp);
            }
            (STOP_CCN, _) => {
                self.state = State::Closed;
                bail!("the L2TP server closed the tunnel ({})", result(&avps));
            }
            (CDN, _) => {
                self.state = State::Closed;
                bail!("the L2TP server closed the session ({})", result(&avps));
            }
            (HELLO, _) => {}
            (other, state) => debug!(message = other, ?state, "L2TP control message ignored"),
        }
        Ok(Received::Nothing)
    }

    fn receive_data(&self, flags: u16, datagram: &[u8]) -> anyhow::Result<Received> {
        let mut at = 2;
        let mut end = datagram.len();
        if flags & FLAG_LENGTH != 0 {
            end = usize::from(u16::from_be_bytes([datagram[2], datagram[3]])).min(end);
            at += 2;
        }
        ensure!(end >= at + 4, "truncated L2TP data message");
        let (tunnel, session) = (
            u16::from_be_bytes([datagram[at], datagram[at + 1]]),
            u16::from_be_bytes([datagram[at + 2], datagram[at + 3]]),
        );
        at += 4;
        if flags & FLAG_SEQUENCE != 0 {
            at += 4;
        }
        if flags & FLAG_OFFSET != 0 {
            ensure!(end >= at + 2, "truncated L2TP data message");
            at += 2 + usize::from(u16::from_be_bytes([datagram[at], datagram[at + 1]]));
        }
        if tunnel != self.local_tunnel || session != self.local_session || at > end {
            return Ok(Received::Nothing);
        }
        let mut frame = &datagram[at..end];
        if frame.starts_with(&[0xff, 0x03]) {
            frame = &frame[2..];
        }
        Ok(Received::Ppp(frame.to_vec()))
    }
}

/// The protocol of a PPP frame (possibly compressed to one byte) and its
/// contents.
pub fn ppp_protocol(frame: &[u8]) -> Option<(u16, &[u8])> {
    match frame.first()? {
        b if b & 1 == 1 => Some((u16::from(*b), &frame[1..])),
        _ => Some((u16::from_be_bytes([frame[0], *frame.get(1)?]), &frame[2..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A control message from the server, with its AVPs.
    fn server(tunnel: &Tunnel, ns: u16, nr: u16, message: u16, avps: &[Vec<u8>]) -> Vec<u8> {
        let body = [vec![avp(AVP_MESSAGE_TYPE, &message.to_be_bytes())], avps.to_vec()].concat().concat();
        let mut out = (FLAG_TYPE | FLAG_LENGTH | FLAG_SEQUENCE | VERSION).to_be_bytes().to_vec();
        out.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
        out.extend_from_slice(&tunnel.local_tunnel.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&ns.to_be_bytes());
        out.extend_from_slice(&nr.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn message_type(bytes: &[u8]) -> Option<u16> {
        parse_avps(&bytes[12..]).ok().and_then(|a| u16_value(&a, AVP_MESSAGE_TYPE))
    }

    #[test]
    fn tunnel_and_session() {
        let now = Instant::now();
        let mut t = Tunnel::new(now);
        let out = t.take_output();
        assert_eq!(message_type(&out[0]), Some(SCCRQ));
        let sccrp = server(&t, 0, 1, SCCRP, &[avp(AVP_ASSIGNED_TUNNEL_ID, &77u16.to_be_bytes())]);
        assert!(matches!(t.receive(&sccrp, now).unwrap(), Received::Nothing));
        let out = t.take_output();
        assert_eq!(out.iter().map(|m| message_type(m)).collect::<Vec<_>>(), [Some(SCCCN), Some(ICRQ)]);
        assert_eq!(&out[0][4..6], &77u16.to_be_bytes(), "to the server's tunnel");
        assert_eq!(&out[0][10..12], &1u16.to_be_bytes(), "Nr acknowledges the SCCRP");

        // A duplicate SCCRP (our acknowledgment was lost): acknowledged again.
        assert!(matches!(t.receive(&sccrp, now).unwrap(), Received::Nothing));
        assert_eq!(t.take_output()[0].len(), 12, "a ZLB");

        let icrp = server(&t, 1, 3, ICRP, &[avp(AVP_ASSIGNED_SESSION_ID, &9u16.to_be_bytes())]);
        assert!(matches!(t.receive(&icrp, now).unwrap(), Received::SessionUp));
        assert_eq!(message_type(&t.take_output()[0]), Some(ICCN));
        assert!(t.is_up());

        let data = t.data(0xc021, &[1, 2]);
        assert_eq!(data, [0, 2, 0, 77, 0, 9, 0xff, 0x03, 0xc0, 0x21, 1, 2]);
        let mut theirs = vec![0x40, 0x02, 0, 14];
        theirs.extend_from_slice(&t.local_tunnel.to_be_bytes());
        theirs.extend_from_slice(&t.local_session.to_be_bytes());
        theirs.extend_from_slice(&[0xff, 0x03, 0xc0, 0x21, 9, 9]);
        let Received::Ppp(frame) = t.receive(&theirs, now).unwrap() else { panic!() };
        assert_eq!(ppp_protocol(&frame), Some((0xc021, &[9u8, 9][..])));

        let stop = server(&t, 2, 4, STOP_CCN, &[avp(AVP_RESULT_CODE, &[0, 6, 0, 0, b'b', b'y', b'e'])]);
        let err = t.receive(&stop, now).err().unwrap();
        assert!(err.to_string().contains("result 6: bye"), "{err}");
    }

    #[test]
    fn resends_until_acknowledged() {
        let now = Instant::now();
        let mut t = Tunnel::new(now);
        t.take_output();
        t.tick(now + Duration::from_millis(1100)).unwrap();
        assert_eq!(t.take_output().len(), 1);
        let mut later = now;
        let failed = (0..20).any(|_| {
            later += MAX_RETRANSMIT;
            t.tick(later).is_err()
        });
        assert!(failed, "gives up");
        assert_eq!(ppp_protocol(&[0x21, 0x45]), Some((0x21, &[0x45u8][..])), "compressed protocol field");
    }
}
