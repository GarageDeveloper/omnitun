//! The last L2TP and PPP exchanges of a session, written to the log when
//! it ends: why a tunnel went silent is in what came (or stopped coming)
//! just before. IP traffic is only counted.

use std::collections::VecDeque;
use std::time::Instant;

use tracing::info;

use crate::l2tp::ppp_protocol;
use crate::ppp;

/// Events kept.
const KEEP: usize = 80;
/// Events per log line (lines are cut at 2 KiB by the service).
const PER_LINE: usize = 8;

#[derive(Clone, Copy)]
pub enum Direction {
    In,
    Out,
}

#[derive(Default)]
struct Traffic {
    packets: u64,
    last: Option<Instant>,
}

pub struct Recorder {
    started: Instant,
    events: VecDeque<(Instant, Direction, String)>,
    ip_in: Traffic,
    ip_out: Traffic,
    reported: bool,
}

impl Recorder {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            events: VecDeque::new(),
            ip_in: Traffic::default(),
            ip_out: Traffic::default(),
            reported: false,
        }
    }

    /// An L2TP datagram (UDP payload) that came in or went out.
    pub fn record(&mut self, direction: Direction, datagram: &[u8]) {
        let now = Instant::now();
        match describe(datagram) {
            Some(text) => {
                if self.events.len() == KEEP {
                    self.events.pop_front();
                }
                self.events.push_back((now, direction, text));
            }
            None => {
                let traffic = match direction {
                    Direction::In => &mut self.ip_in,
                    Direction::Out => &mut self.ip_out,
                };
                traffic.packets += 1;
                traffic.last = Some(now);
            }
        }
    }

    /// Writes the record to the log, once per session.
    pub fn report(&mut self, why: &str) {
        if self.reported {
            return;
        }
        self.reported = true;
        let now = Instant::now();
        let ago = |at: Option<Instant>| at.map(|t| format!("{} s ago", now.duration_since(t).as_secs()));
        info!(
            reason = why,
            age_s = now.duration_since(self.started).as_secs(),
            ip_in = self.ip_in.packets,
            last_ip_in = ago(self.ip_in.last).as_deref().unwrap_or("never"),
            ip_out = self.ip_out.packets,
            last_ip_out = ago(self.ip_out.last).as_deref().unwrap_or("never"),
            "L2TP/PPP at the end of the session; last exchanges follow"
        );
        // A few events per line: the service keeps at most 50 lines a
        // second from an engine, and the newest events matter most.
        let events: Vec<String> = self
            .events
            .iter()
            .map(|(at, direction, text)| {
                let arrow = match direction {
                    Direction::In => "<-",
                    Direction::Out => "->",
                };
                format!("-{}s {arrow} {text}", now.duration_since(*at).as_secs())
            })
            .collect();
        for chunk in events.chunks(PER_LINE) {
            info!("  {}", chunk.join(" | "));
        }
    }
}

/// An L2TP datagram in a few words; `None` for IP traffic.
fn describe(datagram: &[u8]) -> Option<String> {
    let word = |at: usize| datagram.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let flags = word(0)?;
    if flags & 0x8000 != 0 {
        let (tunnel, session, ns, nr) = (word(4)?, word(6)?, word(8)?, word(10)?);
        let len = usize::from(word(2)?).min(datagram.len());
        if len <= 12 {
            return Some(format!("L2TP ZLB ack tunnel={tunnel} ns={ns} nr={nr}"));
        }
        // The first AVP (flags and length, vendor, type) is the message
        // type: its value follows.
        let kind = match word(18)? {
            1 => "SCCRQ",
            2 => "SCCRP",
            3 => "SCCCN",
            4 => "StopCCN",
            6 => "HELLO",
            10 => "ICRQ",
            11 => "ICRP",
            12 => "ICCN",
            14 => "CDN",
            _ => "control",
        };
        return Some(format!("L2TP {kind} tunnel={tunnel} session={session} ns={ns} nr={nr}"));
    }
    let mut at = 2;
    let mut end = datagram.len();
    if flags & 0x4000 != 0 {
        end = usize::from(word(2)?).min(end);
        at += 2;
    }
    let (tunnel, session) = (word(at)?, word(at + 2)?);
    at += 4;
    if flags & 0x0800 != 0 {
        at += 4;
    }
    if flags & 0x0200 != 0 {
        at += 2 + usize::from(word(at)?);
    }
    let mut frame = datagram.get(at..end)?;
    if frame.starts_with(&[0xff, 0x03]) {
        frame = &frame[2..];
    }
    let (protocol, contents) = ppp_protocol(frame)?;
    let name = match protocol {
        ppp::IP => return None,
        ppp::LCP => "LCP",
        ppp::IPCP => "IPCP",
        ppp::PAP => "PAP",
        ppp::CHAP => "CHAP",
        0x8057 => "IPV6CP",
        _ => return Some(format!("PPP protocol {protocol:#06x} tunnel={tunnel} session={session}")),
    };
    let code = match (protocol, contents.first()?) {
        (ppp::LCP | ppp::IPCP | 0x8057, 1) => "ConfReq",
        (ppp::LCP | ppp::IPCP | 0x8057, 2) => "ConfAck",
        (ppp::LCP | ppp::IPCP | 0x8057, 3) => "ConfNak",
        (ppp::LCP | ppp::IPCP | 0x8057, 4) => "ConfRej",
        (ppp::LCP | ppp::IPCP | 0x8057, 5) => "TermReq",
        (ppp::LCP | ppp::IPCP | 0x8057, 6) => "TermAck",
        (ppp::LCP | ppp::IPCP | 0x8057, 7) => "CodeRej",
        (ppp::LCP, 8) => "ProtRej",
        (ppp::LCP, 9) => "EchoReq",
        (ppp::LCP, 10) => "EchoRep",
        (ppp::LCP, 11) => "DiscardReq",
        _ => "message",
    };
    let id = contents.get(1).copied().unwrap_or(0);
    Some(format!("PPP {name} {code} id={id} tunnel={tunnel} session={session}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions() {
        // HELLO: header (flags T L S, version 2), then the Message Type AVP.
        let hello = [0xc8, 0x02, 0, 20, 0, 7, 0, 0, 0, 3, 0, 5, 0x80, 8, 0, 0, 0, 0, 0, 6];
        assert_eq!(describe(&hello).unwrap(), "L2TP HELLO tunnel=7 session=0 ns=3 nr=5");
        let zlb = [0xc8, 0x02, 0, 12, 0, 7, 0, 0, 0, 3, 0, 5];
        assert_eq!(describe(&zlb).unwrap(), "L2TP ZLB ack tunnel=7 ns=3 nr=5");
        // Data, PPP LCP Echo-Request.
        let echo = [0x00, 0x02, 0, 7, 0, 9, 0xff, 0x03, 0xc0, 0x21, 9, 4, 0, 8, 1, 2, 3, 4];
        assert_eq!(describe(&echo).unwrap(), "PPP LCP EchoReq id=4 tunnel=7 session=9");
        let ip = [0x00, 0x02, 0, 7, 0, 9, 0xff, 0x03, 0x00, 0x21, 0x45];
        assert!(describe(&ip).is_none());
    }
}
