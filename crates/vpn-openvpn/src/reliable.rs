//! The reliability layer of one key state: control messages are numbered,
//! acknowledged, resent until acknowledged (over UDP) and delivered in
//! order.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Messages in flight before waiting for acknowledgments (OpenVPN keeps
/// 6 send buffers).
const SEND_WINDOW: u32 = 6;
/// Messages ahead of the next expected one that are kept (12 receive
/// buffers in OpenVPN).
const RECEIVE_WINDOW: u32 = 12;
const FIRST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_TIMEOUT: Duration = Duration::from_secs(16);

struct InFlight {
    opcode: u8,
    payload: Vec<u8>,
    due: Instant,
    timeout: Duration,
}

pub struct Reliable {
    next_id: u32,
    in_flight: BTreeMap<u32, InFlight>,
    queued: VecDeque<(u8, Vec<u8>)>,
    expected: u32,
    early: BTreeMap<u32, (u8, Vec<u8>)>,
    acks: Vec<u32>,
    /// Over TCP nothing is lost: no resend.
    resend: bool,
}

/// A message to put on the wire.
pub struct Outgoing {
    pub id: u32,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Reliable {
    pub fn new(resend: bool) -> Self {
        Self {
            next_id: 0,
            in_flight: BTreeMap::new(),
            queued: VecDeque::new(),
            expected: 0,
            early: BTreeMap::new(),
            acks: Vec::new(),
            resend,
        }
    }

    pub fn push(&mut self, opcode: u8, payload: Vec<u8>) {
        self.queued.push_back((opcode, payload));
    }

    /// New messages the window allows, and those to send again.
    pub fn due(&mut self, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for (id, m) in &mut self.in_flight {
            if self.resend && m.due <= now {
                m.timeout = (m.timeout * 2).min(MAX_TIMEOUT);
                m.due = now + m.timeout;
                out.push(Outgoing { id: *id, opcode: m.opcode, payload: m.payload.clone() });
            }
        }
        let oldest = self.in_flight.keys().next().copied().unwrap_or(self.next_id);
        while self.next_id - oldest < SEND_WINDOW
            && let Some((opcode, payload)) = self.queued.pop_front()
        {
            let id = self.next_id;
            self.next_id += 1;
            out.push(Outgoing { id, opcode, payload: payload.clone() });
            self.in_flight.insert(id, InFlight { opcode, payload, due: now + FIRST_TIMEOUT, timeout: FIRST_TIMEOUT });
        }
        out
    }

    /// When a resend will be due.
    pub fn next_due(&self) -> Option<Instant> {
        self.resend.then(|| self.in_flight.values().map(|m| m.due).min()).flatten()
    }

    pub fn acknowledged(&mut self, ids: &[u32]) {
        for id in ids {
            self.in_flight.remove(id);
        }
    }

    /// Takes a received message; returns those now deliverable in order.
    /// Every message is acknowledged, duplicates included (the first
    /// acknowledgment may have been lost).
    pub fn receive(&mut self, id: u32, opcode: u8, payload: Vec<u8>) -> Vec<(u8, Vec<u8>)> {
        if id >= self.expected.saturating_add(RECEIVE_WINDOW) {
            return Vec::new();
        }
        if !self.acks.contains(&id) {
            self.acks.push(id);
        }
        if id < self.expected {
            return Vec::new();
        }
        self.early.insert(id, (opcode, payload));
        let mut ready = Vec::new();
        while let Some(message) = self.early.remove(&self.expected) {
            ready.push(message);
            self.expected += 1;
        }
        ready
    }

    pub fn has_acks(&self) -> bool {
        !self.acks.is_empty()
    }

    pub fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let n = self.acks.len().min(max);
        self.acks.drain(..n).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_resend_and_order() {
        let now = Instant::now();
        let mut r = Reliable::new(true);
        for i in 0..8u8 {
            r.push(4, vec![i]);
        }
        let first = r.due(now);
        assert_eq!(first.iter().map(|m| m.id).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5], "window of 6");
        assert!(r.due(now).is_empty());
        r.acknowledged(&[0, 1]);
        assert_eq!(r.due(now).iter().map(|m| m.id).collect::<Vec<_>>(), [6, 7]);
        let again = r.due(now + Duration::from_secs(3));
        assert_eq!(again.len(), 6, "2..7 sent again");
        r.acknowledged(&[2, 3, 4, 5, 6, 7]);
        assert!(r.in_flight.is_empty() && r.queued.is_empty());

        let mut r = Reliable::new(false);
        assert!(r.receive(1, 4, b"b".to_vec()).is_empty());
        assert_eq!(r.receive(0, 4, b"a".to_vec()), [(4, b"a".to_vec()), (4, b"b".to_vec())]);
        assert!(r.receive(0, 4, b"a".to_vec()).is_empty(), "duplicate");
        assert!(r.receive(100, 4, b"far".to_vec()).is_empty());
        assert_eq!(r.take_acks(4), [1, 0]);
        assert!(!r.has_acks());
    }
}
