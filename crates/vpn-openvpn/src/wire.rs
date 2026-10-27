//! Packet layout: the opcode byte (opcode << 3 | key id), then for control
//! packets the sender's session id, the acknowledgments and, except in a
//! bare ACK, the message id and payload.

use anyhow::{Context, ensure};

pub const SOFT_RESET_V1: u8 = 3;
pub const CONTROL_V1: u8 = 4;
pub const ACK_V1: u8 = 5;
pub const DATA_V1: u8 = 6;
pub const HARD_RESET_CLIENT_V2: u8 = 7;
pub const HARD_RESET_SERVER_V2: u8 = 8;
pub const DATA_V2: u8 = 9;

pub type SessionId = [u8; 8];

pub fn opcode(byte: u8) -> u8 {
    byte >> 3
}

pub fn key_id(byte: u8) -> u8 {
    byte & 7
}

pub fn header_byte(opcode: u8, key_id: u8) -> u8 {
    opcode << 3 | key_id
}

/// Acknowledgments carried by one packet; OpenVPN reads at most 8, some
/// servers (SoftEther) only 4.
pub const MAX_ACKS: usize = 4;

/// A control packet, once unwrapped, without its header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlBody {
    pub acks: Vec<u32>,
    /// The session the acknowledgments are for: ours.
    pub acked_session: Option<SessionId>,
    /// None in a bare ACK.
    pub message_id: Option<u32>,
    pub payload: Vec<u8>,
}

impl ControlBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 * self.acks.len() + 8 + 4 + self.payload.len());
        out.push(self.acks.len() as u8);
        for ack in &self.acks {
            out.extend_from_slice(&ack.to_be_bytes());
        }
        if !self.acks.is_empty() {
            out.extend_from_slice(&self.acked_session.expect("acknowledgments name a session"));
        }
        if let Some(id) = self.message_id {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&self.payload);
        }
        out
    }

    pub fn decode(opcode: u8, data: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader(data);
        let count = r.u8()? as usize;
        ensure!(count <= 8, "too many acknowledgments in a control packet");
        let acks = (0..count).map(|_| r.u32()).collect::<anyhow::Result<Vec<_>>>()?;
        let acked_session = if count > 0 { Some(r.take(8)?.try_into().unwrap()) } else { None };
        let (message_id, payload) = if opcode == ACK_V1 {
            ensure!(r.0.is_empty(), "trailing bytes in an ACK");
            (None, Vec::new())
        } else {
            (Some(r.u32()?), r.0.to_vec())
        };
        Ok(Self { acks, acked_session, message_id, payload })
    }
}

/// A cursor over received bytes.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "truncated message");
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// A string with a 16-bit length that counts its final NUL.
    pub fn string(&mut self) -> anyhow::Result<String> {
        let len = self.u16()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let bytes = self.take(len)?;
        let text = bytes.strip_suffix(&[0]).context("string without its final NUL")?;
        Ok(String::from_utf8_lossy(text).into_owned())
    }
}

/// Writes a string as `Reader::string` reads it.
pub fn put_string(out: &mut Vec<u8>, text: &str) {
    if text.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
        return;
    }
    out.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_bodies_round_trip() {
        let body = ControlBody {
            acks: vec![0, 1],
            acked_session: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            message_id: Some(2),
            payload: b"tls".to_vec(),
        };
        assert_eq!(ControlBody::decode(CONTROL_V1, &body.encode()).unwrap(), body);
        let ack = ControlBody { acks: vec![5], acked_session: Some([9; 8]), ..Default::default() };
        assert_eq!(ControlBody::decode(ACK_V1, &ack.encode()).unwrap(), ack);
        assert!(ControlBody::decode(CONTROL_V1, &[9]).is_err());
        assert!(ControlBody::decode(CONTROL_V1, &[1, 0, 0]).is_err());
    }

    #[test]
    fn strings() {
        let mut out = Vec::new();
        put_string(&mut out, "V4,dev-type tun");
        put_string(&mut out, "");
        let mut r = Reader(&out);
        assert_eq!((r.string().unwrap().as_str(), r.string().unwrap().as_str()), ("V4,dev-type tun", ""));
        assert!(Reader(&[0, 3, b'a', b'b', b'c']).string().is_err(), "no NUL");
    }
}
