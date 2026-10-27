//! The control channel: one TLS session per key state, carried by the
//! reliability layer inside wrapped control packets. Each key state ends
//! with key method 2: both sides send random material (and we our
//! credentials), from which the data channel keys are derived.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use vpn_core::{FailureKind, failure};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{DataCipher, DataKeys, EKM_LABEL, KeySource, Wrap, prf_key_block};
use crate::reliable::Reliable;
use crate::tls::TlsSetup;
use crate::wire::{self, ControlBody, Reader, SessionId};

/// TLS bytes per control packet: below the 1250 bytes OpenVPN servers
/// expect, wrapping included.
const CHUNK: usize = 1000;
/// Longest plaintext kept while waiting for a message's end.
const MAX_PLAINTEXT: usize = 64 * 1024;

/// What we send in key method 2.
pub struct Hello {
    /// The OCC options string.
    pub options: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub peer_info: String,
}

/// A control packet that fails its checks: dropped, the session goes on.
#[derive(Debug)]
pub struct BadPacket(pub String);

impl std::fmt::Display for BadPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BadPacket {}

pub enum Event {
    /// Both sides' key material is in: keys can be derived.
    KeyExchanged(u8),
    /// A text message (`PUSH_REPLY,…`, `AUTH_FAILED`, …).
    Message(String),
}

pub struct KeyState {
    pub key_id: u8,
    reliable: Reliable,
    tls: ClientConnection,
    reset_received: bool,
    hello_sent: bool,
    source: KeySource,
    server_random: Option<ServerRandom>,
    plaintext: Zeroizing<Vec<u8>>,
    pub data: Option<DataKeys>,
    pub started: Instant,
    /// Lame duck: kept to decrypt until then.
    pub retire_at: Option<Instant>,
}

impl KeyState {
    pub fn negotiated(&self) -> bool {
        self.server_random.is_some()
    }

    /// Derives the data channel keys from the exchanged material, or from
    /// the TLS exporter (`key-derivation tls-ekm`).
    pub fn derive(&mut self, cipher: DataCipher, ekm: bool, sessions: (&SessionId, &SessionId)) -> anyhow::Result<()> {
        let (r1, r2) = self.server_random.context("key material not exchanged")?;
        let block = if ekm {
            let mut block = Zeroizing::new([0u8; 256]);
            self.tls
                .export_keying_material(&mut *block, EKM_LABEL, None)
                .map_err(|e| anyhow::anyhow!("TLS key export failed: {e}"))?;
            block
        } else {
            prf_key_block(&self.source, &r1, &r2, sessions.0, sessions.1)
        };
        self.data = Some(DataKeys::new(cipher, &block)?);
        Ok(())
    }
}

pub struct Control {
    wrap: Wrap,
    pub local_sid: SessionId,
    pub remote_sid: Option<SessionId>,
    pub keys: Vec<KeyState>,
    tls: TlsSetup,
    server_name: ServerName<'static>,
    resend: bool,
    pub hello: Hello,
}

impl Control {
    /// Starts key state 0 with a hard reset.
    pub fn new(
        wrap: Wrap,
        tls: TlsSetup,
        server_name: ServerName<'static>,
        resend: bool,
        hello: Hello,
    ) -> anyhow::Result<Self> {
        let mut control = Self {
            wrap,
            local_sid: rand::random(),
            remote_sid: None,
            keys: Vec::new(),
            tls,
            server_name,
            resend,
            hello,
        };
        control.add_key(0, wire::HARD_RESET_CLIENT_V2)?;
        Ok(control)
    }

    fn add_key(&mut self, key_id: u8, reset: u8) -> anyhow::Result<&mut KeyState> {
        let tls =
            ClientConnection::new(self.tls.config.clone(), self.server_name.clone()).context("cannot start TLS")?;
        let mut reliable = Reliable::new(self.resend);
        reliable.push(reset, Vec::new());
        self.keys.push(KeyState {
            key_id,
            reliable,
            tls,
            reset_received: false,
            hello_sent: false,
            source: KeySource { pre_master: rand::random(), random1: rand::random(), random2: rand::random() },
            server_random: None,
            plaintext: Zeroizing::new(Vec::new()),
            data: None,
            started: Instant::now(),
            retire_at: None,
        });
        Ok(self.keys.last_mut().unwrap())
    }

    /// Starts a new key state (1 to 7, never 0 again): renegotiation.
    pub fn renegotiate(&mut self) -> anyhow::Result<u8> {
        let current = self.keys.iter().map(|k| k.key_id).max().unwrap_or(0);
        let key_id = if current >= 7 { 1 } else { current + 1 };
        self.keys.retain(|k| k.key_id != key_id);
        self.add_key(key_id, wire::SOFT_RESET_V1)?;
        Ok(key_id)
    }

    pub fn key(&mut self, key_id: u8) -> Option<&mut KeyState> {
        self.keys.iter_mut().find(|k| k.key_id == key_id)
    }

    /// The key state that carries data now: the newest with keys.
    pub fn primary(&mut self) -> Option<&mut KeyState> {
        self.keys.iter_mut().filter(|k| k.data.is_some()).max_by_key(|k| k.started)
    }

    pub fn sessions(&self) -> (SessionId, SessionId) {
        (self.local_sid, self.remote_sid.unwrap_or_default())
    }

    /// Sends a text message on the key state's TLS session.
    pub fn send_message(&mut self, key_id: u8, text: &str) -> anyhow::Result<()> {
        let key = self.key(key_id).context("no such key state")?;
        key.tls.writer().write_all(text.as_bytes())?;
        key.tls.writer().write_all(&[0])?;
        Ok(())
    }

    /// Handles a received control packet.
    pub fn receive(&mut self, packet: &[u8]) -> anyhow::Result<Vec<Event>> {
        let (opcode, key_id) = (wire::opcode(packet[0]), wire::key_id(packet[0]));
        let bad = |e: anyhow::Error| anyhow::Error::from(BadPacket(format!("{e:#}")));
        let (body, pid) = self.wrap.open(packet).map_err(bad)?;
        let sender: SessionId = packet[1..9].try_into().unwrap();
        let body = ControlBody::decode(opcode, &body).map_err(bad)?;
        match self.remote_sid {
            None if opcode == wire::HARD_RESET_SERVER_V2 => self.remote_sid = Some(sender),
            Some(sid) if sid == sender => {}
            _ => {
                tracing::debug!("control packet from another session ignored");
                return Ok(Vec::new());
            }
        }
        self.wrap.accept(pid);
        if !body.acks.is_empty() && body.acked_session != Some(self.local_sid) {
            tracing::debug!("acknowledgments for another session ignored");
            return Ok(Vec::new());
        }
        if self.key(key_id).is_none() {
            if opcode != wire::SOFT_RESET_V1 || key_id == 0 {
                tracing::debug!(key_id, opcode, "packet for an unknown key state ignored");
                return Ok(Vec::new());
            }
            // The server renegotiates.
            tracing::info!(key_id, "the server renegotiates the keys");
            self.add_key(key_id, wire::SOFT_RESET_V1)?;
        }
        let rejected = self.tls.rejected.clone();
        let sign_error = self.tls.sign_error.clone();
        let hello = &self.hello;
        let key = self.keys.iter_mut().find(|k| k.key_id == key_id).unwrap();
        key.reliable.acknowledged(&body.acks);
        let Some(id) = body.message_id else { return Ok(Vec::new()) };
        let mut events = Vec::new();
        for (opcode, payload) in key.reliable.receive(id, opcode, body.payload) {
            match opcode {
                wire::HARD_RESET_SERVER_V2 | wire::SOFT_RESET_V1 => key.reset_received = true,
                wire::CONTROL_V1 if key.reset_received => {
                    let mut input = payload.as_slice();
                    while !input.is_empty() {
                        key.tls.read_tls(&mut input)?;
                        if let Err(e) = key.tls.process_new_packets() {
                            if let Some(error) = sign_error.lock().unwrap().take() {
                                return Err(error.context("cannot sign with the client certificate"));
                            }
                            if let Some(reason) = rejected.lock().unwrap().take() {
                                return Err(failure(FailureKind::Other, reason));
                            }
                            return Err(tls_failure(e));
                        }
                    }
                    if !key.tls.is_handshaking() && !key.hello_sent {
                        let message = key_method_2(&key.source, hello);
                        key.tls.writer().write_all(&message)?;
                        key.hello_sent = true;
                    }
                    read_plaintext(key, &mut events)?;
                }
                _ => tracing::debug!(opcode, "unexpected control message ignored"),
            }
        }
        Ok(events)
    }

    /// Packets to send now: TLS output, resends, acknowledgments.
    pub fn outgoing(&mut self, now: Instant) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        for key in &mut self.keys {
            if key.reset_received {
                let mut out = Vec::new();
                while key.tls.wants_write() {
                    key.tls.write_tls(&mut out)?;
                }
                for chunk in out.chunks(CHUNK) {
                    key.reliable.push(wire::CONTROL_V1, chunk.to_vec());
                }
            }
            for message in key.reliable.due(now) {
                let acks = if self.remote_sid.is_some() { key.reliable.take_acks(wire::MAX_ACKS) } else { Vec::new() };
                let body = ControlBody {
                    acked_session: (!acks.is_empty()).then_some(self.remote_sid).flatten(),
                    acks,
                    message_id: Some(message.id),
                    payload: message.payload,
                };
                packets.push(seal(&mut self.wrap, message.opcode, key.key_id, &self.local_sid, &body));
            }
            while self.remote_sid.is_some() && key.reliable.has_acks() {
                let acks = key.reliable.take_acks(wire::MAX_ACKS);
                let body = ControlBody { acks, acked_session: self.remote_sid, ..Default::default() };
                packets.push(seal(&mut self.wrap, wire::ACK_V1, key.key_id, &self.local_sid, &body));
            }
        }
        Ok(packets)
    }

    /// When a resend is due.
    pub fn next_due(&self) -> Option<Instant> {
        self.keys.iter().filter_map(|k| k.reliable.next_due()).min()
    }
}

fn seal(wrap: &mut Wrap, opcode: u8, key_id: u8, sid: &SessionId, body: &ControlBody) -> Vec<u8> {
    let mut header = [0u8; crate::crypto::HEADER_LEN];
    header[0] = wire::header_byte(opcode, key_id);
    header[1..].copy_from_slice(sid);
    wrap.seal(&header, &body.encode())
}

fn tls_failure(error: rustls::Error) -> anyhow::Error {
    let text = match &error {
        rustls::Error::AlertReceived(alert) => format!(
            "the server ended the TLS handshake ({alert:?}): it may require a client certificate, \
             or refuse ours"
        ),
        e => format!("TLS handshake with the server failed: {e}"),
    };
    failure(FailureKind::Other, text)
}

/// Our key method 2 message: a zero, the method, our key material, the
/// options string, the credentials and the peer info.
fn key_method_2(source: &KeySource, hello: &Hello) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(2);
    out.extend_from_slice(&source.pre_master);
    out.extend_from_slice(&source.random1);
    out.extend_from_slice(&source.random2);
    wire::put_string(&mut out, &hello.options);
    wire::put_string(&mut out, &hello.username);
    wire::put_string(&mut out, &hello.password);
    wire::put_string(&mut out, &hello.peer_info);
    out
}

/// The server's random1 and random2.
type ServerRandom = ([u8; 32], [u8; 32]);

/// The server's key method 2 message, if complete: its randoms and the
/// bytes it took.
fn server_key_method_2(data: &[u8]) -> anyhow::Result<Option<(ServerRandom, usize)>> {
    let mut r = Reader(data);
    let parse = |r: &mut Reader| -> anyhow::Result<ServerRandom> {
        ensure!(r.u32()? == 0, "unexpected key method message");
        ensure!(r.u8()? & 0x0f == 2, "the server does not use key method 2");
        let random1 = r.take(32)?.try_into().unwrap();
        let random2 = r.take(32)?.try_into().unwrap();
        let options = r.string()?;
        tracing::debug!("server options: {options}");
        for _ in 0..3 {
            r.string()?; // user name, password, peer info: empty
        }
        Ok((random1, random2))
    };
    match parse(&mut r) {
        Ok(randoms) => Ok(Some((randoms, data.len() - r.0.len()))),
        Err(e) if e.to_string() == "truncated message" => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_plaintext(key: &mut KeyState, events: &mut Vec<Event>) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        match key.tls.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => key.plaintext.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => bail!("TLS: {e}"),
        }
    }
    buf.zeroize();
    ensure!(key.plaintext.len() <= MAX_PLAINTEXT, "the server sent an oversized control message");
    if key.server_random.is_none() {
        let Some((randoms, used)) = server_key_method_2(&key.plaintext)? else { return Ok(()) };
        key.server_random = Some(randoms);
        key.plaintext.drain(..used);
        tracing::info!(
            key_id = key.key_id,
            version = ?key.tls.protocol_version(),
            suite = ?key.tls.negotiated_cipher_suite().map(|s| s.suite()),
            "OpenVPN control channel keys exchanged"
        );
        events.push(Event::KeyExchanged(key.key_id));
    }
    while let Some(end) = key.plaintext.iter().position(|b| *b == 0) {
        let text = String::from_utf8_lossy(&key.plaintext[..end]).into_owned();
        key.plaintext.drain(..=end);
        if !text.is_empty() {
            events.push(Event::Message(text));
        }
    }
    Ok(())
}

/// How long a key negotiation may take (OpenVPN's `hand-window`).
pub const HAND_WINDOW: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_key_material() {
        let mut message = vec![0, 0, 0, 0, 2];
        message.extend_from_slice(&[1; 32]);
        message.extend_from_slice(&[2; 32]);
        wire::put_string(&mut message, "V4,dev-type tun");
        assert!(server_key_method_2(&message).unwrap().is_none(), "strings missing");
        for _ in 0..3 {
            wire::put_string(&mut message, "");
        }
        let full = message.len();
        message.extend_from_slice(b"PUSH_REPLY\0");
        let ((r1, r2), used) = server_key_method_2(&message).unwrap().unwrap();
        assert_eq!((r1, r2, used), ([1; 32], [2; 32], full));
        message[4] = 1;
        assert!(server_key_method_2(&message).is_err(), "key method 1");
    }
}
