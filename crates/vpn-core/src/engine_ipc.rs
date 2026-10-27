//! Protocol between `omnitund` (root) and an engine process (unprivileged,
//! sandboxed): one engine per session, one `Start` per connection attempt.
//! Newline-delimited JSON on a control socket; the tun descriptor travels
//! on a second socket as SCM_RIGHTS, announced by `ToEngine::Tun`. The
//! user's answers never come this way: the engine asks on its own prompt
//! socket (see `ipc`).
//!
//! The engine is untrusted from the daemon's point of view: everything it
//! sends is validated there (settings bounds, domain syntax, conflicts).

use serde::{Deserialize, Serialize};

use crate::{FailureKind, Profile, TunnelSettings};

/// Longest control line accepted from either side.
pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ToEngine {
    /// A connection attempt for this profile (certificate files inlined).
    /// `attach_wait_ms`: how long a question waits for the client to attach
    /// to the prompt socket; zero for reconnections, which use remembered
    /// answers or an already attached client.
    Start { profile: Box<Profile>, attach_wait_ms: u64 },
    /// The tun interface for the negotiated settings; its descriptor
    /// follows on the descriptor socket.
    Tun { name: String },
    /// End the current attempt (log out); the engine stays for the next.
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum FromEngine {
    /// Authenticated and negotiated: waiting for `Tun`.
    Connected { settings: TunnelSettings },
    /// Counters of this attempt, from zero.
    Stats { rx_bytes: u64, tx_bytes: u64, rx_packets: u64, tx_packets: u64 },
    /// The attempt is over: the connection failed, the tunnel dropped
    /// (`error`), or it was stopped (`None`).
    Ended { error: Option<EngineError> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineError {
    pub failure: FailureKind,
    pub message: String,
}
