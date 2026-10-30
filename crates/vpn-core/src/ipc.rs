//! Control protocol between the CLI or app and the daemon: newline-delimited JSON
//! over a Unix socket. Every connection starts with `Hello`. A `Connect`
//! receives `Attach` (where the session's questions are asked), state
//! changes, then `Done` once the tunnel is up; a `Watch` connection
//! receives every state change of the caller's sessions.
//!
//! Questions never go through the daemon: the session's engine asks them
//! on its prompt socket (`Attach`), readable by the session's owner only.
//! There it sends `Prompt` and `OpenUrl` events and receives `Answer`
//! requests, in the same format as here.

use serde::{Deserialize, Serialize};

use crate::{FailureKind, Profile, Prompt, brand};

/// Bumped on incompatible changes; both sides refuse a different version.
pub const PROTOCOL_VERSION: u32 = 3;

pub fn socket_path() -> String {
    std::env::var(brand::SOCKET_ENV).unwrap_or_else(|_| brand::default_socket())
}

/// The directory of the sessions' prompt sockets, next to the control
/// socket (`/var/run/omnitund.sock` → `/var/run/omnitund`). Owned by root
/// and not writable by anyone else, so nobody can plant a file there.
pub fn prompt_socket_dir(control: &str) -> String {
    match control.strip_suffix(".sock") {
        Some(base) => base.to_owned(),
        None => format!("{control}.d"),
    }
}

/// A session's prompt socket.
pub fn prompt_socket_path(control: &str, session: &str) -> String {
    format!("{}/{session}.sock", prompt_socket_dir(control))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Must be the first request on every connection.
    Hello {
        protocol: u32,
        /// e.g. "omnitunctl", "Omnitun.app".
        client: String,
        version: String,
    },
    Connect {
        profile: Box<Profile>,
        /// The connected session this one goes through (a VPN chain): its
        /// gateway is reached through that session's tunnel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
    },
    /// `id`: the session's profile id.
    Disconnect {
        id: String,
    },
    Status,
    /// Answer to a `Prompt` event, on a prompt socket only; `None` when
    /// the user cancelled.
    Answer {
        id: u64,
        value: Option<String>,
    },
    /// Keep the connection open and receive `State` events for every
    /// session of the caller, after an initial `Status`.
    Watch,
    /// Disconnect everything and exit, so the service manager restarts the
    /// daemon (after an update). Root, or the owner of every session.
    Shutdown,
}

/// Answers carry secrets: they are never written to logs.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Hello { protocol, client, version } => f
                .debug_struct("Hello")
                .field("protocol", protocol)
                .field("client", client)
                .field("version", version)
                .finish(),
            Request::Connect { profile, via } => {
                f.debug_struct("Connect").field("profile", profile).field("via", via).finish()
            }
            Request::Watch => f.write_str("Watch"),
            Request::Shutdown => f.write_str("Shutdown"),
            Request::Disconnect { id } => f.debug_struct("Disconnect").field("id", id).finish(),
            Request::Status => f.write_str("Status"),
            Request::Answer { id, value } => {
                f.debug_struct("Answer").field("id", id).field("value", &value.as_ref().map(|_| "<redacted>")).finish()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// After `Connect`: the session's prompt socket, to connect to for its
    /// questions (also later, to answer a reconnection's code).
    Attach {
        socket: String,
    },
    Hello {
        protocol: u32,
        version: String,
        /// Optional capabilities, for clients newer than the daemon.
        features: Vec<String>,
    },
    Prompt {
        id: u64,
        prompt: Prompt,
    },
    OpenUrl {
        url: String,
    },
    State {
        /// The session's profile id.
        id: String,
        state: SessionState,
        detail: Option<String>,
        /// Why it failed or is reconnecting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<FailureKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry: Option<Retry>,
    },
    Warning {
        message: String,
    },
    Status {
        sessions: Vec<SessionInfo>,
    },
    Done,
    Error {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<FailureKind>,
    },
}

impl Event {
    pub fn error(message: impl Into<String>) -> Self {
        Event::Error { message: message.into(), failure: None }
    }
}

/// A scheduled reconnection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retry {
    pub attempt: u32,
    pub max: u32,
    pub delay_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// The profile's id: the session's key.
    pub id: String,
    /// The profile's name, for people.
    pub name: String,
    pub protocol: String,
    pub state: SessionState,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub full_tunnel: bool,
    pub routes: Vec<String>,
    pub dns_domains: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Unix time the tunnel came up.
    pub connected_since: Option<u64>,
    /// Why the session is reconnecting or failed.
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub failure: Option<FailureKind>,
    /// The session it goes through, if chained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Outer address of the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Name servers given by the gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<String>,
    /// Networks kept outside the tunnel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_routes: Vec<String>,
    /// Unix time the current tunnel came up (`connected_since` is the
    /// first one, before any reconnection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_since: Option<u64>,
    /// Reconnection attempts after the tunnel dropped.
    #[serde(default)]
    pub reconnects: u32,
    /// Unix time and cause of the last drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_drop: Option<(u64, String)>,
    /// Addresses routed by domain now (#37).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dynamic_routes: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_not_logged() {
        let text = format!("{:?}", Request::Answer { id: 7, value: Some("hunter2".into()) });
        assert!(!text.contains("hunter2"), "{text}");
    }
}
