//! OS integration: one tun interface per session, routes and split DNS
//! (macOS: `route` + `scutil`; Linux: `ip` + `resolvectl`), and a registry
//! that keeps concurrent sessions from stepping on each other.

mod cmd;
pub mod conflicts;
pub mod fdpass;
mod journal;
mod netconfig;
mod tun;

pub use conflicts::{Claims, Conflict, Registry};
pub use netconfig::{AppliedConfig, apply, cleanup_stale};
pub use tun::{TunDevice, TunInterface, attach, create, create_device};

/// Session names end up in interface keys and command arguments.
pub fn valid_session_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 36 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
