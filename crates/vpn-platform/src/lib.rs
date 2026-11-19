//! OS integration: one tun interface per session, routes and split DNS
//! (macOS: `route` + `scutil`; Linux: `ip` + `resolvectl`; Windows: the IP
//! Helper API and the NRPT), and a registry that keeps concurrent sessions
//! from stepping on each other.

#[cfg(unix)]
mod cmd;
pub mod conflicts;
pub mod dynamic;
#[cfg(unix)]
pub mod fdpass;
mod journal;
mod netconfig;
mod runtime;
mod tun;

pub use conflicts::{Claims, Conflict, Registry};
pub use dynamic::Direction;
pub use netconfig::{AppliedConfig, DynamicClaims, Through, apply, cleanup_stale, current_resolvers};
pub use runtime::prepare_runtime_dir;
#[cfg(windows)]
pub use tun::TunPackets;
#[cfg(unix)]
pub use tun::attach;
pub use tun::{TunDevice, TunInterface, create, create_device};

/// Session names end up in interface keys and command arguments.
pub fn valid_session_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 36 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
