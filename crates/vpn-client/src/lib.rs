//! User-side half of the client, shared by `omnitunctl` and the desktop app:
//! the profiles file, secrets in the OS keychain, and the conversation with
//! `omnitund` (prompts, certificate trust, browser login).

pub mod client_key;
pub mod daemon;
pub mod diagnostic;
pub mod import;
pub mod keychain;
pub mod profiles;
pub mod secrets;
pub mod service_log;
pub mod session;
pub mod vpnprofile;

pub use daemon::Daemon;
pub use profiles::ProfileStore;
pub use session::{ConnectOptions, Connected, Interaction, Notice, Trust, connect, connect_with};

/// Gateway-supplied text may carry terminal escape sequences, invisible
/// or reordering characters, or pages of text.
pub fn printable(text: &str) -> String {
    const MAX: usize = 1000;
    let mut out: String = text.chars().filter(|c| !c.is_control() && !vpn_core::is_invisible(*c)).take(MAX).collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out
}
