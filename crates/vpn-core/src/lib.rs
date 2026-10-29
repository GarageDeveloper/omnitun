//! Shared types for the VPN client: the protocol `Engine` trait, tunnel
//! settings handed to the platform layer, connection profiles and the
//! prompt interface used for interactive authentication.

pub mod brand;

/// The commit built, given by apple/package.sh (`OMNITUN_COMMIT`); absent
/// from a plain `cargo build`.
pub const COMMIT: Option<&str> = option_env!("OMNITUN_COMMIT");

/// "0.1.0 (a9c0a22)", or "0.1.0" without a commit: for people, never
/// compared.
pub fn version() -> String {
    match COMMIT {
        Some(commit) => format!("{} ({commit})", env!("CARGO_PKG_VERSION")),
        None => env!("CARGO_PKG_VERSION").to_owned(),
    }
}
pub mod engine;
pub mod engine_ipc;
pub mod failure;
pub mod ipc;
pub mod l2tp;
pub mod net;
pub mod noted;
pub mod openvpn;
pub mod profile;
pub mod prompt;
pub mod settings;
pub mod wireguard;

pub use engine::{Engine, PacketIo, SessionContext, TunnelStats};
pub use failure::{CertificateInfo, Failure, FailureExt, FailureKind, failure};
pub use l2tp::{L2TP_PORT, L2tpProfile, PppAuth};
pub use noted::Noted;
pub use openvpn::{
    Compression, ControlChannel, OpenVpnProfile, OpenVpnRemote, StaticChallenge, Transport, X509NameCheck, X509NameKind,
};
pub use profile::{
    ExchangeMode, FortiSslAuth, FortiSslProfile, GatewayAuth, IpsecProfile, LEGACY_ALGORITHMS, Profile, ProfileFile,
    ProtocolConfig, is_invisible, new_id, valid_id,
};
pub use prompt::{Prompt, PromptKind, Prompter, SignAlgorithm, SignRequest};
pub use settings::{DnsSettings, TunnelSettings, valid_domain};
pub use wireguard::{WIREGUARD_MTU, WIREGUARD_PORT, WireGuardProfile};
