//! Records exchanged with the app, and their conversions from the core
//! types (which stay free of binding attributes).

use vpn_core::ipc::{Retry as CoreRetry, SessionInfo, SessionState};
use vpn_core::{CertificateInfo, FailureKind, PromptKind as CoreKind};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ClientError {
    #[error("{message}")]
    Failed { failure: FailureInfo, message: String },
}

impl From<anyhow::Error> for ClientError {
    fn from(e: anyhow::Error) -> Self {
        let failure = FailureInfo::from(vpn_core::failure::kind_of(&e));
        // The outermost context first, as the CLI shows it.
        ClientError::Failed { failure, message: vpn_client::printable(&format!("{e:#}")) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FailureCode {
    Unreachable,
    AuthFailed,
    OtpRejected,
    PskRejected,
    PermissionDenied,
    CertificateUntrusted,
    CertificateChanged,
    Conflict,
    NeedsUser,
    Cancelled,
    Timeout,
    ServiceUnavailable,
    Other,
}

/// Why something failed, with what the app needs to explain it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FailureInfo {
    pub code: FailureCode,
    /// The certificate presented (untrusted or changed certificate).
    pub certificate: Option<Certificate>,
    /// Fingerprints that were pinned (changed certificate).
    pub pinned: Vec<String>,
    /// The other session (conflict).
    pub conflict_with: Option<String>,
}

impl From<FailureKind> for FailureInfo {
    fn from(kind: FailureKind) -> Self {
        let mut info = Self { code: FailureCode::Other, certificate: None, pinned: Vec::new(), conflict_with: None };
        info.code = match kind {
            FailureKind::Unreachable => FailureCode::Unreachable,
            FailureKind::AuthFailed => FailureCode::AuthFailed,
            FailureKind::OtpRejected => FailureCode::OtpRejected,
            FailureKind::PskRejected => FailureCode::PskRejected,
            FailureKind::PermissionDenied => FailureCode::PermissionDenied,
            FailureKind::CertificateUntrusted { certificate } => {
                info.certificate = Some((&certificate).into());
                FailureCode::CertificateUntrusted
            }
            FailureKind::CertificateChanged { certificate, pinned } => {
                info.certificate = Some((&certificate).into());
                info.pinned = pinned;
                FailureCode::CertificateChanged
            }
            FailureKind::Conflict { with } => {
                info.conflict_with = with;
                FailureCode::Conflict
            }
            FailureKind::NeedsUser => FailureCode::NeedsUser,
            FailureKind::Cancelled => FailureCode::Cancelled,
            FailureKind::Timeout => FailureCode::Timeout,
            FailureKind::ServiceUnavailable => FailureCode::ServiceUnavailable,
            FailureKind::Other => FailureCode::Other,
        };
        info
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Certificate {
    pub host: String,
    pub port: u16,
    /// SHA-256 of the certificate, lowercase hex.
    pub sha256: String,
    /// The certificate (DER), for `SecCertificateCreateWithData`.
    pub der: Vec<u8>,
    /// Why normal validation failed.
    pub reason: Option<String>,
}

impl From<&CertificateInfo> for Certificate {
    fn from(c: &CertificateInfo) -> Self {
        Self {
            host: vpn_client::printable(&c.host),
            port: c.port,
            sha256: c.sha256.clone(),
            der: hex::decode(&c.der).unwrap_or_default(),
            reason: c.reason.as_deref().map(vpn_client::printable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PromptKind {
    /// Hidden input (password, pre-shared key).
    Secret,
    /// One-time code; never offer to save it.
    Otp,
    Text,
    Confirm,
}

/// A Keychain certificate with its private key.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeychainIdentity {
    pub name: String,
    pub issuer: String,
    /// Unix time.
    pub not_after: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Prompt {
    /// `password`, `otp`, `psk`, `username`…
    pub key: String,
    pub kind: PromptKind,
    pub message: String,
    /// FortiToken push: an empty answer waits for approval on the phone.
    pub push: bool,
    /// A code of exactly this many digits, sent once complete; 0 for any
    /// other answer, sent as typed.
    pub digits: u8,
}

impl From<&vpn_core::Prompt> for Prompt {
    fn from(p: &vpn_core::Prompt) -> Self {
        Self {
            key: p.key.clone(),
            kind: match p.kind {
                CoreKind::Secret => PromptKind::Secret,
                CoreKind::Otp => PromptKind::Otp,
                CoreKind::Text => PromptKind::Text,
                CoreKind::Confirm => PromptKind::Confirm,
                // Answered by the client from the Keychain, never shown.
                CoreKind::Sign => PromptKind::Secret,
            },
            message: vpn_client::printable(&p.message),
            push: p.push,
            digits: p.digits,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TrustDecision {
    Reject,
    Once,
    /// Trust and save the fingerprint in the profile.
    Always,
}

impl From<TrustDecision> for vpn_client::Trust {
    fn from(d: TrustDecision) -> Self {
        match d {
            TrustDecision::Reject => Self::Reject,
            TrustDecision::Once => Self::Once,
            TrustDecision::Always => Self::Pin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Disconnected,
    Failed,
}

impl From<SessionState> for ConnectionState {
    fn from(s: SessionState) -> Self {
        match s {
            SessionState::Connecting => Self::Connecting,
            SessionState::Connected => Self::Connected,
            SessionState::Reconnecting => Self::Reconnecting,
            SessionState::Disconnecting => Self::Disconnecting,
            SessionState::Disconnected => Self::Disconnected,
            SessionState::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct Retry {
    pub attempt: u32,
    pub max: u32,
    pub delay_secs: u64,
}

impl From<CoreRetry> for Retry {
    fn from(r: CoreRetry) -> Self {
        Self { attempt: r.attempt, max: r.max, delay_secs: r.delay_secs }
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Notice {
    State {
        state: ConnectionState,
        detail: Option<String>,
        retry: Option<Retry>,
    },
    Warning {
        message: String,
    },
    LoginStarted {
        url: String,
    },
    UrlRefused {
        url: String,
    },
    CertificatePinned,
    /// Now connecting the profile `id`: the one asked for, or a VPN it
    /// goes through.
    Connecting {
        id: String,
        name: String,
    },
}

impl From<vpn_client::Notice> for Notice {
    fn from(n: vpn_client::Notice) -> Self {
        match n {
            vpn_client::Notice::State { state, detail, retry } => {
                Self::State { state: state.into(), detail, retry: retry.map(Into::into) }
            }
            vpn_client::Notice::Warning(message) => Self::Warning { message },
            vpn_client::Notice::LoginStarted(url) => Self::LoginStarted { url },
            vpn_client::Notice::UrlRefused(url) => Self::UrlRefused { url },
            vpn_client::Notice::CertificatePinned => Self::CertificatePinned,
            vpn_client::Notice::Connecting { id, name } => Self::Connecting { id, name },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StateChange {
    /// The session's profile id.
    pub id: String,
    pub state: ConnectionState,
    pub detail: Option<String>,
    pub failure: Option<FailureInfo>,
    pub retry: Option<Retry>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Session {
    /// The profile's id: the session's key.
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub state: ConnectionState,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub full_tunnel: bool,
    pub routes: Vec<String>,
    pub dns_domains: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Unix time the tunnel came up.
    pub connected_since: Option<u64>,
    pub detail: Option<String>,
    pub failure: Option<FailureInfo>,
    /// The session it goes through, if chained.
    pub via: Option<String>,
}

impl From<SessionInfo> for Session {
    fn from(s: SessionInfo) -> Self {
        Self {
            id: s.id,
            name: s.name,
            protocol: s.protocol,
            state: s.state.into(),
            interface: s.interface,
            address: s.address,
            full_tunnel: s.full_tunnel,
            routes: s.routes,
            dns_domains: s.dns_domains,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            connected_since: s.connected_since,
            detail: s.detail.as_deref().map(vpn_client::printable),
            failure: s.failure.map(Into::into),
            via: s.via,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuthMethod {
    Password,
    Saml,
    PreSharedKey,
    /// A client certificate alone (OpenVPN without `auth-user-pass`).
    Certificate,
    /// A key pair (WireGuard).
    Key,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProfileSummary {
    /// Stable: what sessions, secrets and chains refer to.
    pub id: String,
    pub name: String,
    /// `forti-ssl`, `ipsec`, `openvpn`, `l2tp` or `wireguard`.
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub auth: AuthMethod,
    pub dns_domains: Vec<String>,
    pub description: Option<String>,
    /// Offer to keep the password in the Keychain.
    pub save_password: bool,
    /// VPNs it is chained through, preferred first.
    pub via: Vec<String>,
    /// `/` between subfolders.
    pub folder: Option<String>,
    /// A company VPN: never up at the same time as another VPN.
    pub exclusive: bool,
    /// The networks of a connection in split mode; empty: no split mode.
    pub split_routes: Vec<crate::ListEntry>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DuplicatedProfile {
    /// The copy's id.
    pub id: String,
    /// Why its saved secrets were not copied, if they were not.
    pub secrets_error: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportedProfile {
    pub name: String,
    /// Ready for `Client::add_profiles`.
    pub toml: String,
    /// What the user still has to do (store a secret, unsupported option).
    pub notes: Vec<String>,
    /// Ask for the pre-shared key, which FortiClient keeps encrypted.
    pub needs_psk: bool,
    /// Signs in with a password, which can be typed before adding the
    /// profile (OpenVPN `auth-user-pass`).
    pub needs_password: bool,
    /// Why it cannot be imported (then `toml` is empty).
    pub refused: Option<String>,
}

impl From<vpn_client::import::Found> for ImportedProfile {
    fn from(found: vpn_client::import::Found) -> Self {
        match found.result {
            Ok(i) => {
                // A password the user may type now: OpenVPN's, or XAuth's.
                let needs_password = toml::from_str::<vpn_core::ProfileFile>(&i.toml).is_ok_and(|f| {
                    f.profiles.iter().any(|p| match &p.protocol {
                        vpn_core::ProtocolConfig::OpenVpn(o) => o.auth_user_pass,
                        vpn_core::ProtocolConfig::Ipsec(s) => s.xauth && p.save_password,
                        vpn_core::ProtocolConfig::L2tp(_) => p.save_password,
                        vpn_core::ProtocolConfig::FortiSsl(_) | vpn_core::ProtocolConfig::WireGuard(_) => false,
                    })
                });
                Self {
                    name: i.name,
                    toml: i.toml,
                    notes: i.notes,
                    needs_psk: i.needs_psk,
                    needs_password,
                    refused: None,
                }
            }
            Err(e) => Self {
                name: vpn_client::printable(&found.display),
                toml: String::new(),
                notes: Vec::new(),
                needs_psk: false,
                needs_password: false,
                refused: Some(format!("{e:#}")),
            },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceInfo {
    pub version: String,
    pub protocol: u32,
    /// The caller's sessions.
    pub sessions: u32,
}
