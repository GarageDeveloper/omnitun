//! Typed reasons a connection fails, so clients can show the right message
//! and action instead of parsing text. Engines attach a `Failure` to the
//! error they return; anything untagged is reported as `Other`.

use serde::{Deserialize, Serialize};

/// A server certificate the user may be asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub host: String,
    pub port: u16,
    /// SHA-256 of the leaf certificate, lowercase hex.
    pub sha256: String,
    /// The leaf certificate (DER, hex), for clients that can display it.
    pub der: String,
    /// Why normal validation failed, when it was attempted.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FailureKind {
    /// Name resolution, TCP or IKE got no answer.
    Unreachable,
    /// Wrong user name or password (portal or XAuth/EAP).
    AuthFailed,
    /// The one-time code or push approval was refused.
    OtpRejected,
    /// The gateway does not accept the pre-shared key.
    PskRejected,
    /// The account may not use this VPN.
    PermissionDenied,
    /// The certificate could not be validated and the user did not trust it.
    CertificateUntrusted {
        certificate: CertificateInfo,
    },
    /// A pinned certificate was replaced: connection blocked.
    CertificateChanged {
        certificate: CertificateInfo,
        pinned: Vec<String>,
    },
    /// Routes, DNS domains or full tunnel clash with another session.
    Conflict {
        with: Option<String>,
    },
    /// The gateway needs the user (code, browser) and no client is attached.
    NeedsUser,
    /// The user cancelled a prompt or the browser login.
    Cancelled,
    Timeout,
    /// The client cannot reach the daemon: not running, not allowed to
    /// use its socket, or another protocol version.
    ServiceUnavailable,
    Other,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

/// An error carrying its kind.
pub fn failure(kind: FailureKind, message: impl Into<String>) -> anyhow::Error {
    Failure { kind, message: message.into() }.into()
}

/// The kind attached anywhere in the error's chain.
pub fn kind_of(error: &anyhow::Error) -> FailureKind {
    // `downcast_ref` also sees a `Failure` attached as context, which the
    // chain only exposes wrapped.
    error
        .downcast_ref::<Failure>()
        .or_else(|| error.chain().find_map(|e| e.downcast_ref::<Failure>()))
        .map_or(FailureKind::Other, |f| f.kind.clone())
}

/// Tags an untagged error; its message (with context) is kept as is.
pub trait FailureExt<T> {
    fn kind(self, kind: FailureKind) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> FailureExt<T> for Result<T, E> {
    fn kind(self, kind: FailureKind) -> anyhow::Result<T> {
        self.map_err(|e| {
            let e = e.into();
            if kind_of(&e) != FailureKind::Other { e } else { failure(kind, format!("{e:#}")) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_survives_context() {
        let e = failure(FailureKind::PskRejected, "HASH_R mismatch").context("IKEv1 phase 1");
        assert_eq!(kind_of(&e), FailureKind::PskRejected);
        assert_eq!(kind_of(&anyhow::anyhow!("plain")), FailureKind::Other);
        let tagged: anyhow::Result<()> = Err(std::io::Error::other("refused")).kind(FailureKind::Unreachable);
        let e = tagged.unwrap_err();
        assert_eq!(kind_of(&e), FailureKind::Unreachable);
        assert_eq!(format!("{e:#}"), "refused");
        let tagged: anyhow::Result<()> =
            Err(anyhow::anyhow!("refused").context("cannot reach x")).kind(FailureKind::ServiceUnavailable);
        assert_eq!(format!("{:#}", tagged.unwrap_err()), "cannot reach x: refused");
    }
}
