use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptKind {
    /// Hidden input, may be satisfied from the keychain.
    Secret,
    /// One-time code (FortiToken, SMS, e-mail); never stored.
    Otp,
    /// Plain visible input.
    Text,
    /// A yes/no decision; the answer must repeat `Prompt::confirm_with`.
    Confirm,
    /// A signature with the client certificate's key, which stays in the
    /// user's Keychain; never remembered.
    Sign,
}

impl PromptKind {
    /// Whether the session may reuse the answer when it reconnects.
    pub fn remembered(self) -> bool {
        !matches!(self, PromptKind::Otp | PromptKind::Sign)
    }
}

/// What the client certificate's key must sign (key `sign`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// SHA-256 (hex) of the client certificate, as in the profile.
    pub certificate: String,
    pub algorithm: SignAlgorithm,
    /// The octets to sign, hex; the answer is the signature, hex (DER
    /// for ECDSA).
    pub data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignAlgorithm {
    RsaPkcs1Sha1,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    /// RSASSA-PSS with MGF1 of the same hash and a salt as long as the
    /// hash (TLS 1.3).
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaSha256,
    EcdsaSha384,
}

/// Whether `data` is what an IKEv2 initiator signs (RFC 7296 §2.15): its
/// IKE_SA_INIT request, then the responder's nonce and a PRF output. The
/// client only signs that, so a compromised engine cannot have the user's
/// key sign anything else (a TLS handshake, a document).
pub fn is_ike_auth_octets(data: &[u8]) -> bool {
    const HEADER: usize = 28;
    if data.len() < HEADER {
        return false;
    }
    let length = u32::from_be_bytes([data[24], data[25], data[26], data[27]]) as usize;
    // Nonce of 16 to 256 bytes, PRF output of 20 to 64 bytes.
    let tail = data.len().checked_sub(length);
    data[8..16] == [0; 8]
        && data[17] == 0x20 // IKEv2
        && data[18] == 34 // IKE_SA_INIT
        && data[19] == 0x08 // initiator request
        && data[20..24] == [0; 4]
        && length >= HEADER
        && tail.is_some_and(|t| (36..=320).contains(&t))
}

/// Whether `data` is what a TLS client signs in its CertificateVerify:
/// in TLS 1.3 the fixed context string and a transcript hash (RFC 8446
/// §4.4.3), in TLS 1.2 the handshake messages from the ClientHello on
/// (RFC 5246 §7.4.8). Same purpose as [`is_ike_auth_octets`].
pub fn is_tls_client_signature_octets(data: &[u8]) -> bool {
    const TLS13: &[u8] = b"TLS 1.3, client CertificateVerify\0";
    if let Some(rest) = data.strip_prefix(&[b' '; 64]) {
        return rest.strip_prefix(TLS13).is_some_and(|hash| matches!(hash.len(), 32 | 48));
    }
    // ClientHello, its 24-bit length, then version 1.2 (also the legacy
    // version of a 1.3 hello, so other messages follow it).
    let hello = data.len() >= 6 && data[0] == 1 && data[4..6] == [3, 3];
    let length = hello.then(|| u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize);
    length.is_some_and(|l| data.len() > 4 + l)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    /// Stable key, e.g. `"password"`, `"otp"`, `"psk"`, `"username"`.
    pub key: String,
    pub kind: PromptKind,
    pub message: String,
    /// The certificate to trust (key `trust_certificate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<crate::CertificateInfo>,
    /// FortiToken push: an empty answer approves on the phone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub push: bool,
    /// What to sign (key `sign`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<SignRequest>,
}

impl Prompt {
    pub fn new(key: impl Into<String>, kind: PromptKind, message: impl Into<String>) -> Self {
        Self { key: key.into(), kind, message: message.into(), certificate: None, push: false, sign: None }
    }

    /// Asks the client to sign with the key of its certificate.
    pub fn sign(request: SignRequest, message: impl Into<String>) -> Self {
        Self { sign: Some(request), ..Self::new(SIGN, PromptKind::Sign, message) }
    }

    /// Asks whether to trust a certificate; the answer to accept is its
    /// SHA-256, so a cached answer never accepts a different certificate.
    pub fn trust(certificate: crate::CertificateInfo) -> Self {
        let message = format!(
            "cannot verify the certificate of {}:{} (sha256 {})",
            certificate.host, certificate.port, certificate.sha256
        );
        Self { certificate: Some(certificate), ..Self::new(TRUST_CERTIFICATE, PromptKind::Confirm, message) }
    }
}

/// Prompt key for a certificate trust decision.
pub const TRUST_CERTIFICATE: &str = "trust_certificate";

/// Not a question: the L2TP server proved it knows the password
/// (MS-CHAPv2), so the profile no longer accepts weaker authentications,
/// which would let anyone with the pre-shared key pose as it.
pub const L2TP_SERVER_PROVED: &str = "l2tp_server_proved";

/// Prompt key for a signature with the client certificate's key.
pub const SIGN: &str = "sign";

/// Interactive channel back to the user who requested the connection.
#[async_trait]
pub trait Prompter: Send + Sync {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<String>;
    /// Ask the user's session to open a URL in a browser (SAML).
    async fn open_url(&self, url: &str) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_signed_octets() {
        let mut tls13 = vec![b' '; 64];
        tls13.extend_from_slice(b"TLS 1.3, client CertificateVerify\0");
        assert!(!is_tls_client_signature_octets(&tls13), "no hash");
        tls13.extend_from_slice(&[7; 32]);
        assert!(is_tls_client_signature_octets(&tls13));
        let mut server = vec![b' '; 64];
        server.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        server.extend_from_slice(&[7; 32]);
        assert!(!is_tls_client_signature_octets(&server), "the server's context");

        let mut tls12 = vec![1, 0, 0, 4, 3, 3, 0, 0];
        assert!(!is_tls_client_signature_octets(&tls12), "the hello alone");
        tls12.extend_from_slice(&[2, 0, 0, 0]);
        assert!(is_tls_client_signature_octets(&tls12));
        assert!(!is_tls_client_signature_octets(b"\x30\x82 a certificate to sign"));
        assert!(!is_tls_client_signature_octets(&[]));
    }
}
