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

/// The server name (SNI) in the ClientHello that TLS 1.2 octets to sign
/// start with; `None` without one, or for TLS 1.3 octets, which hold only
/// a hash and bind no name.
pub fn tls12_server_name(data: &[u8]) -> Option<String> {
    let length = u32::from_be_bytes([0, *data.get(1)?, *data.get(2)?, *data.get(3)?]) as usize;
    if data[0] != 1 {
        return None;
    }
    let mut hello = Reader(data.get(4..4 + length)?);
    hello.take(2 + 32)?; // version, random
    for prefix in [1, 2, 1] {
        hello.vector(prefix)?; // session id, cipher suites, compression
    }
    let mut extensions = Reader(hello.vector(2)?);
    while !extensions.0.is_empty() {
        let kind = extensions.take(2)?;
        let body = extensions.vector(2)?;
        if kind == [0, 0] {
            let mut list = Reader(Reader(body).vector(2)?);
            while !list.0.is_empty() {
                let name_type = list.take(1)?[0];
                let name = list.vector(2)?;
                if name_type == 0 {
                    return std::str::from_utf8(name).ok().map(str::to_owned);
                }
            }
        }
    }
    None
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    /// A vector with a `prefix`-byte length.
    fn vector(&mut self, prefix: usize) -> Option<&'a [u8]> {
        let length = self.take(prefix)?.iter().fold(0, |n, b| n << 8 | usize::from(*b));
        self.take(length)
    }
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
    /// A code of exactly this many digits (FortiToken): a client may keep
    /// only digits and send it once complete. 0 for any other answer (a PIN
    /// and a token code, letters), which is sent as typed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub digits: u8,
    /// What to sign (key `sign`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<SignRequest>,
}

impl Prompt {
    pub fn new(key: impl Into<String>, kind: PromptKind, message: impl Into<String>) -> Self {
        Self { key: key.into(), kind, message: message.into(), certificate: None, push: false, digits: 0, sign: None }
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

fn is_zero(n: &u8) -> bool {
    *n == 0
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
        assert_eq!(tls12_server_name(&tls12), None, "too short for a hello");
        assert_eq!(tls12_server_name(&tls13), None);
    }

    /// A ClientHello with `extensions`, then a ServerHello.
    fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut out = vec![1, 0];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&[2, 0, 0, 0]);
        out
    }

    #[test]
    fn tls12_names() {
        let name = b"vpn.example.com";
        let mut sni = vec![0, 0, 0, name.len() as u8 + 5, 0, name.len() as u8 + 3, 0, 0, name.len() as u8];
        sni.extend_from_slice(name);
        let other = [0, 10, 0, 2, 0, 29]; // supported groups
        let signed = hello(&[&other[..], &sni].concat());
        assert!(is_tls_client_signature_octets(&signed));
        assert_eq!(tls12_server_name(&signed).as_deref(), Some("vpn.example.com"));
        assert_eq!(tls12_server_name(&hello(&other)), None, "no SNI");
        let mut broken = signed.clone();
        broken[4 + 2 + 32 + 7 + 1] = 0xff; // extensions longer than the hello
        assert_eq!(tls12_server_name(&broken), None);
    }
}
