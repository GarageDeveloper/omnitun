//! Client certificate authentication with a key the engine never holds:
//! each TLS signature is asked to the user's client, which signs with its
//! Keychain or its PEM key file after checking what it signs.

use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use vpn_core::{Prompt, Prompter, SignAlgorithm, SignRequest};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The last signature that failed, reported instead of the TLS error.
pub type SignError = Arc<Mutex<Option<anyhow::Error>>>;

#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyKind {
    Rsa,
    P256,
    P384,
}

/// Schemes we offer, preferred first; TLS 1.3 leaves only PSS for RSA.
const RSA_SCHEMES: [(SignatureScheme, SignAlgorithm); 6] = [
    (SignatureScheme::RSA_PSS_SHA256, SignAlgorithm::RsaPssSha256),
    (SignatureScheme::RSA_PSS_SHA384, SignAlgorithm::RsaPssSha384),
    (SignatureScheme::RSA_PSS_SHA512, SignAlgorithm::RsaPssSha512),
    (SignatureScheme::RSA_PKCS1_SHA256, SignAlgorithm::RsaPkcs1Sha256),
    (SignatureScheme::RSA_PKCS1_SHA384, SignAlgorithm::RsaPkcs1Sha384),
    (SignatureScheme::RSA_PKCS1_SHA512, SignAlgorithm::RsaPkcs1Sha512),
];

/// Hands rustls the chain, with a key that signs through the prompter.
pub struct RemoteCertificate {
    certified: Arc<CertifiedKey>,
}

impl RemoteCertificate {
    pub fn new(
        chain: Vec<CertificateDer<'static>>,
        prompter: Arc<dyn Prompter>,
        error: SignError,
    ) -> anyhow::Result<Self> {
        let leaf = chain.first().context("empty client certificate chain")?;
        let (_, cert) = X509Certificate::from_der(leaf).context("invalid client certificate")?;
        let spki = cert.public_key();
        let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok());
        let kind = match (&spki.algorithm.algorithm, curve) {
            (alg, _) if *alg == OID_PKCS1_RSAENCRYPTION => KeyKind::Rsa,
            (alg, Some(c)) if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY && c == OID_EC_P256 => KeyKind::P256,
            (alg, Some(c)) if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY && c == OID_NIST_EC_P384 => KeyKind::P384,
            _ => bail!("the client certificate's key must be RSA, ECDSA P-256 or P-384"),
        };
        let sha256 = crate::sha256_hex(leaf);
        let key = RemoteKey { kind, sha256, prompter, error };
        Ok(Self { certified: Arc::new(CertifiedKey::new(chain, Arc::new(key))) })
    }
}

impl std::fmt::Debug for RemoteCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteCertificate").finish_non_exhaustive()
    }
}

impl ResolvesClientCert for RemoteCertificate {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct RemoteKey {
    kind: KeyKind,
    sha256: String,
    prompter: Arc<dyn Prompter>,
    error: SignError,
}

impl std::fmt::Debug for RemoteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteKey").field("kind", &self.kind).field("sha256", &self.sha256).finish()
    }
}

impl SigningKey for RemoteKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let (scheme, algorithm) = match self.kind {
            KeyKind::Rsa => RSA_SCHEMES.into_iter().find(|(s, _)| offered.contains(s))?,
            KeyKind::P256 => (SignatureScheme::ECDSA_NISTP256_SHA256, SignAlgorithm::EcdsaSha256),
            KeyKind::P384 => (SignatureScheme::ECDSA_NISTP384_SHA384, SignAlgorithm::EcdsaSha384),
        };
        if !offered.contains(&scheme) {
            return None;
        }
        let key = Self {
            kind: self.kind,
            sha256: self.sha256.clone(),
            prompter: self.prompter.clone(),
            error: self.error.clone(),
        };
        Some(Box::new(RemoteSigner { key, scheme, algorithm }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.kind {
            KeyKind::Rsa => SignatureAlgorithm::RSA,
            KeyKind::P256 | KeyKind::P384 => SignatureAlgorithm::ECDSA,
        }
    }
}

#[derive(Debug)]
struct RemoteSigner {
    key: RemoteKey,
    scheme: SignatureScheme,
    algorithm: SignAlgorithm,
}

impl RemoteSigner {
    fn ask(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let request =
            SignRequest { certificate: self.key.sha256.clone(), algorithm: self.algorithm, data: hex::encode(message) };
        let prompt = Prompt::sign(request, "Signature of the TLS handshake with the client certificate");
        // rustls signs synchronously, inside the handshake: this worker
        // waits for the client while the others carry the question.
        let handle = tokio::runtime::Handle::try_current().context("no async runtime")?;
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            bail!("signing with a client certificate needs a multi-threaded runtime");
        }
        let answer = tokio::task::block_in_place(|| handle.block_on(self.key.prompter.ask(prompt)))?;
        hex::decode(answer.trim()).context("malformed signature from the client")
    }
}

impl Signer for RemoteSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.ask(message).map_err(|e| {
            let text = format!("client certificate signature: {e:#}");
            *self.key.error.lock().unwrap() = Some(e);
            rustls::Error::General(text)
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
