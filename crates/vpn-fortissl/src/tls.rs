//! TLS setup: standard PKI validation or SHA-256 pinning of the gateway's
//! leaf certificate (FortiGates commonly ship self-signed certificates).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use vpn_core::{CertificateInfo, FailureExt, FailureKind, FortiSslProfile, Prompter, failure};

use vpn_tls::{RemoteCertificate, SignError};

pub type Stream = TlsStream<TcpStream>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough for the user to allow a Keychain signature with the client
/// certificate.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Connection parameters shared by every HTTPS request and the tunnel.
#[derive(Clone)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub server_name: ServerName<'static>,
    connector: TlsConnector,
    host: String,
    port: u16,
    pins: Vec<String>,
    /// Certificate the verifier last rejected, with the reason.
    rejected: Rejected,
    /// Why the client could not sign with its certificate.
    sign_error: SignError,
}

impl Endpoint {
    /// `prompter` signs for the client certificate, when there is one.
    pub fn new(
        profile: &FortiSslProfile,
        addr: SocketAddr,
        prompter: Option<Arc<dyn Prompter>>,
    ) -> anyhow::Result<Self> {
        let server_name = ServerName::try_from(profile.host.clone())
            .with_context(|| format!("invalid gateway host name {:?}", profile.host))?;
        let rejected = Arc::new(Mutex::new(None));
        let sign_error = Arc::new(Mutex::new(None));
        let (config, pins) = client_config(profile, rejected.clone(), prompter, sign_error.clone())?;
        Ok(Self {
            addr,
            server_name,
            connector: TlsConnector::from(Arc::new(config)),
            host: profile.host.clone(),
            port: profile.port,
            pins,
            rejected,
            sign_error,
        })
    }

    pub async fn connect(&self) -> anyhow::Result<Stream> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
            .kind(FailureKind::Unreachable)
            .with_context(|| format!("cannot reach gateway {}", self.addr))?;
        tcp.set_nodelay(true)?;
        let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.connector.connect(self.server_name.clone(), tcp));
        let Ok(handshake) = handshake.await else {
            return Err(failure(
                FailureKind::Timeout,
                format!("gateway {} accepted the connection but did not finish the TLS handshake", self.addr),
            ));
        };
        match handshake {
            Ok(stream) => Ok(stream),
            Err(e) => {
                if let Some(error) = self.sign_error.lock().unwrap().take() {
                    return Err(error.context("cannot sign with the client certificate"));
                }
                match self.rejected.lock().unwrap().take() {
                    Some((der, reason)) => Err(self.certificate_failure(&der, reason)),
                    None => Err(anyhow::Error::from(e).context("TLS handshake with gateway failed")),
                }
            }
        }
    }

    fn certificate_failure(&self, der: &[u8], reason: Option<String>) -> anyhow::Error {
        let certificate = CertificateInfo {
            host: self.host.clone(),
            port: self.port,
            sha256: sha256_hex(der),
            der: hex::encode(der),
            reason,
        };
        let sha256 = certificate.sha256.clone();
        if self.pins.is_empty() {
            failure(
                FailureKind::CertificateUntrusted { certificate },
                format!("cannot verify the gateway certificate (sha256 {sha256})"),
            )
        } else {
            failure(
                FailureKind::CertificateChanged { certificate, pinned: self.pins.clone() },
                format!("gateway certificate sha256={sha256} matches no trusted_cert entry: connection blocked"),
            )
        }
    }
}

pub use vpn_tls::sha256_hex;

type Rejected = Arc<Mutex<Option<(Vec<u8>, Option<String>)>>>;

fn client_config(
    profile: &FortiSslProfile,
    rejected: Rejected,
    prompter: Option<Arc<dyn Prompter>>,
    sign_error: SignError,
) -> anyhow::Result<(ClientConfig, Vec<String>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = &profile.ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.context("invalid CA bundle")?).context("invalid CA certificate")?;
        }
    }
    // The Keychain may hold certificates rustls cannot use as anchors.
    if let Some(pem) = &profile.keychain_ca_pem {
        let (added, ignored) =
            roots.add_parsable_certificates(CertificateDer::pem_slice_iter(pem.as_bytes()).flatten());
        tracing::debug!("{added} Keychain certificate authorities ({ignored} unusable)");
    }
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("cannot build certificate verifier")?;

    let pins = profile.trusted_cert.iter().map(|pin| pin.replace(':', "").to_ascii_lowercase()).collect::<Vec<_>>();
    for pin in &pins {
        if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("trusted_cert {pin:?} is not a SHA-256 hex digest");
        }
    }

    let verifier = Arc::new(GatewayVerifier { pins: pins.clone(), webpki, provider: provider.clone(), rejected });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    if profile.has_file_paths() {
        bail!("certificate files must be inlined by the client, not read by the daemon");
    }
    if profile.client_key_pem.is_some() {
        bail!("the client certificate's key stays with the user's client");
    }
    // From the Keychain, or the PEM file the client inlined.
    let config = match (profile.client_chain_pem.as_ref().or(profile.client_cert_pem.as_ref()), prompter) {
        (Some(pem), Some(prompter)) => {
            let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("invalid client certificate")?;
            builder.with_client_cert_resolver(Arc::new(RemoteCertificate::new(chain, prompter, sign_error)?))
        }
        (Some(_), None) => bail!("no client to sign with the client certificate"),
        (None, _) => builder.with_no_client_auth(),
    };
    Ok((config, pins))
}

/// Pinning when `pins` is non-empty, PKI otherwise. Either way a failure
/// reports the leaf fingerprint so the user can decide to pin it.
#[derive(Debug)]
struct GatewayVerifier {
    pins: Vec<String>,
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    rejected: Rejected,
}

impl GatewayVerifier {
    fn reject(&self, end_entity: &CertificateDer<'_>, reason: Option<String>, message: String) -> rustls::Error {
        *self.rejected.lock().unwrap() = Some((end_entity.to_vec(), reason));
        rustls::Error::General(message)
    }
}

impl ServerCertVerifier for GatewayVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = sha256_hex(end_entity);
        if !self.pins.is_empty() {
            return if self.pins.contains(&fingerprint) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(self.reject(
                    end_entity,
                    None,
                    format!("gateway certificate sha256={fingerprint} matches no trusted_cert entry"),
                ))
            };
        }
        self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).map_err(|e| {
            self.reject(end_entity, Some(e.to_string()), format!("{e}; gateway certificate sha256={fingerprint}"))
        })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
