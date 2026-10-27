//! TLS of the control channel. OpenVPN servers present a certificate of
//! their private CA that does not name them: the chain is checked against
//! the profile's CA only (or the certificate against pinned
//! fingerprints), then its purpose (`remote-cert-tls server`) and name
//! (`verify-x509-name`), never the host name.

use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use vpn_core::{OpenVpnProfile, Prompter, X509NameCheck, X509NameKind};
use vpn_tls::{RemoteCertificate, SignError};
use x509_parser::prelude::{FromDer, X509Certificate};

/// id-kp-serverAuth (1.3.6.1.5.5.7.3.1), DER contents.
const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// Why the server certificate was refused, for the error message.
pub type Rejected = Arc<Mutex<Option<String>>>;

pub struct TlsSetup {
    pub config: Arc<ClientConfig>,
    pub rejected: Rejected,
    pub sign_error: SignError,
}

pub fn setup(profile: &OpenVpnProfile, prompter: Arc<dyn Prompter>) -> anyhow::Result<TlsSetup> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut anchors = Vec::new();
    if let Some(pem) = &profile.ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.context("invalid CA certificate (ca)")?;
            anchors.push(webpki::anchor_from_trusted_cert(&cert).context("unusable CA certificate (ca)")?.to_owned());
        }
    }
    let pins: Vec<String> = profile.trusted_cert.iter().map(|p| p.replace(':', "").to_ascii_lowercase()).collect();
    if anchors.is_empty() && pins.is_empty() {
        bail!("the server's CA (ca) or fingerprint (peer-fingerprint) is needed");
    }
    let rejected = Rejected::default();
    let verifier = Arc::new(ServerCheck {
        anchors,
        pins,
        remote_cert_tls: profile.remote_cert_tls,
        name: profile.verify_x509_name.clone(),
        provider: provider.clone(),
        rejected: rejected.clone(),
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    if profile.client_key_pem.is_some() {
        bail!("the client certificate's key stays with the user's client");
    }
    let sign_error = SignError::default();
    let mut config = match profile.client_chain_pem.as_ref().or(profile.client_cert_pem.as_ref()) {
        Some(pem) => {
            let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("invalid client certificate")?;
            let remote = RemoteCertificate::new(chain, prompter, sign_error.clone())?;
            builder.with_client_cert_resolver(Arc::new(remote))
        }
        None => builder.with_no_client_auth(),
    };
    // Every key negotiation authenticates in full, as OpenVPN expects.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(TlsSetup { config: Arc::new(config), rejected, sign_error })
}

/// rustls wants a server name; the verifier ignores it.
pub fn server_name(host: &str) -> ServerName<'static> {
    ServerName::try_from(host.to_owned()).unwrap_or_else(|_| ServerName::try_from("openvpn.invalid").unwrap())
}

#[derive(Debug)]
struct ServerCheck {
    anchors: Vec<TrustAnchor<'static>>,
    pins: Vec<String>,
    remote_cert_tls: bool,
    name: Option<X509NameCheck>,
    provider: Arc<CryptoProvider>,
    rejected: Rejected,
}

/// Any purpose, as OpenVPN without `remote-cert-tls`.
struct AnyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

impl ServerCheck {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), String> {
        let fingerprint = vpn_tls::sha256_hex(end_entity);
        if !self.pins.is_empty() {
            if !self.pins.contains(&fingerprint) {
                return Err(format!("the server certificate (sha256 {fingerprint}) matches no peer-fingerprint"));
            }
        } else {
            let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|e| format!("invalid certificate: {e}"))?;
            let algorithms = self.provider.signature_verification_algorithms.all;
            let result = if self.remote_cert_tls {
                cert.verify_for_usage(
                    algorithms,
                    &self.anchors,
                    intermediates,
                    now,
                    webpki::KeyUsage::required(EKU_SERVER_AUTH),
                    None,
                    None,
                )
            } else {
                cert.verify_for_usage(algorithms, &self.anchors, intermediates, now, AnyUsage, None, None)
            };
            result.map_err(|e| match e {
                webpki::Error::RequiredEkuNotFoundContext(_) => {
                    "the server certificate is not meant for a server (remote-cert-tls server)".to_owned()
                }
                webpki::Error::UnknownIssuer => "the server certificate is not issued by the profile's CA".to_owned(),
                e => format!("the server certificate is not valid: {e:?}"),
            })?;
        }
        if let Some(check) = &self.name {
            let (_, cert) = X509Certificate::from_der(end_entity).map_err(|_| "invalid certificate".to_owned())?;
            let subject = cert.subject();
            let cn = subject.iter_common_name().next().and_then(|cn| cn.as_str().ok()).unwrap_or_default();
            let matches = match check.kind {
                X509NameKind::Subject => subject.to_string() == check.name,
                X509NameKind::Name => cn == check.name,
                X509NameKind::NamePrefix => cn.starts_with(&check.name),
            };
            if !matches {
                return Err(format!(
                    "the server certificate ({subject}) does not match verify-x509-name {}",
                    check.name
                ));
            }
        }
        Ok(())
    }
}

impl ServerCertVerifier for ServerCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, intermediates, now).map(|()| ServerCertVerified::assertion()).map_err(|reason| {
            *self.rejected.lock().unwrap() = Some(reason.clone());
            rustls::Error::General(reason)
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
