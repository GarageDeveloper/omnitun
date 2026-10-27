//! The key of a profile's client certificate, which stays on the user's
//! side: the engine asks the client for each signature, the daemon never
//! sees it.

use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use vpn_core::{Profile, ProtocolConfig, SignAlgorithm};
use zeroize::Zeroizing;

#[derive(Clone)]
pub enum ClientKey {
    /// In the user's Keychain.
    Keychain { sha256: String },
    /// From the profile's PEM key file, read by the client.
    Pem { sha256: String, key: Arc<dyn SigningKey> },
}

impl ClientKey {
    /// Takes the key out of `profile`, whose file paths are already
    /// inlined, and adds the Keychain certificate's chain.
    pub fn take(profile: &mut Profile) -> anyhow::Result<Option<Self>> {
        let keychain = |sha256: &String, chain: &mut Option<String>| -> anyhow::Result<Option<Self>> {
            *chain = Some(crate::keychain::certificate_chain(sha256)?);
            Ok(Some(Self::Keychain { sha256: sha256.clone() }))
        };
        match &mut profile.protocol {
            ProtocolConfig::L2tp(_) | ProtocolConfig::WireGuard(_) => Ok(None),
            ProtocolConfig::Ipsec(p) => match &p.client_certificate {
                Some(sha256) => keychain(sha256, &mut p.client_chain_pem),
                None => Ok(None),
            },
            ProtocolConfig::FortiSsl(p) => {
                let key = p.client_key_pem.take().map(Zeroizing::new);
                if let Some(sha256) = &p.client_certificate {
                    return keychain(sha256, &mut p.client_chain_pem);
                }
                match (&p.client_cert_pem, key) {
                    (Some(chain), Some(key)) => Self::pem(chain, &key).map(Some),
                    (None, None) => Ok(None),
                    _ => bail!("client_cert and client_key must be set together"),
                }
            }
            ProtocolConfig::OpenVpn(p) => {
                let key = p.client_key_pem.take().map(Zeroizing::new);
                if let Some(sha256) = &p.client_certificate {
                    return keychain(sha256, &mut p.client_chain_pem);
                }
                match (&p.client_cert_pem, key) {
                    (Some(chain), Some(key)) => Self::pem(chain, &key).map(Some),
                    (None, None) => Ok(None),
                    _ => bail!("cert and key must be set together"),
                }
            }
        }
    }

    fn pem(chain: &str, key: &str) -> anyhow::Result<Self> {
        let chain = CertificateDer::pem_slice_iter(chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("invalid client certificate")?;
        let leaf = chain.first().context("the client certificate file holds no certificate")?;
        let sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(leaf));
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).context("invalid client key")?;
        let key = rustls::crypto::ring::sign::any_supported_type(&key).context("unsupported client key")?;
        match CertifiedKey::new(chain, key.clone()).keys_match() {
            Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
            Err(_) => bail!("the client key does not belong to the client certificate"),
        }
        Ok(Self::Pem { sha256, key })
    }

    /// SHA-256 (hex) of the certificate.
    pub fn sha256(&self) -> &str {
        match self {
            Self::Keychain { sha256 } | Self::Pem { sha256, .. } => sha256,
        }
    }

    /// Signs `data`; the Keychain may wait for the user to allow it.
    pub fn sign(&self, algorithm: SignAlgorithm, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = match self {
            Self::Keychain { sha256 } => return crate::keychain::sign(sha256, algorithm, data),
            Self::Pem { key, .. } => key,
        };
        let scheme = match algorithm {
            SignAlgorithm::RsaPkcs1Sha1 => SignatureScheme::RSA_PKCS1_SHA1,
            SignAlgorithm::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
            SignAlgorithm::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
            SignAlgorithm::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
            SignAlgorithm::RsaPssSha256 => SignatureScheme::RSA_PSS_SHA256,
            SignAlgorithm::RsaPssSha384 => SignatureScheme::RSA_PSS_SHA384,
            SignAlgorithm::RsaPssSha512 => SignatureScheme::RSA_PSS_SHA512,
            SignAlgorithm::EcdsaSha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            SignAlgorithm::EcdsaSha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        };
        let signer = key.choose_scheme(&[scheme]).with_context(|| format!("the client key cannot sign {scheme:?}"))?;
        signer.sign(data).map_err(|e| anyhow::anyhow!("cannot sign with the client key: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["alice".into()]).unwrap().self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn profile(cert: &str, key: &str) -> Profile {
        let mut profile: Profile =
            toml::from_str("name = \"s\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"").unwrap();
        let ProtocolConfig::FortiSsl(p) = &mut profile.protocol else { unreachable!() };
        (p.client_cert_pem, p.client_key_pem) = (Some(cert.into()), Some(key.into()));
        profile
    }

    #[test]
    fn pem_key_stays_with_the_client() {
        let (cert, key) = certificate();
        let mut p = profile(&cert, &key);
        let key = ClientKey::take(&mut p).unwrap().unwrap();
        let ProtocolConfig::FortiSsl(ssl) = &p.protocol else { unreachable!() };
        assert!(ssl.client_key_pem.is_none(), "taken out of the profile");
        let der: CertificateDer = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        assert_eq!(key.sha256(), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&der)));

        let signature = key.sign(SignAlgorithm::EcdsaSha256, b"data").unwrap();
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            parsed.public_key().subject_public_key.data.to_vec(),
        );
        public.verify(b"data", &signature).unwrap();
        assert!(key.sign(SignAlgorithm::RsaPssSha256, b"data").is_err(), "not an RSA key");

        let (_, other) = certificate();
        assert!(ClientKey::take(&mut profile(&cert, &other)).is_err(), "the key of another certificate");
    }
}
