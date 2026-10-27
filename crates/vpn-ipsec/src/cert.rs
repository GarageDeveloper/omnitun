//! Gateway certificates (IKEv2): the chain, validated against the system
//! roots and the profile's CAs or pinned like the SSL VPN's; the gateway
//! identity it vouches for; and the AUTH signature made with its key
//! (RFC 7296 §2.15 and §3.8, RFC 7427).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail, ensure};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use vpn_core::{CertificateInfo, FailureKind, SignAlgorithm, failure};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeId, KeyPurposeIdIter};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
    OID_NIST_HASH_SHA512, OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
    OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED25519,
};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use x509_parser::signature_algorithm::SignatureAlgorithm;
use x509_parser::x509::AlgorithmIdentifier;

use crate::ikev2::consts::{auth_method, id_type};
use crate::ikev2::payload::Identity;

/// SIGNATURE_HASH_ALGORITHMS values (RFC 7427 §4): SHA2-256, -384, -512
/// and "identity" (Ed25519).
pub const SIGNATURE_HASHES: [u16; 4] = [2, 3, 4, 5];

/// CERT and CERTREQ encoding of an X.509 signature certificate.
pub const X509_SIGNATURE: u8 = 4;

/// What makes a gateway certificate trusted.
pub struct GatewayTrust {
    anchors: Vec<TrustAnchor<'static>>,
    /// SHA-1 of the profile CAs' public keys, for CERTREQ.
    ca_key_hashes: Vec<[u8; 20]>,
    /// SHA-256 fingerprints of pinned gateway certificates.
    pins: Vec<String>,
    host: String,
    port: u16,
}

impl GatewayTrust {
    /// `keychain_pem`: the CAs the user's Keychain trusts; unlike the
    /// profile's, they are not named in CERTREQ, and unusable ones are
    /// skipped.
    pub fn new(
        ca_pem: Option<&str>,
        keychain_pem: Option<&str>,
        trusted_cert: &[String],
        host: &str,
        port: u16,
    ) -> anyhow::Result<Self> {
        let mut anchors: Vec<TrustAnchor<'static>> = webpki_roots::TLS_SERVER_ROOTS.to_vec();
        for cert in CertificateDer::pem_slice_iter(keychain_pem.unwrap_or_default().as_bytes()).flatten() {
            match webpki::anchor_from_trusted_cert(&cert) {
                Ok(anchor) => anchors.push(anchor.to_owned()),
                Err(e) => tracing::debug!("Keychain certificate authority skipped: {e}"),
            }
        }
        let mut ca_key_hashes = Vec::new();
        for cert in CertificateDer::pem_slice_iter(ca_pem.unwrap_or_default().as_bytes()) {
            let cert = cert.context("invalid CA certificate (PEM expected)")?;
            let (_, parsed) = X509Certificate::from_der(&cert).map_err(|e| anyhow!("invalid CA certificate: {e}"))?;
            ca_key_hashes.push(Sha1::digest(parsed.public_key().raw).into());
            anchors.push(webpki::anchor_from_trusted_cert(&cert).context("unusable CA certificate")?.to_owned());
        }
        let pins = trusted_cert.iter().map(|p| p.replace(':', "").to_ascii_lowercase()).collect::<Vec<_>>();
        for pin in &pins {
            ensure!(
                pin.len() == 64 && pin.chars().all(|c| c.is_ascii_hexdigit()),
                "trusted_cert {pin:?} is not a SHA-256"
            );
        }
        Ok(Self { anchors, ca_key_hashes, pins, host: host.to_owned(), port })
    }

    /// CERTREQ body: our CAs, or none (then any certificate is welcome).
    pub fn certreq(&self) -> Vec<u8> {
        let mut body = vec![X509_SIGNATURE];
        for hash in &self.ca_key_hashes {
            body.extend_from_slice(hash);
        }
        body
    }

    /// Checks the chain (end entity first) and that it vouches for
    /// `expected` (the configured remote ID, or the gateway address) and
    /// for the identity the gateway sent. A pinned certificate is trusted
    /// as is. Failures carry the certificate so the user can decide.
    pub fn check(&self, chain: &[Vec<u8>], expected: &Identity, id_r: &Identity) -> anyhow::Result<()> {
        let leaf = chain.first().context("gateway sent no certificate")?;
        let sha256 = hex::encode(Sha256::digest(leaf));
        let info = |reason: Option<String>| CertificateInfo {
            host: self.host.clone(),
            port: self.port,
            sha256: sha256.clone(),
            der: hex::encode(leaf),
            reason,
        };
        // The signature binds IDr, so it must be the certificate's identity
        // even when the certificate is pinned.
        ensure!(covers(leaf, id_r)?, "the gateway certificate is not valid for its identity {}", id_r.display());
        if !self.pins.is_empty() {
            if self.pins.contains(&sha256) {
                return Ok(());
            }
            return Err(failure(
                FailureKind::CertificateChanged { certificate: info(None), pinned: self.pins.clone() },
                format!("gateway certificate sha256={sha256} matches no trusted_cert entry: connection blocked"),
            ));
        }
        let untrusted = |reason: String| {
            failure(
                FailureKind::CertificateUntrusted { certificate: info(Some(reason.clone())) },
                format!("cannot verify the gateway certificate: {reason} (sha256 {sha256})"),
            )
        };
        let der = CertificateDer::from(leaf.as_slice());
        let end_entity = EndEntityCert::try_from(&der).map_err(|e| untrusted(e.to_string()))?;
        let intermediates: Vec<CertificateDer<'_>> =
            chain[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH)?);
        end_entity
            .verify_for_usage(webpki::ALL_VERIFICATION_ALGS, &self.anchors, &intermediates, now, IkeUsage, None, None)
            .map_err(|e| untrusted(e.to_string()))?;
        if !covers(leaf, expected)? {
            return Err(untrusted(format!("the certificate is not valid for {}", expected.display())));
        }
        Ok(())
    }
}

/// Server authentication or IPsec IKE (RFC 4945 §5.1.3.12), or no EKU.
struct IkeUsage;

const EKU_SERVER_AUTH: KeyPurposeId<'static> = KeyPurposeId::new(&[43, 6, 1, 5, 5, 7, 3, 1]);
const EKU_IPSEC_IKE: KeyPurposeId<'static> = KeyPurposeId::new(&[43, 6, 1, 5, 5, 7, 3, 17]);
const EKU_ANY: KeyPurposeId<'static> = KeyPurposeId::new(&[85, 29, 37, 0]);

impl ExtendedKeyUsageValidator for IkeUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        let mut any = false;
        for eku in iter {
            let eku = eku?;
            any = true;
            if eku == EKU_SERVER_AUTH || eku == EKU_IPSEC_IKE || eku == EKU_ANY {
                return Ok(());
            }
        }
        // The context variant needs crate-private data to be built.
        #[allow(deprecated)]
        if any { Err(webpki::Error::RequiredEkuNotFound) } else { Ok(()) }
    }
}

fn parse(der: &[u8]) -> anyhow::Result<X509Certificate<'_>> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| anyhow!("invalid certificate: {e}"))?;
    Ok(cert)
}

/// The certificate's subject (DER), for an ID_DER_ASN1_DN identity.
pub fn subject(der: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(parse(der)?.subject().as_raw().to_vec())
}

/// Whether the certificate names `id`: in its subject alternative names
/// (DNS name, IPv4 address, e-mail), or as its subject (DN).
pub fn covers(der: &[u8], id: &Identity) -> anyhow::Result<bool> {
    let cert_der = CertificateDer::from(der);
    let end_entity = EndEntityCert::try_from(&cert_der).map_err(|e| anyhow!("invalid gateway certificate: {e}"))?;
    Ok(match id.id_type {
        id_type::FQDN | id_type::IPV4_ADDR => {
            let name = if id.id_type == id_type::FQDN {
                let Ok(text) = std::str::from_utf8(&id.data) else { return Ok(false) };
                let Ok(name) = ServerName::try_from(text) else { return Ok(false) };
                name
            } else {
                let Ok(octets) = <[u8; 4]>::try_from(id.data.as_slice()) else { return Ok(false) };
                ServerName::IpAddress(std::net::Ipv4Addr::from(octets).into())
            };
            end_entity.verify_is_valid_for_subject_name(&name).is_ok()
        }
        id_type::RFC822_ADDR => {
            let cert = parse(der)?;
            let names = cert.subject_alternative_name().ok().flatten();
            names.is_some_and(|san| {
                san.value.general_names.iter().any(
                    |n| matches!(n, GeneralName::RFC822Name(mail) if mail.as_bytes().eq_ignore_ascii_case(&id.data)),
                )
            })
        }
        id_type::DER_ASN1_DN => parse(der)?.subject().as_raw() == id.data.as_slice(),
        _ => false,
    })
}

/// Verifies the gateway's AUTH payload: `signed` is RealMessage2 | Ni |
/// prf(SK_pr, IDr).
pub fn verify_auth(der: &[u8], method: u8, data: &[u8], signed: &[u8]) -> anyhow::Result<()> {
    let cert = parse(der)?;
    let spki = cert.public_key();
    let key: &[u8] = &spki.subject_public_key.data;
    let kind = key_kind(&cert);
    let (alg, sig): (&'static dyn VerificationAlgorithm, &[u8]) = match (method, kind) {
        (auth_method::RSA_SIGNATURE, KeyKind::Rsa) => (&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, data),
        (auth_method::ECDSA_SHA256_P256, KeyKind::P256) => (&signature::ECDSA_P256_SHA256_FIXED, data),
        (auth_method::ECDSA_SHA384_P384, KeyKind::P384) => (&signature::ECDSA_P384_SHA384_FIXED, data),
        (auth_method::DIGITAL_SIGNATURE, _) => {
            let (&len, rest) = data.split_first().context("empty AUTH payload")?;
            ensure!(rest.len() > len as usize, "truncated RFC 7427 AUTH payload");
            let (id, sig) = rest.split_at(len as usize);
            let (_, id) = AlgorithmIdentifier::from_der(id).map_err(|e| anyhow!("bad signature algorithm: {e}"))?;
            (digital_signature(&id, kind)?, sig)
        }
        (auth_method::ECDSA_SHA512_P521, _) => bail!("ECDSA with P-521 is not supported for gateway signatures"),
        (other, _) => bail!("gateway signature method {other} does not match its certificate key"),
    };
    UnparsedPublicKey::new(alg, key)
        .verify(signed, sig)
        .map_err(|_| failure(FailureKind::Other, "the gateway AUTH signature is invalid"))
}

fn key_kind(cert: &X509Certificate<'_>) -> KeyKind {
    let spki = cert.public_key();
    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok());
    match (&spki.algorithm.algorithm, curve) {
        (alg, _) if *alg == OID_PKCS1_RSAENCRYPTION => KeyKind::Rsa,
        (alg, Some(c)) if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY && c == OID_EC_P256 => KeyKind::P256,
        (alg, Some(c)) if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY && c == OID_NIST_EC_P384 => KeyKind::P384,
        _ => KeyKind::Other,
    }
}

/// How our AUTH is signed with the client certificate's key, which the
/// client holds: RFC 7427 when the gateway announced SHA2-256, the
/// RFC 7296 / RFC 4754 methods otherwise.
pub struct ClientSigner {
    pub method: u8,
    pub algorithm: SignAlgorithm,
    /// RFC 7427: the length-prefixed AlgorithmIdentifier before the
    /// signature.
    prefix: &'static [u8],
    /// Classic ECDSA methods: r and s, each this wide.
    fixed: Option<usize>,
}

// RFC 7427 Appendix A.
const SHA256_WITH_RSA: &[u8] =
    &[15, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
const ECDSA_WITH_SHA256: &[u8] = &[12, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_WITH_SHA384: &[u8] = &[12, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

impl ClientSigner {
    /// `gateway_hashes`: its SIGNATURE_HASH_ALGORITHMS, if any.
    pub fn new(leaf: &[u8], gateway_hashes: &[u16]) -> anyhow::Result<Self> {
        let kind = key_kind(&parse(leaf)?);
        let rfc7427 = gateway_hashes.contains(&2);
        let signer = |method, algorithm, prefix, fixed| Self { method, algorithm, prefix, fixed };
        Ok(match (kind, rfc7427) {
            (KeyKind::Rsa, true) => {
                signer(auth_method::DIGITAL_SIGNATURE, SignAlgorithm::RsaPkcs1Sha256, SHA256_WITH_RSA, None)
            }
            (KeyKind::P256, true) => {
                signer(auth_method::DIGITAL_SIGNATURE, SignAlgorithm::EcdsaSha256, ECDSA_WITH_SHA256, None)
            }
            (KeyKind::P384, true) if gateway_hashes.contains(&3) => {
                signer(auth_method::DIGITAL_SIGNATURE, SignAlgorithm::EcdsaSha384, ECDSA_WITH_SHA384, None)
            }
            (KeyKind::P384, true) => {
                signer(auth_method::DIGITAL_SIGNATURE, SignAlgorithm::EcdsaSha256, ECDSA_WITH_SHA256, None)
            }
            (KeyKind::Rsa, false) => signer(auth_method::RSA_SIGNATURE, SignAlgorithm::RsaPkcs1Sha1, &[], None),
            (KeyKind::P256, false) => signer(auth_method::ECDSA_SHA256_P256, SignAlgorithm::EcdsaSha256, &[], Some(32)),
            (KeyKind::P384, false) => signer(auth_method::ECDSA_SHA384_P384, SignAlgorithm::EcdsaSha384, &[], Some(48)),
            (KeyKind::Other, _) => bail!("the client certificate key must be RSA, ECDSA P-256 or ECDSA P-384"),
        })
    }

    /// The AUTH payload body for `signature` (DER for ECDSA).
    pub fn auth_data(&self, signature: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature = match self.fixed {
            Some(width) => ecdsa_fixed(signature, width).context("malformed ECDSA signature from the Keychain")?,
            None => signature.to_vec(),
        };
        Ok([self.prefix, &signature].concat())
    }
}

/// An ECDSA-Sig-Value (SEQUENCE of INTEGER r, s) as r | s, `width` bytes
/// each (RFC 4754).
fn ecdsa_fixed(der: &[u8], width: usize) -> Option<Vec<u8>> {
    fn element(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (&t, rest) = data.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let (len, rest) = match len {
            0x81 => (*rest.first()? as usize, &rest[1..]),
            len if len < 0x80 => (len as usize, rest),
            _ => return None,
        };
        (t == tag && rest.len() >= len).then(|| rest.split_at(len))
    }
    let (body, rest) = element(der, 0x30)?;
    let mut out = Vec::with_capacity(2 * width);
    let (r, body) = element(body, 0x02)?;
    let (s, body) = element(body, 0x02)?;
    if !rest.is_empty() || !body.is_empty() {
        return None;
    }
    for int in [r, s] {
        let start = int.iter().position(|&b| b != 0).unwrap_or(int.len());
        let int = &int[start..];
        if int.len() > width {
            return None;
        }
        out.extend(std::iter::repeat_n(0, width - int.len()));
        out.extend_from_slice(int);
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Rsa,
    P256,
    P384,
    /// Ed25519 or unsupported: the verification decides.
    Other,
}

/// The algorithm an RFC 7427 AUTH names, checked against the key type.
fn digital_signature(
    id: &AlgorithmIdentifier<'_>,
    kind: KeyKind,
) -> anyhow::Result<&'static dyn VerificationAlgorithm> {
    let oid = &id.algorithm;
    let is_rsa = kind == KeyKind::Rsa;
    let (p256, p384) = (kind == KeyKind::P256, kind == KeyKind::P384);
    Ok(match () {
        _ if is_rsa && *oid == OID_PKCS1_SHA256WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA256,
        _ if is_rsa && *oid == OID_PKCS1_SHA384WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA384,
        _ if is_rsa && *oid == OID_PKCS1_SHA512WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA512,
        _ if is_rsa && *oid == OID_PKCS1_RSASSAPSS => {
            let Ok(SignatureAlgorithm::RSASSA_PSS(params)) = SignatureAlgorithm::try_from(id) else {
                bail!("bad RSASSA-PSS parameters");
            };
            match params.hash_algorithm_oid() {
                h if *h == OID_NIST_HASH_SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
                h if *h == OID_NIST_HASH_SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
                h if *h == OID_NIST_HASH_SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
                h => bail!("RSASSA-PSS with hash {h} is not supported"),
            }
        }
        _ if p256 && *oid == OID_SIG_ECDSA_WITH_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
        _ if p256 && *oid == OID_SIG_ECDSA_WITH_SHA384 => &signature::ECDSA_P256_SHA384_ASN1,
        _ if p384 && *oid == OID_SIG_ECDSA_WITH_SHA256 => &signature::ECDSA_P384_SHA256_ASN1,
        _ if p384 && *oid == OID_SIG_ECDSA_WITH_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
        _ if *oid == OID_SIG_ED25519 => &signature::ED25519,
        _ if *oid == OID_SIG_ECDSA_WITH_SHA512 => bail!("ECDSA with SHA-512 is not supported for gateway signatures"),
        _ => bail!("gateway signature algorithm {oid} is not supported or does not match its key"),
    })
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType};
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
        Ed25519KeyPair,
    };

    use super::*;

    struct Pki {
        ca_pem: String,
        leaf: Vec<u8>,
        leaf_key: KeyPair,
    }

    fn pki(eku: ExtendedKeyUsagePurpose, leaf_alg: &'static rcgen::SignatureAlgorithm) -> Pki {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name.push(DnType::CommonName, "test CA");
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate_for(leaf_alg).unwrap();
        let mut leaf = CertificateParams::new(vec!["gw.test".to_owned()]).unwrap();
        leaf.subject_alt_names.push(SanType::IpAddress("192.0.2.1".parse().unwrap()));
        leaf.subject_alt_names.push(SanType::Rfc822Name("gw@corp.test".try_into().unwrap()));
        leaf.distinguished_name.push(DnType::CommonName, "gw.test");
        leaf.extended_key_usages = vec![eku];
        let leaf_cert = leaf.signed_by(&leaf_key, &Issuer::new(ca, &ca_key)).unwrap();
        Pki { ca_pem: ca_cert.pem(), leaf: leaf_cert.der().to_vec(), leaf_key }
    }

    fn fqdn(name: &str) -> Identity {
        Identity::parse(name)
    }

    #[test]
    fn chain_and_identities() {
        let p = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let trust = GatewayTrust::new(Some(&p.ca_pem), None, &[], "gw.test", 500).unwrap();
        let chain = [p.leaf.clone()];
        trust.check(&chain, &fqdn("gw.test"), &fqdn("gw.test")).unwrap();
        trust.check(&chain, &fqdn("192.0.2.1"), &fqdn("gw@corp.test")).unwrap();
        let dn = Identity { id_type: id_type::DER_ASN1_DN, data: parse(&p.leaf).unwrap().subject().as_raw().to_vec() };
        trust.check(&chain, &fqdn("gw.test"), &dn).unwrap();
        // The certificate must name what the profile expects...
        let err = trust.check(&chain, &fqdn("other.test"), &fqdn("gw.test")).unwrap_err();
        assert!(matches!(vpn_core::failure::kind_of(&err), FailureKind::CertificateUntrusted { .. }), "{err}");
        // ...and the identity the gateway signed.
        assert!(trust.check(&chain, &fqdn("gw.test"), &fqdn("other.test")).is_err());
        assert!(trust.check(&[], &fqdn("gw.test"), &fqdn("gw.test")).is_err());
    }

    /// The Keychain's CAs are anchors too, kept out of CERTREQ; garbage
    /// among them is skipped.
    #[test]
    fn keychain_authorities() {
        let p = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let keychain = format!("{junk}{}", p.ca_pem);
        let trust = GatewayTrust::new(None, Some(&keychain), &[], "gw.test", 500).unwrap();
        trust.check(std::slice::from_ref(&p.leaf), &fqdn("gw.test"), &fqdn("gw.test")).unwrap();
        assert_eq!(trust.certreq(), [X509_SIGNATURE]);
    }

    #[test]
    fn unknown_ca_pins_and_key_usage() {
        let p = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let chain = [p.leaf.clone()];
        let other = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let untrusted = GatewayTrust::new(Some(&other.ca_pem), None, &[], "gw.test", 500).unwrap();
        let err = untrusted.check(&chain, &fqdn("gw.test"), &fqdn("gw.test")).unwrap_err();
        let FailureKind::CertificateUntrusted { certificate } = vpn_core::failure::kind_of(&err) else {
            panic!("{err}")
        };
        assert_eq!(certificate.sha256, hex::encode(Sha256::digest(&p.leaf)));

        // A pin trusts the certificate as is; another pin blocks it.
        let pinned = GatewayTrust::new(None, None, &[certificate.sha256.to_ascii_uppercase()], "gw.test", 500).unwrap();
        pinned.check(&chain, &fqdn("other.test"), &fqdn("gw.test")).unwrap();
        let changed = GatewayTrust::new(None, None, &["00".repeat(32)], "gw.test", 500).unwrap();
        let err = changed.check(&chain, &fqdn("gw.test"), &fqdn("gw.test")).unwrap_err();
        assert!(matches!(vpn_core::failure::kind_of(&err), FailureKind::CertificateChanged { .. }));

        // A client certificate is no gateway certificate.
        let client = pki(ExtendedKeyUsagePurpose::ClientAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let trust = GatewayTrust::new(Some(&client.ca_pem), None, &[], "gw.test", 500).unwrap();
        assert!(trust.check(&[client.leaf], &fqdn("gw.test"), &fqdn("gw.test")).is_err());
        assert_eq!(trust.certreq().len(), 21, "encoding and one CA key hash");
    }

    #[test]
    fn auth_signatures() {
        let rng = SystemRandom::new();
        let signed = b"RealMessage2 | Ni | prf(SK_pr, IDr)";
        let p = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ECDSA_P256_SHA256);
        let pkcs8 = p.leaf_key.serialize_der();

        // RFC 4754: fixed-size r | s.
        let fixed = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
        let sig = fixed.sign(&rng, signed).unwrap().as_ref().to_vec();
        verify_auth(&p.leaf, auth_method::ECDSA_SHA256_P256, &sig, signed).unwrap();
        assert!(verify_auth(&p.leaf, auth_method::ECDSA_SHA256_P256, &sig, b"something else").is_err());
        assert!(verify_auth(&p.leaf, auth_method::RSA_SIGNATURE, &sig, signed).is_err(), "not an RSA key");
        assert!(verify_auth(&p.leaf, auth_method::ECDSA_SHA384_P384, &sig, signed).is_err(), "not a P-384 key");

        // RFC 7427: AlgorithmIdentifier, then a DER signature.
        let ecdsa_sha256 = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let asn1 = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
        let mut data = vec![ecdsa_sha256.len() as u8];
        data.extend_from_slice(&ecdsa_sha256);
        data.extend_from_slice(asn1.sign(&rng, signed).unwrap().as_ref());
        verify_auth(&p.leaf, auth_method::DIGITAL_SIGNATURE, &data, signed).unwrap();
        let rsa_sha256 = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
        let mut wrong = vec![rsa_sha256.len() as u8];
        wrong.extend_from_slice(&rsa_sha256);
        wrong.extend_from_slice(&data[1 + ecdsa_sha256.len()..]);
        assert!(verify_auth(&p.leaf, auth_method::DIGITAL_SIGNATURE, &wrong, signed).is_err(), "RSA on an EC key");

        let ed = pki(ExtendedKeyUsagePurpose::ServerAuth, &rcgen::PKCS_ED25519);
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&ed.leaf_key.serialize_der()).unwrap();
        let ed25519 = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let mut data = vec![ed25519.len() as u8];
        data.extend_from_slice(&ed25519);
        data.extend_from_slice(key.sign(signed).as_ref());
        verify_auth(&ed.leaf, auth_method::DIGITAL_SIGNATURE, &data, signed).unwrap();
    }

    /// Our AUTH with the client's key, as the Keychain signs (DER for
    /// ECDSA): RFC 7427 when the gateway allows it, classic otherwise.
    #[test]
    fn client_signatures() {
        let rng = SystemRandom::new();
        let signed = b"RealMessage1 | Nr | prf(SK_pi, IDi)";
        for (alg, ring_alg, hashes, method, algorithm) in [
            (
                &rcgen::PKCS_ECDSA_P256_SHA256,
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &[2u16, 3, 4][..],
                14,
                SignAlgorithm::EcdsaSha256,
            ),
            (&rcgen::PKCS_ECDSA_P256_SHA256, &ECDSA_P256_SHA256_ASN1_SIGNING, &[], 9, SignAlgorithm::EcdsaSha256),
            (&rcgen::PKCS_ECDSA_P384_SHA384, &ECDSA_P384_SHA384_ASN1_SIGNING, &[2, 3], 14, SignAlgorithm::EcdsaSha384),
            (&rcgen::PKCS_ECDSA_P384_SHA384, &ECDSA_P384_SHA384_ASN1_SIGNING, &[], 10, SignAlgorithm::EcdsaSha384),
        ] {
            let p = pki(ExtendedKeyUsagePurpose::ClientAuth, alg);
            let signer = ClientSigner::new(&p.leaf, hashes).unwrap();
            assert_eq!((signer.method, signer.algorithm), (method, algorithm));
            let key = EcdsaKeyPair::from_pkcs8(ring_alg, &p.leaf_key.serialize_der(), &rng).unwrap();
            for _ in 0..8 {
                // r and s vary in length: some need padding.
                let data = signer.auth_data(key.sign(&rng, signed).unwrap().as_ref()).unwrap();
                verify_auth(&p.leaf, method, &data, signed).unwrap();
            }
        }
        // A P-384 key with a gateway that only knows SHA2-256.
        let p = pki(ExtendedKeyUsagePurpose::ClientAuth, &rcgen::PKCS_ECDSA_P384_SHA384);
        assert_eq!(ClientSigner::new(&p.leaf, &[2]).unwrap().algorithm, SignAlgorithm::EcdsaSha256);
        let ed = pki(ExtendedKeyUsagePurpose::ClientAuth, &rcgen::PKCS_ED25519);
        assert!(ClientSigner::new(&ed.leaf, &[2]).is_err(), "no Ed25519 in the Keychain");
        assert!(ecdsa_fixed(&[0x30, 0x03, 0x02, 0x01, 0x01], 32).is_none(), "s missing");
    }
}
