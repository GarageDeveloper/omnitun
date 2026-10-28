//! What the user's Keychain holds besides passwords: the certificate
//! authorities it trusts (MDM profiles, certificates marked "Always
//! Trust"), handed to the engine at each connection since the sandboxed
//! engine cannot read the Keychain; and the identities (certificate and
//! private key) a profile may authenticate with. Their keys never leave
//! the Keychain: the engine asks the client for each signature.

use vpn_core::SignAlgorithm;
#[cfg(target_os = "macos")]
use x509_parser::prelude::{FromDer, X509Certificate};

/// A certificate with its private key, as offered in the editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The subject's common name, or the whole subject.
    pub name: String,
    pub issuer: String,
    /// Unix time.
    pub not_after: i64,
    /// SHA-256 (hex) of the certificate: what profiles store.
    pub sha256: String,
}

/// The identities fit for VPN authentication: no code-signing or e-mail
/// certificate, RSA or ECDSA P-256/P-384 keys.
pub fn identities() -> anyhow::Result<Vec<Identity>> {
    #[cfg(target_os = "macos")]
    return Ok(macos::identities(None)?.into_iter().filter_map(|(der, _)| describe(&der)).collect());
    #[cfg(not(target_os = "macos"))]
    Ok(Vec::new())
}

/// The certificate `sha256` and its intermediates, as PEM, for the
/// engine to send.
pub fn certificate_chain(sha256: &str) -> anyhow::Result<String> {
    #[cfg(target_os = "macos")]
    return Ok(macos::chain(sha256, None)?.iter().map(|der| pem("CERTIFICATE", der)).collect());
    #[cfg(not(target_os = "macos"))]
    anyhow::bail!("client certificates come from the macOS Keychain (certificate {sha256})")
}

/// Signs `data` with the key of certificate `sha256`; the Keychain may
/// ask the user to allow it. ECDSA signatures are DER.
pub fn sign(sha256: &str, algorithm: SignAlgorithm, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    return macos::sign(sha256, algorithm, data, None);
    #[cfg(not(target_os = "macos"))]
    anyhow::bail!(
        "client certificates come from the macOS Keychain ({algorithm:?} with {sha256}, {} bytes)",
        data.len()
    )
}

/// The common name, or the whole name. Many CAs put UTF-8 in
/// TeletexString, which x509-parser reads as Latin-1.
#[cfg(target_os = "macos")]
fn common_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    let Some(cn) = name.iter_common_name().next() else { return name.to_string() };
    let value = cn.attr_value();
    match value.header.tag() {
        x509_parser::der_parser::asn1_rs::Tag::BmpString => cn.as_str().map(str::to_owned).ok(),
        _ => std::str::from_utf8(value.data).map(str::to_owned).ok(),
    }
    .unwrap_or_else(|| name.to_string())
}

#[cfg(target_os = "macos")]
fn sha256_hex(der: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(der))
}

/// EKUs a VPN client certificate may carry, besides none at all.
#[cfg(target_os = "macos")]
const VPN_USAGES: [&str; 5] = [
    "1.3.6.1.5.5.7.3.2",  // clientAuth
    "1.3.6.1.5.5.7.3.17", // ipsecIKE
    "1.3.6.1.5.5.7.3.5",  // ipsecEndSystem
    "1.3.6.1.5.5.7.3.7",  // ipsecUser
    "2.5.29.37.0",        // anyExtendedKeyUsage
];

#[cfg(target_os = "macos")]
fn describe(der: &[u8]) -> Option<Identity> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        let eku = eku.value;
        let fits =
            eku.any || eku.client_auth || eku.other.iter().any(|oid| VPN_USAGES.contains(&oid.to_id_string().as_str()));
        if !fits {
            return None;
        }
    }
    let key = cert.public_key().algorithm.algorithm.to_id_string();
    if key != "1.2.840.113549.1.1.1" && key != "1.2.840.10045.2.1" {
        return None; // neither RSA nor EC
    }
    let name = common_name(cert.subject());
    if name.starts_with("com.apple.") {
        return None; // the system's own (iCloud, Kerberos)
    }
    Some(Identity {
        name,
        issuer: common_name(cert.issuer()),
        not_after: cert.validity().not_after.timestamp(),
        sha256: sha256_hex(der),
    })
}

/// The CAs trusted in the user and admin (MDM) trust settings, as PEM;
/// empty elsewhere than macOS. The public roots come with the engine.
pub fn trusted_authorities() -> String {
    #[cfg(target_os = "macos")]
    match macos::trusted_authorities() {
        Ok(ders) => return ders.iter().map(|der| pem("CERTIFICATE", der)).collect(),
        Err(e) => tracing::warn!("cannot read the Keychain trust settings: {e:#}"),
    }
    String::new()
}

#[cfg(any(target_os = "macos", test))]
fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).expect("base64")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;

    use anyhow::Context;
    use security_framework::certificate::SecCertificate;
    use security_framework::identity::SecIdentity;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::key::Algorithm;
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::policy::SecPolicy;
    use security_framework::trust::SecTrust;
    use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
    use vpn_core::SignAlgorithm;

    /// Every identity, with its certificate; `keychains` restricts the
    /// search (tests).
    pub fn identities(keychains: Option<&[SecKeychain]>) -> anyhow::Result<Vec<(Vec<u8>, SecIdentity)>> {
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::identity()).load_refs(true).limit(Limit::All);
        if let Some(keychains) = keychains {
            search.keychains(keychains);
        }
        let found = match search.search() {
            Ok(found) => found,
            Err(e) if e.code() == -25300 => return Ok(Vec::new()), // errSecItemNotFound
            Err(e) => return Err(e).context("cannot search the Keychain"),
        };
        Ok(found
            .into_iter()
            .filter_map(|item| match item {
                SearchResult::Ref(Reference::Identity(identity)) => {
                    Some((identity.certificate().ok()?.to_der(), identity))
                }
                _ => None,
            })
            .collect())
    }

    fn find(sha256: &str, keychains: Option<&[SecKeychain]>) -> anyhow::Result<(Vec<u8>, SecIdentity)> {
        identities(keychains)?
            .into_iter()
            .find(|(der, _)| super::sha256_hex(der).eq_ignore_ascii_case(sha256))
            .with_context(|| format!("the client certificate {sha256} is not in the Keychain"))
    }

    /// The certificate, then the intermediates the system finds for it
    /// (the root is left out: the gateway has it).
    pub fn chain(sha256: &str, keychains: Option<&[SecKeychain]>) -> anyhow::Result<Vec<Vec<u8>>> {
        let (leaf, identity) = find(sha256, keychains)?;
        let mut chain = vec![leaf];
        let trust = SecTrust::create_with_certificates(&[identity.certificate()?], &[SecPolicy::create_x509()])?;
        // An untrusted chain is still built as far as it goes.
        let _ = trust.evaluate_with_error();
        for cert in trust.chain().iter().skip(1) {
            if cert.subject() != cert.issuer() {
                chain.push(cert.to_der());
            }
        }
        Ok(chain)
    }

    pub fn sign(
        sha256: &str,
        algorithm: SignAlgorithm,
        data: &[u8],
        keychains: Option<&[SecKeychain]>,
    ) -> anyhow::Result<Vec<u8>> {
        let (_, identity) = find(sha256, keychains)?;
        let key = identity.private_key().context("the client certificate has no usable private key")?;
        let algorithm = match algorithm {
            SignAlgorithm::RsaPkcs1Sha1 => Algorithm::RSASignatureMessagePKCS1v15SHA1,
            SignAlgorithm::RsaPkcs1Sha256 => Algorithm::RSASignatureMessagePKCS1v15SHA256,
            SignAlgorithm::RsaPkcs1Sha384 => Algorithm::RSASignatureMessagePKCS1v15SHA384,
            SignAlgorithm::RsaPkcs1Sha512 => Algorithm::RSASignatureMessagePKCS1v15SHA512,
            SignAlgorithm::RsaPssSha256 => Algorithm::RSASignatureMessagePSSSHA256,
            SignAlgorithm::RsaPssSha384 => Algorithm::RSASignatureMessagePSSSHA384,
            SignAlgorithm::RsaPssSha512 => Algorithm::RSASignatureMessagePSSSHA512,
            SignAlgorithm::EcdsaSha256 => Algorithm::ECDSASignatureMessageX962SHA256,
            SignAlgorithm::EcdsaSha384 => Algorithm::ECDSASignatureMessageX962SHA384,
        };
        key.create_signature(algorithm, data).map_err(|e| anyhow::anyhow!("the Keychain did not sign: {e}"))
    }

    /// User settings override admin ones, as in the system's evaluation.
    /// Empty settings trust a certificate as a root for every use; settings
    /// for other uses only (S/MIME, code signing) say nothing about TLS.
    pub fn trusted_authorities() -> anyhow::Result<Vec<Vec<u8>>> {
        let mut decided: HashMap<Vec<u8>, TrustSettingsForCertificate> = HashMap::new();
        for domain in [Domain::User, Domain::Admin] {
            let settings = TrustSettings::new(domain);
            let Ok(certificates) = settings.iter() else {
                continue; // no trust settings in this domain
            };
            for certificate in certificates {
                let trust = match settings.tls_trust_settings_for_certificate(&certificate) {
                    Ok(Some(trust)) => trust,
                    Ok(None) if trusted_for_everything(&certificate, domain) => TrustSettingsForCertificate::TrustRoot,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::debug!("{}: {e}", certificate.subject_summary());
                        continue;
                    }
                };
                decided.entry(certificate.to_der()).or_insert(trust);
            }
        }
        Ok(decided
            .into_iter()
            .filter(|(_, trust)| {
                matches!(trust, TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot)
            })
            .map(|(der, _)| der)
            .collect())
    }

    /// Whether the certificate's settings in `domain` are an empty list,
    /// which trusts it as a root whatever the use.
    fn trusted_for_everything(certificate: &SecCertificate, domain: Domain) -> bool {
        use core_foundation::array::{CFArray, CFArrayRef};
        use core_foundation::base::{CFType, TCFType};
        use security_framework_sys::base::errSecSuccess;
        use security_framework_sys::trust_settings::SecTrustSettingsCopyTrustSettings;

        let mut array: CFArrayRef = std::ptr::null();
        // SAFETY: a valid certificate and out pointer; the array returned
        // follows the create rule.
        let status =
            unsafe { SecTrustSettingsCopyTrustSettings(certificate.as_concrete_TypeRef(), domain.into(), &mut array) };
        if status != errSecSuccess || array.is_null() {
            return false;
        }
        let array = unsafe { CFArray::<CFType>::wrap_under_create_rule(array) };
        array.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pem_lines() {
        let pem = super::pem("CERTIFICATE", &[0u8; 60]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!((lines[1].len(), lines[2].len()), (64, 16));
        use rustls::pki_types::pem::PemObject;
        assert!(rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()).next().is_some());
    }

    /// A throwaway keychain with one identity, without access control so
    /// no dialog shows: found, described, chained and signing with the
    /// macOS API. Run with `--ignored` (it creates a keychain file).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn keychain_identity_signs() {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        use security_framework::os::macos::import_export::ImportOptions;
        use security_framework::os::macos::keychain::CreateOptions;
        use vpn_core::SignAlgorithm;
        use x509_parser::prelude::FromDer;

        let dir = std::env::temp_dir().join(format!("omnitun-keychain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.keychain-db");
        let mut keychain = CreateOptions::new().password("test").create(&path).unwrap();
        keychain.unlock(Some("test")).unwrap();
        let cleanup = scopeguard(&path);

        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["alice.corp.test".to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "Alice");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).unwrap();
        // As users receive identities: a PKCS#12 file.
        std::fs::write(dir.join("alice.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("alice.key"), key.serialize_pem()).unwrap();
        let status = std::process::Command::new("/usr/bin/openssl")
            .current_dir(&dir)
            .args(["pkcs12", "-export", "-inkey", "alice.key", "-in", "alice.pem", "-out", "alice.p12"])
            .args(["-passout", "pass:test"])
            .status()
            .unwrap();
        assert!(status.success());
        let p12 = std::fs::read(dir.join("alice.p12")).unwrap();
        ImportOptions::new()
            .filename("alice.p12")
            .passphrase("test")
            .keychain(&keychain)
            .no_access_control(true)
            .import(&p12)
            .unwrap();

        let keychains = [keychain];
        let found = super::macos::identities(Some(&keychains)).unwrap();
        assert_eq!(found.len(), 1);
        let identity = super::describe(&found[0].0).unwrap();
        assert_eq!((identity.name.as_str(), identity.issuer.as_str()), ("Alice", "Alice"));
        assert_eq!(identity.sha256, super::sha256_hex(cert.der()));
        // Self-signed: no intermediate.
        assert_eq!(super::macos::chain(&identity.sha256, Some(&keychains)).unwrap(), vec![cert.der().to_vec()]);

        let data = b"RealMessage1 | Nr | prf(SK_pi, IDi)";
        let signature =
            super::macos::sign(&identity.sha256, SignAlgorithm::EcdsaSha256, data, Some(&keychains)).unwrap();
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(cert.der()).unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &parsed.public_key().subject_public_key.data,
        )
        .verify(data, &signature)
        .unwrap();
        assert!(super::macos::sign(&"00".repeat(32), SignAlgorithm::EcdsaSha256, data, Some(&keychains)).is_err());
        drop(cleanup);
    }

    /// Deletes the test keychain (and takes it off the search list).
    #[cfg(target_os = "macos")]
    fn scopeguard(path: &std::path::Path) -> impl Drop + '_ {
        struct Guard<'a>(&'a std::path::Path);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let _ = std::process::Command::new("/usr/bin/security").arg("delete-keychain").arg(self.0).status();
                let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
            }
        }
        Guard(path)
    }

    /// Reads this Mac's settings (whatever they hold) without failing.
    #[cfg(target_os = "macos")]
    #[test]
    fn reads_the_trust_settings() {
        super::macos::trusted_authorities().unwrap();
    }
}
