//! Windows: the user's certificate store stands for the macOS Keychain.
//! Identities are the certificates of the personal store (`CurrentUser\My`,
//! where a PKCS#12 file goes when opened or imported with `certutil
//! -user -importpfx`) with a private key; the key signs through CNG and
//! never leaves the store. The CAs handed to the engine are those an
//! administrator or a group policy added to the trusted roots, and the
//! user's own: the public roots come with the engine.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use anyhow::{Context, bail};
use vpn_core::SignAlgorithm;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, CALG_SHA_256, CALG_SHA_384,
    CALG_SHA_512, CALG_SHA1, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID,
    CERT_NCRYPT_KEY_SPEC, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_PHYSICAL_W, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_ACQUIRE_CACHE_FLAG,
    CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, CRYPT_KEY_PROV_INFO, CRYPT_MACHINE_KEYSET, CertCloseStore,
    CertEnumCertificatesInStore, CertFreeCertificateChain, CertGetCertificateChain, CertGetCertificateContextProperty,
    CertOpenStore, CryptAcquireCertificatePrivateKey, CryptAcquireContextW, CryptCreateHash, CryptDestroyHash,
    CryptReleaseContext, CryptSetHashParam, CryptSignHashW, HCERTSTORE, HP_HASHVAL, MS_ENH_RSA_AES_PROV_W,
    NCryptSignHash, PKCS_7_ASN_ENCODING, PROV_RSA_AES, PROV_RSA_FULL, X509_ASN_ENCODING,
};

/// NTE_BAD_ALGID: the provider does not know the hash.
const NTE_BAD_ALGID: i32 = 0x8009_0008_u32 as i32;

const CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY: u32 = 7 << 16;
const CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY: u32 = 8 << 16;
const CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE: u32 = 9 << 16;

/// The certificates (DER) of the personal store with a private key.
pub fn identities() -> anyhow::Result<Vec<Vec<u8>>> {
    let store = Store::open(CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, "MY")?;
    Ok(store.certificates().filter(|c| has_key(c.0)).map(|c| c.der()).collect())
}

/// The certificate `sha256` and its intermediates (the root is left out:
/// the gateway has it).
pub fn chain(sha256: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let store = Store::open(CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, "MY")?;
    let leaf = store.find(sha256)?;
    let para = CERT_CHAIN_PARA { cbSize: size_of::<CERT_CHAIN_PARA>() as u32, ..Default::default() };
    let mut context: *mut CERT_CHAIN_CONTEXT = null_mut();
    // SAFETY: a certificate of an open store; the context is freed below.
    // An untrusted chain is still built as far as it goes.
    if unsafe { CertGetCertificateChain(null_mut(), leaf.0, null(), store.0, &para, 0, null(), &mut context) } == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot build the certificate's chain");
    }
    let mut chain = vec![leaf.der()];
    // SAFETY: the context holds `cChain` simple chains of `cElement`
    // elements each, alive until freed.
    unsafe {
        if (*context).cChain > 0 {
            let simple = *(*context).rgpChain;
            for i in 1..(*simple).cElement as usize {
                let element = *(*simple).rgpElement.add(i);
                let cert = Certificate((*element).pCertContext);
                let der = cert.der();
                std::mem::forget(cert); // owned by the chain context
                if !self_signed(&der) {
                    chain.push(der);
                }
            }
        }
        CertFreeCertificateChain(context);
    }
    Ok(chain)
}

/// Signs `data` with the key of certificate `sha256`, hashing it first as
/// the algorithm says. ECDSA signatures are DER. CNG keys are preferred;
/// a key of a CryptoAPI provider (an old certificate template, a PKCS#12
/// imported for a CSP, a smart card with only a CSP) signs through it, RSA
/// PKCS#1 only: CSPs know neither PSS nor ECDSA.
pub fn sign(sha256: &str, algorithm: SignAlgorithm, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    sign_with(sha256, algorithm, data, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG)
}

/// `sign`, opening the key with `acquire` (0: CryptoAPI only, for tests).
fn sign_with(sha256: &str, algorithm: SignAlgorithm, data: &[u8], acquire: u32) -> anyhow::Result<Vec<u8>> {
    use ring::digest;
    let store = Store::open(CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, "MY")?;
    let cert = store.find(sha256)?;
    let (hash, name, calg, padding) = match algorithm {
        SignAlgorithm::RsaPkcs1Sha1 => (&digest::SHA1_FOR_LEGACY_USE_ONLY, "SHA1", CALG_SHA1, Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha256 => (&digest::SHA256, "SHA256", CALG_SHA_256, Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha384 => (&digest::SHA384, "SHA384", CALG_SHA_384, Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha512 => (&digest::SHA512, "SHA512", CALG_SHA_512, Padding::Pkcs1),
        SignAlgorithm::RsaPssSha256 => (&digest::SHA256, "SHA256", CALG_SHA_256, Padding::Pss),
        SignAlgorithm::RsaPssSha384 => (&digest::SHA384, "SHA384", CALG_SHA_384, Padding::Pss),
        SignAlgorithm::RsaPssSha512 => (&digest::SHA512, "SHA512", CALG_SHA_512, Padding::Pss),
        SignAlgorithm::EcdsaSha256 => (&digest::SHA256, "SHA256", CALG_SHA_256, Padding::None),
        SignAlgorithm::EcdsaSha384 => (&digest::SHA384, "SHA384", CALG_SHA_384, Padding::None),
    };
    let hashed = digest::digest(hash, data);
    let hashed = hashed.as_ref();

    let (mut key, mut spec, mut free) = (0usize, 0u32, 0i32);
    // SAFETY: a certificate of an open store; the key handle is cached
    // with the certificate (CRYPT_ACQUIRE_CACHE_FLAG), not ours to free.
    if unsafe {
        CryptAcquireCertificatePrivateKey(
            cert.0,
            acquire | CRYPT_ACQUIRE_CACHE_FLAG,
            null(),
            &mut key,
            &mut spec,
            &mut free,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("the client certificate has no usable private key");
    }
    if spec == CERT_NCRYPT_KEY_SPEC {
        sign_cng(key, name, padding, hashed)
    } else {
        if !matches!(padding, Padding::Pkcs1) {
            bail!(
                "the client certificate's key is in an old CryptoAPI provider, which can only make RSA PKCS#1 \
                 signatures: import it again for a CNG provider"
            );
        }
        sign_csp(&cert, key, spec, calg, hashed)
    }
}

fn sign_cng(key: usize, name: &str, padding: Padding, hashed: &[u8]) -> anyhow::Result<Vec<u8>> {
    let algorithm_id: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let pkcs1 = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: algorithm_id.as_ptr() };
    // The salt as long as the hash, as TLS and IKE expect.
    let pss = BCRYPT_PSS_PADDING_INFO { pszAlgId: algorithm_id.as_ptr(), cbSalt: hashed.len() as u32 };
    let (info, flags): (*const c_void, u32) = match padding {
        Padding::Pkcs1 => ((&raw const pkcs1).cast(), BCRYPT_PAD_PKCS1),
        Padding::Pss => ((&raw const pss).cast(), BCRYPT_PAD_PSS),
        Padding::None => (null(), 0),
    };
    let mut size = 0u32;
    // SAFETY: a size query, then a buffer of that size.
    let status =
        unsafe { NCryptSignHash(key, info, hashed.as_ptr(), hashed.len() as u32, null_mut(), 0, &mut size, flags) };
    if status != 0 {
        bail!("cannot sign with the client certificate's key (0x{status:08x})");
    }
    let mut signature = vec![0u8; size as usize];
    let status = unsafe {
        NCryptSignHash(key, info, hashed.as_ptr(), hashed.len() as u32, signature.as_mut_ptr(), size, &mut size, flags)
    };
    if status != 0 {
        bail!("cannot sign with the client certificate's key (0x{status:08x})");
    }
    signature.truncate(size as usize);
    Ok(match padding {
        Padding::None => ecdsa_der(&signature)?,
        _ => signature,
    })
}

/// RSA PKCS#1 with the key of a CryptoAPI provider. The base and strong
/// providers (PROV_RSA_FULL) hash no SHA-2: their keys are opened again in
/// the AES provider, which reads the same containers.
fn sign_csp(cert: &Certificate, provider: usize, spec: u32, calg: u32, hashed: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The hash before the provider it was made in: dropped in this order.
    let (hash, _reopened) = match CspHash::new(provider, calg, hashed) {
        Ok(hash) => (hash, None),
        Err(e) if e.raw_os_error() == Some(NTE_BAD_ALGID) => {
            let reopened = Provider::aes(cert)?
                .context("the client certificate's CryptoAPI provider cannot sign with this hash")?;
            let hash =
                CspHash::new(reopened.0, calg, hashed).context("cannot hash for the client certificate's key")?;
            (hash, Some(reopened))
        }
        Err(e) => return Err(e).context("cannot hash for the client certificate's key"),
    };
    let mut size = 0u32;
    // SAFETY: a size query, then a buffer of that size, on a hash of the
    // key's provider; `spec` is the key's (AT_SIGNATURE or AT_KEYEXCHANGE).
    if unsafe { CryptSignHashW(hash.0, spec, null(), 0, null_mut(), &mut size) } == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot sign with the client certificate's key");
    }
    let mut signature = vec![0u8; size as usize];
    if unsafe { CryptSignHashW(hash.0, spec, null(), 0, signature.as_mut_ptr(), &mut size) } == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot sign with the client certificate's key");
    }
    signature.truncate(size as usize);
    // CryptoAPI writes it little-endian.
    signature.reverse();
    Ok(signature)
}

/// A CryptoAPI hash object holding an already computed hash.
struct CspHash(usize);

impl CspHash {
    fn new(provider: usize, calg: u32, hashed: &[u8]) -> std::io::Result<Self> {
        let mut hash = 0usize;
        // SAFETY: a provider handle that outlives the hash; destroyed on
        // drop. HP_HASHVAL takes a value as long as the algorithm's hash.
        unsafe {
            if CryptCreateHash(provider, calg, 0, 0, &mut hash) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let hash = Self(hash);
            if CryptSetHashParam(hash.0, HP_HASHVAL, hashed.as_ptr(), 0) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(hash)
        }
    }
}

impl Drop for CspHash {
    fn drop(&mut self) {
        // SAFETY: a hash this value created.
        unsafe { CryptDestroyHash(self.0) };
    }
}

/// A CryptoAPI provider this module opened.
struct Provider(usize);

impl Provider {
    /// The certificate's key container in the AES provider, if its key is
    /// in one of Microsoft's software RSA providers; None otherwise.
    fn aes(cert: &Certificate) -> anyhow::Result<Option<Self>> {
        let mut size = 0u32;
        // SAFETY: a size query, then a buffer of that size, aligned for
        // the CRYPT_KEY_PROV_INFO it receives (strings point inside it).
        unsafe {
            if CertGetCertificateContextProperty(cert.0, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut size) == 0 {
                return Ok(None);
            }
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            if CertGetCertificateContextProperty(
                cert.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                buffer.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                return Ok(None);
            }
            let info = &*buffer.as_ptr().cast::<CRYPT_KEY_PROV_INFO>();
            let provider = wide_string(info.pwszProvName);
            if info.dwProvType != PROV_RSA_FULL || !provider.starts_with("Microsoft") {
                return Ok(None);
            }
            let mut handle = 0usize;
            let flags = info.dwFlags & CRYPT_MACHINE_KEYSET;
            if CryptAcquireContextW(&mut handle, info.pwszContainerName, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, flags)
                == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("cannot open the client certificate's key in the AES provider");
            }
            Ok(Some(Self(handle)))
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: a provider this value opened.
        unsafe { CryptReleaseContext(self.0, 0) };
    }
}

/// A NUL-terminated UTF-16 string, empty if null.
///
/// # Safety
/// `s` is null or points to a NUL-terminated string.
unsafe fn wide_string(s: *const u16) -> String {
    if s.is_null() {
        return String::new();
    }
    // SAFETY: as the caller says.
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) })
}

/// The roots added by an administrator, a group policy or the user.
pub fn trusted_authorities() -> anyhow::Result<Vec<Vec<u8>>> {
    let mut found = Vec::new();
    for (provider, location, name) in [
        (CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, "Root"),
        (CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, "Root"),
        (CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY, "Root"),
        // The user's own: their part of the logical Root store.
        (CERT_STORE_PROV_PHYSICAL_W, CERT_SYSTEM_STORE_CURRENT_USER, r"Root\.Default"),
    ] {
        // A store that does not exist holds nothing.
        let Ok(store) = Store::open(provider, location, name) else { continue };
        found.extend(store.certificates().map(|c| c.der()));
    }
    found.sort();
    found.dedup();
    Ok(found)
}

enum Padding {
    Pkcs1,
    Pss,
    None,
}

/// CNG's ECDSA signature (r and s, each as long as the curve) as DER.
pub(crate) fn ecdsa_der(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        bail!("invalid ECDSA signature of {} bytes", raw.len());
    }
    let integer = |bytes: &[u8]| {
        let bytes = &bytes[bytes.iter().take_while(|b| **b == 0).count().min(bytes.len() - 1)..];
        let mut out = vec![0x02];
        let pad = bytes[0] & 0x80 != 0;
        der_length(&mut out, bytes.len() + pad as usize);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(bytes);
        out
    };
    let (r, s) = raw.split_at(raw.len() / 2);
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30];
    der_length(&mut out, body.len());
    out.extend(body);
    Ok(out)
}

fn der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn self_signed(der: &[u8]) -> bool {
    use x509_parser::prelude::{FromDer, X509Certificate};
    X509Certificate::from_der(der).is_ok_and(|(_, c)| c.subject() == c.issuer())
}

/// Whether the certificate names a private key (without opening it, which
/// could ask the user).
fn has_key(cert: *const CERT_CONTEXT) -> bool {
    let mut size = 0;
    // SAFETY: a size query on a valid certificate.
    unsafe { CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut size) != 0 }
}

struct Store(HCERTSTORE);

impl Store {
    fn open(provider: windows_sys::core::PCSTR, location: u32, name: &str) -> anyhow::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated name; closed on drop.
        let store = unsafe {
            CertOpenStore(
                provider,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                name.as_ptr().cast(),
            )
        };
        if store.is_null() {
            return Err(std::io::Error::last_os_error()).context("cannot open the certificate store");
        }
        Ok(Self(store))
    }

    fn certificates(&self) -> impl Iterator<Item = Certificate> + '_ {
        let mut previous: *const CERT_CONTEXT = null();
        std::iter::from_fn(move || {
            // SAFETY: enumeration frees the previous context and returns
            // the next; each is duplicated for the caller.
            let next = unsafe { CertEnumCertificatesInStore(self.0, previous) };
            if next.is_null() {
                return None;
            }
            previous = next;
            // SAFETY: a valid context, duplicated so the caller owns one.
            Some(Certificate(unsafe {
                windows_sys::Win32::Security::Cryptography::CertDuplicateCertificateContext(next)
            }))
        })
    }

    /// The certificate whose SHA-256 is `sha256`.
    fn find(&self, sha256: &str) -> anyhow::Result<Certificate> {
        use sha2::Digest;
        let wanted = sha256.to_ascii_lowercase();
        self.certificates()
            .find(|c| hex::encode(sha2::Sha256::digest(c.der())) == wanted)
            .with_context(|| format!("certificate {sha256} is not in your personal certificate store"))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: a store this value opened.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

struct Certificate(*const CERT_CONTEXT);

impl Certificate {
    fn der(&self) -> Vec<u8> {
        // SAFETY: a valid context holds its encoding.
        unsafe { std::slice::from_raw_parts((*self.0).pbCertEncoded, (*self.0).cbCertEncoded as usize).to_vec() }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: a context this value owns (duplicated).
        unsafe { windows_sys::Win32::Security::Cryptography::CertFreeCertificateContext(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_signatures_become_der() {
        // r with its high bit set (padded), s with leading zeros (trimmed).
        let mut raw = vec![0x80; 32];
        raw.extend([0, 0, 1].iter().chain([7u8; 29].iter()));
        let der = ecdsa_der(&raw).unwrap();
        assert_eq!(&der[..2], &[0x30, 2 + 33 + 2 + 30]);
        assert_eq!(&der[2..5], &[0x02, 33, 0x00]);
        assert_eq!(&der[37..40], &[0x02, 30, 1]);
    }

    /// A self-signed certificate of the personal store whose key is in an
    /// old CryptoAPI provider, removed with its key on drop.
    struct CspCertificate {
        der: Vec<u8>,
        thumbprint: String,
    }

    impl CspCertificate {
        fn new() -> Self {
            let script = "$c = New-SelfSignedCertificate -Subject 'CN=omnitun CSP test' \
                -CertStoreLocation Cert:\\CurrentUser\\My -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 \
                -Provider 'Microsoft Enhanced Cryptographic Provider v1.0'; \
                $c.Thumbprint; [Convert]::ToBase64String($c.RawData)";
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            let out = String::from_utf8(out.stdout).unwrap();
            let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
            let thumbprint = lines.next().unwrap().to_owned();
            let der =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, lines.next().unwrap()).unwrap();
            Self { der, thumbprint }
        }

        fn sha256(&self) -> String {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(&self.der))
        }

        fn verify(
            &self,
            algorithm: &'static dyn ring::signature::VerificationAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) {
            use x509_parser::prelude::{FromDer, X509Certificate};
            let (_, cert) = X509Certificate::from_der(&self.der).unwrap();
            let key =
                ring::signature::UnparsedPublicKey::new(algorithm, cert.public_key().subject_public_key.data.to_vec());
            key.verify(data, signature).expect("the signature verifies with the certificate's key");
        }
    }

    impl Drop for CspCertificate {
        fn drop(&mut self) {
            let script = format!("Remove-Item Cert:\\CurrentUser\\My\\{} -DeleteKey", self.thumbprint);
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .status();
        }
    }

    #[test]
    fn csp_keys_sign() {
        let cert = CspCertificate::new();
        let data = b"IKE AUTH payload";
        // Through CryptoAPI itself, SHA-1 and SHA-2 (the strong provider
        // hashes no SHA-2: the key is opened again in the AES provider).
        for (algorithm, verify) in [
            (SignAlgorithm::RsaPkcs1Sha1, &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
            (SignAlgorithm::RsaPkcs1Sha256, &ring::signature::RSA_PKCS1_2048_8192_SHA256),
            (SignAlgorithm::RsaPkcs1Sha512, &ring::signature::RSA_PKCS1_2048_8192_SHA512),
        ] {
            let signature = sign_with(&cert.sha256(), algorithm, data, 0).unwrap();
            cert.verify(verify, data, &signature);
        }
        let e = sign_with(&cert.sha256(), SignAlgorithm::RsaPssSha256, data, 0).unwrap_err();
        assert!(e.to_string().contains("CryptoAPI"), "{e}");
        // As the app does: CNG if Windows can open the key with it.
        let signature = sign(&cert.sha256(), SignAlgorithm::RsaPkcs1Sha256, data).unwrap();
        cert.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, data, &signature);
    }
}
