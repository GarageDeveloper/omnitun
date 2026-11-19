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
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, CERT_CHAIN_CONTEXT,
    CERT_CHAIN_PARA, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_NCRYPT_KEY_SPEC, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_PHYSICAL_W, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CRYPT_ACQUIRE_CACHE_FLAG, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, CertCloseStore, CertEnumCertificatesInStore,
    CertFreeCertificateChain, CertGetCertificateChain, CertGetCertificateContextProperty, CertOpenStore,
    CryptAcquireCertificatePrivateKey, HCERTSTORE, NCryptSignHash, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

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
/// the algorithm says. ECDSA signatures are DER.
pub fn sign(sha256: &str, algorithm: SignAlgorithm, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ring::digest;
    let store = Store::open(CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, "MY")?;
    let cert = store.find(sha256)?;
    let (hash, name, padding) = match algorithm {
        SignAlgorithm::RsaPkcs1Sha1 => (&digest::SHA1_FOR_LEGACY_USE_ONLY, "SHA1", Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha256 => (&digest::SHA256, "SHA256", Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha384 => (&digest::SHA384, "SHA384", Padding::Pkcs1),
        SignAlgorithm::RsaPkcs1Sha512 => (&digest::SHA512, "SHA512", Padding::Pkcs1),
        SignAlgorithm::RsaPssSha256 => (&digest::SHA256, "SHA256", Padding::Pss),
        SignAlgorithm::RsaPssSha384 => (&digest::SHA384, "SHA384", Padding::Pss),
        SignAlgorithm::RsaPssSha512 => (&digest::SHA512, "SHA512", Padding::Pss),
        SignAlgorithm::EcdsaSha256 => (&digest::SHA256, "SHA256", Padding::None),
        SignAlgorithm::EcdsaSha384 => (&digest::SHA384, "SHA384", Padding::None),
    };
    let hashed = digest::digest(hash, data);
    let hashed = hashed.as_ref();

    let (mut key, mut spec, mut free) = (0usize, 0u32, 0i32);
    // SAFETY: a certificate of an open store; the key handle is cached
    // with the certificate (CRYPT_ACQUIRE_CACHE_FLAG), not ours to free.
    if unsafe {
        CryptAcquireCertificatePrivateKey(
            cert.0,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_CACHE_FLAG,
            null(),
            &mut key,
            &mut spec,
            &mut free,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("the client certificate has no usable private key");
    }
    if spec != CERT_NCRYPT_KEY_SPEC {
        bail!("the client certificate's key is not a CNG key");
    }
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
}
