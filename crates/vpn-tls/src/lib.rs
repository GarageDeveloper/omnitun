//! TLS pieces shared by the engines: client certificates whose key stays
//! with the user's client.

mod client_cert;

pub use client_cert::{RemoteCertificate, SignError};

/// SHA-256 (hex) of a certificate, as profiles store it.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, data))
}
