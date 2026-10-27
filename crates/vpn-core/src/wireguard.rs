//! WireGuard profiles: one peer, the server, as in a `wg-quick` client
//! configuration. The interface's private key and the peer's pre-shared
//! key are secrets: they live in the Keychain, never in the profile.

use std::net::IpAddr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// The port WireGuard servers usually listen on.
pub const WIREGUARD_PORT: u16 = 51820;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardProfile {
    /// The peer's host (`Endpoint`).
    pub endpoint: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// The peer's public key, base64 (`PublicKey`).
    pub public_key: String,
    /// Our addresses in the tunnel (`Address`); the first IPv4 one is used.
    pub addresses: Vec<Ipv4Net>,
    /// Networks the peer stands for (`AllowedIPs`): routed through the
    /// tunnel, and the only sources accepted from it. 0.0.0.0/0 makes a
    /// full tunnel.
    pub allowed_ips: Vec<Ipv4Net>,
    /// The peer also uses a pre-shared key (`PresharedKey`), kept in the
    /// Keychain as `psk`.
    #[serde(default)]
    pub preshared_key: bool,
    /// Seconds between keepalives (`PersistentKeepalive`), for NATs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
    /// `DNS` servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<IpAddr>,
    /// `DNS` search domains, resolved through those servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_search: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Our public key, base64: what the server's administrator declares.
    /// Derived from the private key, kept to show it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_public_key: Option<String>,
}

/// Default tunnel MTU, as wg-quick: 1500 less the IPv6 and WireGuard
/// overheads.
pub const WIREGUARD_MTU: u16 = 1420;

const MAX_ALLOWED_IPS: usize = 64;

impl WireGuardProfile {
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        ensure!(parse_key(&self.public_key).is_some(), "the peer's public key must be 32 bytes in base64");
        if let Some(key) = &self.local_public_key {
            ensure!(parse_key(key).is_some(), "our public key must be 32 bytes in base64");
        }
        ensure!(!self.addresses.is_empty(), "the profile needs its address in the tunnel (Address)");
        ensure!(self.addresses.len() <= 8, "at most 8 addresses");
        ensure!(!self.allowed_ips.is_empty(), "the profile needs the networks of the peer (AllowedIPs)");
        ensure!(self.allowed_ips.len() <= MAX_ALLOWED_IPS, "at most {MAX_ALLOWED_IPS} allowed networks");
        ensure!(self.persistent_keepalive != Some(0), "the keepalive interval must be at least 1 second");
        ensure!(self.mtu.is_none_or(|mtu| (576..=1500).contains(&mtu)), "the MTU must be between 576 and 1500");
        ensure!(self.dns_servers.len() <= 4, "at most 4 DNS servers");
        ensure!(self.dns_search.len() <= 16, "at most 16 DNS search domains");
        for domain in &self.dns_search {
            ensure!(crate::valid_domain(domain), "invalid DNS search domain {domain:?}");
        }
        Ok(())
    }

    /// The peer stands for everything.
    pub fn full_tunnel(&self) -> bool {
        self.allowed_ips.iter().any(|net| net.prefix_len() == 0)
    }
}

/// A WireGuard key: 32 bytes in base64.
pub fn parse_key(text: &str) -> Option<[u8; 32]> {
    let bytes = decode_base64(text.trim())?;
    bytes.try_into().ok()
}

/// Standard base64 with padding, the only form WireGuard writes.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let body = text.trim_end_matches('=');
    if text.len() - body.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in body.bytes() {
        let value = ALPHABET.iter().position(|&c| c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero (canonical encoding).
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

fn default_port() -> u16 {
    WIREGUARD_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let key = "YpdTsMtb/QCdYKzHlzKkLcLzEbdTK0vP4ILmdcIvnhc=";
        assert!(parse_key(key).is_some());
        assert!(parse_key("YpdTsMtb/QCdYKzHlzKkLcLzEbdTK0vP4ILmdcIvnh=").is_none(), "short");
        assert!(parse_key("YpdTsMtb/QCdYKzHlzKkLcLzEbdTK0vP4ILmdcIvnhd=").is_none(), "non-canonical");
        assert!(parse_key("not a key").is_none());
        assert_eq!(decode_base64("aGk=").unwrap(), b"hi");
    }

    #[test]
    fn profile() {
        let p: crate::Profile = toml::from_str(
            "name = \"wg\"\nprotocol = \"wireguard\"\nendpoint = \"vpn.example.com\"\n\
             public_key = \"YpdTsMtb/QCdYKzHlzKkLcLzEbdTK0vP4ILmdcIvnhc=\"\n\
             addresses = [\"10.7.0.2/32\"]\nallowed_ips = [\"10.7.0.0/24\", \"0.0.0.0/0\"]",
        )
        .unwrap();
        p.validate().unwrap();
        let crate::ProtocolConfig::WireGuard(w) = &p.protocol else { panic!() };
        assert_eq!(w.port, WIREGUARD_PORT);
        assert!(w.full_tunnel());
        assert_eq!(p.protocol.endpoint(), ("vpn.example.com", WIREGUARD_PORT));
    }
}
