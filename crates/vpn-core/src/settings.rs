use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// Network configuration negotiated with the gateway, applied by the
/// platform layer to a dedicated tun interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSettings {
    /// Address assigned to us inside the tunnel.
    pub address: Ipv4Addr,
    pub mtu: u16,
    /// Networks to send through the tunnel. Ignored when `full_tunnel`.
    pub routes: Vec<Ipv4Net>,
    /// Networks that must stay outside the tunnel.
    pub excluded_routes: Vec<Ipv4Net>,
    /// Route everything through the tunnel.
    pub full_tunnel: bool,
    pub dns: DnsSettings,
    /// Outer address of the gateway; gets a host route via the physical
    /// interface so the tunnel never routes its own transport.
    pub gateway: IpAddr,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsSettings {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    /// Domains resolved through this tunnel's servers (split DNS).
    /// Empty with `full_tunnel` means "all queries".
    pub match_domains: Vec<String>,
}

impl DnsSettings {
    /// Every name that ends up in resolver configuration.
    pub fn domains(&self) -> impl Iterator<Item = &String> {
        self.search_domains.iter().chain(&self.match_domains)
    }
}

/// A plain DNS name (letters, digits, hyphens, dot-separated labels). Names
/// come from the gateway and end up in resolver commands, so anything else
/// is refused rather than escaped.
pub fn valid_domain(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::valid_domain;

    #[test]
    fn domain_validation() {
        for ok in ["corp.example", "Corp.Example.", "a-b.c1", "localdomain"] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in ["", ".", "~.", "a..b", "-x.example", "a b", "a\nd.init", "x;y", "*.example", "a/b"] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
    }
}
