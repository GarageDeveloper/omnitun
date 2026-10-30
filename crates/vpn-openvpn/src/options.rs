//! The server's pushed options (`PUSH_REPLY`), and the tunnel settings
//! they make.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, bail, ensure};
use ipnet::Ipv4Net;
use tracing::{debug, warn};
use vpn_core::{Compression, DnsSettings, TunnelSettings};

use crate::crypto::DataCipher;

const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 4;
const MAX_DOMAINS: usize = 16;
/// Inner MTU that leaves room for the outer headers on a 1500-byte path,
/// unless the server asks for less.
const TUNNEL_MTU: u16 = 1400;

#[derive(Debug, Default)]
pub struct Pushed {
    /// `PUSH_REPLY` messages so far, continuations included.
    messages: u32,
    pub address: Option<Ipv4Addr>,
    /// The netmask (`topology subnet`) or the peer address (net30, p2p).
    pub ifconfig_second: Option<Ipv4Addr>,
    pub topology_subnet: bool,
    pub routes: Vec<Ipv4Net>,
    pub redirect_gateway: bool,
    pub dns: Vec<IpAddr>,
    pub domains: Vec<String>,
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    pub peer_id: Option<u32>,
    pub cipher: Option<DataCipher>,
    pub unsupported_cipher: Option<String>,
    pub ekm: bool,
    pub compression: Option<Compression>,
    pub tun_mtu: Option<u16>,
    pub auth_token: Option<String>,
    pub auth_token_user: Option<String>,
}

/// Splits an option line into words, honouring double quotes.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let (mut quoted, mut any) = (false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
                any = false;
            }
            c => current.push(c),
        }
    }
    if any || !current.is_empty() {
        out.push(current);
    }
    out
}

/// Bounds on what a server may push, well above real configurations.
const MAX_MESSAGES: u32 = 64;
const MAX_ITEMS: usize = 1024;

impl Pushed {
    /// Adds one `PUSH_REPLY` message; returns whether more follow
    /// (`push-continuation 2`).
    pub fn add(&mut self, message: &str) -> anyhow::Result<bool> {
        let body = message.strip_prefix("PUSH_REPLY").context("not a PUSH_REPLY")?;
        self.messages += 1;
        ensure!(
            self.messages <= MAX_MESSAGES,
            "the server pushed more than {MAX_MESSAGES} continued PUSH_REPLY messages"
        );
        ensure!(
            self.routes.len() <= MAX_ITEMS && self.dns.len() <= MAX_ITEMS && self.domains.len() <= MAX_ITEMS,
            "the server pushed more than {MAX_ITEMS} routes, DNS servers or domains"
        );
        let mut more = false;
        for option in body.split(',').map(str::trim).filter(|o| !o.is_empty()) {
            let w = words(option);
            let arg = |i: usize| w.get(i).map(String::as_str).unwrap_or_default();
            let ip = |i: usize| arg(i).parse::<Ipv4Addr>().ok();
            let number = |i: usize| arg(i).parse::<u32>().ok();
            match arg(0) {
                "ifconfig" => {
                    self.address = Some(ip(1).context("invalid ifconfig")?);
                    self.ifconfig_second = ip(2);
                }
                "topology" => self.topology_subnet = arg(1) == "subnet",
                "route" => match (ip(1), if w.len() > 2 { ip(2) } else { Some(Ipv4Addr::BROADCAST) }) {
                    (Some(net), Some(mask)) => match Ipv4Net::with_netmask(net, mask) {
                        Ok(net) => self.routes.push(net.trunc()),
                        Err(_) => warn!("ignoring route with an invalid mask: {option}"),
                    },
                    _ => warn!("ignoring route {option:?}"),
                },
                "redirect-gateway" => {
                    // "!ipv4" redirects IPv6 only, which this client does
                    // not carry.
                    self.redirect_gateway = !w.iter().any(|f| f == "!ipv4");
                }
                "dhcp-option" => match arg(1).to_ascii_uppercase().as_str() {
                    "DNS" => match arg(2).parse() {
                        Ok(server) => self.dns.push(server),
                        Err(_) => warn!("ignoring DNS server {option:?}"),
                    },
                    "DOMAIN" | "DOMAIN-SEARCH" | "ADAPTER_DOMAIN_SUFFIX" => {
                        let domain = arg(2).trim_end_matches('.').to_owned();
                        if vpn_core::valid_domain(&domain) {
                            self.domains.push(domain);
                        } else {
                            warn!("ignoring DNS domain {option:?}");
                        }
                    }
                    _ => debug!("ignoring {option}"),
                },
                "ping" => self.ping = number(1),
                "ping-restart" => self.ping_restart = number(1),
                "peer-id" => self.peer_id = number(1).filter(|id| *id < 1 << 24),
                "cipher" => match DataCipher::parse(arg(1)) {
                    Some(cipher) => self.cipher = Some(cipher),
                    None => self.unsupported_cipher = Some(arg(1).to_owned()),
                },
                "key-derivation" => self.ekm = arg(1) == "tls-ekm",
                "protocol-flags" => {
                    if w.iter().any(|f| f == "tls-ekm") {
                        self.ekm = true;
                    }
                }
                "comp-lzo" => self.compression = Some(Compression::Lzo),
                "compress" => {
                    self.compression = Some(match arg(1) {
                        "" | "stub" | "lz4" => Compression::Stub,
                        "stub-v2" | "lz4-v2" => Compression::StubV2,
                        "lzo" => Compression::Lzo,
                        "migrate" => Compression::None,
                        other => bail!("the server asks for {other} compression, which this client does not support"),
                    })
                }
                "tun-mtu" => self.tun_mtu = number(1).and_then(|m| u16::try_from(m).ok()),
                "auth-token" => self.auth_token = Some(arg(1).to_owned()),
                "auth-token-user" => self.auth_token_user = Some(arg(1).to_owned()),
                "push-continuation" => more = arg(1) == "2",
                "route-ipv6" | "ifconfig-ipv6" | "tun-ipv6" => debug!("IPv6 not carried: ignoring {option}"),
                _ => debug!("ignoring pushed option {option}"),
            }
        }
        Ok(more)
    }

    /// The tunnel to set up; `gateway` is the server's outer address.
    pub fn settings(&self, gateway: IpAddr) -> anyhow::Result<TunnelSettings> {
        let address = self.address.context("the server assigned no address (ifconfig)")?;
        let mut routes = self.routes.clone();
        // The tunnel's own network: the server and the other clients.
        match self.ifconfig_second {
            Some(mask) if self.topology_subnet => {
                if let Ok(net) = Ipv4Net::with_netmask(address, mask) {
                    routes.push(net.trunc());
                }
            }
            Some(peer) => routes.push(Ipv4Net::from(peer)),
            None => {}
        }
        routes.retain(|r| r.prefix_len() > 0 || self.redirect_gateway);
        routes.sort();
        routes.dedup();
        cap(&mut routes, MAX_ROUTES, "routes");
        // In the server's order, each once.
        let mut servers = self.dns.clone();
        let mut seen = std::collections::HashSet::new();
        servers.retain(|s| seen.insert(*s));
        cap(&mut servers, MAX_DNS_SERVERS, "DNS servers");
        let mut domains = self.domains.clone();
        let mut seen = std::collections::HashSet::new();
        domains.retain(|d| seen.insert(d.clone()));
        cap(&mut domains, MAX_DOMAINS, "DNS domains");
        let full_tunnel = self.redirect_gateway;
        Ok(TunnelSettings {
            address,
            mtu: self.tun_mtu.map_or(TUNNEL_MTU, |m| m.clamp(576, TUNNEL_MTU)),
            routes,
            excluded_routes: Vec::new(),
            full_tunnel,
            dns: DnsSettings {
                servers,
                match_domains: if full_tunnel { Vec::new() } else { domains.clone() },
                search_domains: domains,
            },
            gateway,
        })
    }
}

fn cap<T>(items: &mut Vec<T>, max: usize, what: &str) {
    if items.len() > max {
        warn!("server pushed {} {what}; keeping the first {max}", items.len());
        items.truncate(max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_reply() {
        let mut p = Pushed::default();
        let more = p
            .add(
                "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,\
                 route 192.168.10.0 255.255.255.0,route 10.20.0.5,dhcp-option DNS 10.8.0.1,\
                 dhcp-option DOMAIN corp.example,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,\
                 cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500,\
                 push-continuation 2",
            )
            .unwrap();
        assert!(more);
        assert!(!p.add("PUSH_REPLY,compress stub-v2,auth-token SESS_ID_x,push-continuation 1").unwrap());
        assert_eq!((p.peer_id, p.cipher, p.ekm, p.ping), (Some(3), Some(DataCipher::Aes256Gcm), true, Some(10)));
        assert_eq!(p.compression, Some(Compression::StubV2));
        assert_eq!(p.auth_token.as_deref(), Some("SESS_ID_x"));
        let s = p.settings("192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(s.address, Ipv4Addr::new(10, 8, 0, 2));
        let routes: Vec<String> = s.routes.iter().map(ToString::to_string).collect();
        assert_eq!(routes, ["10.8.0.0/24", "10.20.0.5/32", "192.168.10.0/24"]);
        assert_eq!((s.full_tunnel, s.mtu), (false, 1400));
        assert_eq!(s.dns.match_domains, ["corp.example"]);

        let mut net30 = Pushed::default();
        net30.add("PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,redirect-gateway def1 bypass-dhcp").unwrap();
        let s = net30.settings("192.0.2.1".parse().unwrap()).unwrap();
        assert!(s.full_tunnel && s.dns.match_domains.is_empty());

        // Each DNS server once, in the server's order.
        let mut dns = Pushed::default();
        dns.add(
            "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.2,\
             dhcp-option DNS 10.8.0.1",
        )
        .unwrap();
        let s = dns.settings("192.0.2.1".parse().unwrap()).unwrap();
        let servers: Vec<String> = s.dns.servers.iter().map(ToString::to_string).collect();
        assert_eq!(servers, ["10.8.0.1", "10.8.0.2"]);
        assert_eq!(s.routes, ["10.8.0.5/32".parse().unwrap()]);
        assert!(Pushed::default().add("PUSH_REPLY,compress lzo-v9").is_err());
        assert!(Pushed::default().settings("192.0.2.1".parse().unwrap()).is_err(), "no address");
    }

    #[test]
    fn quoted_words() {
        assert_eq!(words(r#"dhcp-option DOMAIN "corp example""#), ["dhcp-option", "DOMAIN", "corp example"]);
    }
}
