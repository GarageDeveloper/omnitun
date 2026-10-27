//! Turns Mode-Config attributes (including Cisco Unity split tunnelling,
//! which FortiGate sends with `unity-support enable`) into `TunnelSettings`.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Context;
use ipnet::Ipv4Net;
use tracing::{debug, info, warn};
use vpn_core::{DnsSettings, TunnelSettings};

use super::consts::cfg;
use super::payload::CfgAttr;

/// Inner MTU for AES-CBC ESP in UDP on a 1500-byte path.
const TUNNEL_MTU: u16 = 1400;
const MAX_ROUTES: usize = 64;
const MAX_DNS_SERVERS: usize = 4;
const MAX_DOMAINS: usize = 16;
/// Unity split entries: address, mask, then protocol and ports.
const UNITY_ENTRY: usize = 14;

fn ipv4(v: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(v).ok().map(Ipv4Addr::from)
}

fn push_net(routes: &mut Vec<Ipv4Net>, addr: &[u8], mask: &[u8]) {
    if let (Some(addr), Some(mask)) = (ipv4(addr), ipv4(mask))
        && let Ok(net) = Ipv4Net::with_netmask(addr, mask)
        && !routes.contains(&net.trunc())
    {
        routes.push(net.trunc());
    }
}

fn push_domains(out: &mut Vec<String>, raw: &[u8]) {
    for d in String::from_utf8_lossy(raw).split([',', ' ', ';', '\0']) {
        let d = d.trim().trim_end_matches('.');
        if !d.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(d)) {
            out.push(d.to_owned());
        }
    }
}

fn cap<T>(items: &mut Vec<T>, max: usize, what: &str) {
    if items.len() > max {
        warn!("gateway pushed {} {what}; keeping the first {max}", items.len());
        items.truncate(max);
    }
}

/// Transport mode assigns nothing: our own address, no route.
pub fn transport(local: Ipv4Addr, gateway: Ipv4Addr) -> TunnelSettings {
    TunnelSettings {
        address: local,
        mtu: 1400,
        routes: Vec::new(),
        excluded_routes: Vec::new(),
        full_tunnel: false,
        dns: Default::default(),
        gateway: std::net::IpAddr::V4(gateway),
    }
}

pub fn build(attrs: &[CfgAttr], gateway: Ipv4Addr) -> anyhow::Result<TunnelSettings> {
    let mut address = None;
    let mut servers = Vec::new();
    let mut search = Vec::new();
    let mut split_dns = Vec::new();
    let mut routes = Vec::new();
    for attr in attrs {
        let v = attr.bytes();
        match attr.kind {
            cfg::INTERNAL_IP4_ADDRESS => address = ipv4(v).or(address),
            cfg::INTERNAL_IP4_DNS => {
                if let Some(ip) = ipv4(v).map(IpAddr::V4).filter(|ip| !servers.contains(ip)) {
                    servers.push(ip);
                }
            }
            cfg::INTERNAL_IP4_SUBNET if v.len() >= 8 => push_net(&mut routes, &v[..4], &v[4..8]),
            cfg::UNITY_SPLIT_INCLUDE => {
                for entry in v.as_chunks::<UNITY_ENTRY>().0 {
                    push_net(&mut routes, &entry[..4], &entry[4..8]);
                }
            }
            cfg::UNITY_DEF_DOMAIN => push_domains(&mut search, v),
            cfg::UNITY_SPLITDNS_NAME => push_domains(&mut split_dns, v),
            _ => {}
        }
    }
    debug!(kinds = ?attrs.iter().map(|a| a.kind).collect::<Vec<_>>(), "mode-config attributes");
    info!(?servers, ?search, ?split_dns, "mode-config DNS");
    let address = address.context("gateway assigned no inner address (enable mode-cfg on the phase1)")?;
    // A pushed default route means full tunnel.
    let full_tunnel = routes.is_empty() || routes.iter().any(|r| r.prefix_len() == 0);
    routes.retain(|r| r.prefix_len() != 0);
    cap(&mut routes, MAX_ROUTES, "routes");
    cap(&mut servers, MAX_DNS_SERVERS, "DNS servers");
    cap(&mut search, MAX_DOMAINS, "DNS domains");
    cap(&mut split_dns, MAX_DOMAINS, "split DNS domains");
    let match_domains = if full_tunnel {
        Vec::new()
    } else if split_dns.is_empty() {
        search.clone()
    } else {
        split_dns
    };
    Ok(TunnelSettings {
        address,
        mtu: TUNNEL_MTU,
        routes,
        excluded_routes: Vec::new(),
        full_tunnel,
        dns: DnsSettings { servers, search_domains: search, match_domains },
        gateway: IpAddr::V4(gateway),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unity(entries: &[([u8; 4], [u8; 4])]) -> CfgAttr {
        let mut v = Vec::new();
        for (a, m) in entries {
            v.extend_from_slice(a);
            v.extend_from_slice(m);
            v.extend_from_slice(&[0; 6]);
        }
        CfgAttr::var(cfg::UNITY_SPLIT_INCLUDE, v)
    }

    #[test]
    fn split_tunnel_from_unity_attributes() {
        let attrs = [
            CfgAttr::var(cfg::INTERNAL_IP4_ADDRESS, [10, 9, 0, 2]),
            CfgAttr::var(cfg::INTERNAL_IP4_DNS, [10, 0, 0, 53]),
            CfgAttr::var(cfg::INTERNAL_IP4_DNS, [10, 0, 0, 53]),
            unity(&[([10, 0, 0, 0], [255, 0, 0, 0]), ([192, 168, 7, 9], [255, 255, 255, 0])]),
            CfgAttr::var(cfg::INTERNAL_IP4_SUBNET, [10, 0, 0, 0, 255, 0, 0, 0]),
            CfgAttr::var(cfg::UNITY_DEF_DOMAIN, *b"corp.test"),
            CfgAttr::var(cfg::UNITY_SPLITDNS_NAME, *b"corp.test,lab.test"),
        ];
        let s = build(&attrs, Ipv4Addr::new(203, 0, 113, 1)).unwrap();
        assert_eq!(s.address, Ipv4Addr::new(10, 9, 0, 2));
        assert!(!s.full_tunnel);
        assert_eq!(s.routes, ["10.0.0.0/8".parse::<Ipv4Net>().unwrap(), "192.168.7.0/24".parse().unwrap()]);
        assert_eq!(s.dns.servers.len(), 1);
        assert_eq!(s.dns.search_domains, ["corp.test"]);
        assert_eq!(s.dns.match_domains, ["corp.test", "lab.test"]);
    }

    #[test]
    fn no_split_means_full_tunnel() {
        let s = build(&[CfgAttr::var(cfg::INTERNAL_IP4_ADDRESS, [10, 9, 0, 2])], Ipv4Addr::LOCALHOST).unwrap();
        assert!(s.full_tunnel && s.routes.is_empty());
        assert!(build(&[], Ipv4Addr::LOCALHOST).is_err());
    }
}
