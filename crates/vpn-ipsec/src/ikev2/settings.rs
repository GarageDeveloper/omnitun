//! Turns the IKE_AUTH configuration payload and traffic selectors into
//! `TunnelSettings`.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Context;
use ipnet::Ipv4Net;
use tracing::warn;
use vpn_core::{DnsSettings, TunnelSettings};

use super::consts::cfg;
use super::message::Message;
use super::payload::TrafficSelector;

/// Inner MTU leaving room for IPv4 + UDP + ESP header, IV, padding and ICV
/// on a 1500-byte path.
const TUNNEL_MTU: u16 = 1400;
const MAX_ROUTES: usize = 64;
const MAX_DNS_SERVERS: usize = 4;
const MAX_DOMAINS: usize = 16;

fn cap<T>(items: &mut Vec<T>, max: usize, what: &str) {
    if items.len() > max {
        warn!("gateway pushed {} {what}; keeping the first {max}", items.len());
        items.truncate(max);
    }
}

pub fn build(msg: &Message, gateway: Ipv4Addr) -> anyhow::Result<TunnelSettings> {
    let mut address = None;
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    let mut subnets = Vec::new();
    for attr in msg.cp_attrs() {
        let v = &attr.value;
        match attr.kind {
            cfg::INTERNAL_IP4_ADDRESS if v.len() == 4 => address = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            cfg::INTERNAL_IP4_DNS if v.len() == 4 => servers.push(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
            cfg::INTERNAL_IP4_SUBNET if v.len() == 8 => {
                let addr = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                let mask = Ipv4Addr::new(v[4], v[5], v[6], v[7]);
                if let Ok(net) = Ipv4Net::with_netmask(addr, mask) {
                    subnets.push(net.trunc());
                }
            }
            cfg::INTERNAL_DNS_DOMAIN => {
                let d = String::from_utf8_lossy(v).trim().trim_end_matches('.').to_string();
                if !d.is_empty() {
                    domains.push(d);
                }
            }
            _ => {}
        }
    }
    let address = address
        .or_else(|| match msg.ts_i() {
            [ts] if ts.start == ts.end => Some(ts.start),
            _ => None,
        })
        .context("gateway assigned no inner address (enable mode-cfg on the phase1)")?;
    let mut routes = if subnets.is_empty() { msg.ts_r().iter().flat_map(selector_cidrs).collect() } else { subnets };
    routes.sort();
    routes.dedup();
    cap(&mut routes, MAX_ROUTES, "routes");
    servers.dedup();
    cap(&mut servers, MAX_DNS_SERVERS, "DNS servers");
    domains.dedup();
    cap(&mut domains, MAX_DOMAINS, "DNS domains");
    let full_tunnel = routes.iter().any(|r| r.prefix_len() == 0);
    Ok(TunnelSettings {
        address,
        mtu: TUNNEL_MTU,
        routes,
        excluded_routes: Vec::new(),
        full_tunnel,
        dns: DnsSettings {
            servers,
            match_domains: if full_tunnel { Vec::new() } else { domains.clone() },
            search_domains: domains,
        },
        gateway: IpAddr::V4(gateway),
    })
}

fn selector_cidrs(ts: &TrafficSelector) -> Vec<Ipv4Net> {
    range_to_cidrs(u32::from(ts.start), u32::from(ts.end))
}

/// Smallest set of CIDR blocks covering `start..=end`.
pub fn range_to_cidrs(start: u32, end: u32) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    let (mut cur, end) = (u64::from(start), u64::from(end));
    while cur <= end {
        let mut bits = if cur == 0 { 32 } else { cur.trailing_zeros().min(32) };
        while cur + (1u64 << bits) - 1 > end {
            bits -= 1;
        }
        out.push(Ipv4Net::new(Ipv4Addr::from(cur as u32), (32 - bits) as u8).expect("valid prefix"));
        cur += 1u64 << bits;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::message::Header;
    use crate::ikev2::payload::{CpAttr, Payload};

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn ranges() {
        assert_eq!(range_to_cidrs(0, u32::MAX), vec![net("0.0.0.0/0")]);
        assert_eq!(
            range_to_cidrs(u32::from(Ipv4Addr::new(10, 0, 0, 0)), u32::from(Ipv4Addr::new(10, 0, 255, 255))),
            vec![net("10.0.0.0/16")]
        );
        assert_eq!(
            range_to_cidrs(u32::from(Ipv4Addr::new(10, 0, 0, 1)), u32::from(Ipv4Addr::new(10, 0, 0, 6))),
            vec![net("10.0.0.1/32"), net("10.0.0.2/31"), net("10.0.0.4/31"), net("10.0.0.6/32")]
        );
    }

    fn message(payloads: Vec<Payload>) -> Message {
        let header = Header { spi_i: 1, spi_r: 2, next: 0, exchange: 35, flags: 0x20, msg_id: 1, length: 0 };
        Message { header, payloads }
    }

    #[test]
    fn caps_pushed_lists() {
        let mut attrs = vec![CpAttr { kind: cfg::INTERNAL_IP4_ADDRESS, value: vec![10, 0, 0, 2] }];
        for i in 0..100u8 {
            attrs.push(CpAttr { kind: cfg::INTERNAL_IP4_SUBNET, value: vec![10, i, 0, 0, 255, 255, 0, 0] });
            attrs.push(CpAttr { kind: cfg::INTERNAL_IP4_DNS, value: vec![10, 0, 0, i] });
            attrs.push(CpAttr { kind: cfg::INTERNAL_DNS_DOMAIN, value: format!("d{i}.test").into_bytes() });
        }
        let s = build(&message(vec![Payload::Cp { cfg_type: cfg::REPLY, attrs }]), Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(s.routes.len(), MAX_ROUTES);
        assert_eq!(s.dns.servers.len(), MAX_DNS_SERVERS);
        assert_eq!(s.dns.search_domains.len(), MAX_DOMAINS);
        assert_eq!(s.dns.match_domains.len(), MAX_DOMAINS);
    }

    #[test]
    fn split_and_full_tunnel() {
        let cp = Payload::Cp {
            cfg_type: cfg::REPLY,
            attrs: vec![
                CpAttr { kind: cfg::INTERNAL_IP4_ADDRESS, value: vec![10, 212, 134, 10] },
                CpAttr { kind: cfg::INTERNAL_IP4_DNS, value: vec![10, 0, 0, 53] },
                CpAttr { kind: cfg::INTERNAL_DNS_DOMAIN, value: b"corp.example.".to_vec() },
            ],
        };
        let split = TrafficSelector {
            start: Ipv4Addr::new(192, 168, 0, 0),
            end: Ipv4Addr::new(192, 168, 255, 255),
            ..TrafficSelector::any()
        };
        let s = build(&message(vec![cp.clone(), Payload::TsR(vec![split])]), Ipv4Addr::new(203, 0, 113, 1)).unwrap();
        assert_eq!(s.address, Ipv4Addr::new(10, 212, 134, 10));
        assert_eq!(s.routes, vec![net("192.168.0.0/16")]);
        assert!(!s.full_tunnel);
        assert_eq!(s.dns.match_domains, vec!["corp.example".to_string()]);
        let s = build(&message(vec![cp, Payload::TsR(vec![TrafficSelector::any()])]), Ipv4Addr::LOCALHOST).unwrap();
        assert!(s.full_tunnel);
        assert!(s.dns.match_domains.is_empty());
        assert!(build(&message(vec![]), Ipv4Addr::LOCALHOST).is_err());
    }
}
