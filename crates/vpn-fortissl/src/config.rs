//! Parsing of the `/remote/fortisslvpn_xml` tunnel configuration.

use std::net::Ipv4Addr;

use anyhow::Context;
use ipnet::Ipv4Net;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

#[derive(Debug, Default, PartialEq)]
pub struct GatewayConfig {
    pub assigned: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub dns_suffixes: Vec<String>,
    pub split_routes: Vec<Ipv4Net>,
    /// Networks excluded from the tunnel (`split-tunnel-info negate='1'`).
    pub excluded_routes: Vec<Ipv4Net>,
    pub idle_timeout: Option<u32>,
    pub auth_timeout: Option<u32>,
}

#[derive(Clone, Copy, PartialEq)]
enum Family {
    /// Older firmware has no `<ipv4>` wrapper: treat bare elements as IPv4.
    Unscoped,
    V4,
    V6,
}

pub fn parse(xml: &str) -> anyhow::Result<GatewayConfig> {
    let mut reader = Reader::from_str(xml);
    let mut cfg = GatewayConfig::default();
    let mut family = Family::Unscoped;
    let mut negate = false;

    loop {
        let event = reader.read_event().context("malformed tunnel configuration XML")?;
        match event {
            Event::Start(e) => {
                match e.local_name().as_ref() {
                    "ipv4" => family = Family::V4,
                    "ipv6" => family = Family::V6,
                    "split-tunnel-info" => negate = attr(&e, "negate").as_deref() == Some("1"),
                    _ => {}
                }
                element(&e, family, negate, &mut cfg);
            }
            Event::Empty(e) => element(&e, family, negate, &mut cfg),
            Event::End(e) => match e.local_name().as_ref() {
                "ipv4" | "ipv6" => family = Family::Unscoped,
                "split-tunnel-info" => negate = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(cfg)
}

/// Entries kept per list: far more than the daemon accepts (it refuses the
/// configuration then), and a bound on the duplicate checks.
const MAX_ITEMS: usize = 1024;

fn element(e: &BytesStart, family: Family, negate: bool, cfg: &mut GatewayConfig) {
    let v4 = family != Family::V6;
    match e.local_name().as_ref() {
        "assigned-addr" if v4 => {
            if let Some(ip) = attr(e, "ipv4").and_then(|s| s.parse().ok()) {
                cfg.assigned = Some(ip);
            }
        }
        "dns" if v4 => {
            if let Some(ip) = attr(e, "ip").and_then(|s| s.parse().ok())
                && cfg.dns.len() < MAX_ITEMS
                && !cfg.dns.contains(&ip)
            {
                cfg.dns.push(ip);
            }
            if let Some(domain) = attr(e, "domain") {
                push_domains(&mut cfg.dns_suffixes, &domain);
            }
        }
        "dns-suffix" => {
            if let Some(val) = attr(e, "val") {
                push_domains(&mut cfg.dns_suffixes, &val);
            }
        }
        "addr" if v4 => {
            let ip = attr(e, "ip").and_then(|s| s.parse::<Ipv4Addr>().ok());
            let mask = attr(e, "mask").and_then(|s| s.parse::<Ipv4Addr>().ok());
            if let (Some(ip), Some(mask)) = (ip, mask)
                && let Ok(net) = Ipv4Net::with_netmask(ip, mask)
            {
                let net = net.trunc();
                let list = if negate { &mut cfg.excluded_routes } else { &mut cfg.split_routes };
                if list.len() < MAX_ITEMS && !list.contains(&net) {
                    list.push(net);
                }
            }
        }
        "idle-timeout" => cfg.idle_timeout = attr(e, "val").and_then(|s| s.parse().ok()),
        "auth-timeout" => cfg.auth_timeout = attr(e, "val").and_then(|s| s.parse().ok()),
        _ => {}
    }
}

fn push_domains(list: &mut Vec<String>, value: &str) {
    for d in value.split([';', ',', ' ']).map(str::trim).filter(|d| !d.is_empty()) {
        if list.len() < MAX_ITEMS && !list.iter().any(|x| x == d) {
            list.push(d.to_owned());
        }
    }
}

fn attr(e: &BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == name)
        .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version='1.0' encoding='utf-8'?>
<sslvpn-tunnel ver='2' dtls='1' patch='1'>
  <dtls-config heartbeat-interval='10' heartbeat-fail-count='10' heartbeat-idle-timeout='10' client-hello-timeout='10'/>
  <tunnel-method value='ppp'/>
  <tunnel-method value='tun'/>
  <fos platform='FG100F' major='7' minor='2' patch='8' build='1639' branch='1639'/>
  <client-config save-password='off' keep-alive='off' auto-connect='off'/>
  <ipv4>
    <dns ip='10.1.1.53'/>
    <dns ip='10.1.2.53'/>
    <dns-suffix val='corp.example;lab.example'/>
    <assigned-addr ipv4='10.212.134.200'/>
    <split-tunnel-info>
      <addr ip='10.1.0.0' mask='255.255.0.0'/>
      <addr ip='192.168.50.7' mask='255.255.255.255'/>
    </split-tunnel-info>
    <split-tunnel-info negate='1'>
      <addr ip='10.1.99.0' mask='255.255.255.0'/>
    </split-tunnel-info>
  </ipv4>
  <ipv6>
    <dns ipv6='fd00::53'/>
    <split-tunnel-info><addr ipv6='fd00::' prefix-len='64'/></split-tunnel-info>
  </ipv6>
  <idle-timeout val='3600'/>
  <auth-timeout val='28800'/>
</sslvpn-tunnel>"#;

    #[test]
    fn parses_fortios7_config() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(cfg.assigned, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(cfg.dns, vec![Ipv4Addr::new(10, 1, 1, 53), Ipv4Addr::new(10, 1, 2, 53)]);
        assert_eq!(cfg.dns_suffixes, vec!["corp.example", "lab.example"]);
        assert_eq!(cfg.split_routes, vec!["10.1.0.0/16".parse().unwrap(), "192.168.50.7/32".parse().unwrap()]);
        assert_eq!(cfg.excluded_routes, vec!["10.1.99.0/24".parse().unwrap()]);
        assert_eq!(cfg.idle_timeout, Some(3600));
        assert_eq!(cfg.auth_timeout, Some(28800));
    }

    #[test]
    fn parses_legacy_unscoped_config() {
        let xml =
            "<sslvpn-tunnel><assigned-addr ipv4='10.0.0.5'/><dns ip='10.0.0.1' domain='old.example'/></sslvpn-tunnel>";
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.assigned, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(cfg.dns_suffixes, vec!["old.example"]);
        assert!(cfg.split_routes.is_empty());
    }
}
