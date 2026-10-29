//! What a route list entry names: a network, or the addresses a domain
//! resolves to (dynamic split tunneling, issue #37). `corp.example` is that
//! name only; `*.corp.example` is it and every name under it.

use std::fmt;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::noted::NoteKey;

/// A domain, or every name under it with a leading `*.`; kept in lower
/// case, without the trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainPattern {
    base: String,
    wildcard: bool,
}

impl DomainPattern {
    /// The name, without `*.`.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Whether `name` (any case, trailing dot or not) is covered.
    pub fn matches(&self, name: &str) -> bool {
        let name = name.strip_suffix('.').unwrap_or(name);
        name.eq_ignore_ascii_case(&self.base) || (self.wildcard && is_under(name, &self.base))
    }
}

/// Whether `name` is `domain` or a name under it (any case, trailing dots
/// or not).
pub fn is_under(name: &str, domain: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if name.eq_ignore_ascii_case(domain) {
        return true;
    }
    name.len() > domain.len()
        && name.is_char_boundary(name.len() - domain.len())
        && name[name.len() - domain.len()..].eq_ignore_ascii_case(domain)
        && name.as_bytes()[name.len() - domain.len() - 1] == b'.'
}

impl FromStr for DomainPattern {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim().to_ascii_lowercase();
        let (wildcard, base) = match text.strip_prefix("*.") {
            Some(base) => (true, base),
            None => (false, text.as_str()),
        };
        let base = base.strip_suffix('.').unwrap_or(base);
        if !crate::valid_domain(base) {
            return Err(format!("{text:?} is not a domain (corp.example, or *.corp.example for every name under it)"));
        }
        // An address is not a name: `10.1.2.3` would never be asked for.
        if base.rsplit('.').next().is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit())) {
            return Err(format!("{text:?} looks like an address, not a domain"));
        }
        Ok(Self { base: base.to_owned(), wildcard })
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.base)
    }
}

impl Serialize for DomainPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DomainPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

impl NoteKey for DomainPattern {
    const KEYS: &'static [&'static str] = &["domain"];

    fn key(&self) -> &'static str {
        "domain"
    }

    fn keyed(_key: &str, text: &str) -> Result<Self, String> {
        text.parse()
    }
}

/// An entry of a route list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    Network(Ipv4Net),
    /// Routed as its addresses are resolved.
    Domain(DomainPattern),
}

impl Destination {
    pub fn network(&self) -> Option<Ipv4Net> {
        match self {
            Self::Network(net) => Some(*net),
            Self::Domain(_) => None,
        }
    }

    pub fn domain(&self) -> Option<&DomainPattern> {
        match self {
            Self::Domain(domain) => Some(domain),
            Self::Network(_) => None,
        }
    }
}

impl From<Ipv4Net> for Destination {
    fn from(net: Ipv4Net) -> Self {
        Self::Network(net)
    }
}

/// A network has a prefix (`10.1.0.0/16`); anything else is a domain.
impl FromStr for Destination {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.contains('/') {
            return text.parse().map(Self::Network).map_err(|_| format!("{text:?} is not a network (10.1.0.0/16)"));
        }
        if text.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(format!("{text:?} needs its prefix ({text}/32 for this address alone)"));
        }
        text.parse().map(Self::Domain)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(net) => net.fmt(f),
            Self::Domain(domain) => domain.fmt(f),
        }
    }
}

impl Serialize for Destination {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

impl NoteKey for Destination {
    const KEYS: &'static [&'static str] = &["net", "domain"];

    fn key(&self) -> &'static str {
        match self {
            Self::Network(_) => "net",
            Self::Domain(_) => "domain",
        }
    }

    /// `{ net = … }` must hold a network, `{ domain = … }` a domain.
    fn keyed(key: &str, text: &str) -> Result<Self, String> {
        if key == "net" {
            Ipv4Net::keyed(key, text).map(Self::Network)
        } else {
            DomainPattern::keyed(key, text).map(Self::Domain)
        }
    }
}

impl PartialEq<Ipv4Net> for crate::Noted<Destination> {
    fn eq(&self, other: &Ipv4Net) -> bool {
        self.value == Destination::Network(*other)
    }
}

/// The networks of a route list, without its domains or notes.
pub fn networks(list: &[crate::Noted<Destination>]) -> Vec<Ipv4Net> {
    list.iter().filter_map(|entry| entry.value.network()).collect()
}

/// The domains of a route list.
pub fn domains(list: &[crate::Noted<Destination>]) -> impl Iterator<Item = &DomainPattern> {
    list.iter().filter_map(|entry| entry.value.domain())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Noted;

    #[test]
    fn patterns() {
        let exact: DomainPattern = "Intranet.Corp.Example.".parse().unwrap();
        assert_eq!(exact.to_string(), "intranet.corp.example");
        assert!(exact.matches("intranet.corp.example") && exact.matches("INTRANET.corp.example."));
        assert!(!exact.matches("a.intranet.corp.example"));
        let any: DomainPattern = "*.corp-saas.com".parse().unwrap();
        assert!(any.matches("corp-saas.com") && any.matches("eu.app.corp-saas.com"));
        assert!(!any.matches("notcorp-saas.com") && !any.matches("corp-saas.com.evil.example"));
        assert!(!any.matches("é.corp-saas.co"), "no panic on a multibyte name");
        for bad in ["", "*", "*.", "a..b", "a.*.b", "**.a", "10.1.2.3", "*.10.1.2", "a b", "-a.example"] {
            assert!(bad.parse::<DomainPattern>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn destinations() {
        assert_eq!("10.1.0.0/16".parse::<Destination>().unwrap().network(), Some("10.1.0.0/16".parse().unwrap()));
        assert!("*.zoom.us".parse::<Destination>().unwrap().domain().is_some());
        let err = "10.1.2.3".parse::<Destination>().unwrap_err();
        assert!(err.contains("10.1.2.3/32"), "{err}");
        assert!("10.1.0.0/33".parse::<Destination>().is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Lists {
        routes: Vec<Noted<Destination>>,
    }

    #[test]
    fn route_lists_hold_networks_and_domains() {
        let text = r#"routes = ["10.0.0.0/8", "*.corp-saas.com", { net = "10.20.0.5/32", note = "Jira" }, { domain = "crm.example", note = "CRM" }]"#;
        let lists: Lists = toml::from_str(text).unwrap();
        assert_eq!(
            networks(&lists.routes),
            ["10.0.0.0/8".parse().unwrap(), "10.20.0.5/32".parse::<Ipv4Net>().unwrap()]
        );
        assert_eq!(
            domains(&lists.routes).map(ToString::to_string).collect::<Vec<_>>(),
            ["*.corp-saas.com", "crm.example"]
        );
        let written = toml::to_string(&lists).unwrap();
        assert!(written.contains(r#"{ domain = "crm.example", note = "CRM" }"#), "{written}");
        assert_eq!(toml::from_str::<Lists>(&written).unwrap(), lists);
        let json = serde_json::to_string(&lists).unwrap();
        assert_eq!(serde_json::from_str::<Lists>(&json).unwrap(), lists);
        for bad in [r#"routes = [{ net = "crm.example" }]"#, r#"routes = [{ domain = "10.0.0.0/8" }]"#] {
            assert!(toml::from_str::<Lists>(bad).is_err(), "{bad}");
        }
    }
}
