//! Bookkeeping that lets several tunnels coexist: each session declares
//! the routes and DNS domains it will install, and a new session is refused
//! when it would silently hijack another one's traffic.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[derive(Debug, Clone, Default)]
pub struct Claims {
    /// The session's name, for messages (sessions are keyed by id).
    pub name: String,
    /// The user who started it (0: root). A session's flags never let it
    /// take traffic from another user's session.
    pub owner: u32,
    pub routes: Vec<Ipv4Net>,
    /// Networks forced onto the physical uplink.
    pub excluded_routes: Vec<Ipv4Net>,
    pub full_tunnel: bool,
    pub dns_domains: Vec<String>,
    /// Accept routes that overlap another session's (the more specific
    /// route wins; for identical routes the first session keeps them).
    pub allow_overlap: bool,
    /// The gateway, reached through the physical uplink by a host route.
    pub gateway: Option<Ipv4Addr>,
    /// Sessions this one is chained through: overlapping their routes, and
    /// having its gateway inside them, is expected.
    pub related: Vec<String>,
}

impl Claims {
    /// What the session sends into its tunnel: everything for a full tunnel.
    fn tunneled(&self) -> Vec<Ipv4Net> {
        if self.full_tunnel { vec![Ipv4Net::default()] } else { self.routes.clone() }
    }
}

/// A blocking clash with another session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub with: String,
    pub message: String,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Conflict {}

#[derive(Debug, Default)]
pub struct Registry {
    active: BTreeMap<String, Claims>,
}

impl Registry {
    /// Validates `claims` against the active sessions. Returns warnings for
    /// tolerable overlaps, or an error describing the blocking conflict.
    pub fn check(&self, name: &str, claims: &Claims) -> Result<Vec<String>, Conflict> {
        let mut warnings = Vec::new();
        for (key, theirs) in self.active.iter().filter(|(n, _)| n.as_str() != name) {
            let conflict = |message: String| Conflict { with: key.clone(), message };
            // The routing table and the resolver are shared by all users:
            // overlap and chaining are accepted only between sessions of one
            // user (or root's).
            let trusted = claims.owner == theirs.owner || claims.owner == 0;
            let chained = trusted && (claims.related.contains(key) || theirs.related.iter().any(|r| r == name));
            let allow_overlap = trusted && claims.allow_overlap;
            let other = if theirs.name.is_empty() { key } else { &theirs.name };
            if claims.full_tunnel && theirs.full_tunnel {
                return Err(conflict(format!(
                    "{other} is already a full tunnel; only one session can carry the default route"
                )));
            }
            // A route as specific as, or more specific than, one of another
            // session (a full tunnel claims everything) would pull that
            // session's traffic into this tunnel. A wider route takes
            // nothing from it: the more specific one wins.
            let (our_routes, their_routes) = (claims.tunneled(), theirs.tunneled());
            for ours in &our_routes {
                for route in &their_routes {
                    if route.contains(ours) {
                        if !allow_overlap && !chained {
                            return Err(conflict(if trusted {
                                format!("route {ours} overlaps {route} of {other} (set allow_route_overlap to accept)")
                            } else {
                                format!("route {ours} overlaps {route} of another user's VPN")
                            }));
                        }
                        warnings.push(if ours == route {
                            format!("route {ours} is shared with {other}; {other} keeps it")
                        } else {
                            format!("route {ours} takes {other}'s traffic for {ours} out of {route}")
                        });
                    } else if ours.contains(route) {
                        warnings.push(format!("route {ours} overlaps {route} of {other}; {other} keeps {route}"));
                    }
                }
            }
            // An exclusion overlapping another session's routes would send
            // that traffic out in clear on the physical interface.
            let leaks = |excluded: &[Ipv4Net], routes: &[Ipv4Net]| {
                excluded.iter().find_map(|x| routes.iter().find(|r| x.contains(*r) || r.contains(x)).map(|r| (*x, *r)))
            };
            if let Some((x, r)) = leaks(&claims.excluded_routes, &their_routes) {
                return Err(conflict(format!("excluded route {x} would bypass {other}'s tunnel for {r}")));
            }
            if let Some((x, r)) = leaks(&theirs.excluded_routes, &our_routes) {
                return Err(conflict(format!("{other} excludes {x}, which would bypass this tunnel for {r}")));
            }
            // So would the host route to this session's gateway, unless the
            // other session is a full tunnel (every gateway lies inside it).
            if let Some(gateway) = claims.gateway
                && let Some(route) = theirs.routes.iter().find(|r| r.contains(&gateway))
                && !theirs.full_tunnel
                && !chained
            {
                return Err(conflict(format!("the gateway {gateway} is inside {route}, routed through {other}")));
            }
            for ours in &claims.dns_domains {
                for domain in &theirs.dns_domains {
                    let (a, b) = (normalize(ours), normalize(domain));
                    if a == b {
                        return Err(conflict(format!("DNS domain {a} is already resolved through {other}")));
                    }
                    if (is_subdomain(&a, &b) || is_subdomain(&b, &a)) && !trusted {
                        return Err(conflict(format!("DNS domain {a} overlaps {b} of another user's VPN")));
                    }
                    if is_subdomain(&a, &b) || is_subdomain(&b, &a) {
                        warnings.push(format!("DNS domain {a} overlaps {b} of {other}; the more specific one wins"));
                    }
                }
            }
        }
        Ok(warnings)
    }

    pub fn insert(&mut self, name: &str, claims: Claims) {
        self.active.insert(name.to_owned(), claims);
    }

    pub fn remove(&mut self, name: &str) {
        self.active.remove(name);
    }
}

fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_subdomain(child: &str, parent: &str) -> bool {
    child.len() > parent.len() && child.ends_with(parent) && child.as_bytes()[child.len() - parent.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(routes: &[&str], full: bool, domains: &[&str]) -> Claims {
        Claims {
            name: String::new(),
            owner: 501,
            routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            excluded_routes: Vec::new(),
            full_tunnel: full,
            dns_domains: domains.iter().map(|d| d.to_string()).collect(),
            allow_overlap: false,
            related: Vec::new(),
            gateway: None,
        }
    }

    #[test]
    fn disjoint_sessions_coexist() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], false, &["corp.example"]));
        let warnings = reg.check("b", &claims(&["192.168.50.0/24"], false, &["lab.example"])).unwrap();
        assert!(warnings.is_empty());
    }

    /// A VPN chained through a full tunnel: its routes, and its gateway,
    /// are inside the other one, as expected.
    #[test]
    fn chained_sessions_may_overlap() {
        let mut r = Registry::default();
        r.insert("acme-eu", claims(&[], true, &[]));
        let mut common = claims(&["10.42.0.0/16"], false, &[]);
        common.gateway = Some("52.72.0.1".parse().unwrap());
        assert!(r.check("common", &common).is_err(), "not chained: refused");
        common.related = vec!["acme-us".into(), "acme-eu".into()];
        assert_eq!(r.check("common", &common).unwrap().len(), 1, "a warning");
        let mut split = Registry::default();
        split.insert("eu", claims(&["52.72.0.0/16"], false, &[]));
        common.related = vec!["eu".into()];
        assert!(split.check("common", &common).is_ok(), "the gateway inside the chained VPN");
    }

    /// Another user's flags never let them take this user's traffic.
    #[test]
    fn other_users_may_not_overlap() {
        let mut r = Registry::default();
        r.insert("a", claims(&["10.0.0.0/8"], false, &["corp.example"]));
        let mut b = claims(&["10.1.0.0/16"], false, &[]);
        b.owner = 502;
        b.allow_overlap = true;
        b.related = vec!["a".into()];
        assert!(r.check("b", &b).is_err(), "overlap and chain refused");
        let mut dns = claims(&[], false, &["intranet.corp.example"]);
        dns.owner = 502;
        assert!(r.check("d", &dns).is_err(), "a subdomain refused");
        b.owner = 0;
        assert!(r.check("b", &b).is_ok(), "root may");
        let mut own = claims(&["10.1.0.0/16"], false, &["intranet.corp.example"]);
        own.allow_overlap = true;
        assert!(r.check("o", &own).is_ok(), "the same user may");
    }

    #[test]
    fn second_full_tunnel_is_refused() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&[], true, &[]));
        assert!(reg.check("b", &claims(&[], true, &[])).is_err());
    }

    /// A full tunnel claims everything: more specific routes or exclusions
    /// of another session would take its traffic away.
    #[test]
    fn a_full_tunnel_is_protected() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&[], true, &[]));
        let mut b = claims(&["0.0.0.0/2", "64.0.0.0/2"], false, &[]);
        assert!(reg.check("b", &b).is_err(), "routes stealing the full tunnel's traffic");
        b.allow_overlap = true;
        assert_eq!(reg.check("b", &b).unwrap().len(), 2, "accepted only on request");
        let mut c = claims(&["192.168.50.0/24"], false, &[]);
        c.allow_overlap = true;
        c.excluded_routes = vec!["0.0.0.0/2".parse().unwrap()];
        assert!(reg.check("c", &c).is_err(), "exclusions leaking the full tunnel's traffic");
    }

    /// A split tunnel next to an existing one loses nothing to a later full
    /// tunnel: its routes are more specific.
    #[test]
    fn a_wider_route_takes_nothing() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.1.0.0/16"], false, &[]));
        assert_eq!(reg.check("b", &claims(&[], true, &[])).unwrap().len(), 1);
        assert_eq!(reg.check("b", &claims(&["10.0.0.0/8"], false, &[])).unwrap().len(), 1);
    }

    /// The host route to a gateway inside another session's routes would
    /// send that session's traffic for this address out in clear.
    #[test]
    fn a_gateway_cannot_sit_in_another_tunnel() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], false, &[]));
        let mut b = claims(&["192.168.50.0/24"], false, &[]);
        b.gateway = Some("10.1.2.3".parse().unwrap());
        assert!(reg.check("b", &b).is_err());
        b.gateway = Some("203.0.113.9".parse().unwrap());
        assert!(reg.check("b", &b).is_ok());
        let mut reg = Registry::default();
        reg.insert("a", claims(&[], true, &[]));
        let mut c = claims(&[], false, &[]);
        c.allow_overlap = true;
        c.gateway = Some("10.1.2.3".parse().unwrap());
        assert!(reg.check("c", &c).is_ok(), "every gateway is inside a full tunnel");
    }

    #[test]
    fn identical_route_needs_opt_in() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], false, &[]));
        let mut b = claims(&["10.0.0.0/8"], false, &[]);
        assert!(reg.check("b", &b).is_err());
        b.allow_overlap = true;
        assert_eq!(reg.check("b", &b).unwrap().len(), 1);
    }

    #[test]
    fn nested_route_needs_opt_in() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], false, &[]));
        let mut b = claims(&["10.20.0.0/16"], false, &[]);
        assert!(reg.check("b", &b).is_err());
        b.allow_overlap = true;
        assert_eq!(reg.check("b", &b).unwrap().len(), 1);
    }

    #[test]
    fn exclusions_cannot_bypass_another_tunnel() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], false, &[]));
        let mut b = claims(&["192.168.0.0/16"], false, &[]);
        b.excluded_routes = vec!["10.0.0.0/9".parse().unwrap()];
        assert!(reg.check("b", &b).is_err());

        let mut reg = Registry::default();
        reg.insert("b", b);
        assert!(reg.check("a", &claims(&["10.1.0.0/16"], false, &[])).is_err());
    }

    #[test]
    fn dns_domains() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&[], false, &["Corp.Example."]));
        assert!(reg.check("b", &claims(&[], false, &["corp.example"])).is_err());
        assert_eq!(reg.check("b", &claims(&[], false, &["eu.corp.example"])).unwrap().len(), 1);
        assert!(reg.check("b", &claims(&[], false, &["notcorp.example"])).unwrap().is_empty());
    }

    #[test]
    fn reconnecting_session_does_not_conflict_with_itself() {
        let mut reg = Registry::default();
        reg.insert("a", claims(&["10.0.0.0/8"], true, &["corp.example"]));
        assert!(reg.check("a", &claims(&["10.0.0.0/8"], true, &["corp.example"])).is_ok());
    }
}
