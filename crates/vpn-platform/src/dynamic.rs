//! Routes by domain (issue #37): the addresses a listed name resolves to
//! get a host route of their own, through the tunnel (included domains of
//! a split tunnel) or the uplink (domains kept outside a full tunnel). They
//! are kept at least `FLOOR`, since connections outlive a DNS answer, and at
//! most `MAX_PER_SESSION` per session, the first to expire dropped first.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// How long an address stays routed at least, whatever its TTL.
pub const FLOOR: Duration = Duration::from_secs(600);
/// And at most without being resolved again.
pub const CEILING: Duration = Duration::from_secs(86_400);
pub const MAX_PER_SESSION: usize = 1024;

/// Where a session's routes by domain go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Into the tunnel: a split tunnel's included domains.
    Tunnel,
    /// Out through the uplink: a full tunnel's excluded domains.
    Uplink,
}

/// Whether an address may get a route by domain going `direction`. Never
/// this host, multicast or reserved space. Outside a full tunnel, only
/// public addresses: a DNS answer must not take a private network, the
/// company's perhaps, out of the tunnel.
pub fn routable(address: Ipv4Addr, direction: Direction) -> bool {
    let [a, b, ..] = address.octets();
    let local = a == 0 || address.is_loopback() || address.is_link_local() || address.is_broadcast() || a >= 224;
    let private = address.is_private() || (a == 100 && (64..128).contains(&b));
    !local && (direction == Direction::Tunnel || !private)
}

/// The addresses routed for one session, until when, and the name they
/// were last resolved for.
#[derive(Debug, Default)]
pub struct DynamicRoutes {
    until: HashMap<Ipv4Addr, (Instant, String)>,
}

impl DynamicRoutes {
    pub fn len(&self) -> usize {
        self.until.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.until.contains_key(&address)
    }

    /// Keeps a routed address longer, resolved again for `name`; false if
    /// it is not routed.
    pub fn refresh(&mut self, address: Ipv4Addr, name: &str, ttl: Duration, now: Instant) -> bool {
        match self.until.get_mut(&address) {
            Some((until, last)) => {
                *until = (*until).max(expiry(ttl, now));
                if last != name {
                    *last = name.to_owned();
                }
                true
            }
            None => false,
        }
    }

    /// Records a newly routed address; returns the one dropped to make
    /// room, whose route must go.
    pub fn insert(&mut self, address: Ipv4Addr, name: &str, ttl: Duration, now: Instant) -> Option<Ipv4Addr> {
        let dropped = if self.until.len() >= MAX_PER_SESSION && !self.contains(address) {
            let first = self.until.iter().min_by_key(|(_, (until, _))| *until).map(|(a, _)| *a);
            first.inspect(|a| {
                self.until.remove(a);
            })
        } else {
            None
        };
        self.until.insert(address, (expiry(ttl, now), name.to_owned()));
        dropped
    }

    /// Forgets an address whose route could not be added.
    pub fn remove(&mut self, address: Ipv4Addr) {
        self.until.remove(&address);
    }

    /// The addresses expired at `now`, forgotten.
    pub fn expired(&mut self, now: Instant) -> Vec<Ipv4Addr> {
        let expired: Vec<Ipv4Addr> =
            self.until.iter().filter(|(_, (until, _))| *until <= now).map(|(a, _)| *a).collect();
        for address in &expired {
            self.until.remove(address);
        }
        expired
    }

    /// When the next address expires.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.until.values().map(|(until, _)| *until).min()
    }

    /// Every address, its name and its expiry, by name then address.
    pub fn entries(&self) -> Vec<(Ipv4Addr, &str, Instant)> {
        let mut entries: Vec<_> = self.until.iter().map(|(a, (until, name))| (*a, name.as_str(), *until)).collect();
        entries.sort_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0)));
        entries
    }

    /// Every address, forgotten.
    pub fn drain(&mut self) -> Vec<Ipv4Addr> {
        self.until.drain().map(|(a, _)| a).collect()
    }
}

fn expiry(ttl: Duration, now: Instant) -> Instant {
    now + ttl.clamp(FLOOR, CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u32) -> Ipv4Addr {
        Ipv4Addr::from(0xcb00_7100 + n)
    }

    #[test]
    fn kept_for_the_ttl_with_a_floor_and_a_ceiling() {
        let now = Instant::now();
        let mut routes = DynamicRoutes::default();
        assert_eq!(routes.insert(ip(1), "a.example", Duration::from_secs(30), now), None);
        routes.insert(ip(2), "b.example", Duration::from_secs(7 * 86_400), now);
        assert!(routes.expired(now + FLOOR - Duration::from_secs(1)).is_empty(), "the floor, not 30 s");
        assert_eq!(routes.expired(now + FLOOR), [ip(1)]);
        assert_eq!(routes.next_expiry(), Some(now + CEILING), "a week is capped");
        assert!(!routes.refresh(ip(1), "a.example", Duration::ZERO, now), "expired: routed again");
    }

    #[test]
    fn resolved_again_lasts_longer_never_shorter() {
        let now = Instant::now();
        let mut routes = DynamicRoutes::default();
        routes.insert(ip(1), "a.example", Duration::from_secs(3600), now);
        assert!(routes.refresh(ip(1), "a.example", Duration::from_secs(60), now + Duration::from_secs(10)));
        assert_eq!(routes.next_expiry(), Some(now + Duration::from_secs(3600)));
        assert!(routes.refresh(ip(1), "cdn.example", Duration::from_secs(3600), now + Duration::from_secs(100)));
        assert_eq!(routes.next_expiry(), Some(now + Duration::from_secs(3700)));
        assert_eq!(routes.entries(), [(ip(1), "cdn.example", now + Duration::from_secs(3700))], "the last name");
    }

    #[test]
    fn the_first_to_expire_makes_room() {
        let now = Instant::now();
        let mut routes = DynamicRoutes::default();
        for n in 0..MAX_PER_SESSION as u32 {
            // ip(5) expires first.
            let ttl = if n == 5 { FLOOR } else { Duration::from_secs(7200) };
            assert_eq!(routes.insert(ip(n), "a.example", ttl, now), None);
        }
        assert_eq!(routes.insert(ip(5000), "b.example", FLOOR, now), Some(ip(5)));
        assert_eq!(routes.len(), MAX_PER_SESSION);
        assert_eq!(routes.insert(ip(5000), "b.example", FLOOR, now), None, "already there");
        assert_eq!(routes.drain().len(), MAX_PER_SESSION);
        assert!(routes.is_empty());
    }

    #[test]
    fn addresses_that_may_be_routed() {
        for address in ["203.0.113.7", "52.72.0.1", "8.8.8.8"] {
            let address = address.parse().unwrap();
            assert!(routable(address, Direction::Tunnel) && routable(address, Direction::Uplink), "{address}");
        }
        for private in ["10.1.2.3", "172.16.0.1", "192.168.1.5", "100.64.0.1"] {
            let address = private.parse().unwrap();
            assert!(routable(address, Direction::Tunnel), "{private} through the tunnel");
            assert!(!routable(address, Direction::Uplink), "{private} never out of a full tunnel");
        }
        for never in ["0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.251", "240.0.0.1", "255.255.255.255"] {
            assert!(!routable(never.parse().unwrap(), Direction::Tunnel), "{never}");
        }
    }
}
