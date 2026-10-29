//! Protocol between `omnitund` (root) and a session's DNS proxy
//! (`omnitun-engine --dns-proxy`, unprivileged and sandboxed), for routes by
//! domain (#37). Newline-delimited JSON on a control socket; the daemon
//! binds the proxy's UDP and TCP sockets and passes them as descriptors.
//!
//! The proxy is untrusted: the daemon routes an address only for a name
//! the session lists, and checks the address like any route.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::DomainPattern;

/// Longest control line accepted from either side.
pub const MAX_LINE: u64 = 64 * 1024;
/// Addresses of one answer reported to the daemon; the rest are not routed.
pub const MAX_ADDRESSES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// The names whose addresses are routed (and whose AAAA, HTTPS and
    /// SVCB answers are emptied).
    pub routed: Vec<DomainPattern>,
    /// Where queries go, the most specific domain first chosen; a resolver
    /// without domains takes the rest.
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    /// Names under these domains; none: every name.
    pub domains: Vec<String>,
    /// Tried in order.
    pub servers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ToProxy {
    /// The first line: what to do.
    Config { config: ProxyConfig },
    /// The routes for request `id` are in place (or will not be): answer.
    Routed { id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum FromProxy {
    /// `name` (a routed one) resolved to `addresses` for `ttl` seconds; the
    /// answer waits for `Routed`.
    Resolved { id: u64, name: String, addresses: Vec<Ipv4Addr>, ttl: u32 },
}
