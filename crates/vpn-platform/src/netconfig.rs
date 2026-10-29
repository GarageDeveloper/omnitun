//! Routes and DNS for one session. Everything installed is recorded as an
//! undo step so the session can be torn down without touching the routes
//! and resolvers of other sessions.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;

use anyhow::{Context, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use vpn_core::TunnelSettings;

use crate::dynamic::{self, Direction, DynamicRoutes};
use crate::{cmd, journal};

/// Gateway host routes are shared by sessions talking to the same gateway:
/// count of sessions, and the uplink the route was added through. Held
/// while the route is added or deleted: a second session must not count
/// on a route the first one is still adding, and may fail to.
static GATEWAY_ROUTES: LazyLock<tokio::sync::Mutex<HashMap<Ipv4Addr, (usize, Uplink)>>> =
    LazyLock::new(Default::default);

#[derive(Debug)]
enum Undo {
    Route(Ipv4Net, Via),
    /// IPv6 refused on the tunnel interface: gone with it after a crash.
    Ipv6Block(Ipv6Net),
    GatewayRoute(Ipv4Addr),
    Dns,
    /// The session's DNS proxy as resolver for some domains.
    ProxyDns,
}

#[derive(Debug, Clone)]
enum Via {
    Interface(String),
    Physical(Uplink),
}

/// The physical path to the Internet, captured before any route is added.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Uplink {
    gateway: Option<Ipv4Addr>,
    interface: String,
}

#[derive(Debug)]
pub struct AppliedConfig {
    session: String,
    interface: String,
    undo: Vec<Undo>,
    /// Routes by domain (#37); none unless the session reports names.
    dynamic: DynamicRoutes,
    direction: Direction,
    uplink: Option<Uplink>,
    /// Already going `direction`: no route by domain needed.
    covered: Vec<Ipv4Net>,
    /// The gateway and the tunnel's own address.
    reserved: Vec<Ipv4Addr>,
    /// To put the DNS back as it was without the proxy (Linux).
    settings: TunnelSettings,
}

/// Who else routes what: the conflict registry, seen by a session.
pub trait DynamicClaims {
    /// Whether `address` may be routed by domain for this session; recorded.
    fn claim(&self, address: Ipv4Addr) -> bool;
    fn release(&self, address: Ipv4Addr);
}

/// Installs routes and DNS for `session` on tun interface `interface`.
/// On failure, whatever was already installed is removed again.
/// `gateway_via`: the tunnel interface the gateway is reached through (a
/// chained session), instead of the physical uplink.
pub async fn apply(
    session: &str,
    interface: &str,
    settings: &TunnelSettings,
    gateway_via: Option<&str>,
) -> anyhow::Result<AppliedConfig> {
    if !crate::valid_session_name(session) {
        bail!("invalid session name {session:?}");
    }
    let mut applied = AppliedConfig {
        session: session.to_owned(),
        interface: interface.to_owned(),
        undo: Vec::new(),
        dynamic: DynamicRoutes::default(),
        direction: if settings.full_tunnel { Direction::Uplink } else { Direction::Tunnel },
        uplink: None,
        covered: if settings.full_tunnel { settings.excluded_routes.clone() } else { settings.routes.clone() },
        reserved: [
            Some(settings.address),
            match settings.gateway {
                IpAddr::V4(gateway) => Some(gateway),
                IpAddr::V6(_) => None,
            },
        ]
        .into_iter()
        .flatten()
        .collect(),
        settings: settings.clone(),
    };
    if let Err(e) = applied.install(settings, gateway_via).await {
        applied.revert().await;
        return Err(e);
    }
    Ok(applied)
}

impl AppliedConfig {
    async fn install(&mut self, settings: &TunnelSettings, gateway_via: Option<&str>) -> anyhow::Result<()> {
        let uplink = uplink().await.context("cannot determine the default route")?;
        self.uplink = Some(uplink.clone());
        let tun = Via::Interface(self.interface.clone());

        if let (IpAddr::V4(gateway), Some(parent)) = (settings.gateway, gateway_via) {
            // Chained: the encrypted transport goes through the other tunnel.
            let via = Via::Interface(parent.to_owned());
            add_route(Ipv4Net::from(gateway), &via)
                .await
                .with_context(|| format!("cannot route gateway {gateway} through {parent}"))?;
            self.undo.push(Undo::Route(Ipv4Net::from(gateway), via));
        } else if let IpAddr::V4(gateway) = settings.gateway {
            // Keep the encrypted transport itself off every tunnel.
            let mut routes = GATEWAY_ROUTES.lock().await;
            if let std::collections::hash_map::Entry::Vacant(entry) = routes.entry(gateway) {
                // Never take ownership of a host route someone else installed.
                add_route(Ipv4Net::from(gateway), &Via::Physical(uplink.clone()))
                    .await
                    .with_context(|| format!("cannot add host route to gateway {gateway}"))?;
                entry.insert((0, uplink.clone()));
            }
            routes.get_mut(&gateway).expect("inserted above").0 += 1;
            drop(routes);
            self.undo.push(Undo::GatewayRoute(gateway));
        }

        let routes: Vec<Ipv4Net> = if settings.full_tunnel {
            vec!["0.0.0.0/1".parse()?, "128.0.0.0/1".parse()?]
        } else {
            settings.routes.clone()
        };
        for route in routes {
            add_route(route, &tun).await?;
            self.undo.push(Undo::Route(route, tun.clone()));
        }
        // The tunnels carry no IPv6: in a full tunnel it would leave in
        // clear through the uplink.
        if settings.full_tunnel && settings.gateway.is_ipv4() {
            let ready = ipv6_capable(&self.interface).await;
            for net in ["::/1", "8000::/1"] {
                let net: Ipv6Net = net.parse()?;
                let blocked = match &ready {
                    Ok(()) => block_ipv6(net, &self.interface).await,
                    Err(e) => Err(anyhow::anyhow!("{e:#}")),
                };
                match blocked {
                    Ok(()) => self.undo.push(Undo::Ipv6Block(net)),
                    Err(e) => tracing::warn!(
                        session = self.session,
                        "IPv6 not blocked, it may leave outside the tunnel: {e:#}"
                    ),
                }
            }
        }
        for route in &settings.excluded_routes {
            let via = Via::Physical(uplink.clone());
            add_route(*route, &via).await?;
            self.undo.push(Undo::Route(*route, via));
        }

        if !settings.dns.servers.is_empty() {
            self.undo.push(Undo::Dns);
            set_dns(&self.session, &self.interface, settings).await?;
        }
        Ok(())
    }

    /// Where this session's routes by domain go.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// How many addresses are routed by domain.
    pub fn dynamic_routes(&self) -> usize {
        self.dynamic.len()
    }

    /// When the next route by domain expires, for the session to call
    /// [`Self::expire_dynamic`].
    pub fn next_dynamic_expiry(&self) -> Option<std::time::Instant> {
        self.dynamic.next_expiry()
    }

    fn dynamic_via(&self) -> Option<Via> {
        match self.direction {
            Direction::Tunnel => Some(Via::Interface(self.interface.clone())),
            Direction::Uplink => self.uplink.clone().map(Via::Physical),
        }
    }

    /// Routes the addresses a listed name resolved to, valid for `ttl`,
    /// before the answer goes back: those already routed are kept longer,
    /// those another session routes are left alone. Returns how many are
    /// routed by domain now.
    pub async fn route_resolved(
        &mut self,
        addresses: &[Ipv4Addr],
        ttl: std::time::Duration,
        claims: &(dyn DynamicClaims + Sync),
    ) -> usize {
        let Some(via) = self.dynamic_via() else { return 0 };
        let now = std::time::Instant::now();
        let mut routed = 0;
        for &address in addresses {
            if self.dynamic.refresh(address, ttl, now) {
                routed += 1;
                continue;
            }
            let needed = dynamic::routable(address, self.direction)
                && !self.reserved.contains(&address)
                && !self.covered.iter().any(|net| net.contains(&address));
            if !needed || !claims.claim(address) {
                continue;
            }
            if let Some(dropped) = self.dynamic.insert(address, ttl, now) {
                self.unroute(dropped, &via, claims).await;
            }
            match add_route(Ipv4Net::from(address), &via).await {
                Ok(()) => routed += 1,
                Err(e) => {
                    tracing::warn!(session = self.session, "cannot route {address} by domain: {e:#}");
                    self.dynamic.remove(address);
                    claims.release(address);
                }
            }
        }
        routed
    }

    /// Removes the routes by domain whose time is up.
    pub async fn expire_dynamic(&mut self, claims: &(dyn DynamicClaims + Sync)) {
        let Some(via) = self.dynamic_via() else { return };
        for address in self.dynamic.expired(std::time::Instant::now()) {
            self.unroute(address, &via, claims).await;
        }
    }

    async fn unroute(&self, address: Ipv4Addr, via: &Via, claims: &(dyn DynamicClaims + Sync)) {
        if let Err(e) = delete_route(Ipv4Net::from(address), via).await {
            tracing::warn!(session = self.session, "cannot remove the route by domain to {address}: {e:#}");
        }
        claims.release(address);
    }

    /// Sends the names under `domains` to the session's DNS proxy on
    /// 127.0.0.1:`port`, and flushes the system's DNS cache so names
    /// resolved before take the routes too. On Linux the tunnel's resolver
    /// becomes the proxy, which relays the tunnel's domains to its servers.
    pub async fn use_proxy(&mut self, port: u16, domains: &[String]) -> anyhow::Result<()> {
        if let Some(bad) = domains.iter().find(|d| !vpn_core::valid_domain(d)) {
            bail!("refusing invalid DNS domain {bad:?}");
        }
        self.undo.push(Undo::ProxyDns);
        set_proxy_dns(&self.session, &self.interface, &self.settings, port, domains).await?;
        flush_dns_cache().await;
        Ok(())
    }

    /// The DNS proxy is gone: the DNS goes back to how it is without it
    /// (routes by domain stop growing; those in place expire).
    pub async fn stop_proxy(&mut self) {
        if let Some(i) = self.undo.iter().position(|u| matches!(u, Undo::ProxyDns)) {
            self.undo.remove(i);
            if let Err(e) = clear_proxy_dns(&self.session, &self.interface, &self.settings, true).await {
                tracing::warn!(session = self.session, "cannot put the DNS back without the proxy: {e:#}");
            }
            flush_dns_cache().await;
        }
    }

    /// Removes everything this session installed. Errors are logged, not
    /// returned: teardown must go as far as it can.
    pub async fn revert(&mut self) {
        // Routes by domain first: they sit on top of the others. The
        // session's claims go with it.
        if let Some(via) = self.dynamic_via() {
            for address in self.dynamic.drain() {
                if let Err(e) = delete_route(Ipv4Net::from(address), &via).await {
                    tracing::warn!(session = self.session, "cleanup of the route by domain to {address} failed: {e:#}");
                }
            }
        }
        while let Some(step) = self.undo.pop() {
            let res = match &step {
                Undo::Route(net, via) => delete_route(*net, via).await,
                Undo::Ipv6Block(net) => unblock_ipv6(*net, &self.interface).await,
                Undo::GatewayRoute(gateway) => {
                    let mut routes = GATEWAY_ROUTES.lock().await;
                    match routes.get_mut(gateway) {
                        Some((count, _)) if *count > 1 => {
                            *count -= 1;
                            Ok(())
                        }
                        // The last session: deleted before another one may
                        // add it again.
                        _ => match routes.remove(gateway) {
                            Some((_, uplink)) => delete_route(Ipv4Net::from(*gateway), &Via::Physical(uplink)).await,
                            None => Ok(()),
                        },
                    }
                }
                Undo::Dns => clear_dns(&self.session, &self.interface).await,
                Undo::ProxyDns => clear_proxy_dns(&self.session, &self.interface, &self.settings, false).await,
            };
            if let Err(e) = res {
                tracing::warn!(session = self.session, "cleanup of {step:?} failed: {e:#}");
            }
        }
    }
}

#[cfg(target_os = "macos")]
async fn uplink() -> anyhow::Result<Uplink> {
    let out = cmd::run("/sbin/route", &["-n", "get", "default"]).await?;
    let field = |key: &str| out.lines().filter_map(|l| l.trim().strip_prefix(key)).map(|v| v.trim().to_owned()).next();
    Ok(Uplink {
        gateway: field("gateway:").and_then(|g| g.parse().ok()),
        interface: field("interface:").context("no default interface")?,
    })
}

#[cfg(target_os = "linux")]
async fn uplink() -> anyhow::Result<Uplink> {
    let out = cmd::run("ip", &["-4", "route", "show", "default"]).await?;
    let line = out.lines().next().context("no default route")?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1)).copied();
    Ok(Uplink {
        gateway: after("via").and_then(|g| g.parse().ok()),
        interface: after("dev").context("default route has no device")?.to_owned(),
    })
}

fn physical(net: Ipv4Net, uplink: &Uplink) -> journal::Entry {
    journal::Entry { net, gateway: uplink.gateway, interface: uplink.interface.clone() }
}

/// Routes through the uplink are journaled first: they would survive a
/// crash of the daemon.
async fn add_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    if let Via::Physical(uplink) = via {
        journal::add(physical(net, uplink));
    }
    let added = os_add_route(net, via).await;
    if added.is_err()
        && let Via::Physical(uplink) = via
    {
        journal::remove(&physical(net, uplink));
    }
    added
}

async fn delete_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let deleted = os_delete_route(net, via).await;
    if let Via::Physical(uplink) = via {
        journal::remove(&physical(net, uplink));
    }
    deleted
}

#[cfg(target_os = "macos")]
async fn os_add_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let dest = net.to_string();
    let kind = if net.prefix_len() == 32 { "-host" } else { "-net" };
    let dest = if net.prefix_len() == 32 { net.addr().to_string() } else { dest };
    match via {
        Via::Interface(ifname) => cmd::run("/sbin/route", &["-n", "add", kind, &dest, "-interface", ifname]).await?,
        Via::Physical(Uplink { gateway: Some(gw), .. }) => {
            cmd::run("/sbin/route", &["-n", "add", kind, &dest, &gw.to_string()]).await?
        }
        Via::Physical(Uplink { interface, .. }) => {
            cmd::run("/sbin/route", &["-n", "add", kind, &dest, "-interface", interface]).await?
        }
    };
    Ok(())
}

/// The gateway is named so a route someone else added for the same
/// destination is left alone.
#[cfg(target_os = "macos")]
async fn os_delete_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let (kind, dest) =
        if net.prefix_len() == 32 { ("-host", net.addr().to_string()) } else { ("-net", net.to_string()) };
    match via {
        Via::Interface(ifname) | Via::Physical(Uplink { gateway: None, interface: ifname }) => {
            cmd::run("/sbin/route", &["-n", "delete", kind, &dest, "-interface", ifname]).await?
        }
        Via::Physical(Uplink { gateway: Some(gw), .. }) => {
            cmd::run("/sbin/route", &["-n", "delete", kind, &dest, &gw.to_string()]).await?
        }
    };
    Ok(())
}

/// macOS refuses IPv6 routes to an interface without an IPv6 address: a
/// link-local one, gone with the interface.
#[cfg(target_os = "macos")]
async fn ipv6_capable(interface: &str) -> anyhow::Result<()> {
    let address = format!("fe80::1%{interface}");
    cmd::run("/sbin/ifconfig", &[interface, "inet6", &address, "prefixlen", "64", "alias"]).await?;
    Ok(())
}

/// A reject route: IPv6 connections fail at once, and applications fall
/// back to IPv4, which the tunnel carries. `route` exits with 0 even when
/// the kernel refused: only its confirmation counts.
#[cfg(target_os = "macos")]
async fn block_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    let net = net.to_string();
    let out = cmd::run("/sbin/route", &["-n", "add", "-inet6", &net, "-interface", interface, "-reject"]).await?;
    if !route_added(&out, &net, interface) {
        bail!("route refused it: {}", out.trim());
    }
    Ok(())
}

/// Whether `route add`'s output confirms the route, which a refusal
/// follows with its reason.
#[cfg(any(target_os = "macos", test))]
fn route_added(out: &str, net: &str, gateway: &str) -> bool {
    out.lines().any(|l| l.trim() == format!("add net {net}: gateway {gateway}"))
}

#[cfg(target_os = "macos")]
async fn unblock_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    cmd::run("/sbin/route", &["-n", "delete", "-inet6", &net.to_string(), "-interface", interface]).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn ipv6_capable(_interface: &str) -> anyhow::Result<()> {
    Ok(())
}

/// Into the tunnel interface, whose engine drops all but IPv4.
#[cfg(target_os = "linux")]
async fn block_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    cmd::run("ip", &["-6", "route", "add", &net.to_string(), "dev", interface]).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn unblock_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    cmd::run("ip", &["-6", "route", "del", &net.to_string(), "dev", interface]).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn route_args(net: Ipv4Net, via: &Via) -> Vec<String> {
    let mut args = vec![net.to_string()];
    match via {
        Via::Interface(ifname) => args.extend(["dev".into(), ifname.clone()]),
        Via::Physical(uplink) => {
            if let Some(gw) = uplink.gateway {
                args.extend(["via".into(), gw.to_string()]);
            }
            args.extend(["dev".into(), uplink.interface.clone()]);
        }
    }
    args
}

#[cfg(target_os = "linux")]
async fn os_add_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let mut args = vec!["route".to_owned(), "add".to_owned()];
    args.extend(route_args(net, via));
    cmd::run("ip", &args.iter().map(String::as_str).collect::<Vec<_>>()).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn os_delete_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let mut args = vec!["route".to_owned(), "del".to_owned()];
    args.extend(route_args(net, via));
    cmd::run("ip", &args.iter().map(String::as_str).collect::<Vec<_>>()).await?;
    Ok(())
}

#[cfg(target_os = "macos")]
const SERVICE_PREFIX: &str = "State:/Network/Service/";

#[cfg(target_os = "macos")]
fn scutil_key(session: &str, entity: &str) -> String {
    format!("{SERVICE_PREFIX}{}-{session}/{entity}", vpn_core::brand::ID)
}

/// macOS: a per-session service in the dynamic store. Split tunnels publish
/// supplemental match domains; a full tunnel also publishes an IPv4 entity
/// with `OverridePrimary` so its resolver becomes the default one.
#[cfg(target_os = "macos")]
async fn set_dns(session: &str, interface: &str, settings: &TunnelSettings) -> anyhow::Result<()> {
    check_domains(settings)?;
    let dns = &settings.dns;
    let servers: Vec<String> = dns.servers.iter().map(|s| s.to_string()).collect();
    let mut script = format!("d.init\nd.add ServerAddresses * {}\n", servers.join(" "));
    if !dns.search_domains.is_empty() {
        script += &format!("d.add SearchDomains * {}\n", dns.search_domains.join(" "));
    }
    if !settings.full_tunnel {
        let domains = if dns.match_domains.is_empty() { &dns.search_domains } else { &dns.match_domains };
        if domains.is_empty() {
            tracing::warn!(session, "split tunnel without DNS domains: tunnel DNS servers left unused");
            return Ok(());
        }
        script += &format!("d.add SupplementalMatchDomains * {}\n", domains.join(" "));
    }
    script += &format!("set {}\n", scutil_key(session, "DNS"));
    if settings.full_tunnel {
        let router = settings.address;
        script += &format!(
            "d.init\nd.add Addresses * {}\nd.add InterfaceName {interface}\nd.add Router {router}\n\
             d.add OverridePrimary # 1\nset {}\n",
            settings.address,
            scutil_key(session, "IPv4"),
        );
    }
    cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&script)).await?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn clear_dns(session: &str, _interface: &str) -> anyhow::Result<()> {
    let script = format!("remove {}\nremove {}\n", scutil_key(session, "IPv4"), scutil_key(session, "DNS"));
    cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&script)).await?;
    Ok(())
}

/// Linux: systemd-resolved per-link configuration, which keeps sessions
/// independent by construction.
#[cfg(target_os = "linux")]
async fn set_dns(_session: &str, interface: &str, settings: &TunnelSettings) -> anyhow::Result<()> {
    check_domains(settings)?;
    let dns = &settings.dns;
    let mut args = vec!["dns".to_owned(), interface.to_owned()];
    args.extend(dns.servers.iter().map(|s| s.to_string()));
    resolvectl(&args).await?;

    let mut domains: Vec<String> = dns.search_domains.clone();
    domains.extend(dns.match_domains.iter().map(|d| format!("~{d}")));
    if settings.full_tunnel {
        domains.push("~.".into());
    }
    if !domains.is_empty() {
        let mut args = vec!["domain".to_owned(), interface.to_owned()];
        args.extend(domains);
        resolvectl(&args).await?;
    }
    let default_route = if settings.full_tunnel { "true" } else { "false" };
    resolvectl(&["default-route".into(), interface.into(), default_route.into()]).await
}

#[cfg(target_os = "linux")]
async fn clear_dns(_session: &str, interface: &str) -> anyhow::Result<()> {
    resolvectl(&["revert".into(), interface.into()]).await
}

#[cfg(target_os = "linux")]
async fn resolvectl(args: &[String]) -> anyhow::Result<()> {
    cmd::run("resolvectl", &args.iter().map(String::as_str).collect::<Vec<_>>())
        .await
        .context("systemd-resolved is required for per-tunnel DNS")?;
    Ok(())
}

/// macOS: a resolver entry of its own for the proxy's domains, next to the
/// session's; port other than 53 accepted (#37, phase 0).
#[cfg(target_os = "macos")]
async fn set_proxy_dns(
    session: &str,
    _interface: &str,
    _settings: &TunnelSettings,
    port: u16,
    domains: &[String],
) -> anyhow::Result<()> {
    let script = format!(
        "d.init\nd.add ServerAddresses * 127.0.0.1\nd.add ServerPort # {port}\n\
         d.add SupplementalMatchDomains * {}\nset {}\n",
        domains.join(" "),
        scutil_key(&format!("{session}-dns-proxy"), "DNS"),
    );
    cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&script)).await?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn clear_proxy_dns(
    session: &str,
    _interface: &str,
    _settings: &TunnelSettings,
    _restore: bool,
) -> anyhow::Result<()> {
    let script = format!("remove {}\n", scutil_key(&format!("{session}-dns-proxy"), "DNS"));
    cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&script)).await?;
    Ok(())
}

/// Linux: one resolver per link, so the tunnel's link resolves through the
/// proxy, for its own domains and the proxy's.
#[cfg(target_os = "linux")]
async fn set_proxy_dns(
    _session: &str,
    interface: &str,
    settings: &TunnelSettings,
    port: u16,
    domains: &[String],
) -> anyhow::Result<()> {
    check_domains(settings)?;
    resolvectl(&["dns".into(), interface.into(), format!("127.0.0.1:{port}")]).await?;
    let dns = &settings.dns;
    let mut routing: Vec<String> = dns.search_domains.clone();
    routing.extend(dns.match_domains.iter().chain(domains).map(|d| format!("~{d}")));
    if settings.full_tunnel {
        routing.push("~.".into());
    }
    let mut args = vec!["domain".to_owned(), interface.to_owned()];
    args.extend(routing);
    resolvectl(&args).await?;
    let default_route = if settings.full_tunnel { "true" } else { "false" };
    resolvectl(&["default-route".into(), interface.into(), default_route.into()]).await
}

/// `restore`: the session goes on, with its DNS as without the proxy.
#[cfg(target_os = "linux")]
async fn clear_proxy_dns(
    _session: &str,
    interface: &str,
    settings: &TunnelSettings,
    restore: bool,
) -> anyhow::Result<()> {
    if restore && !settings.dns.servers.is_empty() {
        return set_dns(_session, interface, settings).await;
    }
    resolvectl(&["revert".into(), interface.into()]).await
}

#[cfg(target_os = "macos")]
async fn flush_dns_cache() {
    let _ = cmd::run("/usr/bin/dscacheutil", &["-flushcache"]).await;
    let _ = cmd::run("/usr/bin/killall", &["-HUP", "mDNSResponder"]).await;
}

#[cfg(target_os = "linux")]
async fn flush_dns_cache() {
    let _ = cmd::run("resolvectl", &["flush-caches"]).await;
}

/// The resolvers answering now for names no VPN claims, before this
/// session's DNS is set: those the DNS proxy relays to, so whatever was in
/// place (an antivirus filtering DNS, say) keeps seeing the queries.
/// `ignore`: the tunnel interfaces of other sessions (Linux).
pub async fn current_resolvers(ignore: &[String]) -> anyhow::Result<Vec<SocketAddr>> {
    #[cfg(target_os = "macos")]
    let servers = {
        let _ = ignore;
        default_resolvers_macos(&cmd::run("/usr/sbin/scutil", &["--dns"]).await?)
    };
    #[cfg(target_os = "linux")]
    let servers = link_resolvers_linux(&cmd::run("resolvectl", &["dns"]).await?, ignore);
    if servers.is_empty() {
        bail!("no DNS server in use");
    }
    Ok(servers)
}

/// The servers of `scutil --dns`'s first resolver (the default one).
#[cfg(any(target_os = "macos", test))]
fn default_resolvers_macos(text: &str) -> Vec<SocketAddr> {
    let first = text
        .split("\nresolver #")
        .nth(1)
        .filter(|block| block.starts_with("1\n"))
        .map(|block| block.split("\n\n").next().unwrap_or(block))
        .unwrap_or("");
    let field = |line: &str, key: &str| {
        let (k, v) = line.split_once(':')?;
        (k.trim() == key || k.trim().starts_with(&format!("{key}["))).then(|| v.trim().to_owned())
    };
    let port = first.lines().find_map(|l| field(l, "port")).and_then(|p| p.parse().ok()).unwrap_or(53);
    first
        .lines()
        .filter_map(|l| field(l, "nameserver"))
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, port))
        .take(8)
        .collect()
}

/// `resolvectl dns`: the servers of the links, then the global ones, a
/// fallback in practice; never those of the tunnels in `ignore` (the
/// global list may repeat them) nor resolved's own stubs. Servers are
/// written `1.1.1.1`, `1.1.1.1:5353`, `1.1.1.1#name` or `[::1]:53`.
#[cfg(any(target_os = "linux", test))]
fn link_resolvers_linux(text: &str, ignore: &[String]) -> Vec<SocketAddr> {
    let parse = |server: &str| {
        let server = server.split('#').next().unwrap_or(server);
        server.parse::<SocketAddr>().ok().or_else(|| server.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
    };
    let link_of = |scope: &str| {
        scope.strip_prefix("Link ").and_then(|l| l.split_once('(')).map(|(_, n)| n.trim_end_matches(')').to_owned())
    };
    let scopes: Vec<(&str, &str)> =
        text.lines().filter_map(|l| l.split_once(':')).map(|(s, l)| (s.trim(), l)).collect();
    let mut excluded: Vec<SocketAddr> = ["127.0.0.53:53", "127.0.0.54:53"].iter().map(|s| s.parse().unwrap()).collect();
    for (scope, list) in &scopes {
        if link_of(scope).is_some_and(|name| ignore.contains(&name)) {
            excluded.extend(list.split_whitespace().filter_map(parse));
        }
    }
    let (global, links): (Vec<_>, Vec<_>) = scopes.iter().partition(|(scope, _)| *scope == "Global");
    let mut servers = Vec::new();
    for (scope, list) in links.into_iter().chain(global) {
        if scope != "Global" && link_of(scope).is_none() {
            continue;
        }
        for addr in list.split_whitespace().filter_map(parse) {
            if !excluded.contains(&addr) && !servers.contains(&addr) {
                servers.push(addr);
            }
        }
    }
    servers.truncate(8);
    servers
}

/// DNS names come from the gateway and end up in scutil's command stream
/// or resolvectl's argv: refuse anything that is not a plain hostname.
fn check_domains(settings: &TunnelSettings) -> anyhow::Result<()> {
    if let Some(bad) = settings.dns.domains().find(|d| !vpn_core::valid_domain(d)) {
        bail!("refusing invalid DNS domain {bad:?}");
    }
    Ok(())
}

/// Removes what a previous daemon that did not shut down cleanly left
/// behind: its journaled routes through the uplink and, on macOS, its
/// resolver entries (including those from before the rename). Routes bound
/// to its tun interfaces vanished with them.
pub async fn cleanup_stale() {
    let stale = journal::take_stale();
    if !stale.is_empty() {
        tracing::info!("removing {} stale routes", stale.len());
    }
    for entry in stale {
        let uplink = Uplink { gateway: entry.gateway, interface: entry.interface };
        if let Err(e) = os_delete_route(entry.net, &Via::Physical(uplink)).await {
            tracing::warn!("stale route {}: {e:#}", entry.net);
        }
    }
    cleanup_stale_dns().await;
}

#[cfg(target_os = "macos")]
async fn cleanup_stale_dns() {
    let Ok(listing) = cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&format!("list {SERVICE_PREFIX}.*\n"))).await
    else {
        return;
    };
    let ours = [vpn_core::brand::ID, vpn_core::brand::legacy::DAEMON].map(|id| format!("{SERVICE_PREFIX}{id}-"));
    let keys: Vec<&str> = listing
        .lines()
        .filter_map(|l| l.split(" = ").nth(1))
        .map(str::trim)
        .filter(|k| ours.iter().any(|p| k.starts_with(p.as_str())))
        .collect();
    if keys.is_empty() {
        return;
    }
    tracing::info!("removing {} stale resolver entries", keys.len());
    let script: String = keys.iter().map(|k| format!("remove {k}\n")).collect();
    if let Err(e) = cmd::run_with_stdin("/usr/sbin/scutil", &[], Some(&script)).await {
        tracing::warn!("stale resolver cleanup failed: {e:#}");
    }
}

#[cfg(target_os = "linux")]
async fn cleanup_stale_dns() {}

#[cfg(test)]
mod tests {
    #[test]
    fn resolvers_in_place() {
        let scutil = "DNS configuration\n\nresolver #1\n  search domain[0] : localdomain\n  \
                      nameserver[0] : 192.168.0.1\n  nameserver[1] : 2001:db8::1\n  if_index : 15 (en0)\n\n\
                      resolver #2\n  domain   : local\n  nameserver[0] : 10.9.9.9\n";
        assert_eq!(
            super::default_resolvers_macos(scutil),
            ["192.168.0.1:53".parse().unwrap(), "[2001:db8::1]:53".parse().unwrap()]
        );
        let antivirus = "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n  port     : 5300\n";
        assert_eq!(super::default_resolvers_macos(antivirus), ["127.0.0.1:5300".parse().unwrap()]);
        assert!(super::default_resolvers_macos("DNS configuration\n\nresolver #1\n  flags : x\n").is_empty());

        // The global list repeats the links' servers, a tunnel's included.
        let resolvectl = "Global: 1.1.1.1#cloudflare-dns.com 127.0.0.53 127.0.0.1:40000\n\
                          Link 2 (eth0): 192.168.1.1 [2001:db8::53]:53\n\
                          Link 5 (tun0): 127.0.0.1:40000\nLink 3 (wlan0): 192.168.1.1:5353\n";
        assert_eq!(
            super::link_resolvers_linux(resolvectl, &["tun0".into()]),
            [
                "192.168.1.1:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
                "192.168.1.1:5353".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn route_confirmation() {
        assert!(super::route_added("add net ::/1: gateway utun6\n", "::/1", "utun6"));
        let refused = "add net ::/1: gateway utun6: Network is unreachable\n";
        assert!(!super::route_added(refused, "::/1", "utun6"));
        assert!(!super::route_added("", "::/1", "utun6"));
    }
}
