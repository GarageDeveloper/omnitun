//! Routes and DNS for one session. Everything installed is recorded as an
//! undo step so the session can be torn down without touching the routes
//! and resolvers of other sessions.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use vpn_core::TunnelSettings;

use crate::{cmd, journal};

/// Gateway host routes are shared by sessions talking to the same gateway:
/// count of sessions, and the uplink the route was added through.
static GATEWAY_ROUTES: LazyLock<Mutex<HashMap<Ipv4Addr, (usize, Uplink)>>> = LazyLock::new(Default::default);

#[derive(Debug)]
enum Undo {
    Route(Ipv4Net, Via),
    GatewayRoute(Ipv4Addr),
    Dns,
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
    let mut applied = AppliedConfig { session: session.to_owned(), interface: interface.to_owned(), undo: Vec::new() };
    if let Err(e) = applied.install(settings, gateway_via).await {
        applied.revert().await;
        return Err(e);
    }
    Ok(applied)
}

impl AppliedConfig {
    async fn install(&mut self, settings: &TunnelSettings, gateway_via: Option<&str>) -> anyhow::Result<()> {
        let uplink = uplink().await.context("cannot determine the default route")?;
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
            let first = {
                let mut routes = GATEWAY_ROUTES.lock().unwrap();
                let (count, _) = routes.entry(gateway).or_insert((0, uplink.clone()));
                *count += 1;
                *count == 1
            };
            if first && let Err(e) = add_route(Ipv4Net::from(gateway), &Via::Physical(uplink.clone())).await {
                // Never take ownership of a host route someone else installed.
                GATEWAY_ROUTES.lock().unwrap().remove(&gateway);
                return Err(e.context(format!("cannot add host route to gateway {gateway}")));
            }
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

    /// Removes everything this session installed. Errors are logged, not
    /// returned: teardown must go as far as it can.
    pub async fn revert(&mut self) {
        while let Some(step) = self.undo.pop() {
            let res = match &step {
                Undo::Route(net, via) => delete_route(*net, via).await,
                Undo::GatewayRoute(gateway) => {
                    let last = {
                        let mut routes = GATEWAY_ROUTES.lock().unwrap();
                        match routes.get_mut(gateway) {
                            Some((count, _)) if *count > 1 => {
                                *count -= 1;
                                None
                            }
                            _ => routes.remove(gateway).map(|(_, uplink)| uplink),
                        }
                    };
                    match last {
                        Some(uplink) => delete_route(Ipv4Net::from(*gateway), &Via::Physical(uplink)).await,
                        None => Ok(()),
                    }
                }
                Undo::Dns => clear_dns(&self.session, &self.interface).await,
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
