//! The daemon's side of a session's DNS proxy, for routes by domain (#37):
//! only for a session whose profile lists domains for its mode (included
//! in a split tunnel, excluded from a full one). The proxy is the engine
//! binary, unprivileged and sandboxed, given the sockets bound here; what
//! it reports is checked against the session's domains before anything is
//! routed. If it fails, the session goes on with its DNS as without it.

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use vpn_core::dns_ipc::{FromProxy, MAX_LINE, ProxyConfig, ToProxy, Upstream};
use vpn_core::{DomainPattern, Profile, TunnelSettings};

use crate::engine::Launcher;

/// What a session's proxy does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub config: ProxyConfig,
    /// The domains the system resolver sends to the proxy.
    pub domains: Vec<String>,
}

impl Plan {
    /// Whether the proxy may report `name`.
    pub fn routes(&self, name: &str) -> bool {
        self.config.routed.iter().any(|pattern| pattern.matches(name))
    }
}

/// The proxy for `profile` connected with `settings`, relaying to the
/// tunnel's servers for its domains and to `previous` (the resolvers in
/// place before) for the rest; none without domains for this mode.
pub fn plan(profile: &Profile, settings: &TunnelSettings, previous: &[SocketAddr]) -> anyhow::Result<Option<Plan>> {
    let mut routed: Vec<DomainPattern> = if settings.full_tunnel {
        profile.excluded_domains.iter().map(|d| d.value.clone()).collect()
    } else {
        profile.included_domains().into_iter().cloned().collect()
    };
    routed.sort();
    routed.dedup();
    if routed.is_empty() {
        if profile.routes_by_domain() {
            let mode = if settings.full_tunnel { "a full tunnel" } else { "a split tunnel" };
            tracing::info!(session = profile.name, "its domains are not for {mode}: none routed");
        }
        return Ok(None);
    }
    let dns = &settings.dns;
    let tunnel_domains: Vec<String> = dns
        .match_domains
        .iter()
        .chain(&dns.search_domains)
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let tunnel_servers: Vec<SocketAddr> = dns.servers.iter().map(|ip| SocketAddr::new(*ip, 53)).collect();
    let in_tunnel = |base: &str| {
        !tunnel_servers.is_empty() && tunnel_domains.iter().any(|d| vpn_core::destination::is_under(base, d))
    };
    let mut domains: Vec<String> = routed.iter().map(|p| p.base().to_owned()).collect();
    domains.dedup();
    // The names under the tunnel's domains are resolved by its servers as
    // without the proxy; the others by the resolvers in place.
    let outside: Vec<String> = domains.iter().filter(|d| !in_tunnel(d)).cloned().collect();
    if !outside.is_empty() && previous.is_empty() {
        bail!("no DNS server in use to resolve {}", outside.join(", "));
    }
    let mut upstreams = Vec::new();
    if !tunnel_servers.is_empty() && !tunnel_domains.is_empty() {
        upstreams.push(Upstream { domains: tunnel_domains, servers: tunnel_servers.clone(), independent: false });
    }
    if !outside.is_empty() {
        upstreams.push(Upstream { domains: outside, servers: previous.to_vec(), independent: true });
    }
    // The rest: what a full tunnel resolves through, else what was there.
    let rest = if settings.full_tunnel && !tunnel_servers.is_empty() {
        Upstream { domains: Vec::new(), servers: tunnel_servers, independent: false }
    } else {
        Upstream { domains: Vec::new(), servers: previous.to_vec(), independent: true }
    };
    if !rest.servers.is_empty() {
        upstreams.push(rest);
    }
    Ok(Some(Plan { config: ProxyConfig { routed, upstreams }, domains }))
}

/// A session's running proxy. Dropping it ends the proxy.
pub struct DnsProxy {
    pub port: u16,
    out: mpsc::Sender<ToProxy>,
    events: mpsc::Receiver<FromProxy>,
    child: Option<tokio::process::Child>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for DnsProxy {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A UDP socket and a TCP listener on one loopback port.
fn bind() -> anyhow::Result<(std::net::UdpSocket, std::net::TcpListener)> {
    for _ in 0..8 {
        let udp = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
        let port = udp.local_addr()?.port();
        // The port may be taken for TCP: another one then.
        if let Ok(tcp) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            return Ok((udp, tcp));
        }
    }
    bail!("no loopback port free for both UDP and TCP")
}

impl DnsProxy {
    /// Starts session `name`'s proxy with `config`.
    pub async fn start(launcher: &Launcher, name: &str, config: ProxyConfig) -> anyhow::Result<Self> {
        let (udp, tcp) = bind().context("cannot bind the DNS proxy's sockets")?;
        let port = udp.local_addr()?.port();
        let (control, theirs) = StdUnixStream::pair()?;
        let mut tasks = Vec::new();
        let child = match launcher {
            Launcher::Process { path, uid, gid, sandbox } => {
                let fds: [OwnedFd; 3] = [theirs.into(), udp.into(), tcp.into()];
                let mut child = crate::engine::spawn(path, *uid, *gid, *sandbox, &["--dns-proxy".into()], fds)?;
                if let Some(stderr) = child.stderr.take() {
                    tasks.push(tokio::spawn(crate::engine::relay_log(format!("{name} dns"), stderr)));
                }
                Some(child)
            }
            #[cfg(test)]
            Launcher::InProcess => {
                theirs.set_nonblocking(true)?;
                udp.set_nonblocking(true)?;
                tcp.set_nonblocking(true)?;
                let (control, udp, tcp) = (
                    UnixStream::from_std(theirs)?,
                    tokio::net::UdpSocket::from_std(udp)?,
                    tokio::net::TcpListener::from_std(tcp)?,
                );
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = vpn_dnsproxy::run(control, udp, tcp).await {
                        tracing::debug!("in-process DNS proxy: {e:#}");
                    }
                }));
                None
            }
        };
        control.set_nonblocking(true)?;
        let (read, mut write) = UnixStream::from_std(control)?.into_split();
        let (out, mut out_rx) = mpsc::channel::<ToProxy>(64);
        tasks.push(tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                let mut line = serde_json::to_vec(&message).expect("messages serialize");
                line.push(b'\n');
                if write.write_all(&line).await.is_err() {
                    break;
                }
            }
        }));
        let (events_tx, events) = mpsc::channel::<FromProxy>(64);
        tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(read);
            loop {
                let mut line = String::new();
                match (&mut lines).take(MAX_LINE).read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => match serde_json::from_str::<FromProxy>(&line) {
                        Ok(message) => {
                            if events_tx.send(message).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("the DNS proxy sent an invalid message: {e}");
                            break;
                        }
                    },
                }
            }
        }));
        out.send(ToProxy::Config { config }).await.context("the DNS proxy exited")?;
        Ok(Self { port, out, events, child, tasks })
    }

    /// The proxy's next report; `None` once it is gone.
    pub async fn next(&mut self) -> Option<FromProxy> {
        self.events.recv().await
    }

    /// Releases the answer waiting for request `id`.
    pub async fn routed(&self, id: u64) {
        let _ = self.out.send(ToProxy::Routed { id }).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn profile(extra: &str) -> Profile {
        toml::from_str(&format!("name = \"t\"\nprotocol = \"forti-ssl\"\nhost = \"h.example\"\n{extra}")).unwrap()
    }

    fn settings(full: bool, servers: &[&str], domains: &[&str]) -> TunnelSettings {
        TunnelSettings {
            address: Ipv4Addr::new(10, 0, 0, 2),
            mtu: 1400,
            routes: vec![],
            excluded_routes: vec![],
            full_tunnel: full,
            dns: vpn_core::DnsSettings {
                servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
                search_domains: vec![],
                match_domains: domains.iter().map(|d| d.to_string()).collect(),
            },
            gateway: "203.0.113.1".parse().unwrap(),
        }
    }

    fn previous() -> Vec<SocketAddr> {
        vec!["192.168.1.1:53".parse().unwrap()]
    }

    #[test]
    fn nothing_without_domains_for_the_mode() {
        let p = profile("routes = [\"10.0.0.0/8\"]");
        assert_eq!(plan(&p, &settings(false, &[], &[]), &previous()).unwrap(), None);
        let p = profile("excluded_domains = [\"zoom.us\"]");
        assert_eq!(plan(&p, &settings(false, &[], &[]), &previous()).unwrap(), None, "split: no exclusions");
        let p = profile("routes = [\"*.saas.example\"]");
        assert_eq!(plan(&p, &settings(true, &[], &[]), &previous()).unwrap(), None, "full: no inclusions");
    }

    /// Included names under the tunnel's domains go to its servers; the
    /// others to the resolvers in place.
    #[test]
    fn included_domains_of_a_split_tunnel() {
        let p = profile("routes = [\"10.0.0.0/8\", \"*.saas.example\", \"*.app.corp.example\", \"crm.example\"]");
        let s = settings(false, &["10.0.0.53"], &["corp.example"]);
        let plan = plan(&p, &s, &previous()).unwrap().unwrap();
        assert_eq!(plan.domains, ["app.corp.example", "crm.example", "saas.example"]);
        let tunnel: SocketAddr = "10.0.0.53:53".parse().unwrap();
        assert_eq!(
            plan.config.upstreams,
            [
                Upstream { domains: vec!["corp.example".into()], servers: vec![tunnel], independent: false },
                Upstream {
                    domains: vec!["crm.example".into(), "saas.example".into()],
                    servers: previous(),
                    independent: true
                },
                Upstream { domains: vec![], servers: previous(), independent: true },
            ]
        );
        assert!(plan.routes("eu.saas.example") && plan.routes("crm.example"));
        assert!(!plan.routes("www.example.org") && !plan.routes("x.crm.example"));
    }

    /// Excluded names leave a full tunnel through the resolvers in place;
    /// the rest through the tunnel's servers, as without the proxy.
    #[test]
    fn excluded_domains_of_a_full_tunnel() {
        let p = profile("excluded_domains = [\"*.zoom.us\", { domain = \"teams.microsoft.com\", note = \"Teams\" }]");
        let s = settings(true, &["10.0.0.53"], &[]);
        let plan = plan(&p, &s, &previous()).unwrap().unwrap();
        let tunnel: SocketAddr = "10.0.0.53:53".parse().unwrap();
        assert_eq!(
            plan.config.upstreams,
            [
                Upstream {
                    domains: vec!["teams.microsoft.com".into(), "zoom.us".into()],
                    servers: previous(),
                    independent: true
                },
                Upstream { domains: vec![], servers: vec![tunnel], independent: false },
            ]
        );
        assert!(plan.routes("eu01.zoom.us") && !plan.routes("intranet.corp.example"));
    }

    #[test]
    fn the_resolvers_in_place_are_needed() {
        let p = profile("excluded_domains = [\"zoom.us\"]");
        assert!(plan(&p, &settings(true, &["10.0.0.53"], &[]), &[]).is_err());
        // Under the tunnel's domains only: its servers are enough.
        let p = profile("routes = [\"*.app.corp.example\"]");
        assert!(plan(&p, &settings(false, &["10.0.0.53"], &["corp.example"]), &[]).unwrap().is_some());
    }

    /// The proxy end to end, in this process: it reports, the daemon
    /// releases.
    #[tokio::test]
    async fn starts_and_reports() {
        let config = ProxyConfig { routed: vec!["*.saas.example".parse().unwrap()], upstreams: vec![] };
        let mut proxy = DnsProxy::start(&Launcher::InProcess, "t", config).await.unwrap();
        assert_ne!(proxy.port, 0);
        // No upstream: SERVFAIL at once, nothing reported; the proxy answers.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'x', 0, 0, 1, 0, 1];
        client.send_to(&query, ("127.0.0.1", proxy.port)).await.unwrap();
        let mut buf = [0; 512];
        let len =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        assert_eq!(buf[3] & 0x0f, 2, "SERVFAIL");
        assert!(len >= 12);
        drop(proxy.out.clone());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), proxy.next()).await.is_err(), "no report");
    }
}
