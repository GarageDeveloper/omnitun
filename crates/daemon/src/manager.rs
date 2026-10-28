//! Owns every session: one task per session drives its engine, tun
//! interface and network configuration, and reconnects after a drop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use vpn_core::ipc::{Event, Retry, SessionInfo, SessionState};
use vpn_core::{FailureKind, Profile, ProtocolConfig, TunnelSettings, TunnelStats, failure};
use vpn_platform::{Claims, Conflict, Registry};

use crate::engine::{Launcher, RemoteEngine};
use crate::prompter::{ClientLink, SessionClient};

const MAX_RECONNECTS: u32 = 5;
/// Sessions at once, failed ones excepted.
const MAX_SESSIONS: usize = 16;
/// Sessions one user may hold (root excepted), failed ones included.
const MAX_SESSIONS_PER_USER: usize = 8;
/// A failed session stays listed this long unless dismissed.
const FAILED_TTL: Duration = Duration::from_secs(3600);
/// Bounds on what a gateway may push.
const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 4;
/// Address space no tunnel may route.
const RESERVED: [Ipv4Net; 3] = [
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(0, 0, 0, 0), 8),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(224, 0, 0, 0), 3),
];
const MAX_DNS_DOMAINS: usize = 32;
const MIN_MTU: u16 = 576;
const MAX_MTU: u16 = 9000;
/// A tunnel that stayed up this long resets the reconnect counter.
const STABLE_UPTIME: Duration = Duration::from_secs(60);
const WATCH_QUEUE: usize = 256;
/// How long an engine's first question waits for the client to attach to
/// the prompt socket.
const ATTACH_WAIT: Duration = Duration::from_secs(10);

pub struct Manager {
    launcher: Launcher,
    /// The control socket; prompt sockets are named after it.
    control_socket: String,
    attach_wait: Duration,
    sessions: Mutex<HashMap<String, Session>>,
    registry: Mutex<Registry>,
    /// State changes, for `Watch` connections.
    events: broadcast::Sender<Watched>,
    /// Fired by an accepted `Shutdown` request.
    pub shutdown: CancellationToken,
}

impl Manager {
    pub fn new(launcher: Launcher, control_socket: String) -> Self {
        Self {
            launcher,
            control_socket,
            attach_wait: ATTACH_WAIT,
            sessions: Default::default(),
            registry: Default::default(),
            events: broadcast::channel(WATCH_QUEUE).0,
            shutdown: CancellationToken::new(),
        }
    }
}

/// Engines run in-process, on the protocol's socket pair; prompt sockets
/// go to a directory of their own.
#[cfg(test)]
impl Default for Manager {
    fn default() -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        // Short: socket paths are limited to about 100 bytes, and the
        // per-user temporary directory of macOS is long.
        let dir = std::path::Path::new("/tmp").join(format!(
            "otd-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let control = dir.join("c.sock").display().to_string();
        prepare_prompt_dir(&vpn_core::ipc::prompt_socket_dir(&control)).unwrap();
        Self::new(Launcher::InProcess, control)
    }
}

#[derive(Clone)]
struct Watched {
    owner: u32,
    event: Event,
}

/// Failures that a retry cannot fix, or that would lock the account.
fn retry_useless(kind: &FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::AuthFailed
            | FailureKind::OtpRejected
            | FailureKind::PskRejected
            | FailureKind::PermissionDenied
            | FailureKind::CertificateUntrusted { .. }
            | FailureKind::CertificateChanged { .. }
            | FailureKind::Conflict { .. }
            | FailureKind::NeedsUser
            | FailureKind::Cancelled
    )
}

struct Session {
    /// uid of the user who started it; only they (or root) may stop it.
    owner: u32,
    cancel: CancellationToken,
    info: Arc<Mutex<SessionInfo>>,
    stats: Arc<TunnelStats>,
    task: Option<JoinHandle<()>>,
}

impl Manager {
    /// Starts a session. Progress is reported to `client` until the tunnel
    /// is up (`Done`) or has failed (`Error`).
    /// `via`: a connected session of the same user that this one is
    /// chained through.
    pub fn connect(
        self: &Arc<Self>,
        profile: Profile,
        via: Option<String>,
        client: ClientLink,
        owner: u32,
    ) -> anyhow::Result<()> {
        // Sessions are keyed by the profile's id: it names their sockets
        // and resolver keys; the name is only shown.
        if !vpn_core::valid_id(&profile.id) || !vpn_platform::valid_session_name(&profile.id) {
            bail!("the profile has no valid id; update the client");
        }
        profile.validate()?;
        if let ProtocolConfig::FortiSsl(p) = &profile.protocol
            && p.has_file_paths()
        {
            bail!("certificate files must be inlined by the client, not read by the daemon");
        }
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(&profile.id) {
            // A failed session stays listed until replaced or dismissed.
            Some(s) if s.info.lock().unwrap().state == SessionState::Failed && (owner == 0 || s.owner == owner) => {
                sessions.remove(&profile.id);
            }
            Some(_) => bail!("{} is already active", profile.name),
            None => {}
        }
        // Failed sessions count only against their user's share: two users
        // cannot fill the table for a third with failures.
        let live = sessions.values().filter(|s| s.info.lock().unwrap().state != SessionState::Failed).count();
        if live >= MAX_SESSIONS {
            bail!("too many sessions (max {MAX_SESSIONS})");
        }
        if let Some(parent) = &via {
            let up = sessions.get(parent).is_some_and(|s| {
                (owner == 0 || s.owner == owner) && s.info.lock().unwrap().state == SessionState::Connected
            });
            if !up || *parent == profile.id {
                let parent = sessions.get(parent).map_or(parent.clone(), |s| s.info.lock().unwrap().name.clone());
                bail!("{parent}, which {} goes through, is not connected", profile.name);
            }
        }
        if owner != 0 && sessions.values().filter(|s| s.owner == owner).count() >= MAX_SESSIONS_PER_USER {
            bail!("too many sessions for this user (max {MAX_SESSIONS_PER_USER}); disconnect or dismiss one");
        }
        let info = Arc::new(Mutex::new(SessionInfo {
            id: profile.id.clone(),
            name: profile.name.clone(),
            protocol: profile.protocol.name().into(),
            state: SessionState::Connecting,
            interface: None,
            address: None,
            full_tunnel: false,
            routes: Vec::new(),
            dns_domains: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            connected_since: None,
            detail: None,
            failure: None,
            via: via.clone(),
            gateway: None,
            mtu: None,
            dns_servers: Vec::new(),
            excluded_routes: Vec::new(),
            up_since: None,
            reconnects: 0,
            last_drop: None,
        }));
        // The engine asks the owner's client directly, on this socket.
        let prompt_socket = vpn_core::ipc::prompt_socket_path(&self.control_socket, &profile.id);
        let (prompts, prompt_file) = prompt_listener(&prompt_socket, owner)?;
        // A client certificate's key stays with the client, which signs
        // for the engine; an older client may still send it.
        let mut profile = profile;
        if let ProtocolConfig::FortiSsl(p) = &mut profile.protocol {
            p.client_key_pem = None;
        }
        let engine = RemoteEngine::spawn(&self.launcher, &profile.name, owner, prompts.try_clone()?)
            .inspect_err(|_| remove_prompt_socket(&prompt_socket, prompt_file))
            .context("cannot start the engine")?;
        client.send(Event::Attach { socket: prompt_socket.clone() });

        let cancel = CancellationToken::new();
        let stats = Arc::new(TunnelStats::default());
        let runner = Runner {
            manager: self.clone(),
            owner,
            profile: profile.clone(),
            info: info.clone(),
            client: Arc::new(SessionClient::new(client)),
            cancel: cancel.clone(),
            stats: stats.clone(),
            prompts,
            prompt_socket,
            prompt_file,
            via,
        };
        let task = tokio::spawn(runner.run(engine));
        sessions.insert(profile.id, Session { owner, cancel, info, stats, task: Some(task) });
        Ok(())
    }

    /// Stops a session; `uid` must own it unless it is root.
    /// `id`: the session's profile id.
    pub async fn disconnect(&self, id: &str, uid: u32) -> anyhow::Result<()> {
        let task = {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get_mut(id)
                .filter(|s| uid == 0 || s.owner == uid)
                .with_context(|| format!("{id} is not active"))?;
            session.cancel.cancel();
            session.task.take()
        };
        if let Some(task) = task {
            let _ = task.await;
        }
        self.forget(id);
        Ok(())
    }

    /// Closes every session at once: the service manager kills the daemon
    /// if stopping takes too long, so teardowns must not queue up.
    pub async fn disconnect_all(&self) {
        let tasks: Vec<(String, Option<tokio::task::JoinHandle<()>>)> = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions
                .iter_mut()
                .map(|(name, session)| {
                    session.cancel.cancel();
                    (name.clone(), session.task.take())
                })
                .collect()
        };
        for (name, task) in tasks {
            if let Some(task) = task {
                let _ = task.await;
            }
            self.forget(&name);
        }
    }

    /// Sends the current sessions, then every state change of `uid`'s
    /// sessions (all of them for root), until the client goes away.
    pub fn watch(&self, uid: u32, link: ClientLink) {
        let mut rx = self.events.subscribe();
        if !link.send(Event::Status { sessions: self.status(uid) }) {
            return;
        }
        tokio::spawn(async move {
            loop {
                let watched = tokio::select! {
                    r = rx.recv() => r,
                    _ = link.closed() => return,
                };
                match watched {
                    Ok(w) if uid == 0 || w.owner == uid => {
                        if !link.send(w.event) {
                            return;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    /// A shutdown disconnects everyone: only root, or a user who owns
    /// every session, may ask for it.
    pub fn may_shutdown(&self, uid: u32) -> bool {
        uid == 0 || self.sessions.lock().unwrap().values().all(|s| s.owner == uid)
    }

    /// Sessions visible to `uid`: its own, or all of them for root.
    pub fn status(&self, uid: u32) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        let mut list: Vec<SessionInfo> = sessions
            .values()
            .filter(|s| uid == 0 || s.owner == uid)
            .map(|s| {
                let mut info = s.info.lock().unwrap().clone();
                info.rx_bytes = s.stats.rx_bytes.load(Ordering::Relaxed);
                info.tx_bytes = s.stats.tx_bytes.load(Ordering::Relaxed);
                info
            })
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        list
    }

    /// Registers a session's routes and DNS domains unless they conflict
    /// with another active session; returns the overlap warnings.
    fn reserve(&self, name: &str, claims: Claims) -> Result<Vec<String>, Conflict> {
        let mut registry = self.registry.lock().unwrap();
        let checked = registry.check(name, &claims);
        if checked.is_ok() {
            registry.insert(name, claims);
        }
        checked
    }

    fn forget(&self, name: &str) {
        self.sessions.lock().unwrap().remove(name);
    }

    /// The tunnel interface of a connected session.
    fn interface_of(&self, name: &str) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        let info = sessions.get(name)?.info.lock().unwrap();
        (info.state == SessionState::Connected).then(|| info.interface.clone()).flatten()
    }

    /// Stops the sessions chained through `name`: its tunnel is gone.
    fn stop_chained(&self, name: &str) {
        for session in self.sessions.lock().unwrap().values() {
            if session.info.lock().unwrap().via.as_deref() == Some(name) {
                tracing::info!(
                    session = session.info.lock().unwrap().name,
                    "stopped: {name}, which it goes through, went down"
                );
                session.cancel.cancel();
            }
        }
    }
}

struct Runner {
    manager: Arc<Manager>,
    owner: u32,
    profile: Profile,
    info: Arc<Mutex<SessionInfo>>,
    client: Arc<SessionClient>,
    cancel: CancellationToken,
    stats: Arc<TunnelStats>,
    /// Kept to start a new engine if the session's one dies.
    prompts: std::os::fd::OwnedFd,
    prompt_socket: String,
    prompt_file: Option<FileId>,
    /// The session this one is chained through.
    via: Option<String>,
}

/// Why a connection attempt ended.
enum Outcome {
    Cancelled,
    /// The tunnel was up and then dropped: worth reconnecting. `stable`
    /// when this attempt's tunnel had been up for `STABLE_UPTIME`.
    Dropped {
        error: anyhow::Error,
        stable: bool,
    },
    /// Never came up, or a configuration conflict: give up.
    Failed(anyhow::Error),
}

impl Runner {
    fn set_state(&self, state: SessionState, detail: Option<String>) {
        self.set_state_with(state, detail, None, None);
    }

    fn set_state_with(
        &self,
        state: SessionState,
        detail: Option<String>,
        failure: Option<FailureKind>,
        retry: Option<Retry>,
    ) {
        {
            let mut info = self.info.lock().unwrap();
            info.state = state;
            info.detail = detail.clone();
            info.failure = failure.clone();
        }
        match &detail {
            Some(d) => tracing::info!(session = self.profile.name, "{state:?}: {d}"),
            None => tracing::info!(session = self.profile.name, "{state:?}"),
        }
        let event = Event::State { id: self.profile.id.clone(), state, detail, failure, retry };
        let _ = self.manager.events.send(Watched { owner: self.owner, event: event.clone() });
        self.client.notify(event);
    }

    async fn run(self, mut engine: RemoteEngine) {
        let mut attempt = 0;
        loop {
            let first = attempt == 0 && self.info.lock().unwrap().connected_since.is_none();
            match self.attempt(&mut engine, first).await {
                Outcome::Cancelled => {
                    self.set_state(SessionState::Disconnected, None);
                    break;
                }
                Outcome::Failed(e) => {
                    let kind = failure::kind_of(&e);
                    self.set_state_with(SessionState::Failed, Some(format!("{e:#}")), Some(kind.clone()), None);
                    self.client
                        .notify(Event::Error { message: format!("{}: {e:#}", self.profile.name), failure: Some(kind) });
                    break;
                }
                Outcome::Dropped { error: e, stable } => {
                    {
                        let mut info = self.info.lock().unwrap();
                        info.reconnects += 1;
                        info.last_drop = Some((now(), format!("{e:#}")));
                    }
                    if stable {
                        attempt = 0;
                    }
                    attempt += 1;
                    let kind = failure::kind_of(&e);
                    if attempt > MAX_RECONNECTS || retry_useless(&kind) {
                        let detail = if retry_useless(&kind) {
                            format!("{e:#}")
                        } else {
                            format!("gave up reconnecting: {e:#}")
                        };
                        self.set_state_with(SessionState::Failed, Some(detail), Some(kind), None);
                        break;
                    }
                    let delay = Duration::from_secs(2u64.pow(attempt.min(5)));
                    self.set_state_with(
                        SessionState::Reconnecting,
                        Some(format!("{e:#}; retry {attempt}/{MAX_RECONNECTS} in {}s", delay.as_secs())),
                        Some(kind),
                        Some(Retry { attempt, max: MAX_RECONNECTS, delay_secs: delay.as_secs() }),
                    );
                    tokio::select! {
                        _ = self.cancel.cancelled() => {
                            self.set_state(SessionState::Disconnected, None);
                            break;
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
        self.client.detach();
        engine.kill().await;
        remove_prompt_socket(&self.prompt_socket, self.prompt_file);
        // Failed sessions stay visible, with their error, until dismissed
        // or for an hour.
        if self.info.lock().unwrap().state != SessionState::Failed {
            self.manager.forget(&self.profile.id);
        } else {
            let (manager, name, info) = (self.manager.clone(), self.profile.id.clone(), self.info.clone());
            tokio::spawn(async move {
                tokio::time::sleep(FAILED_TTL).await;
                let mut sessions = manager.sessions.lock().unwrap();
                if sessions.get(&name).is_some_and(|s| Arc::ptr_eq(&s.info, &info)) {
                    sessions.remove(&name);
                }
            });
        }
    }

    async fn attempt(&self, engine: &mut RemoteEngine, first: bool) -> Outcome {
        if !engine.is_alive() {
            tracing::warn!(session = self.profile.name, "the engine died; starting a new one");
            *engine = match self.prompts.try_clone().map_err(anyhow::Error::from).and_then(|prompts| {
                RemoteEngine::spawn(&self.manager.launcher, &self.profile.name, self.owner, prompts)
            }) {
                Ok(engine) => engine,
                Err(e) => return Outcome::Failed(e.context("cannot start the engine")),
            };
        }
        // Only the first attempt waits for the client that asked for it;
        // reconnections use remembered answers or an attached client.
        let attach_wait = if first && self.client.is_attached() { self.manager.attach_wait } else { Duration::ZERO };
        if let Err(e) = engine.start(&self.profile, attach_wait).await {
            return Outcome::Failed(e);
        }
        let connected = tokio::select! {
            _ = self.cancel.cancelled() => {
                engine.stop().await;
                return Outcome::Cancelled;
            }
            res = engine.connect(&self.stats) => res,
        };
        // The engine is untrusted: what it negotiated is checked here.
        let connected = match connected {
            Ok(settings) => check_gateway(&self.profile, settings).await,
            Err(e) => Err(e),
        };
        let settings = match connected.and_then(|s| apply_profile(&self.profile, s)) {
            Ok(s) => s,
            // A gateway that was reachable before is worth retrying.
            Err(e) if self.info.lock().unwrap().connected_since.is_some() => {
                engine.stop().await;
                return Outcome::Dropped { error: e, stable: false };
            }
            Err(e) => {
                engine.stop().await;
                return Outcome::Failed(e);
            }
        };

        match self.manager.reserve(&self.profile.id, claims(&self.profile, &settings, self.owner)) {
            Ok(mut warnings) => {
                warnings.extend(unused_dns(&settings));
                for message in warnings {
                    tracing::warn!(session = self.profile.name, "{message}");
                    self.client.notify(Event::Warning { message });
                }
            }
            Err(conflict) => {
                engine.stop().await;
                return Outcome::Failed(failure(FailureKind::Conflict { with: Some(conflict.with) }, conflict.message));
            }
        }

        let mut up_at = None;
        let outcome = self.bring_up(engine, &settings, &mut up_at).await;
        // What went through this tunnel cannot work any more.
        self.manager.stop_chained(&self.profile.id);
        let stable = up_at.is_some_and(|t: std::time::Instant| t.elapsed() >= STABLE_UPTIME);
        self.manager.registry.lock().unwrap().remove(&self.profile.id);
        engine.stop().await;
        {
            let mut info = self.info.lock().unwrap();
            info.interface = None;
        }
        // Set once the tunnel has been up, in this attempt or an earlier one.
        let was_up = self.info.lock().unwrap().connected_since.is_some();
        let fail =
            |error: anyhow::Error| if was_up { Outcome::Dropped { error, stable } } else { Outcome::Failed(error) };
        match outcome {
            _ if self.cancel.is_cancelled() => Outcome::Cancelled,
            Ok(()) => fail(anyhow::anyhow!("tunnel closed by the gateway")),
            Err(e) => fail(e),
        }
    }

    /// Creates the interface, installs routes and DNS, and lets the engine
    /// move the packets until the tunnel ends.
    async fn bring_up(
        &self,
        engine: &mut RemoteEngine,
        settings: &TunnelSettings,
        up_at: &mut Option<std::time::Instant>,
    ) -> anyhow::Result<()> {
        // A chained session reaches its gateway through the other tunnel.
        let gateway_via = match &self.via {
            Some(parent) => Some(
                self.manager
                    .interface_of(parent)
                    .with_context(|| format!("{parent}, which this VPN goes through, is not connected"))?,
            ),
            None => None,
        };
        let device = vpn_platform::create_device(settings).context("cannot create tun interface")?;
        let mut applied = vpn_platform::apply(&self.profile.id, &device.name, settings, gateway_via.as_deref()).await?;
        {
            let mut info = self.info.lock().unwrap();
            info.interface = Some(device.name.clone());
            info.address = Some(settings.address.to_string());
            info.full_tunnel = settings.full_tunnel;
            info.routes = settings.routes.iter().map(|r| r.to_string()).collect();
            info.dns_domains = settings.dns.match_domains.clone();
            info.gateway = Some(settings.gateway.to_string());
            info.mtu = Some(settings.mtu);
            info.dns_servers = settings.dns.servers.iter().map(ToString::to_string).collect();
            info.excluded_routes = settings.excluded_routes.iter().map(ToString::to_string).collect();
            info.connected_since.get_or_insert(now());
            info.up_since = Some(now());
        }
        *up_at = Some(std::time::Instant::now());
        self.set_state(SessionState::Connected, Some(format!("{} on {}", settings.address, device.name)));
        self.client.notify(Event::Done);

        let result = tokio::select! {
            _ = self.cancel.cancelled() => Ok(()),
            res = engine.run(&self.stats, &device) => res,
        };
        if self.cancel.is_cancelled() {
            self.set_state(SessionState::Disconnecting, None);
        }
        engine.stop().await;
        applied.revert().await;
        drop(device);
        result
    }
}

/// What a session will install, for conflict checks with the others.
fn claims(profile: &Profile, settings: &TunnelSettings, owner: u32) -> Claims {
    Claims {
        name: profile.name.clone(),
        owner,
        routes: settings.routes.clone(),
        excluded_routes: settings.excluded_routes.clone(),
        full_tunnel: settings.full_tunnel,
        dns_domains: settings.dns.match_domains.clone(),
        allow_overlap: profile.allow_route_overlap,
        related: profile.via.clone(),
        gateway: match settings.gateway {
            IpAddr::V4(gateway) => Some(gateway),
            IpAddr::V6(_) => None,
        },
    }
}

/// Applies the user's per-profile overrides on top of what the gateway pushed.
/// A split tunnel whose DNS servers no name goes to: without domains (none
/// pushed, none in the profile), its internal names do not resolve.
fn unused_dns(settings: &TunnelSettings) -> Option<String> {
    let dns = &settings.dns;
    let unused = !settings.full_tunnel
        && !dns.servers.is_empty()
        && dns.match_domains.is_empty()
        && dns.search_domains.is_empty();
    unused.then(|| {
        "no DNS domain goes to this VPN's DNS servers: add the domains to resolve through it (dns_domains)".to_owned()
    })
}

fn apply_profile(profile: &Profile, mut settings: TunnelSettings) -> anyhow::Result<TunnelSettings> {
    if let Some(routes) = &profile.routes {
        settings.routes = routes.clone();
        settings.full_tunnel = false;
    }
    // A pushed default route means full tunnel; installing 0.0.0.0/0 on the
    // tun would fight the physical default route.
    if settings.routes.iter().any(|r| r.prefix_len() == 0) {
        settings.routes.retain(|r| r.prefix_len() != 0);
        settings.full_tunnel = true;
    }
    if let Some(full) = profile.full_tunnel {
        settings.full_tunnel = full;
    }
    // This host (0/8, loopback) and multicast or reserved space (224/3)
    // are never another network's to route (a wider route, as 0/1, may
    // span them).
    for routes in [&mut settings.routes, &mut settings.excluded_routes] {
        routes.retain(|r| {
            let local = RESERVED.iter().any(|x| x.contains(r));
            if local {
                tracing::warn!("ignoring route {r} from the gateway: reserved address space");
            }
            !local
        });
    }
    let address = settings.address;
    if RESERVED.iter().any(|x| x.contains(&address))
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local()
        || IpAddr::V4(address) == settings.gateway
    {
        bail!("the gateway assigned an unusable tunnel address {address}");
    }
    if !(MIN_MTU..=MAX_MTU).contains(&settings.mtu) {
        bail!("the gateway asked for an MTU of {} (accepted: {MIN_MTU}-{MAX_MTU})", settings.mtu);
    }
    if settings.routes.len() > MAX_ROUTES || settings.excluded_routes.len() > MAX_ROUTES {
        bail!("the gateway pushed more than {MAX_ROUTES} routes; set `routes` in the profile");
    }
    if settings.dns.domains().count() > MAX_DNS_DOMAINS {
        bail!("the gateway pushed more than {MAX_DNS_DOMAINS} DNS domains");
    }
    if let Some(bad) = settings.dns.domains().find(|d| !vpn_core::valid_domain(d)) {
        bail!("refusing invalid DNS domain {bad:?}");
    }
    // A gateway may not take over names everyone uses (a top-level domain,
    // `local`): domains it pushes need two labels. The profile's own domains
    // are the user's choice and may be single labels.
    for domains in [&mut settings.dns.search_domains, &mut settings.dns.match_domains] {
        domains.retain(|d| {
            let keep = pushed_domain_acceptable(d);
            if !keep {
                tracing::warn!("ignoring DNS domain {d:?} pushed by the gateway");
            }
            keep
        });
    }
    settings.dns.servers.retain(|server| {
        let keep = match server {
            IpAddr::V4(v4) => {
                !(v4.is_unspecified()
                    || v4.is_loopback()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_link_local())
            }
            // No IPv6 inside the tunnels yet: such a server would be reached outside.
            IpAddr::V6(_) => false,
        };
        if !keep {
            tracing::warn!("ignoring DNS server {server} pushed by the gateway");
        }
        keep
    });
    if settings.dns.servers.len() > MAX_DNS_SERVERS {
        tracing::warn!("keeping the first {MAX_DNS_SERVERS} of {} DNS servers", settings.dns.servers.len());
        settings.dns.servers.truncate(MAX_DNS_SERVERS);
    }
    if !settings.full_tunnel && settings.routes.is_empty() {
        bail!("the gateway pushed no routes; set `routes` or `full_tunnel = true` in the profile");
    }
    // The tunnel's DNS servers are reached through the tunnel, never in
    // clear: a server outside the routes gets a host route of its own.
    if !settings.full_tunnel {
        for server in &settings.dns.servers {
            if let IpAddr::V4(v4) = server
                && !settings.routes.iter().any(|r| r.contains(v4))
            {
                settings.routes.push(Ipv4Net::from(*v4));
            }
        }
    }
    for domain in &profile.dns_domains {
        if !vpn_core::valid_domain(domain) {
            bail!("refusing invalid DNS domain {domain:?} in the profile");
        }
        if !settings.dns.match_domains.contains(domain) {
            settings.dns.match_domains.push(domain.clone());
        }
    }
    Ok(settings)
}

/// Domains a gateway may push: at least two labels, and not a whole
/// special-use namespace.
fn pushed_domain_acceptable(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domain.split('.').filter(|l| !l.is_empty()).count() >= 2
        && !["in-addr.arpa", "ip6.arpa", "home.arpa"].contains(&domain.as_str())
}

/// The gateway the engine reports gets a host route through the physical
/// interface: it must be the profile's server, not any address the engine
/// would like to take out of the tunnels.
async fn check_gateway(profile: &Profile, settings: TunnelSettings) -> anyhow::Result<TunnelSettings> {
    let (host, port) = profile.protocol.endpoint();
    let addresses: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("cannot resolve {host} to check the gateway"))?
            .map(|a| a.ip())
            .collect(),
    };
    if !addresses.contains(&settings.gateway) {
        bail!("the engine reported gateway {} which is not an address of {host}", settings.gateway);
    }
    Ok(settings)
}

/// Creates (or checks) the directory of the prompt sockets: a real
/// directory owned by this process's user (root) and writable by nobody
/// else, which nobody else may list either (the socket names are the
/// sessions'); stale sockets of a previous run are removed.
pub fn prepare_prompt_dir(dir: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o711).create(dir).with_context(|| format!("cannot create {dir}"))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))?;
        }
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {dir}")),
        Ok(meta) => {
            let me = nix::unistd::geteuid().as_raw();
            if !meta.file_type().is_dir() || meta.uid() != me || meta.mode() & 0o022 != 0 {
                bail!("{dir} must be a directory owned by uid {me} and writable by nobody else; remove it");
            }
            // Listable by everyone in earlier versions.
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))?;
        }
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        if entry.file_name().to_string_lossy().ends_with(".sock") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// A socket file, as created: removed only if still the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

fn file_id(path: &str) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| FileId { dev: m.dev(), ino: m.ino() })
}

/// Removes the session's prompt socket unless it was replaced since (a new
/// session of the same name owns it then).
fn remove_prompt_socket(path: &str, created: Option<FileId>) {
    if created.is_some() && file_id(path) == created {
        let _ = std::fs::remove_file(path);
    }
}

/// The session's prompt socket: only its owner (and root) may connect. The
/// mode is set right after creation (a umask is process-wide); in between,
/// the engine still refuses any other user's client. Nothing here follows
/// a symbolic link.
fn prompt_listener(path: &str, owner: u32) -> anyhow::Result<(std::os::fd::OwnedFd, Option<FileId>)> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).with_context(|| format!("cannot create {path}"))?;
    if nix::unistd::geteuid().is_root() {
        std::os::unix::fs::lchown(path, Some(owner), None)?;
    }
    nix::sys::stat::fchmodat(
        nix::fcntl::AT_FDCWD,
        path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
        nix::sys::stat::FchmodatFlags::NoFollowSymlink,
    )?;
    Ok((listener.into(), file_id(path)))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use vpn_core::DnsSettings;

    use super::*;

    fn profile(extra: serde_json::Value) -> Profile {
        let mut v = serde_json::json!({
            "name": "paris",
            "protocol": "forti-ssl",
            "host": "127.0.0.1",
            "port": 1,
            "username": "alice",
        });
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let mut p: Profile = serde_json::from_value(v).unwrap();
        if p.id.is_empty() {
            p.id = test_id(&p.name);
        }
        p
    }

    /// A stable id for the test profile or session `name`.
    fn test_id(name: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut h);
        format!("00000000-0000-4000-8000-{:012x}", h.finish() & 0xffff_ffff_ffff)
    }

    fn settings(routes: &[&str], full_tunnel: bool, domains: &[&str]) -> TunnelSettings {
        TunnelSettings {
            address: Ipv4Addr::new(10, 0, 0, 2),
            mtu: 1354,
            routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            excluded_routes: vec![],
            full_tunnel,
            dns: DnsSettings {
                servers: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
                search_domains: domains.iter().map(|d| d.to_string()).collect(),
                match_domains: domains.iter().map(|d| d.to_string()).collect(),
            },
            gateway: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        }
    }

    fn client() -> (ClientLink, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel(64);
        (ClientLink::new(tx), rx)
    }

    /// Registers a session without running anything.
    fn fake_session(m: &Manager, name: &str, owner: u32) -> CancellationToken {
        let cancel = CancellationToken::new();
        let info = SessionInfo {
            id: test_id(name),
            name: name.into(),
            protocol: "forti-ssl".into(),
            state: SessionState::Connected,
            interface: None,
            via: None,
            address: None,
            full_tunnel: false,
            routes: vec![],
            dns_domains: vec![],
            rx_bytes: 0,
            tx_bytes: 0,
            connected_since: None,
            detail: None,
            failure: None,
            gateway: None,
            mtu: None,
            dns_servers: vec![],
            excluded_routes: vec![],
            up_since: None,
            reconnects: 0,
            last_drop: None,
        };
        let stats = Arc::new(TunnelStats::default());
        stats.record_rx(100);
        stats.record_tx(40);
        m.sessions.lock().unwrap().insert(
            test_id(name),
            Session { owner, cancel: cancel.clone(), info: Arc::new(Mutex::new(info)), stats, task: None },
        );
        cancel
    }

    /// The next event, past the prompt socket announcement.
    async fn next_event(rx: &mut mpsc::Receiver<Event>) -> Event {
        loop {
            match timeout(Duration::from_secs(10), rx.recv()).await.expect("no event").expect("channel closed") {
                Event::Attach { .. } => {}
                event => return event,
            }
        }
    }

    /// A client on the session's prompt socket, as the app or CLI would be.
    struct PromptClient(tokio::io::Lines<tokio::io::BufReader<tokio::net::UnixStream>>);

    impl PromptClient {
        async fn attach(rx: &mut mpsc::Receiver<Event>) -> Self {
            use tokio::io::AsyncBufReadExt;
            let Some(Event::Attach { socket }) = timeout(Duration::from_secs(5), rx.recv()).await.unwrap() else {
                panic!("expected the prompt socket first")
            };
            let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
            Self(tokio::io::BufReader::new(stream).lines())
        }

        async fn next(&mut self) -> Event {
            let line = timeout(Duration::from_secs(10), self.0.next_line()).await.unwrap().unwrap().unwrap();
            serde_json::from_str(&line).unwrap()
        }
    }

    fn closed_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn watchers_see_only_their_sessions() {
        let m = Arc::new(Manager::default());
        let (mine, mut mine_rx) = client();
        let (theirs, mut theirs_rx) = client();
        m.watch(1000, mine);
        m.watch(1001, theirs);
        assert!(matches!(next_event(&mut mine_rx).await, Event::Status { sessions } if sessions.is_empty()));
        assert!(matches!(next_event(&mut theirs_rx).await, Event::Status { .. }));

        let (link, _rx) = client();
        m.connect(profile(serde_json::json!({ "port": closed_port() })), None, link, 1000).unwrap();
        let Event::State { id, state, failure, .. } = next_event(&mut mine_rx).await else {
            panic!("expected a state")
        };
        assert_eq!((id, state, failure), (test_id("paris"), SessionState::Failed, Some(FailureKind::Unreachable)));
        assert!(timeout(Duration::from_millis(200), theirs_rx.recv()).await.is_err(), "another user's session leaked");
    }

    #[test]
    fn the_prompt_directory_must_be_private_to_root() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("omnitund-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("p");
        let dir_str = dir.to_str().unwrap();
        prepare_prompt_dir(dir_str).unwrap();
        std::fs::write(dir.join("old.sock"), b"").unwrap();
        prepare_prompt_dir(dir_str).unwrap();
        assert!(!dir.join("old.sock").exists(), "stale sockets are removed");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_prompt_dir(dir_str).is_err(), "writable by others");
        std::fs::remove_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&base, &dir).unwrap();
        assert!(prepare_prompt_dir(dir_str).is_err(), "a symbolic link");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A chain goes through a connected session of the same user only.
    #[tokio::test]
    async fn chained_through_a_connected_session_only() {
        let m = Arc::new(Manager::default());
        let (link, _rx) = client();
        let profile = || profile(serde_json::json!({ "port": closed_port() }));
        let err = m.connect(profile(), Some(test_id("eu")), link, 1000).unwrap_err();
        assert!(
            err.to_string().contains(&format!("{}, which paris goes through, is not connected", test_id("eu"))),
            "{err}"
        );
        fake_session(&m, "eu", 1001);
        let (link, _rx) = client();
        assert!(m.connect(profile(), Some(test_id("eu")), link, 1000).is_err(), "another user's session");
        fake_session(&m, "mine", 1000);
        let (link, _rx) = client();
        assert!(m.connect(profile(), Some(test_id("mine")), link, 1000).is_ok());
    }

    #[tokio::test]
    async fn one_user_cannot_take_every_slot() {
        let m = Arc::new(Manager::default());
        for i in 0..MAX_SESSIONS_PER_USER {
            fake_session(&m, &format!("s{i}"), 1000);
        }
        let (link, _rx) = client();
        let err = m.connect(profile(serde_json::json!({ "port": closed_port() })), None, link, 1000).unwrap_err();
        assert!(err.to_string().contains("too many sessions for this user"), "{err}");
        let (link, _rx) = client();
        assert!(m.connect(profile(serde_json::json!({ "port": closed_port() })), None, link, 1001).is_ok());
    }

    #[tokio::test]
    async fn only_root_or_the_sole_owner_may_shut_down() {
        let m = Manager::default();
        assert!(m.may_shutdown(1000), "nothing to lose");
        fake_session(&m, "a", 1000);
        assert!(m.may_shutdown(1000));
        fake_session(&m, "b", 1001);
        assert!(!m.may_shutdown(1000), "would cut another user's tunnel");
        assert!(m.may_shutdown(0));
    }

    #[test]
    fn credential_failures_are_not_retried() {
        assert!(retry_useless(&FailureKind::PskRejected));
        assert!(retry_useless(&FailureKind::AuthFailed));
        assert!(!retry_useless(&FailureKind::Unreachable));
        assert!(!retry_useless(&FailureKind::Other));
    }

    // --- apply_profile -----------------------------------------------------

    #[test]
    fn reserved_routes_are_ignored() {
        let mut s = settings(&["127.0.0.0/24", "224.0.0.0/4", "0.0.0.0/1", "10.0.0.0/8"], false, &[]);
        s.excluded_routes = vec!["240.0.0.0/8".parse().unwrap()];
        let s = apply_profile(&profile(serde_json::json!({})), s).unwrap();
        assert_eq!(s.routes.iter().map(ToString::to_string).collect::<Vec<_>>(), ["0.0.0.0/1", "10.0.0.0/8"]);
        assert!(s.excluded_routes.is_empty());
        let mut s = settings(&[], false, &[]);
        s.address = "240.0.0.1".parse().unwrap();
        assert!(apply_profile(&profile(serde_json::json!({})), s).is_err());
    }

    #[test]
    fn profile_routes_replace_pushed_ones_and_disable_full_tunnel() {
        let p = profile(serde_json::json!({ "routes": ["10.50.0.0/16"] }));
        let s = apply_profile(&p, settings(&[], true, &[])).unwrap();
        // The pushed DNS server (10.0.0.53) stays reachable through the tunnel.
        assert_eq!(s.routes.iter().map(ToString::to_string).collect::<Vec<_>>(), vec!["10.50.0.0/16", "10.0.0.53/32"]);
        assert!(!s.full_tunnel);
    }

    #[test]
    fn dns_pushed_by_the_gateway_is_kept_in_its_lane() {
        // No top-level domain or special namespace from the gateway...
        let mut s = settings(&["10.0.0.0/8"], false, &["corp.example", "com", "local", "in-addr.arpa"]);
        s.dns.servers.extend([IpAddr::V4(Ipv4Addr::LOCALHOST), "2001:db8::1".parse().unwrap()]);
        let s = apply_profile(&profile(serde_json::json!({})), s).unwrap();
        assert_eq!(s.dns.match_domains, ["corp.example"]);
        assert_eq!(s.dns.search_domains, ["corp.example"]);
        assert_eq!(s.dns.servers, [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))], "no loopback or IPv6 server");
        // ... but the user may name a single-label domain in the profile.
        let p = profile(serde_json::json!({ "dns_domains": ["corp"] }));
        assert!(
            apply_profile(&p, settings(&["10.0.0.0/8"], false, &[]))
                .unwrap()
                .dns
                .match_domains
                .contains(&"corp".into())
        );
    }

    #[test]
    fn mtu_and_address_are_bounded() {
        for mtu in [0, 100, 65000] {
            let mut s = settings(&["10.0.0.0/8"], false, &[]);
            s.mtu = mtu;
            assert!(apply_profile(&profile(serde_json::json!({})), s).is_err(), "mtu {mtu}");
        }
        let mut s = settings(&["10.0.0.0/8"], false, &[]);
        s.address = Ipv4Addr::new(169, 254, 3, 4);
        assert!(apply_profile(&profile(serde_json::json!({})), s).is_err());
    }

    #[tokio::test]
    async fn the_gateway_must_be_the_profile_server() {
        let p = profile(serde_json::json!({ "host": "203.0.113.1" }));
        assert!(check_gateway(&p, settings(&["10.0.0.0/8"], false, &[])).await.is_ok());
        let mut s = settings(&["10.0.0.0/8"], false, &[]);
        s.gateway = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let err = check_gateway(&p, s).await.unwrap_err();
        assert!(err.to_string().contains("not an address of 203.0.113.1"), "{err}");
    }

    #[test]
    fn full_tunnel_override() {
        let forced =
            apply_profile(&profile(serde_json::json!({ "full_tunnel": true })), settings(&["10.0.0.0/8"], false, &[]));
        assert!(forced.unwrap().full_tunnel);
        // Refusing full tunnel needs routes from somewhere.
        let err =
            apply_profile(&profile(serde_json::json!({ "full_tunnel": false })), settings(&[], true, &[])).unwrap_err();
        assert!(err.to_string().contains("pushed no routes"), "{err}");
        let both = profile(serde_json::json!({ "full_tunnel": true, "routes": ["10.1.0.0/16"] }));
        let s = apply_profile(&both, settings(&[], false, &[])).unwrap();
        assert!(s.full_tunnel && s.routes.len() == 1);
        // Gateway's choice kept when the profile says nothing.
        assert!(apply_profile(&profile(serde_json::json!({})), settings(&[], true, &[])).unwrap().full_tunnel);
        assert!(apply_profile(&profile(serde_json::json!({})), settings(&[], false, &[])).is_err());
    }

    #[test]
    fn split_mode_overrides_a_full_tunnel() {
        let p = profile(serde_json::json!({ "full_tunnel": true, "split_routes": ["10.1.0.0/16", "192.168.5.0/24"] }));
        let split = p.clone().in_split_mode().unwrap();
        // The gateway takes all traffic, or pushes its own networks: only
        // the split-mode networks remain.
        for pushed in [settings(&[], true, &[]), settings(&["10.0.0.0/8"], false, &[])] {
            let s = apply_profile(&split, pushed).unwrap();
            assert!(!s.full_tunnel);
            assert!(s.routes.starts_with(&["10.1.0.0/16".parse().unwrap(), "192.168.5.0/24".parse().unwrap()]));
            assert!(!s.routes.contains(&"10.0.0.0/8".parse().unwrap()));
        }
        assert!(apply_profile(&p, settings(&[], true, &[])).unwrap().full_tunnel, "normal connection unchanged");
    }

    #[test]
    fn unused_dns_servers_are_reported() {
        let split = apply_profile(&profile(serde_json::json!({})), settings(&["10.0.0.0/8"], false, &[])).unwrap();
        assert!(!split.dns.servers.is_empty(), "{split:?}");
        assert!(unused_dns(&split).is_some());
        let named = profile(serde_json::json!({ "dns_domains": ["corp.example"] }));
        assert!(unused_dns(&apply_profile(&named, settings(&["10.0.0.0/8"], false, &[])).unwrap()).is_none());
        assert!(
            unused_dns(&apply_profile(&profile(serde_json::json!({})), settings(&[], true, &[])).unwrap()).is_none()
        );
    }

    #[test]
    fn extra_dns_domains_are_merged_once() {
        let p = profile(serde_json::json!({ "dns_domains": ["corp.example", "extra.example", "extra.example"] }));
        let s = apply_profile(&p, settings(&["10.0.0.0/8"], false, &["corp.example"])).unwrap();
        assert_eq!(s.dns.match_domains, vec!["corp.example", "extra.example"]);
        assert_eq!(s.dns.search_domains, vec!["corp.example"], "search domains are the gateway's");
    }

    #[test]
    fn invalid_dns_domains_are_refused() {
        // From the gateway (search or match) ...
        let mut bad = settings(&["10.0.0.0/8"], false, &[]);
        bad.dns.search_domains = vec!["corp.example\nnameserver 6.6.6.6".into()];
        assert!(
            apply_profile(&profile(serde_json::json!({})), bad).unwrap_err().to_string().contains("invalid DNS domain")
        );
        let err =
            apply_profile(&profile(serde_json::json!({})), settings(&["10.0.0.0/8"], false, &["a;b"])).unwrap_err();
        assert!(err.to_string().contains("\"a;b\""), "{err}");
        // ... or from the profile.
        let p = profile(serde_json::json!({ "dns_domains": ["../etc"] }));
        assert!(apply_profile(&p, settings(&["10.0.0.0/8"], false, &[])).is_err());
    }

    #[test]
    fn claims_use_match_domains_and_overlap_flag() {
        let mut s = settings(&["10.0.0.0/8"], false, &["corp.example"]);
        s.dns.search_domains.push("search-only.example".into());
        s.excluded_routes = vec!["10.9.0.0/16".parse().unwrap()];
        let c = claims(&profile(serde_json::json!({ "allow_route_overlap": true })), &s, 501);
        assert_eq!(c.dns_domains, vec!["corp.example"]);
        assert_eq!(c.excluded_routes, s.excluded_routes);
        assert!(c.allow_overlap && !c.full_tunnel);
    }

    #[test]
    fn reserve_refuses_conflicts_without_registering_them() {
        let m = Manager::default();
        let p = profile(serde_json::json!({}));
        assert!(
            m.reserve("a", claims(&p, &settings(&["10.0.0.0/8"], false, &["corp.example"]), 501)).unwrap().is_empty()
        );
        let err = m.reserve("b", claims(&p, &settings(&["10.1.0.0/16"], false, &[]), 501)).unwrap_err();
        assert!(err.message.contains("overlaps"), "{err}");
        let err = m.reserve("b", claims(&p, &settings(&["172.16.0.0/12"], false, &["corp.example"]), 501)).unwrap_err();
        assert!(err.message.contains("corp.example") && err.with == "a", "{err}");
        // A refused session left no claims behind: a third one may use them.
        assert!(m.reserve("c", claims(&p, &settings(&["172.16.0.0/12"], false, &[]), 501)).is_ok());
        // Overlap accepted with the flag, as a warning.
        let lenient = profile(serde_json::json!({ "allow_route_overlap": true }));
        let warnings = m.reserve("d", claims(&lenient, &settings(&["10.2.0.0/16"], false, &[]), 501)).unwrap();
        assert_eq!(warnings.len(), 1);
        // Releasing a session frees its routes.
        assert!(m.reserve("b", claims(&p, &settings(&["10.1.0.0/16"], false, &[]), 501)).is_err());
        m.registry.lock().unwrap().remove("a");
        assert!(m.reserve("b", claims(&p, &settings(&["10.1.0.0/16"], false, &["corp.example"]), 501)).is_ok());
        // Re-checking a session against itself is not a conflict.
        assert!(m.reserve("b", claims(&p, &settings(&["10.1.0.0/16"], false, &["corp.example"]), 501)).is_ok());
    }

    // --- connect / disconnect / status -------------------------------------

    #[tokio::test]
    async fn connect_validates_names_and_file_paths() {
        let m = Arc::new(Manager::default());
        for name in ["", " lead", "../etc", "tab\tname", &"n".repeat(65)] {
            let (link, _rx) = client();
            let err = m.connect(profile(serde_json::json!({ "name": name })), None, link, 1000).unwrap_err();
            assert!(err.to_string().contains("profile names are"), "{name:?}: {err}");
        }
        // Sessions are keyed by the id: one that could escape a path is refused.
        for id in ["../../etc/passwd", "PARIS", "x"] {
            let (link, _rx) = client();
            let err = m.connect(profile(serde_json::json!({ "id": id })), None, link, 1000).unwrap_err();
            assert!(err.to_string().contains("no valid id"), "{id:?}: {err}");
        }
        let (link, _rx) = client();
        let p = profile(serde_json::json!({ "ca_file": "/etc/master.passwd" }));
        assert!(m.connect(p, None, link, 1000).unwrap_err().to_string().contains("must be inlined"));
        assert!(m.sessions.lock().unwrap().is_empty(), "nothing started");
    }

    #[tokio::test]
    async fn connect_refuses_duplicates_and_too_many_sessions() {
        let m = Arc::new(Manager::default());
        fake_session(&m, "paris", 1000);
        let (link, _rx) = client();
        let err = m.connect(profile(serde_json::json!({})), None, link, 1000).unwrap_err();
        assert!(err.to_string().contains("paris is already active"), "{err}");
        for i in 1..MAX_SESSIONS {
            fake_session(&m, &format!("s{i}"), 1000);
        }
        let (link, _rx) = client();
        let err = m.connect(profile(serde_json::json!({ "name": "one-more" })), None, link, 1000).unwrap_err();
        assert!(err.to_string().contains("too many sessions"), "{err}");
    }

    #[tokio::test]
    async fn only_owner_or_root_can_disconnect_and_see_sessions() {
        let m = Manager::default();
        let alice = fake_session(&m, "alice-vpn", 1000);
        let bob = fake_session(&m, "bob-vpn", 1001);

        let err = m.disconnect(&test_id("alice-vpn"), 1001).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} is not active", test_id("alice-vpn")),
            "no hint that the session exists"
        );
        assert!(!alice.is_cancelled());
        assert!(m.disconnect(&test_id("nope"), 0).await.is_err());

        let names = |uid| m.status(uid).into_iter().map(|s| s.name).collect::<Vec<_>>();
        assert_eq!(names(1000), vec!["alice-vpn"]);
        assert_eq!(names(1001), vec!["bob-vpn"]);
        assert_eq!(names(0), vec!["alice-vpn", "bob-vpn"]);
        assert!(names(1002).is_empty());
        let s = &m.status(1000)[0];
        assert_eq!((s.rx_bytes, s.tx_bytes), (100, 40), "live counters are reported");

        m.disconnect(&test_id("alice-vpn"), 1000).await.unwrap();
        assert!(alice.is_cancelled());
        m.disconnect(&test_id("bob-vpn"), 0).await.unwrap();
        assert!(bob.is_cancelled());
        assert!(names(0).is_empty());
    }

    #[tokio::test]
    async fn disconnect_all_cancels_everything() {
        let m = Manager::default();
        let tokens = [fake_session(&m, "a", 1000), fake_session(&m, "b", 1001)];
        m.disconnect_all().await;
        assert!(tokens.iter().all(CancellationToken::is_cancelled));
    }

    /// Full session task without tun: the gateway is unreachable, so the
    /// session fails before asking for any secret, reports it and is
    /// forgotten.
    #[tokio::test]
    async fn failed_session_reports_and_cleans_up() {
        let m = Arc::new(Manager::default());
        let (link, mut rx) = client();
        let port = closed_port();
        m.connect(profile(serde_json::json!({ "port": port })), None, link.clone(), 1000).unwrap();
        assert_eq!(m.status(1000)[0].state, SessionState::Connecting);

        let Event::State { id, state, detail, failure, .. } = next_event(&mut rx).await else {
            panic!("expected a state, no prompt")
        };
        assert_eq!((id, state), (test_id("paris"), SessionState::Failed));
        assert!(detail.unwrap().contains("cannot reach gateway"));
        assert_eq!(failure, Some(FailureKind::Unreachable));
        let Event::Error { message, failure } = next_event(&mut rx).await else { panic!("expected an error") };
        assert!(message.starts_with("paris: "), "{message}");
        assert_eq!(failure, Some(FailureKind::Unreachable));

        // The failed session stays listed with its error, holding no claims.
        let listed = m.status(1000);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, SessionState::Failed);
        assert!(listed[0].detail.as_deref().unwrap().contains("cannot reach gateway"));
        assert!(m.reserve("other", Claims { full_tunnel: true, ..Default::default() }).is_ok(), "no claims left");
        // Another user cannot replace it; its owner can, and disconnecting dismisses it.
        let (link, _rx) = client();
        assert!(m.connect(profile(serde_json::json!({ "port": port })), None, link, 1001).is_err());
        let (link, mut rx) = client();
        m.connect(profile(serde_json::json!({ "port": port })), None, link, 1000).unwrap();
        let _ = next_event(&mut rx).await;
        m.disconnect(&test_id("paris"), 1000).await.unwrap();
        assert!(m.status(0).is_empty());
    }

    /// An IPsec profile asks for its pre-shared key before any network I/O.
    fn prompting_profile() -> Profile {
        profile(serde_json::json!({ "protocol": "ipsec", "gateway": "127.0.0.1", "port": closed_port() }))
    }

    #[tokio::test]
    async fn disconnect_while_prompting() {
        let m = Arc::new(Manager::default());
        let (link, mut rx) = client();
        m.connect(prompting_profile(), None, link, 1000).unwrap();
        let mut prompts = PromptClient::attach(&mut rx).await;
        assert!(matches!(prompts.next().await, Event::Prompt { .. }));

        assert!(m.disconnect(&test_id("paris"), 1001).await.is_err());
        timeout(Duration::from_secs(5), m.disconnect(&test_id("paris"), 1000)).await.unwrap().unwrap();
        assert!(m.status(0).is_empty(), "disconnect waits for the session to end");
        let Event::State { state, .. } = next_event(&mut rx).await else { panic!("expected a state") };
        assert_eq!(state, SessionState::Disconnected);
    }

    /// The answer goes from the client to the engine on the prompt socket
    /// (here a cancellation, which the engine reports as such).
    #[tokio::test]
    async fn answers_reach_the_engine_directly() {
        use tokio::io::AsyncWriteExt;
        let m = Arc::new(Manager::default());
        let (link, mut rx) = client();
        m.connect(prompting_profile(), None, link, 1000).unwrap();
        let Some(Event::Attach { socket }) = timeout(Duration::from_secs(5), rx.recv()).await.unwrap() else {
            panic!("expected the prompt socket first")
        };
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(read));
        let line = timeout(Duration::from_secs(10), lines.next_line()).await.unwrap().unwrap().unwrap();
        let Event::Prompt { id, prompt } = serde_json::from_str(&line).unwrap() else { panic!("expected a prompt") };
        assert_eq!(prompt.key, "psk");
        let answer = serde_json::to_string(&vpn_core::ipc::Request::Answer { id, value: None }).unwrap();
        write.write_all(format!("{answer}\n").as_bytes()).await.unwrap();

        let Event::State { state, failure, .. } = next_event(&mut rx).await else { panic!("expected a state") };
        assert_eq!((state, failure), (SessionState::Failed, Some(FailureKind::Cancelled)));
    }

    #[tokio::test]
    async fn stopping_closes_every_session() {
        let m = Arc::new(Manager::default());
        let mut clients = Vec::new();
        for name in ["paris", "lyon", "lille"] {
            let (link, mut rx) = client();
            let gateway =
                serde_json::json!({ "name": name, "protocol": "ipsec", "gateway": "127.0.0.1", "port": closed_port() });
            m.connect(profile(gateway), None, link, 1000 + clients.len() as u32).unwrap();
            let mut prompts = PromptClient::attach(&mut rx).await;
            assert!(matches!(prompts.next().await, Event::Prompt { .. }));
            clients.push((rx, prompts));
        }
        timeout(Duration::from_secs(5), m.disconnect_all()).await.expect("stopping hangs");
        assert!(m.status(0).is_empty());
    }

    /// omnitunctl killed while the password prompt is shown: the session ends
    /// within seconds (it used to sit in Connecting for the 5-minute answer
    /// timeout, blocking the name).
    #[tokio::test]
    async fn session_fails_when_client_leaves_during_prompt() {
        let m = Arc::new(Manager::default());
        let (link, mut rx) = client();
        m.connect(prompting_profile(), None, link, 1000).unwrap();
        let mut prompts = PromptClient::attach(&mut rx).await;
        assert!(matches!(prompts.next().await, Event::Prompt { .. }));
        drop(prompts);
        timeout(Duration::from_secs(2), async {
            while m.status(0)[0].state != SessionState::Failed {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session kept waiting for a omnitunctl that is gone");
    }

    #[tokio::test]
    async fn session_fails_when_client_left_before_prompt() {
        let m = Arc::new(Manager::default());
        let (link, rx) = client();
        drop(rx);
        m.connect(profile(serde_json::json!({ "port": closed_port() })), None, link, 1000).unwrap();
        timeout(Duration::from_secs(5), async {
            while m.status(0)[0].state != SessionState::Failed {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session without client should fail, not wait");
    }

    #[test]
    fn pushed_settings_are_sanity_checked() {
        let profile = profile(serde_json::json!({}));
        let mut s = settings(&["10.0.0.0/8"], false, &[]);
        s.routes.push("0.0.0.0/0".parse().unwrap());
        let s = apply_profile(&profile, s).unwrap();
        assert!(s.full_tunnel);
        assert!(s.routes.iter().all(|r| r.prefix_len() != 0));

        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            let mut s = settings(&["10.0.0.0/8"], false, &[]);
            s.address = bad.parse().unwrap();
            assert!(apply_profile(&profile, s).is_err(), "{bad}");
        }

        let mut s = settings(&["10.0.0.0/8"], false, &[]);
        s.dns.servers = (1..=10).map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))).collect();
        assert_eq!(apply_profile(&profile, s).unwrap().dns.servers.len(), MAX_DNS_SERVERS);

        let mut s = settings(&["10.0.0.0/8"], false, &[]);
        s.routes = (0..=MAX_ROUTES as u32)
            .map(|i| ipnet::Ipv4Net::new(Ipv4Addr::from(0x0a00_0000 + (i << 8)), 24).unwrap())
            .collect();
        assert!(apply_profile(&profile, s).is_err());
    }
}
