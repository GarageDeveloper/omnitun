//! `omnitund`: privileged daemon that owns the tunnels. It must run as root
//! (Windows: SYSTEM or an administrator) to create tun interfaces and change
//! routes and DNS; users drive it with `omnitunctl` through a Unix socket
//! (Windows: a named pipe) restricted to one group.

mod autodisconnect;
mod dnsproxy;
mod engine;
#[cfg(unix)]
mod logfile;
mod manager;
mod prompter;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use vpn_core::ipc::{Event, PROTOCOL_VERSION, Request};
use vpn_core::{User, UserId};
use vpn_transport::{Listener, Stream};
use zeroize::Zeroize;

use crate::manager::Manager;
use crate::prompter::ClientLink;

/// Events queued for a client that does not read are capped; past that the
/// client is dropped.
const CLIENT_QUEUE: usize = 64;
/// Concurrent control connections.
const MAX_CLIENTS: usize = 32;
/// Of which one user (root aside) may hold: more than the sessions a user
/// may start at once, with their watchers, but not every slot.
const MAX_CLIENTS_PER_USER: usize = 12;

/// Requests larger than this are rejected (a profile with an inlined CA
/// bundle stays well below).
const MAX_LINE: usize = 1024 * 1024;
/// Bound on closing all sessions when stopping; below the service
/// managers' stop timeouts (`ExitTimeOut`, `TimeoutStopSec`).
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// How long a new connection may take to say hello.
const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a closing connection may take to send its last events.
const FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Parser)]
#[command(version, about = "Omnitun daemon: owns the VPN tunnels")]
struct Args {
    /// Control socket path.
    #[arg(long, default_value_t = vpn_core::ipc::socket_path())]
    socket: String,
    /// Group allowed to use the control socket.
    #[arg(long, default_value = default_group())]
    group: String,
    /// Engine binary (default: next to this one).
    #[arg(long)]
    engine: Option<std::path::PathBuf>,
    /// Unprivileged account the engines run as.
    #[arg(long, default_value = vpn_core::brand::ENGINE_USER)]
    engine_user: String,
    /// Run engines without the macOS sandbox (debugging only).
    #[arg(long)]
    no_engine_sandbox: bool,
    /// Print the engines' sandbox profile and exit.
    #[arg(long)]
    print_engine_sandbox: bool,
    /// Run although a non-root user could replace the daemon or the engine
    /// (a development build; never for an installed service).
    #[arg(long)]
    allow_writable_binaries: bool,
}

/// A program run as root, and every folder above it, must be root's and
/// writable by no one else: otherwise that user is root.
#[cfg(unix)]
fn root_only(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    use anyhow::Context;
    let path = path.canonicalize().with_context(|| format!("cannot find {}", path.display()))?;
    for p in path.ancestors() {
        let meta = std::fs::metadata(p).with_context(|| format!("cannot check {}", p.display()))?;
        // A sticky folder (/tmp) still lets others replace their own files.
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            anyhow::bail!("{} can be changed by a user other than root", p.display());
        }
    }
    Ok(())
}

/// Windows: the ACL of the program and its folders is not checked yet.
#[cfg(windows)]
fn root_only(path: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("who may change {} is not checked on Windows yet", path.display())
}

/// Created by the installer; only its members may drive the daemon.
const fn default_group() -> &'static str {
    vpn_core::brand::ID
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Whatever the daemon creates without an explicit mode is root's only.
    #[cfg(unix)]
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    // launchd and systemd collect stderr (StandardErrorPath, journal).
    // Colors only for a terminal, not in the log file.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    #[cfg(target_os = "macos")]
    if args.print_engine_sandbox {
        let engine = args.engine.clone().map_or_else(engine::default_path, Ok)?;
        print!("{}", engine::sandbox_profile(&engine));
        return Ok(());
    }
    #[cfg(unix)]
    {
        // A core dump would contain prompt answers and session keys.
        nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
        // A known ceiling on descriptor numbers: engines are started with
        // every descriptor above their own closed, up to this limit.
        let (_, hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?;
        nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, hard.min(4096), hard)?;
    }
    if !vpn_transport::current_user()?.admin {
        let who = if cfg!(windows) { "SYSTEM or an elevated administrator" } else { "root" };
        anyhow::bail!("{} must run as {who}", vpn_core::brand::DAEMON);
    }

    let engine_path = args.engine.clone().map_or_else(engine::default_path, Ok)?;
    for binary in [std::env::current_exe()?, engine_path] {
        if let Err(e) = root_only(&binary) {
            if !args.allow_writable_binaries {
                let folder = if cfg!(windows) {
                    "Program Files"
                } else if cfg!(target_os = "macos") {
                    "/Library/PrivilegedHelperTools"
                } else {
                    "/usr/local/sbin"
                };
                anyhow::bail!("{e:#}: install it in a folder only administrators can write ({folder})");
            }
            tracing::warn!("{e:#}");
        }
    }

    let sandbox = cfg!(target_os = "macos") && !args.no_engine_sandbox;
    if !sandbox {
        tracing::warn!("engines run without a sandbox");
    }
    let launcher = engine::Launcher::process(args.engine.clone(), &args.engine_user, sandbox)?;
    let mut listener = Listener::bind(&args.socket, &args.group)?;
    tracing::info!("listening on {} (group {})", args.socket, args.group);
    #[cfg(unix)]
    logfile::spawn_rotation();
    vpn_platform::prepare_runtime_dir()?;
    vpn_platform::cleanup_stale().await;
    manager::prepare_prompt_dir(&vpn_core::ipc::prompt_socket_dir(&args.socket))?;
    let manager = Arc::new(Manager::new(launcher, args.socket.clone()));
    let clients = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    let quotas = Arc::new(Quotas::default());

    let signals = stop_signals()?;
    tokio::pin!(signals);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, user)) => {
                    let Ok(permit) = clients.clone().try_acquire_owned() else {
                        tracing::warn!("too many control connections, refusing one");
                        continue;
                    };
                    let Some(slot) = quotas.take(&user) else {
                        tracing::warn!("too many control connections from {user}, refusing one");
                        continue;
                    };
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, user, manager).await {
                            tracing::debug!("client: {e:#}");
                        }
                        drop((permit, slot));
                    });
                }
                Err(e) => tracing::warn!("accept: {e}"),
            },
            () = &mut signals => break,
            _ = manager.shutdown.cancelled() => break,
        }
    }
    tracing::info!("shutting down, closing all sessions");
    manager.stopping();
    // Each engine gets a few seconds to say goodbye; past the deadline the
    // daemon exits anyway, well before launchd or systemd would kill it,
    // and the next start removes what is left.
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, manager.disconnect_all()).await.is_err() {
        tracing::warn!("sessions did not close in {SHUTDOWN_TIMEOUT:?}; leaving the rest to the next start");
    }
    drop(listener);
    Ok(())
}

/// Every catchable signal that would end the process: the tunnels are torn
/// down first (SIGKILL cannot be caught: the route journal covers it).
#[cfg(unix)]
fn stop_signals() -> anyhow::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut signals = [SignalKind::terminate(), SignalKind::interrupt(), SignalKind::hangup(), SignalKind::quit()]
        .map(signal)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(async move {
        let [term, int, hup, quit] = &mut signals[..] else { unreachable!() };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
            _ = quit.recv() => {}
        }
    })
}

/// The console's Ctrl+C, Ctrl+Break, closing and system shutdown.
#[cfg(windows)]
fn stop_signals() -> anyhow::Result<impl Future<Output = ()>> {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
    let (mut c, mut brk, mut close, mut shutdown) = (ctrl_c()?, ctrl_break()?, ctrl_close()?, ctrl_shutdown()?);
    Ok(async move {
        tokio::select! {
            _ = c.recv() => {}
            _ = brk.recv() => {}
            _ = close.recv() => {}
            _ = shutdown.recv() => {}
        }
    })
}

/// Control connections per user: one group member cannot take every slot
/// and lock the others out (connections that said hello have no idle
/// timeout: a watcher or a waiting `connect` is idle).
#[derive(Default)]
struct Quotas(Mutex<HashMap<UserId, usize>>);

/// One connection of a user, given back when dropped.
struct Slot {
    quotas: Arc<Quotas>,
    user: UserId,
}

impl Quotas {
    fn take(self: &Arc<Self>, user: &User) -> Option<Slot> {
        let mut counts = self.0.lock().unwrap();
        let count = counts.entry(user.id.clone()).or_default();
        if !user.admin && *count >= MAX_CLIENTS_PER_USER {
            return None;
        }
        *count += 1;
        Some(Slot { quotas: self.clone(), user: user.id.clone() })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.quotas.0.lock().unwrap();
        if let Some(count) = counts.get_mut(&self.user) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.user);
            }
        }
    }
}

/// Optional capabilities announced in `Hello`.
const FEATURES: &[&str] = &[
    "watch",
    "shutdown",
    "trust_certificate",
    "failure_kinds",
    "prompt_socket",
    "stopping",
    vpn_core::ipc::AUTO_DISCONNECT,
];

fn failed(e: anyhow::Error) -> Event {
    Event::Error { message: format!("{e:#}"), failure: Some(vpn_core::failure::kind_of(&e)) }
}

/// One client connection of `user`: requests in, events out.
async fn serve(stream: Stream, user: User, manager: Arc<Manager>) -> anyhow::Result<()> {
    tracing::debug!("client {user}");
    let Stream { read, mut write } = stream;
    let (events_tx, mut events_rx) = mpsc::channel::<Event>(CLIENT_QUEUE);
    let link = ClientLink::new(events_tx.clone());

    let mut writer = tokio::spawn(async move {
        while let Some(event) = events_rx.recv().await {
            let mut line = serde_json::to_vec(&event).expect("events serialize");
            line.push(b'\n');
            if write.write_all(&line).await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(read);
    // Request lines carry prompt answers: wipe them, not just truncate.
    let mut buf = zeroize::Zeroizing::new(String::new());
    let mut greeted = false;
    let mut watching = false;
    // What the client said it understands, in its hello.
    let mut client_features = Vec::new();
    loop {
        buf.zeroize();
        let mut limited = (&mut lines).take(MAX_LINE as u64);
        let read = limited.read_line(&mut buf);
        // A connection that never says hello does not hold a client slot.
        let n = if greeted {
            read.await?
        } else {
            match tokio::time::timeout(HELLO_TIMEOUT, read).await {
                Ok(n) => n?,
                Err(_) => break,
            }
        };
        if n == 0 {
            break;
        }
        if !buf.ends_with('\n') {
            link.send(Event::error("request too large"));
            break;
        }
        let request = match serde_json::from_str::<Request>(&buf) {
            Ok(r) => r,
            Err(e) => {
                link.send(Event::error(format!("bad request: {e}")));
                continue;
            }
        };
        // The version check comes first, so an outdated client or daemon
        // fails clearly instead of misreading messages.
        if !greeted {
            let Request::Hello { protocol, client, version, features } = request else {
                link.send(Event::error("the first request must be hello"));
                break;
            };
            if protocol != PROTOCOL_VERSION {
                link.send(Event::error(format!(
                    "protocol {protocol} not supported: {} {} speaks protocol {PROTOCOL_VERSION} \
                     (restart the service after an update)",
                    vpn_core::brand::DAEMON,
                    vpn_core::version()
                )));
                break;
            }
            tracing::debug!("client {user}: {client} {version} {features:?}");
            greeted = true;
            client_features = features;
            link.send(Event::Hello {
                protocol: PROTOCOL_VERSION,
                version: vpn_core::version(),
                features: FEATURES.iter().map(|f| f.to_string()).collect(),
            });
            continue;
        }
        let reply = match request {
            Request::Hello { .. } => Some(Event::error("hello was already sent")),
            Request::Connect { profile, via } => manager.connect(*profile, via, link.clone(), &user).err().map(failed),
            Request::Disconnect { id } => Some(match manager.disconnect(&id, &user).await {
                Ok(()) => Event::Done,
                Err(e) => failed(e),
            }),
            Request::Postpone { id } => Some(match manager.postpone(&id, &user) {
                Ok(()) => Event::Done,
                Err(e) => failed(e),
            }),
            Request::Status => Some(Event::Status { sessions: manager.status(&user) }),
            Request::Answer { .. } => Some(Event::error("answers go to the session's prompt socket")),
            Request::Watch if watching => Some(Event::error("this connection is already watching")),
            Request::Watch => {
                watching = true;
                let expiring = client_features.iter().any(|f| f == vpn_core::ipc::AUTO_DISCONNECT);
                manager.watch(&user, link.clone(), expiring);
                None
            }
            Request::Shutdown => Some(if manager.may_shutdown(&user) {
                tracing::info!("shutdown requested by {user}");
                manager.shutdown.cancel();
                Event::Done
            } else {
                Event::error("another user has active sessions; only an administrator may stop the service")
            }),
        };
        if let Some(event) = reply
            && !link.send(event)
        {
            tracing::debug!("client {user} is not reading its events, closing");
            break;
        }
    }
    drop(events_tx);
    drop(link);
    // Deliver what is queued (the error that ended the connection, say);
    // a session or watcher may still hold the link, so do not wait forever.
    if tokio::time::timeout(FLUSH_TIMEOUT, &mut writer).await.is_err() {
        writer.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    async fn exchange(requests: &[serde_json::Value]) -> Vec<Event> {
        let (ours, theirs) = Stream::pair();
        let server = tokio::spawn(serve(theirs, User::uid(1000), Arc::new(Manager::default())));
        let Stream { read, mut write } = ours;
        for r in requests {
            write.write_all(format!("{r}\n").as_bytes()).await.unwrap();
        }
        // Not just dropped: the read half keeps the stream open.
        write.shutdown().await.unwrap();
        let mut lines = BufReader::new(read).lines();
        let mut events = Vec::new();
        while let Ok(Ok(Some(line))) = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line()).await
        {
            events.push(serde_json::from_str(&line).unwrap());
        }
        let _ = server.await;
        events
    }

    fn hello(protocol: u32) -> serde_json::Value {
        serde_json::json!({ "request": "hello", "protocol": protocol, "client": "test", "version": "0" })
    }

    #[test]
    fn one_user_cannot_hold_every_connection() {
        let quotas = Arc::new(Quotas::default());
        let (me, them, root) = (User::uid(1000), User::uid(1001), User::uid(0));
        let mine: Vec<Slot> = (0..MAX_CLIENTS_PER_USER).map(|_| quotas.take(&me).unwrap()).collect();
        assert!(quotas.take(&me).is_none());
        let theirs = quotas.take(&them);
        assert!(theirs.is_some() && quotas.take(&root).is_some(), "other users and root still get in");
        drop(mine);
        assert!(quotas.take(&me).is_some(), "slots come back");
        drop(theirs);
        assert!(quotas.0.lock().unwrap().is_empty(), "no count left behind");
    }

    #[tokio::test]
    async fn hello_comes_first() {
        let events = exchange(&[serde_json::json!({ "request": "status" })]).await;
        assert!(matches!(&events[..], [Event::Error { message, .. }] if message.contains("hello")), "{events:?}");
    }

    #[tokio::test]
    async fn other_protocol_versions_are_refused() {
        let events = exchange(&[hello(PROTOCOL_VERSION + 1), serde_json::json!({ "request": "status" })]).await;
        assert!(
            matches!(&events[..], [Event::Error { message, .. }] if message.contains("not supported")),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn one_watch_per_connection() {
        let watch = serde_json::json!({ "request": "watch" });
        let events = exchange(&[hello(PROTOCOL_VERSION), watch.clone(), watch]).await;
        assert!(
            matches!(&events[..], [Event::Hello { .. }, Event::Status { .. }, Event::Error { message, .. }]
                if message.contains("already watching")),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn greeted_clients_are_served() {
        let events = exchange(&[hello(PROTOCOL_VERSION), serde_json::json!({ "request": "status" })]).await;
        let [Event::Hello { protocol, features, .. }, Event::Status { sessions }] = &events[..] else {
            panic!("{events:?}")
        };
        assert_eq!(*protocol, PROTOCOL_VERSION);
        assert!(features.iter().any(|f| f == "watch"));
        assert!(sessions.is_empty());
    }
}
