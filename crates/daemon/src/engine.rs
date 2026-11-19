//! The daemon's side of an engine process: starts it unprivileged and
//! sandboxed for one session, starts its attempts, hands it the tun
//! interface, and treats everything it says as untrusted. The user's
//! answers go to the engine directly, on the session's prompt socket.
//!
//! On Windows, where neither an interface nor a listening socket can be
//! handed over, the daemon relays the interface's packets on a pipe, and
//! accepts the owner's prompt clients itself to hand each connection over
//! (the answers still go to the engine only).

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use vpn_core::engine_ipc::{EngineError, FromEngine, ToEngine};
use vpn_core::{FailureKind, Profile, TunnelSettings, TunnelStats, User, failure};
use vpn_platform::TunDevice;
use zeroize::Zeroizing;

/// Longest message accepted from an engine (settings with every route fit
/// in a few kilobytes).
const MAX_ENGINE_LINE: u64 = 64 * 1024;
/// Engine log lines relayed per second; the rest is dropped.
const LOG_LINES_PER_SECOND: u32 = 50;
const MAX_LOG_LINE: u64 = 2048;

/// How long an engine may take to log out once asked to stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(6);

/// The session's listening prompt socket, handed to its engine.
#[cfg(unix)]
pub type Prompts = OwnedFd;

/// The session's prompt pipe: the clients accepted on it, for the engine
/// of the moment. Clones share it; the last one closes the pipe.
#[cfg(windows)]
#[derive(Clone)]
pub struct Prompts(std::sync::Arc<PromptPipe>);

#[cfg(windows)]
pub struct PromptPipe {
    clients: tokio::sync::Mutex<mpsc::Receiver<(std::os::windows::io::OwnedHandle, User)>>,
    accept: tokio::task::JoinHandle<()>,
}

#[cfg(windows)]
impl Drop for PromptPipe {
    fn drop(&mut self) {
        // The listener goes with the task, and the pipe with it.
        self.accept.abort();
    }
}

#[cfg(windows)]
impl Prompts {
    pub fn new(mut listener: vpn_transport::HandoffListener) -> Self {
        let (tx, clients) = mpsc::channel(4);
        let accept = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(client) => {
                        if tx.send(client).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("prompt pipe: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
        Self(std::sync::Arc::new(PromptPipe { clients: tokio::sync::Mutex::new(clients), accept }))
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(self.clone())
    }
}

/// An engine process.
#[cfg(unix)]
pub(crate) type Process = tokio::process::Child;
#[cfg(windows)]
pub(crate) type Process = std::sync::Arc<crate::winproc::Child>;

/// How engines are started.
pub enum Launcher {
    /// A separate process, the normal case.
    #[cfg(unix)]
    Process {
        path: PathBuf,
        uid: u32,
        gid: u32,
        /// macOS: run under `sandbox-exec` with `sandbox_profile`.
        sandbox: bool,
    },
    /// Run as LocalService, restricted (see `winproc`).
    #[cfg(windows)]
    Process { path: PathBuf },
    /// In this process, on a socket pair: tests, which cannot switch users.
    #[cfg(all(test, unix))]
    InProcess,
}

impl Launcher {
    /// The engine binary next to the daemon's, run as `user`.
    pub fn process(path: Option<PathBuf>, user: &str, sandbox: bool) -> anyhow::Result<Self> {
        let path = match path {
            Some(p) => p,
            None => default_path()?,
        };
        if !path.is_file() {
            bail!("engine {} not found (use --engine)", path.display());
        }
        #[cfg(windows)]
        {
            let _ = (user, sandbox);
            Ok(Self::Process { path })
        }
        #[cfg(unix)]
        {
            Self::unix_process(path, user, sandbox)
        }
    }

    #[cfg(unix)]
    fn unix_process(path: PathBuf, user: &str, sandbox: bool) -> anyhow::Result<Self> {
        let account = nix::unistd::User::from_name(user)?
            .with_context(|| format!("user {user} does not exist (created by the installer; use --engine-user)"))?;
        if account.uid.is_root() {
            bail!("engines must not run as root");
        }
        Ok(Self::Process { path, uid: account.uid.as_raw(), gid: account.gid.as_raw(), sandbox })
    }
}

/// The engine binary next to the daemon's.
pub fn default_path() -> std::io::Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name(format!("{}{}", vpn_core::brand::ENGINE, std::env::consts::EXE_SUFFIX)))
}

/// What an engine may do on macOS: read the system libraries, resolve
/// names, use the network. Nothing of the user's, no other process.
#[cfg(target_os = "macos")]
pub fn sandbox_profile(engine: &std::path::Path) -> String {
    let engine = engine.display();
    format!(
        r#"(version 1)
(deny default)
(allow process-exec (literal "{engine}"))
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-read* (subpath "/usr/lib") (subpath "/System") (subpath "/private/var/db/dyld")
                  (literal "{engine}") (literal "/dev/urandom") (literal "/dev/null")
                  (literal "/private/etc/hosts") (literal "/private/etc/resolv.conf")
                  (subpath "/private/var/run/resolv.conf"))
(allow sysctl-read)
(allow network*)
(allow system-socket)
(allow mach-lookup (global-name "com.apple.dnssd.service")
                   (global-name "com.apple.SystemConfiguration.DNSConfiguration")
                   (global-name "com.apple.SystemConfiguration.configd"))
"#
    )
}

/// The engine of one session. Dropping it kills the engine.
pub struct RemoteEngine {
    out: mpsc::Sender<ToEngine>,
    events: mpsc::Receiver<FromEngine>,
    #[cfg(unix)]
    fds: Option<StdUnixStream>,
    #[cfg(windows)]
    packets: PacketPipe,
    child: Option<Process>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The engine reported the end of its attempt.
    ended: bool,
}

impl Drop for RemoteEngine {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            kill_now(child);
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl RemoteEngine {
    /// Starts the engine of session `name`, owned by `owner`, whose clients
    /// on `prompts` it serves.
    #[cfg(windows)]
    pub fn spawn(launcher: &Launcher, name: &str, owner: &User, prompts: Prompts) -> anyhow::Result<Self> {
        use std::os::windows::io::AsRawHandle;

        let Launcher::Process { path } = launcher;
        let (control, control_theirs) = vpn_transport::pipe_pair(true)?;
        let (packets, packets_theirs) = vpn_transport::pipe_pair(true)?;
        let (clients, clients_theirs) = vpn_transport::pipe_pair(true)?;
        let (stderr, stderr_theirs) = vpn_transport::pipe_pair(false)?;
        let theirs = [&control_theirs, &packets_theirs, &clients_theirs].map(|h| h.as_raw_handle());
        // Inherited handles keep their values.
        let args: Vec<String> = ["--control", "--packets", "--prompts"]
            .iter()
            .zip(theirs)
            .flat_map(|(flag, handle)| [flag.to_string(), (handle as usize).to_string()])
            .collect();
        let child = std::sync::Arc::new(
            crate::winproc::Child::spawn(path, &args, &theirs, stderr_theirs.as_raw_handle())
                .with_context(|| format!("cannot start {}", path.display()))?,
        );
        // The engine has its copies now.
        drop((control_theirs, packets_theirs, clients_theirs, stderr_theirs));
        let mut tasks = vec![
            tokio::spawn(relay_log(name.to_owned(), stderr)),
            tokio::spawn(hand_over(prompts, child.clone(), owner.id.clone(), clients)),
        ];
        let (read, write) = tokio::io::split(control);
        let (out, events) = talk(read, write, &mut tasks);
        Ok(Self { out, events, packets: PacketPipe::new(packets), child: Some(child), tasks, ended: true })
    }

    /// Starts the engine of session `name`, owned by `owner`, listening for
    /// its clients on `prompts`.
    #[cfg(unix)]
    pub fn spawn(launcher: &Launcher, name: &str, owner: &User, prompts: Prompts) -> anyhow::Result<Self> {
        let vpn_core::UserId::Uid(owner) = owner.id else { bail!("{owner} is not a Unix user") };
        let (control, control_theirs) = StdUnixStream::pair()?;
        let (fds, fds_theirs) = StdUnixStream::pair()?;
        let mut tasks = Vec::new();
        let child = match launcher {
            Launcher::Process { path, uid, gid, sandbox } => {
                let mut child = spawn(
                    path,
                    *uid,
                    *gid,
                    *sandbox,
                    &["--owner".into(), owner.to_string()],
                    [control_theirs.into(), fds_theirs.into(), prompts],
                )?;
                if let Some(stderr) = child.stderr.take() {
                    tasks.push(tokio::spawn(relay_log(name.to_owned(), stderr)));
                }
                Some(child)
            }
            #[cfg(all(test, unix))]
            Launcher::InProcess => {
                control_theirs.set_nonblocking(true)?;
                let control = tokio::net::UnixStream::from_std(control_theirs)?;
                let prompts = std::os::unix::net::UnixListener::from(prompts);
                prompts.set_nonblocking(true)?;
                let prompts = tokio::net::UnixListener::from_std(prompts)?;
                // Tests cannot switch users: the client is this process.
                let me = nix::unistd::getuid().as_raw();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = omnitun_engine::serve(control, fds_theirs, prompts, me).await {
                        tracing::debug!("in-process engine: {e:#}");
                    }
                }));
                None
            }
        };
        control.set_nonblocking(true)?;
        let (read, write) = tokio::net::UnixStream::from_std(control)?.into_split();
        let (out, events) = talk(read, write, &mut tasks);
        Ok(Self { out, events, fds: Some(fds), child, tasks, ended: true })
    }

    /// Starts an attempt; questions wait `attach_wait` for a client.
    pub async fn start(&mut self, profile: &Profile, attach_wait: Duration) -> anyhow::Result<()> {
        self.ended = false;
        let attach_wait_ms = attach_wait.as_millis() as u64;
        self.out
            .send(ToEngine::Start { profile: Box::new(profile.clone()), attach_wait_ms })
            .await
            .map_err(|_| failure(FailureKind::Other, "the engine process exited unexpectedly"))
    }

    /// Waits for the attempt to authenticate and negotiate.
    pub async fn connect(&mut self, stats: &TunnelStats) -> anyhow::Result<TunnelSettings> {
        loop {
            match self.next_event(stats).await? {
                FromEngine::Connected { settings } => return Ok(settings),
                FromEngine::Ended { error } => return Err(ended(error)),
                FromEngine::Stats { .. } => {}
            }
        }
    }

    /// Relays the interface's packets and waits for the tunnel to end.
    #[cfg(windows)]
    pub async fn run(&mut self, stats: &TunnelStats, device: &TunDevice) -> anyhow::Result<()> {
        self.out.send(ToEngine::Tun { name: device.name.clone() }).await.context("engine gone")?;
        let _relay = self.packets.relay(device.packets());
        self.wait_end(stats).await
    }

    /// Hands the interface over and waits for the tunnel to end.
    #[cfg(unix)]
    pub async fn run(&mut self, stats: &TunnelStats, device: &TunDevice) -> anyhow::Result<()> {
        self.out.send(ToEngine::Tun { name: device.name.clone() }).await.context("engine gone")?;
        let fds = self.fds.take().context("interface already being handed over")?;
        let fd = device.fd();
        let fds = tokio::task::spawn_blocking(move || vpn_platform::fdpass::send_fd(&fds, fd).map(|()| fds)).await??;
        self.fds = Some(fds);
        self.wait_end(stats).await
    }

    /// Waits for the end of a running tunnel.
    async fn wait_end(&mut self, stats: &TunnelStats) -> anyhow::Result<()> {
        loop {
            match self.next_event(stats).await? {
                FromEngine::Ended { error: None } => return Ok(()),
                FromEngine::Ended { error } => return Err(ended(error)),
                FromEngine::Connected { .. } => bail!("engine connected twice"),
                FromEngine::Stats { .. } => {}
            }
        }
    }

    /// Ends the current attempt: the engine logs out. Calling it again does
    /// nothing. The engine stays for the next attempt.
    pub async fn stop(&mut self) {
        if !self.ended {
            let _ = self.out.send(ToEngine::Stop).await;
            let ended = async {
                while let Some(message) = self.events.recv().await {
                    if matches!(message, FromEngine::Ended { .. }) {
                        break;
                    }
                }
            };
            if tokio::time::timeout(STOP_TIMEOUT, ended).await.is_err() {
                tracing::warn!("the engine did not stop in time; killing it");
                self.kill().await;
            }
            self.ended = true;
        }
    }

    /// Whether the engine process is still there to talk to.
    pub fn is_alive(&self) -> bool {
        !self.out.is_closed() && !self.events.is_closed()
    }

    /// Ends the session's engine.
    pub async fn kill(&mut self) {
        if let Some(child) = &mut self.child {
            kill_now(child);
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            self.child = None;
        }
        for task in &self.tasks {
            task.abort();
        }
    }

    /// The next message from the engine; counters are recorded.
    async fn next_event(&mut self, stats: &TunnelStats) -> anyhow::Result<FromEngine> {
        let message = self.events.recv().await.ok_or_else(|| {
            self.ended = true;
            failure(FailureKind::Other, "the engine process exited unexpectedly")
        })?;
        match &message {
            FromEngine::Stats { rx_bytes, tx_bytes, rx_packets, tx_packets } => {
                stats.add(*rx_bytes, *tx_bytes, *rx_packets, *tx_packets)
            }
            FromEngine::Ended { .. } => self.ended = true,
            FromEngine::Connected { .. } => {}
        }
        Ok(message)
    }
}

/// The control channel of an engine: messages to it go out through the
/// returned sender, and its own come in on the receiver.
fn talk(
    read: impl AsyncRead + Send + Unpin + 'static,
    mut write: impl AsyncWrite + Send + Unpin + 'static,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> (mpsc::Sender<ToEngine>, mpsc::Receiver<FromEngine>) {
    let (out, mut out_rx) = mpsc::channel::<ToEngine>(16);
    tasks.push(tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            // The first start may carry the client certificate's key.
            let mut line = Zeroizing::new(serde_json::to_vec(&message).expect("messages serialize"));
            line.push(b'\n');
            if write.write_all(&line).await.is_err() {
                break;
            }
        }
    }));
    let (events_tx, events) = mpsc::channel::<FromEngine>(16);
    tasks.push(tokio::spawn(async move {
        let mut lines = BufReader::new(read);
        loop {
            let mut line = String::new();
            match (&mut lines).take(MAX_ENGINE_LINE).read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) if !line.ends_with('\n') => {
                    tracing::warn!("engine sent an oversized message; dropping it");
                    break;
                }
                Ok(_) => match serde_json::from_str::<FromEngine>(&line) {
                    Ok(message) => {
                        if events_tx.send(message).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("engine sent an invalid message: {e}");
                        break;
                    }
                },
            }
        }
    }));
    (out, events)
}

#[cfg(unix)]
pub(crate) fn kill_now(child: &mut Process) {
    let _ = child.start_kill();
}

#[cfg(windows)]
pub(crate) fn kill_now(child: &mut Process) {
    child.kill();
}

/// The packet channel of a Windows engine, used by one attempt at a time.
#[cfg(windows)]
struct PacketPipe {
    read: std::sync::Arc<tokio::sync::Mutex<tokio::io::ReadHalf<tokio::net::windows::named_pipe::NamedPipeServer>>>,
    write: std::sync::Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeServer>>>,
}

#[cfg(windows)]
impl PacketPipe {
    fn new(pipe: tokio::net::windows::named_pipe::NamedPipeServer) -> Self {
        let (read, write) = tokio::io::split(pipe);
        Self {
            read: std::sync::Arc::new(tokio::sync::Mutex::new(read)),
            write: std::sync::Arc::new(tokio::sync::Mutex::new(write)),
        }
    }

    /// Moves packets between the interface and the engine until dropped.
    fn relay(&self, device: vpn_platform::TunPackets) -> Relay {
        use vpn_core::engine_ipc::{MAX_PACKET, read_packet, write_packet};
        let outbound = {
            let (write, device) = (self.write.clone(), device.clone());
            tokio::spawn(async move {
                let mut write = write.lock().await;
                let mut buf = vec![0u8; MAX_PACKET];
                loop {
                    let n = match device.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!("interface read: {e}");
                            return;
                        }
                    };
                    if write_packet(&mut *write, &buf[..n]).await.is_err() {
                        return;
                    }
                }
            })
        };
        let inbound = {
            let read = self.read.clone();
            tokio::spawn(async move {
                let mut read = read.lock().await;
                let mut buf = vec![0u8; MAX_PACKET];
                // What the engine sends goes into the interface, as its
                // writes to a descriptor would on Unix.
                while let Ok(Some(n)) = read_packet(&mut *read, &mut buf).await {
                    if let Err(e) = device.send(&buf[..n]).await {
                        tracing::debug!("interface write: {e}");
                    }
                }
            })
        };
        Relay([outbound, inbound])
    }
}

/// Stops the relay of an attempt's packets when dropped.
#[cfg(windows)]
struct Relay([tokio::task::JoinHandle<()>; 2]);

#[cfg(windows)]
impl Drop for Relay {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Hands the owner's prompt clients (and the administrators') to the
/// engine: a copy of each connection's handle in its process, announced
/// on `clients`.
#[cfg(windows)]
async fn hand_over(
    prompts: Prompts,
    child: Process,
    owner: vpn_core::UserId,
    mut clients: tokio::net::windows::named_pipe::NamedPipeServer,
) {
    use std::os::windows::io::AsRawHandle;
    let mut accepted = prompts.0.clients.lock().await;
    while let Some((connection, user)) = accepted.recv().await {
        if !user.may_act_for(&owner) {
            tracing::warn!("refusing a prompt client of {user}");
            continue;
        }
        let handle = match child.give(connection.as_raw_handle()) {
            Ok(handle) => handle,
            Err(e) => {
                tracing::warn!("cannot hand a prompt client over: {e}");
                continue;
            }
        };
        if clients.write_all(format!("{handle}\n").as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Copies a child's log into the daemon's, as an engine's: one line at a
/// time, bounded in length and rate, control characters escaped.
pub(crate) async fn relay_log(name: String, stderr: impl AsyncRead + Unpin + Send + 'static) {
    let mut lines = BufReader::new(stderr);
    let (mut window, mut count) = (tokio::time::Instant::now(), 0u32);
    loop {
        let mut line = Vec::new();
        match (&mut lines).take(MAX_LOG_LINE).read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if window.elapsed() >= Duration::from_secs(1) {
            if count > LOG_LINES_PER_SECOND {
                tracing::warn!(engine = name, "{} log lines dropped", count - LOG_LINES_PER_SECOND);
            }
            (window, count) = (tokio::time::Instant::now(), 0);
        }
        count += 1;
        if count <= LOG_LINES_PER_SECOND {
            // Control characters escaped: one engine line stays one log line.
            let text: String = String::from_utf8_lossy(&line)
                .trim_end()
                .chars()
                .flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] })
                .collect();
            tracing::info!("[{name}] {text}");
        }
    }
}

fn ended(error: Option<EngineError>) -> anyhow::Error {
    match error {
        Some(EngineError { failure: kind, message }) => failure(kind, message),
        None => anyhow::anyhow!("the engine stopped"),
    }
}

/// Starts the engine binary as `uid` with `args`, with only its three
/// sockets open (as 3, 4 and 5): it must not inherit other sessions' tun
/// interfaces or clients' sockets.
#[cfg(unix)]
pub(crate) fn spawn(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
    sandbox: bool,
    args: &[String],
    fds: [OwnedFd; 3],
) -> anyhow::Result<tokio::process::Child> {
    let mut command = if sandbox {
        #[cfg(target_os = "macos")]
        {
            let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
            c.arg("-p").arg(sandbox_profile(path)).arg(path);
            c
        }
        #[cfg(not(target_os = "macos"))]
        bail!("no sandbox on this platform yet; use --no-engine-sandbox")
    } else {
        tokio::process::Command::new(path)
    };
    command
        .args(args)
        .env_clear()
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // Relayed by the daemon, not written straight into its log file.
        .stderr(std::process::Stdio::piped())
        .uid(uid)
        .gid(gid)
        .kill_on_drop(true);
    let raw = fds.each_ref().map(|fd| fd.as_raw_fd());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        // Every descriptor number is below the soft limit (set by main).
        let max = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)
            .map(|(soft, _)| soft.min(1 << 20) as i32)
            .unwrap_or(65536);
        command.pre_exec(move || {
            // Out of the way of 3 to 5 first, then into place.
            let mut moved = [0; 3];
            for (i, fd) in raw.iter().enumerate() {
                moved[i] = libc::fcntl(*fd, libc::F_DUPFD, 16);
                if moved[i] < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (i, fd) in moved.iter().enumerate() {
                if libc::dup2(*fd, 3 + i as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Close-on-exec ones go at exec anyway, among them the pipe
            // through which the standard library reports a failed exec.
            for fd in 6..max {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    // The engine has its copies now.
    drop(fds);
    Ok(child)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A missing engine (during an update, say) is an error of `spawn`,
    /// not a process that exits at once.
    #[tokio::test]
    async fn a_missing_engine_fails_to_start() {
        let fds = std::array::from_fn(|_| OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
        let (uid, gid) = (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw());
        let error = spawn(std::path::Path::new("/nonexistent/omnitun-engine"), uid, gid, false, &[], fds).unwrap_err();
        let io = error.downcast_ref::<std::io::Error>().expect("the exec error");
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound, "{error:#}");
    }
}
