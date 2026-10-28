//! The daemon's side of an engine process: starts it unprivileged and
//! sandboxed for one session, starts its attempts, hands it the tun
//! interface, and treats everything it says as untrusted. The user's
//! answers go to the engine directly, on the session's prompt socket.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use vpn_core::engine_ipc::{EngineError, FromEngine, ToEngine};
use vpn_core::{FailureKind, Profile, TunnelSettings, TunnelStats, failure};
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

/// How engines are started.
pub enum Launcher {
    /// A separate process, the normal case.
    Process {
        path: PathBuf,
        uid: u32,
        gid: u32,
        /// macOS: run under `sandbox-exec` with `sandbox_profile`.
        sandbox: bool,
    },
    /// In this process, on a socket pair: tests, which cannot switch users.
    #[cfg(test)]
    InProcess,
}

impl Launcher {
    /// The engine binary next to the daemon's, run as `user`.
    pub fn process(path: Option<PathBuf>, user: &str, sandbox: bool) -> anyhow::Result<Self> {
        let path = match path {
            Some(p) => p,
            None => std::env::current_exe()?.with_file_name(vpn_core::brand::ENGINE),
        };
        if !path.is_file() {
            bail!("engine {} not found (use --engine)", path.display());
        }
        let account = nix::unistd::User::from_name(user)?
            .with_context(|| format!("user {user} does not exist (created by the installer; use --engine-user)"))?;
        if account.uid.is_root() {
            bail!("engines must not run as root");
        }
        Ok(Self::Process { path, uid: account.uid.as_raw(), gid: account.gid.as_raw(), sandbox })
    }
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
    fds: Option<StdUnixStream>,
    child: Option<tokio::process::Child>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The engine reported the end of its attempt.
    ended: bool,
}

impl Drop for RemoteEngine {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl RemoteEngine {
    /// Starts the engine of session `name`, owned by `owner`, listening for
    /// its clients on `prompts`.
    pub fn spawn(launcher: &Launcher, name: &str, owner: u32, prompts: OwnedFd) -> anyhow::Result<Self> {
        let (control, control_theirs) = StdUnixStream::pair()?;
        let (fds, fds_theirs) = StdUnixStream::pair()?;
        let mut tasks = Vec::new();
        let child = match launcher {
            Launcher::Process { path, uid, gid, sandbox } => {
                let mut child =
                    spawn(path, *uid, *gid, *sandbox, owner, [control_theirs.into(), fds_theirs.into(), prompts])?;
                if let Some(stderr) = child.stderr.take() {
                    tasks.push(tokio::spawn(relay_log(name.to_owned(), stderr)));
                }
                Some(child)
            }
            #[cfg(test)]
            Launcher::InProcess => {
                control_theirs.set_nonblocking(true)?;
                let control = UnixStream::from_std(control_theirs)?;
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
        let (read, mut write) = UnixStream::from_std(control)?.into_split();

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

    /// Hands the interface over and waits for the tunnel to end.
    pub async fn run(&mut self, stats: &TunnelStats, device: &TunDevice) -> anyhow::Result<()> {
        self.out.send(ToEngine::Tun { name: device.name.clone() }).await.context("engine gone")?;
        let fds = self.fds.take().context("interface already being handed over")?;
        let fd = device.fd();
        let fds = tokio::task::spawn_blocking(move || vpn_platform::fdpass::send_fd(&fds, fd).map(|()| fds)).await??;
        self.fds = Some(fds);
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
            let _ = child.start_kill();
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

/// Copies an engine's log into the daemon's, as an engine's: one line at a
/// time, bounded in length and rate, control characters escaped.
async fn relay_log(name: String, stderr: tokio::process::ChildStderr) {
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

/// Starts the engine as `uid`, with only its three sockets open (as 3, 4
/// and 5): it must not inherit other sessions' tun interfaces or clients'
/// sockets.
fn spawn(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
    sandbox: bool,
    owner: u32,
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
        .arg("--owner")
        .arg(owner.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing engine (during an update, say) is an error of `spawn`,
    /// not a process that exits at once.
    #[tokio::test]
    async fn a_missing_engine_fails_to_start() {
        let fds = std::array::from_fn(|_| OwnedFd::from(std::fs::File::open("/dev/null").unwrap()));
        let (uid, gid) = (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw());
        let error = spawn(std::path::Path::new("/nonexistent/omnitun-engine"), uid, gid, false, uid, fds).unwrap_err();
        let io = error.downcast_ref::<std::io::Error>().expect("the exec error");
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound, "{error:#}");
    }
}
