//! `omnitun-engine`: started by `omnitund` for one connection attempt, under
//! an unprivileged account and (on macOS) a sandbox, for one session. The
//! daemon passes the control socket as descriptor 3, the descriptor socket
//! as 4 and the session's listening prompt socket as 5; `--owner <uid>`
//! names the only user (besides root) whose client may attach to it.
//!
//! On Windows, three inherited pipes named by their handles: `--control`,
//! `--packets` (the interface's packets, relayed by the daemon) and
//! `--prompts` (the owner's prompt clients, accepted by the daemon).
//!
//! `--dns-proxy`: a session's DNS proxy instead (routes by domain, #37):
//! the control socket as descriptor 3, the bound UDP socket as 4 and the
//! TCP listener on the same port as 5.

#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(unix)]
use anyhow::{Context, bail};

#[cfg(unix)]
const CONTROL_FD: i32 = 3;
#[cfg(unix)]
const FDS_FD: i32 = 4;
#[cfg(unix)]
const PROMPTS_FD: i32 = 5;

// Two workers: a client certificate signature blocks one inside the TLS
// handshake while the other carries the question to the client.
#[cfg(unix)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    init_log();
    if std::env::args().nth(1).as_deref() == Some("--check") {
        return check().await;
    }
    // Parsing network data is exactly what root must not do.
    if nix::unistd::geteuid().is_root() {
        bail!("{} must not run as root", vpn_core::brand::ENGINE);
    }
    if std::env::args().nth(1).as_deref() == Some("--dns-proxy") {
        return dns_proxy().await;
    }
    let mut args = std::env::args().skip(1);
    let owner = match (args.next().as_deref(), args.next()) {
        (Some("--owner"), Some(uid)) => uid.parse().context("--owner")?,
        _ => bail!("usage: {} --owner <uid> (started by the daemon)", vpn_core::brand::ENGINE),
    };
    // SAFETY: the daemon set up these three descriptors for this process.
    let (control, fds, prompts) =
        unsafe { (OwnedFd::from_raw_fd(CONTROL_FD), OwnedFd::from_raw_fd(FDS_FD), OwnedFd::from_raw_fd(PROMPTS_FD)) };
    let control = std::os::unix::net::UnixStream::from(control);
    control.set_nonblocking(true)?;
    let control = tokio::net::UnixStream::from_std(control).context("control socket")?;
    let prompts = std::os::unix::net::UnixListener::from(prompts);
    prompts.set_nonblocking(true)?;
    let prompts = tokio::net::UnixListener::from_std(prompts).context("prompt socket")?;
    omnitun_engine::serve(control, std::os::unix::net::UnixStream::from(fds), prompts, owner).await
}

#[cfg(unix)]
async fn dns_proxy() -> anyhow::Result<()> {
    // SAFETY: the daemon set up these three descriptors for this process.
    let (control, udp, tcp) =
        unsafe { (OwnedFd::from_raw_fd(CONTROL_FD), OwnedFd::from_raw_fd(FDS_FD), OwnedFd::from_raw_fd(PROMPTS_FD)) };
    let control = std::os::unix::net::UnixStream::from(control);
    control.set_nonblocking(true)?;
    let udp = std::net::UdpSocket::from(udp);
    udp.set_nonblocking(true)?;
    let tcp = std::net::TcpListener::from(tcp);
    tcp.set_nonblocking(true)?;
    vpn_dnsproxy::run(
        tokio::net::UnixStream::from_std(control).context("control socket")?,
        tokio::net::UdpSocket::from_std(udp).context("DNS socket")?,
        tokio::net::TcpListener::from_std(tcp).context("DNS listener")?,
    )
    .await
}

/// Started by the daemon, which relays the log with its own timestamps:
/// plain lines without time. In a terminal, the usual format.
fn init_log() {
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let log = tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(terminal).with_env_filter(filter);
    if terminal { log.init() } else { log.without_time().with_target(false).init() }
}

/// What an engine needs from its sandbox: name resolution, outbound
/// connections and a loopback listener (SAML); and what it must not do.
async fn check() -> anyhow::Result<()> {
    let host = std::env::args().nth(2).unwrap_or_else(|| "apple.com".into());
    let resolved = tokio::net::lookup_host((host.as_str(), 443)).await.map(|mut a| a.next());
    println!("resolve {host}: {resolved:?}");
    if let Ok(Some(address)) = resolved {
        let tcp =
            tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect(address)).await;
        println!("tcp {address}: {}", if matches!(tcp, Ok(Ok(_))) { "ok" } else { "failed" });
    }
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await;
    println!("udp socket: {}", if udp.is_ok() { "ok" } else { "failed" });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await;
    println!("loopback listener: {}", if listener.is_ok() { "ok" } else { "failed" });
    // A user's home given as the next argument.
    #[cfg(unix)]
    let (secret, users, written) = ("/etc/master.passwd", "/Users", "/tmp/omnitun-engine-check");
    #[cfg(windows)]
    let (secret, users, written) =
        (r"C:\Windows\System32\config\SAM", r"C:\Users", r"C:\ProgramData\omnitun-engine-check");
    let users = std::env::args().nth(3).unwrap_or_else(|| users.into());
    let refused = |allowed: bool| if allowed { "ALLOWED" } else { "refused" };
    println!("read {secret}: {}", refused(std::fs::read(secret).is_ok()));
    println!("list {users}: {}", refused(std::fs::read_dir(&users).is_ok()));
    let wrote = std::fs::write(written, b"x").is_ok();
    let _ = std::fs::remove_file(written);
    println!("write {written}: {}", refused(wrote));
    Ok(())
}

/// Windows: the daemon passes its pipes' handles, inherited, as arguments.
#[cfg(windows)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use tokio::net::windows::named_pipe::NamedPipeClient;

    init_log();
    if std::env::args().nth(1).as_deref() == Some("--check") {
        return check().await;
    }
    // Parsing network data is exactly what an administrator must not do.
    if vpn_transport::current_user()?.admin {
        bail!("{} must not run as an administrator", vpn_core::brand::ENGINE);
    }
    let usage =
        || format!("usage: {} --control <handle> --packets <handle> --prompts <handle>", vpn_core::brand::ENGINE);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let handle = |flag: &str| -> anyhow::Result<NamedPipeClient> {
        let value = args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).with_context(usage)?;
        let value: usize = value.parse().with_context(|| format!("{flag} {value}"))?;
        // SAFETY: an overlapped pipe handle this process inherited for
        // this use, owned from now on.
        unsafe { NamedPipeClient::from_raw_handle(value as std::os::windows::io::RawHandle) }
            .with_context(|| format!("{flag} {value}"))
    };
    omnitun_engine::serve(handle("--control")?, handle("--packets")?, handle("--prompts")?).await
}
