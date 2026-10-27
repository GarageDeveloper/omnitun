//! `omnitun-engine`: started by `omnitund` for one connection attempt, under
//! an unprivileged account and (on macOS) a sandbox, for one session. The
//! daemon passes the control socket as descriptor 3, the descriptor socket
//! as 4 and the session's listening prompt socket as 5; `--owner <uid>`
//! names the only user (besides root) whose client may attach to it.

use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::{Context, bail};

const CONTROL_FD: i32 = 3;
const FDS_FD: i32 = 4;
const PROMPTS_FD: i32 = 5;

// Two workers: a client certificate signature blocks one inside the TLS
// handshake while the other carries the question to the client.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // Started by the daemon, which relays the log with its own timestamps:
    // plain lines without time. In a terminal, the usual format.
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let log = tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(terminal).with_env_filter(filter);
    if terminal {
        log.init()
    } else {
        log.without_time().with_target(false).init()
    }
    if std::env::args().nth(1).as_deref() == Some("--check") {
        return check().await;
    }
    // Parsing network data is exactly what root must not do.
    if nix::unistd::geteuid().is_root() {
        bail!("{} must not run as root", vpn_core::brand::ENGINE);
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

/// What an engine needs from its sandbox: name resolution, outbound
/// connections and a loopback listener (SAML).
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
    let secret = std::fs::read("/etc/master.passwd");
    println!("read /etc/master.passwd: {}", if secret.is_ok() { "ALLOWED" } else { "refused" });
    let home = std::fs::read_dir("/Users");
    println!("list /Users: {}", if home.is_ok() { "ALLOWED" } else { "refused" });
    Ok(())
}
