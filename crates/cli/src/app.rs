//! `omnitunctl app`: the menu bar app (macOS), started, or restarted when
//! it is stuck or gone from the menu bar. The VPNs run in the service and
//! stay up either way.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use vpn_core::brand;

/// How long a running copy has to end before it is killed.
const QUIT_WAIT: Duration = Duration::from_secs(5);

/// Opens the app, or brings it forward when it runs.
pub fn start() -> anyhow::Result<()> {
    let status = Command::new("/usr/bin/open").args(["-b", brand::REVERSE_DNS]).status().context("cannot run open")?;
    ensure!(status.success(), "cannot open {} (is it installed?)", brand::PRODUCT);
    Ok(())
}

/// Ends the user's running copies, then opens the app again; returns
/// whether one was running. The app does not handle SIGTERM: it ends at
/// once, without the disconnection it does when quit from its menu.
pub fn restart() -> anyhow::Result<bool> {
    let running = running()?;
    signal(&running, libc::SIGTERM);
    let deadline = Instant::now() + QUIT_WAIT;
    while alive(&running) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    signal(&running, libc::SIGKILL);
    while alive(&running) {
        std::thread::sleep(Duration::from_millis(100));
    }
    start()?;
    Ok(!running.is_empty())
}

/// The app's processes in this user's account.
fn running() -> anyhow::Result<Vec<libc::pid_t>> {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let output = Command::new("/usr/bin/pgrep")
        .args(["-x", "-U", &uid.to_string(), brand::PRODUCT])
        .output()
        .context("cannot run pgrep")?;
    // pgrep exits with 1 when nothing matches.
    ensure!(output.status.code().is_some_and(|c| c <= 1), "pgrep failed");
    Ok(String::from_utf8_lossy(&output.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect())
}

fn signal(pids: &[libc::pid_t], signal: libc::c_int) {
    for &pid in pids {
        // SAFETY: plain system call; a process already gone is ESRCH.
        unsafe { libc::kill(pid, signal) };
    }
}

fn alive(pids: &[libc::pid_t]) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    pids.iter().any(|&pid| unsafe { libc::kill(pid, 0) } == 0)
}
