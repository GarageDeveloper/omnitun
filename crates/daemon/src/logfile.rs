//! Rotation of the log file launchd writes our stderr to
//! (StandardErrorPath): past `MAX_SIZE` it becomes `.1` (the older ones
//! shift up to `.KEEP`) and a new file takes its place on stderr, without
//! a restart. A stderr that is not that file (a terminal, the systemd
//! journal) is left alone.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_SIZE: u64 = 10 * 1024 * 1024;
const KEEP: u32 = 5;
const CHECK_EVERY: Duration = Duration::from_secs(300);

/// Where the package sends the daemon's stderr.
pub fn path() -> PathBuf {
    PathBuf::from(format!("/var/log/{}.log", vpn_core::brand::DAEMON))
}

/// Checks the size now and then, for the life of the daemon.
pub fn spawn_rotation() {
    let path = path();
    if !is_stderr(&path) {
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = rotate(&path, MAX_SIZE, KEEP) {
                tracing::warn!("cannot rotate {}: {e}", path.display());
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Whether stderr is the file at `path`.
fn is_stderr(path: &Path) -> bool {
    let Ok(file) = std::fs::metadata(path) else { return false };
    let Ok(stderr) = nix::sys::stat::fstat(std::io::stderr()) else { return false };
    // st_dev is an i32 on macOS, a u64 on Linux.
    #[allow(clippy::unnecessary_cast)]
    let dev = stderr.st_dev as u64;
    file.dev() == dev && file.ino() == stderr.st_ino
}

/// Rotates `path` if it is larger than `max`; returns whether it did.
fn rotate(path: &Path, max: u64, keep: u32) -> std::io::Result<bool> {
    let current = std::fs::metadata(path)?;
    if current.len() <= max {
        return Ok(false);
    }
    let numbered = |n: u32| PathBuf::from(format!("{}.{n}", path.display()));
    for n in (1..keep).rev() {
        if numbered(n).exists() {
            std::fs::rename(numbered(n), numbered(n + 1))?;
        }
    }
    std::fs::rename(path, numbered(1))?;
    // Same owner, group and mode as before (root:admin 640 from the
    // package): the log names servers and accounts.
    let file: File = OpenOptions::new().append(true).create_new(true).mode(current.mode() & 0o777).open(path)?;
    // The daemon's umask (077) took the group's read right away.
    file.set_permissions(std::fs::Permissions::from_mode(current.mode() & 0o777))?;
    std::os::unix::fs::fchown(&file, Some(current.uid()), Some(current.gid()))?;
    nix::unistd::dup2_stderr(&file)?;
    tracing::info!("log rotated: the previous lines are in {}", numbered(1).display());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_shifts_old_files() {
        let dir = std::env::temp_dir().join(format!("omnitund-rotation-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("d.log");
        std::fs::write(&log, "small").unwrap();
        assert!(!rotate(&log, 100, 3).unwrap());
        for round in 0..4 {
            std::fs::write(&log, format!("round {round} {}", "x".repeat(200))).unwrap();
            // Rotating replaces stderr: keep the test's own.
            let saved = nix::unistd::dup(std::io::stderr()).unwrap();
            assert!(rotate(&log, 100, 3).unwrap());
            nix::unistd::dup2_stderr(&saved).unwrap();
        }
        let read = |n: u32| std::fs::read_to_string(dir.join(format!("d.log.{n}"))).unwrap();
        assert!(read(1).starts_with("round 3"));
        assert!(read(3).starts_with("round 1"), "the oldest kept");
        assert!(!dir.join("d.log.4").exists());
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 0, "a new, empty file");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(&log), mode(&dir.join("d.log.1")), "same rights");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
