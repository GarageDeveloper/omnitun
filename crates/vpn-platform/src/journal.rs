//! Routes outside the tunnels (gateway host routes, excluded networks)
//! outlive a crash of the daemon, unlike those bound to its tun interfaces.
//! They are recorded here before being added, so the next start can remove
//! them. The file lives in the runtime directory: a reboot clears both.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ipnet::Ipv4Net;

/// A route through the physical uplink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub net: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
}

static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn path() -> PathBuf {
    let dir = if cfg!(target_os = "macos") { "/var/run" } else { "/run" };
    Path::new(dir).join(format!("{}.routes", vpn_core::brand::DAEMON))
}

/// Records a route about to be added.
pub(crate) fn add(entry: Entry) {
    let mut entries = ENTRIES.lock().unwrap();
    entries.push(entry);
    save(&path(), &entries);
}

/// Forgets a route that was deleted (or could not be).
pub(crate) fn remove(entry: &Entry) {
    let mut entries = ENTRIES.lock().unwrap();
    if let Some(i) = entries.iter().position(|e| e == entry) {
        entries.remove(i);
    }
    save(&path(), &entries);
}

/// The routes a previous daemon left behind; the journal starts afresh.
pub(crate) fn take_stale() -> Vec<Entry> {
    take(&path())
}

fn take(path: &Path) -> Vec<Entry> {
    let entries = std::fs::read_to_string(path).map(|t| parse(&t)).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    entries
}

/// Failing to record must not fail the connection: the route would only
/// survive a crash, as before the journal existed.
fn save(path: &Path, entries: &[Entry]) {
    let result = if entries.is_empty() {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        write(path, &render(entries))
    };
    if let Err(e) = result {
        tracing::warn!("cannot update {}: {e}", path.display());
    }
}

fn write(path: &Path, text: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("routes.tmp");
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    file.write_all(text.as_bytes())?;
    std::fs::rename(&tmp, path)
}

/// One route per line: `network gateway|- interface`.
fn render(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|e| {
            let gateway = e.gateway.map_or_else(|| "-".to_owned(), |g| g.to_string());
            format!("{} {gateway} {}\n", e.net, e.interface)
        })
        .collect()
}

/// Lines that do not parse are ignored; interface names are checked since
/// they end up in command arguments.
fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let net = fields.next()?.parse().ok()?;
            let gateway = match fields.next()? {
                "-" => None,
                g => Some(g.parse().ok()?),
            };
            let interface = fields.next()?.to_owned();
            // A leading dash would read as an option.
            let valid = interface.len() <= 15
                && interface.starts_with(|c: char| c.is_ascii_alphanumeric())
                && interface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
            (valid && fields.next().is_none()).then_some(Entry { net, gateway, interface })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(net: &str, gateway: Option<&str>, interface: &str) -> Entry {
        Entry { net: net.parse().unwrap(), gateway: gateway.map(|g| g.parse().unwrap()), interface: interface.into() }
    }

    #[test]
    fn journal_round_trips() {
        let entries = [entry("203.0.113.7/32", Some("192.168.1.1"), "en0"), entry("10.9.0.0/16", None, "eth0")];
        assert_eq!(parse(&render(&entries)), entries);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let text = "203.0.113.7/32 192.168.1.1 en0\nnonsense\n10.0.0.0/8 - en0 extra\n10.0.0.0/8 - -rf;x\n\
                    10.0.0.0/8 nothost en0\n10.1.0.0/16 - eth0\n";
        assert_eq!(
            parse(text),
            [entry("203.0.113.7/32", Some("192.168.1.1"), "en0"), entry("10.1.0.0/16", None, "eth0")]
        );
    }

    #[test]
    fn stale_routes_are_taken_once() {
        let path = std::env::temp_dir().join(format!("vpn-platform-journal-{}", std::process::id()));
        let entries = [entry("203.0.113.7/32", Some("192.168.1.1"), "en0")];
        save(&path, &entries);
        assert_eq!(take(&path), entries);
        assert!(take(&path).is_empty());
        save(&path, &entries);
        save(&path, &[]);
        assert!(!path.exists());
    }
}
