//! A diagnostic report to send when something goes wrong: versions, the
//! service, the VPNs and their sessions, the service's recent log. Never
//! a secret; servers, accounts, domains and addresses are replaced by
//! placeholders (the same one for the same value, so the report still
//! reads), the VPN names are kept.

use std::fmt::Write as _;

use vpn_core::Profile;
use vpn_core::ipc::{SessionInfo, SessionState};

use crate::service_log::{self, Condenser, Filter};
use crate::{Daemon, ProfileStore};

/// How far back the log goes.
const LOG_HOURS: u64 = 24;
/// Lines of log at most (the most recent).
const LOG_LINES: usize = 2000;

/// The report, as text. `client`: who writes it ("Omnitun 0.1.0").
pub async fn report(store: &ProfileStore, client: &str) -> String {
    // Read only: a diagnosis changes nothing, not even old files' ids.
    let profiles = store.load_read_only();
    let mut redact = Redactor::default();
    if let Ok(profiles) = &profiles {
        for p in profiles {
            redact.learn(p);
        }
    }
    let mut out = String::new();
    let _ = writeln!(out, "{} diagnostic report", vpn_core::brand::PRODUCT);
    let _ = writeln!(out, "Created:  {}", service_log::local_time(service_log::now()));
    let _ = writeln!(out, "Client:   {client}");
    let _ = writeln!(out, "System:   {}", system());
    let _ = writeln!(
        out,
        "\nServers, accounts, domains and addresses are replaced by placeholders; no password, key or certificate is included.\n"
    );

    let _ = writeln!(out, "== Service");
    let sessions = match Daemon::open(vpn_core::brand::CLI).await {
        Ok(daemon) => {
            let _ = writeln!(out, "running, version {}", daemon.version());
            daemon.status().await.map_err(|e| format!("{e:#}"))
        }
        Err(e) => {
            let _ = writeln!(out, "unavailable: {}", redact.text(&format!("{e:#}")));
            Err(String::new())
        }
    };

    let _ = writeln!(out, "\n== VPNs");
    match &profiles {
        Ok(profiles) if profiles.is_empty() => {
            let _ = writeln!(out, "none");
        }
        Ok(profiles) => {
            for p in profiles {
                let _ = writeln!(out, "{}", redact.text(&describe(p)));
            }
        }
        Err(e) => {
            let _ = writeln!(out, "unreadable: {}", redact.text(&format!("{e:#}")));
        }
    }

    let _ = writeln!(out, "\n== Sessions");
    match &sessions {
        Ok(sessions) if sessions.is_empty() => {
            let _ = writeln!(out, "none");
        }
        Ok(sessions) => {
            for s in sessions {
                let _ = writeln!(out, "{}", redact.text(&session(s)));
            }
        }
        Err(e) if !e.is_empty() => {
            let _ = writeln!(out, "unknown: {}", redact.text(e));
        }
        Err(_) => {
            let _ = writeln!(out, "unknown");
        }
    }

    let _ = writeln!(out, "\n== Service log, last {LOG_HOURS} h, main lines");
    match service_log::read_since(service_log::now().saturating_sub(LOG_HOURS * 3600)) {
        Ok(lines) => {
            let mut condenser = Condenser::new(Filter { names: Vec::new(), all: false });
            let mut kept: Vec<String> = lines.into_iter().filter_map(|l| condenser.push(l)).collect();
            kept.extend(condenser.finish());
            let skip = kept.len().saturating_sub(LOG_LINES);
            if skip > 0 {
                let _ = writeln!(out, "({skip} older lines left out)");
            }
            for line in &kept[skip..] {
                let _ = writeln!(out, "{}", redact.text(line));
            }
        }
        Err(e) => {
            let _ = writeln!(out, "not included: {e:#}");
        }
    }
    out
}

/// "macOS 26.7.1 (arm64)", "Linux 6.8.0 (x86_64)".
fn system() -> String {
    let run = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "macos" => format!("macOS {} ({arch})", run("/usr/bin/sw_vers", &["-productVersion"]).unwrap_or_default()),
        os => format!("{os} {} ({arch})", run("uname", &["-r"]).unwrap_or_default()),
    }
}

/// One VPN, without its servers or accounts.
fn describe(p: &Profile) -> String {
    let mut parts = vec![p.protocol.name().to_owned()];
    if let Some(folder) = &p.folder {
        parts.push(format!("folder {folder}"));
    }
    match p.full_tunnel {
        Some(true) => parts.push("all traffic".into()),
        Some(false) => parts.push("split".into()),
        None => {}
    }
    if let Some(routes) = &p.routes {
        parts.push(format!("{} route(s) set", routes.len()));
    }
    if !p.dns_domains.is_empty() {
        parts.push(format!("{} DNS domain(s)", p.dns_domains.len()));
    }
    let routed = vpn_core::destination::domains(&p.split_routes).count() + p.included_domains().len();
    if routed > 0 {
        parts.push(format!("{routed} domain(s) routed through it"));
    }
    if !p.excluded_domains.is_empty() {
        parts.push(format!("{} domain(s) kept outside", p.excluded_domains.len()));
    }
    if !p.via.is_empty() {
        parts.push(format!("chained through {} VPN(s)", p.via.len()));
    }
    if p.exclusive {
        parts.push("company VPN".into());
    }
    if p.allow_route_overlap {
        parts.push("overlap allowed".into());
    }
    // The protocol's own settings, without the identifying ones.
    if let Ok(toml::Value::Table(table)) = toml::Value::try_from(&p.protocol) {
        let mut settings: Vec<String> = table
            .iter()
            .filter(|(key, _)| !IDENTIFYING.contains(&key.as_str()) && *key != "protocol")
            .filter_map(|(key, value)| match value {
                toml::Value::Boolean(b) => Some(format!("{key}={b}")),
                toml::Value::Integer(n) => Some(format!("{key}={n}")),
                toml::Value::String(s) if s.len() <= 40 && !s.contains('\n') => Some(format!("{key}={s}")),
                toml::Value::Array(a) if a.iter().all(|v| v.is_str() && v.as_str().is_some_and(|s| s.len() <= 40)) => {
                    Some(format!("{key}=[{}]", a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")))
                }
                _ => None,
            })
            .collect();
        settings.sort();
        if !settings.is_empty() {
            parts.push(settings.join(" "));
        }
    }
    format!("{}: {}", p.name, parts.join(", "))
}

/// Profile keys whose values name a server, an account or a certificate,
/// or hold key material: never in the report.
const IDENTIFYING: &[&str] = &[
    "host",
    "gateway",
    "endpoint",
    "remotes",
    "username",
    "local_id",
    "remote_id",
    "verify_x509_name",
    "trusted_cert",
    "ca_pem",
    "client_cert_pem",
    "client_key_pem",
    "client_chain_pem",
    "keychain_ca_pem",
    "client_certificate",
    "ca_file",
    "client_cert",
    "client_key",
    "realm",
    "static_key",
    "public_key",
    "local_public_key",
    "addresses",
    "allowed_ips",
    "dns_servers",
    "dns_search",
    "static_challenge",
];

fn session(s: &SessionInfo) -> String {
    let state = match s.state {
        SessionState::Connecting => "connecting",
        SessionState::Connected => "connected",
        SessionState::Reconnecting => "reconnecting",
        SessionState::Disconnecting => "disconnecting",
        SessionState::Disconnected => "disconnected",
        SessionState::Failed => "failed",
    };
    let now = service_log::now();
    let mut parts = vec![format!("{} ({})", state, s.protocol)];
    if let Some(up) = s.up_since.or(s.connected_since) {
        parts.push(format!("up {} min", now.saturating_sub(up) / 60));
    }
    if s.reconnects > 0 {
        parts.push(format!("{} reconnection attempt(s)", s.reconnects));
    }
    if let Some((at, why)) = &s.last_drop {
        parts.push(format!("last drop {} min ago: {why}", now.saturating_sub(*at) / 60));
    }
    if let Some(detail) = &s.detail
        && s.state != SessionState::Connected
    {
        parts.push(detail.clone());
    }
    if let Some(mtu) = s.mtu {
        parts.push(format!("MTU {mtu}"));
    }
    parts.push(if s.full_tunnel { "all traffic".into() } else { format!("{} route(s)", s.routes.len()) });
    parts.push(format!("{} DNS domain(s)", s.dns_domains.len()));
    parts.push(format!("received {} KiB, sent {} KiB", s.rx_bytes / 1024, s.tx_bytes / 1024));
    format!("{}: {}", s.name, parts.join(", "))
}

/// Replaces what identifies servers, people and networks.
#[derive(Default)]
struct Redactor {
    /// Known values and their placeholders, longest first when applied.
    known: Vec<(String, String)>,
    servers: usize,
    domains: usize,
}

impl Redactor {
    /// The servers, accounts and domains of a profile.
    fn learn(&mut self, profile: &Profile) {
        let Ok(toml::Value::Table(table)) = toml::Value::try_from(&profile.protocol) else { return };
        let mut strings = Vec::new();
        for key in ["host", "gateway", "endpoint"] {
            collect(table.get(key), &mut strings);
        }
        // Their servers' and names' own fields: not "udp" or "name".
        let field = |key: &str, field: &str| -> Vec<toml::Value> {
            match table.get(key) {
                Some(toml::Value::Array(items)) => items.iter().filter_map(|i| i.get(field).cloned()).collect(),
                Some(table) => table.get(field).cloned().into_iter().collect(),
                None => Vec::new(),
            }
        };
        for value in field("remotes", "host").iter().chain(&field("verify_x509_name", "name")) {
            collect(Some(value), &mut strings);
        }
        for host in strings {
            if !self.known.iter().any(|(k, _)| *k == host) {
                self.servers += 1;
                self.known.push((host, format!("<server-{}>", self.servers)));
            }
        }
        let mut accounts = Vec::new();
        for key in ["username", "local_id", "remote_id"] {
            collect(table.get(key), &mut accounts);
        }
        for account in accounts {
            self.known.push((account, "<account>".into()));
        }
        // A routed domain's base also masks the names under it.
        let routed = [profile.routes.as_deref().unwrap_or_default(), &profile.split_routes, &profile.extra_routes]
            .into_iter()
            .flat_map(vpn_core::destination::domains)
            .chain(profile.excluded_domains.iter().map(|d| &d.value))
            .map(|d| d.base().to_owned());
        for domain in profile.dns_domains.iter().map(|d| d.value.clone()).chain(routed) {
            if !self.known.iter().any(|(k, _)| *k == domain) {
                self.domains += 1;
                self.known.push((domain, format!("<domain-{}>", self.domains)));
            }
        }
        self.known.retain(|(k, _)| k.len() >= 3);
        self.known.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    }

    fn text(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (value, placeholder) in &self.known {
            out = out.replace(value.as_str(), placeholder);
        }
        let out = mask_addresses(&out);
        mask_emails(&out)
    }
}

/// Every string in `value` (a string, or a table or array of them).
fn collect(value: Option<&toml::Value>, into: &mut Vec<String>) {
    match value {
        Some(toml::Value::String(s)) if !s.is_empty() => {
            // "ip:192.0.2.1", "keyid:group": the value after the type.
            let s = s
                .split_once(':')
                .filter(|(t, _)| ["ip", "fqdn", "email", "keyid"].contains(t))
                .map_or(s.as_str(), |(_, v)| v);
            into.push(s.to_owned());
        }
        Some(toml::Value::Array(items)) => items.iter().for_each(|v| collect(Some(v), into)),
        Some(toml::Value::Table(table)) => table.values().for_each(|v| collect(Some(v), into)),
        _ => {}
    }
}

/// IPv4 addresses (with their prefix length or port kept) become `<ip>`,
/// IPv6 ones `<ipv6>`.
fn mask_addresses(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    // The end of the longest address-looking run from `i` made of `allowed`
    // characters that parses, if followed by no letter or digit.
    let address = |i: usize, allowed: &dyn Fn(char) -> bool, parses: &dyn Fn(&str) -> bool| {
        let mut end = i;
        while end < chars.len() && allowed(chars[end]) {
            end += 1;
        }
        while end > i {
            let word: String = chars[i..end].iter().collect();
            let next_ok = end >= chars.len() || !chars[end].is_ascii_alphanumeric();
            if next_ok && parses(&word) {
                return Some(end);
            }
            end -= 1;
        }
        None
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || ".:".contains(chars[i - 1]));
        if boundary {
            let v4 = address(i, &|c| c.is_ascii_digit() || c == '.', &|w| w.parse::<std::net::Ipv4Addr>().is_ok());
            if let Some(end) = v4 {
                out.push_str("<ip>");
                i = end;
                continue;
            }
            let v6 = address(i, &|c| c.is_ascii_hexdigit() || c == ':' || c == '.', &|w| {
                w.contains(':') && w.parse::<std::net::Ipv6Addr>().is_ok()
            });
            if let Some(end) = v6 {
                out.push_str("<ipv6>");
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `someone@example.com` becomes `<email>`.
fn mask_emails(text: &str) -> String {
    text.split_inclusive(|c: char| c.is_whitespace() || "\"'(),;<>[]{}=".contains(c))
        .map(|piece| {
            let word = piece.trim_end_matches(|c: char| c.is_whitespace() || "\"'(),;<>[]{}=".contains(c));
            let tail = &piece[word.len()..];
            match word.split_once('@') {
                Some((user, domain)) if !user.is_empty() && domain.contains('.') => format!("<email>{tail}"),
                _ => piece.to_owned(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_emails() {
        assert_eq!(
            mask_addresses("route 10.1.2.0/24 via 192.168.0.1:500 on fe80::1 spi=c35cf428 v1.2.3"),
            "route <ip>/24 via <ip>:500 on <ipv6> spi=c35cf428 v1.2.3"
        );
        assert_eq!(mask_addresses("version 0.1.0, 12:34:56"), "version 0.1.0, 12:34:56");
        assert_eq!(mask_emails("user=\"jane.doe@example.com\" ok"), "user=\"<email>\" ok");
    }

    #[test]
    fn profiles_are_redacted() {
        let profile: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nport = 443\n\
             username = \"jdoe\"\ndns_domains = [\"corp.example\"]\n\
             split_routes = [\"10.1.0.0/16\", { domain = \"*.corp-saas.com\", note = \"CRM\" }]\n\
             excluded_domains = [\"zoom.us\"]",
        )
        .unwrap();
        let mut redact = Redactor::default();
        redact.learn(&profile);
        assert_eq!(
            redact.text("jdoe on vpn.example.com resolves corp.example, eu.corp-saas.com, not zoom.us"),
            "<account> on <server-1> resolves <domain-1>, eu.<domain-2>, not <domain-3>"
        );
        let line = describe(&profile);
        assert!(line.starts_with("paris: forti-ssl"), "{line}");
        assert!(line.contains("1 domain(s) routed through it") && line.contains("1 domain(s) kept outside"), "{line}");
        assert!(!line.contains("saas") && !line.contains("zoom"), "{line}");
        assert!(!line.contains("example") && !line.contains("jdoe"), "{line}");
    }

    #[test]
    fn file_paths_and_realms_are_left_out() {
        let profile: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n\
             client_key = \"/Users/jdoe/k.pem\"\nclient_cert = \"/Users/jdoe/c.pem\"\n\
             ca_file = \"/Users/jdoe/ca.pem\"\nrealm = \"staff\"",
        )
        .unwrap();
        let line = describe(&profile);
        assert!(!line.contains("jdoe") && !line.contains("staff"), "{line}");
    }

    /// Only the servers' hosts and the certificate name are servers.
    #[test]
    fn openvpn_transports_are_kept() {
        let profile: Profile = toml::from_str(
            "name = \"lab\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nca_pem = \"CA\"\n\
             verify_x509_name = { name = \"vpn-cert\", kind = \"name\" }\n\
             [[remotes]]\nhost = \"vpn.example.com\"\ntransport = \"udp\"",
        )
        .unwrap();
        let mut redact = Redactor::default();
        redact.learn(&profile);
        assert_eq!(
            redact.text("udp to vpn.example.com, certificate vpn-cert, name lab"),
            "udp to <server-1>, certificate <server-2>, name lab"
        );
    }
}
