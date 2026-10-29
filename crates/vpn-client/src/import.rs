//! Import of FortiClient (macOS) VPN profiles from its `vpn.plist` into
//! `profiles.toml` entries. Secrets are not imported: FortiClient keeps them
//! encrypted: the app asks for the pre-shared key, `omnitunctl` tells how
//! to store it with `omnitunctl secret set`. OpenVPN files: see [`openvpn`].

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Context;
use plist::{Dictionary, Value};

mod macos;
mod ovpn;
mod viscosity;
mod wireguard;
pub use macos::{MACOS_NETWORK_PREFERENCES, macos_vpns};
pub use ovpn::{MAX_SIZE as OPENVPN_MAX_SIZE, openvpn};
pub use viscosity::{VISCOSITY_LIBRARY, viscosity};
pub use wireguard::{WireGuardImport, is_wireguard, new_private_key, public_key, wireguard};

/// One connection found by an importer that reads another client's
/// settings: converted, or refused with the reason.
pub struct Found {
    /// The name the other client shows.
    pub display: String,
    pub result: anyhow::Result<Imported>,
}

pub const FORTICLIENT_PLIST: &str = "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist";

/// One converted profile: TOML text plus notes for the user.
pub struct Imported {
    pub name: String,
    pub toml: String,
    pub notes: Vec<String>,
    /// Authenticates with a pre-shared key, which FortiClient keeps
    /// encrypted: the user has to type it again.
    pub needs_psk: bool,
}

pub fn forticlient(path: &Path) -> anyhow::Result<Vec<Imported>> {
    let root = Value::from_file(path).with_context(|| format!("cannot read {}", path.display()))?;
    let profiles = root
        .as_dictionary()
        .and_then(|d| d.get("Profiles"))
        .and_then(Value::as_dictionary)
        .context("no Profiles in the FortiClient configuration")?;
    let mut out: Vec<Imported> = profiles.values().filter_map(Value::as_dictionary).map(convert).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn convert(p: &Dictionary) -> Imported {
    let display = text(p, "Name").unwrap_or_else(|| "forticlient".into());
    let name = profile_name(&display);
    match int(p, "VpnType") {
        Some(1) => ipsec(p, &display, name),
        _ => ssl(p, &display, name),
    }
}

fn ssl(p: &Dictionary, display: &str, name: String) -> Imported {
    let mut notes = Vec::new();
    let server = text(p, "Server").unwrap_or_default();
    // "Server" may carry the port ("vpn.example:10443").
    let (host, inline_port) = match server.rsplit_once(':') {
        Some((h, port)) if port.parse::<u16>().is_ok() => (h.to_owned(), port.parse().ok()),
        _ => (server.clone(), None),
    };
    let custom = if int(p, "EnableCustomPort") == Some(1) { int(p, "ServerPort") } else { None };
    let port = match custom {
        Some(port) => u16::try_from(port).ok().filter(|p| *p != 0).unwrap_or_else(|| {
            notes.push(format!("invalid port {port} in FortiClient: 443 used"));
            443
        }),
        None => inline_port.unwrap_or(443),
    };

    let mut t = header(display, "VPN SSL");
    line(&mut t, "name", &name);
    common(p, &mut t);
    line(&mut t, "protocol", "forti-ssl");
    line(&mut t, "host", &host);
    if port != 443 {
        writeln!(t, "port = {port}").unwrap();
    }
    let sso = int(p, "SSOEnabled") == Some(1);
    if sso {
        writeln!(t, "auth = {{ method = \"saml\", port = 8020 }}").unwrap();
        notes.push("SAML: the FortiGate must redirect to http://127.0.0.1:8020 (as for FortiClient)".into());
    } else if let Some(user) = text(p, "User").filter(|u| !u.is_empty()) {
        line(&mut t, "username", &user);
        notes.push(format!("password (optional, asked otherwise): {} secret set {name}", vpn_core::brand::CLI));
    }
    if int(p, "PromptForCertificate") == Some(1) {
        writeln!(
            t,
            "# client certificate required by FortiClient: a Keychain certificate\n\
             # client_certificate = \"<sha256>\" ({} identities), or PEM files\n\
             # client_cert = \"…\"\n# client_key = \"…\"",
            vpn_core::brand::CLI
        )
        .unwrap();
        notes.push("client certificate: choose it in the editor (Keychain)".into());
    }
    writeln!(
        t,
        "# Self-signed certificate? Connect once: you will be shown its\n# fingerprint and offered to save it here.\n# trusted_cert = [\"…\"]"
    )
    .unwrap();
    Imported { name, toml: t, notes, needs_psk: false }
}

fn ipsec(p: &Dictionary, display: &str, name: String) -> Imported {
    let mut notes = Vec::new();
    let version = match int(p, "IKEVersion").unwrap_or(1) {
        2 => 2u8,
        1 => 1,
        other => {
            notes.push(format!("unknown IKE version {other} in FortiClient: IKEv1 used"));
            1
        }
    };
    let mut t = header(display, &format!("IPsec IKEv{version}"));
    line(&mut t, "name", &name);
    common(p, &mut t);
    line(&mut t, "protocol", "ipsec");
    line(&mut t, "gateway", &text(p, "Server").unwrap_or_default());
    writeln!(t, "ike_version = {version}").unwrap();
    if version == 1 {
        let mode = if text(p, "ExchangeMode").as_deref() == Some("aggressive") { "aggressive" } else { "main" };
        line(&mut t, "exchange_mode", mode);
        writeln!(t, "xauth = {}", int(p, "EnableXAuth") == Some(1)).unwrap();
    }
    if let Some(user) = text(p, "User").filter(|u| !u.is_empty()) {
        line(&mut t, "username", &user);
        notes.push(format!("password (optional, asked otherwise): {} secret set {name}", vpn_core::brand::CLI));
    }
    if let Some(id) = text(p, "LocalID").filter(|v| !v.is_empty()) {
        line(&mut t, "local_id", &id);
    }
    let needs_psk = int(p, "AuthMethod").unwrap_or(0) == 0;
    if !needs_psk && version == 2 {
        notes.push("certificate authentication: choose the client certificate in the editor (Keychain)".into());
    } else if !needs_psk {
        notes.push("certificate authentication with IKEv1: not supported".into());
    }

    let ike_groups = dh_groups(p, "Phase1DHGroup");
    let ike: Vec<String> = proposals(p, "Phase1Proposals")
        .into_iter()
        .flat_map(|alg| ike_groups.iter().map(move |g| format!("{alg}-{g}")))
        .collect();
    if !ike.is_empty() {
        array(&mut t, "ike", &ike);
    }
    let pfs = if int(p, "Phase2PFSEnabled") == Some(1) { dh_groups(p, "Phase2DHGroup") } else { Vec::new() };
    let esp: Vec<String> = proposals(p, "Phase2Proposals")
        .into_iter()
        .flat_map(|alg| if pfs.is_empty() { vec![alg] } else { pfs.iter().map(|g| format!("{alg}-{g}")).collect() })
        .collect();
    if !esp.is_empty() {
        array(&mut t, "esp", &esp);
    }
    let legacy = vpn_core::LEGACY_ALGORITHMS
        .iter()
        .any(|legacy| ike.iter().chain(&esp).any(|s| s.split('-').any(|t| t == *legacy)));
    if legacy {
        writeln!(t, "legacy_algorithms = true").unwrap();
        notes.push("3DES or DH group 2 in use: legacy algorithms allowed for this VPN".into());
    }
    if [&ike, &esp]
        .iter()
        .any(|list| list.iter().any(|s| s.contains("sha1") || s.contains("modp1024") || s.contains("modp1536")))
    {
        notes.push(
            "weak algorithms (SHA1, DH 2/5) inherited from the FortiGate: to be modernized on the gateway".into(),
        );
    }
    if let Some(secs) = int(p, "Phase1KeyLifeSec").filter(|s| *s > 0) {
        writeln!(t, "phase1_lifetime = {secs}").unwrap();
    }
    let life_type = text(p, "Phase2KeyLifeType").unwrap_or_default().to_ascii_lowercase();
    if life_type != "kbytes"
        && let Some(secs) = int(p, "Phase2KeyLifeSec").filter(|s| *s > 0)
    {
        writeln!(t, "phase2_lifetime = {secs}").unwrap();
    }
    if (life_type == "kbytes" || life_type == "both")
        && let Some(kb) = int(p, "Phase2KeyLifeKbytes").filter(|s| *s > 0)
    {
        if life_type == "kbytes" {
            writeln!(t, "phase2_lifetime = 0").unwrap();
        }
        writeln!(t, "phase2_lifetime_kb = {kb}").unwrap();
    }
    if int(p, "EnableDPD") == Some(0) {
        writeln!(t, "dpd = false").unwrap();
    }
    if int(p, "EnableNATT") == Some(0) {
        notes.push("NAT traversal is turned off in FortiClient: this client always uses it".into());
    }
    if int(p, "EnableModeConfig") == Some(0) {
        notes.push("manual configuration (no Mode Config) is not supported".into());
    }
    if let Some(remote) = text(p, "RemoteNetAddress").filter(|v| !v.is_empty()) {
        writeln!(t, "# remote network declared in FortiClient: {remote}").unwrap();
    }
    Imported { name, toml: t, notes, needs_psk }
}

/// Settings FortiClient has for both kinds of VPN.
fn common(p: &Dictionary, t: &mut String) {
    if let Some(comment) = text(p, "Comment").filter(|c| !c.is_empty()) {
        let comment: String = comment.chars().filter(|c| !c.is_control()).take(256).collect();
        line(t, "description", &comment);
    }
    if int(p, "SavePassword") == Some(0) {
        writeln!(t, "save_password = false").unwrap();
    }
}

/// "AES128|SHA1,AES256|SHA256" → ["aes128-sha1", "aes256-sha256"].
fn proposals(p: &Dictionary, key: &str) -> Vec<String> {
    text(p, key)
        .unwrap_or_default()
        .split(',')
        .map(|prop| prop.split('|').map(|alg| alg.trim().to_ascii_lowercase()).collect::<Vec<_>>().join("-"))
        .filter(|s| !s.is_empty())
        .collect()
}

/// DH group numbers ("5" or "14,5") → strongSwan names.
fn dh_groups(p: &Dictionary, key: &str) -> Vec<String> {
    let raw = match p.get(key) {
        Some(Value::Integer(i)) => i.as_signed().map(|v| v.to_string()).unwrap_or_default(),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    raw.split([',', ' '])
        .filter_map(|g| g.trim().parse::<u32>().ok())
        .map(|g| match g {
            1 => "modp768".into(),
            2 => "modp1024".into(),
            5 => "modp1536".into(),
            14 => "modp2048".into(),
            15 => "modp3072".into(),
            16 => "modp4096".into(),
            17 => "modp6144".into(),
            18 => "modp8192".into(),
            19 => "ecp256".into(),
            20 => "ecp384".into(),
            21 => "ecp521".into(),
            31 => "x25519".into(),
            other => format!("dh{other}"),
        })
        .collect()
}

/// "HQ Paris" → "hq-paris" (session names: letters, digits, '-', '_', ≤ 32).
pub fn profile_name(display: &str) -> String {
    name_or(display, "forticlient")
}

/// A session name made of `display`, or `fallback` if nothing is left.
/// `display` as a profile name (the other client's name, as people know
/// it), or `fallback` if nothing is left: no `/` (it separates folders),
/// no control character, single spaces, 64 characters at most.
fn name_or(display: &str, fallback: &str) -> String {
    let cleaned: String = display
        .chars()
        .filter(|c| !vpn_core::is_invisible(*c))
        .map(|c| if c == '/' || c.is_control() { ' ' } else { c })
        .collect();
    let name: String = cleaned.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(64).collect();
    let name = name.trim_end().to_owned();
    if name.is_empty() { fallback.into() } else { name }
}

fn header(display: &str, kind: &str) -> String {
    let display: String = display.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!("# Imported from FortiClient: \"{display}\" ({kind})\n[[profile]]\n")
}

fn line(t: &mut String, key: &str, value: &str) {
    writeln!(t, "{key} = {}", quote(value)).unwrap();
}

fn array(t: &mut String, key: &str, values: &[String]) {
    let items: Vec<String> = values.iter().map(|v| quote(v)).collect();
    writeln!(t, "{key} = [{}]", items.join(", ")).unwrap();
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn text(p: &Dictionary, key: &str) -> Option<String> {
    match p.get(key)? {
        Value::String(s) if s != "$null" => Some(s.trim().to_owned()),
        Value::Integer(i) => i.as_signed().map(|v| v.to_string()),
        _ => None,
    }
}

fn int(p: &Dictionary, key: &str) -> Option<i64> {
    match p.get(key)? {
        Value::Integer(i) => i.as_signed(),
        Value::Boolean(b) => Some(*b as i64),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_core::{ExchangeMode, ProfileFile, ProtocolConfig};

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Profiles</key><dict>
    <key>Branch IPsec</key><dict>
      <key>Name</key><string>Branch IPsec</string>
      <key>VpnType</key><integer>1</integer>
      <key>Server</key><string>203.0.113.68</string>
      <key>User</key><string>alice</string>
      <key>IKEVersion</key><integer>1</integer>
      <key>ExchangeMode</key><string>aggressive</string>
      <key>EnableXAuth</key><integer>1</integer>
      <key>AuthMethod</key><integer>0</integer>
      <key>AuthInfo</key><string>Enc 00ff</string>
      <key>LocalID</key><string></string>
      <key>Phase1Proposals</key><string>AES128|SHA1,AES256|SHA256</string>
      <key>Phase1DHGroup</key><integer>5</integer>
      <key>Phase2Proposals</key><string>AES128|SHA1,AES256|SHA1</string>
      <key>Phase2PFSEnabled</key><integer>1</integer>
      <key>Phase2DHGroup</key><integer>5</integer>
      <key>Phase1KeyLifeSec</key><integer>28800</integer>
      <key>Phase2KeyLifeType</key><string>both</string>
      <key>Phase2KeyLifeSec</key><integer>3600</integer>
      <key>Phase2KeyLifeKbytes</key><integer>5120</integer>
      <key>EnableDPD</key><integer>0</integer>
      <key>Comment</key><string>Branch office</string>
      <key>SavePassword</key><integer>0</integer>
    </dict>
    <key>HQ SSL</key><dict>
      <key>Name</key><string>HQ SSL</string>
      <key>VpnType</key><integer>0</integer>
      <key>Server</key><string>vpn.example.org</string>
      <key>EnableCustomPort</key><integer>1</integer>
      <key>ServerPort</key><integer>4443</integer>
      <key>User</key><string>alice</string>
      <key>SSOEnabled</key><integer>0</integer>
    </dict>
  </dict>
</dict></plist>"#;

    fn import(sample: &str, tag: &str) -> Vec<Imported> {
        let dir = std::env::temp_dir().join(format!("{}-import-{tag}-{}", vpn_core::brand::CLI, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vpn.plist");
        std::fs::write(&path, sample).unwrap();
        let imported = forticlient(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        imported
    }

    #[test]
    fn imports_forticlient_profiles() {
        let imported = import(SAMPLE, "modern");

        let text: String = imported.iter().map(|i| i.toml.clone() + "\n").collect();
        assert!(!text.contains("00ff"), "secrets must not be imported");
        let file: ProfileFile = toml::from_str(&text).unwrap();
        assert_eq!(file.profiles.len(), 2);

        let ipsec = file.profiles.iter().find(|p| p.name == "Branch IPsec").unwrap();
        let ProtocolConfig::Ipsec(i) = &ipsec.protocol else { panic!() };
        assert_eq!((i.ike_version, i.exchange_mode, i.xauth), (1, ExchangeMode::Aggressive, true));
        assert_eq!(i.ike, ["aes128-sha1-modp1536", "aes256-sha256-modp1536"]);
        assert_eq!(i.esp, ["aes128-sha1-modp1536", "aes256-sha1-modp1536"]);
        assert_eq!(i.username.as_deref(), Some("alice"));
        assert_eq!(
            (i.phase1_lifetime, i.phase2_lifetime, i.phase2_lifetime_kb, i.dpd),
            (28800, 3600, Some(5120), false)
        );
        assert_eq!((ipsec.description.as_deref(), ipsec.save_password), (Some("Branch office"), false));
        assert!(!i.legacy_algorithms);

        let ssl = file.profiles.iter().find(|p| p.name == "HQ SSL").unwrap();
        let ProtocolConfig::FortiSsl(s) = &ssl.protocol else { panic!() };
        assert_eq!((s.host.as_str(), s.port), ("vpn.example.org", 4443));
        assert!(ssl.save_password && ssl.description.is_none());
        let needs_psk: Vec<_> = imported.iter().filter(|i| i.needs_psk).map(|i| i.name.as_str()).collect();
        assert_eq!(needs_psk, ["Branch IPsec"]);
    }

    /// An old gateway's 3DES and group 2 are imported with the legacy
    /// algorithms allowed, so the profile still validates.
    #[test]
    fn legacy_configs_allow_legacy_algorithms() {
        let old = SAMPLE
            .replace("AES128|SHA1,AES256|SHA256", "3DES|SHA1")
            .replace("<key>Phase1DHGroup</key><integer>5</integer>", "<key>Phase1DHGroup</key><integer>2</integer>");
        let imported = import(&old, "legacy");
        let branch = imported.iter().find(|i| i.toml.contains("Branch IPsec")).unwrap();
        assert!(branch.notes.iter().any(|n| n.contains("legacy")), "{:?}", branch.notes);
        let file: ProfileFile = toml::from_str(&branch.toml).unwrap();
        let ProtocolConfig::Ipsec(i) = &file.profiles[0].protocol else { panic!() };
        assert_eq!(i.ike, ["3des-sha1-modp1024"]);
        assert!(i.legacy_algorithms);
        file.profiles[0].validate().unwrap();
    }

    #[test]
    fn names() {
        assert_eq!(profile_name("HQ Paris"), "HQ Paris");
        assert_eq!(profile_name("  Paris / HQ  "), "Paris HQ");
        assert_eq!(profile_name(" / "), "forticlient");
        let name = profile_name("Paris\u{200b} HQ\u{202e}");
        assert_eq!(name, "Paris HQ");
        assert!(vpn_core::profile::valid_name(&name));
    }

    /// Out-of-range numbers are not truncated into other valid ones.
    #[test]
    fn out_of_range_numbers() {
        let odd = SAMPLE
            .replace("<integer>4443</integer>", "<integer>70000</integer>")
            .replace("<key>IKEVersion</key><integer>1</integer>", "<key>IKEVersion</key><integer>258</integer>");
        let imported = import(&odd, "range");
        let text: String = imported.iter().map(|i| i.toml.clone() + "\n").collect();
        let file: ProfileFile = toml::from_str(&text).unwrap();
        let ssl = file.profiles.iter().find(|p| p.name == "HQ SSL").unwrap();
        assert_eq!(ssl.protocol.endpoint().1, 443, "not 70000 as 4464");
        let ipsec = file.profiles.iter().find(|p| p.name == "Branch IPsec").unwrap();
        let ProtocolConfig::Ipsec(i) = &ipsec.protocol else { panic!() };
        assert_eq!(i.ike_version, 1, "not 258 as 2");
        assert!(
            imported.iter().all(|i| i.notes.iter().any(|n| n.contains("invalid port") || n.contains("IKE version")))
        );
    }
}
