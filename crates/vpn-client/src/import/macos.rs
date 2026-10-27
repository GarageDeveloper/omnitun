//! Import of the VPN connections of macOS's System Settings, from the
//! network configuration (`preferences.plist`). "Cisco IPSec" connections
//! are IKEv1 with XAuth: aggressive mode with the group name as identity,
//! main mode without one. Their shared secret and password stay in the
//! System keychain, which only the system may read: the user types them
//! again. "L2TP over IPsec" connections keep their IPsec settings in the
//! same service, their PPP ones beside; IKEv2 connections are listed, not
//! converted.

use std::path::Path;

use anyhow::{Context, bail};
use plist::{Dictionary, Value};
use vpn_core::{ExchangeMode, Profile, ProfileFile, ProtocolConfig, valid_domain};

use super::{Found, Imported};

pub const MACOS_NETWORK_PREFERENCES: &str = "/Library/Preferences/SystemConfiguration/preferences.plist";

/// What macOS's IKEv1 client proposes, legacy algorithms last: servers
/// that work with macOS (Meraki: 3DES or AES-128, SHA-1, DH group 2) must
/// work here too.
const IKE_PROPOSALS: [&str; 9] = [
    "aes256-sha256-modp2048",
    "aes256-sha1-modp2048",
    "aes128-sha1-modp2048",
    "aes256-sha256-modp1536",
    "aes256-sha1-modp1536",
    "aes128-sha1-modp1536",
    "aes256-sha1-modp1024",
    "aes128-sha1-modp1024",
    "3des-sha1-modp1024",
];
const ESP_PROPOSALS: [&str; 5] = ["aes256-sha256", "aes256-sha1", "aes128-sha256", "aes128-sha1", "3des-sha1"];

/// The VPN services of the network configuration at `path` (macOS's own
/// when None), in name order. Services of other apps' VPNs (FortiClient,
/// …) are left out: their settings are theirs.
pub fn macos_vpns(path: Option<&Path>, existing: &[String]) -> anyhow::Result<Vec<Found>> {
    let path = path.unwrap_or(Path::new(MACOS_NETWORK_PREFERENCES));
    let root = Value::from_file(path).with_context(|| format!("cannot read {}", path.display()))?;
    let services = root
        .as_dictionary()
        .and_then(|d| d.get("NetworkServices"))
        .and_then(Value::as_dictionary)
        .context("no network services in the macOS configuration")?;
    let mut services: Vec<(String, &Dictionary)> = services
        .values()
        .filter_map(Value::as_dictionary)
        .filter_map(|s| Some((text(s, &["UserDefinedName"])?, s)))
        .collect();
    services.sort_by(|a, b| a.0.cmp(&b.0));
    let mut taken = existing.to_vec();
    let mut out = Vec::new();
    for (display, service) in services {
        let kind = (text(service, &["Interface", "Type"]), text(service, &["Interface", "SubType"]));
        let result = match (kind.0.as_deref(), kind.1.as_deref()) {
            (Some("IPSec"), _) => cisco_ipsec(service, &display, &taken),
            (Some("PPP"), Some("L2TP")) => l2tp(service, &display, &taken),
            (Some("VPN"), Some(sub)) if sub.starts_with("com.apple.") => {
                Err(anyhow::anyhow!("IKEv2 connections of System Settings cannot be read yet: create it in the editor"))
            }
            _ => continue,
        };
        if let Ok(imported) = &result {
            taken.push(imported.name.clone());
        }
        out.push(Found { display, result });
    }
    Ok(out)
}

fn cisco_ipsec(service: &Dictionary, display: &str, existing: &[String]) -> anyhow::Result<Imported> {
    let ipsec = service.get("IPSec").and_then(Value::as_dictionary).context("no IPsec settings")?;
    let get = |key: &str| text(ipsec, &[key]).filter(|v| !v.is_empty());
    match get("AuthenticationMethod").as_deref() {
        None | Some("SharedSecret") => {}
        Some("Certificate") => bail!("certificate authentication with IKEv1 is not supported"),
        Some(other) => bail!("{other} authentication is not supported"),
    }
    let gateway = get("RemoteAddress").context("no server address")?;
    let mut notes = Vec::new();
    let group = get("LocalIdentifier");
    let xauth = int(ipsec, "XAuthEnabled").is_none_or(|x| x != 0);
    let saved_password = get("XAuthPasswordEncryption").as_deref() != Some("Prompt");

    let base = super::name_or(display, "macos");
    let name = super::ovpn::free_name(&base, existing);
    if name != base {
        notes.push(format!("a VPN named {base} exists already: imported as {name}"));
    }
    let mut profile: Profile = toml::from_str(&format!(
        "name = {}\nprotocol = \"ipsec\"\ngateway = {}\nike_version = 1",
        quote(&name),
        quote(&gateway)
    ))
    .context("invalid server address")?;
    profile.description = Some(display.chars().filter(|c| !c.is_control()).take(256).collect());
    profile.save_password = saved_password;
    let ProtocolConfig::Ipsec(p) = &mut profile.protocol else { unreachable!() };
    // macOS uses aggressive mode with the group name, main mode without.
    p.exchange_mode = if group.is_some() { ExchangeMode::Aggressive } else { ExchangeMode::Main };
    p.local_id = group;
    p.xauth = xauth;
    p.username = get("XAuthName").filter(|_| xauth);
    p.ike = IKE_PROPOSALS.map(String::from).to_vec();
    p.esp = ESP_PROPOSALS.map(String::from).to_vec();
    p.legacy_algorithms = true;
    let main_mode = p.exchange_mode == ExchangeMode::Main;
    profile.validate().context("the imported profile is not valid")?;
    notes.push(
        "proposals: those macOS offers, the legacy ones (3DES, DH group 2) last and allowed; if the server \
         accepts AES with DH 14, they can be turned off in the editor"
            .into(),
    );
    if main_mode {
        notes.push("no group name: main mode, as macOS does".into());
    }
    finish(profile, display, notes)
}

/// An "L2TP over IPsec" service: the server and user in `PPP`, the group
/// name and shared secret in `IPSec`.
fn l2tp(service: &Dictionary, display: &str, existing: &[String]) -> anyhow::Result<Imported> {
    let dict = |key: &str| service.get(key).and_then(Value::as_dictionary);
    let ppp = dict("PPP").context("no PPP settings")?;
    let empty = Dictionary::new();
    let ipsec = dict("IPSec").unwrap_or(&empty);
    let get = |d: &Dictionary, key: &str| text(d, &[key]).filter(|v| !v.is_empty());
    match get(ipsec, "AuthenticationMethod").as_deref() {
        None | Some("SharedSecret") => {}
        Some("Certificate") => bail!("certificate authentication with L2TP is not supported"),
        Some(other) => bail!("{other} authentication is not supported"),
    }
    let gateway = get(ppp, "CommRemoteAddress").context("no server address")?;
    let mut notes = Vec::new();
    let base = super::name_or(display, "macos");
    let name = super::ovpn::free_name(&base, existing);
    if name != base {
        notes.push(format!("a VPN named {base} exists already: imported as {name}"));
    }
    let mut profile: Profile =
        toml::from_str(&format!("name = {}\nprotocol = \"l2tp\"\ngateway = {}", quote(&name), quote(&gateway)))
            .context("invalid server address")?;
    profile.description = Some(display.chars().filter(|c| !c.is_control()).take(256).collect());
    // Saved in the System keychain, or asked at each connection.
    profile.save_password = get(ppp, "AuthPasswordEncryption").as_deref() == Some("Keychain");
    if dict("IPv4").and_then(|d| int(d, "OverridePrimary")).is_some_and(|v| v != 0) {
        profile.full_tunnel = Some(true);
    }
    let strings = |key: &str| -> Vec<String> {
        let list = dict("DNS").and_then(|d| d.get(key)).and_then(Value::as_array);
        list.into_iter().flatten().filter_map(Value::as_string).map(|s| s.trim().to_owned()).collect()
    };
    let domains = strings("SearchDomains");
    profile.dns_domains = domains.iter().filter(|d| valid_domain(d)).cloned().collect();
    let ProtocolConfig::L2tp(p) = &mut profile.protocol else { unreachable!() };
    p.username = get(ppp, "AuthName");
    p.local_id = get(ipsec, "LocalIdentifier");
    p.ike = IKE_PROPOSALS.map(String::from).to_vec();
    p.esp = ESP_PROPOSALS.map(String::from).to_vec();
    p.legacy_algorithms = true;
    let servers = strings("ServerAddresses");
    p.dns_servers = servers.iter().filter_map(|s| s.parse().ok()).take(4).collect();
    if p.dns_servers.len() < servers.len() || profile.dns_domains.len() < domains.len() {
        notes.push("some DNS servers or search domains were left out (invalid, or more than 4 servers)".into());
    }
    let main_mode = p.local_id.is_none();
    profile.validate().context("the imported profile is not valid")?;
    let (secrets, them) = if profile.save_password {
        ("the shared secret and the password stay", "them")
    } else {
        ("the shared secret stays", "it")
    };
    notes.push(format!("{secrets} in the System keychain, which only macOS may read: type {them} again"));
    notes.push(
        "proposals: those macOS offers, the legacy ones (3DES, DH group 2) last and allowed; if the server \
         accepts AES with DH 14, they can be turned off in the editor"
            .into(),
    );
    if main_mode {
        notes.push("no group name: main mode, as macOS does".into());
    }
    if int(ppp, "CCPEnabled").is_some_and(|v| v != 0) {
        notes.push("PPP compression is not supported: ignored".into());
    }
    if int(ppp, "DisconnectOnIdle").is_some_and(|v| v != 0) {
        notes.push("disconnecting when idle is not supported: ignored".into());
    }
    finish(profile, display, notes)
}

/// The profile file of one imported connection; it always needs the PSK.
fn finish(profile: Profile, display: &str, notes: Vec<String>) -> anyhow::Result<Imported> {
    let name = profile.name.clone();
    let body = toml::to_string(&ProfileFile { profiles: vec![profile] })?;
    let display: String = display.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let toml = format!("# Imported from macOS (System Settings): \"{display}\"\n{body}");
    Ok(Imported { name, toml, notes, needs_psk: true })
}

/// A TOML string.
fn quote(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

fn text(dict: &Dictionary, path: &[&str]) -> Option<String> {
    let (last, parents) = path.split_last()?;
    let mut dict = dict;
    for key in parents {
        dict = dict.get(key)?.as_dictionary()?;
    }
    dict.get(last)?.as_string().map(str::to_owned)
}

fn int(dict: &Dictionary, key: &str) -> Option<i64> {
    dict.get(key)?.as_signed_integer()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(name: &str, kind: &str, subtype: Option<&str>, ipsec: &[(&str, Value)]) -> Value {
        let mut interface = Dictionary::new();
        interface.insert("Type".into(), kind.into());
        if let Some(sub) = subtype {
            interface.insert("SubType".into(), sub.into());
        }
        let mut s = Dictionary::new();
        s.insert("UserDefinedName".into(), name.into());
        s.insert("Interface".into(), Value::Dictionary(interface));
        s.insert("IPSec".into(), Value::Dictionary(ipsec.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()));
        Value::Dictionary(s)
    }

    fn dict(entries: &[(&str, Value)]) -> Value {
        Value::Dictionary(entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
    }

    fn read(root: Dictionary, test: &str, existing: &[String]) -> Vec<Found> {
        let path = std::env::temp_dir().join(format!("omnitun-macos-{test}-{}.plist", std::process::id()));
        Value::Dictionary(root).to_file_xml(&path).unwrap();
        let found = macos_vpns(Some(&path), existing).unwrap();
        std::fs::remove_file(&path).unwrap();
        found
    }

    /// An "L2TP over IPsec" service as System Settings writes it.
    fn l2tp_service(name: &str, ipsec: &[(&str, Value)], ppp: &[(&str, Value)]) -> Value {
        let mut s = service(name, "PPP", Some("L2TP"), ipsec);
        let s_dict = s.as_dictionary_mut().unwrap();
        let mut settings = vec![
            ("ACSPEnabled", Value::from(0)),
            ("CommDisplayTerminalWindow", 0.into()),
            ("CommRedialCount", 1.into()),
            ("CommRedialEnabled", 1.into()),
            ("CommRedialInterval", 5.into()),
            ("CommRemoteAddress", "l2tp.example.com".into()),
            ("CommUseTerminalScript", 0.into()),
            ("DialOnDemand", 0.into()),
            ("DisconnectOnFastUserSwitch", 1.into()),
            ("DisconnectOnIdle", 1.into()),
            ("DisconnectOnIdleTimer", 600.into()),
            ("DisconnectOnLogout", 1.into()),
            ("DisconnectOnSleep", 1.into()),
            ("IPCPCompressionVJ", 0.into()),
            ("IdleReminder", 0.into()),
            ("LCPEchoEnabled", 1.into()),
            ("LCPEchoFailure", 15.into()),
            ("LCPEchoInterval", 20.into()),
            ("Logfile", "/var/log/ppp.log".into()),
            ("VerboseLogging", 0.into()),
        ];
        settings.extend(ppp.iter().cloned());
        s_dict.insert("PPP".into(), dict(&settings));
        s_dict.insert("IPv4".into(), dict(&[("ConfigMethod", "PPP".into()), ("OverridePrimary", 1.into())]));
        s_dict.insert("IPv6".into(), dict(&[("ConfigMethod", "Automatic".into())]));
        s_dict.insert(
            "DNS".into(),
            dict(&[
                ("ServerAddresses", Value::Array(vec!["10.0.0.53".into(), "not an address".into(), "fd00::53".into()])),
                ("SearchDomains", Value::Array(vec!["corp.example".into(), "bad domain".into()])),
            ]),
        );
        s
    }

    #[test]
    fn imports_l2tp() {
        let ipsec = [
            ("AuthenticationMethod", Value::from("SharedSecret")),
            ("LocalIdentifier", "meraki".into()),
            ("LocalIdentifierType", "KeyID".into()),
            ("SharedSecret", "ABCD-1234.SS".into()),
            ("SharedSecretEncryption", "Keychain".into()),
        ];
        let saved = [
            ("AuthName", Value::from("alice")),
            ("AuthPassword", "ABCD-1234".into()),
            ("AuthPasswordEncryption", "Keychain".into()),
            ("CCPEnabled", 1.into()),
        ];
        let mut services = Dictionary::new();
        services.insert("1".into(), l2tp_service("Meraki Lyon", &ipsec, &saved));
        // No group name, password asked each time.
        let asked = [("AuthName", Value::from("bob")), ("AuthPasswordEncryption", "Prompt".into())];
        services.insert("2".into(), l2tp_service("Office", &ipsec[3..], &asked));
        let cert = [("AuthenticationMethod", Value::from("Certificate"))];
        services.insert("3".into(), l2tp_service("With certificate", &cert, &[]));
        let mut root = Dictionary::new();
        root.insert("NetworkServices".into(), Value::Dictionary(services));
        let found = read(root, "l2tp", &[]);
        assert_eq!(found.len(), 3);

        let lyon = found[0].result.as_ref().unwrap();
        assert!(lyon.needs_psk);
        assert!(!lyon.toml.contains("ABCD-1234"), "keychain references are not imported");
        let file: ProfileFile = toml::from_str(&lyon.toml).unwrap();
        let profile = &file.profiles[0];
        profile.validate().unwrap();
        assert_eq!(
            (profile.name.as_str(), profile.save_password, profile.full_tunnel),
            ("Meraki Lyon", true, Some(true))
        );
        assert_eq!(profile.dns_domains, ["corp.example"]);
        let ProtocolConfig::L2tp(p) = &profile.protocol else { panic!() };
        assert_eq!(
            (p.gateway.as_str(), p.username.as_deref(), p.local_id.as_deref()),
            ("l2tp.example.com", Some("alice"), Some("meraki"))
        );
        assert_eq!(p.dns_servers, ["10.0.0.53".parse::<std::net::IpAddr>().unwrap(), "fd00::53".parse().unwrap()]);
        assert_eq!(p.ipsec().ike_version, 1);
        assert!(lyon.notes.iter().any(|n| n.contains("compression")));
        assert!(lyon.notes.iter().any(|n| n.contains("idle")));
        assert!(lyon.notes.iter().any(|n| n.contains("left out")));

        let office: ProfileFile = toml::from_str(&found[1].result.as_ref().unwrap().toml).unwrap();
        assert!(!office.profiles[0].save_password);
        let ProtocolConfig::L2tp(p) = &office.profiles[0].protocol else { panic!() };
        assert_eq!((p.username.as_deref(), p.local_id.as_deref()), (Some("bob"), None));
        assert_eq!(p.ipsec().exchange_mode, ExchangeMode::Main);
        let refused = found[2].result.as_ref().map(|_| ()).unwrap_err().to_string();
        assert!(refused.contains("certificate"));
    }

    #[test]
    fn imports_cisco_ipsec() {
        let mut services = Dictionary::new();
        let common = [
            ("RemoteAddress", Value::from("vpn.example.com")),
            ("AuthenticationMethod", "SharedSecret".into()),
            ("SharedSecret", "ABCD-1234.SS".into()),
            ("SharedSecretEncryption", "Keychain".into()),
            ("XAuthEnabled", 1.into()),
            ("XAuthName", "alice".into()),
            ("XAuthPassword", "ABCD-1234.XAUTH".into()),
            ("XAuthPasswordEncryption", "Keychain".into()),
        ];
        let mut grouped = common.to_vec();
        grouped.push(("LocalIdentifier", "staff".into()));
        grouped.push(("LocalIdentifierType", "KeyID".into()));
        services.insert("1".into(), service("Bureau", "IPSec", None, &grouped));
        services.insert("2".into(), service("Forti HQ", "IPSec", None, &common));
        services.insert("3".into(), service("Office Paris", "VPN", Some("com.apple.neplugin.IKEv2"), &[]));
        services.insert("4".into(), service("FortiClient", "VPN", Some("com.fortinet.forticlient.macos.vpn"), &[]));
        services.insert("5".into(), service("Wi-Fi", "Ethernet", None, &[]));
        services.insert("6".into(), service("Cert", "IPSec", None, &[("AuthenticationMethod", "Certificate".into())]));
        let mut root = Dictionary::new();
        root.insert("NetworkServices".into(), Value::Dictionary(services));
        let found = read(root, "cisco", &["Bureau".into()]);

        let names: Vec<&str> = found.iter().map(|f| f.display.as_str()).collect();
        assert_eq!(names, ["Bureau", "Cert", "Forti HQ", "Office Paris"], "other apps and interfaces left out");
        let bureau = found[0].result.as_ref().unwrap();
        assert_eq!(bureau.name, "Bureau 2");
        assert!(bureau.needs_psk);
        assert!(!bureau.toml.contains("ABCD-1234"), "keychain references are not imported");
        let file: ProfileFile = toml::from_str(&bureau.toml).unwrap();
        let ProtocolConfig::Ipsec(p) = &file.profiles[0].protocol else { panic!() };
        assert_eq!((p.exchange_mode, p.local_id.as_deref(), p.xauth), (ExchangeMode::Aggressive, Some("staff"), true));
        assert_eq!((p.username.as_deref(), p.ike_version), (Some("alice"), 1));
        file.profiles[0].validate().unwrap();
        let hq: ProfileFile = toml::from_str(&found[2].result.as_ref().unwrap().toml).unwrap();
        let ProtocolConfig::Ipsec(p) = &hq.profiles[0].protocol else { panic!() };
        assert_eq!(p.exchange_mode, ExchangeMode::Main);
        assert!(found[1].result.is_err() && found[3].result.is_err());
    }
}
