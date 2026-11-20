//! Import of FortiClient's VPNs on Windows, where it keeps them in the
//! registry rather than in a `vpn.plist`: one key per VPN under
//! `Software\Fortinet\FortiClient\Sslvpn\Tunnels` (SSL VPN) and
//! `…\IPSec\Tunnels`, in the user's hive or the machine's (tunnels
//! deployed for everyone); the user's wins. The SSL VPNs' values are read
//! into the entries of the macOS file and converted the same way. IPsec
//! VPNs are listed but not converted: their settings are not read yet.
//!
//! The value names are those FortiClient is known to write (`Server` as
//! `host:port`, `Description`) and those of its XML configuration
//! (`sso_enabled`, `promptcertificate`, `username`); a value that is not
//! there is left to the editor. Secrets are encrypted: never read.

use std::collections::BTreeMap;

use plist::{Dictionary, Value};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

use super::Found;

const SSL: &str = r"Software\Fortinet\FortiClient\Sslvpn\Tunnels";
const IPSEC: &str = r"Software\Fortinet\FortiClient\IPSec\Tunnels";
/// Most VPNs read of each kind.
const MAX_TUNNELS: usize = 64;

/// FortiClient's VPNs: SSL VPNs converted, IPsec VPNs refused with the
/// reason.
pub fn forticlient_windows() -> anyhow::Result<Vec<Found>> {
    let ssl = tunnels(SSL);
    let ipsec = tunnels(IPSEC);
    if ssl.is_empty() && ipsec.is_empty() {
        anyhow::bail!("no FortiClient VPN in the registry");
    }
    let mut out = Vec::new();
    for (name, key) in ssl {
        let entry = ssl_entry(
            &name,
            |value| key.get_value::<String, _>(value).ok(),
            |value| key.get_value::<u32, _>(value).ok(),
        );
        out.push(Found { display: name, result: Ok(super::convert(&entry)) });
    }
    for (name, key) in ipsec {
        let gateway = key.get_value::<String, _>("Server").unwrap_or_default();
        out.push(Found {
            result: Err(anyhow::anyhow!(
                "FortiClient's IPsec VPNs are not read on Windows yet: create it in the editor{}",
                if gateway.is_empty() { String::new() } else { format!(" (gateway {gateway})") }
            )),
            display: name,
        });
    }
    Ok(out)
}

/// The VPN keys under `path`, the user's then the machine's, by name.
fn tunnels(path: &str) -> BTreeMap<String, RegKey> {
    let mut found = BTreeMap::new();
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let Ok(parent) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ) else { continue };
        for name in parent.enum_keys().filter_map(Result::ok).take(MAX_TUNNELS) {
            if let Ok(key) = parent.open_subkey_with_flags(&name, KEY_READ) {
                // The user's, read last, replaces the machine's.
                found.insert(name, key);
            }
        }
    }
    found.into_iter().take(MAX_TUNNELS).collect()
}

/// An SSL VPN's registry values as the entry of FortiClient's macOS file.
fn ssl_entry(name: &str, text: impl Fn(&str) -> Option<String>, number: impl Fn(&str) -> Option<u32>) -> Dictionary {
    let mut entry = Dictionary::new();
    entry.insert("Name".into(), Value::String(name.to_owned()));
    entry.insert("VpnType".into(), Value::Integer(0.into()));
    if let Some(server) = text("Server") {
        entry.insert("Server".into(), Value::String(server.trim().to_owned()));
    }
    if let Some(description) = text("Description").filter(|d| !d.trim().is_empty()) {
        entry.insert("Comment".into(), Value::String(description));
    }
    // Encrypted by recent versions ("Enc …"): left to the user.
    if let Some(user) = text("username").filter(|u| !u.is_empty() && !u.starts_with("Enc ")) {
        entry.insert("User".into(), Value::String(user));
    }
    let flag = |value: &str| number(value).or_else(|| text(value).and_then(|t| t.trim().parse().ok()));
    if flag("sso_enabled") == Some(1) {
        entry.insert("SSOEnabled".into(), Value::Integer(1.into()));
    }
    if flag("promptcertificate") == Some(1) {
        entry.insert("PromptForCertificate".into(), Value::Integer(1.into()));
    }
    entry
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn convert(values: &[(&str, &str)], numbers: &[(&str, u32)]) -> super::super::Imported {
        let values: HashMap<_, _> = values.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).collect();
        let numbers: HashMap<_, _> = numbers.iter().map(|(k, v)| (k.to_ascii_lowercase(), *v)).collect();
        let entry = ssl_entry(
            "Head Office",
            |k| values.get(&k.to_ascii_lowercase()).cloned(),
            |k| numbers.get(&k.to_ascii_lowercase()).copied(),
        );
        super::super::convert(&entry)
    }

    #[test]
    fn ssl_vpn_from_the_registry() {
        let i = convert(&[("Server", "vpn.example.com:10443"), ("Description", "HQ"), ("username", "alice")], &[]);
        let file: vpn_core::ProfileFile = toml::from_str(&i.toml).unwrap();
        let p = &file.profiles[0];
        assert_eq!(p.name, "Head Office");
        assert!(i.toml.contains("host = \"vpn.example.com\""), "{}", i.toml);
        assert!(i.toml.contains("port = 10443"), "{}", i.toml);
        assert!(i.toml.contains("username = \"alice\""), "{}", i.toml);
        assert!(i.toml.contains("description = \"HQ\""), "{}", i.toml);
    }

    #[test]
    fn saml_and_encrypted_user() {
        let i = convert(&[("Server", "vpn.example.com"), ("username", "Enc 0a1b2c")], &[("sso_enabled", 1)]);
        assert!(i.toml.contains("method = \"saml\""), "{}", i.toml);
        assert!(!i.toml.contains("username"), "{}", i.toml);
        assert!(!i.toml.contains("\nport ="), "{}", i.toml);
    }
}
