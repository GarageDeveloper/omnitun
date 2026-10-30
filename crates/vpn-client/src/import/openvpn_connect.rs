//! Import of OpenVPN Connect profiles. OpenVPN Connect keeps a copy of
//! each imported configuration, files inlined, as `profiles/<id>.ovpn` in
//! its folder; the names people know them by are in its `config.json`,
//! under `persist:root` → `status` → `profiles` → `<id>`, each level a
//! JSON document stored as a string. Passwords stay in its Keychain items:
//! never read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use zeroize::Zeroizing;

use super::Found;

/// OpenVPN Connect's folder, under the user's home.
pub const OPENVPN_CONNECT_DIR: &str = "Library/Application Support/OpenVPN Connect";

/// The profiles of OpenVPN Connect's folder (`path` None, or another
/// folder of the same layout), in the order they were imported.
pub fn openvpn_connect(path: Option<&Path>, existing: &[String]) -> anyhow::Result<Vec<Found>> {
    let dir = match path {
        Some(path) => path.to_owned(),
        None => std::env::var_os("HOME").map(PathBuf::from).context("no home folder")?.join(OPENVPN_CONNECT_DIR),
    };
    let folder = dir.join("profiles");
    let entries =
        std::fs::read_dir(&folder).with_context(|| format!("no OpenVPN Connect profiles in {}", folder.display()))?;
    let mut files: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "ovpn"))
        .filter_map(|p| Some((p.file_stem()?.to_string_lossy().into_owned(), p)))
        .collect();
    // Ids are the import times, in milliseconds.
    files.sort_by_key(|(id, _)| (id.parse::<u64>().unwrap_or(u64::MAX), id.clone()));
    let skipped = files.len().saturating_sub(MAX_PROFILES);
    files.truncate(MAX_PROFILES);
    // Without its names, the profiles are still worth offering.
    let names = names(&dir.join("config.json")).unwrap_or_default();
    let mut taken = existing.to_vec();
    let mut out = Vec::new();
    for (id, file) in files {
        let display = names.get(&id).cloned().unwrap_or_else(|| id.clone());
        let base = super::name_or(&display, "openvpn");
        let origin = format!("OpenVPN Connect: \"{display}\"");
        let result = super::ovpn::convert_file(&file, &base, Some(&display), &origin, &taken);
        if let Ok(imported) = &result {
            taken.push(imported.name.clone());
        }
        out.push(Found { display, result });
    }
    // Said, not silently dropped: the most recent are the ones left out.
    if skipped > 0 {
        out.push(Found {
            display: format!("{skipped} more"),
            result: Err(anyhow::anyhow!("not read: at most {MAX_PROFILES} profiles are imported at a time")),
        });
    }
    Ok(out)
}

/// Most profiles read from the folder.
const MAX_PROFILES: usize = 64;

/// Above this, `config.json` is not OpenVPN Connect's.
const MAX_CONFIG_SIZE: u64 = 16 * 1024 * 1024;

/// The fields of a profile's entry that name it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(default)]
    profile_display_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// The names shown for each profile id. The file also holds the content
/// of the last profile read, keys included: wiped once parsed.
fn names(config: &Path) -> anyhow::Result<HashMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(rename = "persist:root")]
        root: String,
    }
    #[derive(serde::Deserialize)]
    struct Root {
        status: String,
    }
    #[derive(serde::Deserialize)]
    struct Status {
        #[serde(default)]
        profiles: HashMap<String, Entry>,
    }
    let size = std::fs::metadata(config)?.len();
    anyhow::ensure!(size <= MAX_CONFIG_SIZE, "{} is too large", config.display());
    let text = Zeroizing::new(std::fs::read_to_string(config)?);
    let root = Zeroizing::new(serde_json::from_str::<File>(&text)?.root);
    let status = Zeroizing::new(serde_json::from_str::<Root>(&root)?.status);
    let status: Status = serde_json::from_str(&status)?;
    Ok(status
        .profiles
        .into_iter()
        .filter_map(|(id, entry)| {
            let shown = [entry.profile_display_name, entry.name]
                .into_iter()
                .flatten()
                .map(|n| {
                    let n: String =
                        n.chars().filter(|c| !c.is_control() && !vpn_core::is_invisible(*c)).take(128).collect();
                    n.trim().to_owned()
                })
                .find(|n| !n.is_empty())?;
            Some((id, shown))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVPN: &str = "client\ndev tun\nproto tcp-client\nremote vpn.example.com 443\nnobind\nauth-user-pass\n\
                        remote-cert-tls server\n";

    /// A folder laid out as OpenVPN Connect's: `config` is its
    /// `status.profiles` object, encoded the way it stores it.
    fn folder(tag: &str, profiles: &[&str], config: Option<serde_json::Value>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omnitun-ovpnc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("profiles")).unwrap();
        let ca = super::super::ovpn::tests::ca_pem();
        for id in profiles {
            std::fs::write(dir.join("profiles").join(format!("{id}.ovpn")), format!("{OVPN}<ca>\n{ca}</ca>\n"))
                .unwrap();
        }
        if let Some(profiles) = config {
            let status = serde_json::json!({ "profiles": profiles, "readProfile": { "config": { "content": "x" } } });
            let root = serde_json::json!({ "status": status.to_string(), "_persist": "{}" });
            let file = serde_json::json!({ "persist:root": root.to_string(), "appliedPatches": [] });
            std::fs::write(dir.join("config.json"), file.to_string()).unwrap();
        }
        dir
    }

    #[test]
    fn imports_the_profiles_under_their_names() {
        let dir = folder(
            "names",
            &["1741618849613", "1740075380760", "1750000000000"],
            Some(serde_json::json!({
                "1740075380760": { "id": "1740075380760", "profileDisplayName": "Roaming", "name": "roaming.ovpn" },
                "1741618849613": { "id": "1741618849613", "profileDisplayName": "", "name": "Roaming backup" },
            })),
        );
        let found = openvpn_connect(Some(&dir), &["Roaming".into()]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let names: Vec<&str> = found.iter().map(|f| f.display.as_str()).collect();
        assert_eq!(names, ["Roaming", "Roaming backup", "1750000000000"], "in import order, named as shown");
        let roaming = found[0].result.as_ref().unwrap();
        assert_eq!(roaming.name, "Roaming 2", "renamed: the name is taken");
        assert!(roaming.toml.contains("# Imported from OpenVPN Connect: \"Roaming\""), "{}", roaming.toml);
        let file: vpn_core::ProfileFile = toml::from_str(&roaming.toml).unwrap();
        assert_eq!(file.profiles[0].description.as_deref(), Some("Roaming"));
        let vpn_core::ProtocolConfig::OpenVpn(p) = &file.profiles[0].protocol else { panic!() };
        assert_eq!((p.remotes[0].host.as_str(), p.remotes[0].port), ("vpn.example.com", 443));
        assert_eq!(found[1].result.as_ref().unwrap().name, "Roaming backup");
    }

    #[test]
    fn names_by_id_without_a_readable_config() {
        let dir = folder("unreadable", &["1740075380760"], None);
        std::fs::write(dir.join("config.json"), "{not json").unwrap();
        let found = openvpn_connect(Some(&dir), &[]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].result.as_ref().unwrap().name, "1740075380760");
    }

    #[test]
    fn says_when_profiles_are_left_out() {
        let ids: Vec<String> = (0..MAX_PROFILES as u64 + 2).map(|i| (1_740_000_000_000 + i).to_string()).collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        let dir = folder("many", &ids, None);
        let found = openvpn_connect(Some(&dir), &[]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found.len(), MAX_PROFILES + 1);
        let last = found.last().unwrap();
        assert_eq!(last.display, "2 more");
        let Err(e) = &last.result else { panic!("a profile left out is not imported") };
        assert!(format!("{e:#}").contains("at most 64"));
    }

    #[test]
    fn names_without_invisible_characters() {
        let dir = folder(
            "invisible",
            &["1740075380760"],
            Some(serde_json::json!({ "1740075380760": { "profileDisplayName": "Ro\u{202e}aming\u{200b}" } })),
        );
        let found = openvpn_connect(Some(&dir), &[]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found[0].display, "Roaming");
    }

    #[test]
    fn fails_without_a_profiles_folder() {
        let dir = std::env::temp_dir().join(format!("omnitun-ovpnc-none-{}", std::process::id()));
        assert!(openvpn_connect(Some(&dir), &[]).is_err());
    }
}
