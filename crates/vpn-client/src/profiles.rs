//! The user's profiles file. Every change goes through `toml_edit`, so
//! comments, key order and the other profiles stay as the user wrote them,
//! and the file is replaced atomically with owner-only permissions.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use toml_edit::{DocumentMut, Item, Table};
use vpn_core::{Profile, ProfileFile, brand};

pub struct ProfileStore {
    path: PathBuf,
    legacy: bool,
}

impl ProfileStore {
    /// `path`, or `~/.config/omnitun/profiles.toml`; the file of the
    /// pre-rename location is used while the new one does not exist.
    pub fn open(path: Option<PathBuf>) -> anyhow::Result<Self> {
        if let Some(path) = path {
            return Ok(Self { path, legacy: false });
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .context("cannot locate the config directory")?;
        let path = base.join(brand::ID).join("profiles.toml");
        let legacy = base.join(brand::legacy::CONFIG_DIR).join("profiles.toml");
        if !path.exists() && legacy.exists() {
            return Ok(Self { path: legacy, legacy: true });
        }
        Ok(Self { path, legacy: false })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file is the one of the pre-rename location.
    pub fn is_legacy(&self) -> bool {
        self.legacy
    }

    /// The profiles; none when the file does not exist yet. A file of an
    /// earlier version gets its ids first (see `migrate`).
    pub fn load(&self) -> anyhow::Result<Vec<Profile>> {
        let file = self.read_file()?;
        if file.profiles.iter().any(|p| p.id.is_empty()) {
            self.migrate()?;
            return Ok(self.read_file()?.profiles);
        }
        Ok(file.profiles)
    }

    /// The profile `key` names: its id, its name if no other profile has
    /// it, or its folder and name (`Clients/Acme/EU`).
    pub fn find(&self, key: &str) -> anyhow::Result<Profile> {
        let profiles = self.load()?;
        if let Some(p) = profiles.iter().find(|p| p.id == key) {
            return Ok(p.clone());
        }
        let named: Vec<&Profile> = profiles.iter().filter(|p| p.name == key).collect();
        match named.as_slice() {
            [one] => return Ok((*one).clone()),
            [] => {}
            several => bail!(
                "several VPNs are named {key}: name it with its folder ({})",
                several.iter().map(|p| path_of(p)).collect::<Vec<_>>().join(", ")
            ),
        }
        profiles.into_iter().find(|p| path_of(p) == key).with_context(|| format!("no VPN named {key}"))
    }

    /// Appends profiles given as TOML (`[[profile]]` tables, as produced by
    /// an import), each with a new id; returns the ids. Refuses a name
    /// already used in the same folder.
    pub fn append(&self, text: &str) -> anyhow::Result<Vec<String>> {
        let mut doc: DocumentMut = text.parse().context("the new profiles are not valid")?;
        let mut ids = Vec::new();
        if let Some(list) = doc.get_mut("profile").and_then(Item::as_array_of_tables_mut) {
            for table in list.iter_mut() {
                // A received or imported profile is a new one: never one of
                // ours that it would claim to be.
                let id = vpn_core::new_id();
                table.insert("id", toml_edit::value(&id));
                table.sort_values_by(|a, _, b, _| (b.get() == "id").cmp(&(a.get() == "id")));
                ids.push(id);
            }
        }
        let text = doc.to_string();
        let added: ProfileFile = toml::from_str(&text).context("the new profiles are not valid")?;
        let known = self.load()?;
        for (i, p) in added.profiles.iter().enumerate() {
            let clash = |k: &Profile| k.name == p.name && k.folder == p.folder;
            if known.iter().any(clash) || added.profiles[..i].iter().any(clash) {
                bail!("{} already exists in {}", path_of(p), self.path.display());
            }
            p.validate().with_context(|| format!("profile {}", p.name))?;
        }
        let existing = self.read_text()?;
        let sep = if existing.is_empty() || existing.ends_with("\n\n") {
            ""
        } else if existing.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        self.write(&format!("{existing}{sep}{text}"))?;
        Ok(ids)
    }

    /// Gives an id to the profiles of a file written before ids existed,
    /// and turns the names of their chains into ids. The file is copied to
    /// `profiles.toml.before-ids` first.
    fn migrate(&self) -> anyhow::Result<()> {
        let backup = self.path.with_extension("toml.before-ids");
        if !backup.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&backup)
                .and_then(|mut f| f.write_all(self.read_text().unwrap_or_default().as_bytes()))
                .with_context(|| format!("cannot back up {} before giving ids", self.path.display()))?;
        }
        self.edit(|doc| {
            let list = profiles(doc)?;
            let mut ids = std::collections::HashMap::new();
            for table in list.iter_mut() {
                let existing = table.get("id").and_then(Item::as_str).filter(|i| !i.is_empty()).map(str::to_owned);
                let id = existing.unwrap_or_else(|| {
                    let id = vpn_core::new_id();
                    table.insert("id", toml_edit::value(&id));
                    table.sort_values_by(|a, _, b, _| (b.get() == "id").cmp(&(a.get() == "id")));
                    id
                });
                if let Some(name) = table.get("name").and_then(Item::as_str) {
                    ids.insert(name.to_owned(), id);
                }
            }
            for table in list.iter_mut() {
                if let Some(via) = table.get_mut("via").and_then(Item::as_array_mut) {
                    for entry in via.iter_mut() {
                        if let Some(id) = entry.as_str().and_then(|name| ids.get(name)) {
                            *entry = id.as_str().into();
                        }
                    }
                }
            }
            Ok(())
        })?;
        // Their Keychain entries follow, while their names are the ones
        // the entries were saved under.
        // (Not from tests: they would read the user's Keychain.)
        if !cfg!(test) {
            for profile in self.read_file()?.profiles {
                crate::secrets::adopt(&profile);
            }
        }
        tracing::info!("profiles given ids; the previous file is kept as {}", backup.display());
        Ok(())
    }

    /// Adds `profile`, or updates the profile with its id in place: its
    /// unchanged values keep their comments, and values left at their
    /// default are not written out.
    pub fn save(&self, profile: &Profile) -> anyhow::Result<()> {
        ensure!(vpn_core::valid_id(&profile.id), "the profile has no id");
        profile.validate()?;
        let others = self.load()?;
        if let Some(clash) =
            others.iter().find(|o| o.id != profile.id && o.name == profile.name && o.folder == profile.folder)
        {
            bail!("a VPN named {} already exists in this folder", path_of(clash));
        }
        let canonical = toml::to_string(profile)?;
        let previous = profile.id.as_str();
        self.edit(|doc| {
            let existing = profile_table(doc, previous);
            let keep: Vec<String> = existing.iter().flat_map(|t| t.iter().map(|(k, _)| k.to_owned())).collect();
            let mut new = minimal(canonical.parse::<DocumentMut>()?.as_table().clone(), &canonical, &keep);
            unplace(&mut new);
            match profile_table(doc, previous) {
                Some(table) => update_table(table, &new),
                None => profiles(doc)?.push(new),
            }
            Ok(())
        })
    }

    /// Replaces the profile's trusted certificate fingerprints.
    pub fn set_trusted_certificates(&self, id: &str, fingerprints: &[String]) -> anyhow::Result<()> {
        let mut profile = self.find(id)?;
        let name = profile.name.clone();
        match &mut profile.protocol {
            vpn_core::ProtocolConfig::FortiSsl(p) => p.trusted_cert = fingerprints.to_vec(),
            vpn_core::ProtocolConfig::Ipsec(p) if p.gateway_auth == vpn_core::GatewayAuth::Certificate => {
                p.trusted_cert = fingerprints.to_vec();
            }
            vpn_core::ProtocolConfig::Ipsec(_)
            | vpn_core::ProtocolConfig::L2tp(_)
            | vpn_core::ProtocolConfig::WireGuard(_) => {
                bail!("{name} does not use certificates")
            }
            vpn_core::ProtocolConfig::OpenVpn(p) => p.trusted_cert = fingerprints.to_vec(),
        }
        self.save(&profile)
    }

    /// Moves `name` just before `before` in the file (the end if None):
    /// the order the VPNs are listed in.
    pub fn reorder(&self, id: &str, before: Option<&str>) -> anyhow::Result<()> {
        if before == Some(id) {
            return Ok(());
        }
        self.load()?;
        self.edit(|doc| {
            let list = profiles(doc)?;
            let index_of = |list: &toml_edit::ArrayOfTables, n: &str| {
                list.iter().position(|t| t.get("id").and_then(Item::as_str) == Some(n))
            };
            let from = index_of(list, id).with_context(|| format!("no profile {id}"))?;
            let mut moved = list.remove(from);
            // Written where it now stands, not where it was read.
            unplace(&mut moved);
            let to = match before {
                Some(b) => index_of(list, b).with_context(|| format!("no profile {b}"))?,
                None => list.len(),
            };
            list.insert(to, moved);
            Ok(())
        })
    }

    pub fn remove(&self, id: &str) -> anyhow::Result<()> {
        self.load()?;
        self.edit(|doc| {
            let list = profiles(doc)?;
            let index = list
                .iter()
                .position(|t| t.get("id").and_then(Item::as_str) == Some(id))
                .with_context(|| format!("no profile {id}"))?;
            list.remove(index);
            Ok(())
        })
    }

    /// Adds `sha256` to the profile's `trusted_cert`.
    pub fn pin_certificate(&self, id: &str, sha256: &str) -> anyhow::Result<()> {
        self.load()?;
        self.edit(|doc| {
            let table = profile_table(doc, id).with_context(|| format!("no profile {id}"))?;
            let pins = table
                .entry("trusted_cert")
                .or_insert(toml_edit::value(toml_edit::Array::new()))
                .as_array_mut()
                .context("trusted_cert is not a list")?;
            if !pins.iter().any(|p| p.as_str().is_some_and(|p| p.eq_ignore_ascii_case(sha256))) {
                pins.push(sha256);
            }
            Ok(())
        })
    }

    fn read_text(&self) -> anyhow::Result<String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", self.path.display())),
        }
    }

    fn read_file(&self) -> anyhow::Result<ProfileFile> {
        toml::from_str(&self.read_text()?).with_context(|| format!("invalid {}", self.path.display()))
    }

    fn edit(&self, change: impl FnOnce(&mut DocumentMut) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut doc: DocumentMut =
            self.read_text()?.parse().with_context(|| format!("invalid {}", self.path.display()))?;
        change(&mut doc)?;
        let updated = doc.to_string();
        toml::from_str::<ProfileFile>(&updated).context("the updated profiles file would be invalid")?;
        self.write(&updated)
    }

    /// Replaces the file atomically with one only the user can read, in a
    /// directory only the user can list.
    fn write(&self, text: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let dir = self.path.parent().context("profiles file has no directory")?;
        if !dir.exists() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            // Created by hand, or by an earlier version, it may be listable.
            if std::fs::metadata(dir).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let tmp = dir.join(format!(".{}.tmp-{}", brand::ID, std::process::id()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        let written = file.write_all(text.as_bytes()).and_then(|()| file.sync_all());
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &self.path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

fn profiles(doc: &mut DocumentMut) -> anyhow::Result<&mut toml_edit::ArrayOfTables> {
    doc.entry("profile")
        .or_insert(Item::ArrayOfTables(Default::default()))
        .as_array_of_tables_mut()
        .context("`profile` is not a list of tables")
}

fn profile_table<'a>(doc: &'a mut DocumentMut, id: &str) -> Option<&'a mut Table> {
    doc.get_mut("profile")?
        .as_array_of_tables_mut()?
        .iter_mut()
        .find(|t| t.get("id").and_then(Item::as_str) == Some(id))
}

/// `Folder/Sub/Name`, as people tell VPNs apart.
pub fn path_of(profile: &Profile) -> String {
    match &profile.folder {
        Some(folder) => format!("{folder}/{}", profile.name),
        None => profile.name.clone(),
    }
}

/// Drops the keys not in `keep` whose absence gives the same profile.
fn minimal(mut table: Table, canonical: &str, keep: &[String]) -> Table {
    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_owned()).filter(|k| !keep.contains(k)).collect();
    for key in keys {
        let mut trial = table.clone();
        trial.remove(&key);
        let same = toml::from_str::<Profile>(&DocumentMut::from(trial.clone()).to_string())
            .ok()
            .and_then(|p| toml::to_string(&p).ok())
            .is_some_and(|t| t == canonical);
        if same {
            table = trial;
        }
    }
    table
}

/// Rewrites only the values that changed; keys the profile no longer has
/// are removed.
fn update_table(table: &mut Table, new: &Table) {
    table.retain(|key, _| new.contains_key(key));
    for (key, item) in new.iter() {
        match table.get_mut(key) {
            Some(old) if same(old, item) => {}
            Some(Item::Table(old)) if item.is_table() => update_table(old, item.as_table().expect("checked")),
            Some(old) => {
                // A changed value keeps the comments around it.
                let decor = old.as_value().map(|v| v.decor().clone());
                *old = unplaced(item);
                if let (Some(decor), Some(value)) = (decor, old.as_value_mut()) {
                    *value.decor_mut() = decor;
                }
            }
            None => {
                table.insert(key, unplaced(item));
            }
        }
    }
}

/// `item` without the places its tables had in the document they come
/// from: they are written after the table that receives them (OpenVPN
/// servers, `[[profile.remotes]]`), not among other profiles.
fn unplaced(item: &Item) -> Item {
    let mut item = item.clone();
    match &mut item {
        Item::Table(t) => unplace(t),
        Item::ArrayOfTables(list) => list.iter_mut().for_each(unplace),
        _ => {}
    }
    item
}

fn unplace(table: &mut Table) {
    table.set_position(None);
    for (_, item) in table.iter_mut() {
        match item {
            Item::Table(t) => unplace(t),
            Item::ArrayOfTables(list) => list.iter_mut().for_each(unplace),
            _ => {}
        }
    }
}

/// Equal values, whatever their comments and spacing.
fn same(a: &Item, b: &Item) -> bool {
    match (a.as_value(), b.as_value()) {
        (Some(a), Some(b)) => {
            let (mut a, mut b) = (a.clone(), b.clone());
            a.decor_mut().clear();
            b.decor_mut().clear();
            a.to_string() == b.to_string()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_profiles_with_nested_tables() {
        let dir = std::env::temp_dir().join(format!("omnitun-reorder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        let text = "[[profile]]\nname = \"a\"\nprotocol = \"forti-ssl\"\nhost = \"a.example.com\"\n\n\
                    [[profile]]\nname = \"b\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nca_pem = \"CA\"\n\n\
                    [[profile.remotes]]\nhost = \"b.example.com\"\n\n\
                    [[profile]]\nname = \"c\"\nprotocol = \"forti-ssl\"\nhost = \"c.example.com\"\n";
        std::fs::write(&path, text).unwrap();
        let store = ProfileStore::open(Some(path.clone())).unwrap();
        let names = |store: &ProfileStore| store.load().unwrap().into_iter().map(|p| p.name).collect::<Vec<_>>();
        let id = |name: &str| store.find(name).unwrap().id;
        store.reorder(&id("c"), Some(&id("a"))).unwrap();
        assert_eq!(names(&store), ["c", "a", "b"]);
        store.reorder(&id("b"), Some(&id("c"))).unwrap();
        assert_eq!(names(&store), ["b", "c", "a"]);
        let vpn_core::ProtocolConfig::OpenVpn(b) = &store.find("b").unwrap().protocol else { panic!() };
        assert_eq!(b.remotes[0].host, "b.example.com", "its servers moved with it");
        store.reorder(&id("b"), None).unwrap();
        assert_eq!(names(&store), ["c", "a", "b"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const ORIGINAL: &str = "# my profiles\n[[profile]]\nname = \"paris\" # main office\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\ndns_domains = [\"corp\"] # split DNS\n\n[[profile]]\nname = \"lab\"\nprotocol = \"forti-ssl\"\nhost = \"lab.example.com\"\n";

    fn store(test: &str) -> (ProfileStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vpn-client-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        std::fs::write(&path, ORIGINAL).unwrap();
        (ProfileStore::open(Some(path)).unwrap(), dir)
    }

    fn ssl(profile: &Profile) -> &vpn_core::FortiSslProfile {
        let vpn_core::ProtocolConfig::FortiSsl(p) = &profile.protocol else { panic!() };
        p
    }

    #[test]
    fn pinning_keeps_the_rest_of_the_file() {
        let (store, dir) = store("pin");
        let fp = "ab".repeat(32);
        let paris = store.find("paris").unwrap().id;
        store.pin_certificate(&paris, &fp).unwrap();
        store.pin_certificate(&paris, &fp).unwrap();
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("# my profiles") && text.contains("# main office"), "{text}");
        let profiles = store.load().unwrap();
        assert_eq!(ssl(&profiles[0]).trusted_cert, [fp]);
        assert!(ssl(&profiles[1]).trusted_cert.is_empty());
        assert!(store.pin_certificate("nope", "00").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// OpenVPN profiles hold a list of tables (servers) and a subtable.
    #[test]
    fn saving_openvpn_profiles() {
        let (store, dir) = store("openvpn");
        let text = "[[profile]]\nname = \"ovpn\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nca_pem = \"CA\"\n\
                    verify_x509_name = { name = \"vpn\", kind = \"name\" }\n\
                    [[profile.remotes]]\nhost = \"a.example.com\"\n[[profile.remotes]]\nhost = \"b.example.com\"\n";
        store.append(text).unwrap();
        let mut profile = store.find("ovpn").unwrap();
        let vpn_core::ProtocolConfig::OpenVpn(p) = &mut profile.protocol else { panic!() };
        p.remotes.remove(0);
        p.remotes[0].port = 443;
        p.verify_x509_name = None;
        p.username = Some("alice".into());
        store.save(&profile).unwrap();
        let saved = store.find("ovpn").unwrap();
        let vpn_core::ProtocolConfig::OpenVpn(p) = &saved.protocol else { panic!() };
        assert_eq!((p.remotes.len(), p.remotes[0].host.as_str(), p.remotes[0].port), (1, "b.example.com", 443));
        assert_eq!((p.verify_x509_name.as_ref(), p.username.as_deref()), (None, Some("alice")));
        assert_eq!(store.load().unwrap().len(), 3);
        // A new one, then a change to another.
        let mut other = saved.clone();
        other.name = "ovpn2".into();
        other.id = vpn_core::new_id();
        store.save(&other).unwrap();
        let mut lab = store.find("lab").unwrap();
        lab.description = Some("lab".into());
        store.save(&lab).unwrap();
        let names: Vec<String> = store.load().unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["paris", "lab", "ovpn", "ovpn2"]);
        let vpn_core::ProtocolConfig::OpenVpn(p) = store.find("ovpn2").unwrap().protocol else { panic!() };
        assert_eq!(p.remotes.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saving_changes_only_what_changed() {
        let (store, dir) = store("save");
        let mut paris = store.find("paris").unwrap();
        let vpn_core::ProtocolConfig::FortiSsl(p) = &mut paris.protocol else { panic!() };
        p.username = Some("alice".into());
        paris.full_tunnel = Some(false);
        store.save(&paris).unwrap();
        let text = std::fs::read_to_string(store.path()).unwrap();
        for kept in ["# my profiles", "# main office", "# split DNS"] {
            assert!(text.contains(kept), "{kept} lost:\n{text}");
        }
        assert!(!text.contains("trusted_cert"), "empty lists are not written:\n{text}");
        let saved = store.find("paris").unwrap();
        assert_eq!(ssl(&saved).username.as_deref(), Some("alice"));
        assert_eq!(saved.full_tunnel, Some(false));

        // Clearing a value removes its key.
        let mut paris = saved;
        paris.full_tunnel = None;
        store.save(&paris).unwrap();
        assert!(!std::fs::read_to_string(store.path()).unwrap().contains("full_tunnel"));
        assert_eq!(store.load().unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profiles_are_added_and_removed() {
        let (store, dir) = store("add");
        let mut new = store.find("lab").unwrap();
        new.name = "branch".into();
        new.id = vpn_core::new_id();
        store.save(&new).unwrap();
        assert_eq!(
            store.load().unwrap().iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["paris", "lab", "branch"]
        );
        store.remove(&store.find("lab").unwrap().id).unwrap();
        assert!(store.find("lab").is_err());
        assert!(std::fs::read_to_string(store.path()).unwrap().contains("# main office"));
        assert!(store.remove("lab").is_err());

        let mut bad = new.clone();
        bad.name = "bad".into();
        let vpn_core::ProtocolConfig::FortiSsl(p) = &mut bad.protocol else { panic!() };
        p.host = "not a host".into();
        assert!(store.save(&bad).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn appending_refuses_known_names() {
        let (store, dir) = store("append");
        let lab = "[[profile]]\nname = \"lab\"\nprotocol = \"forti-ssl\"\nhost = \"x.example.com\"\n";
        assert!(store.append(lab).is_err());
        let other = lab.replace("\"lab\"", "\"other\"");
        let ids = store.append(&other).unwrap();
        assert_eq!(store.find(&ids[0]).unwrap().name, "other", "a new id");
        // The same name in another folder is another VPN.
        let filed = format!("{lab}folder = \"Clients\"\n");
        assert_eq!(store.append(&filed).unwrap().len(), 1);
        assert!(store.find("lab").unwrap_err().to_string().contains("Clients/lab"), "ambiguous");
        assert_eq!(store.find("Clients/lab").unwrap().folder.as_deref(), Some("Clients"));
        assert_eq!(store.load().unwrap().len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A file of an earlier version: ids given, chains by id, a backup.
    #[test]
    fn profiles_get_ids() {
        let (store, dir) = store("ids");
        let mut text = std::fs::read_to_string(store.path()).unwrap();
        text.push_str(
            "\n[[profile]]\nname = \"common\"\nprotocol = \"forti-ssl\"\nhost = \"c.example.com\"\nvia = [\"lab\"]\n",
        );
        std::fs::write(store.path(), &text).unwrap();
        let profiles = store.load().unwrap();
        assert!(profiles.iter().all(|p| vpn_core::valid_id(&p.id)));
        let lab = profiles.iter().find(|p| p.name == "lab").unwrap();
        let common = profiles.iter().find(|p| p.name == "common").unwrap();
        assert_eq!(common.via, std::slice::from_ref(&lab.id));
        assert_eq!(std::fs::read_to_string(store.path().with_extension("toml.before-ids")).unwrap(), text);
        assert!(std::fs::read_to_string(store.path()).unwrap().contains("# main office"), "comments kept");
        assert_eq!(store.load().unwrap()[0].id, profiles[0].id, "given once");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn renaming_keeps_place_and_comments() {
        let (store, dir) = store("rename");
        let mut paris = store.find("paris").unwrap();
        paris.name = "lyon".into();
        store.save(&paris).unwrap();
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("# main office") && text.contains("name = \"lyon\""), "{text}");
        assert_eq!(store.load().unwrap().iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["lyon", "lab"]);
        let mut lab = store.find("lab").unwrap();
        lab.name = "lyon".into();
        assert!(store.save(&lab).is_err(), "the new name is taken in that folder");
        lab.folder = Some("Elsewhere".into());
        store.save(&lab).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_means_no_profiles() {
        let store = ProfileStore::open(Some(std::env::temp_dir().join("vpn-client-none/profiles.toml"))).unwrap();
        assert!(store.load().unwrap().is_empty());
    }
}
