//! Secrets kept in the OS keychain (macOS Keychain, Secret Service).
//!
//! An entry is bound to the profile's id and to the server it was saved
//! for (account `id/key@host:port`): a profile whose server changed, or
//! an imported homonym, never receives it, and a rename keeps it.

use vpn_core::{Profile, brand};
use zeroize::Zeroizing;

/// The keys a profile may keep.
pub const KEYS: [&str; 3] = ["password", "psk", "private_key"];

pub fn account(profile: &Profile, key: &str) -> String {
    let (host, port) = profile.protocol.endpoint();
    format!("{}/{key}@{host}:{port}", profile.id)
}

fn entry(profile: &Profile, key: &str) -> anyhow::Result<keyring::Entry> {
    Ok(keyring::Entry::new(brand::ID, &account(profile, key))?)
}

/// Accounts of earlier versions, by the profile's name: bound to the
/// server, then unbound in the current and the pre-rename keychain
/// services; `true` marks ours.
fn named_entries(profile: &Profile, key: &str) -> anyhow::Result<[(keyring::Entry, bool); 3]> {
    let (host, port) = profile.protocol.endpoint();
    let name = &profile.name;
    let unbound = format!("{name}/{key}");
    Ok([
        (keyring::Entry::new(brand::ID, &format!("{name}/{key}@{host}:{port}"))?, true),
        (keyring::Entry::new(brand::ID, &unbound)?, true),
        (keyring::Entry::new(brand::legacy::KEYCHAIN_SERVICE, &unbound)?, false),
    ])
}

fn known(key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(KEYS.contains(&key), "no secret {key:?} is kept for a VPN");
    Ok(())
}

/// Reads a stored secret: only the profile's own entry, for its server.
pub fn get(profile: &Profile, key: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
    known(key)?;
    match entry(profile, key)?.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Moves what earlier versions saved under the profile's name to its id,
/// while the name is still the one they used (when ids are given, before
/// any rename): later, a homonym never receives them.
pub fn adopt(profile: &Profile) {
    for key in KEYS {
        if let Err(e) = adopt_one(profile, key) {
            tracing::warn!("{}: the saved {key} could not be moved to its new Keychain entry: {e:#}", profile.name);
        }
    }
}

fn adopt_one(profile: &Profile, key: &str) -> anyhow::Result<()> {
    let bound = entry(profile, key)?;
    match bound.get_password() {
        Ok(_) => return Ok(()),
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.into()),
    }
    for (old, ours) in named_entries(profile, key)? {
        match old.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                bound.set_password(&value)?;
                // The pre-rename entry is left for older binaries.
                if ours {
                    let _ = old.delete_credential();
                }
                return Ok(());
            }
            Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn set(profile: &Profile, key: &str, value: &str) -> anyhow::Result<()> {
    known(key)?;
    Ok(entry(profile, key)?.set_password(value)?)
}

/// Copies the secrets of `from` to `to` (a duplicate); returns the keys
/// copied.
pub fn copy(from: &Profile, to: &Profile) -> anyhow::Result<Vec<&'static str>> {
    let mut copied = Vec::new();
    for key in KEYS {
        if let Some(value) = get(from, key)? {
            set(to, key, &value)?;
            copied.push(key);
        }
    }
    Ok(copied)
}

/// Forgets the secret, including copies earlier versions saved under the
/// profile's name. Returns whether anything was deleted.
pub fn delete(profile: &Profile, key: &str) -> anyhow::Result<bool> {
    known(key)?;
    let mut entries: Vec<keyring::Entry> = named_entries(profile, key)?.into_iter().map(|(e, _)| e).collect();
    entries.push(entry(profile, key)?);
    let mut found = false;
    for entry in entries {
        match entry.delete_credential() {
            Ok(()) => found = true,
            Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(host: &str, port: u16) -> Profile {
        toml::from_str(&format!(
            "id = \"6f9619ff-8b86-4011-b42d-00c04fc964ff\"\nname = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"{host}\"\nport = {port}"
        ))
        .unwrap()
    }

    #[test]
    fn secrets_are_bound_to_the_server() {
        assert_eq!(
            account(&profile("vpn.example.com", 443), "password"),
            "6f9619ff-8b86-4011-b42d-00c04fc964ff/password@vpn.example.com:443"
        );
        assert_ne!(
            account(&profile("vpn.example.com", 443), "password"),
            account(&profile("evil.example.net", 443), "password")
        );
    }

    #[test]
    fn only_known_keys() {
        // Refused before the Keychain is touched.
        let p = profile("vpn.example.com", 443);
        assert!(get(&p, "password@old.example:443").is_err());
        assert!(set(&p, "x", "y").is_err());
        assert!(delete(&p, "").is_err());
    }
}
