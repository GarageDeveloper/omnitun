//! The profiles window's commands: the editor, folders, duplicates,
//! imports and secrets, through `vpn-ffi`'s client, as the macOS app does
//! (same form, same checks, same file).

use std::collections::HashMap;
use std::sync::Arc;

use vpn_ffi::{
    Client, DuplicatedProfile, ImportedProfile, KeychainIdentity, ListEntry, ProfileForm, ProfileSummary,
    ReceivedProfile, VpnKind,
};

type Result<T> = std::result::Result<T, String>;

fn client() -> Result<Arc<Client>> {
    Client::new(None).map_err(|e| e.to_string())
}

fn text<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tauri::command]
pub fn profile_summaries() -> Result<Vec<ProfileSummary>> {
    client()?.profiles().map_err(text)
}

#[tauri::command]
pub fn profile_form(id: String) -> Result<ProfileForm> {
    client()?.profile_form(id).map_err(text)
}

#[tauri::command]
pub fn new_profile_form(kind: VpnKind) -> Result<ProfileForm> {
    Ok(client()?.new_profile_form(kind))
}

#[derive(serde::Serialize)]
pub struct Saved {
    id: String,
    /// Why a secret could not be stored or forgotten; the profile itself
    /// was saved.
    error: Option<String>,
}

/// Saves the form, then its secrets: `Some` stores one, `None` deletes it;
/// keys left out stay as they are.
#[tauri::command]
pub async fn save_profile(
    original: Option<String>,
    form: ProfileForm,
    secrets: HashMap<String, Option<String>>,
) -> Result<Saved> {
    // The certificate store and the credentials may block: off the UI thread.
    tauri::async_runtime::spawn_blocking(move || {
        let client = client()?;
        let id = client.save_profile(original, form).map_err(text)?;
        let mut error = None;
        for (key, value) in secrets {
            let done = match value {
                Some(value) if !value.is_empty() => client.set_secret(id.clone(), key, value).map(|_| ()),
                Some(_) => Ok(()),
                None => client.delete_secret(id.clone(), key).map(|_| ()),
            };
            if let Err(e) = done {
                error.get_or_insert(e.to_string());
            }
        }
        Ok(Saved { id, error })
    })
    .await
    .map_err(text)?
}

/// Which of `keys` have a value stored for profile `id`.
#[tauri::command]
pub async fn stored_secrets(id: String, keys: Vec<String>) -> Result<HashMap<String, bool>> {
    tauri::async_runtime::spawn_blocking(move || {
        let client = client()?;
        Ok(keys.into_iter().map(|k| (k.clone(), client.has_secret(id.clone(), k))).collect())
    })
    .await
    .map_err(text)?
}

#[tauri::command]
pub async fn remove_profile(id: String) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let client = client()?;
        // Its secrets go with it, as in the macOS app.
        for key in ["password", "psk", "private_key"] {
            let _ = client.delete_secret(id.clone(), key.into());
        }
        client.remove_profile(id).map_err(text)
    })
    .await
    .map_err(text)?
}

#[tauri::command]
pub fn move_profile(id: String, folder: Option<String>, before: Option<String>) -> Result<()> {
    client()?.move_profile(id, folder.filter(|f| !f.trim().is_empty()), before).map_err(text)
}

#[tauri::command]
pub async fn duplicate_profile(id: String, name: String) -> Result<DuplicatedProfile> {
    tauri::async_runtime::spawn_blocking(move || client()?.duplicate_profile(id, name).map_err(text))
        .await
        .map_err(text)?
}

/// Writes profile `id` as a `.vpnprofile` file to `path`.
#[tauri::command]
pub fn export_profile(id: String, path: String) -> Result<()> {
    let text_ = client()?.export_profile(id).map_err(text)?;
    std::fs::write(path, text_).map_err(text)
}

#[tauri::command]
pub fn read_vpnprofile(path: String) -> Result<ReceivedProfile> {
    client()?.read_vpnprofile(path).map_err(text)
}

#[tauri::command]
pub fn replace_trusted_certificate(id: String, sha256: String) -> Result<()> {
    client()?.replace_trusted_certificate(id, sha256).map_err(text)
}

#[tauri::command]
pub async fn identities() -> Result<Vec<KeychainIdentity>> {
    tauri::async_runtime::spawn_blocking(|| vpn_ffi::keychain_identities().map_err(text)).await.map_err(text)?
}

#[tauri::command]
pub fn wireguard_public_key(private_key: String) -> Option<String> {
    vpn_ffi::wireguard_public_key(private_key)
}

#[tauri::command]
pub fn new_wireguard_private_key() -> String {
    vpn_ffi::new_wireguard_private_key()
}

/// The certificates of the file at `path` (PEM, or one DER certificate),
/// as PEM.
#[tauri::command]
pub fn certificate_file(path: String) -> Result<String> {
    let data = std::fs::read(path).map_err(text)?;
    vpn_ffi::certificates_as_pem(data).map_err(text)
}

#[tauri::command]
pub fn certificate_names(pem: String) -> Vec<String> {
    vpn_ffi::certificate_names(pem)
}

/// The contents of a text file the user chose (an OpenVPN static key).
#[tauri::command]
pub fn read_text(path: String) -> Result<String> {
    let metadata = std::fs::metadata(&path).map_err(text)?;
    if metadata.len() > 1 << 20 {
        return Err("the file is too large".into());
    }
    std::fs::read_to_string(path).map_err(text)
}

#[tauri::command]
pub fn proposals_as_text(form: ProfileForm) -> Result<ProfileForm> {
    vpn_ffi::proposals_as_text(form).map_err(text)
}

#[tauri::command]
pub fn proposals_as_choices(form: ProfileForm) -> ProfileForm {
    vpn_ffi::proposals_as_choices(form)
}

/// What is wrong with an entry of a list, if anything: `kind` is
/// `network`, `pattern` (a domain kept outside) or `domain`.
#[tauri::command]
pub fn entry_error(kind: String, value: String) -> Option<String> {
    match kind.as_str() {
        "network" => vpn_ffi::network_error(value),
        "pattern" => vpn_ffi::pattern_error(value),
        _ => vpn_ffi::domain_error(value),
    }
}

/// Lines pasted into a list, split into entries and notes.
#[tauri::command]
pub fn parse_list(text: String) -> Vec<ListEntry> {
    vpn_ffi::parse_list(text)
}

/// What a source of profiles holds; nothing is written. `source`:
/// `forticlient`, `openvpn` (a file), `wireguard` (a file), `viscosity`,
/// `openvpn-connect`.
#[tauri::command]
pub async fn import_preview(source: String, path: Option<String>) -> Result<Vec<ImportedProfile>> {
    tauri::async_runtime::spawn_blocking(move || {
        let client = client()?;
        match source.as_str() {
            "forticlient" => client.import_forticlient(path),
            "viscosity" => client.import_viscosity(path),
            "openvpn-connect" => client.import_openvpn_connect(path),
            "openvpn" => client.import_openvpn(path.ok_or("no file")?),
            "wireguard" => client.import_wireguard(path.ok_or("no file")?).map(|p| vec![p]),
            other => return Err(format!("unknown source {other}")),
        }
        .map_err(text)
    })
    .await
    .map_err(text)?
}

/// Adds imported profiles (their `toml`), then the secrets typed for them
/// (`password`, `psk`), by the index of the profile in `toml`'s order.
#[tauri::command]
pub async fn add_imported(toml: String, secrets: Vec<HashMap<String, String>>) -> Result<Vec<String>> {
    tauri::async_runtime::spawn_blocking(move || {
        let client = client()?;
        let ids = client.add_profiles(toml).map_err(text)?;
        let mut failed = Vec::new();
        for (id, values) in ids.iter().zip(secrets) {
            for (key, value) in values {
                if value.is_empty() {
                    continue;
                }
                if let Err(e) = client.set_secret(id.clone(), key, value) {
                    failed.push(e.to_string());
                }
            }
        }
        match failed.first() {
            Some(e) => Err(format!("the profiles were added, but not all their secrets: {e}")),
            None => Ok(ids),
        }
    })
    .await
    .map_err(text)?
}

/// Adds a WireGuard configuration with its keys stored; returns the id.
#[tauri::command]
pub async fn add_wireguard(path: String) -> Result<String> {
    tauri::async_runtime::spawn_blocking(move || client()?.add_wireguard(path).map_err(text)).await.map_err(text)?
}

#[tauri::command]
pub fn is_wireguard_config(path: String) -> bool {
    vpn_ffi::is_wireguard_config(path)
}
