//! The Settings window's commands, as the macOS app's: opening at sign-in,
//! quitting, updates, language, notifications; the service; a diagnostic
//! report. The settings are a JSON file in the app's configuration folder.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

type Result<T> = std::result::Result<T, String>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    /// `system`, `en` or `fr`; read at start.
    pub language: String,
    pub notify_connected: bool,
    pub notify_failures: bool,
    pub disconnect_on_quit: bool,
    pub check_updates: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "system".into(),
            notify_connected: false,
            notify_failures: true,
            disconnect_on_quit: false,
            check_updates: true,
        }
    }
}

static SETTINGS: OnceLock<Mutex<Settings>> = OnceLock::new();
static PATH: OnceLock<PathBuf> = OnceLock::new();
/// The language of this run (a change takes effect at the next start).
static FRENCH: OnceLock<bool> = OnceLock::new();

/// Reads the settings file (defaults if there is none).
pub fn load(app: &AppHandle) {
    let path = app.path().app_config_dir().map(|d| d.join("settings.json")).unwrap_or_default();
    let settings: Settings =
        std::fs::read_to_string(&path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default();
    let french = match settings.language.as_str() {
        "fr" => true,
        "en" => false,
        _ => sys_locale::get_locale().is_some_and(|l| l.to_ascii_lowercase().starts_with("fr")),
    };
    let _ = FRENCH.set(french);
    let _ = PATH.set(path);
    let _ = SETTINGS.set(Mutex::new(settings));
}

pub fn current() -> Settings {
    SETTINGS.get().map(|s| s.lock().unwrap().clone()).unwrap_or_default()
}

pub fn french() -> bool {
    *FRENCH.get_or_init(|| sys_locale::get_locale().is_some_and(|l| l.to_ascii_lowercase().starts_with("fr")))
}

/// `en`, or `fr` in French.
pub fn tr(en: &'static str, fr: &'static str) -> &'static str {
    if french() { fr } else { en }
}

#[tauri::command]
pub fn settings() -> Settings {
    current()
}

/// The language the windows speak in this run: `en` or `fr`.
#[tauri::command]
pub fn language() -> &'static str {
    if french() { "fr" } else { "en" }
}

#[tauri::command]
pub fn set_settings(settings: Settings) -> Result<()> {
    let path = PATH.get().ok_or("no settings folder")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    if let Some(current) = SETTINGS.get() {
        *current.lock().unwrap() = settings;
    }
    Ok(())
}

/// Whether the app starts at sign-in for this user.
#[tauri::command]
pub fn open_at_login() -> bool {
    login::enabled()
}

#[tauri::command]
pub fn set_open_at_login(on: bool) -> Result<()> {
    login::set(on).map_err(|e| e.to_string())
}

#[cfg(windows)]
mod login {
    //! The installer starts the app for everyone (HKLM Run); a user turns
    //! it off for themselves as Task Manager does (StartupApproved). Without
    //! the installer's entry, the user's own Run entry.
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_BINARY};

    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const NAME: &str = "Omnitun";

    fn installed() -> bool {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(RUN, KEY_READ)
            .is_ok_and(|k| k.get_value::<String, _>(NAME).is_ok())
    }

    pub fn enabled() -> bool {
        let user = RegKey::predef(HKEY_CURRENT_USER);
        if installed() {
            // Absent, or an even first byte: on.
            match user.open_subkey_with_flags(APPROVED, KEY_READ).and_then(|k| k.get_raw_value(NAME)) {
                Ok(value) => value.bytes.first().is_none_or(|b| b % 2 == 0),
                Err(_) => true,
            }
        } else {
            user.open_subkey_with_flags(RUN, KEY_READ).is_ok_and(|k| k.get_value::<String, _>(NAME).is_ok())
        }
    }

    pub fn set(on: bool) -> std::io::Result<()> {
        let user = RegKey::predef(HKEY_CURRENT_USER);
        if installed() {
            let (key, _) = user.create_subkey(APPROVED)?;
            let mut bytes = vec![0u8; 12];
            bytes[0] = if on { 2 } else { 3 };
            key.set_raw_value(NAME, &winreg::RegValue { bytes, vtype: REG_BINARY })
        } else if on {
            let exe = std::env::current_exe()?;
            let (key, _) = user.create_subkey(RUN)?;
            key.set_value(NAME, &format!("\"{}\" --hidden", exe.display()))
        } else {
            match user.open_subkey_with_flags(RUN, KEY_WRITE) {
                Ok(key) => match key.delete_value(NAME) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                },
                Err(_) => Ok(()),
            }
        }
    }
}

#[cfg(not(windows))]
mod login {
    pub fn enabled() -> bool {
        false
    }
    pub fn set(_: bool) -> std::io::Result<()> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Windows only"))
    }
}

#[derive(Serialize)]
pub struct Service {
    version: String,
    sessions: u32,
}

/// The service's version and the user's sessions, or why it cannot be
/// reached.
#[tauri::command]
pub async fn service_info() -> Result<Service> {
    let client = vpn_ffi::Client::new(None).map_err(|e| e.to_string())?;
    let info = client.service_info().await.map_err(|e| e.to_string())?;
    Ok(Service { version: info.version, sessions: info.sessions })
}

/// Closes every session; the service manager starts the service again.
#[tauri::command]
pub async fn restart_service() -> Result<()> {
    let client = vpn_ffi::Client::new(None).map_err(|e| e.to_string())?;
    client.shutdown().await.map_err(|e| e.to_string())
}

/// The Services console, where the service's state shows.
#[tauri::command]
pub fn open_services() -> Result<()> {
    std::process::Command::new("mmc").arg("services.msc").spawn().map_err(|e| e.to_string())?;
    Ok(())
}

/// Writes the diagnostic report to `path` and shows it in Explorer.
#[tauri::command]
pub async fn diagnostic_report(path: String) -> Result<()> {
    let client = vpn_ffi::Client::new(None).map_err(|e| e.to_string())?;
    let report = client.diagnostic_report(format!("Omnitun {} (Windows)", vpn_core::version())).await;
    std::fs::write(&path, report).map_err(|e| e.to_string())?;
    let mut explorer = std::process::Command::new("explorer");
    // Explorer reads its own command line: the path quoted after the comma.
    #[cfg(windows)]
    std::os::windows::process::CommandExt::raw_arg(&mut explorer, format!("/select,\"{path}\""));
    let _ = explorer.spawn();
    Ok(())
}

/// The third-party licenses installed next to the app, if any.
#[tauri::command]
pub fn open_notices() -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let notices = exe.with_file_name("THIRD-PARTY-NOTICES.txt");
    if !notices.exists() {
        return Err(tr("The licenses are installed with the app.", "Les licences sont installées avec l'app.").into());
    }
    std::process::Command::new("notepad").arg(notices).spawn().map_err(|e| e.to_string())?;
    Ok(())
}
