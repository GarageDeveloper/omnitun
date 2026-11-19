//! Omnitun for Windows: a tray icon and a window over `omnitund`, as the
//! macOS menu bar app is. Connections go through `vpn_client`, as
//! `omnitunctl`'s do: the window answers the questions (passwords, codes,
//! certificates) and this process keeps signing with a client certificate
//! while its sessions need it. Closing the window leaves the icon; Quit in
//! its menu ends the app, not the VPNs.
//!
//! `--hidden` (at sign-in) starts with the icon only.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tokio::sync::oneshot;
use vpn_client::{ConnectOptions, Daemon, Interaction, Notice, ProfileStore, Trust};
use vpn_core::ipc::{Event, SessionInfo, SessionState};
use vpn_core::{CertificateInfo, Prompt, PromptKind};
use zeroize::Zeroizing;

/// How the app names itself to the daemon.
const CLIENT: &str = "Omnitun (Windows)";
const RELEASES: &str = "https://github.com/GarageDeveloper/omnitun/releases/latest";
const LATEST: &str = "https://api.github.com/repos/GarageDeveloper/omnitun/releases/latest";
const UPDATE_EVERY: Duration = Duration::from_secs(24 * 3600);

enum Answer {
    Text(Option<String>),
    Trust(Trust),
}

#[derive(Default)]
struct State {
    /// Questions waiting for the window, by id.
    pending: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
    next: AtomicU64,
    /// The daemon's sessions, as last reported.
    sessions: Mutex<Vec<SessionInfo>>,
    /// Sessions this process signs for (client certificates), by profile.
    signing: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// A newer release, if one was found.
    update: Mutex<Option<String>>,
}

type Shared = Arc<State>;

#[derive(Serialize, Clone)]
struct ProfileView {
    id: String,
    name: String,
    folder: Option<String>,
    protocol: String,
}

#[derive(Serialize, Clone)]
struct PromptView {
    id: u64,
    profile: String,
    kind: PromptKind,
    message: String,
    digits: u8,
    push: bool,
}

#[derive(Serialize, Clone)]
struct TrustView {
    id: u64,
    profile: String,
    certificate: CertificateInfo,
}

#[derive(Serialize, Clone)]
struct NoticeView {
    profile: String,
    /// "state", "warning", "login", "refused", "pinned", "connecting".
    kind: &'static str,
    text: String,
}

/// The user's side of one connection: the window.
struct Window {
    app: AppHandle,
    state: Shared,
    profile: Mutex<String>,
}

impl Window {
    fn profile(&self) -> String {
        self.profile.lock().unwrap().clone()
    }

    /// Waits for the window's answer to question `id`, showing it.
    async fn wait(&self, id: u64) -> Option<Answer> {
        let (tx, rx) = oneshot::channel();
        self.state.pending.lock().unwrap().insert(id, tx);
        show(&self.app);
        rx.await.ok()
    }
}

#[async_trait]
impl Interaction for Window {
    async fn ask(&self, prompt: &Prompt) -> anyhow::Result<Option<Zeroizing<String>>> {
        let id = self.state.next.fetch_add(1, Ordering::Relaxed);
        let view = PromptView {
            id,
            profile: self.profile(),
            kind: prompt.kind,
            message: vpn_client::printable(&prompt.message),
            digits: prompt.digits,
            push: prompt.push,
        };
        self.app.emit("prompt", view)?;
        Ok(match self.wait(id).await {
            Some(Answer::Text(value)) => value.map(Zeroizing::new),
            _ => None,
        })
    }

    async fn trust(&self, certificate: &CertificateInfo) -> anyhow::Result<Trust> {
        let id = self.state.next.fetch_add(1, Ordering::Relaxed);
        let mut certificate = certificate.clone();
        certificate.host = vpn_client::printable(&certificate.host);
        certificate.reason = certificate.reason.as_deref().map(vpn_client::printable);
        self.app.emit("trust", TrustView { id, profile: self.profile(), certificate })?;
        Ok(match self.wait(id).await {
            Some(Answer::Trust(trust)) => trust,
            _ => Trust::Reject,
        })
    }

    fn open_url(&self, url: &str) {
        open(url);
    }

    fn notice(&self, notice: Notice) {
        let (kind, text) = match notice {
            Notice::State { state, detail, .. } => {
                ("state", format!("{state:?}{}", detail.map(|d| format!(": {d}")).unwrap_or_default()))
            }
            Notice::Warning(message) => ("warning", message),
            Notice::LoginStarted(url) => ("login", url),
            Notice::UrlRefused(url) => ("refused", url),
            Notice::CertificatePinned => ("pinned", String::new()),
            Notice::Connecting { name, .. } => {
                *self.profile.lock().unwrap() = name.clone();
                ("connecting", name)
            }
        };
        let _ = self.app.emit("notice", NoticeView { profile: self.profile(), kind, text });
    }
}

/// Opens a page in the default browser (url.dll takes it as is, where
/// `start` would cut it at its first `&`).
fn open(url: &str) {
    let mut opener = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    let _ = opener.arg(url).spawn();
}

fn store() -> Result<ProfileStore, String> {
    ProfileStore::open(None).map_err(|e| format!("{e:#}"))
}

fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn profiles() -> Result<Vec<ProfileView>, String> {
    let profiles = store()?.load().map_err(|e| format!("{e:#}"))?;
    Ok(profiles
        .into_iter()
        .map(|p| ProfileView { id: p.id, name: p.name, folder: p.folder, protocol: p.protocol.name().to_owned() })
        .collect())
}

#[tauri::command]
fn sessions(state: tauri::State<'_, Shared>) -> Vec<SessionInfo> {
    state.sessions.lock().unwrap().clone()
}

/// Brings `id` up; returns once the daemon took it over, or with why not.
#[tauri::command]
async fn connect(app: AppHandle, state: tauri::State<'_, Shared>, id: String) -> Result<(), String> {
    let store = store()?;
    let profile = store.find(&id).map_err(|e| format!("{e:#}"))?;
    let name = profile.name.clone();
    let window = Window { app: app.clone(), state: state.inner().clone(), profile: Mutex::new(name.clone()) };
    let connected = vpn_client::connect_with(profile, &store, CLIENT, &window, ConnectOptions::default())
        .await
        .map_err(|e| format!("{e:#}"))?;
    if connected.signs() {
        // The key stays here: this process signs while the session needs it.
        let task = tokio::spawn(connected.signing());
        if let Some(previous) = state.signing.lock().unwrap().insert(id, task) {
            previous.abort();
        }
    }
    Ok(())
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, Shared>, id: String) -> Result<(), String> {
    let daemon = Daemon::open(CLIENT).await.map_err(|e| format!("{e:#}"))?;
    daemon.disconnect(&id).await.map_err(|e| format!("{e:#}"))?;
    if let Some(task) = state.signing.lock().unwrap().remove(&id) {
        task.abort();
    }
    Ok(())
}

/// The answer to question `id`; `None` cancels.
#[tauri::command]
fn answer(state: tauri::State<'_, Shared>, id: u64, value: Option<String>) {
    if let Some(waiting) = state.pending.lock().unwrap().remove(&id) {
        let _ = waiting.send(Answer::Text(value));
    }
}

/// "reject", "once" or "pin".
#[tauri::command]
fn trust(state: tauri::State<'_, Shared>, id: u64, decision: String) {
    let trust = match decision.as_str() {
        "once" => Trust::Once,
        "pin" => Trust::Pin,
        _ => Trust::Reject,
    };
    if let Some(waiting) = state.pending.lock().unwrap().remove(&id) {
        let _ = waiting.send(Answer::Trust(trust));
    }
}

/// Opens the profiles file in Notepad (created empty if missing).
#[tauri::command]
fn edit_profiles() -> Result<(), String> {
    let store = store()?;
    let path = store.path().to_owned();
    if !path.exists() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, "# Omnitun profiles: see the README for the fields of each protocol.\n")
            .map_err(|e| e.to_string())?;
    }
    let editor = if cfg!(windows) { "notepad" } else { "open" };
    std::process::Command::new(editor).arg(&path).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn update(state: tauri::State<'_, Shared>) -> Option<String> {
    state.update.lock().unwrap().clone()
}

#[tauri::command]
fn open_releases() {
    open(RELEASES);
}

#[tauri::command]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Follows the daemon's sessions for the window and the icon: their
/// changes as they come, and the whole status (traffic, addresses) after
/// each and every few seconds. Tries again when the daemon is away
/// (stopped, or this user not in its group).
async fn watch(app: AppHandle, state: Shared) {
    let poller = {
        let (app, state) = (app.clone(), state.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                refresh(&app, &state).await;
            }
        })
    };
    loop {
        let result = async {
            let mut daemon = Daemon::open(CLIENT).await?.watch().await?;
            let _ = app.emit("daemon", Option::<String>::None);
            loop {
                match daemon.next().await? {
                    Event::Status { sessions } => *state.sessions.lock().unwrap() = sessions,
                    Event::State { id, state: now, detail, .. } => {
                        if let Some(session) = state.sessions.lock().unwrap().iter_mut().find(|s| s.id == id) {
                            session.state = now;
                            session.detail = detail;
                        }
                        let (app, state) = (app.clone(), state.clone());
                        tokio::spawn(async move { refresh(&app, &state).await });
                    }
                    _ => continue,
                }
                let _ = app.emit("sessions", ());
                refresh_tray(&app, &state);
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            // The window gives the advice in its own language: the cause only.
            let _ = app.emit("daemon", Some(e.root_cause().to_string()));
            state.sessions.lock().unwrap().clear();
            refresh_tray(&app, &state);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        if poller.is_finished() {
            return;
        }
    }
}

/// Reads the whole status once.
async fn refresh(app: &AppHandle, state: &State) {
    let Ok(daemon) = Daemon::open(CLIENT).await else { return };
    let Ok(sessions) = daemon.status().await else { return };
    let changed = {
        let mut current = state.sessions.lock().unwrap();
        let ids = |list: &[SessionInfo]| list.iter().map(|s| (s.id.clone(), s.state)).collect::<Vec<_>>();
        let changed = ids(&current) != ids(&sessions);
        *current = sessions;
        changed
    };
    let _ = app.emit("sessions", ());
    if changed {
        refresh_tray(app, state);
    }
}

/// Looks for a newer release once a day; the window offers it, the user
/// decides (the page opens in the browser).
async fn check_updates(app: AppHandle, state: Shared) {
    loop {
        let latest = tokio::task::spawn_blocking(|| -> anyhow::Result<String> {
            let release: serde_json::Value = ureq::get(LATEST)
                .header("User-Agent", "omnitun-app")
                .header("Accept", "application/vnd.github+json")
                .call()?
                .body_mut()
                .read_json()?;
            Ok(release["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_owned())
        })
        .await;
        if let Ok(Ok(latest)) = latest
            && newer(&latest, env!("CARGO_PKG_VERSION"))
        {
            *state.update.lock().unwrap() = Some(latest.clone());
            let _ = app.emit("update", latest);
        }
        tokio::time::sleep(UPDATE_EVERY).await;
    }
}

/// Whether version `a` (x.y.z) comes after `b`.
fn newer(a: &str, b: &str) -> bool {
    let parse = |v: &str| v.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parse(a) > parse(b)
}

/// The icon's menu: the profiles (checked when up), the window, Quit.
fn tray_menu(app: &AppHandle, state: &State) -> tauri::Result<Menu<tauri::Wry>> {
    let menu = Menu::new(app)?;
    menu.append(&MenuItem::with_id(app, "open", "Omnitun…", true, None::<&str>)?)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    let up: Vec<String> = state
        .sessions
        .lock()
        .unwrap()
        .iter()
        .filter(|s| matches!(s.state, SessionState::Connected | SessionState::Connecting | SessionState::Reconnecting))
        .map(|s| s.id.clone())
        .collect();
    match profiles() {
        Ok(profiles) if !profiles.is_empty() => {
            for p in profiles {
                let checked = up.contains(&p.id);
                menu.append(&CheckMenuItem::with_id(
                    app,
                    format!("p:{}", p.id),
                    &p.name,
                    true,
                    checked,
                    None::<&str>,
                )?)?;
            }
        }
        _ => menu.append(&MenuItem::with_id(app, "none", "No profile", false, None::<&str>)?)?,
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?)?;
    Ok(menu)
}

fn refresh_tray(app: &AppHandle, state: &State) {
    if let (Some(tray), Ok(menu)) = (app.tray_by_id("main"), tray_menu(app, state)) {
        let _ = tray.set_menu(Some(menu));
        let up = state.sessions.lock().unwrap().iter().filter(|s| s.state == SessionState::Connected).count();
        let _ = tray.set_tooltip(Some(match up {
            0 => "Omnitun".to_owned(),
            1 => "Omnitun: 1 VPN up".to_owned(),
            n => format!("Omnitun: {n} VPNs up"),
        }));
    }
}

fn main() {
    let state: Shared = Arc::default();
    let hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            profiles,
            sessions,
            connect,
            disconnect,
            answer,
            trust,
            edit_profiles,
            update,
            open_releases,
            version
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let menu = tray_menu(&handle, &state)?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().expect("the app has an icon"))
                .tooltip("Omnitun")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event({
                    let state = state.clone();
                    move |app, event| {
                        let id = event.id().as_ref().to_owned();
                        match id.as_str() {
                            "open" => show(app),
                            "quit" => app.exit(0),
                            _ => {
                                let Some(profile) = id.strip_prefix("p:") else { return };
                                let up = state
                                    .sessions
                                    .lock()
                                    .unwrap()
                                    .iter()
                                    .any(|s| s.id == profile && s.state != SessionState::Failed);
                                let (app, profile) = (app.clone(), profile.to_owned());
                                tauri::async_runtime::spawn(async move {
                                    let state = app.state::<Shared>();
                                    let result = if up {
                                        disconnect(state, profile).await
                                    } else {
                                        connect(app.clone(), state, profile).await
                                    };
                                    if let Err(e) = result {
                                        let _ = app.emit("error", e);
                                        show(&app);
                                    }
                                });
                            }
                        }
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left, button_state: MouseButtonState::Up, ..
                    } = event
                    {
                        show(tray.app_handle());
                    }
                })
                .build(app)?;
            tauri::async_runtime::spawn(watch(handle.clone(), state.clone()));
            tauri::async_runtime::spawn(check_updates(handle.clone(), state.clone()));
            if !hidden {
                show(&handle);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // The window hides; the icon stays.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("the app starts");
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions_compare_by_number() {
        assert!(super::newer("0.10.0", "0.9.9"));
        assert!(super::newer("0.4.6", "0.4.5"));
        assert!(!super::newer("0.4.5", "0.4.5"));
        assert!(!super::newer("0.4.4", "0.4.5"));
    }
}
