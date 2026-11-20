//! Updates by WinSparkle, as Sparkle on macOS: WinSparkle.dll, next to the
//! app where the installer puts it, reads the `appcast-windows.xml` of the
//! latest GitHub Release (packaging/windows/appcast.sh), offers the MSI of
//! this architecture, checks its EdDSA signature (the macOS app's key) and
//! starts it; the user decides. Without the DLL (a development build), the
//! window offers the newer release it finds on GitHub (main.rs).

use std::ffi::{CString, c_char, c_int};
use std::sync::OnceLock;

use tauri::AppHandle;

const FEED: &str = "https://github.com/GarageDeveloper/omnitun/releases/latest/download/appcast-windows.xml";
/// Sparkle's public key (apple/Info.plist, SUPublicEDKey).
const PUBLIC_KEY: &str = "peDskHzmxuRsSOsL+TqJFYme/VWtiHYoVVun5Ytmtyc=";
const DAY_SECS: c_int = 86_400;

type Void = unsafe extern "C" fn();
type SetText = unsafe extern "C" fn(*const c_char);
type SetInt = unsafe extern "C" fn(c_int);
type SetKey = unsafe extern "C" fn(*const c_char) -> c_int;
type SetDetails = unsafe extern "C" fn(*const u16, *const u16, *const u16);
type SetCallback = unsafe extern "C" fn(Option<unsafe extern "C" fn()>);
type SetCanShutdown = unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>);

struct WinSparkle {
    set_automatic: SetInt,
    check_with_ui: Void,
    cleanup: Void,
    /// Keeps the functions above loaded.
    _library: libloading::Library,
}

static SPARKLE: OnceLock<Option<WinSparkle>> = OnceLock::new();
static APP: OnceLock<AppHandle> = OnceLock::new();

/// Starts WinSparkle if the app has it; false otherwise.
pub fn start(app: &AppHandle, automatic: bool, french: bool) -> bool {
    let _ = APP.set(app.clone());
    SPARKLE.get_or_init(|| load(automatic, french).ok()).is_some()
}

/// Whether WinSparkle looks for updates by itself (once a day).
pub fn set_automatic(on: bool) {
    if let Some(Some(sparkle)) = SPARKLE.get() {
        // SAFETY: a function of the loaded WinSparkle; any thread.
        unsafe { (sparkle.set_automatic)(c_int::from(on)) };
    }
}

/// Looks for an update now, in WinSparkle's window; false without it.
pub fn check_with_ui() -> bool {
    let Some(Some(sparkle)) = SPARKLE.get() else { return false };
    // SAFETY: as above; it returns at once and checks in its own thread.
    unsafe { (sparkle.check_with_ui)() };
    true
}

/// Stops WinSparkle's threads, when the app ends.
pub fn cleanup() {
    if let Some(Some(sparkle)) = SPARKLE.get() {
        // SAFETY: as above, once, from the main thread.
        unsafe { (sparkle.cleanup)() };
    }
}

/// WinSparkle asks before starting the installer: the app may always end
/// (the VPNs belong to the service).
unsafe extern "C" fn can_shutdown() -> c_int {
    1
}

/// The installer started: the app ends, for it to be replaced.
unsafe extern "C" fn shutdown() {
    if let Some(app) = APP.get() {
        app.exit(0);
    }
}

fn load(automatic: bool, french: bool) -> anyhow::Result<WinSparkle> {
    // By its full path: never another WinSparkle.dll from the search path.
    let path = std::env::current_exe()?.with_file_name("WinSparkle.dll");
    if !path.exists() {
        anyhow::bail!("no WinSparkle.dll");
    }
    // SAFETY: WinSparkle's DLL, installed with the app in Program Files.
    let library = unsafe { libloading::Library::new(&path)? };
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (company, name, version) = (wide("GarageDeveloper"), wide("Omnitun"), wide(env!("CARGO_PKG_VERSION")));
    let (feed, key, lang) =
        (CString::new(FEED)?, CString::new(PUBLIC_KEY)?, CString::new(if french { "fr" } else { "en" })?);
    // SAFETY: the functions of winsparkle.h with their C types; the
    // configuration comes before win_sparkle_init, as it asks, from the
    // main thread (the app's setup). The strings are copied by WinSparkle.
    unsafe {
        library.get::<SetText>(b"win_sparkle_set_lang\0")?(lang.as_ptr());
        library.get::<SetText>(b"win_sparkle_set_appcast_url\0")?(feed.as_ptr());
        if library.get::<SetKey>(b"win_sparkle_set_eddsa_public_key\0")?(key.as_ptr()) == 0 {
            anyhow::bail!("WinSparkle refused the public key");
        }
        library.get::<SetDetails>(b"win_sparkle_set_app_details\0")?(company.as_ptr(), name.as_ptr(), version.as_ptr());
        library.get::<SetInt>(b"win_sparkle_set_update_check_interval\0")?(DAY_SECS);
        // Set before init, WinSparkle does not ask on the first run.
        library.get::<SetInt>(b"win_sparkle_set_automatic_check_for_updates\0")?(c_int::from(automatic));
        library.get::<SetCanShutdown>(b"win_sparkle_set_can_shutdown_callback\0")?(Some(can_shutdown));
        library.get::<SetCallback>(b"win_sparkle_set_shutdown_request_callback\0")?(Some(shutdown));
        library.get::<Void>(b"win_sparkle_init\0")?();
        Ok(WinSparkle {
            set_automatic: *library.get::<SetInt>(b"win_sparkle_set_automatic_check_for_updates\0")?,
            check_with_ui: *library.get::<Void>(b"win_sparkle_check_update_with_ui\0")?,
            cleanup: *library.get::<Void>(b"win_sparkle_cleanup\0")?,
            _library: library,
        })
    }
}
