//! Product naming, kept in one place. A rename touches this file, the
//! `name` of the daemon and CLI packages, and the files in `packaging/`.

/// Name shown to people.
pub const PRODUCT: &str = "Omnitun";
/// Lowercase identifier: config directory, keychain service, dynamic store
/// prefix, runtime files.
pub const ID: &str = "omnitun";
/// Binary names; must match the package names of the daemon and the CLI.
pub const DAEMON: &str = "omnitund";
pub const CLI: &str = "omnitunctl";
/// Unprivileged protocol process started by the daemon, one per connection
/// attempt; must match the engine package name.
pub const ENGINE: &str = "omnitun-engine";
/// System account the engines run as (created by the installer).
pub const ENGINE_USER: &str = "_omnitun";
/// Reverse-DNS prefix (a domain we own): bundle, UTI, signing and package
/// identifiers.
pub const REVERSE_DNS: &str = "com.root42.omnitun";
/// launchd label (macOS): `REVERSE_DNS` + `.daemon`; matches
/// `packaging/com.root42.omnitun.daemon.plist`.
pub const LAUNCHD_LABEL: &str = "com.root42.omnitun.daemon";
/// Overrides the control socket path (tests, side-by-side installs).
pub const SOCKET_ENV: &str = "OMNITUN_SOCKET";

/// Names from before the product had one, still read so that existing
/// profiles, keychain entries and stale resolver entries are found.
pub mod legacy {
    pub const CONFIG_DIR: &str = "vpn";
    pub const KEYCHAIN_SERVICE: &str = "vpnctl";
    pub const DAEMON: &str = "vpnd";
}

/// Directory of the daemon's runtime files: the control socket (not on
/// Windows) and the route journal. A reboot clears it on macOS and Linux;
/// on Windows it is `%ProgramData%\Omnitun`, which only SYSTEM and
/// Administrators can change.
pub fn runtime_dir() -> String {
    if cfg!(target_os = "macos") {
        "/var/run".to_owned()
    } else if cfg!(windows) {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
        format!(r"{base}\{PRODUCT}")
    } else {
        "/run".to_owned()
    }
}

/// Default control socket path; a named pipe on Windows.
pub fn default_socket() -> String {
    if cfg!(windows) {
        return format!(r"\\.\pipe\{DAEMON}");
    }
    std::path::Path::new(&runtime_dir()).join(format!("{DAEMON}.sock")).display().to_string()
}
