//! `omnitunctl`: user-side CLI. Reads profiles from the user's config, keeps
//! secrets in the OS keychain, and drives `omnitund` over its control socket.

#[cfg(target_os = "macos")]
mod app;
mod completions;
mod log;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use vpn_client::{Daemon, Interaction, Notice, ProfileStore, Trust, import, printable, secrets};
use vpn_core::ipc::{Event, SessionInfo, SessionState};
use vpn_core::{CertificateInfo, FailureKind, Prompt, PromptKind, brand};
use zeroize::Zeroizing;

/// With the commit when apple/package.sh built it.
static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(vpn_core::version);

#[derive(Parser)]
#[command(version = VERSION.as_str(), about = "Omnitun command line: connect, disconnect and configure VPNs")]
struct Cli {
    /// Profiles file (default: ~/.config/omnitun/profiles.toml).
    #[arg(long, global = true, value_hint = ValueHint::FilePath)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bring up one or more profiles; they run side by side. A chained
    /// profile (`via`) goes through its first VPN that is up, or brings it
    /// up first.
    Connect {
        #[arg(value_name = "PROFILE")]
        names: Vec<String>,
        /// Without the VPNs the profiles are chained through.
        #[arg(long)]
        direct: bool,
        /// In split mode: only the profiles' `split_routes` go through the
        /// VPN.
        #[arg(long)]
        split: bool,
    },
    /// Tear down sessions.
    Disconnect {
        #[arg(value_name = "PROFILE")]
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Show active sessions.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List configured profiles.
    Profiles {
        /// Only the names to give other commands, one per line (for shell
        /// completions).
        #[arg(long)]
        names: bool,
    },
    /// List the Keychain certificates usable for IPsec authentication (the
    /// SHA-256 goes in a profile's client_certificate).
    Identities,
    /// Import profiles from another VPN client.
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },
    /// Manage secrets stored in the keychain for a profile.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Copy a profile, with its saved secrets, under a new name ("<name>
    /// copy" by default), listed after it.
    Duplicate {
        profile: String,
        /// The copy's name; a number is added if its folder has it already.
        #[arg(long)]
        name: Option<String>,
    },
    /// Write a profile as a .vpnprofile file to share (no secret, key or
    /// user name).
    Export {
        #[arg(value_name = "PROFILE")]
        name: String,
        /// File to write (default: standard output).
        #[arg(long, short, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },
    /// Follow state changes of your sessions until interrupted.
    Watch,
    /// The service's log for some sessions (all by default): the main
    /// lines, in local time. Readable by administrators.
    Log {
        /// Profile names.
        #[arg(value_name = "PROFILE")]
        names: Vec<String>,
        /// How far back: 30m, 2h, 3d.
        #[arg(long, default_value = "24h", value_parser = log::duration)]
        since: std::time::Duration,
        /// Every line, debug included, repetitions too.
        #[arg(long)]
        all: bool,
        /// Keep printing new lines.
        #[arg(long, short)]
        follow: bool,
    },
    /// A report to send when something goes wrong: versions, service,
    /// VPNs, sessions and the last day of log, with servers, accounts,
    /// domains and addresses replaced by placeholders.
    Diagnose {
        /// File to write (default: standard output).
        #[arg(long, short, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },
    /// Disconnect everything and restart the service (after an update).
    Shutdown,
    /// The menu bar app (macOS).
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Print the shell completion script: `omnitunctl completions zsh >
    /// "${fpath[1]}/_omnitunctl"`, or for bash into
    /// ~/.local/share/bash-completion/completions/omnitunctl.
    Completions { shell: completions::Shell },
}

#[derive(Subcommand)]
enum AppAction {
    /// Open the app, or bring it forward.
    Start,
    /// Quit the app, killing it if it is stuck, and open it again; the
    /// VPNs stay connected.
    Restart,
}

#[derive(Subcommand)]
enum ImportSource {
    /// A .vpnprofile file received from someone else.
    File {
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,
        /// Add it without asking.
        #[arg(long)]
        yes: bool,
    },
    /// An OpenVPN client configuration (.ovpn, .conf); the files it names
    /// are read and inlined.
    Openvpn {
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,
        /// Append to the profiles file instead of printing.
        #[arg(long)]
        write: bool,
    },
    /// Viscosity's connections: its library, or an exported .visc folder.
    Viscosity {
        #[arg(value_hint = ValueHint::AnyPath)]
        path: Option<PathBuf>,
        /// Append to the profiles file instead of printing.
        #[arg(long)]
        write: bool,
    },
    /// The VPNs of macOS's System Settings (Cisco IPSec); their secrets
    /// stay in the System keychain.
    Macos {
        #[arg(long, default_value = import::MACOS_NETWORK_PREFERENCES, value_hint = ValueHint::FilePath)]
        from: PathBuf,
        /// Append to the profiles file instead of printing.
        #[arg(long)]
        write: bool,
    },
    /// FortiClient's vpn.plist (macOS).
    Forticlient {
        #[arg(long, default_value = import::FORTICLIENT_PLIST, value_hint = ValueHint::FilePath)]
        from: PathBuf,
        /// Append to the profiles file instead of printing.
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Store a secret (asked interactively).
    Set {
        #[arg(value_name = "PROFILE")]
        profile: String,
        /// Which secret: password or psk.
        #[arg(long, default_value = "password")]
        key: String,
    },
    Delete {
        #[arg(value_name = "PROFILE")]
        profile: String,
        #[arg(long, default_value = "password")]
        key: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Needs no profiles file: run before opening one.
    if let Command::Completions { shell } = cli.command {
        print!("{}", completions::script(shell, &mut Cli::command())?);
        return Ok(());
    }
    let store = ProfileStore::open(cli.config)?;
    if store.is_legacy() {
        eprintln!("note: using {}; move it to ~/.config/{}/", store.path().display(), brand::ID);
    }
    match cli.command {
        Command::Connect { names, direct, split } => {
            if names.is_empty() {
                bail!("name at least one profile");
            }
            for key in names {
                // Its name, Folder/Name when several share it, or its id.
                let profile = store.find(&key)?;
                let name = profile.name.clone();
                let terminal = Terminal { name: name.clone(), store: &store };
                let options = vpn_client::ConnectOptions { direct, split };
                if let Err(e) = vpn_client::connect_with(profile.clone(), &store, brand::CLI, &terminal, options).await
                {
                    if let FailureKind::CertificateChanged { certificate, pinned } = vpn_core::failure::kind_of(&e) {
                        eprintln!(
                            "{name}: the server certificate CHANGED. This can be a renewal or an interception.\n  \
                             pinned:    {}\n  presented: {}\n\
                             Confirm the new fingerprint with your IT department before editing trusted_cert.",
                            pinned.join(", "),
                            certificate.sha256
                        );
                    }
                    return Err(e);
                }
            }
        }
        Command::Disconnect { names, all } => {
            let sessions = daemon().await?.status().await?;
            let targets: Vec<(String, String)> = if all {
                sessions.into_iter().map(|s| (s.id, s.name)).collect()
            } else {
                // A session whose profile is gone is named by its id.
                names
                    .into_iter()
                    .map(|key| match store.find(&key) {
                        Ok(p) => Ok((p.id, p.name)),
                        Err(_) if sessions.iter().any(|s| s.id == key) => Ok((key.clone(), key)),
                        Err(e) => Err(e),
                    })
                    .collect::<anyhow::Result<_>>()?
            };
            for (id, name) in targets {
                daemon().await?.disconnect(&id).await?;
                println!("{name}: disconnected");
            }
        }
        Command::Status { json } => {
            let sessions = daemon().await?.status().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else {
                print_status(&sessions);
            }
        }
        Command::Profiles { names: true } => {
            for key in completion_keys(&store.load()?) {
                println!("{key}");
            }
        }
        Command::Profiles { names: false } => {
            for p in store.load()? {
                println!("{:<32} {:<10} {}", vpn_client::profiles::path_of(&p), p.protocol.name(), p.id);
            }
        }
        Command::Identities => {
            for identity in vpn_client::keychain::identities()? {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
                let expired = if identity.not_after < now { ", expired" } else { "" };
                println!("{}  {} (issued by {}{expired})", identity.sha256, identity.name, identity.issuer);
            }
        }
        Command::Import { source: ImportSource::File { path, yes } } => {
            let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
            let profile = vpn_client::vpnprofile::parse(&text)?;
            let (host, port) = profile.protocol.endpoint();
            println!("{}: {} at {host}:{port}", profile.name, profile.protocol.name());
            if let vpn_core::ProtocolConfig::FortiSsl(p) = &profile.protocol {
                for pin in &p.trusted_cert {
                    println!("  trusted certificate SHA-256: {pin}");
                }
            }
            // What changes this Mac's routing and name resolution.
            match profile.full_tunnel {
                Some(true) => println!("  all traffic goes through the VPN"),
                Some(false) => println!("  only the VPN's networks go through it"),
                None => {}
            }
            if let Some(routes) = &profile.routes {
                println!("  networks: {}", routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
            }
            if !profile.split_routes.is_empty() {
                let networks = profile.split_routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                println!("  networks in split mode: {networks}");
            }
            for domain in &profile.dns_domains {
                println!("  names ending in .{domain} are resolved by the VPN");
            }
            if !yes && !confirm("Check these with whoever sent the file. Add this VPN? [y/N] ", false).await? {
                bail!("not added");
            }
            // A received profile is a new one, whatever id it might carry.
            let mut profile = profile;
            profile.id = vpn_core::new_id();
            store.save(&profile)?;
            println!("{} added to {}", profile.name, store.path().display());
        }
        Command::Duplicate { profile, name } => {
            let original = store.find(&profile)?;
            let copy = store.duplicate(&original.id, name.as_deref())?;
            println!("{}: copy of {}", vpn_client::profiles::path_of(&copy), vpn_client::profiles::path_of(&original));
            match vpn_client::secrets::copy(&original, &copy) {
                Ok(keys) if !keys.is_empty() => println!("  saved secrets copied: {}", keys.join(", ")),
                Ok(_) => {}
                Err(e) => eprintln!("  warning: the saved secrets were not copied: {e:#}"),
            }
        }
        Command::Export { name, output } => {
            let text = vpn_client::vpnprofile::export(&store.find(&name)?)?;
            match output {
                // Its shared keys (tls-auth, tls-crypt) are for the other
                // users of the VPN, not for everyone on this Mac.
                Some(path) => {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&path)
                        .and_then(|mut f| f.write_all(text.as_bytes()))
                        .with_context(|| format!("cannot write {}", path.display()))?
                }
                None => print!("{text}"),
            }
        }
        Command::Import { source: ImportSource::Forticlient { from, write } } => {
            let imported = import::forticlient(&from)?;
            if imported.is_empty() {
                bail!("no profile in {}", from.display());
            }
            let text: String = imported.iter().map(|i| i.toml.clone() + "\n").collect();
            if write {
                let added = store.append(&text)?;
                println!("{} profile(s) added to {}", added.len(), store.path().display());
            } else {
                print!("{text}");
            }
            for i in &imported {
                for note in &i.notes {
                    eprintln!("{}: {note}", i.name);
                }
                if i.needs_psk {
                    let name = &i.name;
                    eprintln!(
                        "{name}: pre-shared key not imported (FortiClient encrypts it): {} secret set {name} --key psk",
                        brand::CLI
                    );
                }
            }
        }
        Command::Import { source: ImportSource::Openvpn { path, write } } => {
            let existing: Vec<String> = store.load()?.into_iter().map(|p| p.name).collect();
            let imported = import::openvpn(&path, &existing)?;
            if write {
                store.append(&imported.toml)?;
                println!("{} added to {}", imported.name, store.path().display());
            } else {
                print!("{}", imported.toml);
            }
            for note in &imported.notes {
                eprintln!("{}: {note}", imported.name);
            }
        }
        Command::Import { source: ImportSource::Viscosity { path, write } } => {
            let existing: Vec<String> = store.load()?.into_iter().map(|p| p.name).collect();
            add_found(&store, import::viscosity(path.as_deref(), &existing)?, write, "Viscosity connection")?;
        }
        Command::Import { source: ImportSource::Macos { from, write } } => {
            let existing: Vec<String> = store.load()?.into_iter().map(|p| p.name).collect();
            add_found(&store, import::macos_vpns(Some(&from), &existing)?, write, "macOS VPN")?;
        }
        Command::Watch => watch().await?,
        Command::Diagnose { output } => {
            let client = format!("{} {}", brand::CLI, vpn_core::version());
            let report = vpn_client::diagnostic::report(&store, &client).await;
            match output {
                Some(path) => {
                    std::fs::write(&path, report).with_context(|| format!("cannot write {}", path.display()))?;
                    eprintln!("written to {}: read it before sending it", path.display());
                }
                None => print!("{report}"),
            }
        }
        Command::Log { names, since, all, follow } => {
            // Profiles are logged by name; a deleted one's name still works.
            let names = names.into_iter().map(|key| store.find(&key).map_or(key, |p| p.name)).collect();
            log::show(log::Options { names, since, all, follow }).await?;
        }
        Command::Shutdown => {
            daemon().await?.shutdown().await?;
            println!("{} is restarting; sessions were closed", brand::DAEMON);
        }
        #[cfg(target_os = "macos")]
        Command::App { action: AppAction::Start } => app::start()?,
        #[cfg(target_os = "macos")]
        Command::App { action: AppAction::Restart } => match app::restart()? {
            true => println!("{} restarted; the VPNs stay connected", brand::PRODUCT),
            false => println!("{} was not running: started", brand::PRODUCT),
        },
        #[cfg(not(target_os = "macos"))]
        Command::App { .. } => bail!("the menu bar app only exists on macOS"),
        Command::Completions { .. } => unreachable!("handled before the profiles file is opened"),
        Command::Secret { action } => match action {
            SecretAction::Set { profile, key } => {
                let profile = store.find(&profile)?;
                let value = Zeroizing::new(rpassword::prompt_password(format!("{key} for {}: ", profile.name))?);
                secrets::set(&profile, &key, &value)?;
                let (host, port) = profile.protocol.endpoint();
                println!("stored for {host}:{port}");
            }
            SecretAction::Delete { profile, key } => {
                let found = store.find(&profile)?;
                if !secrets::delete(&found, &key)? {
                    bail!("no {key} stored for {profile}");
                }
                println!("deleted");
            }
        },
    }
    Ok(())
}

async fn daemon() -> anyhow::Result<Daemon> {
    Daemon::open(brand::CLI).await
}

/// Prompts and progress of one connection, in the terminal.
struct Terminal<'a> {
    name: String,
    store: &'a ProfileStore,
}

#[async_trait::async_trait]
impl Interaction for Terminal<'_> {
    async fn ask(&self, prompt: &Prompt) -> anyhow::Result<Option<Zeroizing<String>>> {
        let label = format!("{}: {}: ", self.name, printable(&prompt.message));
        let hidden = prompt.kind == PromptKind::Secret;
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Zeroizing<String>>> {
            if hidden {
                return Ok(Some(Zeroizing::new(rpassword::prompt_password(label)?)));
            }
            print!("{label}");
            std::io::stdout().flush()?;
            let mut line = Zeroizing::new(String::new());
            if std::io::stdin().lock().read_line(&mut line)? == 0 {
                return Ok(None);
            }
            Ok(Some(Zeroizing::new(line.trim().to_owned())))
        })
        .await?
    }

    async fn trust(&self, certificate: &CertificateInfo) -> anyhow::Result<Trust> {
        println!(
            "{}: cannot verify the certificate of {}:{}{}\n  SHA-256: {}\n\
             Compare it with the fingerprint given by your IT department.",
            self.name,
            printable(&certificate.host),
            certificate.port,
            certificate.reason.as_deref().map(|r| format!(" ({})", printable(r))).unwrap_or_default(),
            certificate.sha256
        );
        if !confirm("Trust this certificate? [y/N] ", false).await? {
            return Ok(Trust::Reject);
        }
        Ok(if confirm("Save it in the profile (trusted_cert)? [Y/n] ", true).await? { Trust::Pin } else { Trust::Once })
    }

    fn open_url(&self, url: &str) {
        let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        if let Err(e) = std::process::Command::new(opener).arg(url).spawn() {
            eprintln!("cannot open a browser ({e}); open the URL manually");
        }
    }

    fn notice(&self, notice: Notice) {
        let name = &self.name;
        match notice {
            Notice::State { state, detail: Some(d), .. } => println!("{name}: {state:?} — {d}"),
            Notice::State { state, .. } => println!("{name}: {state:?}"),
            Notice::Warning(message) => eprintln!("{name}: warning: {message}"),
            Notice::LoginStarted(url) => println!("{name}: complete the login in your browser:\n  {}", printable(&url)),
            Notice::UrlRefused(url) => eprintln!("{name}: refusing to open {url} (not the profile's server)"),
            Notice::CertificatePinned => println!("{name}: certificate pinned in {}", self.store.path().display()),
            Notice::Connecting { name: other, .. } if other != *name => println!("{name}: connecting {other} first"),
            Notice::Connecting { .. } => {}
        }
    }
}

async fn confirm(question: &'static str, default: bool) -> anyhow::Result<bool> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        print!("{question}");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(match line.trim().to_ascii_lowercase().as_str() {
            "" => default,
            answer => answer == "y" || answer == "yes" || answer == "o" || answer == "oui",
        })
    })
    .await?
}

/// A session's profile name, or its id if the profile is gone.
fn store_name(id: &str) -> String {
    ProfileStore::open(None).and_then(|s| s.find(id)).map_or(id.to_owned(), |p| p.name)
}

async fn watch() -> anyhow::Result<()> {
    let mut daemon = daemon().await?.watch().await?;
    loop {
        match daemon.next().await? {
            Event::Status { sessions } => print_status(&sessions),
            Event::State { id, state, detail, retry, .. } => {
                let name = store_name(&id);
                let retry = retry.map(|r| format!(" (retry {}/{} in {}s)", r.attempt, r.max, r.delay_secs));
                println!(
                    "{name}: {state:?}{}{}",
                    detail.map(|d| format!(" — {}", printable(&d))).unwrap_or_default(),
                    retry.unwrap_or_default()
                );
            }
            Event::Error { message, .. } => bail!(printable(&message)),
            _ => {}
        }
    }
}

fn print_status(sessions: &[SessionInfo]) {
    if sessions.is_empty() {
        println!("no active session");
        return;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let ago = |at: u64| elapsed(now.saturating_sub(at));
    for (n, s) in sessions.iter().enumerate() {
        let state = match s.state {
            SessionState::Connected => "connected",
            SessionState::Connecting => "connecting",
            SessionState::Reconnecting => "reconnecting",
            SessionState::Disconnecting => "disconnecting",
            SessionState::Disconnected => "disconnected",
            SessionState::Failed => "failed",
        };
        if n > 0 {
            println!();
        }
        println!("{}  {state}  ({})", s.name, s.protocol);
        let row = |label: &str, value: String| println!("  {label:<12} {value}");
        if let Some(up) = s.up_since.or(s.connected_since) {
            let mut since = format!("up {}", ago(up));
            if let Some(first) = s.connected_since.filter(|first| *first != up) {
                since += &format!(", session started {} ago", ago(first));
            }
            row("uptime", since);
        }
        if s.reconnects > 0 {
            let last = s
                .last_drop
                .as_ref()
                .map_or(String::new(), |(at, why)| format!("; last drop {} ago: {}", ago(*at), printable(why)));
            row("drops", format!("{} reconnection attempt(s){last}", s.reconnects));
        }
        if let Some(detail) = &s.detail
            && s.state != SessionState::Connected
        {
            row("detail", printable(detail));
        }
        if let Some(interface) = &s.interface {
            let mut value = interface.clone();
            if let Some(address) = &s.address {
                value += &format!(", address {address}");
            }
            if let Some(mtu) = s.mtu {
                value += &format!(", MTU {mtu}");
            }
            row("interface", value);
        }
        if let Some(gateway) = &s.gateway {
            row("gateway", gateway.clone());
        }
        if let Some(via) = &s.via {
            row("through", via.clone());
        }
        if s.interface.is_some() {
            let routes = if s.full_tunnel { "all traffic".to_owned() } else { s.routes.join(", ") };
            row("routes", routes);
            if !s.excluded_routes.is_empty() {
                row("except", s.excluded_routes.join(", "));
            }
        }
        if !s.dns_servers.is_empty() {
            row("dns servers", s.dns_servers.join(", "));
        }
        if !s.dns_domains.is_empty() {
            row("dns domains", s.dns_domains.join(", "));
        }
        row("traffic", format!("received {}, sent {}", human(s.rx_bytes), human(s.tx_bytes)));
    }
}

/// "3 min", "2 h 05 min", "4 days 3 h".
fn elapsed(secs: u64) -> String {
    let (days, hours, minutes) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    match (days, hours) {
        (0, 0) if secs < 60 => format!("{secs} s"),
        (0, 0) => format!("{minutes} min"),
        (0, _) => format!("{hours} h {minutes:02} min"),
        _ => format!("{days} day(s) {hours} h"),
    }
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Prints or adds what an importer found; refusals and notes go to stderr.
fn add_found(store: &ProfileStore, found: Vec<import::Found>, write: bool, what: &str) -> anyhow::Result<()> {
    if found.is_empty() {
        bail!("no {what} found");
    }
    let mut text = String::new();
    for connection in &found {
        match &connection.result {
            Ok(imported) => {
                text += &imported.toml;
                text.push('\n');
                for note in &imported.notes {
                    eprintln!("{}: {note}", imported.name);
                }
                if imported.needs_psk {
                    let name = &imported.name;
                    eprintln!("{name}: pre-shared key not imported: {} secret set {name} --key psk", brand::CLI);
                }
            }
            Err(e) => eprintln!("{}: not imported: {e:#}", printable(&connection.display)),
        }
    }
    if text.is_empty() {
        bail!("no {what} could be imported");
    }
    if write {
        let added = store.append(&text)?;
        println!("{} profile(s) added to {}", added.len(), store.path().display());
    } else {
        print!("{text}");
    }
    Ok(())
}

/// How each profile can be named on the command line, for completions.
fn completion_keys(profiles: &[vpn_core::Profile]) -> Vec<String> {
    profiles
        .iter()
        .map(|p| {
            // `find` takes the bare name only when no other VPN has it.
            if profiles.iter().filter(|other| other.name == p.name).count() == 1 {
                p.name.clone()
            } else {
                vpn_client::profiles::path_of(p)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, folder: Option<&str>) -> vpn_core::Profile {
        let mut v = serde_json::json!({ "name": name, "protocol": "forti-ssl", "host": "vpn.example.com" });
        if let Some(folder) = folder {
            v["folder"] = folder.into();
        }
        serde_json::from_value(v).unwrap()
    }

    /// What `find` accepts, shortest first: the bare name when it is the
    /// only one, the folder path when several VPNs share it.
    #[test]
    fn completion_keys_are_names_unless_shared() {
        let profiles = [
            profile("paris", None),
            profile("EU", Some("Clients/Acme")),
            profile("EU", Some("Clients/Beta")),
            profile("lyon office", Some("Sites")),
        ];
        assert_eq!(completion_keys(&profiles), ["paris", "Clients/Acme/EU", "Clients/Beta/EU", "lyon office"]);
    }
}
