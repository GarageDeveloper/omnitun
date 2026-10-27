//! Bringing up one profile: the daemon asks, the user's side answers.
//! Secrets come from the keychain when stored, the rest from the
//! [`Interaction`] (terminal, app window); certificate decisions and browser
//! logins are checked here so every front end applies the same rules.

use anyhow::{Context, ensure};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use vpn_core::ipc::{Event, Request, Retry, SessionInfo, SessionState};
use vpn_core::{CertificateInfo, Profile, Prompt, PromptKind};
use zeroize::{Zeroize, Zeroizing};

use crate::client_key::ClientKey;
use crate::{Daemon, ProfileStore, printable};

/// What the user decided about a certificate that cannot be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Reject,
    /// For this connection only.
    Once,
    /// And remember it in the profile (`trusted_cert`).
    Pin,
}

/// Progress worth showing; text from the gateway is already made printable.
#[derive(Debug, Clone)]
pub enum Notice {
    State {
        state: SessionState,
        detail: Option<String>,
        retry: Option<Retry>,
    },
    Warning(String),
    /// The browser login page was opened.
    LoginStarted(String),
    /// The daemon asked to open a page outside the profile's server.
    UrlRefused(String),
    /// Now connecting this profile (id, name): the one asked for, or a VPN
    /// it goes through, brought up first. Prompts and states that follow
    /// are its.
    Connecting {
        id: String,
        name: String,
    },
    CertificatePinned,
}

/// The user's side of a connection.
#[async_trait]
pub trait Interaction: Send + Sync {
    /// Answers a prompt the keychain could not; `None` cancels.
    async fn ask(&self, prompt: &Prompt) -> anyhow::Result<Option<Zeroizing<String>>>;
    async fn trust(&self, certificate: &CertificateInfo) -> anyhow::Result<Trust>;
    /// Opens a login page, already checked to belong to the profile's server.
    fn open_url(&self, url: &str);
    fn notice(&self, notice: Notice);
}

/// Connects `profile` and returns once the daemon has taken it over (it
/// keeps running after this connection closes). Errors carry the
/// [`vpn_core::FailureKind`] reported by the daemon. A chained profile
/// (`via`) goes through the first of its VPNs that is up, or brings up
/// the first one before.
pub async fn connect(
    profile: Profile,
    store: &ProfileStore,
    client: &str,
    user: &dyn Interaction,
) -> anyhow::Result<()> {
    connect_with(profile, store, client, user, ConnectOptions::default()).await
}

/// How to connect, besides the profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectOptions {
    /// Without the VPNs the profile is chained through.
    pub direct: bool,
    /// In split mode: only the profile's `split_routes` go through the VPN.
    pub split: bool,
}

pub async fn connect_with(
    profile: Profile,
    store: &ProfileStore,
    client: &str,
    user: &dyn Interaction,
    options: ConnectOptions,
) -> anyhow::Result<()> {
    let ConnectOptions { direct, split } = options;
    // A company VPN still runs alone in split mode.
    let profile = if split { profile.in_split_mode()? } else { profile };
    let sessions = Daemon::open(client).await?.status().await?;
    let others = exclusive_conflicts(&profile, &sessions, &store.load()?, direct);
    ensure!(others.is_empty(), "{}", exclusive_refusal(&profile, &others));
    let via = match direct || profile.via.is_empty() {
        true => None,
        false => Some(chain_parent(&profile, store, client, user, 0).await?),
    };
    connect_one(profile, store, client, user, via).await
}

/// The sessions that keep `profile` from coming up, by name: a company VPN
/// (`exclusive`) is never up at the same time as another VPN, the VPNs it
/// goes through excepted (unless connected `direct`).
pub fn exclusive_conflicts(
    profile: &Profile,
    sessions: &[SessionInfo],
    profiles: &[Profile],
    direct: bool,
) -> Vec<String> {
    let up = [SessionState::Connecting, SessionState::Connected, SessionState::Reconnecting];
    let exclusive = |id: &str| profiles.iter().any(|p| p.id == id && p.exclusive);
    sessions
        .iter()
        .filter(|s| s.id != profile.id && up.contains(&s.state))
        .filter(|s| direct || !profile.via.contains(&s.id))
        .filter(|s| profile.exclusive || exclusive(&s.id))
        .map(|s| s.name.clone())
        .collect()
}

fn exclusive_refusal(profile: &Profile, others: &[String]) -> String {
    match profile.exclusive {
        true => format!("{} is a company VPN that runs alone: disconnect {} first", profile.name, others.join(", ")),
        false => format!("{} is a company VPN that runs alone: disconnect it first", others.join(", ")),
    }
}

/// The VPN `profile` goes through: the first of its list that is up, or
/// the first one, brought up now (itself chained if it says so).
fn chain_parent<'a>(
    profile: &'a Profile,
    store: &'a ProfileStore,
    client: &'a str,
    user: &'a dyn Interaction,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>> {
    Box::pin(async move {
        ensure!(depth < vpn_core::profile::MAX_VIA, "the VPN chain of {} is too long or loops", profile.name);
        let sessions = Daemon::open(client).await?.status().await?;
        let state = |id: &str| sessions.iter().find(|s| s.id == id).map(|s| s.state);
        if let Some(up) = profile.via.iter().find(|v| state(v) == Some(SessionState::Connected)) {
            return Ok(up.clone());
        }
        let busy = [SessionState::Connecting, SessionState::Reconnecting, SessionState::Disconnecting];
        if let Some(busy) = profile.via.iter().find(|v| state(v).is_some_and(|s| busy.contains(&s))) {
            let busy = store.find(busy).map_or(busy.clone(), |p| p.name);
            anyhow::bail!("{busy}, which {} goes through, is not connected yet: try again once it is", profile.name);
        }
        let first = store
            .find(&profile.via[0])
            .with_context(|| format!("{} goes through a VPN that no longer exists", profile.name))?;
        let (id, name) = (first.id.clone(), first.name.clone());
        let via = match first.via.is_empty() {
            true => None,
            false => Some(chain_parent(&first, store, client, user, depth + 1).await?),
        };
        connect_one(first, store, client, user, via)
            .await
            .with_context(|| format!("{} goes through {name}", profile.name))?;
        Ok(id)
    })
}

async fn connect_one(
    mut profile: Profile,
    store: &ProfileStore,
    client: &str,
    user: &dyn Interaction,
    via: Option<String>,
) -> anyhow::Result<()> {
    user.notice(Notice::Connecting { id: profile.id.clone(), name: profile.name.clone() });
    if let vpn_core::ProtocolConfig::FortiSsl(p) = &mut profile.protocol {
        // The daemon runs as root and never opens user-supplied paths.
        p.inline_files()?;
    }
    // Set at each connection: whatever a stored profile holds is replaced.
    let keychain = crate::keychain::trusted_authorities();
    if let Some(field) = profile.protocol.keychain_ca_pem() {
        *field = (!keychain.is_empty()).then_some(keychain);
    }
    // The key stays here: the engine asks for each signature.
    let key = ClientKey::take(&mut profile)?;
    profile.validate()?;
    let mut daemon = Daemon::open(client).await?;
    daemon.send(&Request::Connect { profile: Box::new(profile.clone()), via }).await?;
    // The session's questions come from its engine, on the prompt socket.
    let mut prompts: Option<PromptSocket> = None;
    let mut signatures = SignBudget::default();
    loop {
        let event = match &mut prompts {
            Some(socket) => tokio::select! {
                event = daemon.next() => event?,
                asked = socket.next() => match asked? {
                    Some(event) => {
                        handle_question(event, socket, &profile, key.as_ref(), store, user, &mut signatures).await?;
                        continue;
                    }
                    None => {
                        prompts = None;
                        continue;
                    }
                },
            },
            None => daemon.next().await?,
        };
        match event {
            Event::Attach { socket } => prompts = Some(PromptSocket::open(&socket).await?),
            Event::State { state, detail, retry, .. } => {
                user.notice(Notice::State { state, detail: detail.as_deref().map(printable), retry })
            }
            Event::Warning { message } => user.notice(Notice::Warning(printable(&message))),
            Event::Done => {
                // Renegotiations and reconnections sign again: this
                // process keeps signing for the session while it lives.
                if let (Some(socket), Some(key)) = (prompts, key) {
                    tokio::spawn(keep_signing(socket, profile, key, signatures));
                }
                return Ok(());
            }
            Event::Error { message, failure } => return Err(crate::daemon::error(message, failure)),
            Event::Prompt { .. } | Event::OpenUrl { .. } | Event::Status { .. } | Event::Hello { .. } => {}
        }
    }
}

/// A question from the session's engine, answered on its prompt socket.
async fn handle_question(
    event: Event,
    socket: &mut PromptSocket,
    profile: &Profile,
    key: Option<&ClientKey>,
    store: &ProfileStore,
    user: &dyn Interaction,
    signatures: &mut SignBudget,
) -> anyhow::Result<()> {
    match event {
        Event::Prompt { id, prompt } if prompt.kind == PromptKind::Sign => {
            let signature = match sign(profile, key, prompt.sign.as_ref(), signatures).await {
                Ok(signature) => Some(signature),
                Err(e) => {
                    user.notice(Notice::Warning(format!("{e:#}")));
                    None
                }
            };
            socket.answer(id, signature).await
        }
        Event::Prompt { id, prompt } if prompt.key == vpn_core::prompt::TRUST_CERTIFICATE => {
            let value = match &prompt.certificate {
                Some(certificate) => trust(profile, store, certificate, user).await?,
                None => None,
            };
            socket.answer(id, value).await
        }
        Event::Prompt { id, prompt } => {
            let value = answer(profile, &prompt, user).await?;
            socket.answer(id, value.as_ref().map(|v| v.to_string())).await
        }
        Event::OpenUrl { url } => {
            if login_url_allowed(profile, &url) {
                user.notice(Notice::LoginStarted(url.clone()));
                user.open_url(&url);
            } else {
                user.notice(Notice::UrlRefused(printable(&url)));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The session's prompt socket: the engine asks, the user answers; the
/// daemon is not on the way.
struct PromptSocket {
    read: BufReader<tokio::net::unix::OwnedReadHalf>,
    write: tokio::net::unix::OwnedWriteHalf,
}

/// Longest question accepted from an engine.
const MAX_QUESTION: u64 = 1024 * 1024;

impl PromptSocket {
    async fn open(path: &str) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(path).await.with_context(|| format!("cannot reach the session at {path}"))?;
        let (read, write) = stream.into_split();
        Ok(Self { read: BufReader::new(read), write })
    }

    /// The next question; `None` once the engine closed the socket.
    async fn next(&mut self) -> anyhow::Result<Option<Event>> {
        let mut line = String::new();
        if (&mut self.read).take(MAX_QUESTION).read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        anyhow::ensure!(line.ends_with('\n'), "the session sent an oversized message");
        Ok(Some(serde_json::from_str(&line)?))
    }

    async fn answer(&mut self, id: u64, value: Option<String>) -> anyhow::Result<()> {
        let mut request = Request::Answer { id, value };
        let mut line = Zeroizing::new(serde_json::to_vec(&request)?);
        line.push(b'\n');
        if let Request::Answer { value: Some(v), .. } = &mut request {
            v.zeroize();
        }
        self.write.write_all(&line).await?;
        Ok(())
    }
}

/// The answer accepting a certificate is its fingerprint, so a stale
/// answer never accepts another one.
async fn trust(
    profile: &Profile,
    store: &ProfileStore,
    certificate: &CertificateInfo,
    user: &dyn Interaction,
) -> anyhow::Result<Option<String>> {
    let decision = user.trust(certificate).await?;
    if decision == Trust::Pin {
        store.pin_certificate(&profile.id, &certificate.sha256)?;
        user.notice(Notice::CertificatePinned);
    }
    Ok((decision != Trust::Reject).then(|| certificate.sha256.clone()))
}

/// Signatures a session may ask for in a row: one per attempt, per TLS
/// connection it could not resume, per OpenVPN renegotiation.
const MAX_SIGNATURES: usize = 8;
const SIGNATURE_PERIOD: std::time::Duration = std::time::Duration::from_secs(600);

/// At most `MAX_SIGNATURES` in any `SIGNATURE_PERIOD`.
#[derive(Default)]
struct SignBudget {
    recent: std::collections::VecDeque<std::time::Instant>,
}

impl SignBudget {
    fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        while self.recent.front().is_some_and(|t| now.duration_since(*t) >= SIGNATURE_PERIOD) {
            self.recent.pop_front();
        }
        if self.recent.len() >= MAX_SIGNATURES {
            return false;
        }
        self.recent.push_back(now);
        true
    }
}

/// After the session is up: answers its signature requests, and nothing
/// else (a password or a code needs the user, who is not there).
async fn keep_signing(mut socket: PromptSocket, profile: Profile, key: ClientKey, mut budget: SignBudget) {
    while let Ok(Some(event)) = socket.next().await {
        let Event::Prompt { id, prompt } = event else { continue };
        let signature = match prompt.kind {
            PromptKind::Sign => sign(&profile, Some(&key), prompt.sign.as_ref(), &mut budget)
                .await
                .inspect_err(|e| tracing::warn!("{}: signature refused: {e:#}", profile.name))
                .ok(),
            _ => None,
        };
        if socket.answer(id, signature).await.is_err() {
            return;
        }
    }
}

/// Signs with the profile's client certificate, and only what IKE or TLS
/// signs: the engine is not trusted to use the key for anything else.
async fn sign(
    profile: &Profile,
    key: Option<&ClientKey>,
    request: Option<&vpn_core::SignRequest>,
    budget: &mut SignBudget,
) -> anyhow::Result<String> {
    let request = request.context("signature request without data")?;
    let key = key.context("this profile has no client certificate")?;
    ensure!(
        key.sha256().eq_ignore_ascii_case(&request.certificate),
        "the session asked to sign with a certificate the profile does not use"
    );
    ensure!(budget.take(), "the session asked for too many signatures");
    let data = hex::decode(&request.data).context("malformed signature request")?;
    let expected = match &profile.protocol {
        vpn_core::ProtocolConfig::Ipsec(_) => vpn_core::prompt::is_ike_auth_octets(&data),
        vpn_core::ProtocolConfig::FortiSsl(_) | vpn_core::ProtocolConfig::OpenVpn(_) => {
            vpn_core::prompt::is_tls_client_signature_octets(&data)
        }
        // No certificate in L2TP and WireGuard profiles.
        vpn_core::ProtocolConfig::L2tp(_) | vpn_core::ProtocolConfig::WireGuard(_) => false,
    };
    ensure!(expected, "the session asked to sign something else than its authentication");
    let (key, algorithm) = (key.clone(), request.algorithm);
    // The Keychain may wait for the user to allow the key's use.
    let signature = tokio::task::spawn_blocking(move || key.sign(algorithm, &data)).await??;
    Ok(hex::encode(signature))
}

/// Keychain first for secrets, then the user.
async fn answer(
    profile: &Profile,
    prompt: &Prompt,
    user: &dyn Interaction,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    if prompt.kind == PromptKind::Secret
        && let Ok(Some(value)) = crate::secrets::get(profile, &prompt.key)
    {
        return Ok(Some(value));
    }
    user.ask(prompt).await
}

/// The browser only opens the HTTPS pages of the profile's own server.
pub fn login_url_allowed(profile: &Profile, url: &str) -> bool {
    let (host, port) = profile.protocol.endpoint();
    let origin = if port == 443 { format!("https://{host}/") } else { format!("https://{host}:{port}/") };
    url.starts_with(&origin) && !url.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(host: &str, port: u16) -> Profile {
        toml::from_str(&format!("name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"{host}\"\nport = {port}"))
            .unwrap()
    }

    #[test]
    fn company_vpns_run_alone() {
        let named = |id: &str, exclusive: bool| Profile {
            id: id.into(),
            name: id.into(),
            exclusive,
            ..profile("vpn.example.com", 443)
        };
        let session = |id: &str, state| SessionInfo {
            id: id.into(),
            name: id.into(),
            protocol: "forti-ssl".into(),
            state,
            interface: None,
            address: None,
            full_tunnel: false,
            routes: Vec::new(),
            dns_domains: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            connected_since: None,
            detail: None,
            failure: None,
            via: None,
            gateway: None,
            mtu: None,
            dns_servers: Vec::new(),
            excluded_routes: Vec::new(),
            up_since: None,
            reconnects: 0,
            last_drop: None,
        };
        let (company, lab, home) = (named("company", true), named("lab", false), named("home", false));
        let profiles = [company.clone(), lab.clone(), home.clone()];
        let lab_up = [session("lab", SessionState::Connected), session("home", SessionState::Failed)];
        assert_eq!(exclusive_conflicts(&company, &lab_up, &profiles, false), ["lab"], "ended sessions do not count");
        assert!(exclusive_conflicts(&home, &lab_up, &profiles, false).is_empty(), "ordinary VPNs run together");
        let company_up = [session("company", SessionState::Reconnecting)];
        assert_eq!(exclusive_conflicts(&lab, &company_up, &profiles, false), ["company"]);
        assert!(exclusive_conflicts(&company, &company_up, &profiles, false).is_empty(), "itself");
        // A VPN it goes through is no other VPN, unless connected directly.
        let chained = Profile { via: vec!["lab".into()], ..company.clone() };
        assert!(exclusive_conflicts(&chained, &lab_up, &profiles, false).is_empty());
        assert_eq!(exclusive_conflicts(&chained, &lab_up, &profiles, true), ["lab"]);
    }

    #[test]
    fn signatures_are_rate_limited() {
        let mut budget = SignBudget::default();
        assert!((0..MAX_SIGNATURES).all(|_| budget.take()));
        assert!(!budget.take());
        budget.recent[0] -= SIGNATURE_PERIOD;
        assert!(budget.take(), "an old one no longer counts");
    }

    #[test]
    fn browser_only_opens_the_profile_server() {
        let p = profile("vpn.example.com", 443);
        assert!(login_url_allowed(&p, "https://vpn.example.com/remote/saml/start?redirect=1"));
        for bad in [
            "http://vpn.example.com/remote/saml/start",
            "https://vpn.example.com.evil.net/x",
            "https://vpn.example.com@evil.net/x",
            "file:///etc/passwd",
            "https://vpn.example.com/\nx",
        ] {
            assert!(!login_url_allowed(&p, bad), "{bad:?}");
        }
        let p = profile("vpn.example.com", 4443);
        assert!(login_url_allowed(&p, "https://vpn.example.com:4443/remote/saml/start"));
        assert!(!login_url_allowed(&p, "https://vpn.example.com/remote/saml/start"));
    }
}
