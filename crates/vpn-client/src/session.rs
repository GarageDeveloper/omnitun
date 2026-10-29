//! Bringing up one profile: the daemon asks, the user's side answers.
//! Secrets come from the keychain when stored, the rest from the
//! [`Interaction`] (terminal, app window); certificate decisions and browser
//! logins are checked here so every front end applies the same rules.

use anyhow::{Context, ensure};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
) -> anyhow::Result<Connected> {
    connect_with(profile, store, client, user, ConnectOptions::default()).await
}

/// A connection the daemon took over. Its client certificate, if any,
/// stays here: renegotiations and reconnections are signed by this process
/// while it lives.
#[must_use = "a session with a client certificate needs this process to sign"]
pub struct Connected {
    signers: Vec<tokio::task::JoinHandle<()>>,
}

impl Connected {
    /// Whether the session (or a VPN it goes through) will ask this
    /// process for signatures.
    pub fn signs(&self) -> bool {
        !self.signers.is_empty()
    }

    /// Returns once no session needs this process to sign any more.
    pub async fn signing(self) {
        for signer in self.signers {
            let _ = signer.await;
        }
    }
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
) -> anyhow::Result<Connected> {
    let ConnectOptions { direct, split } = options;
    // A company VPN still runs alone in split mode.
    let profile = if split { profile.in_split_mode()? } else { profile };
    let sessions = Daemon::open(client).await?.status().await?;
    let others = exclusive_conflicts(&profile, &sessions, &store.load()?, direct);
    ensure!(others.is_empty(), "{}", exclusive_refusal(&profile, &others));
    let mut signers = Vec::new();
    let via = match direct || profile.via.is_empty() {
        true => None,
        false => Some(chain_parent(&profile, store, client, user, 0, &mut signers).await?),
    };
    signers.extend(connect_one(profile, store, client, user, via).await?);
    Ok(Connected { signers })
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
    signers: &'a mut Vec<tokio::task::JoinHandle<()>>,
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
            false => Some(chain_parent(&first, store, client, user, depth + 1, signers).await?),
        };
        let signer = connect_one(first, store, client, user, via)
            .await
            .with_context(|| format!("{} goes through {name}", profile.name))?;
        signers.extend(signer);
        Ok(id)
    })
}

async fn connect_one(
    mut profile: Profile,
    store: &ProfileStore,
    client: &str,
    user: &dyn Interaction,
    via: Option<String>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
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
                return Ok(match (prompts, key) {
                    (Some(socket), Some(key)) => Some(tokio::spawn(keep_signing(socket, profile, key, signatures))),
                    _ => None,
                });
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
        Event::Prompt { id, prompt } if prompt.key == vpn_core::prompt::L2TP_SERVER_PROVED => {
            if let vpn_core::ProtocolConfig::L2tp(_) = &profile.protocol
                && let Err(e) = store.require_mschapv2(&profile.id)
            {
                user.notice(Notice::Warning(format!("{e:#}")));
            }
            socket.answer(id, Some(String::new())).await
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
    read: tokio::net::unix::OwnedReadHalf,
    /// What was read past the last whole question. `next` runs in a
    /// `select!`: a question read in parts survives its cancellation.
    pending: Vec<u8>,
    write: tokio::net::unix::OwnedWriteHalf,
}

/// Longest question accepted from an engine.
const MAX_QUESTION: usize = 1024 * 1024;

impl PromptSocket {
    async fn open(path: &str) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(path).await.with_context(|| format!("cannot reach the session at {path}"))?;
        Ok(Self::new(stream))
    }

    fn new(stream: UnixStream) -> Self {
        let (read, write) = stream.into_split();
        Self { read, pending: Vec::new(), write }
    }

    /// The next question; `None` once the engine closed the socket.
    /// Cancel safe: nothing read is lost.
    async fn next(&mut self) -> anyhow::Result<Option<Event>> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                return Ok(Some(serde_json::from_slice(&line)?));
            }
            ensure!(self.pending.len() < MAX_QUESTION, "the session sent an oversized message");
            if self.read.read_buf(&mut self.pending).await? == 0 {
                ensure!(self.pending.is_empty(), "the session closed in the middle of a message");
                return Ok(None);
            }
        }
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
/// signs: the engine is not trusted to use the key for anything else. A
/// TLS 1.2 signature covers the ClientHello, whose server name must be the
/// profile's server; a TLS 1.3 or IKEv2 one covers only hashes and nonces,
/// so a compromised engine could still have the key sign a handshake with
/// another server trusting the same certificate (within the budget).
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
        vpn_core::ProtocolConfig::FortiSsl(p) => tls_signature_for(&data, [p.host.as_str()]),
        vpn_core::ProtocolConfig::OpenVpn(p) => tls_signature_for(&data, p.remotes.iter().map(|r| r.host.as_str())),
        // No certificate in L2TP and WireGuard profiles.
        vpn_core::ProtocolConfig::L2tp(_) | vpn_core::ProtocolConfig::WireGuard(_) => false,
    };
    ensure!(expected, "the session asked to sign something else than its authentication");
    let (key, algorithm) = (key.clone(), request.algorithm);
    // The Keychain may wait for the user to allow the key's use.
    let signature = tokio::task::spawn_blocking(move || key.sign(algorithm, &data)).await??;
    Ok(hex::encode(signature))
}

/// TLS client signature octets, for one of `hosts` if TLS 1.2: TLS sends no
/// server name for an IP address.
fn tls_signature_for<'a>(data: &[u8], hosts: impl IntoIterator<Item = &'a str>) -> bool {
    use vpn_core::prompt::{is_tls_client_signature_octets, tls12_server_name};
    if !is_tls_client_signature_octets(data) {
        return false;
    }
    if data.first() != Some(&1) {
        return true; // TLS 1.3
    }
    let name = tls12_server_name(data);
    hosts.into_iter().any(|host| match host.parse::<std::net::IpAddr>() {
        Ok(_) => name.is_none(),
        Err(_) => {
            name.as_deref().is_some_and(|n| n.trim_end_matches('.').eq_ignore_ascii_case(host.trim_end_matches('.')))
        }
    })
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

    /// A TLS 1.2 signature is for the hello's server name only.
    #[test]
    fn tls12_signatures_name_the_server() {
        let hello = |sni: Option<&str>| {
            let mut extensions = Vec::new();
            if let Some(name) = sni {
                let n = name.len() as u8;
                extensions.extend_from_slice(&[0, 0, 0, n + 5, 0, n + 3, 0, 0, n]);
                extensions.extend_from_slice(name.as_bytes());
            }
            let mut body = [&[3u8, 3][..], &[9; 32], &[0, 0, 2, 0x13, 0x01, 1, 0]].concat();
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            [&[1u8, 0][..], &(body.len() as u16).to_be_bytes(), &body, &[2, 0, 0, 0]].concat()
        };
        let ours = hello(Some("VPN.example.com"));
        assert!(tls_signature_for(&ours, ["vpn.example.com"]));
        assert!(!tls_signature_for(&hello(Some("bank.example")), ["vpn.example.com"]), "another server");
        assert!(!tls_signature_for(&hello(None), ["vpn.example.com"]), "no name");
        assert!(tls_signature_for(&hello(None), ["198.51.100.7"]), "no name for an address");
        assert!(!tls_signature_for(&ours, ["198.51.100.7"]));
        assert!(tls_signature_for(&ours, ["other.example", "vpn.example.com"]), "one of the remotes");
        let tls13 = [&[b' '; 64][..], b"TLS 1.3, client CertificateVerify\0", &[7; 32]].concat();
        assert!(tls_signature_for(&tls13, ["vpn.example.com"]), "binds no name");
    }

    #[test]
    fn signatures_are_rate_limited() {
        let mut budget = SignBudget::default();
        assert!((0..MAX_SIGNATURES).all(|_| budget.take()));
        assert!(!budget.take());
        budget.recent[0] -= SIGNATURE_PERIOD;
        assert!(budget.take(), "an old one no longer counts");
    }

    /// The user's side, answering as told and keeping what it was shown.
    struct User {
        trust: Trust,
        notices: std::sync::Mutex<Vec<String>>,
    }

    impl User {
        fn new(trust: Trust) -> Self {
            Self { trust, notices: Default::default() }
        }

        fn warned(&self) -> bool {
            self.notices.lock().unwrap().iter().any(|n| n.starts_with("Warning"))
        }
    }

    #[async_trait]
    impl Interaction for User {
        async fn ask(&self, _: &Prompt) -> anyhow::Result<Option<Zeroizing<String>>> {
            Ok(None)
        }
        async fn trust(&self, _: &CertificateInfo) -> anyhow::Result<Trust> {
            Ok(self.trust)
        }
        fn open_url(&self, _: &str) {}
        fn notice(&self, notice: Notice) {
            self.notices.lock().unwrap().push(format!("{notice:?}"));
        }
    }

    /// A session's engine, at the other end of the prompt socket.
    struct Engine {
        read: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
        write: tokio::net::unix::OwnedWriteHalf,
    }

    fn sockets() -> (PromptSocket, Engine) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let (read, write) = theirs.into_split();
        (PromptSocket::new(ours), Engine { read: tokio::io::BufReader::new(read), write })
    }

    impl Engine {
        async fn send(&mut self, event: &Event) {
            let mut line = serde_json::to_vec(event).unwrap();
            line.push(b'\n');
            self.write.write_all(&line).await.unwrap();
        }

        async fn answer(&mut self) -> (u64, Option<String>) {
            use tokio::io::AsyncBufReadExt;
            let mut line = String::new();
            self.read.read_line(&mut line).await.unwrap();
            match serde_json::from_str(&line).unwrap() {
                Request::Answer { id, value } => (id, value),
                other => panic!("{other:?}"),
            }
        }
    }

    /// A FortiSSL profile with a client certificate, and its key.
    fn signing_profile() -> (Profile, ClientKey) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["alice".into()]).unwrap().self_signed(&key).unwrap();
        let mut profile = profile("vpn.example.com", 443);
        profile.id = vpn_core::new_id();
        let vpn_core::ProtocolConfig::FortiSsl(p) = &mut profile.protocol else { unreachable!() };
        (p.client_cert_pem, p.client_key_pem) = (Some(cert.pem()), Some(key.serialize_pem()));
        let key = ClientKey::take(&mut profile).unwrap().unwrap();
        (profile, key)
    }

    fn sign_request(certificate: &str, data: &[u8]) -> Option<vpn_core::SignRequest> {
        Some(vpn_core::SignRequest {
            certificate: certificate.into(),
            algorithm: vpn_core::SignAlgorithm::EcdsaSha256,
            data: hex::encode(data),
        })
    }

    const TLS13: &[u8] = b"TLS 1.3, client CertificateVerify\0";

    fn tls13_octets() -> Vec<u8> {
        [&[b' '; 64][..], TLS13, &[7; 32]].concat()
    }

    #[tokio::test]
    async fn signatures_only_for_the_profile() {
        let (profile, key) = signing_profile();
        let mut budget = SignBudget::default();
        let ours = sign_request(key.sha256(), &tls13_octets());
        assert!(sign(&profile, Some(&key), ours.as_ref(), &mut budget).await.is_ok());
        let other = sign_request(&"ab".repeat(32), &tls13_octets());
        let err = sign(&profile, Some(&key), other.as_ref(), &mut budget).await.unwrap_err();
        assert!(err.to_string().contains("does not use"), "{err}");
        let anything = sign_request(key.sha256(), b"a bank transfer");
        assert!(sign(&profile, Some(&key), anything.as_ref(), &mut budget).await.is_err(), "not TLS");
        assert!(sign(&profile, None, ours.as_ref(), &mut budget).await.is_err(), "no key");
        assert!(sign(&profile, Some(&key), None, &mut budget).await.is_err(), "no request");
        // The same octets, for a protocol without client certificates or
        // signing other octets.
        for protocol in [
            "protocol = \"l2tp\"\ngateway = \"vpn.example.com\"",
            "protocol = \"ipsec\"\ngateway = \"vpn.example.com\"",
        ] {
            let other: Profile = toml::from_str(&format!("name = \"x\"\n{protocol}")).unwrap();
            assert!(sign(&other, Some(&key), ours.as_ref(), &mut budget).await.is_err(), "{protocol}");
        }
        while budget.take() {}
        let err = sign(&profile, Some(&key), ours.as_ref(), &mut budget).await.unwrap_err();
        assert!(err.to_string().contains("too many"), "{err}");
    }

    #[tokio::test]
    async fn questions_are_answered_on_the_prompt_socket() {
        let (dir, store) = {
            let dir = std::env::temp_dir().join(format!("vpn-client-questions-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            (dir.clone(), ProfileStore::open(Some(dir.join("profiles.toml"))).unwrap())
        };
        let (mut profile, key) = signing_profile();
        let vpn_core::ProtocolConfig::FortiSsl(p) = &mut profile.protocol else { unreachable!() };
        p.client_cert_pem = None;
        store.save(&profile).unwrap();
        let (mut socket, mut engine) = sockets();
        let mut budget = SignBudget::default();

        // A signature, then one for another certificate: refused, said.
        let user = User::new(Trust::Reject);
        let mut prompt = Prompt::new("sign", PromptKind::Sign, "");
        prompt.sign = sign_request(key.sha256(), &tls13_octets());
        engine.send(&Event::Prompt { id: 1, prompt: prompt.clone() }).await;
        let asked = socket.next().await.unwrap().unwrap();
        handle_question(asked, &mut socket, &profile, Some(&key), &store, &user, &mut budget).await.unwrap();
        let (id, signature) = engine.answer().await;
        assert_eq!(id, 1);
        assert!(signature.is_some_and(|s| hex::decode(s).is_ok()));
        prompt.sign = sign_request(&"ab".repeat(32), &tls13_octets());
        engine.send(&Event::Prompt { id: 2, prompt }).await;
        let asked = socket.next().await.unwrap().unwrap();
        handle_question(asked, &mut socket, &profile, Some(&key), &store, &user, &mut budget).await.unwrap();
        assert_eq!(engine.answer().await, (2, None));
        assert!(user.warned());

        // A certificate to trust: refused, accepted once, pinned.
        let certificate = CertificateInfo {
            host: "vpn.example.com".into(),
            port: 443,
            sha256: "cd".repeat(32),
            der: String::new(),
            reason: None,
        };
        let mut prompt = Prompt::new(vpn_core::prompt::TRUST_CERTIFICATE, PromptKind::Confirm, "");
        prompt.certificate = Some(certificate.clone());
        for (id, trust, answer) in [
            (3, Trust::Reject, None),
            (4, Trust::Once, Some(certificate.sha256.clone())),
            (5, Trust::Pin, Some(certificate.sha256.clone())),
        ] {
            engine.send(&Event::Prompt { id, prompt: prompt.clone() }).await;
            let asked = socket.next().await.unwrap().unwrap();
            let user = User::new(trust);
            handle_question(asked, &mut socket, &profile, Some(&key), &store, &user, &mut budget).await.unwrap();
            assert_eq!(engine.answer().await, (id, answer));
            let vpn_core::ProtocolConfig::FortiSsl(p) = store.find(&profile.id).unwrap().protocol else { panic!() };
            assert_eq!(p.trusted_cert.len(), usize::from(trust == Trust::Pin), "{trust:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A question read in two parts, an event from the daemon between
    /// them: the first part is kept.
    #[tokio::test]
    async fn questions_survive_a_cancelled_read() {
        let (mut socket, mut engine) = sockets();
        let mut line =
            serde_json::to_vec(&Event::Prompt { id: 9, prompt: Prompt::new("otp", PromptKind::Secret, "Code") })
                .unwrap();
        line.push(b'\n');
        let (first, rest) = line.split_at(line.len() / 2);
        engine.write.write_all(first).await.unwrap();
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), socket.next()).await;
        assert!(cancelled.is_err(), "still waiting for the end of the line");
        engine.write.write_all(rest).await.unwrap();
        let Some(Event::Prompt { id, prompt }) = socket.next().await.unwrap() else { panic!() };
        assert_eq!((id, prompt.key.as_str()), (9, "otp"));
        drop(engine);
        assert!(socket.next().await.unwrap().is_none());
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
