//! OpenVPN engine: a client in TLS mode with `dev tun` and pulled
//! options, compatible with OpenVPN 2.4 to 2.6 servers.
//!
//! The control channel (TLS, optionally wrapped by `tls-auth` or
//! `tls-crypt`) authenticates both sides and exchanges key material
//! (key method 2); the server then pushes the tunnel settings and the
//! data channel cipher, one of AES-GCM or ChaCha20-Poly1305. Keys are
//! derived with the OpenVPN PRF, or the TLS exporter when the server
//! offers it, and renegotiated periodically.
//!
//! # Security choices
//!
//! - Only the profile's CA (or pinned fingerprints) is trusted, and the
//!   server certificate must be meant for a server (`remote-cert-tls
//!   server`) unless the profile says otherwise: OpenVPN certificates do
//!   not name the server, so a client certificate of the same CA could
//!   otherwise pose as it.
//! - Packets are never compressed; the compression framing a server
//!   expects is kept, and compressed packets from it are dropped
//!   (VORACLE).
//! - No CBC data channel, no static-key mode, no `tls-crypt-v2` yet.
//! - A client certificate's key stays with the user's client, which signs
//!   the TLS handshake for the engine (see `vpn_tls`).
//!
//! Layout: `wire` (packet layout), `crypto` (PRF, data channel, control
//! channel wrapping), `reliable`, `tls`, `control` (key states), `link`
//! (UDP/TCP), `options` (pushed options), `session` (the running
//! connection).

mod control;
mod crypto;
mod link;
mod options;
mod reliable;
mod session;
mod tls;
mod wire;

use std::net::SocketAddr;

use anyhow::Context;
use async_trait::async_trait;
use base64::Engine as _;
use tracing::{info, warn};
use vpn_core::failure::kind_of;
use vpn_core::{
    Compression, Engine, FailureExt, FailureKind, OpenVpnProfile, OpenVpnRemote, PacketIo, Prompt, PromptKind,
    SessionContext, Transport, TunnelSettings, failure,
};
use zeroize::Zeroizing;

use crate::control::{Control, Hello};
use crate::session::{Refused, Session};

/// Rounds of dynamic challenge (`CRV1`) before giving up.
const MAX_CHALLENGES: usize = 3;

pub struct OpenVpnEngine {
    profile: OpenVpnProfile,
    session: Option<Session>,
}

impl OpenVpnEngine {
    pub fn new(profile: OpenVpnProfile) -> Self {
        Self { profile, session: None }
    }
}

/// What a dynamic challenge asks (`AUTH_FAILED,CRV1:flags:state:user:text`).
struct Challenge {
    state: String,
    username: String,
    text: String,
    echo: bool,
}

fn parse_challenge(reason: &str) -> Option<Challenge> {
    let rest = reason.strip_prefix("CRV1:")?;
    let mut parts = rest.splitn(4, ':');
    let flags = parts.next()?;
    let state = parts.next()?.to_owned();
    let username = base64::engine::general_purpose::STANDARD.decode(parts.next()?).ok()?;
    let text = parts.next()?.to_owned();
    Some(Challenge {
        state,
        username: String::from_utf8_lossy(&username).into_owned(),
        text,
        echo: flags.split(',').any(|f| f == "E"),
    })
}

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text)
}

fn options_string(profile: &OpenVpnProfile, transport: Transport) -> String {
    let proto = match transport {
        Transport::Udp => "UDPv4",
        Transport::Tcp => "TCPv4_CLIENT",
    };
    let lzo = if profile.compression == Compression::Lzo { ",comp-lzo" } else { "" };
    format!("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto {proto}{lzo},keysize 256,key-method 2,tls-client")
}

fn peer_info(profile: &OpenVpnProfile) -> String {
    let platform = if cfg!(target_os = "macos") { "mac" } else { "linux" };
    // Data V2, push without request, TLS key export, AUTH_PENDING
    // keywords, AUTH_FAILED,TEMP.
    let proto = 2 | 4 | 8 | 16 | 256;
    format!(
        "IV_VER=2.6.0\nIV_PLAT={platform}\nIV_TCPNL=1\nIV_NCP=2\nIV_CIPHERS={}\nIV_PROTO={proto}\n\
         IV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_GUI_VER={}_{}\n",
        profile.data_ciphers.join(":"),
        vpn_core::brand::PRODUCT,
        env!("CARGO_PKG_VERSION"),
    )
}

impl OpenVpnEngine {
    /// User name and password, the static challenge's answer folded in.
    async fn credentials(&self, ctx: &SessionContext) -> anyhow::Result<(String, Zeroizing<String>)> {
        if !self.profile.auth_user_pass {
            return Ok((String::new(), Zeroizing::new(String::new())));
        }
        let ask = |key: &str, kind: PromptKind, text: String| ctx.prompter.ask(Prompt::new(key, kind, text));
        let username = match &self.profile.username {
            Some(user) => user.clone(),
            None => ask("username", PromptKind::Text, format!("User name for {}", ctx.name)).await?.to_string(),
        };
        let password = ask("password", PromptKind::Secret, format!("Password for {username} on {}", ctx.name)).await?;
        let password = match &self.profile.static_challenge {
            Some(challenge) => {
                let kind = if challenge.echo { PromptKind::Text } else { PromptKind::Otp };
                let answer = ask("otp", kind, challenge.text.clone()).await?;
                Zeroizing::new(format!("SCRV1:{}:{}", b64(&password), b64(&answer)))
            }
            None => password,
        };
        Ok((username, password))
    }

    async fn resolve(remote: &OpenVpnRemote) -> anyhow::Result<SocketAddr> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((remote.host.as_str(), remote.port))
            .await
            .kind(FailureKind::Unreachable)
            .with_context(|| format!("cannot resolve {}", remote.host))?
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .copied()
            .with_context(|| format!("{} has no address", remote.host))
            .kind(FailureKind::Unreachable)
    }

    /// One attempt with one server.
    async fn attempt(
        &self,
        ctx: &SessionContext,
        remote: &OpenVpnRemote,
        hello: Hello,
    ) -> anyhow::Result<(Session, TunnelSettings)> {
        let addr = Self::resolve(remote).await?;
        info!(server = %addr, transport = ?remote.transport, "connecting to the OpenVPN server");
        let mut link = link::Link::open(addr, remote.transport).await?;
        let tls = tls::setup(&self.profile, ctx.prompter.clone())?;
        let wrap = crypto::Wrap::new(&self.profile)?;
        let mut control = Control::new(wrap, tls, tls::server_name(&remote.host), !link.tcp, hello)?;
        let pushed = session::establish(&mut link, &mut control, ctx).await?;
        let settings = pushed.settings(addr.ip())?;
        let session = Session::new(link, control, &pushed, &self.profile)?;
        Ok((session, settings))
    }
}

#[async_trait]
impl Engine for OpenVpnEngine {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
        self.profile.validate()?;
        let (mut username, mut password) = self.credentials(ctx).await?;
        let mut challenges = 0;
        let mut index = 0;
        loop {
            let remote = &self.profile.remotes[index];
            let transport = remote.transport;
            let hello = Hello {
                options: options_string(&self.profile, transport),
                username: username.clone(),
                password: password.clone(),
                peer_info: peer_info(&self.profile),
            };
            let error = match self.attempt(ctx, remote, hello).await {
                Ok((session, settings)) => {
                    self.session = Some(session);
                    return Ok(settings);
                }
                Err(e) => e,
            };
            if let Some(Refused::AuthFailed(reason)) = error.downcast_ref::<Refused>() {
                if let Some(challenge) = parse_challenge(reason).filter(|_| challenges < MAX_CHALLENGES) {
                    challenges += 1;
                    let kind = if challenge.echo { PromptKind::Text } else { PromptKind::Otp };
                    let answer = ctx.prompter.ask(Prompt::new("otp", kind, challenge.text)).await?;
                    username = challenge.username;
                    password = Zeroizing::new(format!("CRV1::{}::{}", challenge.state, *answer));
                    continue;
                }
                let detail = if reason.is_empty() { String::new() } else { format!(" ({reason})") };
                return Err(failure(FailureKind::AuthFailed, format!("the OpenVPN server refused the login{detail}")));
            }
            let next = index + 1 < self.profile.remotes.len();
            let kind = kind_of(&error);
            if next && matches!(kind, FailureKind::Unreachable | FailureKind::Timeout) {
                warn!("{:#}; trying the next server", error);
                index += 1;
                continue;
            }
            return Err(error);
        }
    }

    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let session = self.session.as_mut().context("not connected")?;
        session.run(ctx, io).await
    }

    async fn disconnect(&mut self) -> anyhow::Result<()> {
        self.session = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_challenge() {
        let c = parse_challenge("CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN").unwrap();
        assert_eq!((c.state.as_str(), c.username.as_str(), c.echo), ("Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l", "cr1", true));
        assert_eq!(c.text, "Please enter token PIN");
        assert!(parse_challenge("bad password").is_none());
    }

    #[test]
    fn peer_info_lists_the_ciphers() {
        let profile: vpn_core::Profile = toml::from_str(
            "name = \"o\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nca_pem = \"x\"\n\
             [[remotes]]\nhost = \"vpn.example.com\"",
        )
        .unwrap();
        let vpn_core::ProtocolConfig::OpenVpn(p) = profile.protocol else { unreachable!() };
        let info = peer_info(&p);
        assert!(info.contains("IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n"), "{info}");
        assert!(info.contains("IV_PROTO=286\n"));
        assert!(options_string(&p, Transport::Tcp).contains("proto TCPv4_CLIENT"));
    }
}
