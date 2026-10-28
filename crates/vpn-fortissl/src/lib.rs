//! Fortinet SSL VPN engine: portal login (password, FortiToken, SAML),
//! XML tunnel configuration, then PPP inside a TLS connection.

mod auth;
mod config;
#[cfg(test)]
mod fuzz_tests;
mod http;
mod ppp;
mod tls;
mod tunnel;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use vpn_core::failure::kind_of;
use vpn_core::{
    DnsSettings, Engine, FailureExt, FailureKind, FortiSslAuth, FortiSslProfile, PacketIo, Prompt, SessionContext,
    TunnelSettings,
};

use crate::http::Client;
use crate::tls::Endpoint;
use crate::tunnel::Tunnel;

/// MRU proposed to the gateway; also the tun MTU. Leaves room for the
/// TLS record, the 6-byte frame header and PPP within a 1500-byte path.
const MRU: u16 = 1354;

pub struct FortiSslEngine {
    profile: FortiSslProfile,
    client: Option<Client>,
    tunnel: Option<Tunnel>,
}

impl FortiSslEngine {
    pub fn new(profile: FortiSslProfile) -> Self {
        Self { profile, client: None, tunnel: None }
    }

    async fn resolve(&self) -> anyhow::Result<SocketAddr> {
        let addrs = tokio::net::lookup_host((self.profile.host.as_str(), self.profile.port))
            .await
            .kind(FailureKind::Unreachable)
            .with_context(|| format!("cannot resolve {}", self.profile.host))?
            .collect::<Vec<_>>();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .copied()
            .with_context(|| format!("{} has no address", self.profile.host))
            .kind(FailureKind::Unreachable)
    }

    /// Opens a first TLS connection, before any secret is asked. A
    /// certificate that cannot be validated is shown to the user, who may
    /// trust it for this session; the client then decides to pin it.
    async fn checked_endpoint(&mut self, ctx: &SessionContext, addr: SocketAddr) -> anyhow::Result<Endpoint> {
        let endpoint = Endpoint::new(&self.profile, addr, Some(ctx.prompter.clone()))?;
        let error = match endpoint.connect().await {
            Ok(stream) => {
                drop(stream);
                return Ok(endpoint);
            }
            Err(e) => e,
        };
        let FailureKind::CertificateUntrusted { certificate } = kind_of(&error) else {
            return Err(error);
        };
        // A cached answer is the fingerprint accepted earlier in this
        // session: it only matches the same certificate.
        match ctx.prompter.ask(Prompt::trust(certificate.clone())).await {
            Ok(answer) if answer.trim().eq_ignore_ascii_case(&certificate.sha256) => {}
            _ => return Err(error),
        }
        tracing::info!(session = ctx.name, sha256 = certificate.sha256, "certificate trusted by the user");
        self.profile.trusted_cert = vec![certificate.sha256];
        let endpoint = Endpoint::new(&self.profile, addr, Some(ctx.prompter.clone()))?;
        drop(endpoint.connect().await?);
        Ok(endpoint)
    }

    async fn fetch_config(client: &mut Client) -> anyhow::Result<config::GatewayConfig> {
        // Older firmware only allocates the tunnel resources when these
        // pages are visited; newer ones ignore them.
        client.get("/remote/index").await?;
        client.get("/remote/fortisslvpn").await?;
        let resp = client.get("/remote/fortisslvpn_xml").await?;
        let xml = resp.text();
        if resp.status != 200 || !xml.contains("<sslvpn-tunnel") {
            let redirect = resp.header("location").map(|l| format!(", redirected to {l}")).unwrap_or_default();
            bail!(
                "gateway did not return the tunnel configuration (HTTP {}{redirect}); \
                 the session was not recognised or tunnel mode is disabled for this portal",
                resp.status
            );
        }
        config::parse(&xml)
    }
}

#[async_trait]
impl Engine for FortiSslEngine {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
        let addr = self.resolve().await?;
        let endpoint = self.checked_endpoint(ctx, addr).await?;
        let mut client = Client::new(endpoint, &self.profile.host, self.profile.port);

        match &self.profile.auth {
            FortiSslAuth::Password => auth::password_login(&mut client, &self.profile, ctx).await?,
            FortiSslAuth::Saml { port } => auth::saml_login(&mut client, &self.profile, *port, ctx).await?,
        }
        tracing::info!(session = ctx.name, "authenticated to {}", self.profile.host);
        // Kept from now on: `disconnect` logs out even if the rest fails or
        // the attempt is stopped.
        let client = self.client.insert(client);

        let cfg = Self::fetch_config(client).await?;
        tracing::debug!(session = ctx.name, ?cfg, "tunnel configuration");

        let mut tunnel = Tunnel::open(client, MRU).await?;
        tunnel.negotiate(ctx).await?;

        let address = tunnel.ppp.address().or(cfg.assigned).context("gateway assigned no tunnel address")?;
        let servers = if cfg.dns.is_empty() { tunnel.ppp.dns() } else { cfg.dns.clone() };
        let full_tunnel = cfg.split_routes.is_empty();
        let settings = TunnelSettings {
            address,
            mtu: MRU.min(tunnel.ppp.peer_mru()),
            routes: cfg.split_routes.clone(),
            excluded_routes: cfg.excluded_routes.clone(),
            full_tunnel,
            dns: DnsSettings {
                servers: servers.into_iter().map(Into::into).collect(),
                search_domains: cfg.dns_suffixes.clone(),
                match_domains: if full_tunnel { Vec::new() } else { cfg.dns_suffixes.clone() },
            },
            gateway: addr.ip(),
        };
        tracing::info!(session = ctx.name, %address, routes = settings.routes.len(), full_tunnel, "tunnel up");

        self.tunnel = Some(tunnel);
        Ok(settings)
    }

    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        let tunnel = self.tunnel.as_mut().context("run called before connect")?;
        let result = tunnel.run(ctx, io).await;
        self.tunnel = None;
        result
    }

    async fn disconnect(&mut self) -> anyhow::Result<()> {
        self.tunnel = None;
        if let Some(mut client) = self.client.take() {
            match tokio::time::timeout(Duration::from_secs(5), client.get("/remote/logout")).await {
                Ok(Ok(_)) => tracing::debug!("logged out of {}", self.profile.host),
                Ok(Err(e)) => tracing::debug!("logout failed: {e:#}"),
                Err(_) => tracing::debug!("logout timed out"),
            }
        }
        Ok(())
    }
}
