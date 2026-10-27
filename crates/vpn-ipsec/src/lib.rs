//! IPsec engine: IKEv2 initiator (PSK, EAP-MSCHAPv2 or a client
//! certificate; the gateway with the PSK or a certificate) and IKEv1
//! initiator (main or aggressive mode PSK + XAuth + Mode-Config), with
//! userspace ESP always UDP-encapsulated so that no raw
//! socket or kernel IPsec stack is needed. Targets FortiGate dial-up
//! tunnels; checked against strongSwan (`interop/strongswan`).
//!
//! # Security limitations
//!
//! With EAP (`username` set) and a gateway authenticated by the pre-shared
//! key (`gateway_auth = "psk"`), RFC 7296 §2.16 expects the responder to
//! authenticate with a signature instead: anyone holding the PSK —
//! typically shared by every user of the tunnel — can impersonate the
//! gateway and collect MSCHAPv2 responses, which can be cracked offline. A
//! warning is logged at connect time; prefer `gateway_auth = "certificate"`.
//!
//! A client certificate's key stays in the user's Keychain: the engine
//! sends the octets to sign to the client, which signs only IKE AUTH
//! octets (`vpn_core::prompt::is_ike_auth_octets`) for the profile's
//! certificate, a few times per connection. A compromised engine can thus
//! authenticate as the user to an IKE gateway while the user connects,
//! but not get the key or a signature over anything else.
//!
//! Key material is wiped on drop, except the MODP (group 14) private
//! exponent, held in a `BigUint` that cannot be zeroized.
//!
//! IKEv1 aggressive mode with a pre-shared key has a known weakness: the
//! gateway's answer lets anyone who can talk to it attempt an offline
//! dictionary attack on the PSK. Keep the group PSK long and random.
//!
//! Layout: `cert`, `crypto`, `esp`, `eap` and `transport` are
//! protocol-agnostic and shared by the `ikev1` and `ikev2` modules.

mod cert;
mod crypto;
mod eap;

/// MS-CHAPv2 (RFC 2759), for PPP above IPsec.
pub mod mschapv2 {
    pub use crate::eap::{authenticator_response, mschap_username, nt_password_hash, nt_response};
}
mod esp;
mod ikev1;
mod ikev2;
mod proposal;
mod transport;

use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use vpn_core::{Engine, IpsecProfile, PacketIo, SessionContext, TunnelSettings};

/// Stands for "no time limit" (a phase 2 lifetime in kilobytes only);
/// small enough to add to an `Instant`.
pub(crate) const NO_TIME_LIMIT: Duration = Duration::from_secs(10 * 365 * 86_400);

/// The profile validation already refuses 3DES and DH group 2 without
/// `legacy_algorithms`; checked again here, where they would be offered.
pub(crate) fn check_legacy(profile: &vpn_core::IpsecProfile) -> anyhow::Result<()> {
    let legacy = profile.legacy_in_use();
    anyhow::ensure!(
        profile.legacy_algorithms || legacy.is_empty(),
        "{} only work with legacy algorithms allowed",
        legacy.join(" and ")
    );
    Ok(())
}

/// A profile lifetime in seconds, 0 meaning none.
pub(crate) fn lifetime(seconds: u32) -> Duration {
    if seconds == 0 { NO_TIME_LIMIT } else { Duration::from_secs(seconds.into()) }
}

pub struct IpsecEngine {
    profile: IpsecProfile,
    session: Option<Session>,
}

enum Session {
    V1(ikev1::Established),
    V2(ikev2::Established),
}

impl Session {
    async fn close(&mut self) {
        match self {
            Session::V1(s) => s.close().await,
            Session::V2(s) => s.close().await,
        }
    }
}

/// An IKEv1 SA pair in transport mode for one UDP port, for a protocol
/// above IPsec (L2TP, RFC 3193). It exchanges IPv4/UDP packets between our
/// address and the gateway's on that port; DPD, NAT-T keepalives and
/// Quick Mode rekeys run inside `run`.
pub struct TransportChannel {
    inner: ikev1::Established,
}

impl TransportChannel {
    /// Phase 1 with the PSK (asked as `psk`), then Quick Mode in transport
    /// mode for `port`; `profile` must be IKEv1 without XAuth.
    pub async fn establish(profile: &IpsecProfile, port: u16, ctx: &SessionContext) -> anyhow::Result<Self> {
        anyhow::ensure!(profile.ike_version == 1 && !profile.xauth, "transport mode needs IKEv1 without XAuth");
        Ok(Self { inner: ikev1::establish_transport(profile, ctx, port).await? })
    }

    /// Our address, as the packets must carry it.
    pub fn local(&self) -> std::net::Ipv4Addr {
        self.inner.settings.address
    }

    pub fn gateway(&self) -> std::net::Ipv4Addr {
        self.inner.quick.transport.expect("transport mode").gateway
    }

    /// Carries `io` until cancelled or the SAs fail.
    pub async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        self.inner.run(ctx, io).await
    }

    /// Deletes the SAs, best effort.
    pub async fn close(&mut self) {
        self.inner.close().await;
    }
}

impl IpsecEngine {
    pub fn new(profile: IpsecProfile) -> Self {
        Self { profile, session: None }
    }
}

#[async_trait]
impl Engine for IpsecEngine {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
        if let Some(mut old) = self.session.take() {
            old.close().await;
        }
        let (session, settings) = match self.profile.ike_version {
            1 => {
                let s = ikev1::establish(&self.profile, ctx).await?;
                let settings = s.settings.clone();
                (Session::V1(s), settings)
            }
            2 => {
                let s = ikev2::establish(&self.profile, ctx).await?;
                let settings = s.settings.clone();
                (Session::V2(s), settings)
            }
            v => anyhow::bail!("unsupported IKE version {v} (use 1 or 2)"),
        };
        self.session = Some(session);
        Ok(settings)
    }

    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()> {
        match self.session.as_mut().context("IPsec engine is not connected")? {
            Session::V1(s) => s.run(ctx, io).await,
            Session::V2(s) => s.run(ctx, io).await,
        }
    }

    async fn disconnect(&mut self) -> anyhow::Result<()> {
        if let Some(mut session) = self.session.take() {
            session.close().await;
        }
        Ok(())
    }
}
