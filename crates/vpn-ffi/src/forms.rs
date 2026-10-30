//! A profile as the app edits it: every field the editor shows, converted
//! to and from the core profile. Fields the editor does not show (file
//! paths, inlined certificates) are kept as they are when saving.

use anyhow::Context;
use base64::Engine;
use ipnet::Ipv4Net;
use vpn_core::{
    Compression, ControlChannel, Destination, DomainPattern, ExchangeMode, FortiSslAuth, FortiSslProfile, GatewayAuth,
    IpsecProfile, L2tpProfile, Noted, OpenVpnProfile, OpenVpnRemote, PppAuth, Profile, ProtocolConfig, StaticChallenge,
    Transport, WireGuardProfile, X509NameCheck, X509NameKind,
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VpnKind {
    FortiSsl,
    Ipsec,
    OpenVpn,
    /// L2TP over IPsec.
    L2tp,
    WireGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelMode {
    /// As the gateway decides.
    Automatic,
    Full,
    Split,
}

/// One OpenVPN server (`remote`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct OpenVpnServer {
    pub host: String,
    pub port: u16,
    pub transport: OpenVpnTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum OpenVpnTransport {
    Udp,
    Tcp,
}

/// Protection of the OpenVPN control channel by a shared static key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum OpenVpnControlChannel {
    None,
    TlsAuth,
    TlsCrypt,
}

/// The compression framing an OpenVPN server expects (nothing is ever
/// compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum OpenVpnCompression {
    None,
    /// `comp-lzo`.
    Lzo,
    /// `compress` or `compress stub`.
    Stub,
    /// `compress stub-v2`.
    StubV2,
}

/// What `verify-x509-name` compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum X509NameMatch {
    Subject,
    Name,
    NamePrefix,
}

/// One encryption + hash pair of a phase 1 or phase 2 proposal, as
/// FortiClient shows them. Tokens use the profile syntax: `aes128`,
/// `aes192`, `aes256`, `aes128gcm16`, `aes256gcm16`, `chacha20poly1305`,
/// `3des`; `sha1`, `sha256`, `sha384`, `sha512`. With an AEAD cipher (AES-GCM,
/// ChaCha20-Poly1305) the hash is the IKE PRF and is unused in phase 2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct CipherSuite {
    pub encryption: String,
    pub hash: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProfileForm {
    pub name: String,
    pub description: Option<String>,
    /// Offer to keep the password in the Keychain (otherwise asked each time).
    pub save_password: bool,
    pub kind: VpnKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    // SSL VPN
    pub realm: Option<String>,
    pub saml: bool,
    pub saml_port: u16,
    /// SHA-256 fingerprints of trusted gateway certificates (SSL VPN, and
    /// IPsec with a gateway certificate).
    pub trusted_certificates: Vec<String>,
    /// Certificate files referenced by the profile, or a PEM certificate
    /// and key from an OpenVPN import (not editable here).
    pub has_client_certificate: bool,
    // IPsec (also the IPsec side of L2TP: identities, proposals,
    // lifetimes, DPD, legacy algorithms)
    pub ike_version: u8,
    pub aggressive_mode: bool,
    pub xauth: bool,
    pub local_id: Option<String>,
    pub remote_id: Option<String>,
    /// The proposals as text; used as is when `custom_proposals` is set,
    /// otherwise rebuilt from the fields below.
    pub ike_proposals: Vec<String>,
    pub esp_proposals: Vec<String>,
    pub custom_proposals: bool,
    pub phase1_suites: Vec<CipherSuite>,
    /// DH group numbers (IKEv1 aggressive mode only uses the first).
    pub phase1_dh_groups: Vec<u16>,
    pub phase1_lifetime: u32,
    pub phase2_suites: Vec<CipherSuite>,
    /// Perfect forward secrecy group for phase 2, if any.
    pub pfs_group: Option<u16>,
    pub phase2_lifetime: u32,
    pub phase2_lifetime_kb: Option<u64>,
    pub dpd: bool,
    /// Allows 3DES and DH group 2, for old gateways.
    pub legacy_algorithms: bool,
    /// The gateway proves its identity with a certificate (IKEv2), not the PSK.
    pub gateway_certificate: bool,
    /// CA certificates (PEM) for the gateway certificate; for OpenVPN, the
    /// only CA trusted (`ca`).
    pub ca_pem: Option<String>,
    // OpenVPN (`host` and `port` show the first server)
    pub servers: Vec<OpenVpnServer>,
    /// A user name and password (`auth-user-pass`), with or without a
    /// client certificate.
    pub password_auth: bool,
    /// The question of a one-time code asked with the password
    /// (`static-challenge`), and whether to show the answer.
    pub static_challenge: Option<String>,
    pub static_challenge_echo: bool,
    /// The server certificate must be meant for a server.
    pub remote_cert_tls: bool,
    pub verify_x509_name: Option<String>,
    pub verify_x509_match: X509NameMatch,
    pub control_channel: OpenVpnControlChannel,
    /// The `OpenVPN Static key V1` text of tls-auth or tls-crypt.
    pub static_key: Option<String>,
    /// tls-auth `key-direction` (0 or 1), if any.
    pub key_direction: Option<u8>,
    /// tls-auth HMAC digest (`auth`).
    pub auth_digest: String,
    pub data_ciphers: Vec<String>,
    pub compression: OpenVpnCompression,
    /// Data channel rekeying interval in seconds, 0 for never.
    pub reneg_sec: u32,
    // L2TP: the PPP authentications accepted
    pub ppp_mschapv2: bool,
    pub ppp_chap: bool,
    /// The password in clear inside the IPsec SA.
    pub ppp_pap: bool,
    /// DNS servers used when the server assigns none (at most 4); for
    /// WireGuard, the servers of the tunnel.
    pub dns_servers: Vec<String>,
    // WireGuard (`host` and `port`: the peer's endpoint; the private and
    // pre-shared keys are secrets, `private_key` and `psk`)
    /// The peer's public key, base64.
    pub peer_public_key: String,
    /// Our addresses in the tunnel (`Address`).
    pub addresses: Vec<String>,
    /// The peer's networks (`AllowedIPs`).
    pub allowed_ips: Vec<String>,
    pub preshared_key: bool,
    pub persistent_keepalive: Option<u16>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    /// Ours, derived from the private key: what the server declares.
    pub local_public_key: Option<String>,
    // All
    /// SHA-256 of the Keychain certificate we authenticate with: for the
    /// SSL VPN and OpenVPN, in place of the PEM certificate and key; for
    /// IPsec (IKEv2), instead of the PSK or EAP.
    pub client_certificate: Option<String>,
    /// `None`: the routes pushed by the gateway.
    pub routes: Option<Vec<ListEntry>>,
    pub tunnel_mode: TunnelMode,
    /// The networks of a connection in split mode; empty for none.
    pub split_routes: Vec<ListEntry>,
    /// Networks added to those the gateway pushes.
    pub extra_routes: Vec<ListEntry>,
    pub dns_domains: Vec<ListEntry>,
    /// Kept outside a full tunnel.
    pub excluded_domains: Vec<ListEntry>,
    pub allow_route_overlap: bool,
    /// VPNs this one is chained through, preferred first.
    pub via: Vec<String>,
    /// `/` between subfolders; empty for none.
    pub folder: Option<String>,
    /// A company VPN: never up at the same time as another VPN.
    pub exclusive: bool,
}

impl ProfileForm {
    /// A new profile of `kind`, with the protocol's defaults.
    pub fn new(kind: VpnKind) -> Self {
        let profile: Profile = toml::from_str(empty_profile(kind)).expect("defaults parse");
        let mut form = Self::from(&profile);
        if kind == VpnKind::OpenVpn {
            form.servers = vec![OpenVpnServer { host: String::new(), port: 1194, transport: OpenVpnTransport::Udp }];
            form.port = 1194;
            form.password_auth = true;
        }
        let suite = |encryption: &str, hash: &str| CipherSuite { encryption: encryption.into(), hash: hash.into() };
        if kind == VpnKind::Ipsec {
            // Modern choices that the editor can show.
            form.phase1_suites = vec![suite("aes256gcm16", "sha256"), suite("aes256", "sha256")];
            form.phase1_dh_groups = vec![19, 31, 14];
            form.phase2_suites = vec![suite("aes256gcm16", "sha256"), suite("aes256", "sha256")];
            form.pfs_group = None;
            form.custom_proposals = false;
        }
        if kind == VpnKind::L2tp {
            // What L2TP servers commonly accept, as macOS offers it (IKEv1:
            // no AES-GCM in phase 1).
            let suites = vec![suite("aes256", "sha256"), suite("aes256", "sha1"), suite("aes128", "sha1")];
            form.phase1_suites = suites.clone();
            form.phase1_dh_groups = vec![14, 5];
            form.phase2_suites = suites;
            form.pfs_group = None;
            form.custom_proposals = false;
        }
        form
    }

    /// Applies the form on top of `base` (the profile being edited, if any).
    pub fn to_profile(&self, base: Option<&Profile>) -> anyhow::Result<Profile> {
        let mut profile = match (base, self.kind) {
            (Some(p), VpnKind::FortiSsl) if matches!(p.protocol, ProtocolConfig::FortiSsl(_)) => p.clone(),
            (Some(p), VpnKind::Ipsec) if matches!(p.protocol, ProtocolConfig::Ipsec(_)) => p.clone(),
            (Some(p), VpnKind::OpenVpn) if matches!(p.protocol, ProtocolConfig::OpenVpn(_)) => p.clone(),
            (Some(p), VpnKind::L2tp) if matches!(p.protocol, ProtocolConfig::L2tp(_)) => p.clone(),
            (Some(p), VpnKind::WireGuard) if matches!(p.protocol, ProtocolConfig::WireGuard(_)) => p.clone(),
            // Another type: the protocol starts afresh, the profile keeps its
            // id, folder and other settings (its secrets stay bound to the
            // old server).
            (Some(p), _) => {
                Profile { protocol: toml::from_str::<Profile>(empty_profile(self.kind))?.protocol, ..p.clone() }
            }
            (None, _) => {
                let mut fresh: Profile = toml::from_str(empty_profile(self.kind))?;
                fresh.name.clear();
                fresh
            }
        };
        let text = |value: &Option<String>| value.as_ref().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        profile.name = self.name.trim().to_owned();
        profile.description = text(&self.description);
        profile.save_password = self.save_password;
        match &mut profile.protocol {
            ProtocolConfig::OpenVpn(p) => self.apply_openvpn(p)?,
            ProtocolConfig::L2tp(p) => self.apply_l2tp(p)?,
            ProtocolConfig::WireGuard(p) => self.apply_wireguard(p)?,
            ProtocolConfig::FortiSsl(p) => {
                p.host = self.host.trim().to_owned();
                p.port = self.port;
                p.username = text(&self.username);
                p.realm = text(&self.realm);
                p.auth = if self.saml { FortiSslAuth::Saml { port: self.saml_port } } else { FortiSslAuth::Password };
                p.trusted_cert = fingerprints(&self.trusted_certificates)?;
                p.client_certificate = text(&self.client_certificate);
                if p.client_certificate.is_some() {
                    (p.client_cert, p.client_key, p.client_cert_pem, p.client_key_pem) = (None, None, None, None);
                }
            }
            ProtocolConfig::Ipsec(p) => {
                p.gateway = self.host.trim().to_owned();
                p.port = self.port;
                p.username = text(&self.username);
                if !matches!(self.ike_version, 1 | 2) {
                    anyhow::bail!("the IKE version must be 1 or 2");
                }
                p.ike_version = self.ike_version;
                p.exchange_mode = if self.aggressive_mode { ExchangeMode::Aggressive } else { ExchangeMode::Main };
                p.xauth = self.xauth;
                p.local_id = text(&self.local_id);
                p.remote_id = text(&self.remote_id);
                (p.ike, p.esp) = if self.custom_proposals {
                    (clean_list(&self.ike_proposals), clean_list(&self.esp_proposals))
                } else {
                    self.built_proposals()?
                };
                if p.ike.is_empty() || p.esp.is_empty() {
                    anyhow::bail!("at least one IKE and one ESP proposal are needed");
                }
                p.phase1_lifetime = self.phase1_lifetime;
                p.phase2_lifetime = self.phase2_lifetime;
                p.phase2_lifetime_kb = self.phase2_lifetime_kb;
                p.dpd = self.dpd;
                p.legacy_algorithms = self.legacy_algorithms;
                p.gateway_auth = if self.gateway_certificate { GatewayAuth::Certificate } else { GatewayAuth::Psk };
                (p.ca_pem, p.trusted_cert) = if self.gateway_certificate {
                    let ca = self.ca_pem.as_ref().filter(|pem| !pem.trim().is_empty());
                    if let Some(pem) = ca {
                        certificates_as_pem(pem.as_bytes()).context("invalid certificate authority")?;
                    }
                    (ca.cloned(), fingerprints(&self.trusted_certificates)?)
                } else {
                    (None, Vec::new())
                };
                p.client_certificate = text(&self.client_certificate).filter(|_| p.ike_version == 2);
                if p.client_certificate.is_some() {
                    p.username = None;
                }
            }
        }
        profile.routes = match &self.routes {
            None => None,
            Some(routes) => Some(noted_networks(routes)?),
        };
        profile.split_routes = noted_networks(&self.split_routes)?;
        profile.extra_routes = noted_networks(&self.extra_routes)?;
        profile.full_tunnel = match self.tunnel_mode {
            TunnelMode::Automatic => None,
            TunnelMode::Full => Some(true),
            TunnelMode::Split => Some(false),
        };
        profile.dns_domains = noted_domains(&self.dns_domains)?;
        profile.excluded_domains = self
            .excluded_domains
            .iter()
            .filter(|e| !e.value.trim().is_empty())
            .map(|e| Ok(Noted::new(parse_pattern(&e.value)?, note(&e.note))))
            .collect::<anyhow::Result<_>>()?;
        profile.allow_route_overlap = self.allow_route_overlap;
        profile.via = dedup(clean_list(&self.via));
        profile.exclusive = self.exclusive;
        // "Clients / Acme" means Clients/Acme.
        profile.folder = text(&self.folder)
            .map(|f| f.split('/').map(str::trim).filter(|n| !n.is_empty()).collect::<Vec<_>>().join("/"));
        profile.folder = profile.folder.filter(|f| !f.is_empty());
        profile.validate()?;
        Ok(profile)
    }
}

impl ProfileForm {
    /// The OpenVPN fields; the PEM certificate and key of an import stay
    /// unless a Keychain certificate replaces them.
    fn apply_openvpn(&self, p: &mut OpenVpnProfile) -> anyhow::Result<()> {
        let text = |value: &Option<String>| value.as_ref().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        p.remotes = self
            .servers
            .iter()
            .filter(|s| !s.host.trim().is_empty())
            .map(|s| OpenVpnRemote {
                host: s.host.trim().to_owned(),
                port: s.port,
                transport: match s.transport {
                    OpenVpnTransport::Udp => Transport::Udp,
                    OpenVpnTransport::Tcp => Transport::Tcp,
                },
            })
            .collect();
        p.auth_user_pass = self.password_auth;
        p.username = text(&self.username).filter(|_| self.password_auth);
        p.static_challenge = text(&self.static_challenge)
            .filter(|_| self.password_auth)
            .map(|text| StaticChallenge { text, echo: self.static_challenge_echo });
        let ca = self.ca_pem.as_ref().filter(|pem| !pem.trim().is_empty());
        if let Some(pem) = ca {
            certificates_as_pem(pem.as_bytes()).context("invalid certificate authority")?;
        }
        p.ca_pem = ca.cloned();
        p.trusted_cert = fingerprints(&self.trusted_certificates)?;
        p.remote_cert_tls = self.remote_cert_tls;
        p.verify_x509_name = text(&self.verify_x509_name).map(|name| X509NameCheck {
            name,
            kind: match self.verify_x509_match {
                X509NameMatch::Subject => X509NameKind::Subject,
                X509NameMatch::Name => X509NameKind::Name,
                X509NameMatch::NamePrefix => X509NameKind::NamePrefix,
            },
        });
        p.client_certificate = text(&self.client_certificate);
        if p.client_certificate.is_some() {
            (p.client_cert_pem, p.client_key_pem) = (None, None);
        }
        p.control_channel = match self.control_channel {
            OpenVpnControlChannel::None => ControlChannel::None,
            OpenVpnControlChannel::TlsAuth => ControlChannel::TlsAuth,
            OpenVpnControlChannel::TlsCrypt => ControlChannel::TlsCrypt,
        };
        p.static_key =
            (self.static_key.clone()).filter(|key| !key.trim().is_empty() && p.control_channel != ControlChannel::None);
        p.key_direction = self.key_direction.filter(|_| p.control_channel == ControlChannel::TlsAuth);
        p.auth_digest = self.auth_digest.trim().to_ascii_uppercase();
        p.data_ciphers = dedup(clean_list(&self.data_ciphers));
        p.compression = match self.compression {
            OpenVpnCompression::None => Compression::None,
            OpenVpnCompression::Lzo => Compression::Lzo,
            OpenVpnCompression::Stub => Compression::Stub,
            OpenVpnCompression::StubV2 => Compression::StubV2,
        };
        p.reneg_sec = self.reneg_sec;
        Ok(())
    }

    /// The L2TP fields; the exchange mode follows the group name.
    fn apply_l2tp(&self, p: &mut L2tpProfile) -> anyhow::Result<()> {
        let text = |value: &Option<String>| value.as_ref().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        p.gateway = self.host.trim().to_owned();
        p.port = self.port;
        p.username = text(&self.username);
        p.local_id = text(&self.local_id);
        p.remote_id = text(&self.remote_id);
        (p.ike, p.esp) = if self.custom_proposals {
            (clean_list(&self.ike_proposals), clean_list(&self.esp_proposals))
        } else {
            self.built_proposals()?
        };
        if p.ike.is_empty() || p.esp.is_empty() {
            anyhow::bail!("at least one IKE and one ESP proposal are needed");
        }
        p.phase1_lifetime = self.phase1_lifetime;
        p.phase2_lifetime = self.phase2_lifetime;
        p.dpd = self.dpd;
        p.legacy_algorithms = self.legacy_algorithms;
        let chosen =
            [(PppAuth::MsChapV2, self.ppp_mschapv2), (PppAuth::Chap, self.ppp_chap), (PppAuth::Pap, self.ppp_pap)];
        let chosen: Vec<PppAuth> = chosen.iter().filter(|(_, on)| *on).map(|(auth, _)| *auth).collect();
        if chosen.is_empty() {
            anyhow::bail!("choose at least one PPP authentication");
        }
        // The profile's order for those kept, then the new ones, strongest first.
        let mut order: Vec<PppAuth> = p.ppp_auth.iter().copied().filter(|a| chosen.contains(a)).collect();
        for auth in chosen {
            push_new(&mut order, auth);
        }
        p.ppp_auth = order;
        p.dns_servers = clean_list(&self.dns_servers)
            .iter()
            .map(|d| d.parse().map_err(|_| anyhow::anyhow!("{d:?} is not an IP address")))
            .collect::<anyhow::Result<_>>()?;
        Ok(())
    }

    fn apply_wireguard(&self, p: &mut WireGuardProfile) -> anyhow::Result<()> {
        let text = |value: &Option<String>| value.as_ref().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        let networks = |items: &[String], what: &str| -> anyhow::Result<Vec<Ipv4Net>> {
            clean_list(items)
                .iter()
                .map(|n| {
                    // A bare address is a host (wg-quick accepts both).
                    let parsed = n.parse::<Ipv4Net>().or_else(|_| n.parse::<std::net::Ipv4Addr>().map(Ipv4Net::from));
                    parsed.map_err(|_| anyhow::anyhow!("{n:?} is not an IPv4 {what} (like 10.7.0.2/32)"))
                })
                .collect()
        };
        p.endpoint = self.host.trim().to_owned();
        p.port = self.port;
        p.public_key = self.peer_public_key.trim().to_owned();
        p.addresses = networks(&self.addresses, "address")?;
        p.allowed_ips = networks(&self.allowed_ips, "network")?;
        p.preshared_key = self.preshared_key;
        p.persistent_keepalive = self.persistent_keepalive.filter(|k| *k > 0);
        p.dns_servers = clean_list(&self.dns_servers)
            .iter()
            .map(|d| d.parse().map_err(|_| anyhow::anyhow!("{d:?} is not an IP address")))
            .collect::<anyhow::Result<_>>()?;
        p.dns_search = clean_list(&self.dns_search);
        p.mtu = self.mtu.filter(|m| *m > 0);
        p.local_public_key = text(&self.local_public_key);
        Ok(())
    }

    /// The proposal strings described by the suites and groups.
    pub fn built_proposals(&self) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        if self.phase1_suites.is_empty() || self.phase2_suites.is_empty() {
            anyhow::bail!("choose at least one phase 1 and one phase 2 proposal");
        }
        if self.phase1_dh_groups.is_empty() {
            anyhow::bail!("choose at least one DH group for phase 1");
        }
        for suite in self.phase1_suites.iter().chain(&self.phase2_suites) {
            if !ENCRYPTIONS.contains(&suite.encryption.as_str()) || !HASHES.contains(&suite.hash.as_str()) {
                anyhow::bail!("unknown algorithm {}/{}", suite.encryption, suite.hash);
            }
        }
        // IKEv1 has no ChaCha20-Poly1305 identifier; FortiOS offers AES-GCM
        // in IKEv1 phase 2 only.
        if self.ike_version == 1 || self.kind == VpnKind::L2tp {
            if self.phase1_suites.iter().chain(&self.phase2_suites).any(|s| s.encryption == "chacha20poly1305") {
                anyhow::bail!("ChaCha20-Poly1305 needs IKEv2");
            }
            if self.phase1_suites.iter().any(|s| is_aead(&s.encryption)) {
                anyhow::bail!("AES-GCM in phase 1 needs IKEv2");
            }
        }
        let mut ike = Vec::new();
        for group in &self.phase1_dh_groups {
            let group = group_token(*group).with_context(|| format!("DH group {group} is not supported"))?;
            for s in &self.phase1_suites {
                let hash = if is_aead(&s.encryption) { format!("prf{}", s.hash) } else { s.hash.clone() };
                ike.push(format!("{}-{hash}-{group}", s.encryption));
            }
        }
        let pfs = self
            .pfs_group
            .map(|g| group_token(g).with_context(|| format!("DH group {g} is not supported")))
            .transpose()?;
        let esp = self
            .phase2_suites
            .iter()
            .map(|s| {
                let mut parts = vec![s.encryption.as_str()];
                if !is_aead(&s.encryption) {
                    parts.push(&s.hash);
                }
                parts.extend(pfs);
                parts.join("-")
            })
            .collect();
        Ok((dedup(ike), dedup(esp)))
    }

    /// Fills the suites and groups from the proposal strings; sets
    /// `custom_proposals` when they cannot be shown that way.
    pub fn read_proposals(&mut self) {
        let parsed = (|| {
            let mut phase1_suites = Vec::new();
            let mut groups = Vec::new();
            for p in &self.ike_proposals {
                let (suite, group) = parse_ike(p)?;
                push_new(&mut phase1_suites, suite);
                push_new(&mut groups, group?);
            }
            let mut phase2_suites = Vec::new();
            let mut pfs = Vec::new();
            for p in &self.esp_proposals {
                let (suite, group) = parse_esp(p)?;
                push_new(&mut phase2_suites, suite);
                push_new(&mut pfs, group);
            }
            let [pfs_group] = pfs.as_slice() else { return None };
            Some((phase1_suites, groups, phase2_suites, *pfs_group))
        })();
        let Some((phase1_suites, groups, phase2_suites, pfs_group)) = parsed else {
            self.custom_proposals = true;
            return;
        };
        let mut built = self.clone();
        built.phase1_suites = phase1_suites;
        built.phase1_dh_groups = groups;
        built.phase2_suites = phase2_suites;
        built.pfs_group = pfs_group;
        // Only if the choices describe exactly the same proposals.
        match built.built_proposals() {
            Ok((ike, esp)) if ike == clean_list(&self.ike_proposals) && esp == clean_list(&self.esp_proposals) => {
                built.custom_proposals = false;
                *self = built;
            }
            _ => self.custom_proposals = true,
        }
    }
}

const ENCRYPTIONS: [&str; 7] = ["aes128", "aes192", "aes256", "aes128gcm16", "aes256gcm16", "chacha20poly1305", "3des"];
const HASHES: [&str; 4] = ["sha1", "sha256", "sha384", "sha512"];
const GROUPS: [(u16, &str); 11] = [
    (2, "modp1024"),
    (5, "modp1536"),
    (14, "modp2048"),
    (15, "modp3072"),
    (16, "modp4096"),
    (17, "modp6144"),
    (18, "modp8192"),
    (19, "ecp256"),
    (20, "ecp384"),
    (21, "ecp521"),
    (31, "x25519"),
];

/// AES-GCM or ChaCha20-Poly1305: no separate integrity algorithm.
fn is_aead(encryption: &str) -> bool {
    encryption.contains("gcm") || encryption == "chacha20poly1305"
}

fn group_token(group: u16) -> Option<&'static str> {
    GROUPS.iter().find(|(g, _)| *g == group).map(|(_, t)| *t)
}

fn group_number(token: &str) -> Option<u16> {
    GROUPS.iter().find(|(_, t)| *t == token).map(|(g, _)| *g)
}

fn push_new<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn dedup(list: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for item in list {
        push_new(&mut out, item);
    }
    out
}

/// `aes128-sha1-modp1536` or `aes256gcm16-prfsha256-ecp256`.
fn parse_ike(proposal: &str) -> Option<(CipherSuite, Option<u16>)> {
    let tokens: Vec<String> = proposal.trim().split('-').map(str::to_ascii_lowercase).collect();
    let [encryption, hash, group] = tokens.as_slice() else { return None };
    let hash = if is_aead(encryption) { hash.strip_prefix("prf")? } else { hash.as_str() };
    ENCRYPTIONS.contains(&encryption.as_str()).then_some(())?;
    HASHES.contains(&hash).then_some(())?;
    Some((CipherSuite { encryption: encryption.clone(), hash: hash.to_owned() }, Some(group_number(group)?)))
}

/// `aes128-sha1[-modp1536]` or `aes256gcm16[-ecp256]`.
fn parse_esp(proposal: &str) -> Option<(CipherSuite, Option<u16>)> {
    let tokens: Vec<String> = proposal.trim().split('-').map(str::to_ascii_lowercase).collect();
    let (encryption, rest) = tokens.split_first()?;
    ENCRYPTIONS.contains(&encryption.as_str()).then_some(())?;
    let (hash, rest) = if is_aead(encryption) {
        // The hash is unused; keep a sensible value for the picker.
        ("sha256".to_owned(), rest)
    } else {
        let (hash, rest) = rest.split_first()?;
        HASHES.contains(&hash.as_str()).then_some(())?;
        (hash.clone(), rest)
    };
    let group = match rest {
        [] => None,
        [group] => Some(group_number(group)?),
        _ => return None,
    };
    Some((CipherSuite { encryption: encryption.clone(), hash }, group))
}

fn fingerprints(items: &[String]) -> anyhow::Result<Vec<String>> {
    let list = clean_list(items);
    for fingerprint in &list {
        let hex = fingerprint.replace(':', "");
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("{fingerprint:?} is not a SHA-256 fingerprint (64 hexadecimal digits)");
        }
    }
    Ok(list)
}

fn ders(data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let pem: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(data)
        .map(|c| c.map(|c| c.to_vec()))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("invalid PEM: {e:?}"))?;
    let list = if pem.is_empty() { vec![data.to_vec()] } else { pem };
    for der in &list {
        X509Certificate::from_der(der).map_err(|_| anyhow::anyhow!("this is not an X.509 certificate"))?;
    }
    Ok(list)
}

pub fn certificates_as_pem(data: &[u8]) -> anyhow::Result<String> {
    let mut out = String::new();
    for der in ders(data)? {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    Ok(out)
}

pub fn certificate_names(pem: &str) -> Vec<String> {
    ders(pem.as_bytes())
        .unwrap_or_default()
        .iter()
        .filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, c)| c.subject().to_string()))
        .collect()
}

/// A profile of `kind` with the protocol's defaults and no server.
fn empty_profile(kind: VpnKind) -> &'static str {
    match kind {
        VpnKind::FortiSsl => "name = \"\"\nprotocol = \"forti-ssl\"\nhost = \"\"",
        VpnKind::Ipsec => "name = \"\"\nprotocol = \"ipsec\"\ngateway = \"\"",
        VpnKind::OpenVpn => "name = \"\"\nprotocol = \"openvpn\"\nremotes = []",
        VpnKind::L2tp => "name = \"\"\nprotocol = \"l2tp\"\ngateway = \"\"",
        VpnKind::WireGuard => {
            "name = \"\"\nprotocol = \"wireguard\"\nendpoint = \"\"\npublic_key = \"\"\naddresses = []\nallowed_ips = []"
        }
    }
}

/// Trimmed entries, empty ones dropped.
fn clean_list(items: &[String]) -> Vec<String> {
    items.iter().map(|i| i.trim().to_owned()).filter(|i| !i.is_empty()).collect()
}

/// One line of a list in the editor: a network or a domain, and what it
/// is for. Rows whose value is empty are dropped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ListEntry {
    pub value: String,
    pub note: String,
}

/// An entry without a note.
impl From<&str> for ListEntry {
    fn from(value: &str) -> Self {
        Self { value: value.to_owned(), note: String::new() }
    }
}

fn note(text: &str) -> Option<String> {
    Some(text.trim().to_owned()).filter(|n| !n.is_empty())
}

fn noted_networks(items: &[ListEntry]) -> anyhow::Result<Vec<Noted<Destination>>> {
    items
        .iter()
        .filter(|e| !e.value.trim().is_empty())
        .map(|e| Ok(Noted::new(parse_destination(&e.value)?, note(&e.note))))
        .collect()
}

/// A network or an address, or a domain routed as it resolves (#37).
fn parse_destination(text: &str) -> anyhow::Result<Destination> {
    let text = text.trim();
    match parse_network(text) {
        Ok(net) => Ok(Destination::Network(net)),
        // Digits and dots: a mistyped network, explained as such.
        Err(e) if text.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'/') => Err(e),
        Err(_) => text.parse::<DomainPattern>().map(Destination::Domain).map_err(|_| {
            anyhow::anyhow!(
                "{text:?} is not a network (like 10.1.0.0/16), an address or a domain (like *.corp.example)"
            )
        }),
    }
}

fn parse_pattern(text: &str) -> anyhow::Result<DomainPattern> {
    text.trim().parse::<DomainPattern>().map_err(anyhow::Error::msg)
}

fn noted_domains(items: &[ListEntry]) -> anyhow::Result<Vec<Noted<String>>> {
    items
        .iter()
        .filter(|e| !e.value.trim().is_empty())
        .map(|e| Ok(Noted::new(parse_domain(&e.value)?, note(&e.note))))
        .collect()
}

/// A network, or an address alone (a /32); `10.1.0.0` alone is most
/// likely a network whose prefix was forgotten, so it is refused.
fn parse_network(text: &str) -> anyhow::Result<Ipv4Net> {
    let text = text.trim();
    if let Ok(net) = text.parse::<Ipv4Net>() {
        return Ok(net.trunc());
    }
    match text.parse::<std::net::Ipv4Addr>() {
        Ok(address) if address.octets()[3] == 0 => {
            anyhow::bail!(
                "{text:?} looks like a network: add its prefix (like {text}/16), or /32 for this address alone"
            )
        }
        Ok(address) => Ok(Ipv4Net::from(address)),
        Err(_) => anyhow::bail!("{text:?} is not a network (like 10.1.0.0/16) or an address"),
    }
}

fn parse_domain(text: &str) -> anyhow::Result<String> {
    let domain = text.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(vpn_core::valid_domain(&domain), "{text:?} is not a DNS domain");
    Ok(domain)
}

fn entries<T: std::fmt::Display>(list: &[Noted<T>]) -> Vec<ListEntry> {
    list.iter().map(|e| ListEntry { value: e.value.to_string(), note: e.note.clone().unwrap_or_default() }).collect()
}

/// What is wrong with a network typed in the editor, if anything (an
/// address alone is a /32; a domain is routed as it resolves).
#[uniffi::export]
pub fn network_error(text: String) -> Option<String> {
    parse_destination(&text).err().map(|e| e.to_string())
}

/// What is wrong with a domain to keep outside the VPN, if anything.
#[uniffi::export]
pub fn pattern_error(text: String) -> Option<String> {
    parse_pattern(&text).err().map(|e| e.to_string())
}

/// What is wrong with a DNS domain typed in the editor, if anything.
#[uniffi::export]
pub fn domain_error(text: String) -> Option<String> {
    parse_domain(&text).err().map(|e| e.to_string())
}

/// Lines pasted into a list: the first word is the network or domain, the
/// rest of the line its note (`10.1.0.0/16  Intranet`, `10.1.0.0/16 #
/// Intranet`, `10.1.0.0/16, Intranet`).
#[uniffi::export]
pub fn parse_list(text: String) -> Vec<ListEntry> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let (value, rest) = line.split_once(|c: char| c.is_whitespace() || c == ',').unwrap_or((line, ""));
            let note = rest.trim().trim_start_matches(['#', ',', '-']).trim();
            (!value.is_empty())
                .then(|| ListEntry { value: value.trim_end_matches(',').to_owned(), note: note.to_owned() })
        })
        .collect()
}

impl From<&Profile> for ProfileForm {
    fn from(profile: &Profile) -> Self {
        let defaults: IpsecProfile = toml::from_str("gateway = \"\"").expect("defaults parse");
        let openvpn: OpenVpnProfile = toml::from_str("remotes = []").expect("defaults parse");
        let mut form = Self {
            name: profile.name.clone(),
            description: profile.description.clone(),
            save_password: profile.save_password,
            kind: VpnKind::FortiSsl,
            host: String::new(),
            port: 0,
            username: None,
            realm: None,
            saml: false,
            saml_port: 8020,
            trusted_certificates: Vec::new(),
            has_client_certificate: false,
            ike_version: defaults.ike_version,
            aggressive_mode: false,
            xauth: false,
            local_id: None,
            remote_id: None,
            ike_proposals: defaults.ike.clone(),
            esp_proposals: defaults.esp.clone(),
            custom_proposals: false,
            phase1_suites: Vec::new(),
            phase1_dh_groups: Vec::new(),
            phase1_lifetime: defaults.phase1_lifetime,
            phase2_suites: Vec::new(),
            pfs_group: None,
            phase2_lifetime: defaults.phase2_lifetime,
            phase2_lifetime_kb: defaults.phase2_lifetime_kb,
            dpd: defaults.dpd,
            legacy_algorithms: false,
            gateway_certificate: false,
            ca_pem: None,
            servers: Vec::new(),
            password_auth: false,
            static_challenge: None,
            static_challenge_echo: false,
            remote_cert_tls: openvpn.remote_cert_tls,
            verify_x509_name: None,
            verify_x509_match: X509NameMatch::Subject,
            control_channel: OpenVpnControlChannel::None,
            static_key: None,
            key_direction: None,
            auth_digest: openvpn.auth_digest.clone(),
            data_ciphers: openvpn.data_ciphers.clone(),
            compression: OpenVpnCompression::None,
            reneg_sec: openvpn.reneg_sec,
            ppp_mschapv2: true,
            ppp_chap: true,
            // It does not authenticate the server: only when asked for.
            ppp_pap: false,
            dns_servers: Vec::new(),
            peer_public_key: String::new(),
            addresses: Vec::new(),
            allowed_ips: Vec::new(),
            preshared_key: false,
            persistent_keepalive: None,
            dns_search: Vec::new(),
            mtu: None,
            local_public_key: None,
            client_certificate: None,
            routes: profile.routes.as_deref().map(entries),
            // The profile's own networks make a split tunnel.
            tunnel_mode: match profile.full_tunnel {
                None if profile.routes.is_some() => TunnelMode::Split,
                None => TunnelMode::Automatic,
                Some(true) => TunnelMode::Full,
                Some(false) => TunnelMode::Split,
            },
            split_routes: entries(&profile.split_routes),
            extra_routes: entries(&profile.extra_routes),
            dns_domains: entries(&profile.dns_domains),
            excluded_domains: entries(&profile.excluded_domains),
            allow_route_overlap: profile.allow_route_overlap,
            via: profile.via.clone(),
            folder: profile.folder.clone(),
            exclusive: profile.exclusive,
        };
        match &profile.protocol {
            ProtocolConfig::WireGuard(p) => {
                form.kind = VpnKind::WireGuard;
                form.host = p.endpoint.clone();
                form.port = p.port;
                form.peer_public_key = p.public_key.clone();
                form.addresses = p.addresses.iter().map(ToString::to_string).collect();
                form.allowed_ips = p.allowed_ips.iter().map(ToString::to_string).collect();
                form.preshared_key = p.preshared_key;
                form.persistent_keepalive = p.persistent_keepalive;
                form.dns_servers = p.dns_servers.iter().map(ToString::to_string).collect();
                form.dns_search = p.dns_search.clone();
                form.mtu = p.mtu;
                form.local_public_key = p.local_public_key.clone();
            }
            ProtocolConfig::L2tp(p) => {
                form.kind = VpnKind::L2tp;
                form.host = p.gateway.clone();
                form.port = p.port;
                form.username = p.username.clone();
                // IKEv1, aggressive mode with a group name: not choices here.
                form.ike_version = 1;
                form.aggressive_mode = p.local_id.is_some();
                form.local_id = p.local_id.clone();
                form.remote_id = p.remote_id.clone();
                form.ike_proposals = p.ike.clone();
                form.esp_proposals = p.esp.clone();
                form.phase1_lifetime = p.phase1_lifetime;
                form.phase2_lifetime = p.phase2_lifetime;
                form.phase2_lifetime_kb = None;
                form.dpd = p.dpd;
                form.legacy_algorithms = p.legacy_algorithms;
                form.ppp_mschapv2 = p.ppp_auth.contains(&PppAuth::MsChapV2);
                form.ppp_chap = p.ppp_auth.contains(&PppAuth::Chap);
                form.ppp_pap = p.ppp_auth.contains(&PppAuth::Pap);
                form.dns_servers = p.dns_servers.iter().map(ToString::to_string).collect();
            }
            ProtocolConfig::OpenVpn(p) => {
                form.kind = VpnKind::OpenVpn;
                let (host, port) = profile.protocol.endpoint();
                (form.host, form.port) = (host.to_owned(), port);
                form.servers = p
                    .remotes
                    .iter()
                    .map(|r| OpenVpnServer {
                        host: r.host.clone(),
                        port: r.port,
                        transport: match r.transport {
                            Transport::Udp => OpenVpnTransport::Udp,
                            Transport::Tcp => OpenVpnTransport::Tcp,
                        },
                    })
                    .collect();
                form.password_auth = p.auth_user_pass;
                form.username = p.username.clone();
                if let Some(challenge) = &p.static_challenge {
                    form.static_challenge = Some(challenge.text.clone());
                    form.static_challenge_echo = challenge.echo;
                }
                form.ca_pem = p.ca_pem.clone();
                form.trusted_certificates = p.trusted_cert.clone();
                form.remote_cert_tls = p.remote_cert_tls;
                if let Some(check) = &p.verify_x509_name {
                    form.verify_x509_name = Some(check.name.clone());
                    form.verify_x509_match = match check.kind {
                        X509NameKind::Subject => X509NameMatch::Subject,
                        X509NameKind::Name => X509NameMatch::Name,
                        X509NameKind::NamePrefix => X509NameMatch::NamePrefix,
                    };
                }
                form.has_client_certificate = p.client_cert_pem.is_some();
                form.client_certificate = p.client_certificate.clone();
                form.control_channel = match p.control_channel {
                    ControlChannel::None => OpenVpnControlChannel::None,
                    ControlChannel::TlsAuth => OpenVpnControlChannel::TlsAuth,
                    ControlChannel::TlsCrypt => OpenVpnControlChannel::TlsCrypt,
                };
                form.static_key = p.static_key.clone();
                form.key_direction = p.key_direction;
                form.auth_digest = p.auth_digest.clone();
                form.data_ciphers = p.data_ciphers.clone();
                form.compression = match p.compression {
                    Compression::None => OpenVpnCompression::None,
                    Compression::Lzo => OpenVpnCompression::Lzo,
                    Compression::Stub => OpenVpnCompression::Stub,
                    Compression::StubV2 => OpenVpnCompression::StubV2,
                };
                form.reneg_sec = p.reneg_sec;
            }
            ProtocolConfig::FortiSsl(FortiSslProfile {
                host,
                port,
                realm,
                username,
                auth,
                trusted_cert,
                client_cert,
                client_cert_pem,
                client_certificate,
                ..
            }) => {
                form.kind = VpnKind::FortiSsl;
                form.host = host.clone();
                form.port = *port;
                form.realm = realm.clone();
                form.username = username.clone();
                if let FortiSslAuth::Saml { port } = auth {
                    form.saml = true;
                    form.saml_port = *port;
                }
                form.trusted_certificates = trusted_cert.clone();
                form.has_client_certificate = client_cert.is_some() || client_cert_pem.is_some();
                form.client_certificate = client_certificate.clone();
            }
            ProtocolConfig::Ipsec(p) => {
                form.kind = VpnKind::Ipsec;
                form.host = p.gateway.clone();
                form.port = p.port;
                form.username = p.username.clone();
                form.ike_version = p.ike_version;
                form.aggressive_mode = p.exchange_mode == ExchangeMode::Aggressive;
                form.xauth = p.xauth;
                form.local_id = p.local_id.clone();
                form.remote_id = p.remote_id.clone();
                form.ike_proposals = p.ike.clone();
                form.esp_proposals = p.esp.clone();
                form.phase1_lifetime = p.phase1_lifetime;
                form.phase2_lifetime = p.phase2_lifetime;
                form.phase2_lifetime_kb = p.phase2_lifetime_kb;
                form.dpd = p.dpd;
                form.legacy_algorithms = p.legacy_algorithms;
                form.gateway_certificate = p.gateway_auth == GatewayAuth::Certificate;
                form.ca_pem = p.ca_pem.clone();
                form.client_certificate = p.client_certificate.clone();
                form.trusted_certificates = p.trusted_cert.clone();
            }
        }
        form.read_proposals();
        form
    }
}

/// A received `.vpnprofile`, to show before adding it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReceivedProfile {
    pub form: ProfileForm,
    /// A profile of that name exists already.
    pub name_taken: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_round_trips_and_keeps_hidden_fields() {
        let base: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nport = 4443\n\
             client_cert = \"/c.pem\"\ndns_domains = [\"corp\"]",
        )
        .unwrap();
        let mut form = ProfileForm::from(&base);
        assert!(form.has_client_certificate);
        form.username = Some(" alice ".into());
        form.routes = Some(vec!["10.1.0.0/16".into(), " ".into()]);
        let saved = form.to_profile(Some(&base)).unwrap();
        let ProtocolConfig::FortiSsl(p) = &saved.protocol else { panic!() };
        assert_eq!((p.username.as_deref(), p.client_cert.as_deref(), p.port), (Some("alice"), Some("/c.pem"), 4443));
        assert_eq!(saved.routes.unwrap().len(), 1);

        // A Keychain certificate replaces the files.
        form.client_certificate = Some("cd".repeat(32));
        let saved = form.to_profile(Some(&base)).unwrap();
        let ProtocolConfig::FortiSsl(p) = &saved.protocol else { panic!() };
        assert_eq!((p.client_cert.as_deref(), p.client_certificate.clone()), (None, Some("cd".repeat(32))));
        saved.validate().unwrap();
        assert_eq!(ProfileForm::from(&saved).client_certificate, Some("cd".repeat(32)));
    }

    #[test]
    fn another_type_keeps_the_profile() {
        let base: Profile = toml::from_str(
            "id = \"00000000-0000-4000-8000-000000000001\"\nname = \"paris\"\nfolder = \"Sites\"\n\
             protocol = \"forti-ssl\"\nhost = \"vpn.example.com\"",
        )
        .unwrap();
        let mut form = ProfileForm::from(&base);
        form.kind = VpnKind::L2tp;
        form.host = "l2tp.example.com".into();
        let saved = form.to_profile(Some(&base)).unwrap();
        assert!(matches!(saved.protocol, ProtocolConfig::L2tp(_)), "{saved:?}");
        assert_eq!((saved.id.as_str(), saved.folder.as_deref()), (base.id.as_str(), Some("Sites")));
    }

    /// FortiClient's IPsec settings are shown as choices and
    /// written back unchanged.
    #[test]
    fn ipsec_proposals_as_choices() {
        let base: Profile = toml::from_str(
            "name = \"hq\"\nprotocol = \"ipsec\"\ngateway = \"203.0.113.68\"\nike_version = 1\n\
             exchange_mode = \"aggressive\"\nike = [\"aes128-sha1-modp1536\", \"aes256-sha256-modp1536\"]\n\
             esp = [\"aes128-sha1-modp1536\", \"aes256-sha1-modp1536\"]\nphase2_lifetime_kb = 5120",
        )
        .unwrap();
        let form = ProfileForm::from(&base);
        assert!(!form.custom_proposals);
        assert_eq!(form.phase1_dh_groups, [5]);
        assert_eq!(form.pfs_group, Some(5));
        assert_eq!(form.phase2_suites[1], CipherSuite { encryption: "aes256".into(), hash: "sha1".into() });
        assert_eq!(form.phase2_lifetime_kb, Some(5120));
        let saved = form.to_profile(Some(&base)).unwrap();
        let (ProtocolConfig::Ipsec(a), ProtocolConfig::Ipsec(b)) = (&saved.protocol, &base.protocol) else { panic!() };
        assert_eq!((&a.ike, &a.esp, a.phase2_lifetime_kb), (&b.ike, &b.esp, Some(5120)));

        // Choices rebuild the strings: groups first, then suites.
        let mut form = form;
        form.ike_version = 2;
        form.phase1_dh_groups = vec![14, 19];
        form.phase1_suites.push(CipherSuite { encryption: "aes256gcm16".into(), hash: "sha384".into() });
        form.pfs_group = None;
        let (ike, esp) = form.built_proposals().unwrap();
        assert_eq!(ike[..3], ["aes128-sha1-modp2048", "aes256-sha256-modp2048", "aes256gcm16-prfsha384-modp2048"]);
        assert_eq!(ike.len(), 6);
        assert_eq!(esp, ["aes128-sha1", "aes256-sha1"]);
        form.ike_version = 1;
        assert!(form.built_proposals().unwrap_err().to_string().contains("IKEv2"));

        // A phase 2 lifetime in kilobytes only; not neither.
        form.ike_version = 2;
        form.phase2_lifetime = 0;
        assert!(form.to_profile(Some(&base)).is_ok());
        form.phase2_lifetime_kb = None;
        assert!(form.to_profile(Some(&base)).is_err());
    }

    #[test]
    fn chacha_and_legacy_choices() {
        let mut form = ProfileForm::new(VpnKind::Ipsec);
        form.name = "old".into();
        form.host = "203.0.113.10".into();
        let chacha = CipherSuite { encryption: "chacha20poly1305".into(), hash: "sha256".into() };
        form.phase1_suites = vec![chacha.clone()];
        form.phase2_suites = vec![chacha];
        form.phase1_dh_groups = vec![31];
        assert_eq!(
            form.built_proposals().unwrap(),
            (vec!["chacha20poly1305-prfsha256-x25519".into()], vec!["chacha20poly1305".into()])
        );
        form.ike_version = 1;
        assert!(form.built_proposals().unwrap_err().to_string().contains("ChaCha20"));

        // 3DES and group 2 are saved only with legacy algorithms allowed.
        let des = CipherSuite { encryption: "3des".into(), hash: "sha1".into() };
        form.phase1_suites = vec![des.clone()];
        form.phase2_suites = vec![des];
        form.phase1_dh_groups = vec![2];
        assert!(form.to_profile(None).unwrap_err().to_string().contains("legacy"));
        form.legacy_algorithms = true;
        let saved = form.to_profile(None).unwrap();
        let back = ProfileForm::from(&saved);
        assert!(back.legacy_algorithms && !back.custom_proposals);
        assert_eq!(back.phase1_dh_groups, [2]);
    }

    #[test]
    fn client_certificate_replaces_the_user_name() {
        let profile: Profile =
            toml::from_str("name = \"c\"\nprotocol = \"ipsec\"\ngateway = \"192.0.2.1\"\nusername = \"alice\"")
                .unwrap();
        let mut form = ProfileForm::from(&profile);
        form.client_certificate = Some("ab".repeat(32));
        let ProtocolConfig::Ipsec(p) = form.to_profile(None).unwrap().protocol else { panic!() };
        assert_eq!((p.client_certificate, p.username), (Some("ab".repeat(32)), None));
        // IKEv1 has no client certificates (yet): dropped.
        form.ike_version = 1;
        let ProtocolConfig::Ipsec(p) = form.to_profile(None).unwrap().protocol else { panic!() };
        assert!(p.client_certificate.is_none());
    }

    #[test]
    fn gateway_certificate_settings() {
        let cert = rcgen::generate_simple_self_signed(vec!["ca.corp.test".to_owned()]).unwrap().cert;
        // A DER file becomes PEM; PEM stays PEM.
        let pem = certificates_as_pem(cert.der()).unwrap();
        assert_eq!(certificates_as_pem(pem.as_bytes()).unwrap(), pem);
        assert_eq!(certificate_names(&pem).len(), 1);
        assert!(certificates_as_pem(b"not a certificate").is_err());

        let mut form = ProfileForm::new(VpnKind::Ipsec);
        form.name = "corp".into();
        form.host = "vpn.corp.test".into();
        form.gateway_certificate = true;
        form.ca_pem = Some(pem.clone());
        form.trusted_certificates = vec!["ab".repeat(32)];
        let saved = form.to_profile(None).unwrap();
        let ProtocolConfig::Ipsec(p) = &saved.protocol else { panic!() };
        assert_eq!(
            (p.gateway_auth, p.ca_pem.as_deref(), p.trusted_cert.len()),
            (GatewayAuth::Certificate, Some(pem.as_str()), 1)
        );
        let back = ProfileForm::from(&saved);
        assert!(back.gateway_certificate && back.ca_pem.is_some());

        // Back to the PSK: certificate settings are dropped; IKEv1 refuses them.
        form.gateway_certificate = false;
        let ProtocolConfig::Ipsec(p) = form.to_profile(None).unwrap().protocol else { panic!() };
        assert!(p.ca_pem.is_none() && p.trusted_cert.is_empty());
        form.gateway_certificate = true;
        form.ike_version = 1;
        form.phase1_suites = vec![CipherSuite { encryption: "aes256".into(), hash: "sha256".into() }];
        assert!(form.to_profile(None).unwrap_err().to_string().contains("IKEv2"));
    }

    #[test]
    fn unusual_proposals_stay_text() {
        let mut form = ProfileForm::new(VpnKind::Ipsec);
        assert!(!form.custom_proposals, "new profiles use choices");
        form.ike_proposals = vec!["aes256-sha256-prfsha384-modp2048".into()];
        form.read_proposals();
        assert!(form.custom_proposals);
        // Different PFS groups per proposal cannot be one choice either.
        form.ike_proposals = vec!["aes256-sha256-modp2048".into()];
        form.esp_proposals = vec!["aes256-sha256-modp2048".into(), "aes128-sha1".into()];
        form.read_proposals();
        assert!(form.custom_proposals);
        form.esp_proposals = vec!["aes256-sha256-modp2048".into()];
        form.read_proposals();
        assert!(!form.custom_proposals);
    }

    const STATIC_KEY: &str = "-----BEGIN OpenVPN Static key V1-----\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        -----END OpenVPN Static key V1-----\n";

    fn ca_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["ca.corp.test".to_owned()]).unwrap().cert;
        cert.pem()
    }

    /// An imported OpenVPN profile: what the editor shows, and the PEM
    /// certificate and key it does not show, kept when saving.
    #[test]
    fn openvpn_round_trip_keeps_the_imported_key() {
        let text = format!(
            "name = \"office\"\nprotocol = \"openvpn\"\nca_pem = '''{}'''\nclient_cert_pem = \"CERT\"\n\
             client_key_pem = \"KEY\"\ncontrol_channel = \"tls-auth\"\nkey_direction = 1\n\
             static_key = '''{STATIC_KEY}'''\ncompression = \"lzo\"\nauth_digest = \"SHA256\"\n\
             verify_x509_name = {{ name = \"vpn\", kind = \"name-prefix\" }}\n\
             [[remotes]]\nhost = \"vpn1.example.com\"\n[[remotes]]\nhost = \"vpn2.example.com\"\nport = 443\n\
             transport = \"tcp\"\n",
            ca_pem()
        );
        let base: Profile = toml::from_str(&text).unwrap();
        base.validate().unwrap();
        let mut form = ProfileForm::from(&base);
        assert_eq!(form.kind, VpnKind::OpenVpn);
        assert_eq!((form.host.as_str(), form.port), ("vpn1.example.com", 1194));
        assert_eq!(
            form.servers[1],
            OpenVpnServer { host: "vpn2.example.com".into(), port: 443, transport: OpenVpnTransport::Tcp }
        );
        assert!(form.has_client_certificate && !form.password_auth && form.remote_cert_tls);
        assert_eq!((form.control_channel, form.key_direction), (OpenVpnControlChannel::TlsAuth, Some(1)));
        assert_eq!((form.compression, form.verify_x509_match), (OpenVpnCompression::Lzo, X509NameMatch::NamePrefix));

        form.servers.push(OpenVpnServer { host: " ".into(), port: 1194, transport: OpenVpnTransport::Udp });
        form.data_ciphers = vec!["AES-256-GCM".into(), "AES-256-GCM".into()];
        let saved = form.to_profile(Some(&base)).unwrap();
        let ProtocolConfig::OpenVpn(p) = &saved.protocol else { panic!() };
        assert_eq!(p.remotes.len(), 2, "empty rows are dropped");
        assert_eq!((p.client_cert_pem.as_deref(), p.client_key_pem.as_deref()), (Some("CERT"), Some("KEY")));
        assert_eq!(p.data_ciphers, ["AES-256-GCM"]);
        assert_eq!(p.verify_x509_name, Some(X509NameCheck { name: "vpn".into(), kind: X509NameKind::NamePrefix }));
        assert_eq!(p.static_key.as_deref(), Some(STATIC_KEY));

        // A Keychain certificate replaces the PEM ones; tls-crypt has no
        // direction.
        form.client_certificate = Some("ab".repeat(32));
        form.control_channel = OpenVpnControlChannel::TlsCrypt;
        let saved = form.to_profile(Some(&base)).unwrap();
        let ProtocolConfig::OpenVpn(p) = &saved.protocol else { panic!() };
        assert_eq!((p.client_cert_pem.as_deref(), p.key_direction), (None, None));
        assert_eq!(ProfileForm::from(&saved).client_certificate, Some("ab".repeat(32)));

        // No control channel: the key goes.
        form.control_channel = OpenVpnControlChannel::None;
        let ProtocolConfig::OpenVpn(p) = form.to_profile(Some(&base)).unwrap().protocol else { panic!() };
        assert!(p.static_key.is_none());
    }

    #[test]
    fn new_openvpn_profiles() {
        let mut form = ProfileForm::new(VpnKind::OpenVpn);
        assert_eq!(form.servers.len(), 1);
        assert!(form.password_auth && form.remote_cert_tls);
        form.name = "home".into();
        form.servers[0].host = "vpn.example.com".into();
        assert!(form.to_profile(None).unwrap_err().to_string().contains("CA"), "a CA or a fingerprint is needed");
        form.ca_pem = Some(ca_pem());
        form.username = Some("alice".into());
        form.static_challenge = Some("PIN".into());
        let saved = form.to_profile(None).unwrap();
        let ProtocolConfig::OpenVpn(p) = &saved.protocol else { panic!() };
        assert_eq!(
            (p.username.as_deref(), p.static_challenge.as_ref().map(|c| c.text.as_str())),
            (Some("alice"), Some("PIN"))
        );

        // Without a password: no user name nor challenge, and a certificate is needed.
        form.password_auth = false;
        assert!(form.to_profile(None).unwrap_err().to_string().contains("client certificate"));
        form.client_certificate = Some("cd".repeat(32));
        let ProtocolConfig::OpenVpn(p) = form.to_profile(None).unwrap().protocol else { panic!() };
        assert_eq!((p.username, p.static_challenge), (None, None));

        form.control_channel = OpenVpnControlChannel::TlsAuth;
        assert!(form.to_profile(None).unwrap_err().to_string().contains("static key"));
        form.static_key = Some("garbage".into());
        assert!(form.to_profile(None).is_err());
        form.static_key = Some(STATIC_KEY.into());
        form.ca_pem = Some("not a certificate".into());
        assert!(form.to_profile(None).unwrap_err().to_string().contains("certificate authority"));
        form.ca_pem = None;
        form.trusted_certificates = vec!["AB:".repeat(31) + "AB"];
        form.to_profile(None).unwrap();
        form.servers.clear();
        assert!(form.to_profile(None).unwrap_err().to_string().contains("server"));
    }

    #[test]
    fn l2tp_profiles() {
        let mut form = ProfileForm::new(VpnKind::L2tp);
        assert_eq!((form.kind, form.port, form.ike_version), (VpnKind::L2tp, 500, 1));
        assert!(!form.custom_proposals && form.ppp_mschapv2 && form.ppp_chap && !form.ppp_pap);
        form.name = "meraki".into();
        form.host = " vpn.example.com ".into();
        form.username = Some("alice".into());
        form.local_id = Some("staff".into());
        form.dns_servers = vec!["10.0.0.53".into(), " ".into()];
        let saved = form.to_profile(None).unwrap();
        let ProtocolConfig::L2tp(p) = &saved.protocol else { panic!() };
        assert_eq!((p.gateway.as_str(), p.username.as_deref()), ("vpn.example.com", Some("alice")));
        assert_eq!(p.ipsec().exchange_mode, ExchangeMode::Aggressive);
        assert_eq!((p.ike.len(), p.ike[0].as_str()), (6, "aes256-sha256-modp2048"));
        assert_eq!(p.esp, ["aes256-sha256", "aes256-sha1", "aes128-sha1"]);
        assert_eq!(p.ppp_auth, [PppAuth::MsChapV2, PppAuth::Chap], "no PAP unless asked");
        assert_eq!(p.dns_servers.len(), 1);

        // Back to the form: the same choices.
        let back = ProfileForm::from(&saved);
        assert_eq!(back.kind, VpnKind::L2tp);
        assert!(!back.custom_proposals);
        assert_eq!((back.phase1_dh_groups.as_slice(), back.phase1_suites.len()), ([14, 5].as_slice(), 3));
        assert_eq!(
            (back.local_id.as_deref(), back.dns_servers.as_slice()),
            (Some("staff"), ["10.0.0.53".to_owned()].as_slice())
        );

        // The profile's order of PPP authentications is kept.
        let base: Profile = toml::from_str(
            "name = \"m\"\nprotocol = \"l2tp\"\ngateway = \"192.0.2.1\"\nppp_auth = [\"pap\", \"chap\"]",
        )
        .unwrap();
        let mut form = ProfileForm::from(&base);
        assert!(form.ppp_pap && form.ppp_chap && !form.ppp_mschapv2);
        form.ppp_mschapv2 = true;
        let ProtocolConfig::L2tp(p) = form.to_profile(Some(&base)).unwrap().protocol else { panic!() };
        assert_eq!(p.ppp_auth, [PppAuth::Pap, PppAuth::Chap, PppAuth::MsChapV2]);

        // Errors explained: no authentication, a bad address, legacy, AES-GCM.
        (form.ppp_pap, form.ppp_chap, form.ppp_mschapv2) = (false, false, false);
        assert!(form.to_profile(Some(&base)).unwrap_err().to_string().contains("PPP"));
        form.ppp_chap = true;
        form.dns_servers = vec!["dns.example.com".into()];
        assert!(form.to_profile(Some(&base)).unwrap_err().to_string().contains("IP address"));
        form.dns_servers.clear();
        form.custom_proposals = false;
        form.phase1_suites = vec![CipherSuite { encryption: "3des".into(), hash: "sha1".into() }];
        form.phase1_dh_groups = vec![2];
        form.phase2_suites = vec![CipherSuite { encryption: "aes128".into(), hash: "sha1".into() }];
        assert!(form.to_profile(Some(&base)).unwrap_err().to_string().contains("legacy"));
        form.legacy_algorithms = true;
        form.to_profile(Some(&base)).unwrap();
        form.ike_version = 2;
        form.phase1_suites = vec![CipherSuite { encryption: "aes256gcm16".into(), hash: "sha256".into() }];
        assert!(form.to_profile(Some(&base)).unwrap_err().to_string().contains("IKEv2"), "L2TP is always IKEv1");
    }

    #[test]
    fn notes_go_through_the_form() {
        let base: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n\
             split_routes = [\"10.0.0.0/8\", { net = \"10.20.0.5/32\", note = \"Jira\" }]\n\
             dns_domains = [{ domain = \"corp.example\", note = \"Intranet\" }]",
        )
        .unwrap();
        let form = ProfileForm::from(&base);
        assert_eq!(form.split_routes[1], ListEntry { value: "10.20.0.5/32".into(), note: "Jira".into() });
        assert_eq!(form.dns_domains[0].note, "Intranet");
        let saved = form.to_profile(Some(&base)).unwrap();
        assert_eq!((saved.split_routes.clone(), saved.dns_domains.clone()), (base.split_routes, base.dns_domains));
    }

    #[test]
    fn routing_of_any_protocol() {
        let base: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n\
             extra_routes = [\"10.20.0.0/16\", \"*.corp.example\"]",
        )
        .unwrap();
        let form = ProfileForm::from(&base);
        assert_eq!((form.tunnel_mode, form.extra_routes.len()), (TunnelMode::Automatic, 2));
        let saved = form.to_profile(Some(&base)).unwrap();
        assert_eq!(saved.extra_routes, base.extra_routes, "networks added to the gateway's, whatever the protocol");
        let own: Profile = toml::from_str(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nroutes = [\"10.1.0.0/16\"]",
        )
        .unwrap();
        assert_eq!(ProfileForm::from(&own).tunnel_mode, TunnelMode::Split, "its own networks: a split tunnel");
    }

    #[test]
    fn pasted_lines_become_entries() {
        let entries = parse_list(
            "10.1.0.0/16  Intranet\n\n10.1.2.3 # Jira\n10.9.0.0/24, Lab, 2nd floor\n  corp.example\n".into(),
        );
        let pairs: Vec<(&str, &str)> = entries.iter().map(|e| (e.value.as_str(), e.note.as_str())).collect();
        assert_eq!(
            pairs,
            [
                ("10.1.0.0/16", "Intranet"),
                ("10.1.2.3", "Jira"),
                ("10.9.0.0/24", "Lab, 2nd floor"),
                ("corp.example", "")
            ]
        );
        assert!(network_error("10.1.0.0".into()).is_some() && network_error("10.1.2.3".into()).is_none());
        assert!(domain_error("corp.example".into()).is_none() && domain_error("not a domain".into()).is_some());
    }

    #[test]
    fn bad_input_is_explained() {
        let mut form = ProfileForm::new(VpnKind::Ipsec);
        form.name = "branch".into();
        form.host = "203.0.113.10".into();
        assert!(form.to_profile(None).is_ok());
        form.routes = Some(vec!["10.1.0.0".into()]);
        assert!(form.to_profile(None).unwrap_err().to_string().contains("add its prefix"));
        form.routes =
            Some(vec!["10.1.0.0/16".into(), "10.1.2.3".into(), ListEntry { value: "".into(), note: "x".into() }]);
        let routes = form.to_profile(None).unwrap().routes.unwrap();
        assert_eq!(routes.iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.1.0.0/16", "10.1.2.3/32"]);
        form.routes = Some(vec!["no pe".into()]);
        assert!(form.to_profile(None).unwrap_err().to_string().contains("not a network"));
        form.routes = Some(vec!["*.corp-saas.com".into()]);
        let routes = form.to_profile(None).unwrap().routes.unwrap();
        assert!(routes[0].domain().is_some(), "a domain of the profile is kept");
        assert_eq!(network_error("*.corp-saas.com".into()), None);
        assert!(network_error("10.1.2.300".into()).unwrap().contains("not a network"), "an address, mistyped");
        assert!(pattern_error("10.0.0.0/8".into()).is_some() && pattern_error("*.zoom.us".into()).is_none());
        form.excluded_domains = vec![ListEntry { value: "*.Zoom.us".into(), note: "Zoom".into() }];
        let saved = form.to_profile(None).unwrap();
        assert_eq!(saved.excluded_domains[0].value.to_string(), "*.zoom.us");
        form.excluded_domains = vec!["10.0.0.0/8".into()];
        assert!(form.to_profile(None).is_err());
        form.excluded_domains = vec![];
        form.routes = None;
        form.name = "bad/name".into();
        assert!(form.to_profile(None).is_err(), "'/' separates folders");
        let mut ssl = ProfileForm::new(VpnKind::FortiSsl);
        ssl.name = "x".into();
        ssl.host = "vpn.example.com".into();
        ssl.trusted_certificates = vec!["abcd".into()];
        assert!(ssl.to_profile(None).unwrap_err().to_string().contains("SHA-256"));
    }
}
