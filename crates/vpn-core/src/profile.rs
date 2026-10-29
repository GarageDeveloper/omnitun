use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// A named connection, as stored in the user's `profiles.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Stable identity (a UUID): sessions, secrets and chains refer to the
    /// profile by it, so that its name is free. Given when the profile is
    /// created; missing in files written before.
    #[serde(default)]
    pub id: String,
    /// For people: unique within its folder only.
    pub name: String,
    /// Free text shown under the name.
    #[serde(default)]
    pub description: Option<String>,
    /// Where the VPN is filed in the app, `/` between subfolders
    /// ("Clients/Acme").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Offer to keep the password in the Keychain; when false, it is asked
    /// at every connection (FortiClient "prompt on login").
    #[serde(default = "yes")]
    pub save_password: bool,
    #[serde(flatten)]
    pub protocol: ProtocolConfig,
    /// Replace the routes pushed by the gateway.
    #[serde(default)]
    pub routes: Option<Vec<Ipv4Net>>,
    /// Force (or refuse) full-tunnel mode regardless of the gateway.
    #[serde(default)]
    pub full_tunnel: Option<bool>,
    /// The networks of a connection in split mode, chosen when connecting
    /// ("Connect in Split Mode", `omnitunctl connect --split`): only they go
    /// through the VPN, whatever the gateway and `full_tunnel` say. Empty:
    /// no split mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_routes: Vec<Ipv4Net>,
    /// Extra split-DNS domains, in addition to those pushed.
    #[serde(default)]
    pub dns_domains: Vec<String>,
    /// Accept routes identical to another active session's routes.
    #[serde(default)]
    pub allow_route_overlap: bool,
    /// VPNs this one is chained through, preferred first: connected
    /// normally, it goes through the first of them that is up, or brings
    /// up the first one before itself; its routes may overlap theirs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<String>,
    /// A company VPN: never up at the same time as another VPN, the VPNs
    /// it goes through excepted. The app offers to disconnect the others.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum ProtocolConfig {
    FortiSsl(FortiSslProfile),
    Ipsec(IpsecProfile),
    #[serde(rename = "openvpn")]
    OpenVpn(crate::OpenVpnProfile),
    L2tp(crate::L2tpProfile),
    #[serde(rename = "wireguard")]
    WireGuard(crate::WireGuardProfile),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FortiSslProfile {
    pub host: String,
    #[serde(default = "default_https_port")]
    pub port: u16,
    #[serde(default)]
    pub realm: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub auth: FortiSslAuth,
    /// SHA-256 fingerprints (hex) of accepted gateway certificates, for
    /// self-signed FortiGate certificates. Empty: normal PKI validation.
    #[serde(default)]
    pub trusted_cert: Vec<String>,
    /// Additional CA bundle (PEM file), read by omnitunctl as the user.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Client certificate and key (PEM files) for certificate
    /// authentication, read by omnitunctl as the user.
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
    /// Contents of the files above. The daemon never opens user-supplied
    /// paths: it runs as root and would read files the user cannot.
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub client_cert_pem: Option<String>,
    /// The client keeps the key: it signs for the engine (see
    /// [`crate::SignRequest`]) and never sends this field to the daemon.
    #[serde(default)]
    pub client_key_pem: Option<String>,
    /// Client certificate of the user's Keychain, by SHA-256 (hex); the
    /// key stays in the Keychain. Replaces the PEM files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// That certificate's chain (PEM), added by the client at each
    /// connection, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_chain_pem: Option<String>,
    /// Certificate authorities the user's Keychain trusts (PEM), added by
    /// the client at each connection, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_ca_pem: Option<String>,
}

/// The client key is never written to logs.
impl std::fmt::Debug for FortiSslProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FortiSslProfile")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("realm", &self.realm)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("trusted_cert", &self.trusted_cert)
            .field("ca_file", &self.ca_file)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "…"))
            .field("client_cert_pem", &self.client_cert_pem.as_ref().map(|_| "…"))
            .field("client_key_pem", &self.client_key_pem.as_ref().map(|_| "<redacted>"))
            .field("client_certificate", &self.client_certificate)
            .field("client_chain_pem", &self.client_chain_pem.as_ref().map(|_| "…"))
            .field("keychain_ca_pem", &self.keychain_ca_pem.as_ref().map(|_| "…"))
            .finish()
    }
}

impl FortiSslProfile {
    /// Replaces file paths with their contents (done by omnitunctl).
    pub fn inline_files(&mut self) -> anyhow::Result<()> {
        use anyhow::Context;
        let read = |path: &Option<String>| -> anyhow::Result<Option<String>> {
            path.as_deref().map(|p| std::fs::read_to_string(p).with_context(|| format!("cannot read {p}"))).transpose()
        };
        self.ca_pem = read(&self.ca_file)?.or(self.ca_pem.take());
        self.client_cert_pem = read(&self.client_cert)?.or(self.client_cert_pem.take());
        self.client_key_pem = read(&self.client_key)?.or(self.client_key_pem.take());
        self.ca_file = None;
        self.client_cert = None;
        self.client_key = None;
        Ok(())
    }

    pub fn has_file_paths(&self) -> bool {
        self.ca_file.is_some() || self.client_cert.is_some() || self.client_key.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum FortiSslAuth {
    /// Username/password, with FortiToken/OTP when the gateway asks.
    #[default]
    Password,
    /// SAML through the user's browser; the gateway redirects to
    /// `http://127.0.0.1:<port>/?id=...` once the IdP login completes.
    Saml {
        #[serde(default = "default_saml_port")]
        port: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecProfile {
    pub gateway: String,
    #[serde(default = "default_ike_port")]
    pub port: u16,
    /// 2 (default) or 1. FortiClient dial-up tunnels are often IKEv1.
    #[serde(default = "default_ike_version")]
    pub ike_version: u8,
    /// IKEv1 phase 1 exchange.
    #[serde(default)]
    pub exchange_mode: ExchangeMode,
    /// IKEv1 XAuth user authentication (username + password after phase 1).
    #[serde(default)]
    pub xauth: bool,
    /// IKE identity sent as IDi (FortiGate "peer ID"); defaults to the
    /// username or our address.
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub remote_id: Option<String>,
    /// Username for EAP (IKEv2) or XAuth (IKEv1); when unset, PSK-only.
    #[serde(default)]
    pub username: Option<String>,
    /// IKE proposals, strongSwan syntax, e.g. "aes256gcm16-prfsha256-ecp256".
    #[serde(default = "default_ike_proposals")]
    pub ike: Vec<String>,
    /// ESP proposals, e.g. "aes256gcm16", "aes256-sha256".
    #[serde(default = "default_esp_proposals")]
    pub esp: Vec<String>,
    /// IKE SA (phase 1) lifetime, in seconds.
    #[serde(default = "default_phase1_lifetime")]
    pub phase1_lifetime: u32,
    /// IPsec SA (phase 2) lifetime, in seconds; 0: no time limit (then
    /// `phase2_lifetime_kb` must be set).
    #[serde(default = "default_phase2_lifetime")]
    pub phase2_lifetime: u32,
    /// Also rekey phase 2 after this many kilobytes, if set.
    #[serde(default)]
    pub phase2_lifetime_kb: Option<u64>,
    /// Probe the gateway when the tunnel is idle (dead peer detection).
    #[serde(default = "yes")]
    pub dpd: bool,
    /// Allows 3DES and DH group 2 in the proposals, for old gateways only.
    #[serde(default)]
    pub legacy_algorithms: bool,
    /// How the gateway proves its identity (IKEv2).
    #[serde(default)]
    pub gateway_auth: GatewayAuth,
    /// CA certificates (PEM) for the gateway certificate, in place of the
    /// public roots (the Keychain's are still trusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// SHA-256 fingerprints of trusted gateway certificates: when set, the
    /// certificate must be one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_cert: Vec<String>,
    /// Certificate authorities the user's Keychain trusts (PEM), added by
    /// the client at each connection, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_ca_pem: Option<String>,
    /// SHA-256 (hex) of the Keychain certificate we authenticate with
    /// (IKEv2), instead of the PSK or EAP; its key never leaves the
    /// Keychain: the client signs for the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// That certificate and its intermediates (PEM), added by the client
    /// at each connection, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_chain_pem: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayAuth {
    /// The pre-shared key.
    #[default]
    Psk,
    /// A certificate and a signature (IKEv2).
    Certificate,
}

/// Proposal tokens refused unless `legacy_algorithms` is set.
pub const LEGACY_ALGORITHMS: [&str; 2] = ["3des", "modp1024"];

impl IpsecProfile {
    /// The legacy algorithms the proposals use.
    pub fn legacy_in_use(&self) -> Vec<&'static str> {
        LEGACY_ALGORITHMS
            .into_iter()
            .filter(|legacy| {
                self.ike.iter().chain(&self.esp).any(|p| p.split('-').any(|t| t.trim().eq_ignore_ascii_case(legacy)))
            })
            .collect()
    }
}

/// Lifetime bounds, as FortiOS accepts them.
pub const MIN_LIFETIME: u32 = 120;
pub const MAX_LIFETIME: u32 = 172_800;
pub const MIN_LIFETIME_KB: u64 = 5120;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExchangeMode {
    #[default]
    Main,
    Aggressive,
}

fn yes() -> bool {
    true
}

fn default_phase1_lifetime() -> u32 {
    86_400
}

fn default_phase2_lifetime() -> u32 {
    43_200
}

fn default_ike_version() -> u8 {
    2
}

fn default_https_port() -> u16 {
    443
}

fn default_saml_port() -> u16 {
    8020
}

fn default_ike_port() -> u16 {
    500
}

fn default_ike_proposals() -> Vec<String> {
    vec!["aes256gcm16-prfsha256-ecp256".into(), "aes256gcm16-prfsha256-x25519".into(), "aes256-sha256-modp2048".into()]
}

fn default_esp_proposals() -> Vec<String> {
    vec!["aes256gcm16".into(), "aes256-sha256".into()]
}

impl ProtocolConfig {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolConfig::FortiSsl(_) => "forti-ssl",
            ProtocolConfig::Ipsec(_) => "ipsec",
            ProtocolConfig::OpenVpn(_) => "openvpn",
            ProtocolConfig::L2tp(_) => "l2tp",
            ProtocolConfig::WireGuard(_) => "wireguard",
        }
    }

    /// The server secrets are bound to: a stored password is only sent
    /// to the host and port it was saved for.
    pub fn endpoint(&self) -> (&str, u16) {
        match self {
            ProtocolConfig::FortiSsl(p) => (&p.host, p.port),
            ProtocolConfig::Ipsec(p) => (&p.gateway, p.port),
            // The first server; validation refuses a profile without one.
            ProtocolConfig::OpenVpn(p) => p.remotes.first().map_or(("", 0), |r| (&r.host, r.port)),
            ProtocolConfig::L2tp(p) => (&p.gateway, p.port),
            ProtocolConfig::WireGuard(p) => (&p.endpoint, p.port),
        }
    }

    /// Every server the engine may connect to: an OpenVPN profile's
    /// remotes, tried in turn, or the one endpoint.
    pub fn servers(&self) -> Vec<(&str, u16)> {
        match self {
            ProtocolConfig::OpenVpn(p) => p.remotes.iter().map(|r| (r.host.as_str(), r.port)).collect(),
            _ => vec![self.endpoint()],
        }
    }

    /// The certificate authorities the Keychain trusts, for this
    /// connection; none for OpenVPN, which only trusts its own CA.
    pub fn keychain_ca_pem(&mut self) -> Option<&mut Option<String>> {
        match self {
            ProtocolConfig::FortiSsl(p) => Some(&mut p.keychain_ca_pem),
            ProtocolConfig::Ipsec(p) => Some(&mut p.keychain_ca_pem),
            ProtocolConfig::OpenVpn(_) | ProtocolConfig::L2tp(_) | ProtocolConfig::WireGuard(_) => None,
        }
    }
}

/// Most levels of subfolders.
pub const MAX_FOLDER_DEPTH: usize = 4;

/// A folder path: non-empty names without control characters, trimmed.
pub fn valid_folder(folder: &str) -> bool {
    let names: Vec<&str> = folder.split('/').collect();
    names.len() <= MAX_FOLDER_DEPTH
        && names.iter().all(|n| {
            !n.is_empty() && n.len() <= 64 && n.trim() == *n && !n.chars().any(|c| c.is_control() || is_invisible(c))
        })
}

/// Most VPNs a profile lists to be chained through.
pub const MAX_VIA: usize = 4;

/// At most as many as the daemon accepts from a gateway.
pub const MAX_SPLIT_ROUTES: usize = 256;

/// Lowest SAML callback port: the daemon runs as root and must not be
/// made to listen on a privileged port.
pub const MIN_SAML_PORT: u16 = 1024;

/// A name for people: up to 64 characters, no control character, no `/`
/// (it separates folders in paths like `Clients/Acme/EU`), trimmed.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 64
        && name.trim() == name
        && !name.chars().any(|c| c.is_control() || is_invisible(c) || c == '/')
}

/// Unicode format characters: invisible, and the bidirectional ones
/// reorder the text around them (U+202E makes "gnp.exe" read "exe.png"). Never in
/// a name, and stripped from what a gateway sends.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
}

/// A new profile id: a random (version 4) UUID.
pub fn new_id() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// A profile id: a UUID in lower case, hyphenated. It ends up in socket
/// paths, resolver keys and Keychain accounts.
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// A host name or an IP literal, nothing that could alter a URL.
pub fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok() || crate::valid_domain(host)
}

impl Profile {
    /// Checks what the daemon must not trust from a client: the server
    /// address ends up in URLs opened in the browser and in sockets.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !valid_name(&self.name) {
            anyhow::bail!("profile names are 1 to 64 characters, without '/', control characters or spaces around");
        }
        // Empty in a profile not stored yet; the daemon requires one.
        if !self.id.is_empty() && !valid_id(&self.id) {
            anyhow::bail!("invalid profile id {:?}", self.id);
        }
        let (host, port) = self.protocol.endpoint();
        if !valid_host(host) {
            anyhow::bail!("invalid server address {host:?}");
        }
        if port == 0 {
            anyhow::bail!("invalid server port 0");
        }
        if let ProtocolConfig::FortiSsl(FortiSslProfile { auth: FortiSslAuth::Saml { port }, .. }) = &self.protocol
            && *port < MIN_SAML_PORT
        {
            anyhow::bail!("SAML callback port must be {MIN_SAML_PORT} or higher");
        }
        if let ProtocolConfig::FortiSsl(p) = &self.protocol
            && let Some(certificate) = &p.client_certificate
        {
            if p.client_cert.is_some() || p.client_key.is_some() || p.client_cert_pem.is_some() {
                anyhow::bail!("client_certificate (Keychain) replaces client_cert and client_key");
            }
            if !is_sha256_hex(certificate) {
                anyhow::bail!("client_certificate must be the certificate's SHA-256");
            }
        }
        if let ProtocolConfig::FortiSsl(p) = &self.protocol {
            check_pins(&p.trusted_cert)?;
        }
        if let ProtocolConfig::Ipsec(p) = &self.protocol {
            if !matches!(p.ike_version, 1 | 2) {
                anyhow::bail!("ike_version must be 1 or 2");
            }
            check_pins(&p.trusted_cert)?;
            let lifetimes = MIN_LIFETIME..=MAX_LIFETIME;
            if p.phase2_lifetime == 0 && p.phase2_lifetime_kb.is_none() {
                anyhow::bail!("the phase 2 key needs a lifetime in seconds or in kilobytes");
            }
            let phase2_off = p.phase2_lifetime == 0;
            if !lifetimes.contains(&p.phase1_lifetime) || !(phase2_off || lifetimes.contains(&p.phase2_lifetime)) {
                anyhow::bail!("key lifetimes must be between {MIN_LIFETIME} and {MAX_LIFETIME} seconds");
            }
            if p.phase2_lifetime_kb.is_some_and(|kb| kb < MIN_LIFETIME_KB) {
                anyhow::bail!("the phase 2 key lifetime must be at least {MIN_LIFETIME_KB} kilobytes");
            }
            if p.gateway_auth == GatewayAuth::Certificate && p.ike_version != 2 {
                anyhow::bail!("gateway certificates need IKEv2");
            }
            if let Some(certificate) = &p.client_certificate {
                if p.ike_version != 2 {
                    anyhow::bail!("client certificates need IKEv2");
                }
                if p.username.is_some() {
                    anyhow::bail!("a client certificate replaces EAP: remove the username");
                }
                if !is_sha256_hex(certificate) {
                    anyhow::bail!("client_certificate must be the certificate's SHA-256");
                }
            }
            let legacy = p.legacy_in_use();
            if !p.legacy_algorithms && !legacy.is_empty() {
                anyhow::bail!(
                    "{} only work with legacy algorithms allowed (legacy_algorithms = true)",
                    legacy.join(" and ")
                );
            }
        }
        if let ProtocolConfig::OpenVpn(p) = &self.protocol {
            p.validate()?;
        }
        if let ProtocolConfig::L2tp(p) = &self.protocol {
            p.validate()?;
        }
        if let ProtocolConfig::WireGuard(p) = &self.protocol {
            p.validate()?;
        }
        if let Some(folder) = &self.folder
            && !valid_folder(folder)
        {
            anyhow::bail!("folders are up to {MAX_FOLDER_DEPTH} names of at most 64 characters, separated by '/'");
        }
        if self.via.len() > MAX_VIA {
            anyhow::bail!("a VPN can be chained through at most {MAX_VIA} others");
        }
        for (i, parent) in self.via.iter().enumerate() {
            if !valid_id(parent) || *parent == self.id || self.via[..i].contains(parent) {
                anyhow::bail!("invalid VPN to chain through: {parent:?}");
            }
        }
        if self.split_routes.len() > MAX_SPLIT_ROUTES {
            anyhow::bail!("split mode takes at most {MAX_SPLIT_ROUTES} networks");
        }
        if self.split_routes.iter().any(|net| net.prefix_len() == 0) {
            anyhow::bail!("split mode is for some networks: 0.0.0.0/0 would take all traffic");
        }
        if self.description.as_ref().is_some_and(|d| d.chars().count() > 256 || d.chars().any(char::is_control)) {
            anyhow::bail!("the description must be one line of at most 256 characters");
        }
        Ok(())
    }
}

impl Profile {
    /// This profile as connected in split mode: `split_routes` replace the
    /// gateway's routes, and the tunnel never takes all traffic.
    pub fn in_split_mode(mut self) -> anyhow::Result<Self> {
        if self.split_routes.is_empty() {
            anyhow::bail!("{} has no networks for split mode (split_routes)", self.name);
        }
        self.routes = Some(self.split_routes.clone());
        self.full_tunnel = Some(false);
        Ok(self)
    }
}

/// Certificate fingerprints: SHA-256 in hexadecimal, with or without
/// colons.
fn check_pins(pins: &[String]) -> anyhow::Result<()> {
    if let Some(pin) = pins.iter().find(|pin| !is_sha256_hex(&pin.replace(':', ""))) {
        anyhow::bail!("trusted_cert {pin:?} is not a SHA-256 fingerprint (64 hexadecimal digits)");
    }
    Ok(())
}

pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The user's `profiles.toml`: a list of `[[profile]]` tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileFile {
    #[serde(default, rename = "profile")]
    pub profiles: Vec<Profile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssl(host: &str, auth: FortiSslAuth) -> Profile {
        let mut p: Profile = toml::from_str(&format!(
            "name = \"t\"\nprotocol = \"forti-ssl\"\nhost = \"{}\"\nclient_key_pem = \"SECRET-KEY\"",
            host.escape_default()
        ))
        .unwrap();
        if let ProtocolConfig::FortiSsl(s) = &mut p.protocol {
            s.auth = auth;
        }
        p
    }

    #[test]
    fn validation_rejects_hostile_addresses() {
        assert!(ssl("vpn.example.com", FortiSslAuth::Password).validate().is_ok());
        assert!(ssl("192.0.2.1", FortiSslAuth::Password).validate().is_ok());
        for bad in ["evil.example/phish?", "user@host", "a b", "", "host#x"] {
            assert!(ssl(bad, FortiSslAuth::Password).validate().is_err(), "{bad:?}");
        }
        assert!(ssl("vpn.example.com", FortiSslAuth::Saml { port: 80 }).validate().is_err());
        assert!(ssl("vpn.example.com", FortiSslAuth::Saml { port: 8020 }).validate().is_ok());
    }

    #[test]
    fn ids_and_names() {
        let id = new_id();
        assert!(valid_id(&id), "{id}");
        assert_eq!(&id[14..15], "4", "version 4");
        assert_ne!(id, new_id());
        assert!(!valid_id("6F9619FF-8B86-D011-B42D-00C04FC964FF"), "lower case only");
        assert!(!valid_id("../../etc/passwd"));
        for good in ["ACME EU", "Prod (Paris)", "équipe-réseau", "a"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in
            ["", " lead", "trail ", "a/b", "tab\there", &"x".repeat(65), "evil\u{202e}gnp.exe", "zero\u{200b}width"]
        {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn folders() {
        for good in ["Clients", "Clients/Acme", "a/b/c/d", "Équipe réseau"] {
            assert!(valid_folder(good), "{good}");
        }
        for bad in ["", "/Clients", "Clients/", "a//b", " a", "a/b/c/d/e", "a\nb"] {
            assert!(!valid_folder(bad), "{bad:?}");
        }
    }

    #[test]
    fn legacy_algorithms_need_the_option() {
        let base = "name = \"old\"\nprotocol = \"ipsec\"\ngateway = \"192.0.2.1\"\n";
        let with = |extra: &str| toml::from_str::<Profile>(&format!("{base}{extra}")).unwrap().validate();
        assert!(with("ike = [\"aes128-sha1-modp1536\"]").is_ok());
        let err = with("ike = [\"3DES-sha1-modp1024\"]").unwrap_err().to_string();
        assert!(err.contains("3des and modp1024"), "{err}");
        assert!(with("esp = [\"3des-sha1\"]").is_err());
        assert!(with("ike = [\"3des-sha1-modp1024\"]\nlegacy_algorithms = true").is_ok());
    }

    #[test]
    fn client_certificates() {
        let base = "name = \"c\"\nprotocol = \"ipsec\"\ngateway = \"192.0.2.1\"\n";
        let with = |extra: &str| toml::from_str::<Profile>(&format!("{base}{extra}")).unwrap().validate();
        let sha = format!("client_certificate = \"{}\"\n", "ab".repeat(32));
        assert!(with(&sha).is_ok());
        assert!(with(&format!("{sha}ike_version = 1")).is_err(), "IKEv2 only");
        assert!(with(&format!("{sha}username = \"alice\"")).is_err(), "no EAP on top");
        assert!(with("client_certificate = \"alice\"").is_err(), "a fingerprint");

        let base = "name = \"s\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n";
        let with = |extra: &str| toml::from_str::<Profile>(&format!("{base}{extra}")).unwrap().validate();
        assert!(with(&sha).is_ok());
        assert!(with(&format!("{sha}client_cert = \"/c.pem\"")).is_err(), "Keychain or files");
        assert!(with("client_certificate = \"alice\"").is_err(), "a fingerprint");
    }

    #[test]
    fn typos_are_refused_before_connecting() {
        let ipsec = "name = \"c\"\nprotocol = \"ipsec\"\ngateway = \"192.0.2.1\"\n";
        let with = |base: &str, extra: &str| toml::from_str::<Profile>(&format!("{base}{extra}")).unwrap().validate();
        assert!(with(ipsec, "ike_version = 1").is_ok());
        assert!(with(ipsec, "ike_version = 3").is_err());
        let pin = "ab".repeat(32);
        let colons = pin.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":");
        let ssl = "name = \"s\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n";
        for base in [ipsec, ssl] {
            assert!(with(base, &format!("trusted_cert = [\"{pin}\", \"{colons}\"]")).is_ok());
            assert!(with(base, "trusted_cert = [\"ab12\"]").is_err(), "{base}");
        }
    }

    #[test]
    fn descriptions_count_characters() {
        let mut p = ssl("vpn.example.com", FortiSslAuth::Password);
        p.description = Some("é".repeat(256));
        assert!(p.validate().is_ok());
        p.description = Some("é".repeat(257));
        assert!(p.validate().is_err());
    }

    #[test]
    fn debug_output_hides_the_client_key() {
        let text = format!("{:?}", ssl("vpn.example.com", FortiSslAuth::Password));
        assert!(!text.contains("SECRET-KEY"), "{text}");
        assert!(text.contains("vpn.example.com"));
    }

    #[test]
    fn split_mode() {
        let mut p = ssl("vpn.example.com", FortiSslAuth::Password);
        p.full_tunnel = Some(true);
        let err = p.clone().in_split_mode().unwrap_err();
        assert!(err.to_string().contains("no networks for split mode"), "{err}");
        p.split_routes = vec!["10.1.0.0/16".parse().unwrap()];
        p.exclusive = true;
        let split = p.clone().in_split_mode().unwrap();
        assert_eq!(split.routes, Some(p.split_routes.clone()));
        assert_eq!(split.full_tunnel, Some(false));
        assert!(split.exclusive, "a company VPN still runs alone");
        assert!(split.validate().is_ok());

        p.split_routes.push("0.0.0.0/0".parse().unwrap());
        assert!(p.validate().is_err(), "0.0.0.0/0 is not a split");
        p.split_routes =
            (0..=MAX_SPLIT_ROUTES as u32).map(|i| Ipv4Net::new((0x0a00_0000 + (i << 8)).into(), 24).unwrap()).collect();
        assert!(p.validate().is_err());

        let file: ProfileFile = toml::from_str(
            "[[profile]]\nname = \"t\"\nprotocol = \"forti-ssl\"\nhost = \"h.example\"\nsplit_routes = [\"10.2.0.0/16\"]",
        )
        .unwrap();
        assert_eq!(file.profiles[0].split_routes, vec!["10.2.0.0/16".parse::<Ipv4Net>().unwrap()]);
        let written =
            toml::to_string(&ProfileFile { profiles: vec![ssl("h.example", FortiSslAuth::Password)] }).unwrap();
        assert!(!written.contains("split_routes"), "left out when empty");
    }

    #[test]
    fn parses_profiles_toml() {
        let text = r#"
            [[profile]]
            name = "paris"
            protocol = "forti-ssl"
            host = "vpn.example.com"
            username = "alice"
            trusted_cert = ["ab12"]
            dns_domains = ["corp.example"]

            [[profile]]
            name = "lab"
            protocol = "forti-ssl"
            host = "lab.example.com"
            port = 10443
            auth = { method = "saml" }

            [[profile]]
            name = "branch"
            protocol = "ipsec"
            gateway = "203.0.113.10"
            username = "bob"
            routes = ["10.50.0.0/16"]
        "#;
        let file: ProfileFile = toml::from_str(text).unwrap();
        assert_eq!(file.profiles.len(), 3);
        match &file.profiles[1].protocol {
            ProtocolConfig::FortiSsl(p) => {
                assert_eq!(p.port, 10443);
                assert!(matches!(p.auth, FortiSslAuth::Saml { port: 8020 }));
            }
            other => panic!("unexpected {other:?}"),
        }
        match &file.profiles[2].protocol {
            ProtocolConfig::Ipsec(p) => assert_eq!(p.port, 500),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(file.profiles[2].routes.as_ref().unwrap().len(), 1);
    }
}
