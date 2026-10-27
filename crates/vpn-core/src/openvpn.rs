//! OpenVPN profiles: what a client `.ovpn` configuration says, in the
//! subset this client implements (TLS mode, `dev tun`, pulled options).

use serde::{Deserialize, Serialize};

/// Data channel ciphers this client negotiates (`data-ciphers`).
pub const OPENVPN_CIPHERS: [&str; 3] = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];

/// HMAC digests accepted for `tls-auth` (`auth`).
pub const OPENVPN_DIGESTS: [&str; 4] = ["SHA1", "SHA256", "SHA384", "SHA512"];

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenVpnProfile {
    /// Servers, tried in order (`remote`).
    pub remotes: Vec<OpenVpnRemote>,
    /// The server asks for a user name and password (`auth-user-pass`).
    #[serde(default)]
    pub auth_user_pass: bool,
    #[serde(default)]
    pub username: Option<String>,
    /// A one-time code asked with the password (`static-challenge`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_challenge: Option<StaticChallenge>,
    /// The CA that issued the server's certificate (`ca`, PEM). Only this
    /// CA is trusted: OpenVPN servers use private CAs and their
    /// certificates do not name the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// SHA-256 fingerprints of accepted server certificates
    /// (`peer-fingerprint`): when set, the CA is not used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_cert: Vec<String>,
    /// The server certificate must be meant for a server
    /// (`remote-cert-tls server`): without it, any client of the same CA
    /// could pose as the server.
    #[serde(default = "yes")]
    pub remote_cert_tls: bool,
    /// Name the server certificate must carry (`verify-x509-name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_x509_name: Option<X509NameCheck>,
    /// Client certificate chain and key (`cert`, `key`, PEM). The client
    /// keeps the key: it signs for the engine and never sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_pem: Option<String>,
    /// Or a Keychain certificate, by SHA-256 (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// That certificate's chain (PEM), added by the client at each
    /// connection, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_chain_pem: Option<String>,
    /// Protection of the control channel by a key every client shares.
    #[serde(default)]
    pub control_channel: ControlChannel,
    /// The static key of `tls-auth` or `tls-crypt` (`OpenVPN Static key
    /// V1` text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_key: Option<String>,
    /// `key-direction` of `tls-auth` (0 or 1); none: both directions use
    /// the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_direction: Option<u8>,
    /// HMAC digest of `tls-auth` (`auth`).
    #[serde(default = "default_digest")]
    pub auth_digest: String,
    /// Data channel ciphers offered, preferred first (`data-ciphers`).
    #[serde(default = "default_ciphers")]
    pub data_ciphers: Vec<String>,
    /// Compression framing the server expects; packets are never
    /// compressed (VORACLE).
    #[serde(default)]
    pub compression: Compression,
    /// Renegotiate the data channel keys this often (`reneg-sec`), 0 for
    /// never (the server may still do it).
    #[serde(default = "default_reneg")]
    pub reneg_sec: u32,
    /// Networks routed through the tunnel besides those the server pushes
    /// (`route` lines of the configuration).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_routes: Vec<ipnet::Ipv4Net>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVpnRemote {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub transport: Transport,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticChallenge {
    pub text: String,
    /// Show the answer while it is typed.
    #[serde(default)]
    pub echo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509NameCheck {
    pub name: String,
    #[serde(default)]
    pub kind: X509NameKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum X509NameKind {
    /// The whole subject, as OpenVPN prints it (`C=FR, CN=vpn`).
    #[default]
    Subject,
    /// The common name.
    Name,
    /// The start of the common name.
    NamePrefix,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlChannel {
    #[default]
    None,
    /// `tls-auth`: control packets carry an HMAC.
    TlsAuth,
    /// `tls-crypt`: control packets are encrypted and authenticated.
    TlsCrypt,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    #[default]
    None,
    /// `comp-lzo`: a header byte before each packet.
    Lzo,
    /// `compress`, `compress stub` or `compress lz4`: a header byte
    /// swapped with the packet's last byte.
    Stub,
    /// `compress stub-v2` or `compress lz4-v2`.
    StubV2,
}

/// The client certificate's key is never written to logs, nor the static
/// key.
impl std::fmt::Debug for OpenVpnProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnProfile")
            .field("remotes", &self.remotes)
            .field("auth_user_pass", &self.auth_user_pass)
            .field("username", &self.username)
            .field("static_challenge", &self.static_challenge)
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "…"))
            .field("trusted_cert", &self.trusted_cert)
            .field("remote_cert_tls", &self.remote_cert_tls)
            .field("verify_x509_name", &self.verify_x509_name)
            .field("client_cert_pem", &self.client_cert_pem.as_ref().map(|_| "…"))
            .field("client_key_pem", &self.client_key_pem.as_ref().map(|_| "<redacted>"))
            .field("client_certificate", &self.client_certificate)
            .field("client_chain_pem", &self.client_chain_pem.as_ref().map(|_| "…"))
            .field("control_channel", &self.control_channel)
            .field("static_key", &self.static_key.as_ref().map(|_| "<redacted>"))
            .field("key_direction", &self.key_direction)
            .field("auth_digest", &self.auth_digest)
            .field("data_ciphers", &self.data_ciphers)
            .field("compression", &self.compression)
            .field("reneg_sec", &self.reneg_sec)
            .field("extra_routes", &self.extra_routes)
            .finish()
    }
}

/// Most servers a profile may list.
pub const MAX_REMOTES: usize = 16;
/// Most additional networks.
pub const MAX_EXTRA_ROUTES: usize = 64;

impl OpenVpnProfile {
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::{bail, ensure};
        ensure!(!self.remotes.is_empty(), "an OpenVPN profile needs a server (remote)");
        ensure!(self.remotes.len() <= MAX_REMOTES, "at most {MAX_REMOTES} servers");
        for remote in &self.remotes {
            ensure!(crate::profile::valid_host(&remote.host), "invalid server address {:?}", remote.host);
            ensure!(remote.port != 0, "invalid server port 0");
        }
        if self.trusted_cert.is_empty() {
            ensure!(self.ca_pem.is_some(), "the server's CA (ca) or fingerprint (peer-fingerprint) is needed");
        }
        for pin in &self.trusted_cert {
            ensure!(crate::profile::is_sha256_hex(&pin.replace(':', "")), "peer fingerprints must be SHA-256");
        }
        if let Some(check) = &self.verify_x509_name {
            ensure!(!check.name.is_empty() && !check.name.chars().any(char::is_control), "invalid verify-x509-name");
        }
        if let Some(sha256) = &self.client_certificate {
            ensure!(crate::profile::is_sha256_hex(sha256), "client_certificate must be the certificate's SHA-256");
            ensure!(self.client_cert_pem.is_none(), "client_certificate (Keychain) replaces cert and key");
        }
        ensure!(
            self.auth_user_pass || self.client_certificate.is_some() || self.client_cert_pem.is_some(),
            "the profile needs a client certificate or a user name and password (auth-user-pass)"
        );
        match (self.control_channel, &self.static_key) {
            (ControlChannel::None, _) => {}
            (_, None) => bail!("tls-auth and tls-crypt need their static key"),
            (_, Some(key)) => {
                parse_static_key(key)?;
            }
        }
        ensure!(self.key_direction.is_none_or(|d| d <= 1), "key-direction must be 0 or 1");
        ensure!(
            OPENVPN_DIGESTS.iter().any(|d| d.eq_ignore_ascii_case(&self.auth_digest)),
            "unsupported digest {:?} (auth): use {}",
            self.auth_digest,
            OPENVPN_DIGESTS.join(", ")
        );
        ensure!(!self.data_ciphers.is_empty(), "at least one data cipher is needed");
        for cipher in &self.data_ciphers {
            ensure!(
                OPENVPN_CIPHERS.iter().any(|c| c.eq_ignore_ascii_case(cipher)),
                "unsupported data cipher {cipher:?}: use {}",
                OPENVPN_CIPHERS.join(", ")
            );
        }
        ensure!(self.reneg_sec == 0 || self.reneg_sec >= 60, "reneg-sec must be 0 or at least 60 seconds");
        ensure!(self.extra_routes.len() <= MAX_EXTRA_ROUTES, "at most {MAX_EXTRA_ROUTES} additional networks");
        ensure!(
            self.extra_routes.iter().all(|r| r.prefix_len() > 0),
            "an additional network cannot be the default route: choose a full tunnel instead"
        );
        if let Some(challenge) = &self.static_challenge {
            ensure!(self.auth_user_pass, "static-challenge needs auth-user-pass");
            ensure!(challenge.text.len() <= 256, "the static challenge text is too long");
        }
        Ok(())
    }
}

/// The 256 bytes of an `OpenVPN Static key V1` file: two keys of 64 cipher
/// then 64 HMAC bytes.
pub fn parse_static_key(text: &str) -> anyhow::Result<[u8; 256]> {
    use anyhow::Context;
    let body = text
        .split_once("-----BEGIN OpenVPN Static key V1-----")
        .and_then(|(_, rest)| rest.split_once("-----END OpenVPN Static key V1-----"))
        .map(|(body, _)| body)
        .context("not an OpenVPN static key (-----BEGIN OpenVPN Static key V1-----)")?;
    let hex: String =
        body.lines().filter(|l| !l.trim_start().starts_with('#')).flat_map(|l| l.trim().chars()).collect();
    let bytes = hex::decode(hex).context("the OpenVPN static key is not hexadecimal")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("an OpenVPN static key holds 256 bytes"))
}

fn yes() -> bool {
    true
}

fn default_port() -> u16 {
    1194
}

fn default_digest() -> String {
    "SHA1".into()
}

fn default_ciphers() -> Vec<String> {
    OPENVPN_CIPHERS.iter().map(|c| c.to_string()).collect()
}

fn default_reneg() -> u32 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Profile, ProtocolConfig};

    pub const KEY: &str = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        -----END OpenVPN Static key V1-----\n";

    fn profile(extra: &str) -> anyhow::Result<()> {
        let text = format!(
            "name = \"o\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nca_pem = \"CA\"\n{extra}\n\
             [[remotes]]\nhost = \"vpn.example.com\"\n"
        );
        let profile: Profile = toml::from_str(&text)?;
        assert!(matches!(profile.protocol, ProtocolConfig::OpenVpn(_)));
        profile.validate()
    }

    #[test]
    fn validation() {
        profile("").unwrap();
        assert!(profile("data_ciphers = [\"BF-CBC\"]").is_err());
        assert!(profile("auth_digest = \"MD5\"").is_err());
        assert!(profile("control_channel = \"tls-crypt\"").is_err(), "no key");
        let key = format!("control_channel = \"tls-auth\"\nkey_direction = 1\nstatic_key = '''{KEY}'''");
        profile(&key).unwrap();
        assert!(profile("reneg_sec = 10").is_err());
        let text = "name = \"o\"\nprotocol = \"openvpn\"\nauth_user_pass = true\nremotes = []\nca_pem = \"CA\"";
        assert!(toml::from_str::<Profile>(text).unwrap().validate().is_err(), "no server");
    }

    #[test]
    fn static_keys() {
        let key = parse_static_key(KEY).unwrap();
        assert_eq!((key[0], key[255]), (0x00, 0xff));
        assert!(parse_static_key(&KEY.replace("ff\n-----END", "\n-----END")).is_err());
        assert!(parse_static_key("garbage").is_err());
    }
}
