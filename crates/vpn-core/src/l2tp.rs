//! L2TP over IPsec profiles (RFC 3193): IKEv1 with a pre-shared key and an
//! ESP SA in transport mode for UDP port 1701, then L2TP (RFC 2661)
//! carrying PPP, which authenticates the user and assigns the address.
//! The "L2TP over IPsec" of macOS and Windows, Meraki Client VPN.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{ExchangeMode, GatewayAuth, IpsecProfile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2tpProfile {
    pub gateway: String,
    /// IKE port.
    #[serde(default = "default_ike_port")]
    pub port: u16,
    /// PPP user name; asked when unset.
    #[serde(default)]
    pub username: Option<String>,
    /// IKE identity (a group name); our address when unset. With one,
    /// phase 1 uses aggressive mode, as macOS does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// IKE proposals, as for IPsec profiles.
    #[serde(default = "default_ike")]
    pub ike: Vec<String>,
    #[serde(default = "default_esp")]
    pub esp: Vec<String>,
    /// Allows 3DES and DH group 2, which many L2TP servers still use.
    #[serde(default)]
    pub legacy_algorithms: bool,
    #[serde(default = "default_phase1_lifetime")]
    pub phase1_lifetime: u32,
    #[serde(default = "default_phase2_lifetime")]
    pub phase2_lifetime: u32,
    #[serde(default = "yes")]
    pub dpd: bool,
    /// PPP authentications accepted, in the order we prefer them. PAP only
    /// when asked for: it does not authenticate the server.
    #[serde(default = "default_ppp_auth")]
    pub ppp_auth: Vec<PppAuth>,
    /// DNS servers used when the server assigns none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PppAuth {
    /// The password in clear, inside the IPsec SA (Meraki). The server
    /// proves nothing: anyone with the pre-shared key could pose as it.
    Pap,
    /// CHAP with MD5.
    Chap,
    MsChapV2,
}

/// The L2TP port, both sides.
pub const L2TP_PORT: u16 = 1701;

impl L2tpProfile {
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        ensure!(!self.ppp_auth.is_empty(), "at least one PPP authentication is needed");
        ensure!(self.dns_servers.len() <= 4, "at most 4 DNS servers");
        // The IPsec part follows the IPsec rules.
        let ipsec = crate::Profile {
            id: String::new(),
            name: "l2tp".into(),
            description: None,
            folder: None,
            save_password: true,
            protocol: crate::ProtocolConfig::Ipsec(self.ipsec()),
            routes: None,
            full_tunnel: None,
            split_routes: Vec::new(),
            dns_domains: Vec::new(),
            allow_route_overlap: false,
            via: Vec::new(),
            exclusive: false,
        };
        ipsec.validate()
    }

    /// The IPsec side: IKEv1, PSK, no XAuth nor Mode-Config.
    pub fn ipsec(&self) -> IpsecProfile {
        IpsecProfile {
            gateway: self.gateway.clone(),
            port: self.port,
            ike_version: 1,
            exchange_mode: if self.local_id.is_some() { ExchangeMode::Aggressive } else { ExchangeMode::Main },
            xauth: false,
            // macOS sends the group name as a KEY_ID identity.
            local_id: self.local_id.as_ref().map(|group| {
                let typed = ["ip:", "fqdn:", "email:", "keyid:"].iter().any(|p| group.starts_with(p));
                if typed { group.clone() } else { format!("keyid:{group}") }
            }),
            remote_id: self.remote_id.clone(),
            username: None,
            ike: self.ike.clone(),
            esp: self.esp.clone(),
            phase1_lifetime: self.phase1_lifetime,
            phase2_lifetime: self.phase2_lifetime,
            phase2_lifetime_kb: None,
            dpd: self.dpd,
            legacy_algorithms: self.legacy_algorithms,
            gateway_auth: GatewayAuth::Psk,
            ca_pem: None,
            trusted_cert: Vec::new(),
            keychain_ca_pem: None,
            client_certificate: None,
            client_chain_pem: None,
        }
    }
}

fn yes() -> bool {
    true
}

fn default_ike_port() -> u16 {
    500
}

/// What macOS offers, without the legacy algorithms.
fn default_ike() -> Vec<String> {
    [
        "aes256-sha256-modp2048",
        "aes256-sha1-modp2048",
        "aes128-sha1-modp2048",
        "aes256-sha1-modp1536",
        "aes128-sha1-modp1536",
    ]
    .map(String::from)
    .to_vec()
}

fn default_esp() -> Vec<String> {
    ["aes256-sha256", "aes256-sha1", "aes128-sha1"].map(String::from).to_vec()
}

/// Common L2TP server values (Windows, macOS, Meraki).
fn default_phase1_lifetime() -> u32 {
    28_800
}

fn default_phase2_lifetime() -> u32 {
    3_600
}

fn default_ppp_auth() -> Vec<PppAuth> {
    vec![PppAuth::MsChapV2, PppAuth::Chap]
}

#[cfg(test)]
mod tests {
    use crate::{Profile, ProtocolConfig};

    #[test]
    fn profiles() {
        let base = "name = \"meraki\"\nprotocol = \"l2tp\"\ngateway = \"vpn.example.com\"\n";
        let parse = |extra: &str| toml::from_str::<Profile>(&format!("{base}{extra}")).unwrap();
        let p = parse("");
        p.validate().unwrap();
        let ProtocolConfig::L2tp(l) = &p.protocol else { panic!() };
        assert_eq!(l.ppp_auth, [crate::PppAuth::MsChapV2, crate::PppAuth::Chap], "no PAP unless asked");
        assert_eq!(l.ipsec().exchange_mode, crate::ExchangeMode::Main);
        assert!(parse("ike = [\"3des-sha1-modp1024\"]").validate().is_err(), "legacy needs the option");
        parse("ike = [\"3des-sha1-modp1024\"]\nlegacy_algorithms = true").validate().unwrap();
        assert!(parse("ppp_auth = []").validate().is_err());
        let grouped = parse("ppp_auth = [\"pap\"]\nlocal_id = \"group.example\"");
        assert_eq!(grouped.protocol.endpoint(), ("vpn.example.com", 500));
        let ProtocolConfig::L2tp(l) = &grouped.protocol else { panic!() };
        assert_eq!(l.ipsec().local_id.as_deref(), Some("keyid:group.example"));
    }
}
