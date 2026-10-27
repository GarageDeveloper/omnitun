//! `.vpnprofile` files: one profile, as an IT department hands it out.
//!
//! Export keeps a whitelist of fields: never a secret, a key, a client
//! certificate or a user name. Import treats the file as untrusted: one
//! profile, no file paths, no inlined client certificate or key, validated
//! like any profile; the caller shows the server and the certificate
//! fingerprints before adding it.

use anyhow::{Context, bail};
use vpn_core::{Profile, ProfileFile, ProtocolConfig};

/// Largest file accepted.
pub const MAX_SIZE: usize = 256 * 1024;

/// The profile as a `.vpnprofile` file.
pub fn export(profile: &Profile) -> anyhow::Result<String> {
    let mut shared = profile.clone();
    // The recipient's copy is a VPN of their own: new id, their folders,
    // none of our VPNs to go through.
    shared.id = String::new();
    shared.folder = None;
    shared.via = Vec::new();
    match &mut shared.protocol {
        ProtocolConfig::FortiSsl(p) => {
            p.username = None;
            p.ca_file = None;
            p.client_cert = None;
            p.client_key = None;
            p.client_cert_pem = None;
            p.client_key_pem = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
        ProtocolConfig::Ipsec(p) => {
            p.username = None;
            p.local_id = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
        // The CA and the static key stay: every user of the server needs
        // them, as in a shared .ovpn file.
        ProtocolConfig::L2tp(p) => {
            p.username = None;
            p.local_id = None;
        }
        // Each device has its own key pair and address, declared on the
        // server: a copy would be another device's identity.
        ProtocolConfig::WireGuard(_) => {
            bail!("a WireGuard profile belongs to one device: ask the server's administrator for a configuration")
        }
        ProtocolConfig::OpenVpn(p) => {
            p.username = None;
            p.client_cert_pem = None;
            p.client_key_pem = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
    }
    if let Some(field) = shared.protocol.keychain_ca_pem() {
        *field = None;
    }
    let body = toml::to_string(&ProfileFile { profiles: vec![shared] })?;
    Ok(format!(
        "# {} VPN profile \"{}\". It holds no password, private key or user name.\n{body}",
        vpn_core::brand::PRODUCT,
        profile.name
    ))
}

/// Reads a `.vpnprofile` file received from someone else.
pub fn parse(text: &str) -> anyhow::Result<Profile> {
    if text.len() > MAX_SIZE {
        bail!("the file is too large for a VPN profile");
    }
    let file: ProfileFile = toml::from_str(text).context("this is not a valid VPN profile")?;
    let [profile] = <[Profile; 1]>::try_from(file.profiles)
        .map_err(|_| anyhow::anyhow!("the file must hold exactly one profile"))?;
    if let ProtocolConfig::FortiSsl(p) = &profile.protocol {
        // A received file must not make the client read local files, nor
        // install someone else's credentials.
        if p.has_file_paths() {
            bail!("the profile refers to local files (ca_file, client_cert, client_key)");
        }
        if p.client_cert_pem.is_some() || p.client_key_pem.is_some() {
            bail!("the profile carries a client certificate or key");
        }
    }
    if let ProtocolConfig::OpenVpn(p) = &profile.protocol
        && (p.client_cert_pem.is_some() || p.client_key_pem.is_some())
    {
        bail!("the profile carries a client certificate or key");
    }
    if matches!(profile.protocol, ProtocolConfig::WireGuard(_)) {
        bail!("WireGuard VPNs are added from their configuration file (.conf), which carries the device's key");
    }
    let mut profile = profile;
    profile.id = String::new();
    profile.via = Vec::new();
    // Whoever sent the file decides neither what this VPN may cut into,
    // nor which of the recipient's identities it presents.
    profile.allow_route_overlap = false;
    match &mut profile.protocol {
        ProtocolConfig::FortiSsl(p) => {
            p.username = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
        ProtocolConfig::Ipsec(p) => {
            p.username = None;
            p.local_id = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
        ProtocolConfig::L2tp(p) => {
            p.username = None;
            p.local_id = None;
        }
        ProtocolConfig::OpenVpn(p) => {
            p.username = None;
            p.client_certificate = None;
            p.client_chain_pem = None;
        }
        ProtocolConfig::WireGuard(_) => {}
    }
    if let Some(field) = profile.protocol.keychain_ca_pem() {
        *field = None;
    }
    profile.validate()?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(text: &str) -> Profile {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn export_keeps_no_secret_or_personal_field() {
        let p = profile(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nusername = \"alice\"\n\
             client_key_pem = \"KEY\"\nclient_cert = \"/Users/alice/cert.pem\"\ntrusted_cert = [\"ab\"]",
        );
        let text = export(&p).unwrap();
        for leaked in ["alice", "KEY", "cert.pem"] {
            assert!(!text.contains(leaked), "{leaked} in\n{text}");
        }
        let back = parse(&text).unwrap();
        let ProtocolConfig::FortiSsl(s) = &back.protocol else { panic!() };
        assert_eq!(
            (back.name.as_str(), s.host.as_str(), s.trusted_cert.as_slice()),
            ("paris", "vpn.example.com", &["ab".to_string()][..])
        );
    }

    #[test]
    fn received_files_are_untrusted() {
        let one = "[[profile]]\nname = \"x\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\n";
        assert!(parse(one).is_ok());
        assert!(parse(&format!("{one}{one}")).is_err(), "two profiles");
        assert!(parse("").is_err(), "none");
        assert!(parse(&format!("{one}ca_file = \"/etc/master.passwd\"\n")).is_err(), "a local file");
        assert!(parse(&format!("{one}client_key_pem = \"K\"\n")).is_err(), "someone's key");
        assert!(parse(&one.replace("vpn.example.com", "evil.example/x?")).is_err(), "a hostile host");
        assert!(parse(&one.replace("\"x\"", "\"../x\"")).is_err(), "a hostile name");
        assert!(parse(&"#".repeat(MAX_SIZE + 1)).is_err(), "too large");
        let p = parse(&format!(
            "{one}allow_route_overlap = true\nusername = \"alice\"\nclient_certificate = \"{}\"\n",
            "ab".repeat(32)
        ))
        .unwrap();
        let ProtocolConfig::FortiSsl(s) = &p.protocol else { panic!() };
        assert!(!p.allow_route_overlap && s.username.is_none() && s.client_certificate.is_none(), "{p:?}");
    }
}
