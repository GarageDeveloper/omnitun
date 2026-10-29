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
            // The recipient does not have the file: its CA goes inline.
            if let Some(path) = p.ca_file.take() {
                p.ca_pem = Some(std::fs::read_to_string(&path).with_context(|| format!("cannot read {path}"))?);
            }
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
    let body = crate::profiles::to_toml(&ProfileFile { profiles: vec![shared] })?;
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

/// What a received profile makes this client trust, to show before adding
/// it: its certificate authorities, pinned certificates and, for OpenVPN,
/// the name the server must carry and its shared key.
pub fn trust_summary(profile: &Profile) -> Vec<String> {
    let (ca_pem, pins) = match &profile.protocol {
        ProtocolConfig::FortiSsl(p) => (p.ca_pem.as_deref(), p.trusted_cert.as_slice()),
        ProtocolConfig::Ipsec(p) => (p.ca_pem.as_deref(), p.trusted_cert.as_slice()),
        ProtocolConfig::OpenVpn(p) => (p.ca_pem.as_deref(), p.trusted_cert.as_slice()),
        ProtocolConfig::L2tp(_) | ProtocolConfig::WireGuard(_) => (None, &[][..]),
    };
    let mut lines = Vec::new();
    if let Some(pem) = ca_pem {
        lines.extend(authorities(pem));
    }
    lines.extend(pins.iter().map(|pin| format!("trusted certificate SHA-256: {pin}")));
    if let ProtocolConfig::OpenVpn(p) = &profile.protocol {
        if let Some(check) = &p.verify_x509_name {
            lines.push(format!("the server certificate must name {}", crate::printable(&check.name)));
        }
        if p.static_key.is_some() {
            lines.push("carries the server's shared key (tls-auth or tls-crypt)".to_owned());
        }
    }
    lines
}

/// One line per certificate of `pem`: its name and SHA-256.
fn authorities(pem: &str) -> Vec<String> {
    use sha2::Digest;
    use x509_parser::prelude::{FromDer, X509Certificate};
    let mut lines = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()) {
        let Ok(block) = block else {
            lines.push("certificate authority: unreadable PEM".to_owned());
            break;
        };
        let name = X509Certificate::from_der(&block.contents)
            .map(|(_, c)| c.subject().to_string())
            .unwrap_or_else(|_| "unreadable certificate".to_owned());
        let sha256 = hex::encode(sha2::Sha256::digest(&block.contents));
        lines.push(format!("certificate authority: {} (SHA-256 {sha256})", crate::printable(&name)));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(text: &str) -> Profile {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn export_keeps_no_secret_or_personal_field() {
        let pin = "ab".repeat(32);
        let p = profile(&format!(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nusername = \"alice\"\n\
             client_key_pem = \"KEY\"\nclient_cert = \"/Users/alice/cert.pem\"\ntrusted_cert = [\"{pin}\"]"
        ));
        let text = export(&p).unwrap();
        for leaked in ["alice", "KEY", "cert.pem"] {
            assert!(!text.contains(leaked), "{leaked} in\n{text}");
        }
        let back = parse(&text).unwrap();
        let ProtocolConfig::FortiSsl(s) = &back.protocol else { panic!() };
        assert_eq!(
            (back.name.as_str(), s.host.as_str(), s.trusted_cert.as_slice()),
            ("paris", "vpn.example.com", std::slice::from_ref(&pin))
        );
    }

    #[test]
    fn export_inlines_the_ca_file() {
        let dir = std::env::temp_dir().join(format!("vpn-client-export-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n").unwrap();
        let p = profile(&format!(
            "name = \"paris\"\nprotocol = \"forti-ssl\"\nhost = \"vpn.example.com\"\nca_file = \"{}\"",
            ca.display()
        ));
        let back = parse(&export(&p).unwrap()).unwrap();
        let ProtocolConfig::FortiSsl(s) = &back.protocol else { panic!() };
        assert!(s.ca_pem.as_deref().is_some_and(|pem| pem.contains("\nCA\n")), "{s:?}");
        std::fs::remove_file(&ca).unwrap();
        assert!(export(&p).is_err(), "a missing CA is not dropped silently");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn what_a_received_profile_trusts_is_shown() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Acme CA");
        let ca = params.self_signed(&key).unwrap();
        let pin = "ab".repeat(32);
        let p = profile(&format!(
            "name = \"x\"\nprotocol = \"openvpn\"\nremotes = [{{ host = \"vpn.example.com\" }}]\n\
             ca_pem = \"\"\"{}\"\"\"\ntrusted_cert = [\"{pin}\"]\nstatic_key = \"K\"\n\
             verify_x509_name = {{ name = \"vpn.example.com\" }}",
            ca.pem()
        ));
        let lines = trust_summary(&p);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].starts_with("certificate authority: CN=Acme CA (SHA-256 "), "{lines:?}");
        let sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(ca.der()));
        assert!(lines[0].ends_with(&format!("{sha256})")), "{lines:?}");
        assert_eq!(lines[1], format!("trusted certificate SHA-256: {pin}"));
        assert!(lines[2].contains("vpn.example.com") && lines[3].contains("shared key"), "{lines:?}");
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
