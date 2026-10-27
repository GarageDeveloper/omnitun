//! Import of WireGuard client configurations, in the `wg-quick` format
//! (`[Interface]` and `[Peer]`). The private and pre-shared keys go to
//! the Keychain, not into the profile; scripts (`PostUp`…) are never run.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use ipnet::IpNet;
use vpn_core::wireguard::parse_key;
use vpn_core::{Profile, ProfileFile, ProtocolConfig, WIREGUARD_PORT, WireGuardProfile};
use zeroize::Zeroizing;

use super::Imported;
use super::ovpn::free_name;

/// Largest configuration read; real ones are a few hundred bytes.
const MAX_SIZE: u64 = 64 * 1024;

/// A configuration converted: the profile, and the secrets to store with it.
pub struct WireGuardImport {
    pub imported: Imported,
    pub private_key: Zeroizing<String>,
    pub preshared_key: Option<Zeroizing<String>>,
}

/// The file at `path` is a WireGuard configuration (and not an OpenVPN
/// one, which may also end in `.conf`).
pub fn is_wireguard(path: &Path) -> bool {
    read(path).is_ok_and(|text| text.lines().any(|l| l.trim().eq_ignore_ascii_case("[Interface]")))
}

/// Converts the configuration at `path` into a profile named after the
/// file, renamed if the name is among `existing`.
pub fn wireguard(path: &Path, existing: &[String]) -> anyhow::Result<WireGuardImport> {
    let text = read(path)?;
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    convert(&text, &super::name_or(&stem, "wireguard"), &file, existing)
}

fn read(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let size = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?.len();
    ensure!(size <= MAX_SIZE, "{} is too large for a WireGuard configuration", path.display());
    Ok(Zeroizing::new(std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?))
}

/// The public key that goes with `private_key` (base64), if it is one.
pub fn public_key(private_key: &str) -> Option<String> {
    use base64::Engine as _;
    let secret = x25519_dalek::StaticSecret::from(*Zeroizing::new(parse_key(private_key)?));
    let public = x25519_dalek::PublicKey::from(&secret);
    Some(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

/// A new private key (base64).
pub fn new_private_key() -> Zeroizing<String> {
    use base64::Engine as _;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(secret.to_bytes()))
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

fn convert(text: &str, base: &str, file: &str, existing: &[String]) -> anyhow::Result<WireGuardImport> {
    let mut notes = Vec::new();
    let mut private_key = None;
    let mut preshared_key = None;
    let mut profile = WireGuardProfile {
        endpoint: String::new(),
        port: WIREGUARD_PORT,
        public_key: String::new(),
        addresses: Vec::new(),
        allowed_ips: Vec::new(),
        preshared_key: false,
        persistent_keepalive: None,
        dns_servers: Vec::new(),
        dns_search: Vec::new(),
        mtu: None,
        local_public_key: None,
    };
    let mut section = Section::None;
    let mut peers = 0;
    let (mut ipv6, mut ignored) = (false, Vec::new());
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                _ => bail!("line {}: unknown section {line}", number + 1),
            };
            continue;
        }
        let (key, value) =
            line.split_once('=').with_context(|| format!("line {}: expected Key = Value", number + 1))?;
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        let list = || value.split(',').map(str::trim).filter(|v| !v.is_empty());
        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => {
                ensure!(parse_key(value).is_some(), "the private key must be 32 bytes in base64");
                private_key = Some(Zeroizing::new(value.to_owned()));
            }
            (Section::Interface, "address") => {
                for address in list() {
                    match parse_network(address)? {
                        IpNet::V4(net) => profile.addresses.push(net),
                        IpNet::V6(_) => ipv6 = true,
                    }
                }
            }
            (Section::Interface, "dns") => {
                for entry in list() {
                    match entry.parse::<IpAddr>() {
                        Ok(server) => profile.dns_servers.push(server),
                        Err(_) => profile.dns_search.push(entry.to_owned()),
                    }
                }
            }
            (Section::Interface, "mtu") => {
                profile.mtu = Some(value.parse().with_context(|| format!("invalid MTU {value:?}"))?);
            }
            (Section::Interface, "listenport" | "fwmark" | "table" | "saveconfig") => ignored.push(key),
            (Section::Interface, "preup" | "postup" | "predown" | "postdown") => {
                ignored.push(key);
            }
            (Section::Peer, _) if peers > 1 => {}
            (Section::Peer, "publickey") => {
                ensure!(parse_key(value).is_some(), "the peer's public key must be 32 bytes in base64");
                profile.public_key = value.to_owned();
            }
            (Section::Peer, "presharedkey") => {
                ensure!(parse_key(value).is_some(), "the pre-shared key must be 32 bytes in base64");
                profile.preshared_key = true;
                preshared_key = Some(Zeroizing::new(value.to_owned()));
            }
            (Section::Peer, "allowedips") => {
                for network in list() {
                    match parse_network(network)? {
                        IpNet::V4(net) => profile.allowed_ips.push(net.trunc()),
                        IpNet::V6(_) => ipv6 = true,
                    }
                }
            }
            (Section::Peer, "endpoint") => (profile.endpoint, profile.port) = parse_endpoint(value)?,
            (Section::Peer, "persistentkeepalive") => {
                profile.persistent_keepalive = match value {
                    "off" | "0" => None,
                    _ => Some(value.parse().with_context(|| format!("invalid keepalive {value:?}"))?),
                };
            }
            (Section::None, _) => bail!("line {}: {key} outside [Interface] or [Peer]", number + 1),
            _ => ignored.push(key),
        }
    }
    let private_key = private_key.context("the configuration has no private key (PrivateKey)")?;
    ensure!(peers > 0, "the configuration has no [Peer]");
    ensure!(!profile.endpoint.is_empty(), "the peer has no address (Endpoint)");
    if peers > 1 {
        notes.push(format!("{peers} peers: only the first one is imported"));
    }
    if ipv6 {
        notes.push("IPv6 addresses and networks are left out: the tunnel carries IPv4 only".into());
    }
    if ignored.iter().any(|k| k.starts_with("pre") || k.starts_with("post")) {
        notes.push("PreUp, PostUp, PreDown and PostDown commands are never run".into());
    }
    ignored.retain(|k| !(k.starts_with("pre") || k.starts_with("post")));
    ignored.dedup();
    if !ignored.is_empty() {
        notes.push(format!("ignored: {}", ignored.join(", ")));
    }
    if profile.dns_search.iter().any(|d| !vpn_core::valid_domain(d)) {
        bail!("the DNS line holds something that is neither an address nor a domain");
    }
    profile.local_public_key = public_key(&private_key);

    let mut core = Profile {
        id: String::new(),
        name: free_name(base, existing),
        description: None,
        folder: None,
        save_password: true,
        protocol: ProtocolConfig::WireGuard(profile),
        routes: None,
        full_tunnel: None,
        dns_domains: Vec::new(),
        allow_route_overlap: false,
        via: Vec::new(),
        exclusive: false,
    };
    if core.name != base {
        notes.push(format!("a VPN named {base} exists already: imported as {}", core.name));
    }
    core.validate().context("the imported profile is not valid")?;
    if let ProtocolConfig::WireGuard(p) = &mut core.protocol
        && p.dns_servers.is_empty()
        && !p.dns_search.is_empty()
    {
        notes.push("search domains without DNS servers: they are not used".into());
    }
    let origin: String = file.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let name = core.name.clone();
    let body = toml::to_string(&ProfileFile { profiles: vec![core] })?;
    let toml = format!("# Imported from WireGuard: \"{origin}\"\n{body}");
    Ok(WireGuardImport { imported: Imported { name, toml, notes, needs_psk: false }, private_key, preshared_key })
}

/// `10.7.0.2/32`, or a bare address (a host).
fn parse_network(text: &str) -> anyhow::Result<IpNet> {
    text.parse::<IpNet>()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| anyhow::anyhow!("{text:?} is not an address or a network"))
}

/// `host:port`, `[v6]:port`.
fn parse_endpoint(text: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest.split_once("]:").context("invalid Endpoint")?;
            (host, port)
        }
        None => text.rsplit_once(':').context("the Endpoint needs a port (host:port)")?,
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0).with_context(|| format!("invalid port in {text:?}"))?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    const PRIVATE: &str = "oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=";
    const PEER: &str = "GtL7fZc/bLnqZldpVofMCD6hDjrK28SsdLxevJ+qtKU=";
    const PSK: &str = "/UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=";

    fn sample() -> String {
        format!(
            "[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.7.0.2/32, fd00::2/128\nDNS = 10.7.0.1, corp.example\n\
             PostUp = iptables -A FORWARD\n\n[Peer]\n# the office\nPublicKey = {PEER}\nPresharedKey = {PSK}\n\
             AllowedIPs = 10.7.0.0/24, 192.168.10.0/24, ::/0\nEndpoint = vpn.example.com:51821\n\
             PersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn converts_wg_quick() {
        let import = convert(&sample(), "office", "office.conf", &[]).unwrap();
        assert_eq!(*import.private_key, PRIVATE);
        assert_eq!(import.preshared_key.as_deref().map(|k| k.as_str()), Some(PSK));
        let file: ProfileFile = toml::from_str(&import.imported.toml).unwrap();
        let ProtocolConfig::WireGuard(p) = &file.profiles[0].protocol else { panic!() };
        assert_eq!((p.endpoint.as_str(), p.port, p.public_key.as_str()), ("vpn.example.com", 51821, PEER));
        assert_eq!(p.addresses, vec!["10.7.0.2/32".parse::<Ipv4Net>().unwrap()]);
        assert_eq!(p.allowed_ips.len(), 2);
        assert_eq!((p.preshared_key, p.persistent_keepalive), (true, Some(25)));
        assert_eq!(p.dns_search, vec!["corp.example".to_string()]);
        assert!(p.local_public_key.is_some());
        // No secret in the profile.
        assert!(!import.imported.toml.contains(PRIVATE) && !import.imported.toml.contains(PSK));
        let notes = import.imported.notes.join("\n");
        assert!(notes.contains("IPv6") && notes.contains("never run"), "{notes}");
    }

    #[test]
    fn public_key_matches_wg() {
        // RFC 7748, section 6.1: Alice's keys.
        assert_eq!(
            public_key("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=").unwrap(),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
        let generated = new_private_key();
        assert!(public_key(&generated).is_some());
    }

    #[test]
    fn refuses_incomplete_files() {
        assert!(convert("[Interface]\nAddress = 10.0.0.2/32\n", "x", "x.conf", &[]).is_err());
        let no_peer = format!("[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/32\n");
        assert!(convert(&no_peer, "x", "x.conf", &[]).is_err());
        let bad_dns = sample().replace("corp.example", "a;b");
        assert!(convert(&bad_dns, "x", "x.conf", &[]).is_err());
        assert_eq!(parse_endpoint("[2001:db8::1]:51820").unwrap(), ("2001:db8::1".into(), 51820));
        assert!(parse_endpoint("vpn.example.com").is_err());
    }
}
