//! Import of OpenVPN client configurations (`.ovpn`, `.conf`). Files the
//! configuration names (`ca`, `cert`, `key`, `tls-auth`…) are read as the
//! user, relative to the configuration's folder, and inlined: the daemon
//! never opens user paths. Passwords are never imported.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use ipnet::Ipv4Net;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use vpn_core::openvpn::{MAX_REMOTES, OPENVPN_CIPHERS, OPENVPN_DIGESTS, parse_static_key};
use vpn_core::{
    Compression, ControlChannel, OpenVpnProfile, OpenVpnRemote, Profile, ProfileFile, ProtocolConfig, StaticChallenge,
    Transport, X509NameCheck, X509NameKind,
};

use super::Imported;

/// Largest configuration, or file it names, read.
pub const MAX_SIZE: u64 = 1024 * 1024;

/// Converts the OpenVPN configuration at `path` into a profile named after
/// the file, renamed if the name is among `existing`. Refuses what this
/// client cannot do (`dev tap`, static keys, `tls-crypt-v2`).
pub fn openvpn(path: &Path, existing: &[String]) -> anyhow::Result<Imported> {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    convert_file(path, &super::name_or(&stem, "openvpn"), None, &format!("OpenVPN: \"{file}\""), existing)
}

/// Converts the configuration at `path` into a profile named `base` (or
/// `base-2`… if taken), described by `description` unless the file names
/// itself; `origin` goes in the header comment.
pub(super) fn convert_file(
    path: &Path,
    base: &str,
    description: Option<&str>,
    origin: &str,
    existing: &[String],
) -> anyhow::Result<Imported> {
    let text = read(path)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let config = Config::parse(&text, dir)?;
    let mut notes = Vec::new();
    let mut profile = convert(&config, &text, &mut notes)?;
    if profile.description.is_none() {
        profile.description = description.map(str::to_owned);
    }

    profile.name = free_name(base, existing);
    if profile.name != base {
        notes.push(format!("a VPN named {base} exists already: imported as {}", profile.name));
    }
    profile.validate().context("the imported profile is not valid")?;
    if let ProtocolConfig::OpenVpn(p) = &profile.protocol
        && p.auth_user_pass
    {
        notes.push(format!(
            "password (optional, asked otherwise): {} secret set {}",
            vpn_core::brand::CLI,
            profile.name
        ));
    }

    let origin: String = origin.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let name = profile.name.clone();
    let body = toml::to_string(&ProfileFile { profiles: vec![profile] })?;
    let toml = format!("# Imported from {origin}\n{body}");
    Ok(Imported { name, toml, notes, needs_psk: false })
}

/// `base`, or `base 2`, `base 3`… if taken (64 characters at most).
pub(super) fn free_name(base: &str, existing: &[String]) -> String {
    let taken = |name: &str| existing.iter().any(|e| e == name);
    if !taken(base) {
        return base.to_owned();
    }
    (2..)
        .map(|n| {
            let suffix = format!(" {n}");
            let stem: String = base.chars().take(64 - suffix.len()).collect();
            format!("{}{suffix}", stem.trim_end())
        })
        .find(|name| !taken(name))
        .expect("a free name")
}

/// Reads a configuration, within `MAX_SIZE`.
pub(super) fn read_config(path: &Path) -> anyhow::Result<String> {
    read(path)
}

fn read(path: &Path) -> anyhow::Result<String> {
    let size = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?.len();
    ensure!(size <= MAX_SIZE, "{} is too large for an OpenVPN file", path.display());
    std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

/// One option line, or an inline `<tag>…</tag>` block (no arguments).
struct Directive {
    name: String,
    args: Vec<String>,
    inline: Option<String>,
}

struct Config {
    directives: Vec<Directive>,
    blocks: HashMap<String, String>,
    dir: PathBuf,
}

impl Config {
    fn parse(text: &str, dir: &Path) -> anyhow::Result<Self> {
        let mut directives = Vec::new();
        let mut blocks = HashMap::new();
        let mut open: Option<(String, String)> = None;
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            let closes = open.as_ref().is_some_and(|(tag, _)| trimmed.eq_ignore_ascii_case(&format!("</{tag}>")));
            if closes {
                let (tag, content) = open.take().expect("open block");
                blocks.insert(tag.clone(), content.clone());
                directives.push(Directive { name: tag, args: Vec::new(), inline: Some(content) });
                continue;
            }
            if let Some((_, content)) = &mut open {
                content.push_str(line);
                content.push('\n');
                continue;
            }
            if let Some(tag) = trimmed.strip_prefix('<').and_then(|t| t.strip_suffix('>'))
                && !tag.starts_with('/')
                && !tag.is_empty()
            {
                open = Some((tag.to_ascii_lowercase(), String::new()));
                continue;
            }
            let mut args = tokens(line).with_context(|| format!("line {}", number + 1))?;
            if args.is_empty() {
                continue;
            }
            let name = args.remove(0);
            let name = name.strip_prefix("--").unwrap_or(&name).to_ascii_lowercase();
            directives.push(Directive { name, args, inline: None });
        }
        if let Some((tag, _)) = open {
            bail!("<{tag}> is not closed (</{tag}>)");
        }
        Ok(Self { directives, blocks, dir: dir.to_owned() })
    }

    /// The last occurrence of an option: it replaces the earlier ones.
    fn last(&self, name: &str) -> Option<&Directive> {
        self.directives.iter().rev().find(|d| d.name == name)
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Directive> + 'a {
        self.directives.iter().filter(move |d| d.name == name)
    }

    fn has(&self, name: &str) -> bool {
        self.last(name).is_some()
    }

    /// What a file option holds: its inline block, or the file it names.
    fn contents(&self, d: &Directive) -> anyhow::Result<String> {
        if let Some(inline) = &d.inline {
            return Ok(inline.clone());
        }
        match d.args.first().map(String::as_str) {
            None | Some("[inline]") => {
                self.blocks.get(&d.name).cloned().with_context(|| format!("{} [inline] without <{}>", d.name, d.name))
            }
            Some(file) => read(&self.beside(file)?).with_context(|| format!("file named by {}", d.name)),
        }
    }

    /// A file the configuration names: only one in its folder or below
    /// (`keys/ca.crt`), so that a configuration from elsewhere cannot pull
    /// in any of the user's files (`auth-user-pass ../.git-credentials`).
    fn beside(&self, file: &str) -> anyhow::Result<PathBuf> {
        let name = Path::new(file);
        ensure!(
            name.components().all(|c| matches!(c, std::path::Component::Normal(_))),
            "{file:?} is outside the configuration's folder: only files in it are read"
        );
        let dir = self.dir.canonicalize().with_context(|| format!("cannot read {}", self.dir.display()))?;
        let path = dir.join(name).canonicalize().with_context(|| format!("cannot read {file}"))?;
        // A link out of the folder is refused too.
        ensure!(path.starts_with(&dir), "{file:?} links out of the configuration's folder");
        Ok(path)
    }
}

/// Splits an option line as OpenVPN does: blanks separate arguments,
/// quotes group them, a backslash escapes the next character (not
/// between single quotes), `#` or `;` at the start of an argument begins a
/// comment.
fn tokens(line: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some('"') => match c {
                '\\' => current.push(chars.next().context("backslash at the end of the line")?),
                '"' => quote = None,
                _ => current.push(c),
            },
            Some(q) => {
                if c == q {
                    quote = None
                } else {
                    current.push(c)
                }
            }
            None if c.is_whitespace() => {
                if in_token {
                    out.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            None if !in_token && (c == '#' || c == ';') => break,
            None => {
                in_token = true;
                match c {
                    '"' | '\'' => quote = Some(c),
                    '\\' => current.push(chars.next().context("backslash at the end of the line")?),
                    _ => current.push(c),
                }
            }
        }
    }
    ensure!(quote.is_none(), "unterminated quote");
    if in_token {
        out.push(current);
    }
    Ok(out)
}

fn convert(config: &Config, text: &str, notes: &mut Vec<String>) -> anyhow::Result<Profile> {
    refuse_unsupported(config)?;

    // Servers, from `remote` lines and `<connection>` blocks, in order.
    let default_port = match config.last("rport").or(config.last("port")).and_then(|d| d.args.first()) {
        Some(port) => port.parse().with_context(|| format!("invalid port {port:?}"))?,
        None => 1194,
    };
    let default_transport = match config.last("proto").and_then(|d| d.args.first()) {
        Some(proto) => transport(proto)?,
        None => Transport::Udp,
    };
    let mut remotes = Vec::new();
    for d in &config.directives {
        match d.name.as_str() {
            "remote" => remotes.push(remote(&d.args, default_port, default_transport)?),
            "connection" => {
                let inner = Config::parse(&config.contents(d)?, &config.dir)?;
                let port = match inner.last("port").and_then(|d| d.args.first()) {
                    Some(port) => port.parse().with_context(|| format!("invalid port {port:?}"))?,
                    None => default_port,
                };
                let proto = match inner.last("proto").and_then(|d| d.args.first()) {
                    Some(proto) => transport(proto)?,
                    None => default_transport,
                };
                for r in inner.all("remote") {
                    remotes.push(remote(&r.args, port, proto)?);
                }
                if inner.directives.iter().any(|d| !matches!(d.name.as_str(), "remote" | "port" | "proto")) {
                    notes.push(
                        "options inside <connection> blocks other than remote, port and proto are ignored".into(),
                    );
                }
            }
            _ => {}
        }
    }
    ensure!(!remotes.is_empty(), "the configuration names no server (remote)");
    if remotes.len() > MAX_REMOTES {
        notes.push(format!("{} servers listed: only the first {MAX_REMOTES} are kept", remotes.len()));
        remotes.truncate(MAX_REMOTES);
    }
    if config.has("remote-random") {
        notes.push("remote-random: the servers are tried in the order of the file".into());
    }

    // The server's certificate.
    let ca_pem = config.last("ca").map(|d| certificates(&config.contents(d)?, "ca")).transpose()?;
    if config.has("capath") {
        notes.push("capath is not supported: the CA must be given with ca".into());
    }
    let mut trusted_cert = Vec::new();
    for d in config.all("peer-fingerprint") {
        let list = match (&d.inline, d.args.first().map(String::as_str)) {
            (None, Some(arg)) if arg != "[inline]" => arg.to_owned(),
            _ => config.contents(d)?,
        };
        for line in list.lines().flat_map(|l| l.split_whitespace().next()) {
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let hex = line.replace(':', "").to_ascii_lowercase();
            ensure!(
                hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()),
                "peer-fingerprint {line:?} is not a SHA-256 fingerprint"
            );
            if !trusted_cert.contains(&hex) {
                trusted_cert.push(hex);
            }
        }
    }
    let checks_server = config.all("remote-cert-tls").any(|d| d.args.first().is_some_and(|a| a == "server"))
        || config.all("ns-cert-type").any(|d| d.args.first().is_some_and(|a| a == "server"));
    if !checks_server {
        notes.push(
            "remote-cert-tls server is missing: this client checks that the server's certificate is meant for a \
             server (it can be turned off in the editor if the server's certificate is refused)"
                .into(),
        );
    }
    let verify_x509_name = match config.last("verify-x509-name") {
        None => None,
        Some(d) => {
            let name = d.args.first().context("verify-x509-name needs a name")?.clone();
            let kind = match d.args.get(1).map(String::as_str) {
                None | Some("subject") => X509NameKind::Subject,
                Some("name") => X509NameKind::Name,
                Some("name-prefix") => X509NameKind::NamePrefix,
                Some(other) => bail!("unknown verify-x509-name type {other:?}"),
            };
            Some(X509NameCheck { name, kind })
        }
    };
    for (option, what) in [
        ("crl-verify", "the certificate revocation list (crl-verify) is not checked"),
        ("tls-verify", "the tls-verify script is not run"),
        ("verify-hash", "verify-hash is not supported: use peer-fingerprint or the CA"),
        ("remote-cert-ku", "remote-cert-ku is not checked (remote-cert-tls server is)"),
        ("remote-cert-eku", "remote-cert-eku is not checked (remote-cert-tls server is)"),
    ] {
        if config.has(option) {
            notes.push(what.into());
        }
    }

    // The client's credentials.
    let client_cert_pem = config.last("cert").map(|d| certificates(&config.contents(d)?, "cert")).transpose()?;
    let client_key_pem = config.last("key").map(|d| private_key(&config.contents(d)?)).transpose()?;
    ensure!(client_cert_pem.is_some() == client_key_pem.is_some(), "cert and key must be given together");
    let auth_user_pass = config.last("auth-user-pass");
    let mut username = None;
    if let Some(d) = auth_user_pass
        && (d.inline.is_some() || d.args.first().is_some_and(|a| a != "stdin"))
    {
        let content = config.contents(d)?;
        let mut lines = content.lines();
        username = lines.next().map(|l| l.trim().to_owned()).filter(|l| plausible_user(l));
        // The file may be any file of the user's: what is taken from it
        // is shown.
        if let (Some(user), Some(file)) = (&username, d.args.first().filter(|a| *a != "[inline]")) {
            notes.push(format!("user name {user:?}, read from {file}"));
        }
        if lines.next().is_some_and(|l| !l.is_empty()) {
            notes.push(
                "the password in the auth-user-pass file was not imported: it is asked at connection, or can be \
                 saved in the Keychain"
                    .into(),
            );
        }
    }
    if auth_user_pass.is_some() && username.is_none() {
        // Access Server profiles name their user in a comment.
        username = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("# OVPN_ACCESS_SERVER_USERNAME="))
            .map(|u| u.trim().to_owned())
            .filter(|u| plausible_user(u));
    }
    if config.has("pkcs12") {
        ensure!(
            client_cert_pem.is_some() || auth_user_pass.is_some(),
            "PKCS#12 files (pkcs12) are not supported: add the .p12 file to your Keychain and choose its \
             certificate in the editor, or convert it to cert and key files"
        );
        notes.push("pkcs12 is not supported: add the .p12 file to your Keychain and choose it in the editor".into());
    }
    for option in ["pkcs11-providers", "pkcs11-id", "cryptoapicert", "management-external-key"] {
        if config.has(option) {
            notes.push(format!("{option} is not supported: choose a Keychain certificate in the editor"));
        }
    }
    let static_challenge = match config.last("static-challenge") {
        None => None,
        Some(d) => {
            let text = d.args.first().context("static-challenge needs a text")?.clone();
            Some(StaticChallenge { text, echo: d.args.get(1).is_some_and(|e| e == "1") })
        }
    };

    // The control channel.
    let tls_auth = config.last("tls-auth");
    let tls_crypt = config.last("tls-crypt");
    let (control_channel, static_key, key_direction) = match (tls_auth, tls_crypt) {
        (Some(_), Some(_)) => bail!("tls-auth and tls-crypt cannot be used together"),
        (Some(d), None) => {
            let key = static_key(&config.contents(d)?, "tls-auth")?;
            // `tls-auth [inline] 1` may come before its block.
            let inline_direction = config.all("tls-auth").filter_map(|d| d.args.get(1)).last();
            let direction = match inline_direction.or(config.last("key-direction").and_then(|k| k.args.first())) {
                None => None,
                Some(dir) => Some(match dir.as_str() {
                    "0" => 0,
                    "1" => 1,
                    other => bail!("invalid key direction {other:?}"),
                }),
            };
            (ControlChannel::TlsAuth, Some(key), direction)
        }
        (None, Some(d)) => (ControlChannel::TlsCrypt, Some(static_key(&config.contents(d)?, "tls-crypt")?), None),
        (None, None) => (ControlChannel::None, None, None),
    };
    let auth_digest = match config.last("auth").and_then(|d| d.args.first()) {
        None => "SHA1".to_owned(),
        Some(digest) => {
            let upper = digest.to_ascii_uppercase().replace('-', "");
            match OPENVPN_DIGESTS.iter().find(|d| **d == upper) {
                Some(known) => known.to_string(),
                // The digest only matters for tls-auth: the data channel
                // ciphers are AEAD.
                None if control_channel == ControlChannel::TlsAuth => {
                    bail!("tls-auth with the {digest} digest is not supported: use {}", OPENVPN_DIGESTS.join(", "))
                }
                None => "SHA1".to_owned(),
            }
        }
    };

    // The data channel.
    let aead = |name: &str| OPENVPN_CIPHERS.iter().find(|c| c.eq_ignore_ascii_case(name)).map(|c| c.to_string());
    let listed = config.last("data-ciphers").or(config.last("ncp-ciphers")).and_then(|d| d.args.first());
    let mut data_ciphers: Vec<String> = match listed {
        Some(list) => list.split(':').filter_map(|c| aead(c.trim())).collect(),
        None => OPENVPN_CIPHERS.iter().map(|c| c.to_string()).collect(),
    };
    data_ciphers = data_ciphers
        .iter()
        .enumerate()
        .filter(|(i, c)| !data_ciphers[..*i].contains(c))
        .map(|(_, c)| c.clone())
        .collect();
    let fallback = config
        .last("data-ciphers-fallback")
        .or(config.last("cipher"))
        .and_then(|d| d.args.first())
        .filter(|c| aead(c).is_none() && !c.eq_ignore_ascii_case("none"));
    if data_ciphers.is_empty() {
        notes.push(format!(
            "none of the data ciphers listed is supported: the server must allow {} (data-ciphers)",
            OPENVPN_CIPHERS.join(", ")
        ));
        data_ciphers = OPENVPN_CIPHERS.iter().map(|c| c.to_string()).collect();
    } else if let Some(cipher) = fallback {
        notes.push(format!(
            "{cipher} is not supported: the server must allow AEAD ciphers ({}) through data-ciphers \
             (OpenVPN 2.4 or later)",
            OPENVPN_CIPHERS.join(", ")
        ));
    }

    let compression = compression(config, notes)?;
    let reneg_sec = match config.last("reneg-sec").and_then(|d| d.args.first()) {
        None => 3600,
        Some(secs) => match secs.parse::<u32>().with_context(|| format!("invalid reneg-sec {secs:?}"))? {
            secs @ 1..60 => {
                notes.push(format!("reneg-sec {secs} raised to 60 seconds"));
                60
            }
            secs => secs,
        },
    };
    if config.has("fragment") {
        notes.push("fragment is not supported: the server must not use it".into());
    }
    for option in ["http-proxy", "socks-proxy"] {
        if config.has(option) {
            notes.push(format!("{option}: proxies are not supported, the server is reached directly"));
        }
    }
    if ["up", "down", "route-up", "ipchange", "client-connect", "learn-address"].iter().any(|o| config.has(o)) {
        notes.push("scripts (up, down…) are never run; the DNS servers the server pushes are applied".into());
    }

    // What goes through the tunnel.
    let mut full_tunnel = config.has("redirect-gateway").then_some(true);
    let mut routes = None;
    for d in config.all("pull-filter") {
        if let [action, text, ..] = d.args.as_slice()
            && action == "ignore"
        {
            if text.starts_with("redirect-gateway") {
                full_tunnel = Some(false);
            } else {
                notes.push(format!("pull-filter ignore \"{text}\" is not supported"));
            }
        }
    }
    let listed_routes: Vec<vpn_core::Noted<_>> =
        own_routes(config, notes).into_iter().map(|net| vpn_core::Destination::from(net).into()).collect();
    let mut extra_routes = Vec::new();
    if config.has("route-nopull") {
        full_tunnel = full_tunnel.or(Some(false));
        routes = Some(listed_routes);
    } else {
        // Added to the networks the server pushes.
        extra_routes = listed_routes;
        if extra_routes.len() > vpn_core::openvpn::MAX_EXTRA_ROUTES {
            notes.push(format!(
                "{} route lines: only the first {} are kept",
                extra_routes.len(),
                vpn_core::openvpn::MAX_EXTRA_ROUTES
            ));
            extra_routes.truncate(vpn_core::openvpn::MAX_EXTRA_ROUTES);
        }
        extra_routes.retain(|r| r.network().is_some_and(|net| net.prefix_len() > 0));
    }
    let mut dns_domains = Vec::new();
    for d in &config.directives {
        let domains: &[String] = match (d.name.as_str(), d.args.as_slice()) {
            ("dhcp-option", [kind, rest @ ..]) if kind == "DOMAIN" || kind == "DOMAIN-SEARCH" => rest,
            ("dns", [kind, rest @ ..]) if kind == "search-domains" => rest,
            _ => continue,
        };
        for domain in domains {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if vpn_core::valid_domain(&domain) && !dns_domains.contains(&domain) {
                dns_domains.push(domain);
            }
        }
    }

    // Access Server names its profiles.
    let description = config
        .all("setenv")
        .filter_map(|d| match d.args.as_slice() {
            [key, value, ..] if key == "FRIENDLY_NAME" => Some(value),
            _ => None,
        })
        .last()
        .map(|v| v.chars().filter(|c| !c.is_control()).take(256).collect::<String>())
        .filter(|v| !v.is_empty());

    Ok(Profile {
        id: String::new(),
        name: String::new(),
        description,
        folder: None,
        save_password: true,
        protocol: ProtocolConfig::OpenVpn(OpenVpnProfile {
            remotes,
            auth_user_pass: auth_user_pass.is_some(),
            username,
            static_challenge: static_challenge.filter(|_| auth_user_pass.is_some()),
            ca_pem,
            trusted_cert,
            remote_cert_tls: true,
            verify_x509_name,
            client_cert_pem,
            client_key_pem,
            client_certificate: None,
            client_chain_pem: None,
            control_channel,
            static_key,
            key_direction,
            auth_digest,
            data_ciphers,
            compression,
            reneg_sec,
            extra_routes,
        }),
        routes,
        full_tunnel,
        split_routes: Vec::new(),
        dns_domains: dns_domains.into_iter().map(Into::into).collect(),
        excluded_domains: Vec::new(),
        allow_route_overlap: false,
        via: Vec::new(),
        exclusive: false,
    })
}

/// A user name, not a line of some other file.
fn plausible_user(user: &str) -> bool {
    !user.is_empty() && user.len() <= 128 && !user.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Configurations this client cannot connect with at all.
fn refuse_unsupported(config: &Config) -> anyhow::Result<()> {
    let dev = config.last("dev").and_then(|d| d.args.first()).map(|d| d.to_ascii_lowercase());
    let dev_type = config.last("dev-type").and_then(|d| d.args.first()).map(|d| d.to_ascii_lowercase());
    if dev_type.as_deref() == Some("tap")
        || (dev_type.is_none() && dev.as_deref().is_some_and(|d| d.starts_with("tap")))
    {
        bail!("dev tap (layer 2 bridging) is not supported: only dev tun configurations can be imported");
    }
    if config.has("secret") {
        bail!("static key mode (secret) is not supported: the server must use TLS (ca, cert, key)");
    }
    if config.has("tls-crypt-v2") {
        bail!("tls-crypt-v2 is not supported yet");
    }
    if config.has("server") || config.has("tls-server") || config.last("mode").is_some_and(|d| d.args == ["server"]) {
        bail!("this is a server configuration, not a client one");
    }
    Ok(())
}

/// `remote host [port] [proto]`.
fn remote(args: &[String], port: u16, proto: Transport) -> anyhow::Result<OpenVpnRemote> {
    let host = args.first().context("remote needs a server")?.clone();
    ensure!(vpn_core::profile::valid_host(&host), "invalid server address {host:?}");
    let port = match args.get(1) {
        Some(p) => p.parse().with_context(|| format!("invalid port {p:?}"))?,
        None => port,
    };
    let transport = match args.get(2) {
        Some(p) => transport(p)?,
        None => proto,
    };
    Ok(OpenVpnRemote { host, port, transport })
}

fn transport(proto: &str) -> anyhow::Result<Transport> {
    match proto.to_ascii_lowercase().as_str() {
        "udp" | "udp4" | "udp6" => Ok(Transport::Udp),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => Ok(Transport::Tcp),
        other => bail!("unsupported proto {other:?}"),
    }
}

/// The certificates of a PEM file, without the text easy-rsa puts before
/// them.
fn certificates(text: &str, option: &str) -> anyhow::Result<String> {
    let ders = CertificateDer::pem_slice_iter(text.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("{option}: invalid PEM ({e:?})"))?;
    ensure!(!ders.is_empty(), "{option}: no certificate (-----BEGIN CERTIFICATE-----)");
    Ok(ders.iter().map(|der| pem("CERTIFICATE", der)).collect())
}

fn private_key(text: &str) -> anyhow::Result<String> {
    ensure!(
        !text.contains("ENCRYPTED"),
        "the client key is protected by a passphrase, which is not supported: decrypt it first \
         (openssl pkey -in client.key -out client-plain.key)"
    );
    let key = PrivateKeyDer::from_pem_slice(text.as_bytes())
        .map_err(|_| anyhow::anyhow!("key: no private key in PEM format"))?;
    let label = match &key {
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => "PRIVATE KEY",
    };
    Ok(pem(label, key.secret_der()))
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The `OpenVPN Static key V1` block alone.
fn static_key(text: &str, option: &str) -> anyhow::Result<String> {
    parse_static_key(text).with_context(|| format!("{option}: invalid key"))?;
    let start = text.find("-----BEGIN OpenVPN Static key V1-----").expect("checked");
    // The END after the BEGIN: a comment before the block may name it.
    let end = start + text[start..].find("-----END OpenVPN Static key V1-----").expect("checked");
    Ok(format!("{}-----END OpenVPN Static key V1-----\n", &text[start..end]))
}

fn compression(config: &Config, notes: &mut Vec<String>) -> anyhow::Result<Compression> {
    // The last of comp-lzo and compress wins.
    let Some(d) = config.directives.iter().rev().find(|d| d.name == "comp-lzo" || d.name == "compress") else {
        return Ok(Compression::None);
    };
    let algorithm = d.args.first().map(|a| a.to_ascii_lowercase());
    let compression = match (d.name.as_str(), algorithm.as_deref()) {
        // `comp-lzo no` still frames packets.
        ("comp-lzo", _) | ("compress", Some("lzo")) => Compression::Lzo,
        ("compress", None | Some("stub") | Some("lz4")) => Compression::Stub,
        ("compress", Some("stub-v2") | Some("lz4-v2")) => Compression::StubV2,
        (_, other) => bail!("unknown compression {other:?}"),
    };
    let compressing = match d.name.as_str() {
        "comp-lzo" => !matches!(algorithm.as_deref(), Some("no")),
        _ => !matches!(algorithm.as_deref(), None | Some("stub") | Some("stub-v2")),
    };
    if compressing {
        notes.push(
            "compression: this client never compresses (VORACLE); the server should use compress stub-v2 or \
             allow-compression no"
                .into(),
        );
    }
    Ok(compression)
}

/// The networks of `route` lines; exclusions (`net_gateway`) and names
/// are left out.
fn own_routes(config: &Config, notes: &mut Vec<String>) -> Vec<Ipv4Net> {
    let mut routes = Vec::new();
    for d in config.all("route") {
        let network = d.args.first().and_then(|n| n.parse::<Ipv4Addr>().ok());
        let mask = d.args.get(1).map_or(Some(Ipv4Addr::BROADCAST), |m| m.parse::<Ipv4Addr>().ok());
        let excluded = d.args.get(2).is_some_and(|g| g == "net_gateway");
        let net = network.zip(mask).and_then(|(network, mask)| {
            let bits = u32::from(mask);
            (bits.leading_ones() + bits.trailing_zeros() == 32)
                .then(|| Ipv4Net::new(network, bits.leading_ones() as u8).ok().map(|n| n.trunc()))
                .flatten()
        });
        match net {
            Some(net) if !excluded => {
                if !routes.contains(&net) {
                    routes.push(net);
                }
            }
            _ => notes.push(format!("route {} is not supported: left out", d.args.join(" "))),
        }
    }
    routes
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    const KEY: &str = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
        -----END OpenVPN Static key V1-----\n";

    /// A CA certificate, for other importers' tests.
    pub(in crate::import) fn ca_pem() -> String {
        pki().ca
    }

    struct Pki {
        ca: String,
        cert: String,
        key: String,
    }

    fn pki() -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "Easy-RSA CA");
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(params, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["alice".into()]).unwrap().signed_by(&key, &issuer).unwrap();
        Pki { ca: ca.pem(), cert: cert.pem(), key: key.serialize_pem() }
    }

    /// Writes `files` in a fresh folder and imports the first one.
    fn import(tag: &str, files: &[(&str, &str)], existing: &[String]) -> anyhow::Result<Imported> {
        let dir = std::env::temp_dir().join(format!("{}-ovpn-{tag}-{}", vpn_core::brand::CLI, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let imported = openvpn(&dir.join(files[0].0), existing);
        std::fs::remove_dir_all(&dir).unwrap();
        imported
    }

    fn openvpn_profile(imported: &Imported) -> (Profile, OpenVpnProfile) {
        let file: ProfileFile = toml::from_str(&imported.toml).unwrap();
        let profile = file.profiles.into_iter().next().unwrap();
        profile.validate().unwrap();
        let ProtocolConfig::OpenVpn(p) = profile.protocol.clone() else { panic!() };
        (profile, p)
    }

    /// An OpenVPN Access Server user-locked profile, with password.
    #[test]
    fn access_server_profile() {
        let pki = pki();
        let ovpn = format!(
            "# Automatically generated OpenVPN client config file\n\
             # OVPN_ACCESS_SERVER_USERNAME=alice\n\
             # OVPN_ACCESS_SERVER_PROFILE=alice@vpn.example.com/AUTOLOGIN\n\
             setenv FORWARD_COMPATIBLE 1\nclient\nserver-poll-timeout 4\nnobind\n\
             remote vpn.example.com 1194 udp\nremote vpn.example.com 1194 udp\n\
             remote vpn.example.com 443 tcp\nremote 198.51.100.7 1194 udp\n\
             dev tun\ndev-type tun\nremote-cert-tls server\ntls-version-min 1.2\nreneg-sec 604800\n\
             tun-mtu 1420\nauth-user-pass\nverb 3\npush-peer-info\n\
             setenv FRIENDLY_NAME \"Example Corp\"\n\
             data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\ncipher AES-256-CBC\n\
             auth SHA256\nkey-direction 1\n\
             <ca>\n{}</ca>\n<cert>\n{}</cert>\n<key>\n{}</key>\n<tls-crypt>\n{KEY}</tls-crypt>\n",
            pki.ca, pki.cert, pki.key
        );
        let imported = import("as", &[("client.ovpn", &ovpn)], &[]).unwrap();
        assert_eq!(imported.name, "client");
        let (profile, p) = openvpn_profile(&imported);
        assert_eq!(profile.description.as_deref(), Some("Example Corp"));
        assert_eq!(p.remotes.len(), 4);
        assert_eq!(
            p.remotes[2],
            OpenVpnRemote { host: "vpn.example.com".into(), port: 443, transport: Transport::Tcp }
        );
        assert!(p.auth_user_pass);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!((p.control_channel, p.key_direction), (ControlChannel::TlsCrypt, None));
        assert!(p.static_key.as_deref().unwrap().starts_with("-----BEGIN OpenVPN Static key V1-----"));
        assert_eq!(p.data_ciphers, OPENVPN_CIPHERS);
        assert_eq!((p.auth_digest.as_str(), p.reneg_sec), ("SHA256", 604800));
        assert!(p.ca_pem.unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(p.client_key_pem.unwrap().contains("PRIVATE KEY"));
        assert!(p.client_cert_pem.is_some() && p.remote_cert_tls);
        // AES-256-CBC is the fallback for old servers: worth a note.
        assert!(imported.notes.iter().any(|n| n.contains("AES-256-CBC")), "{:?}", imported.notes);
        assert!(imported.notes.iter().any(|n| n.contains("secret set client")), "{:?}", imported.notes);
    }

    /// A pfSense client export: tls-auth with direction 1, split tunnel,
    /// username and password in a file next to it.
    #[test]
    fn pfsense_export() {
        let pki = pki();
        let ovpn = format!(
            "dev tun\npersist-tun\npersist-key\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n\
             data-ciphers-fallback AES-256-CBC\nauth SHA256\ntls-client\nclient\nresolv-retry infinite\n\
             remote 203.0.113.5 1194 udp4\nnobind\nverify-x509-name \"pfsense-server\" name\n\
             auth-user-pass pass.txt\nremote-cert-tls server\nexplicit-exit-notify\n\
             pull-filter ignore \"redirect-gateway\"\nroute 10.20.0.0 255.255.0.0\n\
             dhcp-option DOMAIN corp.example\n\
             <ca>\n{}</ca>\nsetenv opt block-outside-dns\nkey-direction 1\n<tls-auth>\n{KEY}</tls-auth>\n",
            pki.ca
        );
        let imported =
            import("pf", &[("pfSense-UDP4-1194-alice.ovpn", &ovpn), ("pass.txt", "alice\nhunter2\n")], &[]).unwrap();
        assert!(!imported.toml.contains("hunter2"), "passwords are never imported");
        assert_eq!(imported.name, "pfSense-UDP4-1194-alice");
        let (profile, p) = openvpn_profile(&imported);
        assert_eq!(p.remotes, [OpenVpnRemote { host: "203.0.113.5".into(), port: 1194, transport: Transport::Udp }]);
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!((p.control_channel, p.key_direction), (ControlChannel::TlsAuth, Some(1)));
        assert_eq!(p.verify_x509_name, Some(X509NameCheck { name: "pfsense-server".into(), kind: X509NameKind::Name }));
        assert!(p.client_cert_pem.is_none());
        assert_eq!(profile.full_tunnel, Some(false));
        assert_eq!(profile.routes, None, "route adds to the pushed routes");
        assert_eq!(p.extra_routes, ["10.20.0.0/16".parse::<ipnet::Ipv4Net>().unwrap()]);
        assert_eq!(profile.dns_domains, ["corp.example"]);
        assert!(imported.notes.iter().any(|n| n.contains("password in the auth-user-pass file")));
        assert!(imported.notes.iter().any(|n| n.contains("\"alice\", read from pass.txt")), "{:?}", imported.notes);
        assert!(imported.notes.iter().any(|n| n.contains("AES-256-CBC")));
    }

    /// An easy-rsa client with its files next to the configuration
    /// (`.crt` with a text dump first), tls-crypt, lz4 framing.
    #[test]
    fn easy_rsa_with_files() {
        let pki = pki();
        let crt = format!("Certificate:\n    Data:\n        Version: 3 (0x2)\n{}", pki.cert);
        let conf = "client\ndev tun\nproto tcp-client\nport 443\n\
                    remote vpn1.example.com\nremote vpn2.example.com 8443 udp # backup\n\
                    ; remote old.example.com\nresolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\n\
                    ca \"keys/ca.crt\"\ncert keys/alice.crt\nkey keys/alice.key\ntls-crypt keys/ta.key\n\
                    remote-cert-tls server\ncipher AES-256-GCM\ncompress lz4-v2\nredirect-gateway def1\n\
                    route-nopull\nroute 10.8.0.0 255.255.255.0\nroute 192.0.2.0 255.255.255.0 net_gateway\n\
                    up /etc/openvpn/update-resolv-conf\nverb 3\n";
        let imported = import(
            "rsa",
            &[
                ("Office VPN.conf", conf),
                ("keys/ca.crt", &pki.ca),
                ("keys/alice.crt", &crt),
                ("keys/alice.key", &pki.key),
                ("keys/ta.key", KEY),
            ],
            &["Office VPN".into()],
        );
        let imported = match imported {
            Err(e) if e.to_string().contains("cannot read") => panic!("{e:#}"),
            other => other.unwrap(),
        };
        assert_eq!(imported.name, "Office VPN 2", "the name is taken");
        let (profile, p) = openvpn_profile(&imported);
        assert_eq!(
            p.remotes,
            [
                OpenVpnRemote { host: "vpn1.example.com".into(), port: 443, transport: Transport::Tcp },
                OpenVpnRemote { host: "vpn2.example.com".into(), port: 8443, transport: Transport::Udp },
            ]
        );
        assert!(!p.auth_user_pass && p.client_cert_pem.as_deref().unwrap().starts_with("-----BEGIN CERTIFICATE"));
        assert_eq!(p.control_channel, ControlChannel::TlsCrypt);
        assert_eq!(p.compression, Compression::StubV2);
        assert_eq!(profile.full_tunnel, Some(true));
        assert_eq!(profile.routes.unwrap().iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.8.0.0/24"]);
        assert!(imported.notes.iter().any(|n| n.contains("net_gateway")));
        assert!(imported.notes.iter().any(|n| n.contains("scripts")));
        assert!(imported.notes.iter().any(|n| n.contains("compression")));
    }

    /// A configuration reads only files in its own folder.
    #[test]
    fn files_outside_the_folder_are_refused() {
        let conf = |line: &str| format!("client\ndev tun\nremote vpn.example.com\nca ca.crt\n{line}\n");
        let ca = pki().ca;
        for line in ["auth-user-pass ../secret", "auth-user-pass /etc/hosts", "auth-user-pass sub/../../secret"] {
            let Err(err) =
                import("outside", &[("in/x.ovpn", &conf(line)), ("in/ca.crt", &ca), ("secret", "token\n")], &[])
            else {
                panic!("{line} was read");
            };
            assert!(format!("{err:#}").contains("outside the configuration's folder"), "{line}: {err:#}");
        }
        let ok = import(
            "inside",
            &[("in/x.ovpn", &conf("auth-user-pass sub/up")), ("in/ca.crt", &ca), ("in/sub/up", "alice\n")],
            &[],
        )
        .unwrap();
        assert_eq!(openvpn_profile(&ok).1.username.as_deref(), Some("alice"));
    }

    #[test]
    fn unsupported_configurations_are_refused() {
        let pki = pki();
        let base = format!("client\nremote vpn.example.com\n<ca>\n{}</ca>\nauth-user-pass\n", pki.ca);
        let refused = |extra: &str| {
            import("refused", &[("x.ovpn", &format!("{base}{extra}"))], &[]).err().map(|e| format!("{e:#}"))
        };
        assert!(refused("").is_none());
        assert!(refused("dev tap0").unwrap().contains("tap"));
        assert!(refused("secret static.key").unwrap().contains("static key mode"));
        assert!(refused("<tls-crypt-v2>\nx\n</tls-crypt-v2>").unwrap().contains("tls-crypt-v2"));
        assert!(refused("<tls-auth>\nnot a key\n</tls-auth>").unwrap().contains("tls-auth"));
        assert!(refused("<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n").unwrap().contains("not closed"));
        assert!(refused("mode server").unwrap().contains("server configuration"));
        assert!(refused("proto tcp-server").unwrap().contains("proto"));
        let no_ca = import("noca", &[("x.ovpn", "client\nremote vpn.example.com\nauth-user-pass\n")], &[]);
        assert!(format!("{:#}", no_ca.err().unwrap()).contains("CA"));
        let p12 =
            import("p12", &[("x.ovpn", &format!("remote vpn.example.com\npkcs12 me.p12\n<ca>\n{}</ca>", pki.ca))], &[]);
        assert!(format!("{:#}", p12.err().unwrap()).contains("Keychain"));
    }

    #[test]
    fn options_and_notes() {
        let pki = pki();
        let ovpn = format!(
            "remote vpn.example.com 1194\n<ca>\n{}</ca>\nauth-user-pass\nstatic-challenge \"Enter PIN\" 1\n\
             cipher BF-CBC\ndata-ciphers BF-CBC:AES-128-CBC\ncomp-lzo no\nreneg-sec 30\n\
             http-proxy proxy.example.com 3128\n\
             peer-fingerprint AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\n\
             verify-x509-name 'C=FR, CN=vpn'\n",
            pki.ca
        );
        let imported = import("opts", &[("x.ovpn", &ovpn)], &[]).unwrap();
        let (_, p) = openvpn_profile(&imported);
        assert_eq!(p.static_challenge, Some(StaticChallenge { text: "Enter PIN".into(), echo: true }));
        assert_eq!(p.data_ciphers, OPENVPN_CIPHERS, "nothing usable listed: the defaults, with a note");
        assert!(imported.notes.iter().any(|n| n.contains("none of the data ciphers")));
        assert_eq!((p.compression, p.reneg_sec), (Compression::Lzo, 60));
        assert_eq!(p.trusted_cert, ["abcdef0123456789".repeat(4)]);
        assert_eq!(p.verify_x509_name.unwrap().kind, X509NameKind::Subject);
        assert!(imported.notes.iter().any(|n| n.contains("http-proxy")));
        assert!(imported.notes.iter().any(|n| n.contains("remote-cert-tls server is missing")));
        assert!(!imported.notes.iter().any(|n| n.contains("compression")), "comp-lzo no does not compress");
    }

    #[test]
    fn tokenizer() {
        assert_eq!(tokens("remote  a.example 1194 # comment").unwrap(), ["remote", "a.example", "1194"]);
        assert_eq!(tokens("  ; all comment").unwrap(), Vec::<String>::new());
        assert_eq!(tokens(r#"ca "my keys/ca.crt""#).unwrap(), ["ca", "my keys/ca.crt"]);
        assert_eq!(tokens(r"cert my\ keys/c.crt").unwrap(), ["cert", "my keys/c.crt"]);
        assert_eq!(tokens(r#"x 'a\b' "c\"d" e#f"#).unwrap(), ["x", r"a\b", "c\"d", "e#f"]);
        assert!(tokens("x \"open").is_err());
        assert_eq!(free_name("a", &["a".into(), "a 2".into()]), "a 3");
        assert_eq!(free_name(&"x".repeat(64), &["x".repeat(64)]).len(), 64);
    }

    #[test]
    fn static_key_after_a_comment_naming_its_end() {
        let text = format!("# -----END OpenVPN Static key V1-----\n{KEY}");
        let key = static_key(&text, "tls-auth").unwrap();
        assert!(key.starts_with("-----BEGIN OpenVPN Static key V1-----"), "{key}");
        parse_static_key(&key).unwrap();
    }
}
