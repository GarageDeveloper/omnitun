//! End-to-end tests: the real `FortiSslEngine`, driven through the `Engine`
//! trait, against an in-process fake FortiGate (TLS with a self-signed
//! certificate pinned by SHA-256, portal pages, XML configuration, then a
//! scripted PPP peer inside the tunnel).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use vpn_core::failure::kind_of;
use vpn_core::prompt::TRUST_CERTIFICATE;
use vpn_core::{
    Engine, FailureKind, FortiSslAuth, FortiSslProfile, PacketIo, Prompt, PromptKind, Prompter, SessionContext,
    TunnelSettings, TunnelStats,
};
use vpn_fortissl::FortiSslEngine;

const T: Duration = Duration::from_secs(15);
const COOKIE: &str = "s3ss10n";
const PASSWORD: &str = "secret";
const PIN: &str = "123456";
const SAML_ID: &str = "saml-session-42";

// Addresses handed out by the fake gateway.
const PPP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 212, 134, 200);
const PPP_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2)];

const XML: &str = r#"<?xml version='1.0' encoding='utf-8'?>
<sslvpn-tunnel ver='2' dtls='1' patch='1'>
  <tunnel-method value='ppp'/>
  <ipv4>
    <dns ip='10.1.1.53'/>
    <dns ip='10.1.2.53'/>
    <dns-suffix val='corp.example;lab.example'/>
    <assigned-addr ipv4='10.212.134.199'/>
    <split-tunnel-info>
      <addr ip='10.1.0.0' mask='255.255.0.0'/>
      <addr ip='192.168.50.7' mask='255.255.255.255'/>
    </split-tunnel-info>
    <split-tunnel-info negate='1'>
      <addr ip='10.1.99.0' mask='255.255.255.0'/>
    </split-tunnel-info>
  </ipv4>
  <idle-timeout val='3600'/>
  <auth-timeout val='28800'/>
</sslvpn-tunnel>"#;

// ---------------------------------------------------------------------------
// Fake FortiGate
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum TunnelMode {
    /// Normal PPP peer.
    Ppp,
    /// Answer `/remote/sslvpn-tunnel` with an HTTP error page.
    Refuse,
    /// Bring the link up, then send an LCP Terminate-Request.
    TerminateAfterUp,
}

struct Gateway {
    addr: SocketAddr,
    fingerprint: String,
    log: Arc<Mutex<Vec<String>>>,
}

/// TLS versions and client certificates the gateway asks for.
#[derive(Default)]
struct TlsSetup {
    tls12_only: bool,
    /// Require a client certificate issued by this CA.
    client_ca: Option<CertificateDer<'static>>,
}

impl Gateway {
    async fn start(mode: TunnelMode) -> Self {
        Self::start_with(mode, TlsSetup::default()).await
    }

    async fn start_with(mode: TunnelMode, setup: TlsSetup) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned(), "localhost".to_owned()]).unwrap();
        let der: CertificateDer<'static> = cert.cert.der().clone();
        let fingerprint = hex::encode(ring::digest::digest(&ring::digest::SHA256, &der));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] =
            if setup.tls12_only { &[&rustls::version::TLS12] } else { rustls::DEFAULT_VERSIONS };
        let builder =
            rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).unwrap();
        let builder = match setup.client_ca {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca).unwrap();
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                    .build()
                    .unwrap();
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let config = builder.with_single_cert(vec![der], key).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (acceptor, log) = (acceptor.clone(), log2.clone());
                tokio::spawn(async move {
                    // Handshake failures are expected in the pinning test.
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let (_, session) = tls.get_ref();
                        if session.peer_certificates().is_some() {
                            let version = session.protocol_version().unwrap();
                            log.lock().unwrap().push(format!("client certificate {version:?}"));
                        }
                        serve(tls, mode, log).await;
                    }
                });
            }
        });
        Gateway { addr, fingerprint, log }
    }

    fn profile(&self, username: Option<&str>) -> FortiSslProfile {
        FortiSslProfile {
            host: "127.0.0.1".into(),
            port: self.addr.port(),
            realm: None,
            username: username.map(Into::into),
            auth: FortiSslAuth::Password,
            // Colon-separated upper case, as copied from a browser.
            trusted_cert: vec![colonize(&self.fingerprint.to_ascii_uppercase())],
            ca_file: None,
            client_cert: None,
            client_key: None,
            ca_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
            client_certificate: None,
            client_chain_pem: None,
            keychain_ca_pem: None,
        }
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    async fn wait_for(&self, entry: &str) {
        timeout(T, async {
            while !self.log().iter().any(|e| e == entry) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("gateway never saw {entry:?}; log: {:?}", self.log()));
    }
}

fn colonize(hex: &str) -> String {
    hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":")
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    /// Bytes after the headers: the form body, or the first PPP frames the
    /// client pipelines right after `GET /remote/sslvpn-tunnel`.
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn has_session(&self) -> bool {
        self.header("cookie").is_some_and(|c| c.split(';').any(|kv| kv.trim() == format!("SVPNCOOKIE={COOKIE}")))
    }

    fn form(&self) -> HashMap<String, String> {
        std::str::from_utf8(&self.body)
            .unwrap()
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), urldecode(v)))
            .collect()
    }
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap());
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

async fn read_request<S: AsyncRead + Unpin>(s: &mut S) -> Option<Request> {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        let mut chunk = [0u8; 1024];
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..end].to_vec()).unwrap();
    let mut body = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let mut start = lines.next().unwrap().split(' ');
    let (method, path) = (start.next().unwrap().to_owned(), start.next().unwrap().to_owned());
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())).collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.parse::<usize>().unwrap());
    while body.len() < len {
        let mut chunk = [0u8; 1024];
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Request { method, path, headers, body })
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, status: &str, extra_headers: &[&str], body: &str) {
    let mut resp = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for h in extra_headers {
        resp.push_str(h);
        resp.push_str("\r\n");
    }
    resp.push_str("\r\n");
    resp.push_str(body);
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

/// Same as `respond` but with chunked transfer encoding and no length.
async fn respond_chunked<S: AsyncWrite + Unpin>(s: &mut S, body: &str) {
    let mut resp = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/xml\r\n\r\n");
    for part in body.as_bytes().chunks(100) {
        resp.push_str(&format!("{:x};ext=1\r\n", part.len()));
        resp.push_str(std::str::from_utf8(part).unwrap());
        resp.push_str("\r\n");
    }
    resp.push_str("0\r\n\r\n");
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, mode: TunnelMode, log: Arc<Mutex<Vec<String>>>) {
    let Some(req) = read_request(&mut s).await else { return };
    let push = |e: String| log.lock().unwrap().push(e);
    let (route, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
    push(format!("{} {route}", req.method));
    let session_cookie = format!("Set-Cookie: SVPNCOOKIE={COOKIE}; path=/; secure; httponly");

    match (req.method.as_str(), route) {
        ("POST", "/remote/logincheck") => {
            assert_eq!(req.header("content-type"), Some("application/x-www-form-urlencoded"));
            let form = req.form();
            let user = form.get("username").cloned().unwrap_or_default();
            if let Some(code) = form.get("code") {
                // Second round of a FortiToken challenge.
                assert_eq!(form.get("reqid").map(String::as_str), Some("9876"));
                assert_eq!(form.get("magic").map(String::as_str), Some("1-4c"));
                assert!(!form.contains_key("credential"), "password must not be resent with the code");
                push(format!("code={code}"));
                if code == PIN {
                    respond(&mut s, "200 OK", &[&session_cookie], "ret=1,redir=/remote/index\n").await;
                } else {
                    respond(
                        &mut s,
                        "401 Unauthorized",
                        &[],
                        "ret=0,redir=/remote/login?&err=sslvpn_login_auth_failed\n",
                    )
                    .await;
                }
                return;
            }
            let ok = form.get("credential").map(String::as_str) == Some(PASSWORD);
            assert_eq!(form.get("ajax").map(String::as_str), Some("1"));
            assert_eq!(form.get("realm").map(String::as_str), Some(""));
            match (ok, user.as_str()) {
                (false, _) => {
                    let body = "ret=0,redir=/remote/login?&lang=en\n<!--sslvpnerrmsg=Invalid credentials-->";
                    respond(&mut s, "401 Unauthorized", &[], body).await
                }
                (true, "tokenuser" | "radiususer") => {
                    // Empty cookie: must not be mistaken for a session.
                    let token = if user == "tokenuser" { "ftm" } else { "" };
                    let body = format!(
                        "ret=2,reqid=9876,polid=1-1-3,grp=vpn,portal=full,peer=,magic=1-4c,tokeninfo={token},chal_msg=Enter FortiToken code"
                    );
                    respond(&mut s, "200 OK", &["Set-Cookie: SVPNCOOKIE=; path=/"], &body).await
                }
                (true, _) => respond(&mut s, "200 OK", &[&session_cookie], "ret=1,redir=/remote/index\n").await,
            }
        }
        ("GET", "/remote/saml/auth_id") => {
            if query == format!("id={SAML_ID}") {
                respond(&mut s, "200 OK", &[&session_cookie], "<html>ok</html>").await
            } else {
                respond(&mut s, "403 Forbidden", &[], "<html><!--sslvpnerrmsg=Bad SAML id--></html>").await
            }
        }
        ("GET", "/remote/index") | ("GET", "/remote/fortisslvpn") => {
            assert!(req.has_session(), "{route} without session cookie");
            respond(&mut s, "200 OK", &[], "<html>portal</html>").await
        }
        ("GET", "/remote/fortisslvpn_xml") => {
            assert!(req.has_session());
            respond_chunked(&mut s, XML).await
        }
        ("GET", "/remote/logout") => {
            assert!(req.has_session());
            respond(&mut s, "200 OK", &[], "").await
        }
        ("GET", "/remote/sslvpn-tunnel") => {
            assert!(req.has_session());
            if mode == TunnelMode::Refuse {
                respond(&mut s, "403 Forbidden", &[], "denied").await;
                return;
            }
            ppp_peer(Conn { s, pending: req.body }, mode, &log).await;
        }
        _ => respond(&mut s, "404 Not Found", &[], "").await,
    }
}

// --- PPP peer --------------------------------------------------------------

const LCP: u16 = 0xc021;
const IPCP: u16 = 0x8021;
const IP: u16 = 0x0021;

fn cp_frame(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut f = proto.to_be_bytes().to_vec();
    f.extend_from_slice(&[code, id]);
    f.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// Tunnel connection with the bytes already read along with the request.
struct Conn<S> {
    s: S,
    pending: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    async fn read_exact(&mut self, out: &mut [u8]) -> Option<()> {
        let from_pending = out.len().min(self.pending.len());
        out[..from_pending].copy_from_slice(&self.pending[..from_pending]);
        self.pending.drain(..from_pending);
        self.s.read_exact(&mut out[from_pending..]).await.ok()?;
        Some(())
    }

    async fn write_frame(&mut self, payload: &[u8]) {
        let mut out = ((payload.len() + 6) as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&[0x50, 0x50]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        self.s.write_all(&out).await.unwrap();
        self.s.flush().await.unwrap();
    }

    async fn read_frame(&mut self) -> Option<Vec<u8>> {
        let mut h = [0u8; 6];
        self.read_exact(&mut h).await?;
        assert_eq!(&h[2..4], &[0x50, 0x50], "bad magic from client");
        let total = u16::from_be_bytes([h[0], h[1]]) as usize;
        let size = u16::from_be_bytes([h[4], h[5]]) as usize;
        assert_eq!(total, size + 6, "inconsistent frame lengths from client");
        let mut p = vec![0u8; size];
        self.read_exact(&mut p).await?;
        Some(p)
    }
}

fn options(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let len = data[1] as usize;
        out.push((data[0], data[2..len].to_vec()));
        data = &data[len..];
    }
    out
}

async fn ppp_peer<S: AsyncRead + AsyncWrite + Unpin>(mut s: Conn<S>, mode: TunnelMode, log: &Arc<Mutex<Vec<String>>>) {
    let push = |e: &str| log.lock().unwrap().push(e.to_owned());
    // Our own LCP Configure-Request: MRU 1400, magic.
    s.write_frame(&cp_frame(LCP, 1, 1, &[1, 4, 0x05, 0x78, 5, 6, 0x11, 0x22, 0x33, 0x44])).await;
    let mut ipcp_up = false;
    loop {
        let Some(frame) = s.read_frame().await else {
            push("tunnel closed");
            return;
        };
        let proto = u16::from_be_bytes([frame[0], frame[1]]);
        let (code, id, data) = match proto {
            IP => {
                push("ip");
                // Echo the packet back to the client.
                s.write_frame(&frame).await;
                continue;
            }
            _ => {
                let len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
                (frame[2], frame[3], frame[6..2 + len].to_vec())
            }
        };
        match (proto, code) {
            (LCP, 1) => {
                push("lcp req");
                s.write_frame(&cp_frame(LCP, 2, id, &data)).await;
            }
            (LCP, 2) => {
                push("lcp ack");
                s.write_frame(&cp_frame(IPCP, 1, 1, &[3, 6, 169, 254, 2, 1])).await;
            }
            (LCP, 5) => {
                push("lcp term-req");
                s.write_frame(&cp_frame(LCP, 6, id, &[])).await;
                return;
            }
            (LCP, 9) => {
                let mut reply = vec![0x11, 0x22, 0x33, 0x44];
                reply.extend_from_slice(&data[4..]);
                s.write_frame(&cp_frame(LCP, 10, id, &reply)).await;
            }
            (IPCP, 1) => {
                let opts = options(&data);
                let wanted: Vec<(u8, [u8; 4])> =
                    vec![(3, PPP_ADDR.octets()), (129, PPP_DNS[0].octets()), (131, PPP_DNS[1].octets())];
                let mut nak = Vec::new();
                for (ty, val) in &opts {
                    if let Some((_, want)) = wanted.iter().find(|(t, _)| t == ty)
                        && val.as_slice() != want
                    {
                        nak.extend_from_slice(&[*ty, 6]);
                        nak.extend_from_slice(want);
                    }
                }
                if nak.is_empty() {
                    push("ipcp ack");
                    s.write_frame(&cp_frame(IPCP, 2, id, &data)).await;
                } else {
                    push("ipcp nak");
                    s.write_frame(&cp_frame(IPCP, 3, id, &nak)).await;
                }
            }
            (IPCP, 2) => {
                push("ipcp up");
                ipcp_up = true;
                // Also probe the client's echo handling and protocol reject.
                s.write_frame(&cp_frame(LCP, 9, 77, &[0xde, 0xad, 0xbe, 0xef, 1, 2])).await;
                s.write_frame(&cp_frame(0x8057, 1, 1, &[])).await;
                if mode == TunnelMode::TerminateAfterUp {
                    s.write_frame(&cp_frame(LCP, 5, 99, &[])).await;
                }
            }
            (LCP, 10) => {
                assert_eq!(id, 77);
                push("echo reply");
            }
            (LCP, 8) => {
                assert_eq!(&data[..2], &[0x80, 0x57]);
                push("proto rej");
            }
            (LCP, 6) => push("lcp term-ack"),
            other => panic!("unexpected PPP frame {other:x?} (ipcp_up={ipcp_up})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Client side helpers
// ---------------------------------------------------------------------------

type Browser = Box<dyn FnOnce(String) + Send>;

/// Answers prompts from a fixed table and records what was asked.
#[derive(Default)]
struct Script {
    answers: HashMap<String, String>,
    asked: Mutex<Vec<Prompt>>,
    /// SAML: run this when the engine asks to open a URL.
    browser: Mutex<Option<Browser>>,
    opened: Mutex<Vec<String>>,
    /// Signs as the user's client would, with its checks.
    client_key: Option<(String, Arc<dyn rustls::sign::SigningKey>)>,
}

#[async_trait]
impl Prompter for Script {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<String> {
        self.asked.lock().unwrap().push(prompt.clone());
        if let (Some(request), Some((sha256, key))) = (&prompt.sign, &self.client_key) {
            anyhow::ensure!(&request.certificate == sha256, "another certificate");
            let data = hex::decode(&request.data)?;
            anyhow::ensure!(vpn_core::prompt::is_tls_client_signature_octets(&data), "not a TLS signature");
            use rustls::SignatureScheme as S;
            use vpn_core::SignAlgorithm as A;
            let scheme = match request.algorithm {
                A::RsaPssSha256 => S::RSA_PSS_SHA256,
                A::RsaPkcs1Sha256 => S::RSA_PKCS1_SHA256,
                A::EcdsaSha256 => S::ECDSA_NISTP256_SHA256,
                A::EcdsaSha384 => S::ECDSA_NISTP384_SHA384,
                other => anyhow::bail!("unexpected {other:?}"),
            };
            self.asked.lock().unwrap().last_mut().unwrap().message = format!("{:?}", request.algorithm);
            return Ok(hex::encode(key.choose_scheme(&[scheme]).unwrap().sign(&data)?));
        }
        match self.answers.get(prompt.key.as_str()) {
            Some(v) => Ok(v.clone()),
            None => anyhow::bail!("unexpected prompt {}", prompt.key),
        }
    }

    async fn open_url(&self, url: &str) -> anyhow::Result<()> {
        self.opened.lock().unwrap().push(url.to_owned());
        if let Some(browser) = self.browser.lock().unwrap().take() {
            browser(url.to_owned());
        }
        Ok(())
    }
}

fn context(script: Arc<Script>) -> SessionContext {
    SessionContext {
        name: "test".into(),
        prompter: script,
        cancel: CancellationToken::new(),
        stats: Arc::new(TunnelStats::default()),
    }
}

fn script(answers: &[(&str, &str)]) -> Arc<Script> {
    Arc::new(Script {
        answers: answers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        ..Default::default()
    })
}

async fn connect(engine: &mut FortiSslEngine, ctx: &SessionContext) -> anyhow::Result<TunnelSettings> {
    timeout(T, engine.connect(ctx)).await.expect("connect timed out")
}

fn assert_settings(s: &TunnelSettings, gw: &Gateway) {
    assert_eq!(s.address, PPP_ADDR, "PPP-assigned address wins over the XML one");
    assert_eq!(s.mtu, 1354);
    assert_eq!(s.routes, vec!["10.1.0.0/16".parse().unwrap(), "192.168.50.7/32".parse().unwrap()]);
    assert_eq!(s.excluded_routes, vec!["10.1.99.0/24".parse().unwrap()]);
    assert!(!s.full_tunnel);
    // DNS servers pushed in the XML take precedence over IPCP.
    let servers: Vec<IpAddr> = vec![Ipv4Addr::new(10, 1, 1, 53).into(), Ipv4Addr::new(10, 1, 2, 53).into()];
    assert_eq!(s.dns.servers, servers);
    assert_eq!(s.dns.search_domains, vec!["corp.example", "lab.example"]);
    assert_eq!(s.dns.match_domains, vec!["corp.example", "lab.example"]);
    assert_eq!(s.gateway, gw.addr.ip());
}

/// A minimal IPv4/ICMP echo request.
fn ip_packet(seq: u8) -> Bytes {
    let mut p = vec![0x45, 0, 0, 28, 0, seq, 0, 0, 64, 1, 0, 0, 10, 212, 134, 200, 10, 1, 1, 1];
    p.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, seq]);
    Bytes::from(p)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn password_login_tunnel_roundtrip_cancel_and_logout() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let prompts = script(&[("username", "alice"), ("password", PASSWORD)]);
    let ctx = context(prompts.clone());
    let mut engine = FortiSslEngine::new(gw.profile(None));

    let settings = connect(&mut engine, &ctx).await.unwrap();
    assert_settings(&settings, &gw);
    let asked = prompts.asked.lock().unwrap().clone();
    assert_eq!(
        asked.iter().map(|p| (p.key.as_str(), p.kind)).collect::<Vec<_>>(),
        vec![("username", PromptKind::Text), ("password", PromptKind::Secret)]
    );
    assert!(asked[1].message.contains("alice@127.0.0.1"), "{}", asked[1].message);
    for step in
        ["POST /remote/logincheck", "GET /remote/index", "GET /remote/fortisslvpn", "GET /remote/fortisslvpn_xml"]
    {
        assert!(gw.log().iter().any(|e| e == step), "missing {step}: {:?}", gw.log());
    }
    assert!(gw.log().iter().any(|e| e == "ipcp nak"), "client should first ask with 0.0.0.0");

    // Packets flow both ways through PacketIo.
    let (to_tun, mut tun_rx) = mpsc::channel(16);
    let (tun_tx, from_tun) = mpsc::channel(16);
    let run_ctx = ctx.clone();
    let run = tokio::spawn(async move {
        let r = engine.run(&run_ctx, PacketIo { to_tun, from_tun }).await;
        (engine, r)
    });
    for seq in 1..=3u8 {
        tun_tx.send(ip_packet(seq)).await.unwrap();
        let echoed = timeout(T, tun_rx.recv()).await.expect("no echo").expect("tun channel closed");
        assert_eq!(echoed, ip_packet(seq));
    }
    gw.wait_for("echo reply").await;
    gw.wait_for("proto rej").await;
    assert_eq!(ctx.stats.tx_packets.load(Ordering::Relaxed), 3);
    assert_eq!(ctx.stats.rx_packets.load(Ordering::Relaxed), 3);
    assert_eq!(ctx.stats.rx_bytes.load(Ordering::Relaxed), 3 * 28);

    // Cancel: run returns Ok and the gateway receives an LCP Terminate-Request.
    ctx.cancel.cancel();
    let (mut engine, result) = timeout(T, run).await.expect("run did not stop on cancel").unwrap();
    result.unwrap();
    gw.wait_for("lcp term-req").await;

    timeout(T, engine.disconnect()).await.unwrap().unwrap();
    gw.wait_for("GET /remote/logout").await;
    // Calling run again after the session ended is an error, not a panic.
    let (to_tun, _r) = mpsc::channel(1);
    let (_t, from_tun) = mpsc::channel(1);
    assert!(engine.run(&ctx, PacketIo { to_tun, from_tun }).await.is_err());
}

#[tokio::test]
async fn fortitoken_challenge_round() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let prompts = script(&[("password", PASSWORD), ("otp", PIN)]);
    let ctx = context(prompts.clone());
    let mut engine = FortiSslEngine::new(gw.profile(Some("tokenuser")));

    let settings = connect(&mut engine, &ctx).await.unwrap();
    assert_settings(&settings, &gw);
    let asked = prompts.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    assert_eq!((asked[1].key.as_str(), asked[1].kind), ("otp", PromptKind::Otp));
    assert_eq!(asked[1].message, "Enter FortiToken code");
    assert_eq!(asked[1].digits, 6, "a FortiToken code");
    assert!(gw.log().contains(&format!("code={PIN}")));
    engine.disconnect().await.unwrap();
    gw.wait_for("GET /remote/logout").await;
}

/// A RADIUS challenge may want a PIN and a token code, or letters: the
/// client sends what the user typed.
#[tokio::test]
async fn radius_challenge_is_free_text() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let prompts = script(&[("password", PASSWORD), ("otp", PIN)]);
    let ctx = context(prompts.clone());
    let mut engine = FortiSslEngine::new(gw.profile(Some("radiususer")));

    connect(&mut engine, &ctx).await.unwrap();
    let asked = prompts.asked.lock().unwrap().clone();
    assert_eq!((asked[1].kind, asked[1].digits), (PromptKind::Otp, 0));
    engine.disconnect().await.unwrap();
    gw.wait_for("GET /remote/logout").await;
}

#[tokio::test]
async fn wrong_password_is_reported() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let ctx = context(script(&[("password", "nope")]));
    let mut engine = FortiSslEngine::new(gw.profile(Some("alice")));
    let err = format!("{:#}", connect(&mut engine, &ctx).await.unwrap_err());
    assert!(err.contains("wrong credentials"), "{err}");
    assert!(err.contains("Invalid credentials"), "portal hint should be surfaced: {err}");
    assert!(!gw.log().iter().any(|e| e.contains("/remote/index")), "must stop after the failed login");
}

#[tokio::test]
async fn wrong_pin_is_reported() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let ctx = context(script(&[("password", PASSWORD), ("otp", "000000")]));
    let mut engine = FortiSslEngine::new(gw.profile(Some("tokenuser")));
    let err = connect(&mut engine, &ctx).await.unwrap_err();
    assert_eq!(kind_of(&err), FailureKind::OtpRejected, "{err:#}");
    assert!(gw.log().contains(&"code=000000".to_owned()));
}

#[tokio::test]
async fn cancelled_prompt_aborts_login() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    // No answer for "password": the prompter fails, as when the user cancels.
    let ctx = context(script(&[]));
    let mut engine = FortiSslEngine::new(gw.profile(Some("alice")));
    let err = format!("{:#}", connect(&mut engine, &ctx).await.unwrap_err());
    assert!(err.contains("unexpected prompt password"), "{err}");
    assert!(gw.log().is_empty(), "nothing sent before the password is known");
}

#[tokio::test]
async fn certificate_pin_mismatch_is_refused() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let prompts = script(&[("password", PASSWORD)]);
    let ctx = context(prompts.clone());
    let mut profile = gw.profile(Some("alice"));
    profile.trusted_cert = vec!["00".repeat(32)];
    let err = connect(&mut FortiSslEngine::new(profile.clone()), &ctx).await.unwrap_err();
    let FailureKind::CertificateChanged { certificate, pinned } = kind_of(&err) else { panic!("{err:#}") };
    assert_eq!(certificate.sha256, gw.fingerprint);
    assert_eq!(pinned, ["00".repeat(32)]);
    assert!(
        !prompts.asked.lock().unwrap().iter().any(|p| p.key == TRUST_CERTIFICATE),
        "a changed pin is never offered"
    );

    profile.trusted_cert = vec!["not-a-digest".into()];
    let err = format!("{:#}", connect(&mut FortiSslEngine::new(profile), &ctx).await.unwrap_err());
    assert!(err.contains("not a SHA-256 hex digest"), "{err}");
    assert!(!gw.log().iter().any(|e| e.starts_with("POST")), "no credentials sent to an untrusted gateway");
}

#[tokio::test]
async fn unknown_certificate_is_offered_before_any_secret() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let mut profile = gw.profile(Some("alice"));
    profile.trusted_cert.clear();

    // Declined (no answer): the failure carries the certificate.
    let prompts = script(&[("password", PASSWORD)]);
    let ctx = context(prompts.clone());
    let err = connect(&mut FortiSslEngine::new(profile.clone()), &ctx).await.unwrap_err();
    let FailureKind::CertificateUntrusted { certificate } = kind_of(&err) else { panic!("{err:#}") };
    assert_eq!(certificate.sha256, gw.fingerprint);
    assert!(!certificate.der.is_empty());
    let asked = prompts.asked.lock().unwrap().clone();
    assert_eq!(asked[0].key, TRUST_CERTIFICATE, "asked before the password");
    assert!(!asked.iter().any(|p| p.key == "password"));

    // An answer naming another certificate does not trust this one.
    let ctx = context(script(&[(TRUST_CERTIFICATE, &"ab".repeat(32)), ("password", PASSWORD)]));
    let err = connect(&mut FortiSslEngine::new(profile.clone()), &ctx).await.unwrap_err();
    assert!(matches!(kind_of(&err), FailureKind::CertificateUntrusted { .. }), "{err:#}");
    assert!(!gw.log().iter().any(|e| e.starts_with("POST")));

    // Accepted: the connection goes on with that certificate pinned.
    let fingerprint = gw.fingerprint.clone();
    let ctx = context(script(&[(TRUST_CERTIFICATE, &fingerprint), ("password", PASSWORD)]));
    let mut engine = FortiSslEngine::new(profile);
    connect(&mut engine, &ctx).await.unwrap();
    engine.disconnect().await.unwrap();
}

#[tokio::test]
async fn tunnel_refused_by_gateway() {
    let gw = Gateway::start(TunnelMode::Refuse).await;
    let ctx = context(script(&[("password", PASSWORD)]));
    let mut engine = FortiSslEngine::new(gw.profile(Some("alice")));
    let err = format!("{:#}", connect(&mut engine, &ctx).await.unwrap_err());
    assert!(err.contains("gateway refused the tunnel"), "{err}");
}

#[tokio::test]
async fn gateway_terminating_link_ends_run_with_error() {
    let gw = Gateway::start(TunnelMode::TerminateAfterUp).await;
    let ctx = context(script(&[("password", PASSWORD)]));
    let mut engine = FortiSslEngine::new(gw.profile(Some("alice")));
    // The Terminate-Request may arrive during negotiation or once running;
    // either way the session must end with an error, not hang.
    let result = match connect(&mut engine, &ctx).await {
        Err(e) => Err(e),
        Ok(_) => {
            let (to_tun, _rx) = mpsc::channel(16);
            let (_tx, from_tun) = mpsc::channel(16);
            timeout(T, engine.run(&ctx, PacketIo { to_tun, from_tun })).await.expect("run hung")
        }
    };
    let err = format!("{:#}", result.unwrap_err());
    assert!(err.contains("terminated by gateway"), "{err}");
    gw.wait_for("lcp term-ack").await;
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Plays the browser: sends the given request to the SAML callback port and
/// returns the HTTP status line.
async fn browser_get(port: u16, target: &str, dest: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Dest: {dest}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out.lines().next().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn saml_login_via_browser_callback() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let port = free_port();
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let prompts = script(&[]);
    let statuses2 = statuses.clone();
    *prompts.browser.lock().unwrap() = Some(Box::new(move |_url| {
        tokio::spawn(async move {
            let mut st = Vec::new();
            // Planted sub-resource requests and wrong paths are ignored...
            st.push(browser_get(port, &format!("/?id={SAML_ID}"), "image").await);
            st.push(browser_get(port, "/favicon.ico", "document").await);
            st.push(browser_get(port, "/?id=", "document").await);
            // ...the real top-level redirect completes the login.
            st.push(browser_get(port, &format!("/?foo=1&id={SAML_ID}"), "document").await);
            statuses2.lock().unwrap().extend(st);
        });
    }));
    let ctx = context(prompts.clone());
    let mut profile = gw.profile(None);
    profile.auth = FortiSslAuth::Saml { port };
    let mut engine = FortiSslEngine::new(profile);

    let settings = connect(&mut engine, &ctx).await.unwrap();
    assert_settings(&settings, &gw);
    assert_eq!(
        *prompts.opened.lock().unwrap(),
        vec![format!("https://127.0.0.1:{}/remote/saml/start?redirect=1", gw.addr.port())]
    );
    assert!(prompts.asked.lock().unwrap().is_empty(), "SAML needs no prompt");
    timeout(T, async {
        while statuses.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let st = statuses.lock().unwrap().clone();
    assert!(st[..3].iter().all(|s| s.contains("404")), "{st:?}");
    assert!(st[3].contains("200"), "{st:?}");
    engine.disconnect().await.unwrap();
}

#[tokio::test]
async fn saml_bad_id_is_rejected_and_cancel_works() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let port = free_port();
    let prompts = script(&[]);
    *prompts.browser.lock().unwrap() = Some(Box::new(move |_url| {
        tokio::spawn(async move {
            browser_get(port, "/?id=forged", "document").await;
        });
    }));
    let ctx = context(prompts);
    let mut profile = gw.profile(None);
    profile.auth = FortiSslAuth::Saml { port };
    let err = format!("{:#}", connect(&mut FortiSslEngine::new(profile.clone()), &ctx).await.unwrap_err());
    assert!(err.contains("SAML login rejected by gateway (HTTP 403)"), "{err}");
    assert!(err.contains("Bad SAML id"), "{err}");

    // Nobody completes the browser login: cancellation ends the wait.
    let ctx = context(script(&[]));
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
    });
    let err = format!("{:#}", connect(&mut FortiSslEngine::new(profile), &ctx).await.unwrap_err());
    assert!(err.contains("SAML login cancelled"), "{err}");
}

/// A CA, and a client certificate it issued with the key `key` (PEM),
/// for an engine that signs through its prompter.
fn client_certificate(
    key: &str,
    alg: &'static rcgen::SignatureAlgorithm,
) -> (CertificateDer<'static>, String, Arc<dyn rustls::sign::SigningKey>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let key_pair = rcgen::KeyPair::from_pem_and_sign_algo(key, alg).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "alice");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key_pair, &issuer).unwrap();
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&der).unwrap();
    (ca_cert.der().clone(), cert.pem(), signing)
}

/// The engine never holds the key: each handshake signature is asked to
/// the client, RSA-PSS in TLS 1.3 and ECDSA P-384 in TLS 1.2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_certificate_signs_through_the_client() {
    let rsa_key = include_str!("data/client-rsa.key");
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap().serialize_pem();
    for (key, alg, tls12_only, algorithm) in [
        (rsa_key, &rcgen::PKCS_RSA_SHA256, false, "RsaPssSha256"),
        (p384.as_str(), &rcgen::PKCS_ECDSA_P384_SHA384, true, "EcdsaSha384"),
    ] {
        let (ca, pem, signing) = client_certificate(key, alg);
        let gw = Gateway::start_with(TunnelMode::Ppp, TlsSetup { tls12_only, client_ca: Some(ca) }).await;
        let leaf: CertificateDer = rustls::pki_types::pem::PemObject::from_pem_slice(pem.as_bytes()).unwrap();
        let sha256 = hex::encode(ring::digest::digest(&ring::digest::SHA256, &leaf));
        let prompts = Arc::new(Script {
            answers: [("username", "alice"), ("password", PASSWORD)].map(|(k, v)| (k.into(), v.into())).into(),
            client_key: Some((sha256, signing)),
            ..Default::default()
        });
        let ctx = context(prompts.clone());
        let mut profile = gw.profile(None);
        profile.client_cert_pem = Some(pem);
        let mut engine = FortiSslEngine::new(profile);
        connect(&mut engine, &ctx).await.unwrap();
        let version = if tls12_only { "TLSv1_2" } else { "TLSv1_3" };
        assert!(gw.log().contains(&format!("client certificate {version}")), "{:?}", gw.log());
        let signed: Vec<_> = prompts
            .asked
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.kind == PromptKind::Sign)
            .map(|p| p.message.clone())
            .collect();
        assert!(!signed.is_empty() && signed.iter().all(|m| m == algorithm), "{signed:?}");
        // Resumed sessions sign once, not for every HTTPS request.
        assert!(signed.len() <= 2, "{signed:?}");
        timeout(T, engine.disconnect()).await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_signature_is_reported() {
    let p256 = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let (ca, pem, _) = client_certificate(&p256, &rcgen::PKCS_ECDSA_P256_SHA256);
    let gw = Gateway::start_with(TunnelMode::Ppp, TlsSetup { client_ca: Some(ca), ..Default::default() }).await;
    let ctx = context(script(&[]));
    let mut profile = gw.profile(None);
    profile.client_cert_pem = Some(pem);
    let error = connect(&mut FortiSslEngine::new(profile), &ctx).await.unwrap_err();
    assert!(format!("{error:#}").contains("cannot sign with the client certificate"), "{error:#}");
}

#[tokio::test]
async fn the_engine_refuses_a_client_key() {
    let gw = Gateway::start(TunnelMode::Ppp).await;
    let mut profile = gw.profile(None);
    profile.client_key_pem = Some("-----BEGIN PRIVATE KEY-----".into());
    let error = connect(&mut FortiSslEngine::new(profile), &context(script(&[]))).await.unwrap_err();
    assert!(format!("{error:#}").contains("stays with the user's client"), "{error:#}");
}
