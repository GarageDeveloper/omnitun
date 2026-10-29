//! Portal authentication: password (+ FortiToken/OTP challenge) and SAML.
//! Both end with an `SVPNCOOKIE` session cookie in the client's jar.

use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vpn_core::failure::kind_of;
use vpn_core::{FailureKind, FortiSslProfile, Prompt, PromptKind, SessionContext, failure};

use crate::http::{Client, Response};

const MAX_CHALLENGES: usize = 3;
const SAML_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-connection limit for the browser callback request.
const SAML_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn password_login(
    client: &mut Client,
    profile: &FortiSslProfile,
    ctx: &SessionContext,
) -> anyhow::Result<()> {
    let username = match &profile.username {
        Some(u) => u.clone(),
        None => ask(ctx, "username", PromptKind::Text, format!("Username for {}", profile.host)).await?.to_string(),
    };
    let password =
        ask(ctx, "password", PromptKind::Secret, format!("Password for {username}@{}", profile.host)).await?;
    let realm = profile.realm.clone().unwrap_or_default();

    let resp = client
        .post_form(
            "/remote/logincheck",
            &[
                ("ajax", "1"),
                ("username", &username),
                ("realm", &realm),
                ("credential", &password),
                ("just_logged_in", "1"),
            ],
        )
        .await?;
    let mut reply = check_reply(client, &resp)?;

    for _ in 0..MAX_CHALLENGES {
        let Reply::Challenge(fields) = reply else {
            return Ok(());
        };
        let token = field(&fields, "tokeninfo");
        let push = token == "ftm_push";
        let message = match field(&fields, "chal_msg") {
            "" if push => "FortiToken code (leave empty to approve the push notification)".to_owned(),
            "" => "FortiToken / one-time code".to_owned(),
            msg => msg.to_owned(),
        };
        // A FortiGate token (FortiToken, e-mail, SMS) is a 6-digit code; a
        // RADIUS challenge (no token info) may want a PIN and a code, or
        // letters, so it is sent as typed.
        let digits = if token.is_empty() { 0 } else { 6 };
        let prompt = Prompt { push, digits, ..Prompt::new("otp", PromptKind::Otp, message) };
        let code = ctx.prompter.ask(prompt).await?;

        let mut form = vec![("ajax", "1"), ("username", username.as_str()), ("realm", realm.as_str())];
        for key in ["reqid", "polid", "grp", "portal", "peer", "magic"] {
            form.push((key, field(&fields, key)));
        }
        if push && code.trim().is_empty() {
            form.push(("ftmpush", "1"));
        } else {
            form.push(("code", code.trim()));
            form.push(("code2", ""));
        }
        let resp = client.post_form("/remote/logincheck", &form).await?;
        reply = check_reply(client, &resp).map_err(|e| match kind_of(&e) {
            FailureKind::AuthFailed => failure(FailureKind::OtpRejected, "the code or push approval was refused"),
            _ => e,
        })?;
    }
    match reply {
        Reply::Success => Ok(()),
        Reply::Challenge(_) => bail!("authentication failed: too many challenges"),
    }
}

pub async fn saml_login(
    client: &mut Client,
    profile: &FortiSslProfile,
    port: u16,
    ctx: &SessionContext,
) -> anyhow::Result<()> {
    // Listen before opening the browser so the redirect cannot be missed.
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("cannot listen on 127.0.0.1:{port} for the SAML redirect"))?;
    let url = if profile.port == 443 {
        format!("https://{}/remote/saml/start?redirect=1", profile.host)
    } else {
        format!("https://{}:{}/remote/saml/start?redirect=1", profile.host, profile.port)
    };
    ctx.prompter.open_url(&url).await?;
    tracing::info!(session = ctx.name, "waiting for SAML login in the browser");

    let id = tokio::select! {
        id = wait_saml_redirect(&listener) => id?,
        _ = tokio::time::sleep(SAML_TIMEOUT) => return Err(failure(FailureKind::Timeout, "SAML login timed out")),
        _ = ctx.cancel.cancelled() => return Err(failure(FailureKind::Cancelled, "SAML login cancelled")),
    };
    let resp = client.get(&format!("/remote/saml/auth_id?id={}", crate::http::urlencode(&id))).await?;
    if client.session_cookie().is_none() {
        bail!("SAML login rejected by gateway (HTTP {}){}", resp.status, portal_error(&resp));
    }
    Ok(())
}

/// Accepts browser connections until one carries `?id=<saml session>`.
///
/// Each connection is served on its own task with a short read timeout so
/// an idle local connection cannot hold the login. Only a top-level
/// navigation to `GET /?id=` is accepted: an `<img>` or `fetch()` planted by
/// a web page announces another destination through `Sec-Fetch-Dest`.
async fn wait_saml_redirect(listener: &TcpListener) -> anyhow::Result<String> {
    let (found_tx, mut found_rx) = tokio::sync::mpsc::channel::<String>(1);
    // Connections served at once: a local flood cannot exhaust descriptors
    // and end the login.
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let slot = tokio::select! {
            Some(id) = found_rx.recv() => return Ok(id),
            slot = slots.clone().acquire_owned() => slot?,
        };
        let sock = tokio::select! {
            Some(id) = found_rx.recv() => return Ok(id),
            accepted = listener.accept() => match accepted {
                Ok((sock, _)) => sock,
                // Out of descriptors, or a connection reset before it was
                // accepted: the browser's may still come.
                Err(e) => {
                    tracing::debug!("SAML listener: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let found_tx = found_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(id)) = tokio::time::timeout(SAML_READ_TIMEOUT, serve_saml_callback(sock)).await {
                let _ = found_tx.try_send(id);
            }
            drop(slot);
        });
    }
}

async fn serve_saml_callback(mut sock: tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 8192];
    let mut len = 0;
    while len < buf.len() && !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut buf[len..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => len += n,
        }
    }
    let request = String::from_utf8_lossy(&buf[..len]);
    let mut lines = request.lines();
    let mut start = lines.next().unwrap_or_default().split_whitespace();
    let (method, target) = (start.next().unwrap_or_default(), start.next().unwrap_or_default());
    let dest_ok = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("sec-fetch-dest"))
        .is_none_or(|(_, value)| value.trim().eq_ignore_ascii_case("document"));
    let id = (method == "GET" && target.starts_with("/?") && dest_ok).then(|| saml_id(target)).flatten();
    let (status, body) = match &id {
        Some(_) => (
            "200 OK",
            "<html><body><h3>VPN authentication complete.</h3><p>You can close this window.</p></body></html>",
        ),
        None => ("404 Not Found", "<html><body>Not found</body></html>"),
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(reply.as_bytes()).await;
    let _ = sock.shutdown().await;
    id
}

fn saml_id(target: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "id")
        .map(|(_, v)| v.to_owned())
        .filter(|v| !v.is_empty())
}

#[derive(Debug, PartialEq)]
enum Reply {
    Success,
    Challenge(Vec<(String, String)>),
}

fn check_reply(client: &Client, resp: &Response) -> anyhow::Result<Reply> {
    let text = resp.text();
    if text.contains("permission_denied")
        || text.contains("Permission denied")
        || text.contains("sslvpnerrmsgkey=sslvpn_login_permission_denied")
    {
        return Err(failure(
            FailureKind::PermissionDenied,
            "permission denied: this user is not allowed to use the SSL VPN",
        ));
    }
    if resp.status != 200 && resp.status != 401 {
        bail!("login failed: HTTP {}{}", resp.status, portal_error(resp));
    }
    if client.session_cookie().is_some() {
        return Ok(Reply::Success);
    }
    let fields = parse_ret_fields(&text);
    match field(&fields, "ret") {
        "0" => Err(failure(
            FailureKind::AuthFailed,
            format!("authentication failed: wrong credentials{}", portal_error(resp)),
        )),
        "6" => bail!("authentication failed: unsupported challenge from gateway"),
        _ if fields.iter().any(|(k, _)| k == "tokeninfo" || k == "reqid") => Ok(Reply::Challenge(fields)),
        "2" => Ok(Reply::Challenge(fields)),
        _ => bail!("login failed: no session cookie returned{}", portal_error(resp)),
    }
}

/// Parses the `ret=1,redir=...,reqid=...` body returned by logincheck.
fn parse_ret_fields(text: &str) -> Vec<(String, String)> {
    text.trim()
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> &'a str {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or_default()
}

/// Extracts the `<!--sslvpnerrmsg=...-->` hint the portal embeds in pages.
fn portal_error(resp: &Response) -> String {
    let text = resp.text();
    let Some(start) = text.find("sslvpnerrmsg=") else {
        return String::new();
    };
    let rest = &text[start + "sslvpnerrmsg=".len()..];
    let msg = rest.split("-->").next().unwrap_or_default().trim();
    if msg.is_empty() { String::new() } else { format!(" ({msg})") }
}

async fn ask(
    ctx: &SessionContext,
    key: &str,
    kind: PromptKind,
    message: String,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    ctx.prompter.ask(Prompt::new(key, kind, message)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_token_challenge() {
        let f = parse_ret_fields(
            "ret=2,reqid=12,polid=1-1-3,grp=vpn,portal=full,magic=1-4c,tokeninfo=,chal_msg=Please enter code\n",
        );
        assert_eq!(field(&f, "ret"), "2");
        assert_eq!(field(&f, "polid"), "1-1-3");
        assert_eq!(field(&f, "chal_msg"), "Please enter code");
        assert_eq!(field(&f, "missing"), "");
    }

    #[test]
    fn extracts_saml_id() {
        assert_eq!(saml_id("/?id=abc123").as_deref(), Some("abc123"));
        assert_eq!(saml_id("/favicon.ico"), None);
        assert_eq!(saml_id("/?x=1&id=zz").as_deref(), Some("zz"));
    }

    fn client() -> Client {
        let profile = FortiSslProfile {
            host: "gw.example".into(),
            port: 443,
            realm: None,
            username: None,
            auth: Default::default(),
            trusted_cert: vec![],
            ca_file: None,
            client_cert: None,
            client_key: None,
            ca_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
            client_certificate: None,
            client_chain_pem: None,
            keychain_ca_pem: None,
        };
        let endpoint = crate::tls::Endpoint::new(&profile, "192.0.2.1:443".parse().unwrap(), None).unwrap();
        Client::new(endpoint, &profile.host, profile.port)
    }

    #[test]
    fn logincheck_replies() {
        let c = client();
        let resp = |status: u16, body: &str| Response {
            status,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            keep_alive: false,
        };
        let err = |status, body| format!("{:#}", check_reply(&c, &resp(status, body)).unwrap_err());
        assert!(err(401, "ret=0,redir=/remote/login").contains("wrong credentials"));
        assert!(err(200, "ret=6").contains("unsupported challenge"));
        assert!(err(500, "oops<!--sslvpnerrmsg=Internal-->").contains("HTTP 500 (Internal)"));
        assert!(err(200, "ret=1,redir=/remote/index").contains("no session cookie"));
        assert!(err(200, "/remote/login?err=sslvpn_login_permission_denied").contains("permission denied"));
        assert!(matches!(check_reply(&c, &resp(200, "ret=2,reqid=1")), Ok(Reply::Challenge(_))));
        assert!(matches!(check_reply(&c, &resp(200, "tokeninfo=ftm_push")), Ok(Reply::Challenge(_))));
        let mut c = client();
        c.cookies.insert("SVPNCOOKIE".into(), "x".into());
        assert_eq!(check_reply(&c, &resp(200, "")).unwrap(), Reply::Success);
    }

    /// Random portal answers and browser callbacks: errors are fine, panics
    /// are not.
    #[tokio::test]
    async fn fuzz_portal_and_saml_callback() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x5341_4d4c);
        let alphabet = b"ret=0126,&reqid=tokeninfo:chal_msg<!--sslvpnerrmsg=-->?id/ \r\n\xc3\xa9";
        let random_text = |rng: &mut StdRng, max: usize| -> String {
            let len = rng.random_range(0..=max);
            let bytes: Vec<u8> = (0..len)
                .map(
                    |_| if rng.random_bool(0.8) { alphabet[rng.random_range(0..alphabet.len())] } else { rng.random() },
                )
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let c = client();
        for _ in 0..3000 {
            let text = random_text(&mut rng, 80);
            let _ = parse_ret_fields(&text);
            let _ = saml_id(&text);
            let resp = Response {
                status: rng.random_range(0..600),
                headers: vec![],
                body: text.into_bytes(),
                keep_alive: false,
            };
            let _ = portal_error(&resp);
            let _ = check_reply(&c, &resp);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        for i in 0..100 {
            let request = match i % 3 {
                0 => random_text(&mut rng, 200).into_bytes(),
                1 => format!("GET /?{} HTTP/1.1\r\n{}\r\n\r\n", random_text(&mut rng, 30), random_text(&mut rng, 60))
                    .into_bytes(),
                _ => (0..rng.random_range(0..9000)).map(|_| rng.random()).collect(),
            };
            let client = tokio::spawn(async move {
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                let _ = s.write_all(&request).await;
                let _ = s.shutdown().await;
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out).await;
            });
            let (sock, _) = listener.accept().await.unwrap();
            let _ = tokio::time::timeout(SAML_READ_TIMEOUT, serve_saml_callback(sock)).await;
            client.await.unwrap();
        }
    }

    #[test]
    fn portal_error_hint() {
        let resp = Response {
            status: 200,
            headers: vec![],
            body: b"<html><!--sslvpnerrmsg=Account locked--></html>".to_vec(),
            keep_alive: false,
        };
        assert_eq!(portal_error(&resp), " (Account locked)");
    }
}
