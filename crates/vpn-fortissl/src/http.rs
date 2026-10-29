//! Minimal HTTP/1.1 client for the FortiGate web portal. Requests share one
//! keep-alive TLS connection, as a browser does, and reconnect once if the
//! gateway has closed it.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use vpn_core::{FailureKind, failure};
use zeroize::Zeroizing;

use crate::tls::{Endpoint, Stream};

pub const USER_AGENT: &str = "Mozilla/5.0 SV1";
const MAX_BODY: usize = 4 << 20;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body was length-delimited and the server did not ask to close:
    /// the connection can carry the next request.
    pub keep_alive: bool,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// HTTPS client that keeps the portal cookies between requests.
pub struct Client {
    endpoint: Endpoint,
    host_header: String,
    pub cookies: BTreeMap<String, String>,
    conn: Option<Stream>,
}

impl Client {
    pub fn new(endpoint: Endpoint, host: &str, port: u16) -> Self {
        let host_header = if port == 443 { host.to_owned() } else { format!("{host}:{port}") };
        Self { endpoint, host_header, cookies: BTreeMap::new(), conn: None }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Value of `SVPNCOOKIE`, once the portal has issued a non-empty one.
    pub fn session_cookie(&self) -> Option<&str> {
        self.cookies.get("SVPNCOOKIE").map(String::as_str).filter(|v| !v.is_empty())
    }

    pub fn cookie_header(&self) -> String {
        self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    pub async fn get(&mut self, path: &str) -> anyhow::Result<Response> {
        self.request("GET", path, None).await
    }

    pub async fn post_form(&mut self, path: &str, form: &[(&str, &str)]) -> anyhow::Result<Response> {
        self.request("POST", path, Some(encode_form(form))).await
    }

    /// The body may hold a password or a code: it and the request are
    /// erased once sent, and never reallocated on the way.
    async fn request(&mut self, method: &str, path: &str, body: Option<Zeroizing<String>>) -> anyhow::Result<Response> {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n\
             Accept: */*\r\nConnection: keep-alive\r\n",
            self.host_header
        );
        if !self.cookies.is_empty() {
            head.push_str(&format!("Cookie: {}\r\n", self.cookie_header()));
        }
        if let Some(body) = &body {
            head.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let body_len = body.as_ref().map_or(0, |b| b.len());
        let mut req = Zeroizing::new(String::with_capacity(head.len() + body_len));
        req.push_str(&head);
        if let Some(body) = &body {
            req.push_str(body);
        }

        // A kept-alive connection may have been closed by the gateway in the
        // meantime: retry once on a fresh one. Not a POST the gateway may
        // have processed: a one-time code would be refused the second time.
        let context = || format!("{method} {}: no valid HTTP response", no_query(path));
        let resp = match self.conn.take() {
            Some(mut stream) => match exchange(&mut stream, &req).await {
                Ok(resp) => Some((resp, stream)),
                Err(e) if e.replayable || body.is_none() => {
                    tracing::debug!(
                        method,
                        path = no_query(path),
                        "kept-alive connection failed ({:#}), reconnecting",
                        e.error
                    );
                    None
                }
                Err(e) => return Err(e.error.context(context())),
            },
            None => None,
        };
        let (resp, stream) = match resp {
            Some(done) => done,
            None => {
                let mut stream = self.endpoint.connect().await?;
                let resp = exchange(&mut stream, &req).await.map_err(|e| e.error).with_context(context)?;
                (resp, stream)
            }
        };
        if resp.keep_alive {
            self.conn = Some(stream);
        }
        log_response(method, path, &resp);
        self.store_cookies(&resp);
        Ok(resp)
    }

    fn store_cookies(&mut self, resp: &Response) {
        for (name, value) in &resp.headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let pair = value.split(';').next().unwrap_or_default();
            if let Some((k, v)) = pair.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                // An empty value is how the portal deletes a cookie.
                if v.is_empty() {
                    self.cookies.remove(k);
                } else {
                    self.cookies.insert(k.to_owned(), v.to_owned());
                }
            }
        }
    }
}

/// How long the gateway may take to answer: a push approval waits for the
/// user's phone.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

struct ExchangeError {
    /// The connection failed before any byte of response: the gateway did
    /// not process the request, which can be sent again.
    replayable: bool,
    error: anyhow::Error,
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: &str) -> Result<Response, ExchangeError> {
    let unanswered = |error: anyhow::Error| ExchangeError { replayable: true, error };
    let answered = |error: anyhow::Error| ExchangeError { replayable: false, error };
    // No answer in time: the gateway may still be working on it.
    let timed_out = || answered(failure(FailureKind::Timeout, "the gateway did not answer in time"));
    stream.write_all(req.as_bytes()).await.map_err(|e| unanswered(e.into()))?;
    stream.flush().await.map_err(|e| unanswered(e.into()))?;
    let mut first = [0u8; 4096];
    let n =
        timeout(RESPONSE_TIMEOUT, read_some(stream, &mut first)).await.map_err(|_| timed_out())?.map_err(unanswered)?;
    if n == 0 {
        return Err(unanswered(anyhow::anyhow!("connection closed before any response")));
    }
    let mut rest = (&first[..n]).chain(stream);
    timeout(RESPONSE_TIMEOUT, read_response(&mut rest)).await.map_err(|_| timed_out())?.map_err(answered)
}

/// A path or URL without its query, which may carry a SAML session id or a
/// token.
fn no_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(p, _)| p)
}

/// Status, redirect target and cookie names (never values) for diagnosis.
fn log_response(method: &str, path: &str, resp: &Response) {
    let cookies: Vec<String> = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v)
        .filter_map(|v| v.split(';').next()?.split_once('='))
        .map(|(k, v)| format!("{}{}", k.trim(), if v.trim().is_empty() { "(deleted)" } else { "" }))
        .collect();
    tracing::debug!(
        method,
        path = no_query(path),
        status = resp.status,
        location = no_query(resp.header("location").unwrap_or("-")),
        set_cookies = cookies.join(","),
        "portal request"
    );
}

pub async fn read_response<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<Response> {
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            bail!("headers too large");
        }
        let mut chunk = [0u8; 4096];
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            bail!("connection closed before end of headers");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut rest = buf[header_end + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("bad status line {status_line:?}"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect::<Vec<_>>();
    let get = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());

    let close = get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let (body, delimited) = if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        (read_chunked(stream, rest).await?, true)
    } else if let Some(len) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if len > MAX_BODY {
            bail!("body too large ({len} bytes)");
        }
        while rest.len() < len {
            let mut chunk = [0u8; 8192];
            let n = read_some(stream, &mut chunk).await?;
            if n == 0 {
                bail!("connection closed before end of body");
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest.truncate(len);
        (rest, true)
    } else if status == 204 || status == 304 {
        (Vec::new(), true)
    } else {
        read_to_end(stream, &mut rest).await?;
        (rest, false)
    };
    let keep_alive = delimited && !close;
    Ok(Response { status, headers, body, keep_alive })
}

/// Reads, treating a TLS close without `close_notify` as end of stream:
/// FortiGates frequently drop the connection that way.
async fn read_some<R: AsyncRead + Unpin>(stream: &mut R, buf: &mut [u8]) -> anyhow::Result<usize> {
    match stream.read(buf).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e.into()),
    }
}

async fn read_to_end<R: AsyncRead + Unpin>(stream: &mut R, out: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut chunk = [0u8; 8192];
    loop {
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > MAX_BODY {
            bail!("body too large");
        }
    }
}

/// Reads a chunked body up to its terminating zero-size chunk, without
/// waiting for the connection to close (it may be kept alive).
async fn read_chunked<R: AsyncRead + Unpin>(stream: &mut R, mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    loop {
        // The body ends with an empty line (after the last chunk, or the
        // trailers): only then is it worth decoding it all.
        if data.ends_with(b"\r\n\r\n")
            && let Some(body) = decode_chunked(&data)?
        {
            return Ok(body);
        }
        if data.len() > MAX_BODY {
            bail!("body too large");
        }
        let mut chunk = [0u8; 8192];
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            bail!("connection closed inside a chunked body");
        }
        data.extend_from_slice(&chunk[..n]);
    }
}

/// `Ok(None)` while the body is still incomplete.
fn decode_chunked(mut data: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find(data, b"\r\n") else {
            if data.len() > 64 {
                bail!("bad chunk size line");
            }
            return Ok(None);
        };
        let size_str = std::str::from_utf8(&data[..line_end])?;
        let size_str = size_str.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_str, 16).with_context(|| format!("bad chunk size {size_str:?}"))?;
        if size > MAX_BODY {
            bail!("chunk too large");
        }
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The form, URL-encoded into one buffer sized for the worst case (every
/// byte escaped): a password in it is never copied elsewhere.
pub fn encode_form(fields: &[(&str, &str)]) -> Zeroizing<String> {
    let capacity = fields.iter().map(|(k, v)| 3 * (k.len() + v.len()) + 2).sum();
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        urlencode_into(&mut out, k);
        out.push('=');
        urlencode_into(&mut out, v);
    }
    out
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(3 * s.len());
    urlencode_into(&mut out, s);
    out
}

fn urlencode_into(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 15)] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_content_length_and_cookies() {
        let raw =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc; path=/; secure\r\nContent-Length: 5\r\n\r\nret=1extra";
        let resp = read_response(&mut &raw[..]).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ret=1");
        assert_eq!(resp.headers[0], ("Set-Cookie".into(), "SVPNCOOKIE=abc; path=/; secure".into()));
    }

    #[tokio::test]
    async fn parses_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<a/>\r\n3;x=y\r\nabc\r\n0\r\n\r\n";
        let resp = read_response(&mut &raw[..]).await.unwrap();
        assert_eq!(resp.body, b"<a/>abc");
    }

    #[test]
    fn form_encoding() {
        assert_eq!(
            encode_form(&[("username", "a b"), ("credential", "p&=é")]).as_str(),
            "username=a%20b&credential=p%26%3D%C3%A9"
        );
    }

    #[tokio::test]
    async fn keep_alive_responses_do_not_wait_for_close() {
        // The server side stays open: reading must stop at the body's end.
        let (mut client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            .await
            .unwrap();
        let first = read_response(&mut client).await.unwrap();
        assert_eq!((first.body.as_slice(), first.keep_alive), (&b"hello"[..], true));
        // One response per request: the next one only comes after we ask.
        server
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: /remote/login\r\nSet-Cookie: SVPNCOOKIE=; path=/\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let second = read_response(&mut client).await.unwrap();
        assert_eq!((second.status, second.header("location"), second.keep_alive), (302, Some("/remote/login"), true));

        let mut ok = Client::new(
            Endpoint::new(&test_profile(), "127.0.0.1:1".parse().unwrap(), None).unwrap(),
            "gw.example",
            443,
        );
        ok.cookies.insert("SVPNCOOKIE".into(), "abc".into());
        ok.store_cookies(&second);
        assert!(ok.session_cookie().is_none(), "an empty Set-Cookie deletes the cookie");
    }

    #[tokio::test]
    async fn connection_close_disables_reuse() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
        assert!(!read_response(&mut &raw[..]).await.unwrap().keep_alive);
    }

    #[tokio::test]
    async fn only_unanswered_requests_are_replayable() {
        // A kept-alive connection the gateway had closed: nothing came back.
        let (mut client, mut server) = tokio::io::duplex(4096);
        server.shutdown().await.unwrap();
        assert!(exchange(&mut client, "POST / HTTP/1.1\r\n\r\n").await.unwrap_err().replayable);

        let (mut client, mut server) = tokio::io::duplex(4096);
        server.write_all(b"HTTP/1.1 200 OK\r\nContent-Le").await.unwrap();
        server.shutdown().await.unwrap();
        let error = exchange(&mut client, "POST / HTTP/1.1\r\n\r\n").await.unwrap_err();
        assert!(!error.replayable, "the gateway started to answer");

        let (mut client, mut server) = tokio::io::duplex(4096);
        server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
        assert_eq!(exchange(&mut client, "GET / HTTP/1.1\r\n\r\n").await.ok().unwrap().status, 204);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_gateway_times_out() {
        let (mut client, _server) = tokio::io::duplex(4096);
        let error = exchange(&mut client, "POST / HTTP/1.1\r\n\r\n").await.unwrap_err();
        assert!(!error.replayable, "it may still be processed");
        assert_eq!(vpn_core::failure::kind_of(&error.error), FailureKind::Timeout);
    }

    fn test_profile() -> vpn_core::FortiSslProfile {
        serde_json::from_value(serde_json::json!({ "host": "gw.example" })).unwrap()
    }
}
