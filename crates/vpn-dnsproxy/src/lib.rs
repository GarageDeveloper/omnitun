//! A session's DNS proxy for routes by domain (#37), run unprivileged and
//! sandboxed (`omnitun-engine --dns-proxy`). The resolver sends it the
//! names under the session's routed domains; it relays each query to the
//! resolvers that answered before (the tunnel's, or those in place before
//! the VPN: an antivirus that filters DNS keeps doing it), and for a routed
//! name holds the answer until the daemon has routed its addresses, so the
//! first connection already goes the right way.
//!
//! The tunnels carry no IPv6: AAAA answers of routed names are emptied, and
//! so are HTTPS and SVCB ones, whose address hints would skip the A query.
//! Queries are relayed as they came (EDNS, DNSSEC bits), under a fresh
//! random id; an answer must come from the server asked, with that id and
//! the same question.

use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use vpn_core::dns_ipc::{FromProxy, MAX_ADDRESSES, MAX_LINE, ProxyConfig, ToProxy, Upstream};

/// How long one server may take to answer; the next one is tried then.
const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
/// How long an answer waits for its routes: then it goes anyway (the
/// first connection may take the wrong way, DNS still works).
const ROUTE_TIMEOUT: Duration = Duration::from_secs(2);
/// Queries in progress at once; more are dropped, and retried by the
/// resolver.
const MAX_INFLIGHT: usize = 256;
const MAX_TCP_CLIENTS: usize = 32;
const TCP_IDLE: Duration = Duration::from_secs(10);
/// CNAMEs followed from the question to its addresses.
const MAX_CHAIN: usize = 16;
const MAX_UPSTREAMS: usize = 16;
const MAX_SERVERS: usize = 8;
/// Firefox asks it before turning on its own encrypted DNS: no such name,
/// and it keeps the system's, which the routes rely on.
const CANARY: &str = "use-application-dns.net";

/// The daemon's side, as the proxy sees it.
pub trait Router: Send + Sync + 'static {
    /// Routes `addresses`, which `name` resolved to for `ttl` seconds;
    /// returns once they are routed (or refused).
    fn route(&self, name: String, addresses: Vec<Ipv4Addr>, ttl: u32) -> impl Future<Output = ()> + Send;
}

pub struct Proxy<R> {
    config: ProxyConfig,
    router: R,
}

impl<R: Router> Proxy<R> {
    /// `local`: where the proxy listens, never an upstream (a loop).
    pub fn new(config: ProxyConfig, router: R, local: &[SocketAddr]) -> anyhow::Result<Self> {
        if config.upstreams.len() > MAX_UPSTREAMS || config.upstreams.iter().any(|u| u.servers.len() > MAX_SERVERS) {
            bail!("too many upstream resolvers");
        }
        if let Some(server) = config.upstreams.iter().flat_map(|u| &u.servers).find(|s| local.contains(s)) {
            bail!("the upstream resolver {server} is this proxy");
        }
        Ok(Self { config, router })
    }

    /// The answer to `query`, or nothing for what is not a query.
    pub async fn answer(&self, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let request = Message::from_vec(query).ok()?;
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        if request.metadata.op_code != OpCode::Query {
            return reply(&request, ResponseCode::NotImp);
        }
        let [question] = request.queries.as_slice() else {
            return reply(&request, ResponseCode::FormErr);
        };
        let name = plain(&question.name);
        if name == CANARY {
            return reply(&request, ResponseCode::NXDomain);
        }
        let routed = self.config.routed.iter().any(|pattern| pattern.matches(&name));
        if routed && matches!(question.query_type, RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB) {
            return reply(&request, ResponseCode::NoError);
        }
        let Some((answer, response)) = self.forward(query, &request, &name, tcp).await else {
            return reply(&request, ResponseCode::ServFail);
        };
        if routed && question.query_type == RecordType::A {
            self.report(&name, &response).await;
        }
        Some(answer)
    }

    /// The resolvers for `name`: those of the most specific domain it is
    /// under, else those without domains.
    fn upstream_for(&self, name: &str) -> Option<&Upstream> {
        let under = |domain: &String| vpn_core::destination::is_under(name, domain);
        let specific = self
            .config
            .upstreams
            .iter()
            .filter_map(|u| u.domains.iter().filter(|d| under(d)).map(|d| d.len()).max().map(|len| (len, u)))
            .max_by_key(|(len, _)| *len)
            .map(|(_, u)| u);
        specific.or_else(|| self.config.upstreams.iter().find(|u| u.domains.is_empty()))
    }

    async fn forward(&self, query: &[u8], request: &Message, name: &str, tcp: bool) -> Option<(Vec<u8>, Message)> {
        let upstream = self.upstream_for(name)?;
        let id: u16 = rand::random();
        let mut relayed = query.to_vec();
        relayed[..2].copy_from_slice(&id.to_be_bytes());
        // A negative answer of an independent server, while the others are asked.
        let mut negative = None;
        for &server in &upstream.servers {
            let exchange = async {
                if tcp { exchange_tcp(server, &relayed).await } else { exchange_udp(server, &relayed, id).await }
            };
            let mut answer = match tokio::time::timeout(SERVER_TIMEOUT, exchange).await {
                Ok(Ok(answer)) => answer,
                Ok(Err(e)) => {
                    tracing::debug!("resolver {server}: {e:#}");
                    continue;
                }
                Err(_) => {
                    tracing::debug!("resolver {server} did not answer in time");
                    continue;
                }
            };
            let Ok(response) = Message::from_vec(&answer) else { continue };
            if response.metadata.id != id
                || response.metadata.message_type != MessageType::Response
                || !same_questions(&request.queries, &response.queries)
            {
                tracing::debug!("resolver {server} answered another question");
                continue;
            }
            answer[..2].copy_from_slice(&request.metadata.id.to_be_bytes());
            let positive = response.metadata.response_code == ResponseCode::NoError
                && (!response.answers.is_empty() || !upstream.independent);
            if positive || !upstream.independent {
                return Some((answer, response));
            }
            negative.get_or_insert((answer, response));
        }
        negative
    }

    /// Has the daemon route the addresses `name` resolved to, following its
    /// CNAMEs, for the shortest TTL of the chain.
    async fn report(&self, name: &str, response: &Message) {
        if response.metadata.response_code != ResponseCode::NoError {
            return;
        }
        let (addresses, ttl) = addresses_of(name, response);
        if addresses.is_empty() {
            return;
        }
        let routed = self.router.route(name.to_owned(), addresses, ttl);
        if tokio::time::timeout(ROUTE_TIMEOUT, routed).await.is_err() {
            tracing::warn!("the routes for a name took too long: answered without waiting");
        }
    }
}

/// The addresses of `name` in `response`, and their TTL.
fn addresses_of(name: &str, response: &Message) -> (Vec<Ipv4Addr>, u32) {
    let mut chain = vec![name.to_owned()];
    let mut ttl = u32::MAX;
    // Answers may come in any order: follow the CNAMEs first.
    for _ in 0..MAX_CHAIN {
        let next = response.answers.iter().find_map(|record| match &record.data {
            RData::CNAME(target) if chain.contains(&plain(&record.name)) && !chain.contains(&plain(&target.0)) => {
                Some((plain(&target.0), record.ttl))
            }
            _ => None,
        });
        let Some((target, cname_ttl)) = next else { break };
        chain.push(target);
        ttl = ttl.min(cname_ttl);
    }
    let mut addresses = Vec::new();
    let mut a_ttl = u32::MAX;
    for record in &response.answers {
        if let RData::A(address) = &record.data
            && chain.contains(&plain(&record.name))
            && !addresses.contains(&address.0)
            && addresses.len() < MAX_ADDRESSES
        {
            addresses.push(address.0);
            a_ttl = a_ttl.min(record.ttl);
        }
    }
    (addresses, ttl.min(a_ttl))
}

/// A name in lower case, without the trailing dot.
fn plain(name: &Name) -> String {
    let mut text = name.to_ascii().to_ascii_lowercase();
    if text.ends_with('.') {
        text.pop();
    }
    text
}

fn same_questions(a: &[hickory_proto::op::Query], b: &[hickory_proto::op::Query]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            plain(&a.name) == plain(&b.name) && a.query_type == b.query_type && a.query_class == b.query_class
        })
}

/// An answer of our own to `request`: an error, or no data.
fn reply(request: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.response_code = code;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    if request.edns.is_some() {
        response.edns = Some(Edns::new());
    }
    response.to_vec().ok()
}

async fn exchange_udp(server: SocketAddr, query: &[u8], id: u16) -> anyhow::Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let socket = UdpSocket::bind(local).await?;
    // Connected: datagrams from anywhere else are not received.
    socket.connect(server).await?;
    socket.send(query).await?;
    let mut buf = vec![0; 65_535];
    loop {
        let len = socket.recv(&mut buf).await?;
        // Another id is a late or forged answer: keep waiting.
        if len >= 2 && buf[..2] == id.to_be_bytes() {
            buf.truncate(len);
            return Ok(buf);
        }
    }
}

async fn exchange_tcp(server: SocketAddr, query: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(server).await?;
    let len = u16::try_from(query.len()).context("query too long")?;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    read_framed(&mut stream).await
}

async fn read_framed(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).await?;
    let mut message = vec![0; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

/// Answers the queries arriving on `socket`, from this host only.
pub async fn serve_udp<R: Router>(proxy: Arc<Proxy<R>>, socket: UdpSocket) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let mut buf = vec![0; 65_535];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            // An ICMP error for an earlier answer.
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused) =>
            {
                continue;
            }
            Err(e) => return Err(e).context("DNS socket"),
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = inflight.clone().try_acquire_owned() else { continue };
        let query = buf[..len].to_vec();
        let (proxy, socket) = (proxy.clone(), socket.clone());
        tokio::spawn(async move {
            if let Some(answer) = proxy.answer(&query, false).await {
                let _ = socket.send_to(&answer, peer).await;
            }
            drop(permit);
        });
    }
}

/// Answers the queries arriving on `listener` (after a truncated answer),
/// from this host only.
pub async fn serve_tcp<R: Router>(proxy: Arc<Proxy<R>>, listener: TcpListener) -> anyhow::Result<()> {
    let clients = Arc::new(Semaphore::new(MAX_TCP_CLIENTS));
    loop {
        let (mut stream, peer) = listener.accept().await.context("DNS listener")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = clients.clone().try_acquire_owned() else { continue };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            while let Ok(Ok(query)) = tokio::time::timeout(TCP_IDLE, read_framed(&mut stream)).await {
                let Some(answer) = proxy.answer(&query, true).await else { break };
                let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&answer);
                if stream.write_all(&framed).await.is_err() {
                    break;
                }
            }
            drop(permit);
        });
    }
}

/// The daemon, on the control socket: each report waits for its `Routed`.
pub struct ControlRouter {
    out: mpsc::Sender<FromProxy>,
    pending: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    next: AtomicU64,
}

impl ControlRouter {
    fn routed(&self, id: u64) {
        if let Some(waiting) = self.pending.lock().unwrap().remove(&id) {
            let _ = waiting.send(());
        }
    }
}

impl Router for Arc<ControlRouter> {
    async fn route(&self, name: String, addresses: Vec<Ipv4Addr>, ttl: u32) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (done, routed) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, done);
        if self.out.send(FromProxy::Resolved { id, name, addresses, ttl }).await.is_ok() {
            let _ = routed.await;
        }
        // Answered or given up: no longer waited for.
        self.pending.lock().unwrap().remove(&id);
    }
}

/// The proxy process: its configuration first on `control`, then queries
/// on `udp` and `tcp` until the daemon closes `control`.
pub async fn run(control: UnixStream, udp: UdpSocket, tcp: TcpListener) -> anyhow::Result<()> {
    let (read, mut write) = control.into_split();
    let mut lines = BufReader::new(read);
    let mut read_line = async move || -> anyhow::Result<Option<ToProxy>> {
        let mut line = String::new();
        if (&mut lines).take(MAX_LINE).read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&line).context("invalid control message")?))
    };
    let Some(ToProxy::Config { config }) = read_line().await? else {
        bail!("the daemon sent no configuration");
    };
    let (out, mut out_rx) = mpsc::channel::<FromProxy>(64);
    let router = Arc::new(ControlRouter { out, pending: Mutex::default(), next: AtomicU64::new(1) });
    let local = [udp.local_addr()?, tcp.local_addr()?];
    let proxy = Arc::new(Proxy::new(config, router.clone(), &local)?);
    let writer = async move {
        while let Some(message) = out_rx.recv().await {
            let mut line = serde_json::to_vec(&message).expect("messages serialize");
            line.push(b'\n');
            write.write_all(&line).await?;
        }
        anyhow::Ok(())
    };
    let reader = async move {
        while let Some(message) = read_line().await? {
            if let ToProxy::Routed { id } = message {
                router.routed(id);
            }
        }
        anyhow::Ok(())
    };
    tokio::select! {
        res = serve_udp(proxy.clone(), udp) => res,
        res = serve_tcp(proxy, tcp) => res,
        res = writer => res.context("control socket"),
        // The daemon is gone, or ended the session.
        res = reader => res,
    }
}

#[cfg(test)]
mod tests;
