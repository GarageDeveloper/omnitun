//! On loopback: a fake upstream resolver, a fake daemon.

use std::str::FromStr;
use std::sync::atomic::AtomicUsize;

use hickory_proto::op::Query;
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use vpn_core::dns_ipc::Upstream;

use super::*;

/// How a fake upstream answers.
#[derive(Clone, Copy)]
enum Behaviour {
    Normal,
    Silent,
    /// Answers with another id first, then another question, then right.
    Forging,
    /// Truncated over UDP, whole over TCP.
    Truncating,
}

/// A resolver on loopback (UDP and TCP on one port): `*.saas.example` is a
/// CNAME to `edge.cdn.example`, which has two addresses; anything else has
/// 192.0.2.1 and an AAAA.
struct Upstream1 {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

fn answer_for(request: &Message, truncated: bool) -> Message {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    let question = &request.queries[0];
    let name = plain(&question.name);
    if truncated {
        response.metadata.truncation = true;
        return response;
    }
    let edge = Name::from_str("edge.cdn.example.").unwrap();
    if name.ends_with("saas.example") {
        response.add_answer(Record::from_rdata(question.name.clone(), 300, RData::CNAME(CNAME(edge.clone()))));
        if question.query_type == RecordType::A {
            // The addresses before the CNAME: any order goes.
            response.answers.insert(0, Record::from_rdata(edge.clone(), 60, RData::A(A::new(203, 0, 113, 7))));
            response.add_answer(Record::from_rdata(edge, 120, RData::A(A::new(203, 0, 113, 8))));
        }
    } else if question.query_type == RecordType::A {
        response.add_answer(Record::from_rdata(question.name.clone(), 30, RData::A(A::new(192, 0, 2, 1))));
    } else if question.query_type == RecordType::AAAA {
        response.add_answer(Record::from_rdata(
            question.name.clone(),
            30,
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ));
    }
    response
}

async fn upstream(behaviour: Behaviour) -> Upstream1 {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&buf[..len]).unwrap();
            let truncated = matches!(behaviour, Behaviour::Truncating);
            let response = answer_for(&request, truncated);
            match behaviour {
                Behaviour::Silent => continue,
                Behaviour::Forging => {
                    let mut forged = response.clone();
                    forged.metadata.id = request.metadata.id.wrapping_add(1);
                    udp.send_to(&forged.to_vec().unwrap(), peer).await.unwrap();
                    let mut other = response.clone();
                    other.queries = vec![Query::query(Name::from_str("evil.example.").unwrap(), RecordType::A)];
                    udp.send_to(&other.to_vec().unwrap(), peer).await.unwrap();
                }
                _ => {}
            }
            udp.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let count = queries.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let query = read_framed(&mut stream).await.unwrap();
            let response = answer_for(&Message::from_vec(&query).unwrap(), false).to_vec().unwrap();
            let mut framed = (response.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&response);
            stream.write_all(&framed).await.unwrap();
        }
    });
    Upstream1 { addr, queries }
}

/// A name, its addresses and their TTL.
type Report = (String, Vec<Ipv4Addr>, u32);

/// Records what it is asked to route; takes `delay` to do it.
#[derive(Clone, Default)]
struct FakeRouter {
    routed: Arc<Mutex<Vec<Report>>>,
    delay: Duration,
}

impl Router for FakeRouter {
    async fn route(&self, name: String, addresses: Vec<Ipv4Addr>, ttl: u32) {
        tokio::time::sleep(self.delay).await;
        self.routed.lock().unwrap().push((name, addresses, ttl));
    }
}

fn config(servers: &[SocketAddr]) -> ProxyConfig {
    ProxyConfig {
        routed: vec!["*.saas.example".parse().unwrap()],
        upstreams: vec![Upstream { domains: vec![], servers: servers.to_vec() }],
    }
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(name).unwrap(), kind));
    message.to_vec().unwrap()
}

fn parsed(answer: Option<Vec<u8>>) -> Message {
    Message::from_vec(&answer.expect("an answer")).unwrap()
}

#[tokio::test]
async fn routes_before_answering() {
    let upstream = upstream(Behaviour::Normal).await;
    let router = FakeRouter { delay: Duration::from_millis(200), ..Default::default() };
    let proxy = Proxy::new(config(&[upstream.addr]), router.clone(), &[]).unwrap();
    let request = query("App.SaaS.example.", RecordType::A);
    let answer = parsed(proxy.answer(&request, false).await);
    assert_eq!(answer.metadata.id, Message::from_vec(&request).unwrap().metadata.id, "the client's id back");
    assert_eq!(answer.answers.len(), 3, "relayed whole");
    let routed = router.routed.lock().unwrap().clone();
    assert_eq!(
        routed,
        [("app.saas.example".to_owned(), vec![Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)], 60)],
        "routed (shortest TTL of the chain) before the answer came back"
    );
}

#[tokio::test]
async fn other_names_are_only_relayed() {
    let upstream = upstream(Behaviour::Normal).await;
    let router = FakeRouter::default();
    let proxy = Proxy::new(config(&[upstream.addr]), router.clone(), &[]).unwrap();
    let answer = parsed(proxy.answer(&query("www.example.org.", RecordType::A), false).await);
    assert_eq!(answer.answers.len(), 1);
    let answer = parsed(proxy.answer(&query("www.example.org.", RecordType::AAAA), false).await);
    assert_eq!(answer.answers.len(), 1, "AAAA of other names untouched");
    assert!(router.routed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_ipv6_or_hints_for_routed_names() {
    let upstream = upstream(Behaviour::Normal).await;
    let proxy = Proxy::new(config(&[upstream.addr]), FakeRouter::default(), &[]).unwrap();
    for kind in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
        let answer = parsed(proxy.answer(&query("app.saas.example.", kind), false).await);
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError, "{kind}");
        assert!(answer.answers.is_empty(), "{kind}");
    }
    assert_eq!(upstream.queries.load(Ordering::SeqCst), 0, "answered without asking");
}

#[tokio::test]
async fn firefox_keeps_the_system_resolver() {
    let proxy = Proxy::new(config(&[]), FakeRouter::default(), &[]).unwrap();
    let answer = parsed(proxy.answer(&query("use-application-dns.net.", RecordType::A), false).await);
    assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn the_most_specific_resolver_answers() {
    let (corp, public) = (upstream(Behaviour::Normal).await, upstream(Behaviour::Normal).await);
    let config = ProxyConfig {
        routed: vec![],
        upstreams: vec![
            Upstream { domains: vec![], servers: vec![public.addr] },
            Upstream { domains: vec!["example".into()], servers: vec![public.addr] },
            Upstream { domains: vec!["corp.example.".into()], servers: vec![corp.addr] },
        ],
    };
    let proxy = Proxy::new(config, FakeRouter::default(), &[]).unwrap();
    parsed(proxy.answer(&query("intranet.corp.example.", RecordType::A), false).await);
    assert_eq!((corp.queries.load(Ordering::SeqCst), public.queries.load(Ordering::SeqCst)), (1, 0));
    parsed(proxy.answer(&query("notcorp.example.", RecordType::A), false).await);
    parsed(proxy.answer(&query("www.example.org.", RecordType::A), false).await);
    assert_eq!((corp.queries.load(Ordering::SeqCst), public.queries.load(Ordering::SeqCst)), (1, 2));
}

#[tokio::test]
async fn a_silent_resolver_is_skipped() {
    let (silent, normal) = (upstream(Behaviour::Silent).await, upstream(Behaviour::Normal).await);
    let proxy = Proxy::new(config(&[silent.addr, normal.addr]), FakeRouter::default(), &[]).unwrap();
    let answer = parsed(proxy.answer(&query("www.example.org.", RecordType::A), false).await);
    assert_eq!(answer.answers.len(), 1);
    let proxy = Proxy::new(config(&[silent.addr]), FakeRouter::default(), &[]).unwrap();
    let answer = parsed(proxy.answer(&query("www.example.org.", RecordType::A), false).await);
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "none answered");
}

#[tokio::test]
async fn forged_answers_are_ignored() {
    let upstream = upstream(Behaviour::Forging).await;
    let router = FakeRouter::default();
    let proxy = Proxy::new(config(&[upstream.addr]), router.clone(), &[]).unwrap();
    // The forged id is skipped; the wrong question would fail the server,
    // so it is sent after it: the right answer never comes before it.
    let answer = parsed(proxy.answer(&query("app.saas.example.", RecordType::A), false).await);
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert!(router.routed.lock().unwrap().is_empty(), "nothing routed from a forged answer");
}

#[tokio::test]
async fn slow_routes_do_not_block_dns() {
    let upstream = upstream(Behaviour::Normal).await;
    let router = FakeRouter { delay: Duration::from_secs(30), ..Default::default() };
    let proxy = Proxy::new(config(&[upstream.addr]), router, &[]).unwrap();
    let started = std::time::Instant::now();
    let answer = parsed(proxy.answer(&query("app.saas.example.", RecordType::A), false).await);
    assert_eq!(answer.answers.len(), 3);
    assert!(started.elapsed() < ROUTE_TIMEOUT + Duration::from_secs(1));
}

#[tokio::test]
async fn garbage_and_other_messages() {
    let proxy = Proxy::new(config(&[]), FakeRouter::default(), &[]).unwrap();
    assert!(proxy.answer(b"\x00\x01garbage", false).await.is_none());
    let mut two = Message::query();
    two.add_query(Query::query(Name::from_str("a.example.").unwrap(), RecordType::A));
    two.add_query(Query::query(Name::from_str("b.example.").unwrap(), RecordType::A));
    let answer = parsed(proxy.answer(&two.to_vec().unwrap(), false).await);
    assert_eq!(answer.metadata.response_code, ResponseCode::FormErr);
    let response = Message::response(1, OpCode::Query).to_vec().unwrap();
    assert!(proxy.answer(&response, false).await.is_none(), "an answer is not answered");
    let mut update = Message::new(2, MessageType::Query, OpCode::Update);
    update.add_query(Query::query(Name::from_str("a.example.").unwrap(), RecordType::SOA));
    let answer = parsed(proxy.answer(&update.to_vec().unwrap(), false).await);
    assert_eq!(answer.metadata.response_code, ResponseCode::NotImp);
}

#[test]
fn never_its_own_upstream() {
    let local: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    assert!(Proxy::new(config(&[local]), FakeRouter::default(), &[local]).is_err());
    let many = ProxyConfig { routed: vec![], upstreams: vec![Upstream { domains: vec![], servers: vec![local; 9] }] };
    assert!(Proxy::new(many, FakeRouter::default(), &[]).is_err());
}

#[test]
fn chains_are_bounded() {
    // A CNAME loop, and too many addresses.
    let mut response = Message::response(1, OpCode::Query);
    let (a, b) = (Name::from_str("a.example.").unwrap(), Name::from_str("b.example.").unwrap());
    response.add_answer(Record::from_rdata(a.clone(), 10, RData::CNAME(CNAME(b.clone()))));
    response.add_answer(Record::from_rdata(b.clone(), 10, RData::CNAME(CNAME(a.clone()))));
    for i in 0..40 {
        response.add_answer(Record::from_rdata(b.clone(), 10, RData::A(A::new(203, 0, 113, i))));
    }
    let (addresses, ttl) = addresses_of("a.example", &response);
    assert_eq!((addresses.len(), ttl), (MAX_ADDRESSES, 10));
}

/// Over sockets, with the control protocol: a truncated UDP answer, the
/// same over TCP, and the daemon's `Routed` releasing the answer.
#[tokio::test]
async fn the_process_end_to_end() {
    let upstream = upstream(Behaviour::Truncating).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind(udp.local_addr().unwrap()).await.unwrap();
    let listen = udp.local_addr().unwrap();
    let (daemon, proxy_side) = UnixStream::pair().unwrap();
    let proxy = tokio::spawn(run(proxy_side, udp, tcp));
    let (read, mut write) = daemon.into_split();
    let config = ToProxy::Config { config: config(&[upstream.addr]) };
    write.write_all(format!("{}\n", serde_json::to_string(&config).unwrap()).as_bytes()).await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&query("app.saas.example.", RecordType::A), listen).await.unwrap();
    let mut buf = vec![0; 4096];
    let len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf)).await.unwrap().unwrap();
    assert!(Message::from_vec(&buf[..len]).unwrap().metadata.truncation, "truncated over UDP");

    // The resolver retries over TCP: the proxy reports, waits, answers.
    let asked = tokio::spawn(async move {
        let mut stream = TcpStream::connect(listen).await.unwrap();
        let request = query("app.saas.example.", RecordType::A);
        let mut framed = (request.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        stream.write_all(&framed).await.unwrap();
        Message::from_vec(&read_framed(&mut stream).await.unwrap()).unwrap()
    });
    let mut lines = BufReader::new(read).lines();
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await.unwrap().unwrap().unwrap();
    let FromProxy::Resolved { id, name, addresses, ttl } = serde_json::from_str(&line).unwrap();
    assert_eq!((name.as_str(), addresses.len(), ttl), ("app.saas.example", 2, 60));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!asked.is_finished(), "the answer waits for the routes");
    write.write_all(format!("{}\n", serde_json::to_string(&ToProxy::Routed { id }).unwrap()).as_bytes()).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(1), asked).await.unwrap().unwrap();
    assert_eq!(answer.answers.len(), 3);

    // The daemon closes the control socket: the proxy ends.
    drop(write);
    drop(lines);
    let ended = tokio::time::timeout(Duration::from_secs(2), proxy).await.unwrap().unwrap();
    assert!(ended.is_ok(), "{ended:?}");
}
