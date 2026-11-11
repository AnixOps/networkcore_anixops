//! ShadowTLS v3 through the serve loop: a client written from the protocol
//! document against the server, with a scripted handshake site behind it.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::shadow_tls::{self, ShadowTlsSettings};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use ring::{digest, hmac};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);
const PASSWORD: &str = "front door";
const SITE_RANDOM: [u8; 32] = [7; 32];
/// What the site answers a client that speaks no TLS.
const PLAIN_REPLY: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const HEADER: usize = 5;
const TAG: usize = 4;

/// The wrapped protocol: no handshake and no users of its own, every client
/// goes to `target`.
struct ToEcho {
    users: Arc<UserStore>,
    target: SocketAddr,
}

impl StreamInbound for ToEcho {
    fn protocol(&self) -> &'static str {
        "to-echo"
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            Ok(Accepted {
                user: None,
                target: TargetAddr::Ip(self.target),
                stream,
                udp: None,
                mux: false,
            })
        })
    }
}

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![kind, 3, 3];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

async fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut record = vec![0u8; HEADER];
    stream.read_exact(&mut record).await?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(HEADER + len, 0);
    stream.read_exact(&mut record[HEADER..]).await?;
    Ok(record)
}

async fn next(stream: &mut TcpStream) -> Vec<u8> {
    timeout(TIMEOUT, read_record(stream))
        .await
        .expect("no record in time")
        .unwrap()
}

/// The site's ServerHello: with `supported_versions` naming TLS 1.3, or
/// without extensions the way a TLS 1.2 server answers.
fn server_hello(tls13: bool) -> Vec<u8> {
    let mut message = vec![2, 0, 0, 0, 3, 3];
    message.extend_from_slice(&SITE_RANDOM);
    // An empty session id, a cipher suite and no compression.
    message.extend_from_slice(&[0, 0x13, 0x01, 0]);
    if tls13 {
        message.extend_from_slice(&[0, 6, 0, 43, 0, 2, 3, 4]);
    }
    message[3] = (message.len() - 4) as u8;
    record(HANDSHAKE, &message)
}

/// What the site sends after a ClientHello: the ServerHello, a
/// ChangeCipherSpec and two records of the encrypted rest.
fn site_flight(tls13: bool) -> Vec<Vec<u8>> {
    vec![
        server_hello(tls13),
        record(20, &[1]),
        record(APPLICATION_DATA, b"encrypted extensions"),
        record(APPLICATION_DATA, &[0xab; 3000]),
    ]
}

/// The site's answer to a later record.
fn site_reply(received: &[u8]) -> Vec<u8> {
    record(
        APPLICATION_DATA,
        &[&b"site:"[..], &received[HEADER..]].concat(),
    )
}

/// The handshake site: as much of a TLS server as a relay can tell.
async fn start_site(tls13: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = site(&mut stream, tls13).await;
            });
        }
    });
    addr
}

async fn site(stream: &mut TcpStream, tls13: bool) -> io::Result<()> {
    let mut first = [0u8; 1];
    stream.peek(&mut first).await?;
    if first[0] != HANDSHAKE {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") && stream.read_buf(&mut request).await? > 0 {}
        stream.write_all(PLAIN_REPLY).await?;
        stream.shutdown().await?;
        while stream.read_buf(&mut request).await? > 0 {}
        return Ok(());
    }
    read_record(stream).await?;
    stream.write_all(&site_flight(tls13).concat()).await?;
    loop {
        let received = read_record(stream).await?;
        stream.write_all(&site_reply(&received)).await?;
    }
}

fn mac(password: &str, parts: &[&[u8]]) -> hmac::Context {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes());
    let mut mac = hmac::Context::with_key(&key);
    for part in parts {
        mac.update(part);
    }
    mac
}

/// The first four bytes of the HMAC so far.
fn tag_of(mac: &hmac::Context) -> [u8; TAG] {
    let mut tag = [0u8; TAG];
    tag.copy_from_slice(&mac.clone().sign().as_ref()[..TAG]);
    tag
}

/// A ClientHello record signed with `password`.
fn client_hello(password: &str) -> Vec<u8> {
    let mut message = vec![1, 0, 0, 0, 3, 3];
    message.extend_from_slice(&[9; 32]);
    // The session id: 28 bytes and the place of the tag.
    message.push(32);
    message.extend_from_slice(&[5; 28]);
    let tag_at = message.len();
    message.extend_from_slice(&[0; TAG]);
    // One cipher suite, no compression, no extensions.
    message.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0, 0, 0]);
    message[3] = (message.len() - 4) as u8;
    let tag = tag_of(&mac(password, &[&message[..]]));
    message[tag_at..tag_at + TAG].copy_from_slice(&tag);
    record(HANDSHAKE, &message)
}

/// The client's side of a session: what the protocol document has a client
/// derive from the password and the ServerRandom.
struct Session {
    relayed: hmac::Context,
    mask: digest::Digest,
    up: hmac::Context,
    down: hmac::Context,
}

impl Session {
    fn new(password: &str, random: &[u8]) -> Self {
        let keyed = [password.as_bytes(), random].concat();
        Self {
            relayed: mac(password, &[random]),
            mask: digest::digest(&digest::SHA256, &keyed),
            up: mac(password, &[random, &b"C"[..]]),
            down: mac(password, &[random, &b"S"[..]]),
        }
    }

    /// Checks a record the server relayed from the site and returns the
    /// body the site sent.
    fn unmark(&mut self, record: &[u8]) -> Vec<u8> {
        assert_eq!(record[..3], [APPLICATION_DATA, 3, 3]);
        let (tag, body) = record[HEADER..].split_at(TAG);
        self.relayed.update(body);
        assert_eq!(tag, tag_of(&self.relayed));
        let mask = self.mask.as_ref().iter().cycle();
        body.iter()
            .zip(mask)
            .map(|(byte, mask)| byte ^ mask)
            .collect()
    }

    /// A data record of the client.
    fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        self.up.update(data);
        let tag = tag_of(&self.up);
        self.up.update(&tag);
        record(APPLICATION_DATA, &[&tag[..], data].concat())
    }

    /// Checks a data record of the server and returns its data.
    fn open(&mut self, record: &[u8]) -> Vec<u8> {
        assert_eq!(record[..3], [APPLICATION_DATA, 3, 3]);
        let (tag, data) = record[HEADER..].split_at(TAG);
        self.down.update(data);
        assert_eq!(tag, tag_of(&self.down));
        self.down.update(tag);
        data.to_vec()
    }
}

fn handshake(site: SocketAddr) -> Value {
    json!({"server": site.ip().to_string(), "server_port": site.port()})
}

/// The server in front of the echo protocol, with `settings` as its
/// `shadow_tls` object.
async fn start_server(settings: Value) -> (SocketAddr, Arc<dyn StreamInbound>, Arc<InboundStats>) {
    let settings: ShadowTlsSettings = serde_json::from_value(settings).unwrap();
    let inner = Arc::new(ToEcho {
        users: Arc::default(),
        target: start_echo_server().await,
    });
    let inbound = shadow_tls::wrap(inner, Some(&settings)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        ServeSettings::default(),
        stats.clone(),
    ));
    (addr, inbound, stats)
}

/// Connects, sends a ClientHello signed with `password` and reads the
/// site's flight as the server passes it on.
async fn hello(server: SocketAddr, password: &str) -> (TcpStream, Vec<Vec<u8>>) {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.set_nodelay(true).unwrap();
    let hello = client_hello(password);
    // In two segments: the server has to wait for the whole record.
    stream.write_all(&hello[..20]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    stream.write_all(&hello[20..]).await.unwrap();
    let mut flight = Vec::new();
    for _ in 0..4 {
        flight.push(next(&mut stream).await);
    }
    (stream, flight)
}

/// Reads data records until `len` bytes of data arrived.
async fn read_data(stream: &mut TcpStream, session: &mut Session, len: usize) -> Vec<u8> {
    let mut data = Vec::new();
    while data.len() < len {
        data.extend(session.open(&next(stream).await));
    }
    data
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_the_handshake_then_carries_the_protocol() {
    let site = start_site(true).await;
    let (server, inbound, stats) = start_server(json!({
        "users": [{"name": "alice", "password": PASSWORD},
                  {"name": "bob", "password": "back door"}],
        "handshake": handshake(site),
    }))
    .await;
    let (mut stream, flight) = hello(server, PASSWORD).await;
    let expected = site_flight(true);
    // The ServerHello and the ChangeCipherSpec arrive as the site sent
    // them, its ApplicationData marked with the keys of the session.
    assert_eq!(flight[..2], expected[..2]);
    let mut session = Session::new(PASSWORD, &SITE_RANDOM);
    assert_eq!(flight[2].len(), expected[2].len() + TAG);
    assert_eq!(session.unmark(&flight[2]), expected[2][HEADER..]);
    assert_eq!(session.unmark(&flight[3]), expected[3][HEADER..]);

    // The client's Finished is no data record: it reaches the site.
    let finished = record(APPLICATION_DATA, b"client finished");
    stream.write_all(&finished).await.unwrap();
    assert_eq!(
        session.unmark(&next(&mut stream).await),
        site_reply(&finished)[HEADER..]
    );

    // The first data record switches to the wrapped protocol; the second
    // arrived in the same segment.
    let records = [session.seal(b"hello "), session.seal(b"shadow")].concat();
    stream.write_all(&records).await.unwrap();
    assert_eq!(
        read_data(&mut stream, &mut session, 12).await,
        b"hello shadow"
    );

    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    for chunk in payload.chunks(15_000) {
        stream.write_all(&session.seal(chunk)).await.unwrap();
    }
    let echoed = read_data(&mut stream, &mut session, payload.len()).await;
    assert_eq!(echoed, payload);

    // The ShadowTLS users are the inbound's, and alice is charged what the
    // wrapped protocol carried. The relay charges a write just after
    // handing it to the socket.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let users = inbound.users();
    assert_eq!(users.names(), ["alice", "bob"]);
    let traffic = users.traffic(false);
    assert_eq!(traffic.len(), 1);
    assert_eq!(traffic[0].name, "alice");
    let total = 12 + payload.len() as u64;
    assert_eq!((traffic[0].up, traffic[0].down), (total, total));
    assert_eq!(users.online()[0].name, "alice");
    assert_eq!(stats.handshake_failed.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_other_clients_to_the_handshake_site() {
    let site = start_site(true).await;
    let (server, _, stats) =
        start_server(json!({"password": PASSWORD, "handshake": handshake(site)})).await;

    // A ClientHello signed with another password gets the site itself,
    // also for what would be a data record.
    let (mut stream, flight) = hello(server, "not the password").await;
    assert_eq!(flight, site_flight(true));
    let data = Session::new("not the password", &SITE_RANDOM).seal(b"data");
    stream.write_all(&data).await.unwrap();
    assert_eq!(next(&mut stream).await, site_reply(&data));

    // So does a client that speaks no TLS.
    let mut probe = TcpStream::connect(server).await.unwrap();
    probe.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut reply = Vec::new();
    timeout(TIMEOUT, probe.read_to_end(&mut reply))
        .await
        .expect("no reply in time")
        .unwrap();
    assert_eq!(reply, PLAIN_REPLY);
    assert_eq!(stats.handshake_failed.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_mode_needs_a_tls13_site() {
    let site = start_site(false).await;
    for strict in [true, false] {
        let (server, _, _) = start_server(json!({
            "password": PASSWORD,
            "strict_mode": strict,
            "handshake": handshake(site),
        }))
        .await;
        let (mut stream, flight) = hello(server, PASSWORD).await;
        let expected = site_flight(false);
        assert_eq!(flight[..2], expected[..2]);
        let mut session = Session::new(PASSWORD, &SITE_RANDOM);
        let data = session.seal(b"data");
        stream.write_all(&data).await.unwrap();
        if strict {
            // Not served: the client and the site go on as if nothing was
            // between them.
            assert_eq!(flight[2..], expected[2..]);
            assert_eq!(next(&mut stream).await, site_reply(&data));
        } else {
            assert_eq!(session.unmark(&flight[2]), expected[2][HEADER..]);
            assert_eq!(session.unmark(&flight[3]), expected[3][HEADER..]);
            assert_eq!(read_data(&mut stream, &mut session, 4).await, b"data");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_a_bad_record_with_an_alert() {
    let site = start_site(true).await;
    let (server, _, _) =
        start_server(json!({"password": PASSWORD, "handshake": handshake(site)})).await;
    let (mut stream, _) = hello(server, PASSWORD).await;
    let mut session = Session::new(PASSWORD, &SITE_RANDOM);
    let first = session.seal(b"first");
    stream.write_all(&first).await.unwrap();
    assert_eq!(read_data(&mut stream, &mut session, 5).await, b"first");

    // A replayed record does not carry the tag that is due: the server
    // answers with what an encrypted alert looks like and closes.
    stream.write_all(&first).await.unwrap();
    let alert = next(&mut stream).await;
    assert_eq!((alert[0], alert.len()), (APPLICATION_DATA, HEADER + 19));
    let mut rest = Vec::new();
    let closed = timeout(TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .expect("not closed in time");
    assert!(closed.is_err() || rest.is_empty());
}
