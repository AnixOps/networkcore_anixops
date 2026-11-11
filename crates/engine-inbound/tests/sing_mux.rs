//! sing-mux through the serve loop: TCP and UDP streams on one client
//! connection, in smux and yamux frames and as h2mux requests the way
//! sing-box clients send them, with and without padding.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use engine_inbound::addr::{write_addr_port, SOCKS};
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server sends nothing before a test takes it as waiting.
const QUIET: Duration = Duration::from_millis(500);
/// The yamux window of a new stream.
const WINDOW: usize = 256 * 1024;

/// Every connection is alice asking for the multiplexing destination.
struct MuxInbound {
    users: Arc<UserStore>,
}

impl StreamInbound for MuxInbound {
    fn protocol(&self) -> &'static str {
        "sing-mux-test"
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
                user: self.users.get("alice"),
                target: TargetAddr::Domain("sp.mux.sing-box.arpa".into(), 444),
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

async fn tcp_echo() -> SocketAddr {
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

/// A target that sends for as long as it is connected.
async fn tcp_source() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move { while stream.write_all(&[0x5a; 4096]).await.is_ok() {} });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn start() -> (SocketAddr, Arc<UserStore>, Arc<InboundStats>) {
    let users = Arc::new(UserStore::default());
    users.add(User::with_password("alice", "unused")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let settings = ServeSettings {
        connect_timeout: Duration::from_secs(2),
        ..ServeSettings::default()
    };
    tokio::spawn(serve_with_udp(
        listener,
        Arc::new(MuxInbound {
            users: users.clone(),
        }),
        Arc::new(Direct),
        Some(Arc::new(BoundUdpOutbound::new(
            "127.0.0.1:0".parse().unwrap(),
        ))),
        settings,
        stats.clone(),
    ));
    (addr, users, stats)
}

/// What a stream starts with: its flags and destination.
fn request(flags: u16, target: SocketAddr) -> Vec<u8> {
    let mut out = flags.to_be_bytes().to_vec();
    write_addr_port(&mut out, target, SOCKS);
    out
}

/// A UDP packet on a stream, behind its address when the stream has packet
/// addresses.
fn packet(address: Option<SocketAddr>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(address) = address {
        write_addr_port(&mut out, address, SOCKS);
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn smux(command: u8, stream: u32, data: &[u8]) -> Vec<u8> {
    let mut out = vec![1, command];
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&stream.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// A server frame: command, stream and data.
async fn read_smux(client: &mut TcpStream) -> (u8, u32, Vec<u8>) {
    timeout(TIMEOUT, async {
        let mut header = [0u8; 8];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 1);
        let mut data = vec![0u8; usize::from(u16::from_le_bytes([header[2], header[3]]))];
        client.read_exact(&mut data).await.unwrap();
        let stream = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        (header[1], stream, data)
    })
    .await
    .expect("smux frame timed out")
}

/// The next `len` bytes the server sends on `stream`, with no frame of
/// another stream in between.
async fn smux_data(client: &mut TcpStream, stream: u32, len: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < len {
        let (command, id, data) = read_smux(client).await;
        assert_eq!((command, id), (2, stream));
        received.extend(data);
    }
    received
}

/// A yamux frame; `length` is the window increment or ping value of frames
/// without data.
fn yamux(kind: u8, flags: u16, stream: u32, length: u32, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0, kind];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn yamux_data(stream: u32, data: &[u8]) -> Vec<u8> {
    yamux(0, 0, stream, data.len() as u32, data)
}

/// A server frame: type, flags, stream, length and the data of a Data
/// frame.
async fn read_yamux(client: &mut TcpStream) -> (u8, u16, u32, u32, Vec<u8>) {
    timeout(TIMEOUT, async {
        let mut header = [0u8; 12];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0);
        let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        let mut data = vec![0u8; if header[1] == 0 { length as usize } else { 0 }];
        client.read_exact(&mut data).await.unwrap();
        (
            header[1],
            u16::from_be_bytes([header[2], header[3]]),
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            length,
            data,
        )
    })
    .await
    .expect("yamux frame timed out")
}

/// The next `len` bytes the server sends on stream 1, and what its window
/// updates in between add to the client's window.
async fn yamux_echo(client: &mut TcpStream, len: usize) -> (Vec<u8>, usize) {
    let (mut received, mut granted) = (Vec::new(), 0);
    while received.len() < len {
        let (kind, flags, stream, length, data) = read_yamux(client).await;
        assert_eq!((flags, stream), (0, 1));
        match kind {
            0 => received.extend(data),
            _ => granted += length as usize,
        }
    }
    (received, granted)
}

/// The HTTP/2 side of an h2mux client, on a connection that starts with
/// `session`.
async fn h2mux(server: SocketAddr, session: &[u8]) -> SendRequest<Bytes> {
    let mut client = TcpStream::connect(server).await.unwrap();
    client.write_all(session).await.unwrap();
    let (requests, connection) = h2::client::handshake(client).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    requests
}

/// Opens an h2mux stream: a CONNECT request, answered 200 ahead of any
/// data. What the client sends is the request body, what it receives the
/// response body.
async fn h2_stream(requests: &SendRequest<Bytes>) -> (SendStream<Bytes>, RecvStream) {
    let mut requests = requests.clone().ready().await.unwrap();
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("localhost")
        .body(())
        .unwrap();
    let (response, send) = requests.send_request(request, false).unwrap();
    let response = timeout(TIMEOUT, response)
        .await
        .expect("h2mux response timed out")
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    (send, response.into_body())
}

/// The next `len` bytes the server sends on an h2mux stream.
async fn h2_data(body: &mut RecvStream, len: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < len {
        let chunk = timeout(TIMEOUT, body.data())
            .await
            .expect("h2mux data timed out")
            .expect("h2mux stream ended")
            .unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        received.extend_from_slice(&chunk);
    }
    received
}

/// A padded record: `data` behind its length and that of the padding.
fn record(data: &[u8], padding: usize) -> Vec<u8> {
    let mut out = (data.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(out.len() + padding, 0xee);
    out
}

/// The client's reading of a padded connection: the data of the server's
/// first 16 records, then its bytes as they are.
#[derive(Default)]
struct Unpadded {
    records: usize,
    data: Vec<u8>,
}

impl Unpadded {
    /// The next `len` bytes of the server's multiplexer.
    async fn read(&mut self, client: &mut TcpStream, len: usize) -> Vec<u8> {
        let fill = async {
            while self.data.len() < len {
                if self.records == 16 {
                    let mut plain = vec![0u8; len - self.data.len()];
                    client.read_exact(&mut plain).await.unwrap();
                    self.data.extend(plain);
                    break;
                }
                let mut header = [0u8; 4];
                client.read_exact(&mut header).await.unwrap();
                let data = usize::from(u16::from_be_bytes([header[0], header[1]]));
                let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
                assert!((256..768).contains(&padding), "{padding}");
                let mut record = vec![0u8; data + padding];
                client.read_exact(&mut record).await.unwrap();
                self.data.extend_from_slice(&record[..data]);
                self.records += 1;
            }
        };
        timeout(TIMEOUT, fill).await.expect("padded data timed out");
        self.data.drain(..len).collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smux_streams_share_one_connection() {
    let (server, users, _stats) = start().await;
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let other_udp = udp_echo().await;
    let mut client = TcpStream::connect(server).await.unwrap();
    // Version 1, smux, no padding.
    client.write_all(&[1, 0, 0]).await.unwrap();

    // A TCP stream: SYN, then the request with the first payload. The
    // status comes ahead of the first data.
    let mut open = smux(0, 1, &[]);
    open.extend(smux(2, 1, &[request(0, tcp), b"hello".to_vec()].concat()));
    client.write_all(&open).await.unwrap();
    assert_eq!(smux_data(&mut client, 1, 6).await, b"\0hello");
    // NOP is the keepalive.
    let mut more = smux(3, 0, &[]);
    more.extend(smux(2, 1, b"again"));
    client.write_all(&more).await.unwrap();
    assert_eq!(smux_data(&mut client, 1, 5).await, b"again");

    // A UDP stream with packet addresses: each packet names its
    // destination and each reply its source.
    let mut open = smux(0, 3, &[]);
    open.extend(smux(2, 3, &request(3, udp)));
    open.extend(smux(2, 3, &packet(Some(udp), b"ping")));
    client.write_all(&open).await.unwrap();
    let reply = [vec![0], packet(Some(udp), b"ping")].concat();
    assert_eq!(smux_data(&mut client, 3, reply.len()).await, reply);
    let next = packet(Some(other_udp), b"pong");
    client.write_all(&smux(2, 3, &next)).await.unwrap();
    assert_eq!(smux_data(&mut client, 3, next.len()).await, next);

    // A UDP stream without: every packet goes to the stream's destination.
    let mut open = smux(0, 5, &[]);
    open.extend(smux(
        2,
        5,
        &[request(1, udp), packet(None, b"data")].concat(),
    ));
    client.write_all(&open).await.unwrap();
    assert_eq!(smux_data(&mut client, 5, 7).await, b"\0\0\x04data");

    // The client's FIN closes the target side; the server answers FIN when
    // the target closed and again as the stream ends.
    client.write_all(&smux(1, 1, &[])).await.unwrap();
    for _ in 0..2 {
        assert_eq!(read_smux(&mut client).await, (1, 1, Vec::new()));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = users.traffic(false);
    let total = (5 + 5 + 4 + 4 + 4) as u64;
    assert_eq!((traffic[0].up, traffic[0].down), (total, total));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yamux_streams_keep_to_their_windows() {
    let (server, users, _stats) = start().await;
    let tcp = tcp_echo().await;
    let mut client = TcpStream::connect(server).await.unwrap();
    // Version 1, yamux, no padding.
    client.write_all(&[1, 1, 0]).await.unwrap();

    // A window update with SYN opens a stream and is acknowledged; a ping
    // is answered with its value.
    client.write_all(&yamux(1, 1, 1, 0, &[])).await.unwrap();
    assert_eq!(read_yamux(&mut client).await, (1, 2, 1, 0, Vec::new()));
    client.write_all(&yamux(2, 1, 0, 7, &[])).await.unwrap();
    assert_eq!(read_yamux(&mut client).await, (2, 2, 0, 7, Vec::new()));

    let first = [request(0, tcp), b"hello".to_vec()].concat();
    client.write_all(&yamux_data(1, &first)).await.unwrap();
    assert_eq!(yamux_echo(&mut client, 6).await.0, b"\0hello");

    // The server reopens the client's window as the target takes the data.
    let chunk = vec![0x5a; 50_000];
    let mut granted = 0;
    for _ in 0..4 {
        client.write_all(&yamux_data(1, &chunk)).await.unwrap();
        let (echo, update) = yamux_echo(&mut client, chunk.len()).await;
        assert_eq!(echo, chunk);
        granted += update;
    }
    assert!(granted >= WINDOW / 2, "{granted}");

    // It sends within its own: 6 + 200 000 bytes went out, so the rest of
    // the next echo waits for the client's window update.
    for _ in 0..2 {
        client.write_all(&yamux_data(1, &chunk)).await.unwrap();
    }
    let mut received = 0;
    while let Ok(peeked) = timeout(QUIET, client.peek(&mut [0u8; 1])).await {
        peeked.unwrap();
        let (kind, _, _, length, _) = read_yamux(&mut client).await;
        if kind == 0 {
            received += length as usize;
        }
    }
    assert!(received > 0 && received <= WINDOW - 200_006, "{received}");
    client
        .write_all(&yamux(1, 0, 1, WINDOW as u32, &[]))
        .await
        .unwrap();
    yamux_echo(&mut client, 100_000 - received).await;

    // The client's FIN closes the target side; the server answers FIN when
    // the target closed and RST as the stream ends.
    client.write_all(&yamux(1, 4, 1, 0, &[])).await.unwrap();
    let mut ends = Vec::new();
    while ends.len() < 2 {
        let (kind, flags, stream, _, _) = read_yamux(&mut client).await;
        // Window updates may still be on their way.
        if flags != 0 {
            ends.push((kind, flags, stream));
        }
    }
    assert_eq!(ends, [(1, 4, 1), (1, 8, 1)]);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = users.traffic(false);
    assert_eq!((traffic[0].up, traffic[0].down), (300_005, 300_005));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yamux_reset_ends_a_half_closed_stream() {
    let (server, _users, _stats) = start().await;
    let source = tcp_source().await;
    let mut client = TcpStream::connect(server).await.unwrap();
    client.write_all(&[1, 1, 0]).await.unwrap();

    // The client closes its side and never reopens its window, so the
    // server is left waiting with the rest of the download.
    let mut open = yamux(1, 1, 1, 0, &[]);
    open.extend(yamux_data(1, &request(0, source)));
    open.extend(yamux(1, 4, 1, 0, &[]));
    client.write_all(&open).await.unwrap();
    assert_eq!(read_yamux(&mut client).await, (1, 2, 1, 0, Vec::new()));
    let mut received = 0;
    // No frame is larger than 16 KiB.
    while received <= WINDOW - 16 * 1024 {
        let (kind, flags, stream, length, _) = read_yamux(&mut client).await;
        assert_eq!((kind, flags, stream), (0, 0, 1));
        received += length as usize;
    }

    // A reset ends the stream all the same, and the server answers RST.
    client.write_all(&yamux(1, 8, 1, 0, &[])).await.unwrap();
    loop {
        let (kind, flags, stream, _, _) = read_yamux(&mut client).await;
        if kind == 1 {
            assert_eq!((flags, stream), (8, 1));
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2mux_streams_are_connect_requests() {
    let (server, users, _stats) = start().await;
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    // Version 0, h2mux.
    let requests = h2mux(server, &[0, 2]).await;

    // A TCP stream: the request with the first payload, and the status
    // ahead of the first data.
    let (mut send, mut body) = h2_stream(&requests).await;
    let first = [request(0, tcp), b"hello".to_vec()].concat();
    send.send_data(first.into(), false).unwrap();
    assert_eq!(h2_data(&mut body, 6).await, b"\0hello");

    // More than a window at once, either way: the server reopens its own
    // as the target takes the data and sends within the client's.
    let chunk = vec![0x5a; 300_000];
    send.send_data(chunk.clone().into(), false).unwrap();
    assert!(h2_data(&mut body, chunk.len()).await == chunk);

    // A UDP stream with packet addresses on the same connection.
    let (mut packets, mut replies) = h2_stream(&requests).await;
    let open = [request(3, udp), packet(Some(udp), b"ping")].concat();
    packets.send_data(open.into(), false).unwrap();
    let reply = [vec![0], packet(Some(udp), b"ping")].concat();
    assert_eq!(h2_data(&mut replies, reply.len()).await, reply);

    // The end of the request body closes the target side, and the response
    // body ends when the target has closed.
    send.send_data(Bytes::new(), true).unwrap();
    // The end may come as an empty DATA frame with END_STREAM.
    while let Some(end) = timeout(TIMEOUT, body.data())
        .await
        .expect("h2mux end timed out")
    {
        assert!(end.unwrap().is_empty());
    }

    // A request that is not CONNECT is not a stream.
    let mut other = requests.clone().ready().await.unwrap();
    let get = http::Request::builder()
        .uri("https://localhost/")
        .body(())
        .unwrap();
    let (response, _) = other.send_request(get, true).unwrap();
    let response = timeout(TIMEOUT, response)
        .await
        .expect("h2mux response timed out")
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = users.traffic(false);
    assert_eq!((traffic[0].up, traffic[0].down), (300_009, 300_009));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn padded_sessions_pad_their_first_writes() {
    let (server, _users, _stats) = start().await;
    let tcp = tcp_echo().await;
    let mut client = TcpStream::connect(server).await.unwrap();
    // Version 1, smux, padding: two bytes of it behind the request.
    client
        .write_all(&[1, 0, 1, 0, 2, 0xee, 0xee])
        .await
        .unwrap();
    let mut server_data = Unpadded::default();

    // The first 16 writes of each side are records, the rest plain: the
    // client's first opens a stream, and one echo follows another.
    let mut open = smux(0, 1, &[]);
    open.extend(smux(2, 1, &[request(0, tcp), b"hello".to_vec()].concat()));
    client.write_all(&record(&open, 300)).await.unwrap();
    let echo = smux(2, 1, b"\0hello");
    assert_eq!(server_data.read(&mut client, echo.len()).await, echo);
    for round in 1..20u8 {
        let frame = smux(2, 1, &[round; 10]);
        let sent = if round < 16 {
            record(&frame, usize::from(round))
        } else {
            frame.clone()
        };
        client.write_all(&sent).await.unwrap();
        assert_eq!(server_data.read(&mut client, frame.len()).await, frame);
    }
    assert_eq!(server_data.records, 16);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_what_it_does_not_serve() {
    let (server, _users, stats) = start().await;
    let tcp = tcp_echo().await;

    // An unknown protocol and a later version close the connection.
    for session in [[1u8, 3, 0], [2, 0, 0]] {
        let mut client = TcpStream::connect(server).await.unwrap();
        client.write_all(&session).await.unwrap();
        let end = timeout(TIMEOUT, client.read(&mut [0u8; 1])).await.unwrap();
        assert!(matches!(end, Ok(0) | Err(_)));
    }
    assert_eq!(stats.handshake_failed.load(Ordering::Relaxed), 2);

    // Version 0 has no padding flag. A stream whose target refuses is
    // closed without a status, and the connection stays usable.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = closed.local_addr().unwrap();
    drop(closed);
    let mut client = TcpStream::connect(server).await.unwrap();
    client.write_all(&[0, 0]).await.unwrap();
    let mut open = smux(0, 3, &[]);
    open.extend(smux(2, 3, &request(0, refused)));
    client.write_all(&open).await.unwrap();
    assert_eq!(read_smux(&mut client).await, (1, 3, Vec::new()));
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 1);

    let mut open = smux(0, 5, &[]);
    open.extend(smux(2, 5, &[request(0, tcp), b"next".to_vec()].concat()));
    client.write_all(&open).await.unwrap();
    assert_eq!(smux_data(&mut client, 5, 5).await, b"\0next");

    // h2mux resets such a stream, and its connection stays usable too.
    let requests = h2mux(server, &[0, 2]).await;
    let (mut send, mut body) = h2_stream(&requests).await;
    send.send_data(request(0, refused).into(), false).unwrap();
    let end = timeout(TIMEOUT, body.data())
        .await
        .expect("h2mux reset timed out");
    assert!(matches!(end, Some(Err(_))), "{end:?}");
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 2);

    let (mut send, mut body) = h2_stream(&requests).await;
    let first = [request(0, tcp), b"next".to_vec()].concat();
    send.send_data(first.into(), false).unwrap();
    assert_eq!(h2_data(&mut body, 5).await, b"\0next");
}
