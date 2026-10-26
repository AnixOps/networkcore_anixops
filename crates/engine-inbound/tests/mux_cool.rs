//! Mux.Cool and XUDP through the serve loop: TCP and UDP sessions on one
//! client connection, framed the way Xray clients frame them.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::addr::{write_port_addr, VMESS};
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Every connection is alice's mux connection.
struct MuxInbound {
    users: Arc<UserStore>,
}

impl StreamInbound for MuxInbound {
    fn protocol(&self) -> &'static str {
        "mux-test"
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
                target: TargetAddr::Domain("v1.mux.cool".into(), 0),
                stream,
                udp: None,
                mux: true,
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

/// A client frame. `target` is `(network, address)`: on New the session's
/// target, on Keep an XUDP datagram's address.
fn frame(
    session: u16,
    status: u8,
    target: Option<(u8, SocketAddr)>,
    global_id: bool,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut meta = session.to_be_bytes().to_vec();
    meta.push(status);
    meta.push(if data.is_some() { 1 } else { 0 });
    if let Some((network, addr)) = target {
        meta.push(network);
        write_port_addr(&mut meta, addr, VMESS);
        if global_id {
            meta.extend_from_slice(&[7u8; 8]);
        }
    }
    let mut out = (meta.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&meta);
    if let Some(data) = data {
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// A server frame: session, status, option, the UDP address of a Keep frame
/// and the data.
struct Reply {
    session: u16,
    status: u8,
    option: u8,
    source: Option<SocketAddr>,
    data: Vec<u8>,
}

async fn read_reply(stream: &mut TcpStream) -> Reply {
    tokio::time::timeout(TIMEOUT, async {
        let len = usize::from(stream.read_u16().await.unwrap());
        let mut meta = vec![0u8; len];
        stream.read_exact(&mut meta).await.unwrap();
        let source = (meta.len() > 4 && meta[4] == 2).then(|| {
            let port = u16::from_be_bytes([meta[5], meta[6]]);
            assert_eq!(meta[7], 1, "replies come from IPv4 test servers");
            SocketAddr::from(([meta[8], meta[9], meta[10], meta[11]], port))
        });
        let mut data = Vec::new();
        if meta[3] & 1 != 0 {
            let len = usize::from(stream.read_u16().await.unwrap());
            data = vec![0u8; len];
            stream.read_exact(&mut data).await.unwrap();
        }
        Reply {
            session: u16::from_be_bytes([meta[0], meta[1]]),
            status: meta[2],
            option: meta[3],
            source,
            data,
        }
    })
    .await
    .expect("mux reply timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_and_udp_sessions_share_one_connection() {
    let (server, users, _stats) = start().await;
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let other_udp = udp_echo().await;
    let mut client = TcpStream::connect(server).await.unwrap();

    // A TCP session with data in its New frame.
    client
        .write_all(&frame(1, 1, Some((1, tcp)), false, Some(b"hello")))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!((reply.session, reply.status, reply.source), (1, 2, None));
    assert_eq!(reply.data, b"hello");

    // XUDP: New with a global id, then Keep frames naming each datagram's
    // address; replies name their source.
    client
        .write_all(&frame(0, 1, Some((2, udp)), true, Some(b"ping")))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!((reply.session, reply.status), (0, 2));
    assert_eq!(reply.source, Some(udp));
    assert_eq!(reply.data, b"ping");
    client
        .write_all(&frame(0, 2, Some((2, other_udp)), false, Some(b"pong")))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!(reply.source, Some(other_udp));
    assert_eq!(reply.data, b"pong");

    // More TCP data on session 1, then KeepAlive (ignored).
    client
        .write_all(&frame(1, 2, None, false, Some(b"again")))
        .await
        .unwrap();
    client
        .write_all(&frame(0, 4, None, false, None))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!((reply.session, reply.status), (1, 2));
    assert_eq!(reply.data, b"again");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let traffic = users.traffic(false);
    let total = (5 + 4 + 4 + 5) as u64;
    assert_eq!((traffic[0].up, traffic[0].down), (total, total));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ends_are_relayed_both_ways() {
    let (server, _users, stats) = start().await;
    let tcp = tcp_echo().await;
    let mut client = TcpStream::connect(server).await.unwrap();

    // A refused target gets End with the error option.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = closed.local_addr().unwrap();
    drop(closed);
    client
        .write_all(&frame(3, 1, Some((1, refused)), false, None))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!((reply.session, reply.status, reply.option), (3, 3, 2));
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 1);

    // The client's End closes the target side; the server answers End.
    client
        .write_all(&frame(4, 1, Some((1, tcp)), false, Some(b"bye")))
        .await
        .unwrap();
    let reply = read_reply(&mut client).await;
    assert_eq!(reply.data, b"bye");
    client
        .write_all(&frame(4, 3, None, false, None))
        .await
        .unwrap();
    // The echo server sees EOF and closes, so the session ends; any reply
    // left is End for session 4, and the connection stays usable.
    client
        .write_all(&frame(5, 1, Some((1, tcp)), false, Some(b"next")))
        .await
        .unwrap();
    loop {
        let reply = read_reply(&mut client).await;
        if reply.session == 5 {
            assert_eq!(reply.data, b"next");
            break;
        }
        assert_eq!((reply.session, reply.status), (4, 3));
    }
}
