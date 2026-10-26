//! The serve loop with a toy line protocol: per-user traffic, online IPs and
//! revocation.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Client sends `<user>\n`, then payload; every session goes to `target`.
struct LineInbound {
    users: Arc<UserStore>,
    target: SocketAddr,
}

impl StreamInbound for LineInbound {
    fn protocol(&self) -> &'static str {
        "line"
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
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let Some(user) = self.users.get(line.trim_end()) else {
                return Err(Rejected::hold("unknown user", Box::new(reader)));
            };
            Ok(Accepted {
                user: Some(user),
                target: TargetAddr::Ip(self.target),
                stream: Box::new(reader),
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

async fn start_server() -> (SocketAddr, Arc<UserStore>, Arc<InboundStats>) {
    let echo = start_echo_server().await;
    let users = Arc::new(UserStore::default());
    users.add(User::with_password("alice", "unused")).unwrap();
    let inbound = Arc::new(LineInbound {
        users: users.clone(),
        target: echo,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let settings = ServeSettings {
        reject_hold: Duration::from_millis(300),
        ..ServeSettings::default()
    };
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        settings,
        stats.clone(),
    ));
    (addr, users, stats)
}

async fn round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn charges_traffic_and_reports_online_ips() {
    let (addr, users, stats) = start_server().await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"alice\n").await.unwrap();
    round_trip(&mut client, b"hello world").await;

    let online = users.online();
    assert_eq!(online.len(), 1);
    assert_eq!(online[0].name, "alice");
    assert!(online[0].ip.is_loopback());

    let traffic = users.traffic(true);
    assert_eq!(traffic.len(), 1);
    assert_eq!((traffic[0].up, traffic[0].down), (11, 11));
    assert!(users.traffic(true).is_empty());
    assert!(stats.bytes_up.load(Ordering::Relaxed) >= 11);

    drop(client);
    tokio::time::timeout(TIMEOUT, async {
        while !users.online().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("closed connection should go offline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_user_closes_its_connections() {
    let (addr, users, stats) = start_server().await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"alice\n").await.unwrap();
    round_trip(&mut client, b"ping").await;

    assert!(users.remove("alice"));
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(TIMEOUT, client.read(&mut buf))
        .await
        .expect("revoked connection should close");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert_eq!(stats.revoked.load(Ordering::Relaxed), 1);
    // Traffic of the removed user is still reported once.
    assert_eq!(users.traffic(true).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_users_are_held_then_closed() {
    let (addr, _users, stats) = start_server().await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"mallory\npayload").await.unwrap();
    let started = tokio::time::Instant::now();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(TIMEOUT, client.read(&mut buf))
        .await
        .expect("held connection should close after reject_hold");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(stats.handshake_failed.load(Ordering::Relaxed), 1);
}
