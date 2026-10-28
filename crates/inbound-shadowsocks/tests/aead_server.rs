//! The Shadowsocks AEAD (SIP004) server inbound against the engine's own
//! client outbound and the shadowsocks-rust client.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::{StreamInbound, User};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_shadowsocks::{AeadInbound, AeadMethod};
use outbound_shadowsocks::AeadOutbound;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TIMEOUT: Duration = Duration::from_secs(10);
const METHODS: [AeadMethod; 3] = [
    AeadMethod::Aes128Gcm,
    AeadMethod::Aes256Gcm,
    AeadMethod::ChaCha20Poly1305,
];

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

async fn udp_echo_server() -> SocketAddr {
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

struct Server {
    addr: SocketAddr,
    udp: SocketAddr,
    inbound: Arc<AeadInbound>,
    stats: Arc<InboundStats>,
}

async fn start_server(method: AeadMethod, password: &str, users: Vec<User>) -> Server {
    let inbound = Arc::new(AeadInbound::new(method, password).unwrap());
    inbound.users().add_all(users).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let settings = ServeSettings {
        reject_hold: Duration::from_millis(500),
        ..ServeSettings::default()
    };
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        settings,
        stats.clone(),
    ));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp = socket.local_addr().unwrap();
    tokio::spawn(inbound.datagram().expect("udp side").serve(
        socket,
        Arc::new(BoundUdpOutbound::new("127.0.0.1:0".parse().unwrap())),
        stats.clone(),
    ));
    Server {
        addr,
        udp,
        inbound,
        stats,
    }
}

fn client(method: AeadMethod, server: SocketAddr, password: &str) -> AeadOutbound {
    AeadOutbound::new(
        server.ip().to_string(),
        server.port(),
        method,
        password,
        Arc::new(TcpDialer),
    )
    .expect("valid outbound")
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        writer.write_all(payload).await?;
        writer.flush().await
    };
    let read = async {
        let mut received = vec![0u8; payload.len()];
        reader.read_exact(&mut received).await?;
        Ok::<_, io::Error>(received)
    };
    let (written, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(write, read) })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "echo timed out"))?;
    written?;
    assert!(received? == payload, "echoed bytes differ");
    Ok(())
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_key_round_trips_every_method() {
    let echo_addr = start_echo_server().await;
    for method in METHODS {
        let server = start_server(method, "server-pass", Vec::new()).await;
        let mut stream = client(method, server.addr, "server-pass")
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        echo(&mut stream, b"hello").await.unwrap();
        echo(&mut stream, &payload(70 * 1024)).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_are_found_by_key_charged_and_revoked() {
    let echo_addr = start_echo_server().await;
    for method in METHODS {
        let users = (1..=50)
            .map(|id| User::with_password(id.to_string(), format!("user-password-{id}")))
            .collect();
        let server = start_server(method, "", users).await;
        let mut stream = client(method, server.addr, "user-password-37")
            .connect(&TargetAddr::Domain("localhost".into(), echo_addr.port()))
            .await
            .unwrap();
        echo(&mut stream, &payload(4096)).await.unwrap();
        let traffic = server.inbound.users().traffic(false);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].name, "37");
        assert!(traffic[0].up >= 4096 && traffic[0].down >= 4096);

        // A second connection from the same IP hits the remembered key.
        let mut again = client(method, server.addr, "user-password-37")
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        echo(&mut again, b"again").await.unwrap();

        server.inbound.users().remove("37");
        let mut buf = [0u8; 8];
        let closed = tokio::time::timeout(TIMEOUT, again.read(&mut buf)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "removed user is cut off"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_added_at_runtime_can_connect_and_strangers_cannot() {
    let echo_addr = start_echo_server().await;
    let method = AeadMethod::Aes128Gcm;
    let server = start_server(method, "", Vec::new()).await;
    let mut stranger = client(method, server.addr, "late")
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    stranger.write_all(b"nope").await.unwrap();
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_millis(300), stranger.read(&mut buf)).await;
    assert!(
        !matches!(read, Ok(Ok(n)) if n > 0),
        "an unknown key gets no data"
    );

    server
        .inbound
        .users()
        .add(User::with_password("late", "late"))
        .unwrap();
    let mut stream = client(method, server.addr, "late")
        .connect(&TargetAddr::Ip(echo_addr))
        .await
        .unwrap();
    echo(&mut stream, b"welcome").await.unwrap();
    assert!(server.stats.handshake_failed.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_relays_and_charges_users() {
    let echo_addr = udp_echo_server().await;
    for method in METHODS {
        let users = vec![
            User::with_password("1", "first"),
            User::with_password("2", "second"),
        ];
        let server = start_server(method, "", users).await;
        let mut flow = client(method, server.udp, "second")
            .open_udp(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        for data in [b"hello".to_vec(), payload(1200)] {
            flow.send.send(&data).await.unwrap();
            let reply = tokio::time::timeout(TIMEOUT, flow.recv.recv())
                .await
                .expect("udp reply timed out")
                .unwrap();
            assert_eq!(reply, data);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let traffic = server.inbound.users().traffic(false);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].name, "2");
        assert!(traffic[0].up >= 1205 && traffic[0].down >= 1205);
    }
}

#[cfg(unix)]
mod reference_client {
    use super::*;
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use shadowsocks::relay::Address;
    use shadowsocks::{ProxyClientStream, ProxySocket};

    fn kind_for(method: AeadMethod) -> CipherKind {
        match method {
            AeadMethod::Aes128Gcm => CipherKind::AES_128_GCM,
            AeadMethod::Aes256Gcm => CipherKind::AES_256_GCM,
            AeadMethod::ChaCha20Poly1305 => CipherKind::CHACHA20_POLY1305,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_client_tcp_and_udp_as_a_user() {
        let echo_addr = start_echo_server().await;
        let udp_echo = udp_echo_server().await;
        for method in METHODS {
            let users = vec![
                User::with_password("a", "alpha"),
                User::with_password("b", "bravo"),
            ];
            let server = start_server(method, "", users).await;

            let config =
                ServerConfig::new(server.addr, "bravo".to_string(), kind_for(method)).unwrap();
            let stream = ProxyClientStream::connect(
                Context::new_shared(ServerType::Local),
                &config,
                echo_addr,
            )
            .await
            .expect("reference client connects");
            let mut stream = Box::pin(stream);
            echo(&mut stream, b"hello").await.unwrap();
            echo(&mut stream, &payload(70 * 1024)).await.unwrap();

            let config =
                ServerConfig::new(server.udp, "bravo".to_string(), kind_for(method)).unwrap();
            let socket = ProxySocket::connect(Context::new_shared(ServerType::Local), &config)
                .await
                .unwrap();
            let mut buf = vec![0u8; 65_536];
            let mut echoed = false;
            // Datagrams may be lost; retry a few times.
            'attempts: for _ in 0..5 {
                socket
                    .send(&Address::SocketAddress(udp_echo), b"datagram")
                    .await
                    .unwrap();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                while let Ok(reply) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await
                {
                    let (n, source, _) = reply.unwrap();
                    if &buf[..n] == b"datagram" {
                        assert_eq!(source, Address::SocketAddress(udp_echo));
                        echoed = true;
                        break 'attempts;
                    }
                }
            }
            assert!(echoed, "udp echo through {method:?} timed out");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let traffic = server.inbound.users().traffic(false);
            assert_eq!(traffic.len(), 1);
            assert_eq!(traffic[0].name, "b");
        }
    }
}
