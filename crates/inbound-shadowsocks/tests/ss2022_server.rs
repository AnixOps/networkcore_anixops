//! The Shadowsocks-2022 server inbound against the engine's own client
//! outbound and the shadowsocks-rust client.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{StreamInbound, User};
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound};
use inbound_shadowsocks::{Method, Ss2022Inbound};
use outbound_shadowsocks::Ss2022Outbound;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

fn key(method: Method, seed: u8) -> String {
    let key: Vec<u8> = (0..method.key_len())
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect();
    base64::engine::general_purpose::STANDARD.encode(key)
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

/// Echo server; with `banner` it speaks first.
async fn start_echo_server(banner: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Some(banner) = banner {
                    if stream.write_all(banner).await.is_err() {
                        return;
                    }
                }
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

struct Server {
    addr: SocketAddr,
    inbound: Arc<Ss2022Inbound>,
    stats: Arc<InboundStats>,
}

async fn start_server(method: Method, password: &str, users: Vec<User>) -> Server {
    let inbound = Arc::new(Ss2022Inbound::new(method, password, !users.is_empty()).unwrap());
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
    Server {
        addr,
        inbound,
        stats,
    }
}

fn ss_client(
    method: Method,
    server: SocketAddr,
    password: &str,
    dialer: Arc<dyn Dialer>,
) -> Ss2022Outbound {
    Ss2022Outbound::new(
        server.ip().to_string(),
        server.port(),
        method,
        password,
        dialer,
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
async fn single_key_round_trips_every_method() {
    let echo_addr = start_echo_server(None).await;
    for method in [
        Method::Aes128Gcm,
        Method::Aes256Gcm,
        Method::ChaCha20Poly1305,
    ] {
        let password = key(method, 11);
        let server = start_server(method, &password, Vec::new()).await;
        let client = ss_client(method, server.addr, &password, Arc::new(TcpDialer));
        let mut stream = client.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
        echo(&mut stream, &payload(64)).await.unwrap();
        echo(&mut stream, &payload(200 * 1024 + 3)).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_to_a_domain_target() {
    let echo_addr = start_echo_server(Some(b"220 ready\r\n")).await;
    let method = Method::Aes128Gcm;
    let password = key(method, 3);
    let server = start_server(method, &password, Vec::new()).await;
    let client = ss_client(method, server.addr, &password, Arc::new(TcpDialer));
    let target = TargetAddr::Domain("localhost".into(), echo_addr.port());
    let mut stream = match client.connect(&target).await {
        Ok(stream) => stream,
        Err(err) => panic!("connect failed: {err}"),
    };
    let mut banner = [0u8; 11];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut banner))
        .await
        .expect("banner timed out")
        .unwrap();
    assert_eq!(&banner, b"220 ready\r\n");
    echo(&mut stream, b"QUIT\r\n").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_user_charges_the_right_user_and_revokes() {
    let echo_addr = start_echo_server(None).await;
    for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
        let identity = key(method, 1);
        let alice = key(method, 2);
        let bob = key(method, 3);
        let server = start_server(
            method,
            &identity,
            vec![
                User::with_password("alice", alice.clone()),
                User::with_password("bob", bob.clone()),
            ],
        )
        .await;
        let alice_client = ss_client(
            method,
            server.addr,
            &format!("{identity}:{alice}"),
            Arc::new(TcpDialer),
        );
        let mut stream = alice_client
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        echo(&mut stream, &payload(1000)).await.unwrap();

        let users = server.inbound.users();
        // The relay charges a write just after handing it to the socket, so the
        // client can see the echo a moment before it is counted.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let traffic = users.traffic(true);
        assert_eq!(traffic.len(), 1, "{}", method.name());
        assert_eq!(traffic[0].name, "alice");
        assert_eq!((traffic[0].up, traffic[0].down), (1000, 1000));
        let online = users.online();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].name, "alice");

        // Removing alice closes her open session and refuses new ones.
        assert!(users.remove("alice"));
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
            .await
            .expect("revoked session should close");
        assert!(matches!(read, Ok(0) | Err(_)));

        let mut again = alice_client
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        assert!(echo(&mut again, b"denied").await.is_err());
        assert!(server.stats.handshake_failed.load(Ordering::Relaxed) >= 1);

        // Bob is unaffected.
        let bob_client = ss_client(
            method,
            server.addr,
            &format!("{identity}:{bob}"),
            Arc::new(TcpDialer),
        );
        let mut stream = bob_client
            .connect(&TargetAddr::Ip(echo_addr))
            .await
            .unwrap();
        echo(&mut stream, b"bob").await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_added_at_runtime_can_connect() {
    let echo_addr = start_echo_server(None).await;
    let method = Method::Aes256Gcm;
    let identity = key(method, 9);
    let carol = key(method, 10);
    let server = start_server(
        method,
        &identity,
        vec![User::with_password("seed", key(method, 12))],
    )
    .await;
    server
        .inbound
        .users()
        .add(User::with_password("carol", carol.clone()))
        .unwrap();
    let client = ss_client(
        method,
        server.addr,
        &format!("{identity}:{carol}"),
        Arc::new(TcpDialer),
    );
    let mut stream = client.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    echo(&mut stream, b"hello carol").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_key_gets_no_data() {
    let echo_addr = start_echo_server(None).await;
    let method = Method::Aes128Gcm;
    let server = start_server(method, &key(method, 1), Vec::new()).await;
    let client = ss_client(method, server.addr, &key(method, 99), Arc::new(TcpDialer));
    let mut stream = client.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    assert!(echo(&mut stream, b"hello").await.is_err());
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 1);
}

/// Dialer that records every byte the client sends.
struct TapDialer(Arc<Mutex<Vec<u8>>>);

struct Tap {
    inner: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            this.sent.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Dialer for TapDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let inner = TcpStream::connect((host, port)).await?;
            Ok(Box::new(Tap {
                inner,
                sent: self.0.clone(),
            }) as BoxStream)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_requests_are_refused() {
    let echo_addr = start_echo_server(None).await;
    let method = Method::Aes128Gcm;
    let password = key(method, 5);
    let server = start_server(method, &password, Vec::new()).await;
    let sent = Arc::new(Mutex::new(Vec::new()));
    let client = ss_client(
        method,
        server.addr,
        &password,
        Arc::new(TapDialer(sent.clone())),
    );
    let mut stream = client.connect(&TargetAddr::Ip(echo_addr)).await.unwrap();
    echo(&mut stream, b"original").await.unwrap();
    drop(stream);

    let recorded = sent.lock().unwrap().clone();
    let mut replay = TcpStream::connect(server.addr).await.unwrap();
    replay.write_all(&recorded).await.unwrap();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(TIMEOUT, replay.read(&mut buf))
        .await
        .expect("replayed session should be closed after the hold");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "replay must not get a response"
    );
    assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 1);
}

#[cfg(unix)]
mod reference_client {
    use super::*;
    use engine_inbound::udp::BoundUdpOutbound;
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use shadowsocks::relay::udprelay::options::UdpSocketControlData;
    use shadowsocks::relay::Address;
    use shadowsocks::{ProxyClientStream, ProxySocket};
    use tokio::net::UdpSocket;

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

    /// Serves the inbound's UDP side on a port of its own and returns it.
    fn start_udp(server: &Server) -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let served = server.inbound.datagram().expect("udp side").serve(
            socket,
            Arc::new(BoundUdpOutbound::new("127.0.0.1:0".parse().unwrap())),
            server.stats.clone(),
        );
        tokio::spawn(served);
        addr
    }

    async fn reference_udp_echo(
        method: Method,
        server: SocketAddr,
        password: &str,
        target: SocketAddr,
    ) {
        let config = ServerConfig::new(server, password.to_string(), kind_for(method))
            .expect("client config");
        let context = Context::new_shared(ServerType::Local);
        let socket = ProxySocket::connect(context, &config)
            .await
            .expect("reference udp socket");
        let mut buf = vec![0u8; 65_536];
        // Like sslocal, give the association a session id and count packets;
        // `ProxySocket::send` alone repeats packet 0, which is a replay.
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 0x5eed_0000_0000_0000 | u64::from(server.port());
        for data in [b"hello".to_vec(), payload(1200)] {
            // Datagrams may be lost; retry a few times and skip late replies
            // to an earlier attempt.
            let mut echoed = false;
            'attempts: for _ in 0..5 {
                control.packet_id += 1;
                socket
                    .send_with_ctrl(&Address::SocketAddress(target), &control, &data)
                    .await
                    .unwrap();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                while let Ok(reply) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await
                {
                    let (n, source, _) = reply.unwrap();
                    if buf[..n] == data[..] {
                        assert_eq!(source, Address::SocketAddress(target));
                        echoed = true;
                        break 'attempts;
                    }
                }
            }
            assert!(echoed, "udp echo through {method:?} timed out");
        }
    }

    fn kind_for(method: Method) -> CipherKind {
        match method {
            Method::Aes128Gcm => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            Method::Aes256Gcm => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            Method::ChaCha20Poly1305 => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }

    async fn reference_echo(
        method: Method,
        server: SocketAddr,
        password: &str,
        target: SocketAddr,
    ) {
        let config = ServerConfig::new(server, password.to_string(), kind_for(method))
            .expect("client config");
        let context = Context::new_shared(ServerType::Local);
        let stream = ProxyClientStream::connect(context, &config, target)
            .await
            .expect("reference client connects");
        let mut stream = Box::pin(stream);
        // The reference client expects its first write (address header plus
        // payload) to fit one SIP022 chunk, so start small.
        echo(&mut stream, b"hello").await.unwrap();
        echo(&mut stream, &payload(70 * 1024)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_client_single_key() {
        let echo_addr = start_echo_server(None).await;
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let password = key(method, 21);
            let server = start_server(method, &password, Vec::new()).await;
            reference_echo(method, server.addr, &password, echo_addr).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_client_multi_user() {
        let echo_addr = start_echo_server(None).await;
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let identity = key(method, 31);
            let user = key(method, 32);
            let server = start_server(
                method,
                &identity,
                vec![User::with_password("ref", user.clone())],
            )
            .await;
            reference_echo(
                method,
                server.addr,
                &format!("{identity}:{user}"),
                echo_addr,
            )
            .await;
            let traffic = server.inbound.users().traffic(false);
            assert_eq!(traffic.len(), 1);
            assert_eq!(traffic[0].name, "ref");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_client_udp_single_key() {
        let echo_addr = udp_echo_server().await;
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let password = key(method, 41);
            let server = start_server(method, &password, Vec::new()).await;
            let udp = start_udp(&server);
            reference_udp_echo(method, udp, &password, echo_addr).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_client_udp_multi_user() {
        let echo_addr = udp_echo_server().await;
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let identity = key(method, 51);
            let user = key(method, 52);
            let server = start_server(
                method,
                &identity,
                vec![User::with_password("udp", user.clone())],
            )
            .await;
            let udp = start_udp(&server);
            reference_udp_echo(method, udp, &format!("{identity}:{user}"), echo_addr).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let traffic = server.inbound.users().traffic(false);
            assert_eq!(traffic.len(), 1);
            assert_eq!(traffic[0].name, "udp");
            assert!(traffic[0].up >= 1205 && traffic[0].down >= 1205);

            // A wrong user key is not answered.
            let stranger = key(method, 53);
            let config = ServerConfig::new(udp, format!("{identity}:{stranger}"), kind_for(method))
                .expect("client config");
            let socket = ProxySocket::connect(Context::new_shared(ServerType::Local), &config)
                .await
                .unwrap();
            socket
                .send(&Address::SocketAddress(echo_addr), b"nope")
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf))
                    .await
                    .is_err()
            );
        }
    }
}
