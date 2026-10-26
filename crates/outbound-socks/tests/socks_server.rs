//! The SOCKS5 client against this repo's own SOCKS5 server (`inbound-mixed`)
//! relaying directly to local test servers.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_mixed::{serve, Credentials, MixedSettings, MixedStats};
use outbound_socks::{SocksCredentials, SocksFactory, SocksOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "test-direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host().as_str(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

async fn echo_server() -> SocketAddr {
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

/// Sends a banner right after accepting, to check that no reply byte is left
/// in front of the target's data.
async fn banner_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"220 ready\r\n").await;
        }
    });
    addr
}

async fn socks_server(credentials: Option<Credentials>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let settings = MixedSettings {
        credentials,
        ..MixedSettings::default()
    };
    tokio::spawn(serve(
        listener,
        Arc::new(Direct),
        settings,
        Arc::new(MixedStats::default()),
    ));
    addr
}

fn outbound(server: SocketAddr, credentials: Option<(&str, &str)>) -> SocksOutbound {
    SocksOutbound::new(
        server.ip().to_string(),
        server.port(),
        credentials.map(|(username, password)| SocksCredentials {
            username: username.into(),
            password: password.into(),
        }),
        Arc::new(TcpDialer),
    )
    .unwrap()
}

fn user() -> Credentials {
    Credentials {
        username: "alice".into(),
        password: "secret".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_to_ip_and_domain_targets_with_and_without_auth() {
    let echo = echo_server().await;
    let open = socks_server(None).await;
    let authenticated = socks_server(Some(user())).await;
    for socks in [
        outbound(open, None),
        outbound(open, Some(("alice", "secret"))),
        outbound(authenticated, Some(("alice", "secret"))),
    ] {
        for target in [
            TargetAddr::Ip(echo),
            TargetAddr::Domain("localhost".into(), echo.port()),
        ] {
            let mut stream = socks.connect(&target).await.unwrap();
            stream.write_all(b"hello socks").await.unwrap();
            let mut echoed = [0u8; 11];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello socks", "{target}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_targets_get_their_bytes_intact() {
    let banner = banner_server().await;
    let server = socks_server(None).await;
    let mut stream = outbound(server, None)
        .connect(&TargetAddr::Ip(banner))
        .await
        .unwrap();
    let mut line = [0u8; 11];
    stream.read_exact(&mut line).await.unwrap();
    assert_eq!(&line, b"220 ready\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_failures_and_connect_failures_are_errors() {
    let echo = echo_server().await;
    let authenticated = socks_server(Some(user())).await;
    let missing = outbound(authenticated, None)
        .connect(&TargetAddr::Ip(echo))
        .await
        .err()
        .unwrap();
    assert_eq!(missing.kind(), io::ErrorKind::PermissionDenied);
    let wrong = outbound(authenticated, Some(("alice", "wrong")))
        .connect(&TargetAddr::Ip(echo))
        .await
        .err()
        .unwrap();
    assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);

    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let open = socks_server(None).await;
    assert!(outbound(open, None)
        .connect(&TargetAddr::Ip(closed))
        .await
        .is_err());
}

#[test]
fn factory_builds_from_settings_and_rejects_bad_ones() {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(SocksFactory));
    let settings = |json: &str| serde_json::from_str(json).unwrap();
    for good in [
        r#"{"server":"example.com","port":1080}"#,
        r#"{"server":"example.com","port":1080,"username":"u","password":"p"}"#,
    ] {
        let built = registry
            .build("socks", &settings(good), Arc::new(TcpDialer))
            .unwrap();
        assert_eq!(built.protocol(), "socks");
    }
    for bad in [
        r#"{"server":"example.com"}"#,
        r#"{"server":"","port":1080}"#,
        r#"{"server":"example.com","port":1080,"username":"u"}"#,
        r#"{"server":"example.com","port":1080,"username":"","password":"p"}"#,
    ] {
        assert!(registry
            .build("socks", &settings(bad), Arc::new(TcpDialer))
            .is_err());
    }
}

/// A minimal SOCKS5 server for `UDP ASSOCIATE` only. It replies with an
/// unspecified relay address and echoes each datagram back with the same
/// header. With `close_control` it closes the TCP connection after the reply.
async fn udp_socks_server(close_control: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut control, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                control.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                control.write_all(&[5, 0]).await.unwrap();
                let mut request = [0u8; 10];
                control.read_exact(&mut request).await.unwrap();
                assert_eq!(request[..4], [5, 3, 0, 1]);
                let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = relay.local_addr().unwrap().port().to_be_bytes();
                control
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]])
                    .await
                    .unwrap();
                if close_control {
                    return;
                }
                let mut buf = vec![0u8; 65_536];
                let mut probe = [0u8; 1];
                loop {
                    tokio::select! {
                        received = relay.recv_from(&mut buf) => {
                            let (n, from) = received.unwrap();
                            let _ = relay.send_to(&buf[..n], from).await;
                        }
                        _ = control.read(&mut probe) => return,
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_associate_relays_datagrams_to_ip_and_domain_targets() {
    let server = udp_socks_server(false).await;
    let client = outbound(server, None);
    for target in [
        TargetAddr::Ip("127.0.0.1:53".parse().unwrap()),
        TargetAddr::Domain("echo.test".into(), 53),
    ] {
        let mut flow = client.open_udp(&target).await.unwrap();
        for payload in [b"hello".to_vec(), vec![3u8; 1200]] {
            flow.send.send(&payload).await.unwrap();
            let reply = tokio::time::timeout(std::time::Duration::from_secs(10), flow.recv.recv())
                .await
                .expect("udp reply timed out")
                .unwrap();
            assert_eq!(reply, payload);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_flow_ends_with_the_tcp_association() {
    let server = udp_socks_server(true).await;
    let mut flow = outbound(server, None)
        .open_udp(&TargetAddr::Ip("127.0.0.1:53".parse().unwrap()))
        .await
        .unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(10), flow.recv.recv())
        .await
        .expect("flow should end when the server closes the association");
    assert_eq!(
        ended.err().map(|error| error.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
}
