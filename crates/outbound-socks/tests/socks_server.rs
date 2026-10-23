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
