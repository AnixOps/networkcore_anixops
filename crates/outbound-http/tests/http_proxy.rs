//! The HTTP CONNECT client against this repo's own HTTP proxy (`inbound-mixed`)
//! relaying directly to local test servers.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use inbound_mixed::{serve, Credentials, MixedSettings, MixedStats};
use outbound_http::{HttpCredentials, HttpFactory, HttpOutbound};
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

async fn http_proxy(credentials: Option<Credentials>) -> SocketAddr {
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

fn outbound(server: SocketAddr, credentials: Option<(&str, &str)>) -> HttpOutbound {
    HttpOutbound::new(
        server.ip().to_string(),
        server.port(),
        credentials.map(|(username, password)| HttpCredentials {
            username: username.into(),
            password: password.into(),
        }),
        None,
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
async fn tunnels_to_ip_and_domain_targets_with_and_without_auth() {
    let echo = echo_server().await;
    let open = http_proxy(None).await;
    let authenticated = http_proxy(Some(user())).await;
    for http in [
        outbound(open, None),
        outbound(open, Some(("alice", "secret"))),
        outbound(authenticated, Some(("alice", "secret"))),
    ] {
        for target in [
            TargetAddr::Ip(echo),
            TargetAddr::Domain("localhost".into(), echo.port()),
        ] {
            let mut stream = http.connect(&target).await.unwrap();
            stream.write_all(b"hello http").await.unwrap();
            let mut echoed = [0u8; 10];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello http", "{target}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_speaks_first_targets_get_their_bytes_intact() {
    let banner = banner_server().await;
    let proxy = http_proxy(None).await;
    let mut stream = outbound(proxy, None)
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
    let authenticated = http_proxy(Some(user())).await;
    for credentials in [None, Some(("alice", "wrong"))] {
        let err = outbound(authenticated, credentials)
            .connect(&TargetAddr::Ip(echo))
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let open = http_proxy(None).await;
    let err = outbound(open, None)
        .connect(&TargetAddr::Ip(closed))
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_domains_cannot_inject_headers() {
    let open = http_proxy(None).await;
    let err = outbound(open, None)
        .connect(&TargetAddr::Domain("a.test\r\nX-Injected: 1".into(), 80))
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn factory_builds_from_settings_and_rejects_bad_ones() {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(HttpFactory));
    let settings = |json: &str| serde_json::from_str(json).unwrap();
    for good in [
        r#"{"server":"example.com","port":8080}"#,
        r#"{"server":"example.com","port":8080,"username":"u","password":"p"}"#,
        r#"{"server":"example.com","port":443,"tls":true,"insecure":true}"#,
    ] {
        let built = registry
            .build("http", &settings(good), Arc::new(TcpDialer))
            .unwrap();
        assert_eq!(built.protocol(), "http");
    }
    for bad in [
        r#"{"server":"example.com"}"#,
        r#"{"server":"","port":8080}"#,
        r#"{"server":"example.com","port":8080,"password":"p"}"#,
        r#"{"server":"example.com","port":8080,"username":"a:b","password":"p"}"#,
    ] {
        assert!(registry
            .build("http", &settings(bad), Arc::new(TcpDialer))
            .is_err());
    }
}
