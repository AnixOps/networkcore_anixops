//! The client against the server over loopback, in every mode the client
//! speaks, with an echo behind the server.

use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxStream, TcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport_xhttp::server::XhttpServer;
use transport_xhttp::{HttpVersion, Mode, XhttpConnector, XhttpSettings, XhttpTarget};

const LEN: usize = 200_000;

async fn echo(stream: BoxStream) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    let _ = writer.shutdown().await;
}

async fn start_server(settings: &XhttpSettings) -> u16 {
    let server = XhttpServer::new(settings).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server
                    .serve_connection(Box::new(stream), Duration::from_secs(5), |call| {
                        Box::pin(echo(call))
                    })
                    .await;
            });
        }
    });
    port
}

async fn round_trip(settings: &XhttpSettings, port: u16, version: HttpVersion) {
    let connector = XhttpConnector::new(
        settings,
        XhttpTarget {
            server: "127.0.0.1".into(),
            port,
            default_host: "127.0.0.1".into(),
            tls: None,
            version,
            dialer: Arc::new(TcpDialer),
        },
    )
    .unwrap();
    let stream = connector.connect().await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let expected = sent.clone();
    let writing = tokio::spawn(async move {
        for piece in sent.chunks(9_973) {
            writer.write_all(piece).await.unwrap();
            writer.flush().await.unwrap();
        }
        writer
    });
    let mut received = vec![0u8; LEN];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut received))
        .await
        .unwrap_or_else(|_| panic!("{:?} {version:?} timed out", settings.mode))
        .unwrap();
    assert!(received == expected, "{:?} {version:?}", settings.mode);
    drop(writing.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_and_server_agree_in_every_mode() {
    let server_settings = XhttpSettings {
        path: "/xh".into(),
        ..XhttpSettings::default()
    };
    let port = start_server(&server_settings).await;
    for (mode, version) in [
        (Mode::Auto, HttpVersion::Http11),
        (Mode::PacketUp, HttpVersion::Http2),
        (Mode::StreamUp, HttpVersion::Http2),
        (Mode::StreamOne, HttpVersion::Http2),
    ] {
        let settings = XhttpSettings {
            path: "/xh/".into(),
            mode,
            sc_min_posts_interval_ms: transport_xhttp::Range::fixed(1),
            ..XhttpSettings::default()
        };
        round_trip(&settings, port, version).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_path_and_mode_are_refused() {
    let port = start_server(&XhttpSettings {
        path: "/xh".into(),
        mode: Mode::PacketUp,
        ..XhttpSettings::default()
    })
    .await;
    for (path, mode, version) in [
        ("/other", Mode::PacketUp, HttpVersion::Http11),
        ("/xh", Mode::StreamOne, HttpVersion::Http2),
    ] {
        let settings = XhttpSettings {
            path: path.into(),
            mode,
            ..XhttpSettings::default()
        };
        let connector = XhttpConnector::new(
            &settings,
            XhttpTarget {
                server: "127.0.0.1".into(),
                port,
                default_host: "127.0.0.1".into(),
                tls: None,
                version,
                dialer: Arc::new(TcpDialer),
            },
        )
        .unwrap();
        let mut stream = connector.connect().await.unwrap();
        let _ = stream.write_all(b"hello").await;
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
            .await
            .expect("a refused session ends");
        assert!(read.is_err() || rest.is_empty(), "{path} {mode:?}");
    }
}
