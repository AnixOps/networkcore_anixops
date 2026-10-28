//! The HTTPUpgrade server handshake against requests shaped like the
//! sing-box and Xray clients send.

use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use transport_ws::server::{HttpUpgradeAcceptor, WsServerSettings};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Serves one HTTPUpgrade connection that echoes everything it reads.
fn echo_server(settings: WsServerSettings) -> DuplexStream {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let acceptor = HttpUpgradeAcceptor::new(&settings).unwrap();
    tokio::spawn(async move {
        let Ok(stream) = acceptor.accept(Box::new(server)).await else {
            return;
        };
        let (mut reader, mut writer) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    client
}

/// Reads the response head and returns it.
async fn read_head(stream: &mut DuplexStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(TIMEOUT, stream.read(&mut byte))
            .await
            .expect("response timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn raw_bytes_follow_the_upgrade_with_early_data() {
    let mut client = echo_server(WsServerSettings {
        path: "/up".into(),
        host: "cdn.example".into(),
        ..WsServerSettings::default()
    });
    let early = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"early ");
    let request = format!(
        "GET /up?ed=2048 HTTP/1.1\r\nHost: cdn.example\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Protocol: {early}\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
    );
    // The first payload rides in the same write as the request.
    let mut first = request.into_bytes();
    first.extend_from_slice(b"first ");
    client.write_all(&first).await.unwrap();
    let head = read_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert!(head.to_ascii_lowercase().contains("upgrade: websocket"));

    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut expected = b"early first ".to_vec();
    expected.extend_from_slice(&payload);
    let mut echoed = vec![0u8; expected.len()];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(echoed, expected, "raw bytes, no websocket frames");
}

#[tokio::test]
async fn other_paths_and_plain_requests_are_refused() {
    let mut wrong_path = echo_server(WsServerSettings {
        path: "/up".into(),
        ..WsServerSettings::default()
    });
    wrong_path
        .write_all(
            b"GET /other HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();
    assert!(read_head(&mut wrong_path).await.starts_with("HTTP/1.1 404"));

    let mut plain = echo_server(WsServerSettings::default());
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut plain).await.starts_with("HTTP/1.1 400"));
}
