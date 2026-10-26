//! The WebSocket server handshake against this crate's client and against
//! tungstenite.

use std::time::Duration;

use base64::Engine as _;
use engine_outbound::BoxStream;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use transport_ws::server::{WsAcceptor, WsServerSettings};
use transport_ws::{WsConnector, WsSettings};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Serves one WebSocket connection that echoes everything it reads.
fn echo_server(settings: WsServerSettings) -> BoxStream {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let acceptor = WsAcceptor::new(&settings).unwrap();
    tokio::spawn(async move {
        let Ok(stream) = acceptor.accept(Box::new(server)).await else {
            return;
        };
        let (mut reader, mut writer) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Box::new(client)
}

#[tokio::test]
async fn own_client_round_trips_large_writes() {
    let transport = echo_server(WsServerSettings {
        path: "/tunnel".into(),
        host: "ws.example".into(),
        ..WsServerSettings::default()
    });
    let connector = WsConnector::new(
        &WsSettings {
            path: "/tunnel".into(),
            ..WsSettings::default()
        },
        "ws.example",
    )
    .unwrap();
    let mut stream = connector.connect(transport).await.unwrap();
    let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let send = async {
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
    };
    let mut echoed = vec![0u8; payload.len()];
    let receive = reader.read_exact(&mut echoed);
    let (_, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(send, receive) })
        .await
        .expect("echo timed out");
    received.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn tungstenite_client_and_early_data() {
    let transport = echo_server(WsServerSettings::default());
    let mut request = "ws://ws.example/".into_client_request().unwrap();
    let early = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"early bytes");
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", early.parse().unwrap());
    let (mut socket, response) = tokio_tungstenite::client_async(request, transport)
        .await
        .unwrap();
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        early.as_str()
    );
    // The early data comes back first, then the frames.
    socket
        .send(Message::Binary(b"then frames".to_vec().into()))
        .await
        .unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < b"early bytesthen frames".len() {
        let message = tokio::time::timeout(TIMEOUT, socket.next())
            .await
            .expect("echo timed out")
            .unwrap()
            .unwrap();
        match message {
            Message::Binary(data) => echoed.extend_from_slice(&data),
            other => panic!("unexpected message {other:?}"),
        }
    }
    assert_eq!(echoed, b"early bytesthen frames");
}

#[tokio::test]
async fn other_paths_and_plain_http_are_refused() {
    for (request, status) in [
        (
            "GET /other HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "404",
        ),
        ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "400"),
        ("PUT / HTTP/1.1\r\n\r\n", "400"),
    ] {
        let mut transport = echo_server(WsServerSettings::default());
        transport.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(TIMEOUT, transport.read_to_end(&mut response))
            .await
            .expect("refusal timed out")
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{request:?} got {response:?}"
        );
    }
}
