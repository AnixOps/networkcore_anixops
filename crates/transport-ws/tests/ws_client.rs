//! The WebSocket client against a `tokio-tungstenite` server, so framing and
//! the handshake are checked against an independent implementation.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use engine_outbound::BoxStream;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use transport_ws::{accept_value, WsConnector, WsSettings};

#[derive(Default)]
struct Seen {
    path: String,
    host: String,
    user_agent: String,
}

/// Echoes binary messages; a client message "ping me" makes the server send a
/// ping and answer "pong ok" once the client's pong arrives.
async fn ws_server() -> (SocketAddr, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let callback = move |request: &Request,
                                     response: Response|
                      -> Result<Response, ErrorResponse> {
                    let header = |name: &str| {
                        request
                            .headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned()
                    };
                    let mut seen = record.lock().unwrap();
                    seen.path = request.uri().path().to_owned();
                    seen.host = header("host");
                    seen.user_agent = header("user-agent");
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Binary(data) if &data[..] == b"ping me" => {
                            if ws.send(Message::Ping(b"p".to_vec().into())).await.is_err() {
                                return;
                            }
                        }
                        Message::Pong(data) if &data[..] == b"p" => {
                            if ws
                                .send(Message::Binary(b"pong ok".to_vec().into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Message::Binary(data) => {
                            if ws.send(Message::Binary(data)).await.is_err() {
                                return;
                            }
                        }
                        // A close is answered by tungstenite on the next poll.
                        _ => {}
                    }
                }
            });
        }
    });
    (addr, seen)
}

async fn connect(addr: SocketAddr, settings: &WsSettings) -> io::Result<BoxStream> {
    let tcp = TcpStream::connect(addr).await?;
    WsConnector::new(settings, "fallback.test")?
        .connect(Box::new(tcp))
        .await
}

#[test]
fn accept_value_matches_rfc_6455_example() {
    assert_eq!(
        accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiXuOo9K7xsBN+zXxOo2s="
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_sends_path_host_and_headers() {
    let (addr, seen) = ws_server().await;
    let settings = WsSettings {
        path: "/tunnel".into(),
        host: "cdn.example".into(),
        headers: vec![("User-Agent".into(), "networkcore-test".into())],
    };
    let mut stream = connect(addr, &settings).await.unwrap();
    stream.write_all(b"hi").await.unwrap();
    let mut echoed = [0u8; 2];
    stream.read_exact(&mut echoed).await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.path, "/tunnel");
    assert_eq!(seen.host, "cdn.example");
    assert_eq!(seen.user_agent, "networkcore-test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_settings_use_root_path_and_the_default_host() {
    let (addr, seen) = ws_server().await;
    let mut stream = connect(addr, &WsSettings::default()).await.unwrap();
    stream.write_all(b"hi").await.unwrap();
    let mut echoed = [0u8; 2];
    stream.read_exact(&mut echoed).await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.path, "/");
    assert_eq!(seen.host, "fallback.test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_medium_and_large_payloads_round_trip() {
    let (addr, _) = ws_server().await;
    let mut stream = connect(addr, &WsSettings::default()).await.unwrap();
    for len in [1usize, 125, 126, 65_535, 65_536, 200_000] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; len];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "len {len}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pings_are_answered_with_pongs() {
    let (addr, _) = ws_server().await;
    let mut stream = connect(addr, &WsSettings::default()).await.unwrap();
    stream.write_all(b"ping me").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0u8; 7];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_sends_a_close_frame_and_the_server_close_reads_as_eof() {
    let (addr, _) = ws_server().await;
    let mut stream = connect(addr, &WsSettings::default()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    // tungstenite answers the close frame, which reads as end of stream.
    stream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

/// A server that answers the upgrade with `response`.
async fn http_server(response: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_upgrades_and_bad_accept_values_are_errors() {
    let refused = http_server("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
    let err = connect(refused, &WsSettings::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

    let wrong = http_server(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
    )
    .await;
    let err = connect(wrong, &WsSettings::default()).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn settings_that_could_inject_headers_are_rejected() {
    for settings in [
        WsSettings {
            path: "no-slash".into(),
            ..WsSettings::default()
        },
        WsSettings {
            path: "/a\r\nX: 1".into(),
            ..WsSettings::default()
        },
        WsSettings {
            host: "h\r\nX: 1".into(),
            ..WsSettings::default()
        },
        WsSettings {
            headers: vec![("Bad Name".into(), "v".into())],
            ..WsSettings::default()
        },
        WsSettings {
            headers: vec![("X-Ok".into(), "v\r\nX: 1".into())],
            ..WsSettings::default()
        },
    ] {
        assert!(WsConnector::new(&settings, "fallback.test").is_err());
    }
}
