//! The gRPC server side against this crate's client and a raw HTTP/2 client
//! that opens several calls on one connection.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use engine_outbound::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport_grpc::server::serve_connection;
use transport_grpc::{decode_message, encode_message, GrpcConnector, GrpcSettings};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Serves one HTTP/2 connection whose calls to `/svc/Tun` echo their input.
fn echo_server() -> BoxStream {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let _ = serve_connection(Box::new(server), "/svc/Tun", TIMEOUT, |stream| {
            Box::pin(async move {
                let (mut reader, mut writer) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            })
        })
        .await;
    });
    Box::new(client)
}

#[tokio::test]
async fn own_client_round_trips_and_sees_the_end() {
    let connector = GrpcConnector::new(
        &GrpcSettings {
            service_name: "svc".into(),
            authority: String::new(),
        },
        "grpc.example",
        false,
    )
    .unwrap();
    let mut stream = connector.connect(echo_server()).await.unwrap();
    let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let send = async {
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
    };
    let mut echoed = Vec::new();
    let receive = reader.read_to_end(&mut echoed);
    let (_, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(send, receive) })
        .await
        .expect("echo timed out");
    received.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn calls_share_a_connection_and_other_paths_get_404() {
    let (send_request, connection) = h2::client::handshake(echo_server()).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();

    let request = |path: &str| {
        http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://grpc.example{path}"))
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap()
    };
    let (missing, _) = send_request
        .send_request(request("/other/Tun"), true)
        .unwrap();
    assert_eq!(missing.await.unwrap().status(), http::StatusCode::NOT_FOUND);

    let mut calls = Vec::new();
    for index in 0..3u8 {
        let mut send_request = send_request.clone().ready().await.unwrap();
        let (response, mut send) = send_request
            .send_request(request("/svc/Tun"), false)
            .unwrap();
        let mut frame = BytesMut::new();
        encode_message(&[index; 100], &mut frame);
        send.send_data(frame.freeze(), true).unwrap();
        calls.push((index, response));
    }
    for (index, response) in calls {
        let response = tokio::time::timeout(TIMEOUT, response)
            .await
            .expect("call timed out")
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut body = response.into_body();
        let mut frames = BytesMut::new();
        while let Some(chunk) = body.data().await {
            let chunk: Bytes = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            frames.extend_from_slice(&chunk);
        }
        let data = decode_message(&mut frames).unwrap().unwrap();
        assert_eq!(&data[..], &[index; 100][..]);
        let trailers = body.trailers().await.unwrap().unwrap();
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    }
}
