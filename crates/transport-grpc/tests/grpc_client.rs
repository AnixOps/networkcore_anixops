//! The gRPC transport against an in-process `h2` server that echoes `Hunk`
//! messages back, as a gun server relaying to an echo target would.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use engine_outbound::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_grpc::{decode_message, encode_message, GrpcConnector, GrpcSettings};

async fn echo_server(expected_path: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    tokio::spawn(async move {
                        let ok = request.uri().path() == expected_path
                            && request.headers()["content-type"] == "application/grpc";
                        let status = if ok { 200 } else { 404 };
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        let Ok(mut send) = respond.send_response(response, !ok) else {
                            return;
                        };
                        if !ok {
                            return;
                        }
                        let mut recv = request.into_body();
                        let mut frames = BytesMut::new();
                        while let Some(Ok(chunk)) = recv.data().await {
                            let _ = recv.flow_control().release_capacity(chunk.len());
                            frames.extend_from_slice(&chunk);
                            while let Ok(Some(data)) = decode_message(&mut frames) {
                                let mut out = BytesMut::new();
                                encode_message(&data, &mut out);
                                if send.send_data(out.freeze(), false).is_err() {
                                    return;
                                }
                            }
                        }
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        let _ = send.send_trailers(trailers);
                    });
                }
            });
        }
    });
    addr
}

async fn open(addr: SocketAddr, service_name: &str) -> std::io::Result<BoxStream> {
    let connector = GrpcConnector::new(
        &GrpcSettings {
            service_name: service_name.into(),
            authority: String::new(),
        },
        "grpc.test",
        false,
    )?;
    let tcp: BoxStream = Box::new(TcpStream::connect(addr).await?);
    connector.connect(tcp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_round_trip_through_hunk_messages() {
    let addr = echo_server("/svc/Tun").await;
    let stream = open(addr, "svc").await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Larger than one message and than the default HTTP/2 window.
    let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let write = tokio::spawn(async move {
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
        writer.shutdown().await.unwrap();
    });
    let mut echoed = Vec::new();
    reader.read_to_end(&mut echoed).await.unwrap();
    write.await.unwrap();
    assert_eq!(echoed.len(), expected.len());
    assert!(echoed == expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_path_is_an_error() {
    let addr = echo_server("/svc/Tun").await;
    let mut stream = open(addr, "other").await.unwrap();
    // The write may or may not fail first; the read must.
    let _ = stream.write_all(b"hello").await;
    let mut buf = [0u8; 5];
    assert!(stream.read_exact(&mut buf).await.is_err());
}

#[test]
fn empty_data_frames_decode_to_empty_payloads() {
    let mut frames = BytesMut::from(&[0u8, 0, 0, 0, 0][..]);
    assert_eq!(decode_message(&mut frames).unwrap(), Some(Bytes::new()));
}
