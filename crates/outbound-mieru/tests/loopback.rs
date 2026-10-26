//! Client against an in-process server built from the same segment code.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpDialer};
use outbound_mieru::crypto::{
    candidate_keys, derive_key, hashed_password, new_nonce, unix_now, user_hint,
};
use outbound_mieru::segment::{Kind, Segment, SegmentReader, SegmentWriter};
use outbound_mieru::{MieruOptions, MieruOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "alice";
const PASSWORD: &str = "correct horse";
const TIMEOUT: Duration = Duration::from_secs(20);

struct ServerConn {
    socket: TcpStream,
    reader: SegmentReader,
    writer: Option<SegmentWriter>,
    input: Vec<u8>,
}

impl ServerConn {
    fn new(socket: TcpStream) -> Self {
        let hashed = hashed_password(USER.as_bytes(), PASSWORD.as_bytes());
        Self {
            socket,
            reader: SegmentReader::new(candidate_keys(&hashed, unix_now()).to_vec()),
            writer: None,
            input: Vec::new(),
        }
    }

    async fn next(&mut self) -> io::Result<Option<Segment>> {
        loop {
            if let Some(segment) = self.reader.next_segment(&mut self.input)? {
                return Ok(Some(segment));
            }
            let mut buf = [0u8; 8192];
            let n = self.socket.read(&mut buf).await?;
            if n == 0 {
                return Ok(None);
            }
            self.input.extend_from_slice(&buf[..n]);
        }
    }

    async fn send(&mut self, session_id: u32, kind: Kind, payload: &[u8]) -> io::Result<()> {
        let writer = self.writer.get_or_insert_with(|| {
            let hashed = hashed_password(USER.as_bytes(), PASSWORD.as_bytes());
            SegmentWriter::new(
                &derive_key(&hashed, unix_now()),
                new_nonce(USER.as_bytes()).unwrap(),
                session_id,
            )
        });
        let mut out = Vec::new();
        writer.write(&mut out, kind, payload)?;
        self.socket.write_all(&out).await
    }
}

/// Echo server: checks the open request, answers with `reply_code`, echoes
/// data and, after `close_after` echoed bytes, closes the session. Returns
/// the client segment kinds it saw.
async fn serve_one(
    listener: TcpListener,
    expected_request: Vec<u8>,
    reply_code: u8,
    close_after: usize,
) -> Vec<Kind> {
    let (socket, _) = listener.accept().await.unwrap();
    let mut conn = ServerConn::new(socket);
    let mut kinds = Vec::new();
    let mut stream = Vec::new();
    let mut session_id = 0;
    let mut echoed = 0;
    let mut opened = false;
    while let Some(segment) = conn.next().await.unwrap() {
        kinds.push(segment.metadata.kind);
        let hint = user_hint(USER.as_bytes(), conn.reader.peer_nonce().unwrap());
        assert_eq!(conn.reader.peer_nonce().unwrap()[20..], hint);
        match segment.metadata.kind {
            Kind::OpenSessionRequest => {
                session_id = segment.metadata.session_id;
                assert_ne!(session_id, 0);
                assert_eq!(segment.metadata.sequence, 0);
                stream.extend_from_slice(&segment.payload);
                conn.send(session_id, Kind::OpenSessionResponse, &[])
                    .await
                    .unwrap();
            }
            Kind::DataClientToServer => {
                assert_eq!(segment.metadata.session_id, session_id);
                stream.extend_from_slice(&segment.payload);
            }
            Kind::CloseSessionRequest | Kind::CloseSessionResponse => break,
            other => panic!("unexpected client segment {other:?}"),
        }
        if !opened && stream.len() >= expected_request.len() {
            assert_eq!(stream[..expected_request.len()], expected_request[..]);
            stream.drain(..expected_request.len());
            opened = true;
            conn.send(
                session_id,
                Kind::DataServerToClient,
                &[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0],
            )
            .await
            .unwrap();
            if reply_code != 0 {
                conn.send(session_id, Kind::CloseSessionRequest, &[])
                    .await
                    .unwrap();
            }
        }
        if opened && reply_code == 0 && !stream.is_empty() {
            for chunk in stream.chunks(20_000) {
                conn.send(session_id, Kind::DataServerToClient, chunk)
                    .await
                    .unwrap();
            }
            echoed += stream.len();
            stream.clear();
            if echoed >= close_after {
                conn.send(session_id, Kind::CloseSessionRequest, &[])
                    .await
                    .unwrap();
            }
        }
    }
    kinds
}

fn outbound(port: u16) -> MieruOutbound {
    MieruOutbound::new(
        "127.0.0.1",
        port,
        MieruOptions {
            username: USER.to_owned(),
            password: PASSWORD.to_owned(),
            port_range: None,
        },
        Arc::new(TcpDialer),
    )
    .unwrap()
}

#[tokio::test]
async fn echoes_through_a_session_and_answers_the_server_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = TargetAddr::Domain("echo.test".into(), 7);
    let request = b"\x05\x01\x00\x03\x09echo.test\x00\x07".to_vec();
    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let server = tokio::spawn(serve_one(listener, request, 0, payload.len()));

    let stream = tokio::time::timeout(TIMEOUT, outbound(port).connect_stream(&target))
        .await
        .unwrap()
        .unwrap();
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let writer = async {
        write_half.write_all(&payload).await.unwrap();
        write_half.flush().await.unwrap();
    };
    let mut received = Vec::new();
    let reader = async {
        read_half.read_to_end(&mut received).await.unwrap();
    };
    tokio::time::timeout(TIMEOUT, async { tokio::join!(writer, reader) })
        .await
        .unwrap();
    assert_eq!(received, payload);
    // The close response went out while reading the server's close request.
    drop((read_half, write_half));

    let kinds = tokio::time::timeout(TIMEOUT, server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kinds[0], Kind::OpenSessionRequest);
    assert_eq!(*kinds.last().unwrap(), Kind::CloseSessionResponse);
    assert!(kinds[1..kinds.len() - 1]
        .iter()
        .all(|kind| *kind == Kind::DataClientToServer));
}

#[tokio::test]
async fn reports_a_refused_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target: TargetAddr = "10.0.0.1:443".parse::<SocketAddr>().unwrap().into();
    let request = vec![5, 1, 0, 1, 10, 0, 0, 1, 1, 0xbb];
    let server = tokio::spawn(serve_one(listener, request, 5, 0));

    let mut stream = outbound(port).connect_stream(&target).await.unwrap();
    let mut buf = [0u8; 16];
    let err = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    drop(stream);
    tokio::time::timeout(TIMEOUT, server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_wrong_password_never_gets_an_answer_it_can_read() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut conn = ServerConn::new(socket);
        conn.next().await.map(|_| ())
    });
    let client = MieruOutbound::new(
        "127.0.0.1",
        port,
        MieruOptions {
            username: USER.to_owned(),
            password: "wrong".to_owned(),
            port_range: None,
        },
        Arc::new(TcpDialer),
    )
    .unwrap();
    let target = TargetAddr::Domain("echo.test".into(), 7);
    let _stream = client.connect_stream(&target).await.unwrap();
    let result = tokio::time::timeout(TIMEOUT, server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}
