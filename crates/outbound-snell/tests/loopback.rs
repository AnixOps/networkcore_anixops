//! End-to-end client tests against an in-process echo server built from the
//! crate's own direction-agnostic codec.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpDialer};
use outbound_snell::obfs::{HttpObfs, HttpObfsRole};
use outbound_snell::request::{
    encode_udp_downstream, parse_request, parse_udp_upstream, Command, REPLY_PONG, REPLY_TUNNEL,
};
use outbound_snell::{
    Decoder, Encoder, Frame, Framing, HttpObfsSettings, SnellOptions, SnellOutbound, V6Mode,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

const PSK: &[u8] = b"loopback test psk";
const TIMEOUT: Duration = Duration::from_secs(20);

struct Server {
    port: u16,
    connections: Arc<AtomicUsize>,
}

async fn start_server(framing: Framing, obfs: bool) -> Server {
    // v1–v3 servers detect the client's cipher from the first frame.
    let framing = match framing {
        Framing::Legacy(_) => Framing::LegacyAuto,
        framing => framing,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let framing = framing.clone();
            tokio::spawn(async move {
                if obfs {
                    let _ = echo(HttpObfs::new(socket, HttpObfsRole::Server), framing).await;
                } else {
                    let _ = echo(socket, framing).await;
                }
            });
        }
    });
    Server { port, connections }
}

/// Echoes every request's data back, answers PING and UDP, and ends each
/// reusable request with a zero chunk after the client's.
async fn echo<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    framing: Framing,
) -> io::Result<()> {
    let psk: Arc<[u8]> = PSK.into();
    let mut decoder = Decoder::new(framing, psk.clone());
    let mut encoder: Option<Encoder> = None;
    let mut buf = vec![0u8; 16 * 1024];
    let mut command: Option<Command> = None;
    let mut replied = false;
    loop {
        let frame = loop {
            if let Some(frame) = decoder.next_frame()? {
                break frame;
            }
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            decoder.feed(&buf[..n]);
        };
        if encoder.is_none() {
            encoder = Some(Encoder::new(decoder.peer_framing(), PSK)?);
        }
        let encoder = encoder.as_mut().expect("encoder was just created");
        let mut out = Vec::new();
        match (frame, command) {
            (Frame::Data(data), None) => {
                let (request, len) = parse_request(&data)?.expect("request fits one frame");
                match request.command {
                    Command::Ping => {
                        encoder.encode(&mut out, &[REPLY_PONG])?;
                        socket.write_all(&out).await?;
                        return socket.shutdown().await;
                    }
                    Command::Udp => {
                        assert_eq!(len, data.len(), "udp request must be alone");
                        encoder.encode_single(&mut out, &[REPLY_TUNNEL])?;
                    }
                    Command::Connect | Command::ConnectV2 => {
                        replied = len < data.len();
                        if replied {
                            let mut reply = vec![REPLY_TUNNEL];
                            reply.extend_from_slice(&data[len..]);
                            encoder.encode(&mut out, &reply)?;
                        }
                    }
                }
                command = Some(request.command);
            }
            (Frame::Data(data), Some(Command::Udp)) => {
                let (target, payload) = parse_udp_upstream(&data)?;
                let source = match target {
                    TargetAddr::Ip(addr) => addr,
                    TargetAddr::Domain(_, port) => ([127, 0, 0, 1], port).into(),
                };
                let mut datagram = Vec::new();
                encode_udp_downstream(&mut datagram, source, payload);
                encoder.encode_single(&mut out, &datagram)?;
            }
            (Frame::Data(data), Some(_)) => {
                let mut reply = Vec::new();
                if !replied {
                    reply.push(REPLY_TUNNEL);
                    replied = true;
                }
                reply.extend_from_slice(&data);
                encoder.encode(&mut out, &reply)?;
            }
            (Frame::Zero, Some(Command::ConnectV2)) => {
                encoder.encode_zero(&mut out)?;
                command = None;
                replied = false;
            }
            (Frame::Zero, _) => return Err(io::Error::other("unexpected zero chunk")),
        }
        socket.write_all(&out).await?;
        socket.flush().await?;
    }
}

fn options(version: u8, mode: V6Mode, reuse: bool, obfs: bool) -> SnellOptions {
    SnellOptions {
        version,
        mode,
        psk: PSK.to_vec(),
        obfs: obfs.then(|| HttpObfsSettings {
            host: "bing.com".into(),
            uri: "/".into(),
        }),
        reuse,
        user_key: Vec::new(),
    }
}

fn cases() -> Vec<(&'static str, SnellOptions)> {
    vec![
        ("v1", options(1, V6Mode::Default, false, false)),
        ("v2 reuse", options(2, V6Mode::Default, true, false)),
        ("v3 http obfs", options(3, V6Mode::Default, false, true)),
        ("v4", options(4, V6Mode::Default, false, false)),
        (
            "v4 reuse http obfs",
            options(4, V6Mode::Default, true, true),
        ),
        ("v5", options(5, V6Mode::Default, true, false)),
        ("v6 default", options(6, V6Mode::Default, true, false)),
        ("v6 unshaped", options(6, V6Mode::Unshaped, true, false)),
        ("v6 unsafe-raw", options(6, V6Mode::UnsafeRaw, false, false)),
    ]
}

async fn round_trip(outbound: &SnellOutbound, payload: &[u8]) {
    let target = TargetAddr::Domain("echo.test".into(), 7);
    let stream = outbound.connect_stream(&target).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        writer.write_all(payload).await.unwrap();
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.unwrap();
        echoed
    };
    let ((), echoed) = tokio::time::timeout(TIMEOUT, async { tokio::join!(send, receive) })
        .await
        .expect("round trip timed out");
    assert_eq!(echoed.len(), payload.len());
    assert!(echoed == payload);
}

#[tokio::test]
async fn every_version_echoes_small_and_large_payloads() {
    let large: Vec<u8> = (0..300_000).map(|i| (i * 13 % 251) as u8).collect();
    for (name, options) in cases() {
        let framing = Framing::for_version(options.version, options.mode, PSK).unwrap();
        let server = start_server(framing, options.obfs.is_some()).await;
        let reuse = options.reuse;
        let outbound =
            SnellOutbound::new("127.0.0.1", server.port, options, Arc::new(TcpDialer)).unwrap();
        for round in 0..3 {
            round_trip(&outbound, format!("hello {round}").as_bytes()).await;
        }
        round_trip(&outbound, &large).await;
        let connections = server.connections.load(Ordering::SeqCst);
        if reuse {
            assert_eq!(connections, 1, "{name}: reused connections");
        } else {
            assert_eq!(connections, 4, "{name}: one connection per request");
        }
    }
}

#[tokio::test]
async fn ping_and_udp_round_trip() {
    for (name, options) in cases() {
        let version = options.version;
        let framing = Framing::for_version(options.version, options.mode, PSK).unwrap();
        let server = start_server(framing, options.obfs.is_some()).await;
        let outbound =
            SnellOutbound::new("127.0.0.1", server.port, options, Arc::new(TcpDialer)).unwrap();
        tokio::time::timeout(TIMEOUT, outbound.ping())
            .await
            .unwrap()
            .unwrap_or_else(|err| panic!("{name}: ping failed: {err}"));
        if version < 3 {
            assert!(outbound.udp().await.is_err());
            continue;
        }
        let (mut sender, mut receiver) = outbound.udp().await.unwrap();
        let target = TargetAddr::Ip("127.0.0.1:5353".parse().unwrap());
        for i in 0..3u8 {
            assert!(sender.send_to(&target, &[i; 100]).await.unwrap());
            let (source, payload) = tokio::time::timeout(TIMEOUT, receiver.recv_from())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(source, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, vec![i; 100]);
        }
        assert!(!sender.send_to(&target, &vec![0u8; 70_000]).await.unwrap());
    }
}
