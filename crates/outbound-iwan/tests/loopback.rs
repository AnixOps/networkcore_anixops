//! The routable outbound against an in-process iWAN server that behaves like
//! the no-exit test server of spec §10.1: it forwards a packet to the session
//! that owns its destination address and echoes everything else.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use engine_outbound::registry::{OutboundFactory, Settings};
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_iwan::crypto::{self, XorKey};
use outbound_iwan::packet::{self, kind, tlv, Header, Session};
use outbound_iwan::{IwanConfig, IwanFactory, IwanOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PLAIN: (&str, &str, Ipv4Addr) = ("plain", "pw-plain", Ipv4Addr::new(10, 20, 30, 10));
const MASKED: (&str, &str, Ipv4Addr) = ("xor", "pw-xor", Ipv4Addr::new(10, 20, 30, 11));
const SERVER_MTU: u16 = 1380;

struct ServerSession {
    session: Session,
    address: Ipv4Addr,
    xor: Option<XorKey>,
}

/// Starts the server on a loopback port for the rest of the test process.
fn start_server() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || serve(socket));
    port
}

fn serve(socket: UdpSocket) {
    let mut sessions: HashMap<SocketAddr, ServerSession> = HashMap::new();
    let mut next_id = 1u32;
    let mut buffer = [0u8; 4096];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let datagram = &buffer[..len];
        match datagram[0] {
            kind::OPEN => {
                let user = packet::decode_open(datagram).and_then(|open| {
                    [PLAIN, MASKED]
                        .into_iter()
                        .find(|(name, password, _)| {
                            open.username.as_deref() == Some(name.as_bytes())
                                && open.password_block
                                    == Some(crypto::encrypt_password(
                                        name.as_bytes(),
                                        password.as_bytes(),
                                    ))
                        })
                        .map(|user| (user, open.flags != 0 || open.encrypt.unwrap_or(0) != 0))
                });
                let Some(((name, password, address), wants_mask)) = user else {
                    let _ = socket.send_to(&packet::encode_open_rej_with(b"INVPASS"), from);
                    continue;
                };
                // Only the "xor" user may mask, like allow_encrypt.
                let masked = wants_mask && name == MASKED.0;
                next_id += 1;
                let session = Session {
                    token: [0x7E, next_id as u8],
                    id: next_id.to_be_bytes(),
                };
                let ack = packet::encode_open_ack(
                    session,
                    u8::from(masked),
                    &[
                        (tlv::MTU, &SERVER_MTU.to_be_bytes()),
                        (tlv::ADDRESS, &address.octets()),
                        (tlv::DNS0, &[192, 0, 2, 53]),
                        (tlv::ENCRYPT, &[u8::from(masked)]),
                    ],
                );
                sessions.retain(|_, existing| existing.address != address);
                sessions.insert(
                    from,
                    ServerSession {
                        session,
                        address,
                        xor: masked.then(|| XorKey::new(name.as_bytes(), password.as_bytes())),
                    },
                );
                let _ = socket.send_to(&ack, from);
            }
            kind::DATA | kind::DATA_ENC => {
                let Some(sender) = sessions.get(&from) else {
                    continue;
                };
                if (datagram[0] == kind::DATA_ENC) != sender.xor.is_some() {
                    continue;
                }
                let mut ip = datagram[packet::HEADER_LEN..].to_vec();
                if let Some(xor) = &sender.xor {
                    xor.apply(&mut ip);
                }
                let destination = ip
                    .get(16..20)
                    .map(|octets| Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
                let (to, receiver) = sessions
                    .iter()
                    .find(|(_, session)| Some(session.address) == destination)
                    .unwrap_or((&from, sender));
                let reply = packet::encode_data(receiver.session, receiver.xor.as_ref(), &ip);
                let _ = socket.send_to(&reply, to);
            }
            kind::ECHOREQ => {
                let Some((header, payload)) = packet::verify_signed(datagram) else {
                    continue;
                };
                let reply = packet::signed(Header::new(kind::ECHORESP, 0, header.session), payload);
                let _ = socket.send_to(&reply, from);
            }
            kind::CLOSE => {
                sessions.remove(&from);
            }
            _ => {}
        }
    }
}

fn settings(port: u16, user: (&str, &str, Ipv4Addr), password: &str, encrypt: bool) -> Settings {
    let json = serde_json::json!({
        "server": "127.0.0.1",
        "port": port,
        "username": user.0,
        "password": password,
        "encrypt": encrypt,
        "tcp_buffer_bytes": 16 * 1024,
    });
    match json {
        serde_json::Value::Object(map) => map,
        _ => unreachable!(),
    }
}

fn node(port: u16, user: (&str, &str, Ipv4Addr), encrypt: bool) -> IwanOutbound {
    let settings = settings(port, user, user.1, encrypt);
    let config: IwanConfig = serde_json::from_value(serde_json::Value::Object(settings)).unwrap();
    IwanOutbound::new(config.validate().unwrap())
}

async fn connect_with_retry(
    node: &IwanOutbound,
    target: &TargetAddr,
) -> io::Result<engine_outbound::BoxStream> {
    // The peer's listener may not exist yet; its stack answers RST until then.
    let mut last = None;
    for _ in 0..40 {
        match node.connect(target).await {
            Ok(stream) => return Ok(stream),
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                last = Some(err);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_between_a_plain_and_a_masked_node() {
    let port = start_server();
    let plain = node(port, PLAIN, false);
    let masked = node(port, MASKED, true);
    let listener = masked.clone();
    let accepted = tokio::spawn(async move { listener.accept_tcp(8000).await });

    let target = TargetAddr::Ip(SocketAddr::new(MASKED.2.into(), 8000));
    let mut client = connect_with_retry(&plain, &target).await.unwrap();
    let mut server = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    client.write_all(b"hello").await.unwrap();
    let mut greeting = [0u8; 5];
    server.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");

    // More than a window each way, so flow control and the MTU both matter.
    let upload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let expected = upload.clone();
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; expected.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_all(b"done").await.unwrap();
        server.shutdown().await.unwrap();
        server
    });
    client.write_all(&upload).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"done");
    drop(reader.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_between_two_nodes() {
    let port = start_server();
    let plain = node(port, PLAIN, true);
    let masked = node(port, MASKED, true);
    let to_plain = TargetAddr::Ip(SocketAddr::new(PLAIN.2.into(), 7001));
    let to_masked = TargetAddr::Ip(SocketAddr::new(MASKED.2.into(), 7000));
    let mut masked_flow = masked.open_udp_on(7000, &to_plain).await.unwrap();
    let mut plain_flow = plain.open_udp_on(7001, &to_masked).await.unwrap();

    plain_flow.send.send(b"ping").await.unwrap();
    let ping = tokio::time::timeout(Duration::from_secs(5), masked_flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ping, b"ping");
    masked_flow.send.send(b"pong").await.unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(5), plain_flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pong, b"pong");

    // An ephemeral-port flow through the TcpOutbound interface too.
    let mut flow = plain.open_udp(&to_masked).await.unwrap();
    flow.send.send(b"again").await.unwrap();
    let again = tokio::time::timeout(Duration::from_secs(5), masked_flow.recv.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again, b"again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_login_fails_the_connection() {
    let port = start_server();
    let config: IwanConfig = serde_json::from_value(serde_json::Value::Object(settings(
        port, PLAIN, "wrong", false,
    )))
    .unwrap();
    let node = IwanOutbound::new(config.validate().unwrap());
    let target = TargetAddr::Ip(SocketAddr::new(MASKED.2.into(), 80));
    let err = node.connect(&target).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("INVPASS"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_targets_and_bad_settings_are_rejected() {
    let port = start_server();
    let plain = node(port, PLAIN, false);
    let target = TargetAddr::Ip("[2001:db8::1]:80".parse().unwrap());
    let err = plain.connect(&target).await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);

    let factory = IwanFactory;
    assert_eq!(factory.type_name(), "iwan");
    let built = factory
        .build(&settings(port, PLAIN, PLAIN.1, false), Arc::new(TcpDialer))
        .ok()
        .unwrap();
    assert_eq!(built.protocol(), "iwan");
    let mut bad = settings(port, PLAIN, PLAIN.1, false);
    bad.insert("mtu".into(), 2000.into());
    assert!(factory.build(&bad, Arc::new(TcpDialer)).is_err());
}
