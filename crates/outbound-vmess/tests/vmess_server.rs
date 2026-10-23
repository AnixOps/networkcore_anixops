//! The VMess client against a minimal in-process VMess AEAD server written
//! from the protocol description (Xray-core `proxy/vmess`), plus factory
//! checks. `vmess_interop.rs` runs the client against real Xray-core and
//! sing-box servers.

use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_vmess::crypto::{
    chacha_key, cmd_key, fnv1a32, kdf, kdf16, seal_aes_gcm, sha256_16, SizeMask, HEADER_KEY,
    HEADER_LENGTH_KEY, HEADER_LENGTH_NONCE, HEADER_NONCE, RESPONSE_IV, RESPONSE_KEY,
    RESPONSE_LENGTH_IV, RESPONSE_LENGTH_KEY,
};
use outbound_vmess::{VmessFactory, VmessOutbound};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn uuid() -> [u8; 16] {
    outbound_vmess::parse_uuid(UUID).unwrap()
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

fn open(key: &LessSafeKey, nonce: [u8; 12], aad: &[u8], data: &mut [u8]) -> Option<usize> {
    key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
        .ok()
        .map(|plain| plain.len())
}

fn aes_key(key: &[u8; 16]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).unwrap())
}

fn nonce12(bytes: &[u8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&bytes[..12]);
    out
}

/// One direction of the chunk stream, as the server sees it.
struct Chunks {
    key: LessSafeKey,
    iv: [u8; 16],
    count: u16,
    mask: SizeMask,
}

impl Chunks {
    fn new(security: u8, key: &[u8; 16], iv: [u8; 16]) -> Self {
        let key = match security {
            3 => aes_key(key),
            4 => LessSafeKey::new(
                UnboundKey::new(&aead::CHACHA20_POLY1305, &chacha_key(key)).unwrap(),
            ),
            other => panic!("unexpected security {other}"),
        };
        Self {
            key,
            iv,
            count: 0,
            mask: SizeMask::new(&iv),
        }
    }

    fn nonce(&mut self) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.count += 1;
        Nonce::assume_unique_for_key(nonce)
    }

    /// `None` at the end chunk or on any error.
    async fn read<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> Option<Vec<u8>> {
        let mut size = [0u8; 2];
        stream.read_exact(&mut size).await.ok()?;
        let size = usize::from(u16::from_be_bytes(size) ^ self.mask.next_mask());
        if size == 16 {
            return None;
        }
        let mut sealed = vec![0u8; size];
        stream.read_exact(&mut sealed).await.ok()?;
        let nonce = self.nonce();
        let len = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut sealed)
            .ok()?
            .len();
        sealed.truncate(len);
        Some(sealed)
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let size = (payload.len() + 16) as u16;
        let mut out = (size ^ self.mask.next_mask()).to_be_bytes().to_vec();
        let mut body = payload.to_vec();
        let nonce = self.nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
            .unwrap();
        out.extend_from_slice(&body);
        out
    }
}

struct Request {
    security: u8,
    key: [u8; 16],
    iv: [u8; 16],
    response_v: u8,
    host: String,
    port: u16,
}

/// Opens and parses the sealed request header.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S, cmd: &[u8; 16]) -> Option<Request> {
    let mut auth_id = [0u8; 16];
    let mut sealed_length = [0u8; 18];
    let mut connection_nonce = [0u8; 8];
    stream.read_exact(&mut auth_id).await.ok()?;
    stream.read_exact(&mut sealed_length).await.ok()?;
    stream.read_exact(&mut connection_nonce).await.ok()?;
    let path = |label: &'static [u8]| -> [&[u8]; 3] { [label, &auth_id, &connection_nonce] };
    open(
        &aes_key(&kdf16(cmd, &path(HEADER_LENGTH_KEY))),
        nonce12(&kdf(cmd, &path(HEADER_LENGTH_NONCE))),
        &auth_id,
        &mut sealed_length,
    )?;
    let length = usize::from(u16::from_be_bytes([sealed_length[0], sealed_length[1]]));
    let mut header = vec![0u8; length + 16];
    stream.read_exact(&mut header).await.ok()?;
    let plain_len = open(
        &aes_key(&kdf16(cmd, &path(HEADER_KEY))),
        nonce12(&kdf(cmd, &path(HEADER_NONCE))),
        &auth_id,
        &mut header,
    )?;
    header.truncate(plain_len);

    let (body, checksum) = header.split_at(header.len() - 4);
    if fnv1a32(body).to_be_bytes() != checksum || body[0] != 1 || body[37] != 1 {
        return None;
    }
    let mut iv = [0u8; 16];
    let mut key = [0u8; 16];
    iv.copy_from_slice(&body[1..17]);
    key.copy_from_slice(&body[17..33]);
    let response_v = body[33];
    assert_eq!(body[34], 0x05, "options ChunkStream | ChunkMasking");
    let security = body[35] & 0x0f;
    // ver, iv, key, V, option, padding|security, reserved, command (37).
    let port = u16::from_be_bytes([body[38], body[39]]);
    let host = match body[40] {
        1 => std::net::Ipv4Addr::new(body[41], body[42], body[43], body[44]).to_string(),
        2 => {
            let len = usize::from(body[41]);
            String::from_utf8(body[42..42 + len].to_vec()).ok()?
        }
        _ => return None,
    };
    Some(Request {
        security,
        key,
        iv,
        response_v,
        host,
        port,
    })
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let cmd = cmd_key(&uuid());
    let Some(Request {
        security,
        key,
        iv,
        response_v,
        host,
        port,
    }) = read_request(&mut stream, &cmd).await
    else {
        return;
    };
    let Ok(upstream) = TcpStream::connect((host.as_str(), port)).await else {
        return;
    };
    let response_key = sha256_16(&key);
    let response_iv = sha256_16(&iv);

    // Sealed response header: V, option, no command.
    let mut length = 4u16.to_be_bytes().to_vec();
    seal_aes_gcm(
        &kdf16(&response_key, &[RESPONSE_LENGTH_KEY]),
        &kdf(&response_iv, &[RESPONSE_LENGTH_IV]),
        &[],
        &mut length,
    );
    let mut header = vec![response_v, 0, 0, 0];
    seal_aes_gcm(
        &kdf16(&response_key, &[RESPONSE_KEY]),
        &kdf(&response_iv, &[RESPONSE_IV]),
        &[],
        &mut header,
    );
    if stream.write_all(&length).await.is_err() || stream.write_all(&header).await.is_err() {
        return;
    }

    let mut uplink = Chunks::new(security, &key, iv);
    let mut downlink = Chunks::new(security, &response_key, response_iv);
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let (mut target_read, mut target_write) = upstream.into_split();
    let up = async move {
        while let Some(payload) = uplink.read(&mut client_read).await {
            if target_write.write_all(&payload).await.is_err() {
                return;
            }
        }
        let _ = target_write.shutdown().await;
    };
    let down = async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match target_read.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if client_write
                        .write_all(&downlink.seal(&buf[..n]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                _ => break,
            }
        }
        let _ = client_write.write_all(&downlink.seal(&[])).await;
        let _ = client_write.shutdown().await;
    };
    tokio::join!(up, down);
}

async fn vmess_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream));
        }
    });
    addr
}

fn registry() -> OutboundRegistry {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(VmessFactory));
    registry
}

fn settings(server: SocketAddr, security: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({
        "server": server.ip().to_string(),
        "port": server.port(),
        "uuid": UUID,
        "security": security,
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn fnv1a_and_cmd_key_match_known_values() {
    // FNV-1a 32 of "a" from the reference implementation.
    assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
    assert_eq!(fnv1a32(b""), 0x811c_9dc5);
    // Fixed inputs give fixed keys.
    assert_eq!(cmd_key(&uuid()), cmd_key(&uuid()));
    assert_ne!(cmd_key(&uuid()), cmd_key(&[0u8; 16]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relays_with_both_body_ciphers() {
    let echo = echo_server().await;
    let server = vmess_server().await;
    for security in ["aes-128-gcm", "chacha20-poly1305", "auto"] {
        let vmess = registry()
            .build("vmess", &settings(server, security), Arc::new(TcpDialer))
            .unwrap();
        assert_eq!(vmess.protocol(), "vmess");
        for target in [
            TargetAddr::Ip(echo),
            TargetAddr::Domain("localhost".into(), echo.port()),
        ] {
            let mut stream = vmess.connect(&target).await.unwrap();
            // Larger than one chunk, to cover chunk splitting and counters.
            let payload: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload, "{security} {target}");
            stream.shutdown().await.unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_uuid_gets_no_data() {
    let echo = echo_server().await;
    let server = vmess_server().await;
    let vmess = VmessOutbound::new(
        server.ip().to_string(),
        server.port(),
        [7u8; 16],
        outbound_vmess::Security::Aes128Gcm,
        None,
        Arc::new(TcpDialer),
    )
    .unwrap();
    let mut stream = vmess.connect(&TargetAddr::Ip(echo)).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 5];
    assert!(stream.read_exact(&mut buf).await.is_err());
}

#[test]
fn factory_rejects_unsupported_settings() {
    let base = |extra: serde_json::Value| {
        let mut value = serde_json::json!({"server": "192.0.2.1", "port": 443, "uuid": UUID});
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        value.as_object().unwrap().clone()
    };
    for bad in [
        base(serde_json::json!({"alter_id": 64})),
        base(serde_json::json!({"security": "none"})),
        base(serde_json::json!({"security": "zero"})),
        base(serde_json::json!({"uuid": "not-a-uuid"})),
        base(serde_json::json!({"transport": {"type": "grpc"}})),
        base(serde_json::json!({"server": ""})),
    ] {
        assert!(registry()
            .build("vmess", &bad, Arc::new(TcpDialer))
            .is_err());
    }
    for good in [
        base(serde_json::json!({})),
        base(serde_json::json!({"tls": {"server_name": "a.example"}})),
        base(serde_json::json!({"tls": {}, "transport": {"type": "ws", "path": "/vm"}})),
    ] {
        assert!(registry()
            .build("vmess", &good, Arc::new(TcpDialer))
            .is_ok());
    }
}
