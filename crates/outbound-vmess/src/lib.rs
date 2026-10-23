//! VMess AEAD TCP outbound (alterId 0, as current Xray-core and V2Ray use)
//! over plain TCP or standard TLS, optionally inside a WebSocket.
//!
//! The request header is sealed with the AEAD header scheme (AuthID plus
//! AES-128-GCM keyed from the user's cmd key) and sent with the first
//! payload chunk. The body uses AES-128-GCM or ChaCha20-Poly1305 chunks with
//! SHAKE128-masked lengths (options ChunkStream and ChunkMasking).
//!
//! [`VmessFactory`] registers the outbound under `"type": "vmess"`.

pub mod crypto;
mod factory;
mod stream;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use transport_grpc::GrpcConnector;
use transport_tls::TlsConnector;
use transport_ws::WsConnector;

pub use factory::{parse_uuid, VmessFactory, TYPE_NAME};

use crate::crypto::{
    auth_id, chacha_key, cmd_key, fnv1a32, kdf, kdf16, seal_request_header, sha256_16, RESPONSE_IV,
    RESPONSE_KEY, RESPONSE_LENGTH_IV, RESPONSE_LENGTH_KEY,
};
use crate::stream::{BodyCipher, ResponseKeys, VmessStream};

pub const PROTOCOL: &str = "vmess";

const VERSION: u8 = 1;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const COMMAND_TCP: u8 = 1;

/// Body cipher; the wire values are Xray's `SecurityType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Security {
    /// `auto` picks AES-128-GCM, as Xray does on hardware with AES support.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "" | "auto" | "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    fn wire(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::ChaCha20Poly1305 => 4,
        }
    }

    fn body_key(self, key: &[u8; 16]) -> LessSafeKey {
        let unbound = match self {
            Self::Aes128Gcm => UnboundKey::new(&aead::AES_128_GCM, key),
            Self::ChaCha20Poly1305 => UnboundKey::new(&aead::CHACHA20_POLY1305, &chacha_key(key)),
        };
        LessSafeKey::new(unbound.expect("body key has the algorithm's length"))
    }
}

pub struct VmessOutbound {
    server: String,
    port: u16,
    cmd_key: [u8; 16],
    security: Security,
    tls: Option<TlsConnector>,
    websocket: Option<WsConnector>,
    grpc: Option<GrpcConnector>,
    dialer: Arc<dyn Dialer>,
    random: SystemRandom,
}

impl fmt::Debug for VmessOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmessOutbound")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("uuid", &"<redacted>")
            .field("security", &self.security)
            .field("tls", &self.tls.is_some())
            .field("websocket", &self.websocket.is_some())
            .field("grpc", &self.grpc.is_some())
            .finish()
    }
}

impl VmessOutbound {
    /// `tls: None` is VMess over plain TCP.
    pub fn new(
        server: impl Into<String>,
        port: u16,
        uuid: [u8; 16],
        security: Security,
        tls: Option<TlsConnector>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess server address is empty",
            ));
        }
        Ok(Self {
            server,
            port,
            cmd_key: cmd_key(&uuid),
            security,
            tls,
            websocket: None,
            grpc: None,
            dialer,
            random: SystemRandom::new(),
        })
    }

    /// Carries VMess in a WebSocket (inside TLS when TLS is set).
    pub fn with_websocket(mut self, websocket: WsConnector) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Carries the stream in a gRPC (`gun`) call instead of a WebSocket.
    pub fn with_grpc(mut self, grpc: GrpcConnector) -> Self {
        self.grpc = Some(grpc);
        self
    }

    fn random_bytes<const N: usize>(&self) -> io::Result<[u8; N]> {
        let mut out = [0u8; N];
        self.random
            .fill(&mut out)
            .map_err(|_| io::Error::other("system random source failed"))?;
        Ok(out)
    }

    fn open_session(&self, target: &TargetAddr) -> io::Result<Session> {
        let body_iv: [u8; 16] = self.random_bytes()?;
        let body_key: [u8; 16] = self.random_bytes()?;
        let [response_v, padding_seed] = self.random_bytes::<2>()?;
        let padding_len = usize::from(padding_seed % 16);
        let padding: [u8; 16] = self.random_bytes()?;

        let mut header = Vec::with_capacity(64 + 255);
        header.push(VERSION);
        header.extend_from_slice(&body_iv);
        header.extend_from_slice(&body_key);
        header.push(response_v);
        header.push(OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);
        header.push(((padding_len as u8) << 4) | self.security.wire());
        header.push(0);
        header.push(COMMAND_TCP);
        encode_address(target, &mut header)?;
        header.extend_from_slice(&padding[..padding_len]);
        let checksum = fnv1a32(&header);
        header.extend_from_slice(&checksum.to_be_bytes());

        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("system clock is before 1970"))?
            .as_secs();
        let id = auth_id(&self.cmd_key, unix_time, self.random_bytes()?);
        let connection_nonce: [u8; 8] = self.random_bytes()?;
        let sealed = seal_request_header(&self.cmd_key, &id, &connection_nonce, &header);

        let response_key = sha256_16(&body_key);
        let response_iv = sha256_16(&body_iv);
        Ok(Session {
            sealed,
            writer: BodyCipher::new(self.security.body_key(&body_key), body_iv),
            reader: BodyCipher::new(self.security.body_key(&response_key), response_iv),
            response: ResponseKeys {
                length_key: kdf16(&response_key, &[RESPONSE_LENGTH_KEY]),
                length_iv: kdf(&response_iv, &[RESPONSE_LENGTH_IV]),
                header_key: kdf16(&response_key, &[RESPONSE_KEY]),
                header_iv: kdf(&response_iv, &[RESPONSE_IV]),
                expected: response_v,
            },
        })
    }
}

struct Session {
    sealed: Vec<u8>,
    writer: BodyCipher,
    reader: BodyCipher,
    response: ResponseKeys,
}

/// Port, then address type 1 (IPv4), 2 (domain) or 3 (IPv6).
fn encode_address(target: &TargetAddr, out: &mut Vec<u8>) -> io::Result<()> {
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(3);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vmess target domain must be 1..=255 bytes",
                    )
                })?;
            out.push(2);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

impl TcpOutbound for VmessOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let session = self.open_session(target)?;
            let mut stream = self.dialer.dial(&self.server, self.port).await?;
            if let Some(tls) = &self.tls {
                stream = tls.connect(stream).await?;
            }
            if let Some(websocket) = &self.websocket {
                stream = websocket.connect(stream).await?;
            }
            if let Some(grpc) = &self.grpc {
                stream = grpc.connect(stream).await?;
            }
            Ok(Box::new(VmessStream::new(
                stream,
                session.sealed,
                session.writer,
                session.reader,
                session.response,
            )) as BoxStream)
        })
    }
}
