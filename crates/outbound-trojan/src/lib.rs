//! Trojan TCP outbound (trojan-gfw protocol) over standard TLS.
//!
//! After the TLS handshake the client sends
//! `hex(SHA-224(password)) CRLF CMD ATYP DST.ADDR DST.PORT CRLF` and then the
//! payload; the server answers with the target's bytes directly. The request
//! is held back and written together with the first payload so it leaves in
//! the same TLS record, like other Trojan clients do.
//!
//! With [`TrojanOutbound::with_websocket`] the Trojan stream runs inside a
//! WebSocket over the TLS connection (the `ws` transport of Trojan-Go and
//! Xray).
//!
//! [`TrojanFactory`] registers the outbound under `"type": "trojan"`.

mod factory;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use transport_grpc::GrpcConnector;
use transport_tls::{TlsConnector, TlsSettings};
use transport_ws::WsConnector;

pub use factory::{TrojanFactory, TYPE_NAME};

pub const PROTOCOL: &str = "trojan";

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub struct TrojanOutbound {
    server: String,
    port: u16,
    /// Lowercase hex SHA-224 of the password; the password itself is dropped.
    password_hash: [u8; 56],
    tls: TlsConnector,
    websocket: Option<WsConnector>,
    grpc: Option<GrpcConnector>,
    dialer: Arc<dyn Dialer>,
}

impl TrojanOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        password: &str,
        tls: &TlsSettings,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("trojan server address is empty"));
        }
        if password.is_empty() {
            return Err(invalid("trojan password is empty"));
        }
        Ok(Self {
            server,
            port,
            password_hash: password_hash(password),
            tls: TlsConnector::new(tls)?,
            websocket: None,
            grpc: None,
            dialer,
        })
    }

    /// Carries the Trojan stream in a WebSocket inside the TLS connection.
    pub fn with_websocket(mut self, websocket: WsConnector) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Carries the stream in a gRPC (`gun`) call instead of a WebSocket.
    pub fn with_grpc(mut self, grpc: GrpcConnector) -> Self {
        self.grpc = Some(grpc);
        self
    }
}

impl TcpOutbound for TrojanOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let request = request_header(&self.password_hash, target)?;
            let transport = self.dialer.dial(&self.server, self.port).await?;
            let mut tls = self.tls.connect(transport).await?;
            if let Some(websocket) = &self.websocket {
                tls = websocket.connect(tls).await?;
            }
            if let Some(grpc) = &self.grpc {
                tls = grpc.connect(tls).await?;
            }
            Ok(Box::new(TrojanStream {
                inner: tls,
                pending: request,
                written: 0,
                merged: false,
            }) as BoxStream)
        })
    }
}

/// Lowercase hex of SHA-224, as the protocol puts it on the wire.
pub fn password_hash(password: &str) -> [u8; 56] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = HEX[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

fn request_header(password_hash: &[u8; 56], target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(56 + 2 + 4 + 256 + 2 + 2);
    out.extend_from_slice(password_hash);
    out.extend_from_slice(b"\r\n");
    out.push(CMD_CONNECT);
    match target {
        TargetAddr::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| invalid("trojan target domain length is invalid"))?;
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// The TLS stream with the request header written ahead of the first payload,
/// or on the first flush or read if the application reads first.
struct TrojanStream {
    inner: BoxStream,
    /// Request header (plus the first payload once merged) not yet written.
    pending: Vec<u8>,
    written: usize,
    /// Whether the first payload was appended to the header.
    merged: bool,
}

impl TrojanStream {
    fn poll_send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        if !self.pending.is_empty() {
            self.pending = Vec::new();
            self.written = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.merged {
            // Header and first payload go out in one write, so one TLS
            // record. The bytes are accepted now; a send that is still
            // pending finishes on the next write, flush or read.
            self.merged = true;
            self.pending.extend_from_slice(buf);
            if let Poll::Ready(Err(err)) = self.poll_send_pending(cx) {
                return Poll::Ready(Err(err));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TrojanStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Server-speaks-first targets: the request must reach the server
        // before any response can arrive.
        if !self.pending.is_empty() {
            ready!(self.poll_send_pending(cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
