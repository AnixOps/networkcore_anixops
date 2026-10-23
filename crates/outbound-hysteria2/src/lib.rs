//! Hysteria2 TCP outbound over QUIC.
//!
//! The client opens one QUIC connection (ALPN `h3`) per outbound and
//! authenticates with an HTTP/3 request, `POST https://hysteria/auth` with the
//! `Hysteria-Auth` header; the server accepts with status 233. Each proxied
//! TCP connection is then a bidirectional QUIC stream that starts with
//!
//! ```text
//! varint 0x401 | varint len | "host:port" | varint len | padding
//! ```
//!
//! and the server answers `u8 status | varint len | message | varint len |
//! padding` (status 0 is success) before the payload flows. Varints are QUIC
//! variable-length integers (RFC 9000 section 16).
//!
//! The connection is shared by every stream and opened again when it closes.
//! Salamander obfuscation, port hopping and Brutal congestion control are not
//! supported; the outbound uses QUIC's default congestion control.
//!
//! [`Hysteria2Factory`] registers the outbound under `"type": "hysteria2"`.

mod factory;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use transport_tls::TlsSettings;

pub use factory::{Hysteria2Factory, TYPE_NAME};

pub const PROTOCOL: &str = "hysteria2";

/// Status of a successful authentication.
pub const AUTH_OK_STATUS: u16 = 233;
/// First varint of a TCP request stream.
pub const TCP_REQUEST_ID: u64 = 0x401;

const AUTH_URI: &str = "https://hysteria/auth";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
/// Longest server message read from a TCP response.
const MAX_RESPONSE_FIELD: u64 = 64 * 1024;

pub struct Hysteria2Outbound {
    server: String,
    port: u16,
    password: String,
    server_name: String,
    client_config: quinn::ClientConfig,
    session: Mutex<Option<Session>>,
}

/// One authenticated QUIC connection.
struct Session {
    connection: quinn::Connection,
    /// The connection closes when the last request sender is dropped.
    _requests: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
    _endpoint: quinn::Endpoint,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Hysteria2Outbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        password: impl Into<String>,
        tls: &TlsSettings,
    ) -> io::Result<Self> {
        let server = server.into();
        let password = password.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("hysteria2 server address is empty"));
        }
        if password.is_empty() {
            return Err(invalid("hysteria2 password is empty"));
        }
        if http::HeaderValue::from_str(&password).is_err() {
            return Err(invalid("hysteria2 password is not a valid header value"));
        }
        let mut tls = tls.clone();
        if tls.alpn.is_empty() {
            tls.alpn.push("h3".to_owned());
        }
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(transport_tls::client_config(&tls)?)
                .map_err(|_| invalid("hysteria2 tls settings are unusable for quic"))?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
            .receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
            .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
                    .map_err(|_| invalid("hysteria2 idle timeout is invalid"))?,
            ));
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));
        Ok(Self {
            server,
            port,
            password,
            server_name: tls.server_name,
            client_config,
            session: Mutex::new(None),
        })
    }

    /// The live QUIC connection, authenticating a new one if needed.
    async fn connection(&self) -> io::Result<quinn::Connection> {
        let mut session = self.session.lock().await;
        if let Some(current) = session.as_ref() {
            if current.connection.close_reason().is_none() {
                return Ok(current.connection.clone());
            }
        }
        *session = None;
        let fresh = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake())
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "hysteria2 handshake timed out")
            })??;
        let connection = fresh.connection.clone();
        *session = Some(fresh);
        Ok(connection)
    }

    async fn handshake(&self) -> io::Result<Session> {
        let addr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hysteria2 server not found"))?;
        let bind: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(bind)?;
        let connection = endpoint
            .connect_with(self.client_config.clone(), addr, &self.server_name)
            .map_err(|_| invalid("hysteria2 quic connect settings are invalid"))?
            .await
            .map_err(quic_error)?;

        let (mut driver, mut requests) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| other("hysteria2 http/3 setup failed"))?;
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let session = Session {
            connection: connection.clone(),
            _requests: requests.clone(),
            driver,
            _endpoint: endpoint,
        };

        let request = http::Request::post(AUTH_URI)
            .header("Hysteria-Auth", self.password.as_str())
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", random_padding(256, 2048)?)
            .body(())
            .map_err(|_| invalid("hysteria2 auth request is invalid"))?;
        let mut stream = requests
            .send_request(request)
            .await
            .map_err(|_| other("hysteria2 auth request failed"))?;
        stream
            .finish()
            .await
            .map_err(|_| other("hysteria2 auth request failed"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|_| other("hysteria2 auth response failed"))?;
        if response.status().as_u16() != AUTH_OK_STATUS {
            connection.close(quinn::VarInt::from_u32(0x100), b"");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hysteria2 authentication rejected",
            ));
        }
        Ok(session)
    }
}

impl TcpOutbound for Hysteria2Outbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let request = tcp_request(target)?;
            let connection = self.connection().await?;
            let (mut send, mut recv) = connection.open_bi().await.map_err(quic_error)?;
            send.write_all(&request).await?;
            read_tcp_response(&mut recv).await?;
            Ok(Box::new(QuicStream { send, recv }) as BoxStream)
        })
    }
}

/// The TCP request header for `target`, with random padding.
pub fn tcp_request(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let address = target.to_string();
    if address.len() > 2048 {
        return Err(invalid("hysteria2 target address is too long"));
    }
    let padding = random_padding(64, 512)?;
    let mut out = Vec::with_capacity(8 + address.len() + 8 + padding.len());
    put_varint(&mut out, TCP_REQUEST_ID);
    put_varint(&mut out, address.len() as u64);
    out.extend_from_slice(address.as_bytes());
    put_varint(&mut out, padding.len() as u64);
    out.extend_from_slice(padding.as_bytes());
    Ok(out)
}

async fn read_tcp_response<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<()> {
    let status = reader.read_u8().await?;
    let message_len = read_varint(reader).await?;
    if message_len > MAX_RESPONSE_FIELD {
        return Err(other("hysteria2 response is too long"));
    }
    let mut message = vec![0u8; message_len as usize];
    reader.read_exact(&mut message).await?;
    let padding_len = read_varint(reader).await?;
    if padding_len > MAX_RESPONSE_FIELD {
        return Err(other("hysteria2 response is too long"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    reader.read_exact(&mut padding).await?;
    if status != 0 {
        // The message comes from the server and names the target, not a
        // credential.
        let message = String::from_utf8_lossy(&message);
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("hysteria2 server refused the connection: {message}"),
        ));
    }
    Ok(())
}

/// Appends a QUIC variable-length integer (values up to 2^62 - 1).
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Reads a QUIC variable-length integer.
pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = value << 8 | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

/// Random alphanumeric text of a random length in `min..max`.
fn random_padding(min: usize, max: usize) -> io::Result<String> {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let rng = SystemRandom::new();
    let mut len = [0u8; 2];
    rng.fill(&mut len)
        .map_err(|_| other("system random source failed"))?;
    let len = min + usize::from(u16::from_be_bytes(len)) % (max - min);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes)
        .map_err(|_| other("system random source failed"))?;
    Ok(bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect())
}

/// One proxied TCP connection: a bidirectional QUIC stream. The tokio trait
/// methods are called by path because quinn's inherent `poll_read` and
/// `poll_write` return quinn error types.
struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

fn quic_error(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, err)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn other(message: &'static str) -> io::Error {
    io::Error::other(message)
}
