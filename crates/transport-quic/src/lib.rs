//! QUIC client transport for QUIC-based outbounds (Hysteria2, TUIC, ...):
//! quinn over rustls, with TLS settings, roots and the `insecure` verifier
//! from `transport-tls`.
//!
//! [`QuicConnector`] resolves the server, binds a UDP socket of the matching
//! family and returns an established [`QuicConnection`]; the protocol crate
//! authenticates on it and opens one stream per proxied connection.
//! [`QuicStream`] turns a bidirectional stream into a [`BoxStream`].

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use engine_outbound::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use transport_tls::TlsSettings;

pub use quinn;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;

/// Congestion controller of the connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl Congestion {
    /// Parses the names share links and configs use (`cubic`, `new_reno`,
    /// `newreno`, `bbr`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "cubic" => Some(Self::Cubic),
            "new_reno" | "newreno" | "new-reno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }
}

/// A configured client for one server; cheap to share.
pub struct QuicConnector {
    server: String,
    port: u16,
    server_name: String,
    client_config: quinn::ClientConfig,
}

/// An established connection and the endpoint that drives its socket.
pub struct QuicConnection {
    pub connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl QuicConnector {
    /// `tls.alpn` falls back to `default_alpn` when empty.
    pub fn new(
        server: impl Into<String>,
        port: u16,
        tls: &TlsSettings,
        default_alpn: &[&str],
        congestion: Congestion,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("quic server address is empty"));
        }
        let mut tls = tls.clone();
        if tls.alpn.is_empty() {
            tls.alpn = default_alpn.iter().map(|alpn| (*alpn).to_owned()).collect();
        }
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(transport_tls::client_config(&tls)?)
                .map_err(|_| invalid("tls settings are unusable for quic"))?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
            .receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
            .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
                    .map_err(|_| invalid("quic idle timeout is invalid"))?,
            ));
        match congestion {
            Congestion::Cubic => {}
            Congestion::NewReno => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            Congestion::Bbr => {
                transport.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
        }
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));
        Ok(Self {
            server,
            port,
            server_name: tls.server_name,
            client_config,
        })
    }

    /// Resolves the server and completes the QUIC handshake, within a
    /// timeout.
    pub async fn connect(&self) -> io::Result<QuicConnection> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.connect_inner())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
    }

    async fn connect_inner(&self) -> io::Result<QuicConnection> {
        let addr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "quic server not found"))?;
        let bind: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(bind)?;
        let connection = endpoint
            .connect_with(self.client_config.clone(), addr, &self.server_name)
            .map_err(|_| invalid("quic connect settings are invalid"))?
            .await
            .map_err(quic_error)?;
        Ok(QuicConnection {
            connection,
            _endpoint: endpoint,
        })
    }
}

/// One proxied connection on a bidirectional QUIC stream. The tokio trait
/// methods are called by path because quinn's inherent `poll_read` and
/// `poll_write` return quinn error types.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    pub fn boxed(send: quinn::SendStream, recv: quinn::RecvStream) -> BoxStream {
        Box::new(Self::new(send, recv))
    }
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

/// Maps a quinn connection error to `ConnectionAborted`.
pub fn quic_error(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, err)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
