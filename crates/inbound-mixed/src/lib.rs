//! Local mixed inbound: SOCKS5 and HTTP proxy requests on one listening port.
//!
//! The first byte of a connection picks the protocol: `0x05` is SOCKS5,
//! anything else is parsed as an HTTP/1.x proxy request. Both end in a
//! [`TargetAddr`] that is handed to a [`TcpOutbound`]; after that the bytes are
//! relayed unchanged in both directions.
//!
//! Supported: SOCKS5 without authentication and with username/password
//! (RFC 1929), `CONNECT` only; HTTP `CONNECT` tunnels and absolute-form plain
//! HTTP requests, optionally with `Proxy-Authorization: Basic`. SOCKS5 `BIND`
//! and `UDP ASSOCIATE` are answered with "command not supported".
//!
//! The listener is meant for loopback. Errors and logs never contain
//! credentials or request contents.

mod http;
mod socks5;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Largest request head accepted from a client, for SOCKS5 and HTTP alike.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
/// How long an error reply waits for the client to close before the socket
/// is dropped.
const LINGER: Duration = Duration::from_millis(500);

/// Credentials a client must present. Has no `Debug` on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct MixedSettings {
    pub max_connections: usize,
    /// Time allowed for the client's SOCKS5 or HTTP request head.
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    /// When set, both protocols require these credentials.
    pub credentials: Option<Credentials>,
}

impl Default for MixedSettings {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            credentials: None,
        }
    }
}

/// Counters only; no addresses.
#[derive(Debug, Default)]
pub struct MixedStats {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub active: AtomicU64,
    pub handshake_failed: AtomicU64,
    pub connect_failed: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

/// A parsed proxy request, before the outbound connection exists.
pub(crate) struct Request {
    pub target: TargetAddr,
    /// Bytes to send to the target first (a rewritten plain HTTP request head).
    pub initial: Vec<u8>,
    pub reply: Reply,
}

/// How to answer the client once the outbound connection succeeded or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Socks5,
    HttpConnect,
    /// Plain HTTP: the target's own response is the answer.
    HttpForward,
}

/// Both ends of an accepted client connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAddrs {
    /// The client's own address.
    pub peer: SocketAddr,
    /// The listener address the client connected to.
    pub local: SocketAddr,
}

/// Connects a client's request; unlike a [`TcpOutbound`] it learns which
/// client asked, for routing by the local process.
pub trait ClientConnector: Send + Sync {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>>;
}

/// Any outbound, ignoring who asked.
struct AnyClient(Arc<dyn TcpOutbound>);

impl ClientConnector for AnyClient {
    fn connect_client<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.0.connect(target)
    }
}

/// Accepts connections until the listener fails or the task is dropped.
pub async fn serve(
    listener: TcpListener,
    outbound: Arc<dyn TcpOutbound>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    serve_clients(listener, Arc::new(AnyClient(outbound)), settings, stats).await
}

/// [`serve`] with a connector that is told each client's addresses.
pub async fn serve_clients(
    listener: TcpListener,
    connector: Arc<dyn ClientConnector>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(settings.max_connections));
    let settings = Arc::new(settings);
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        let client = ClientAddrs { peer, local };
        let connector = connector.clone();
        let settings = settings.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            stats.active.fetch_add(1, Ordering::Relaxed);
            handle(stream, client, connector.as_ref(), &settings, &stats).await;
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle(
    mut client: TcpStream,
    addrs: ClientAddrs,
    connector: &dyn ClientConnector,
    settings: &MixedSettings,
    stats: &MixedStats,
) {
    let request = tokio::time::timeout(
        settings.handshake_timeout,
        read_request(&mut client, settings.credentials.as_ref()),
    )
    .await;
    let request = match request {
        Ok(Ok(request)) => request,
        Ok(Err(_)) | Err(_) => {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            close_gracefully(client).await;
            return;
        }
    };

    let connected = tokio::time::timeout(
        settings.connect_timeout,
        connector.connect_client(addrs, &request.target),
    )
    .await;
    let mut remote = match connected {
        Ok(Ok(remote)) => remote,
        Ok(Err(_)) | Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            let _ = send_failure(&mut client, request.reply).await;
            close_gracefully(client).await;
            return;
        }
    };
    if send_success(&mut client, request.reply).await.is_err() {
        return;
    }
    if !request.initial.is_empty() {
        if remote.write_all(&request.initial).await.is_err() {
            return;
        }
        stats
            .bytes_up
            .fetch_add(request.initial.len() as u64, Ordering::Relaxed);
    }
    relay(client, remote, stats).await;
}

async fn read_request(
    client: &mut TcpStream,
    credentials: Option<&Credentials>,
) -> io::Result<Request> {
    let mut first = [0u8; 1];
    let peeked = client.peek(&mut first).await?;
    if peeked == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if first[0] == socks5::VERSION {
        socks5::read_request(client, credentials).await
    } else {
        http::read_request(client, credentials).await
    }
}

async fn send_success<S: AsyncWrite + Unpin>(client: &mut S, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Socks5 => {
            client
                .write_all(&socks5::reply(socks5::REP_SUCCEEDED))
                .await
        }
        Reply::HttpConnect => {
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
        }
        Reply::HttpForward => Ok(()),
    }
}

async fn send_failure<S: AsyncWrite + Unpin>(client: &mut S, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Socks5 => {
            client
                .write_all(&socks5::reply(socks5::REP_GENERAL_FAILURE))
                .await
        }
        Reply::HttpConnect | Reply::HttpForward => {
            client
                .write_all(http::status_response(502, "Bad Gateway").as_bytes())
                .await
        }
    }
}

/// Sends FIN after an error reply and drains what the client still sends for
/// a moment. Dropping a socket with unread input makes the kernel answer with
/// a reset, and on Windows the reset discards the reply before the client
/// reads it.
async fn close_gracefully(mut client: TcpStream) {
    let _ = client.shutdown().await;
    let mut sink = [0u8; 1024];
    let mut drained = 0;
    let deadline = tokio::time::Instant::now() + LINGER;
    while drained < MAX_HEAD_BYTES {
        match tokio::time::timeout_at(deadline, client.read(&mut sink)).await {
            Ok(Ok(n)) if n > 0 => drained += n,
            _ => break,
        }
    }
}

async fn relay(mut client: TcpStream, mut remote: BoxStream, stats: &MixedStats) {
    if let Ok((up, down)) = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    )
    .await
    {
        stats.bytes_up.fetch_add(up, Ordering::Relaxed);
        stats.bytes_down.fetch_add(down, Ordering::Relaxed);
    }
}

/// Reads exactly `buf.len()` bytes; shared by both protocol parsers.
pub(crate) async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> io::Result<()> {
    tokio::io::AsyncReadExt::read_exact(stream, buf)
        .await
        .map(|_| ())
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
