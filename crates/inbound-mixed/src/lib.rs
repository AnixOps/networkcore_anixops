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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Largest request head accepted from a client, for SOCKS5 and HTTP alike.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;

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

/// Accepts connections until the listener fails or the task is dropped.
pub async fn serve(
    listener: TcpListener,
    outbound: Arc<dyn TcpOutbound>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(settings.max_connections));
    let settings = Arc::new(settings);
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let outbound = outbound.clone();
        let settings = settings.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            stats.active.fetch_add(1, Ordering::Relaxed);
            handle(stream, outbound.as_ref(), &settings, &stats).await;
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle(
    mut client: TcpStream,
    outbound: &dyn TcpOutbound,
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
            return;
        }
    };

    let connected =
        tokio::time::timeout(settings.connect_timeout, outbound.connect(&request.target)).await;
    let mut remote = match connected {
        Ok(Ok(remote)) => remote,
        Ok(Err(_)) | Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            let _ = send_failure(&mut client, request.reply).await;
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
