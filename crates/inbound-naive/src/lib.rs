//! NaiveProxy server inbound: an HTTP/2 `CONNECT` proxy inside TLS, as
//! NaiveProxy clients and sing-box's `naive` outbound speak it.
//!
//! A client keeps one HTTP/2 connection and opens a stream per proxied
//! connection:
//!
//! ```text
//! :method: CONNECT
//! :authority: example.com:443
//! proxy-authorization: Basic base64(username:password)
//! padding: <filler>
//! padding-type-request: 1, 0
//! ```
//!
//! The answer is `200` once the target is connected, and the stream's DATA
//! frames then carry the connection both ways. The `padding` header only
//! varies the size of the HEADERS frame. `padding-type-request` lists the
//! payload paddings the client knows, preferred first: `0` is none and `1`
//! frames the first eight reads and writes of each direction
//! ([`padding`]). The server names its choice in `padding-type-reply`; a
//! client from before these headers asks for the framing with `padding`
//! alone and takes a `padding` header in the answer as agreement.
//!
//! Server behaviour:
//!
//! * A connection that does not start with the HTTP/2 preface goes to the
//!   fallback unchanged, or is held open and drained without one.
//! * A request that is not a `CONNECT` with a known user's credentials is
//!   answered by the fallback: it is repeated there over cleartext HTTP/2
//!   and the response is passed back, so the port looks like the web site
//!   behind it. Without a fallback the request is held unanswered, then
//!   reset.
//! * A target that cannot be connected gets `502`. Every `200` carries a
//!   `padding` header of random length.
//! * A tunnel ends when either side closes or resets it, or its user is
//!   removed. Only TCP is relayed.

mod factory;
pub mod padding;

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use base64::Engine as _;
use bytes::Bytes;
use engine_inbound::server::ConnectionContext;
use engine_inbound::stream::PrefixedStream;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{
    fallback_or_hold, read_first, Accepted, Rejected, StreamInbound, User, UserEntry, UserStore,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use futures_util::stream::{FuturesUnordered, StreamExt};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::header::{HeaderMap, HeaderValue, PROXY_AUTHORIZATION};
use http::{Method, StatusCode};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use factory::{NaiveInboundFactory, TYPE_NAME};
pub use padding::Padded;

pub const PROTOCOL: &str = "naive";

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Most requests open at once on one client connection.
const MAX_STREAMS: u32 = 256;
const STREAM_WINDOW: u32 = 1024 * 1024;
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
/// Largest DATA frame handed to the HTTP/2 connection at once.
const MAX_WRITE: usize = 64 * 1024;
/// Symbols whose HPACK Huffman codes are longer than a byte, so a `padding`
/// header grows the HEADERS frame by at least its length.
const PADDING_SYMBOLS: &[u8] = b"!#$'()+<>?@[]^`{|}~";

pub struct NaiveInbound {
    users: Arc<UserStore>,
    /// Users by the token of their Basic credentials.
    index: UserIndex<String>,
    fallback: Option<TargetAddr>,
}

impl NaiveInbound {
    pub fn new(fallback: Option<TargetAddr>) -> Self {
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("naive user password is missing"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Self {
            index: UserIndex::new(users.clone(), basic_token),
            users,
            fallback,
        }
    }

    async fn serve(&self, mut stream: BoxStream, context: ConnectionContext<'_>) {
        let timeout = context.settings.handshake_timeout;
        let first = match tokio::time::timeout(timeout, first_bytes(&mut stream)).await {
            Ok(Ok(first)) if !first.is_empty() => first,
            _ => {
                context.handshake_failed();
                return;
            }
        };
        if !first.starts_with(PREFACE) {
            let reason = "naive client does not speak HTTP/2";
            match fallback_or_hold(self.fallback.as_ref(), first, stream, reason) {
                Ok(accepted) => context.relay_accepted(accepted).await,
                Err(rejected) => {
                    context.handshake_failed();
                    if let Some(stream) = rejected.stream {
                        context.hold(stream).await;
                    }
                }
            }
            return;
        }
        let handshake = h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_concurrent_streams(MAX_STREAMS)
            .handshake::<_, Bytes>(PrefixedStream::new(stream).with_read_prefix(first));
        let Ok(Ok(mut connection)) = tokio::time::timeout(timeout, handshake).await else {
            context.handshake_failed();
            return;
        };
        let mut requests = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = connection.accept() => match accepted {
                    Some(Ok((request, respond))) => {
                        requests.push(self.request(request, respond, context));
                    }
                    _ => break,
                },
                Some(()) = requests.next(), if !requests.is_empty() => {}
            }
        }
        // The client opens no more requests; the connection's I/O goes on
        // for the open ones.
        tokio::select! {
            _ = poll_fn(|cx| connection.poll_closed(cx)) => {}
            _ = async { while requests.next().await.is_some() {} } => {}
        }
    }

    /// The user of a proxy request: a `CONNECT` with the Basic credentials
    /// of a known user.
    fn user(&self, request: &http::Request<RecvStream>) -> Option<Arc<UserEntry>> {
        if request.method() != Method::CONNECT {
            return None;
        }
        let credentials = request.headers().get(PROXY_AUTHORIZATION)?.to_str().ok()?;
        let (scheme, token) = credentials.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        self.index.get(&token.trim().to_owned())
    }

    /// Serves one request of a client connection to its end.
    async fn request(
        &self,
        request: http::Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        context: ConnectionContext<'_>,
    ) {
        let Some(user) = self.user(&request) else {
            self.decoy(request, respond, context).await;
            return;
        };
        if user.is_revoked() {
            context.revoked();
            return;
        }
        let Some(_online) = user.try_connect(context.peer.ip()) else {
            context.stats.device_limited.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let (Some(host), Some(port)) = (request.uri().host(), request.uri().port_u16()) else {
            let _ = respond.send_response(status(StatusCode::BAD_REQUEST), true);
            return;
        };
        let target = TargetAddr::from_host(host, port);
        let Ok(mut remote) = context.connect(&target).await else {
            let _ = respond.send_response(status(StatusCode::BAD_GATEWAY), true);
            return;
        };
        let (padded, reply) = padding_type(request.headers());
        let mut response = status(StatusCode::OK);
        response.headers_mut().insert("padding", padding_header());
        if let Some(reply) = reply {
            let reply = HeaderValue::from_static(reply);
            response.headers_mut().insert("padding-type-reply", reply);
        }
        let Ok(send) = respond.send_response(response, false) else {
            return;
        };
        let tunnel = Tunnel::new(request.into_body(), send);
        let mut tunnel: BoxStream = if padded {
            Box::new(Padded::new(tunnel))
        } else {
            Box::new(tunnel)
        };
        let _ = context
            .relay_to(Some(&user), Some(&target), &mut tunnel, &mut remote)
            .await;
    }

    /// Answers a request that is not a known user's proxy request with the
    /// fallback's response to it.
    async fn decoy(
        &self,
        request: http::Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        context: ConnectionContext<'_>,
    ) {
        let Some(fallback) = &self.fallback else {
            context.handshake_failed();
            // Held like a failed handshake of the other inbounds; the stream
            // is reset when `respond` drops.
            tokio::time::sleep(context.settings.reject_hold).await;
            return;
        };
        let Ok(remote) = context.connect(fallback).await else {
            return;
        };
        let Ok((sender, connection)) = h2::client::handshake(remote).await else {
            return;
        };
        let exchange = async {
            let (head, body) = request.into_parts();
            let ended = body.is_end_stream();
            let mut sender = sender.ready().await?;
            let (response, send) =
                sender.send_request(http::Request::from_parts(head, ()), ended)?;
            let upload = pipe(body, send, ended);
            let download = async {
                let (head, body) = response.await?.into_parts();
                let ended = body.is_end_stream();
                let head = http::Response::from_parts(head, ());
                let send = respond.send_response(head, ended)?;
                pipe(body, send, ended).await
            };
            tokio::pin!(upload);
            // The response ends the exchange, whatever is left of the
            // request (the open body of a `CONNECT`, say).
            tokio::select! {
                done = download => done,
                Err(error) = &mut upload => Err(error),
            }
        };
        tokio::select! {
            _ = connection => {}
            _ = exchange => {}
        }
    }
}

/// Reads what the client sends first, until it can be told from the HTTP/2
/// preface. Empty when the client closed the connection.
async fn first_bytes(stream: &mut BoxStream) -> io::Result<Vec<u8>> {
    let mut first = read_first(stream).await?;
    while !first.is_empty() && first.len() < PREFACE.len() && PREFACE.starts_with(&first) {
        let more = read_first(stream).await?;
        if more.is_empty() {
            break;
        }
        first.extend_from_slice(&more);
    }
    Ok(first)
}

/// The Basic credentials a user's client sends: the login name (`username`,
/// or `name`) and the password.
fn basic_token(user: &User) -> Option<String> {
    let login = user.username.as_deref().unwrap_or(&user.name);
    let password = user.password.as_deref()?;
    Some(base64::engine::general_purpose::STANDARD.encode(format!("{login}:{password}")))
}

/// Whether a request's tunnel frames its first reads and writes, and the
/// `padding-type-reply` that says so: the first type we know of
/// `padding-type-request`, or the framing for a client that sends only
/// `padding`.
fn padding_type(headers: &HeaderMap) -> (bool, Option<&'static str>) {
    let Some(request) = headers.get("padding-type-request") else {
        return (headers.contains_key("padding"), None);
    };
    let known = request
        .to_str()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .find(|kind| matches!(*kind, "0" | "1"));
    match known {
        Some("1") => (true, Some("1")),
        _ => (false, Some("0")),
    }
}

/// A `padding` header value: 30 to 62 random symbols, never indexed.
fn padding_header() -> HeaderValue {
    let mut random = [0u8; 63];
    let _ = SystemRandom::new().fill(&mut random);
    let len = 30 + usize::from(random[0] % 33);
    let filler: Vec<u8> = random[1..=len]
        .iter()
        .map(|byte| PADDING_SYMBOLS[usize::from(*byte) % PADDING_SYMBOLS.len()])
        .collect();
    let mut value = HeaderValue::from_bytes(&filler).expect("padding symbols are visible ASCII");
    value.set_sensitive(true);
    value
}

fn status(code: StatusCode) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = code;
    response
}

/// Copies the data and trailers that follow a message head to `to`, within
/// flow control; nothing follows a head that `ended` its stream.
async fn pipe(
    mut from: RecvStream,
    mut to: SendStream<Bytes>,
    ended: bool,
) -> Result<(), h2::Error> {
    if ended {
        return Ok(());
    }
    while let Some(chunk) = from.data().await {
        let mut chunk = chunk?;
        let len = chunk.len();
        while !chunk.is_empty() {
            to.reserve_capacity(chunk.len().min(MAX_WRITE));
            while to.capacity() == 0 {
                match poll_fn(|cx| to.poll_capacity(cx)).await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    // The receiver closed the stream.
                    None => return Ok(()),
                }
            }
            let n = to.capacity().min(chunk.len());
            to.send_data(chunk.split_to(n), false)?;
        }
        let _ = from.flow_control().release_capacity(len);
    }
    match from.trailers().await? {
        Some(trailers) => to.send_trailers(trailers),
        None => to.send_data(Bytes::new(), true),
    }
}

/// The body of a `CONNECT` stream as a byte stream, within flow control.
struct Tunnel {
    recv: RecvStream,
    send: SendStream<Bytes>,
    /// Received data not yet read.
    chunk: Bytes,
    eof: bool,
    shut: bool,
}

impl Tunnel {
    fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            chunk: Bytes::new(),
            eof: false,
            shut: false,
        }
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.chunk.is_empty() {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    let _ = this.recv.flow_control().release_capacity(chunk.len());
                    this.chunk = chunk;
                }
                Some(Err(error)) if error.reason() == Some(h2::Reason::NO_ERROR) => {
                    this.eof = true;
                }
                Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                None => this.eof = true,
            }
        }
        let n = this.chunk.len().min(buf.remaining());
        buf.put_slice(&this.chunk.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shut {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len().min(MAX_WRITE));
        while this.send.capacity() == 0 {
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = this.send.capacity().min(buf.len());
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(h2_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data is with the HTTP/2 connection once written.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shut {
            this.shut = true;
            this.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        }
        Poll::Ready(Ok(()))
    }
}

fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        return error.into_io().expect("is_io");
    }
    io::Error::other(error)
}

impl StreamInbound for NaiveInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async { Err(Rejected::close("naive serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.serve(stream, context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|&(name, value)| {
                (
                    http::HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                )
            })
            .collect()
    }

    #[test]
    fn padding_is_negotiated_by_the_request_headers() {
        let preferred = headers(&[("padding", "~~"), ("padding-type-request", "1, 0")]);
        assert_eq!(padding_type(&preferred), (true, Some("1")));
        let unknown_first = headers(&[("padding-type-request", "2,1,0")]);
        assert_eq!(padding_type(&unknown_first), (true, Some("1")));
        let none = headers(&[("padding", "~~"), ("padding-type-request", "0, 1")]);
        assert_eq!(padding_type(&none), (false, Some("0")));
        let unknown = headers(&[("padding-type-request", "7")]);
        assert_eq!(padding_type(&unknown), (false, Some("0")));
        // Clients from before the type headers.
        assert_eq!(padding_type(&headers(&[("padding", "~~")])), (true, None));
        assert_eq!(padding_type(&headers(&[])), (false, None));
    }

    #[test]
    fn padding_headers_vary_in_length() {
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..200 {
            let value = padding_header();
            assert!((30..=62).contains(&value.len()), "{}", value.len());
            assert!(value.is_sensitive());
            assert!(value
                .as_bytes()
                .iter()
                .all(|byte| PADDING_SYMBOLS.contains(byte)));
            lengths.insert(value.len());
        }
        assert!(lengths.len() > 10, "{lengths:?}");
    }

    #[test]
    fn users_log_in_with_their_username_or_name() {
        let mut user = User::with_password("1001", "secret");
        // base64("1001:secret")
        assert_eq!(basic_token(&user).as_deref(), Some("MTAwMTpzZWNyZXQ="));
        user.username = Some("alice".into());
        // base64("alice:secret")
        assert_eq!(basic_token(&user).as_deref(), Some("YWxpY2U6c2VjcmV0"));
        assert_eq!(basic_token(&User::with_uuid("1002", "uuid")), None);

        let inbound = NaiveInbound::new(None);
        assert!(inbound
            .users()
            .add(User::with_uuid("1002", "uuid"))
            .is_err());
        inbound.users().add(user).unwrap();
        assert!(inbound.index.get(&"YWxpY2U6c2VjcmV0".to_owned()).is_some());
        assert!(inbound.index.get(&"MTAwMTpzZWNyZXQ=".to_owned()).is_none());
    }
}
