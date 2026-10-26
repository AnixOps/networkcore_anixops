//! XHTTP server side for inbound protocol crates (docs/protocols/xhttp.md).
//!
//! [`XhttpServer::serve_connection`] serves one accepted connection (plain
//! TCP or TLS) as HTTP/2 when it starts with the HTTP/2 preface, otherwise
//! as HTTP/1.1. Every download `GET {path}{session}` and every
//! `POST {path}` (`stream-one`) becomes one proxied stream handed to the
//! caller; uploads (`POST {path}{session}/{seq}` or a streaming
//! `POST {path}{session}`) feed the session's upload side. A session's
//! requests may arrive on different connections, so sessions live in the
//! server, and a session whose download does not arrive in time is dropped.

use std::collections::{BTreeMap, HashMap};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use engine_outbound::{BoxFuture, BoxStream};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::mpsc;

use crate::settings::{invalid, Mode, Range, XhttpSettings};
use crate::{h1, h2_error, next_chunk, CONNECTION_WINDOW, STREAM_WINDOW};

/// Most requests open at once on one HTTP/2 connection.
pub const MAX_CONCURRENT_STREAMS: u32 = 256;
/// Uploads a session may hold ahead of the next one in order.
pub const MAX_BUFFERED_POSTS: usize = 30;
/// Sessions waiting for their download at once.
pub const MAX_SESSIONS: usize = 4096;
/// How long a session waits for its download `GET`.
const SESSION_WAIT: Duration = Duration::from_secs(30);
/// Idle time allowed between requests on an HTTP/1.1 connection.
const H1_IDLE: Duration = Duration::from_secs(300);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Largest DATA frame or HTTP/1.1 chunk written for the download.
const MAX_WRITE: usize = 64 * 1024;

/// Serves XHTTP for one inbound; shared by all its connections.
pub struct XhttpServer {
    path: String,
    host: String,
    mode: Mode,
    padding: Range,
    max_post: usize,
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

struct SessionEntry {
    session: Arc<Session>,
    /// Taken by the download; `None` once it arrived.
    upload: Option<mpsc::Receiver<Bytes>>,
}

/// The upload side of a session: uploads in `seq` order, or one stream.
struct Session {
    order: tokio::sync::Mutex<Order>,
}

struct Order {
    next: u64,
    pending: BTreeMap<u64, Bytes>,
    /// `None` once a streaming upload ended.
    tx: Option<mpsc::Sender<Bytes>>,
}

/// Where a request goes.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Reject(u16),
    /// `GET {path}{session}`.
    Download(String),
    /// `POST {path}`.
    StreamOne,
    /// `POST {path}{session}`.
    StreamUp(String),
    /// `POST {path}{session}/{seq}`.
    Packet(String, u64),
}

impl XhttpServer {
    pub fn new(settings: &XhttpSettings) -> io::Result<Arc<Self>> {
        settings.validate()?;
        if !settings.query().is_empty() {
            return Err(invalid("xhttp server path takes no query"));
        }
        Ok(Arc::new(Self {
            path: settings.normalized_path(),
            host: settings.host.clone(),
            mode: settings.mode,
            padding: settings.x_padding_bytes,
            max_post: settings.sc_max_each_post_bytes.to as usize,
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// Serves `stream` until the client closes it, handing every proxied
    /// stream to `call` and running the returned futures on this task.
    pub async fn serve_connection<'a, F>(
        self: &Arc<Self>,
        stream: BoxStream,
        handshake_timeout: Duration,
        call: F,
    ) -> io::Result<()>
    where
        F: FnMut(BoxStream) -> BoxFuture<'a, ()>,
    {
        let (stream, h2) = tokio::time::timeout(handshake_timeout, sniff(stream))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if h2 {
            self.serve_h2(stream, handshake_timeout, call).await
        } else {
            self.serve_h1(stream, handshake_timeout, call).await
        }
    }

    fn route(
        &self,
        method: &str,
        host: Option<&str>,
        path: &str,
        query: Option<&str>,
        referer: Option<&str>,
    ) -> Route {
        if !self.host.is_empty() && !host.is_some_and(|host| same_host(host, &self.host)) {
            return Route::Reject(404);
        }
        let Some(rest) = path.strip_prefix(self.path.as_str()) else {
            return Route::Reject(404);
        };
        let padding = match referer.filter(|referer| !referer.is_empty()) {
            Some(referer) => referer
                .split('#')
                .next()
                .and_then(|referer| referer.split_once('?'))
                .map_or(0, |(_, query)| padding_len(query)),
            None => query.map_or(0, padding_len),
        };
        if !self.padding.contains(padding) {
            return Route::Reject(400);
        }
        let mut parts = rest.split('/');
        let session = parts.next().unwrap_or_default();
        let seq = parts.next().unwrap_or_default();
        if parts.next().is_some_and(|extra| !extra.is_empty())
            || session.len() > 64
            || !session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Route::Reject(400);
        }
        let allowed = |mode: Mode| self.mode == Mode::Auto || self.mode == mode;
        match (method, session.is_empty(), seq.is_empty()) {
            ("GET", false, true) if allowed(Mode::PacketUp) || allowed(Mode::StreamUp) => {
                Route::Download(session.to_owned())
            }
            ("POST", true, true) if allowed(Mode::StreamOne) => Route::StreamOne,
            ("POST", false, true) if allowed(Mode::StreamUp) => Route::StreamUp(session.to_owned()),
            ("POST", false, false) if allowed(Mode::PacketUp) => match seq.parse() {
                Ok(seq) => Route::Packet(session.to_owned(), seq),
                Err(_) => Route::Reject(400),
            },
            ("GET", true, _) => Route::Reject(404),
            ("GET" | "POST", _, _) => Route::Reject(400),
            _ => Route::Reject(405),
        }
    }

    /// The session `id`, created when new; `None` when the table is full.
    fn session(self: &Arc<Self>, id: &str) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = sessions.get(id) {
            return Some(entry.session.clone());
        }
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let (tx, rx) = mpsc::channel(MAX_BUFFERED_POSTS);
        let session = Arc::new(Session {
            order: tokio::sync::Mutex::new(Order {
                next: 0,
                pending: BTreeMap::new(),
                tx: Some(tx),
            }),
        });
        sessions.insert(
            id.to_owned(),
            SessionEntry {
                session: session.clone(),
                upload: Some(rx),
            },
        );
        let server = Arc::downgrade(self);
        let id = id.to_owned();
        tokio::spawn(async move {
            tokio::time::sleep(SESSION_WAIT).await;
            reap(server, &id);
        });
        Some(session)
    }

    /// Takes the upload side of session `id` for its download.
    fn take_upload(self: &Arc<Self>, id: &str) -> Option<mpsc::Receiver<Bytes>> {
        self.session(id)?;
        let mut sessions = self.sessions.lock().unwrap_or_else(|err| err.into_inner());
        sessions.get_mut(id)?.upload.take()
    }

    fn remove(&self, id: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|err| err.into_inner());
        sessions.remove(id);
    }

    fn padding_header(&self) -> String {
        "X".repeat(self.padding.sample() as usize)
    }

    /// Wraps a proxied stream's future so the session ends with it.
    fn finish_with<'a>(
        self: &Arc<Self>,
        call: BoxFuture<'a, ()>,
        session: Option<String>,
    ) -> BoxFuture<'a, ()> {
        let Some(id) = session else {
            return call;
        };
        let server = self.clone();
        Box::pin(async move {
            call.await;
            server.remove(&id);
        })
    }

    async fn serve_h2<'a, F>(
        self: &Arc<Self>,
        stream: Prefixed,
        handshake_timeout: Duration,
        mut call: F,
    ) -> io::Result<()>
    where
        F: FnMut(BoxStream) -> BoxFuture<'a, ()>,
    {
        let handshake = h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .handshake::<_, Bytes>(stream);
        let mut connection = tokio::time::timeout(handshake_timeout, handshake)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(h2_error)?;
        let mut calls: Vec<BoxFuture<'a, ()>> = Vec::new();
        let mut accepting = true;
        poll_fn(|cx| {
            calls.retain_mut(|call| call.as_mut().poll(cx).is_pending());
            while accepting {
                match connection.poll_accept(cx) {
                    Poll::Ready(Some(Ok((request, respond)))) => {
                        if let Some((stream, session)) = self.accept_h2(request, respond) {
                            let mut future = self.finish_with(call(stream), session);
                            if future.as_mut().poll(cx).is_pending() {
                                calls.push(future);
                            }
                        }
                    }
                    Poll::Ready(Some(Err(_)) | None) => accepting = false,
                    Poll::Pending => break,
                }
            }
            if accepting {
                return Poll::Pending;
            }
            // No new requests; keep the connection's I/O going for the open
            // streams.
            if calls.is_empty() || connection.poll_closed(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            Poll::Pending
        })
        .await
    }

    /// Answers one HTTP/2 request; a proxied stream (and its session) for a
    /// download or `stream-one`, uploads run on their own tasks.
    fn accept_h2(
        self: &Arc<Self>,
        request: http::Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> Option<(BoxStream, Option<String>)> {
        let host = request.uri().authority().map(|a| a.as_str()).or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        });
        let referer = request
            .headers()
            .get(http::header::REFERER)
            .and_then(|value| value.to_str().ok());
        let route = self.route(
            request.method().as_str(),
            host,
            request.uri().path(),
            request.uri().query(),
            referer,
        );
        match route {
            Route::Reject(status) => {
                let _ = respond.send_response(self.h2_status(status), true);
                None
            }
            Route::Download(id) => {
                let Some(upload) = self.take_upload(&id) else {
                    let _ = respond.send_response(self.h2_status(409), true);
                    return None;
                };
                let send = respond.send_response(self.h2_download(), false).ok()?;
                let stream = Joined {
                    reader: UploadReader::new(upload),
                    writer: H2Writer::new(send),
                };
                Some((Box::new(stream), Some(id)))
            }
            Route::StreamOne => {
                let send = respond.send_response(self.h2_download(), false).ok()?;
                let stream = Joined {
                    reader: BodyReader::new(request.into_body()),
                    writer: H2Writer::new(send),
                };
                Some((Box::new(stream), None))
            }
            Route::StreamUp(id) => {
                let Some(session) = self.session(&id) else {
                    let _ = respond.send_response(self.h2_status(503), true);
                    return None;
                };
                let response = self.h2_status(200);
                tokio::spawn(async move {
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };
                    let mut body = request.into_body();
                    while let Ok(Some(chunk)) = next_chunk(&mut body).await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if session.push_stream(chunk).await.is_err() {
                            break;
                        }
                    }
                    session.finish().await;
                    let _ = send.send_data(Bytes::new(), true);
                });
                None
            }
            Route::Packet(id, seq) => {
                let Some(session) = self.session(&id) else {
                    let _ = respond.send_response(self.h2_status(503), true);
                    return None;
                };
                let server = self.clone();
                tokio::spawn(async move {
                    let status = match read_h2_body(request.into_body(), server.max_post).await {
                        Ok(Some(body)) => match session.push_packet(seq, body).await {
                            Ok(()) => 200,
                            Err(_) => 500,
                        },
                        Ok(None) => 413,
                        Err(_) => return,
                    };
                    let _ = respond.send_response(server.h2_status(status), true);
                });
                None
            }
        }
    }

    fn h2_status(&self, status: u16) -> http::Response<()> {
        let mut response = http::Response::new(());
        *response.status_mut() =
            http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_REQUEST);
        if let Ok(padding) = http::HeaderValue::from_str(&self.padding_header()) {
            response.headers_mut().insert("x-padding", padding);
        }
        response
    }

    fn h2_download(&self) -> http::Response<()> {
        let mut response = self.h2_status(200);
        let headers = response.headers_mut();
        headers.insert("x-accel-buffering", http::HeaderValue::from_static("no"));
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        response
    }

    async fn serve_h1<'a, F>(
        self: &Arc<Self>,
        stream: Prefixed,
        handshake_timeout: Duration,
        mut call: F,
    ) -> io::Result<()>
    where
        F: FnMut(BoxStream) -> BoxFuture<'a, ()>,
    {
        let mut reader = BufReader::new(stream);
        let mut first = true;
        loop {
            let wait = if first { handshake_timeout } else { H1_IDLE };
            let request = match tokio::time::timeout(wait, h1::read_request(&mut reader)).await {
                Ok(Ok(Some(request))) => request,
                Ok(Ok(None)) if !first => return Ok(()),
                Ok(Ok(None)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Err(err)) => return if first { Err(err) } else { Ok(()) },
                Err(_) if first => return Err(io::ErrorKind::TimedOut.into()),
                Err(_) => return Ok(()),
            };
            first = false;
            let (path, query) = match request.target.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (request.target.as_str(), None),
            };
            let route = self.route(
                &request.method,
                request.host.as_deref(),
                path,
                query,
                request.referer.as_deref(),
            );
            match route {
                Route::Reject(status) => {
                    return self.h1_status(reader.get_mut(), status, true).await;
                }
                Route::StreamOne | Route::StreamUp(_) => {
                    // Streaming uploads need HTTP/2 in this implementation.
                    return self.h1_status(reader.get_mut(), 400, true).await;
                }
                Route::Download(id) => {
                    let Some(upload) = self.take_upload(&id) else {
                        return self.h1_status(reader.get_mut(), 409, true).await;
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\n\
                         Content-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\
                         X-Padding: {}\r\n\r\n",
                        self.padding_header()
                    );
                    reader.get_mut().write_all(head.as_bytes()).await?;
                    reader.get_mut().flush().await?;
                    // The client sends nothing more on this connection.
                    let stream = Joined {
                        reader: UploadReader::new(upload),
                        writer: ChunkedWriter::new(reader.into_inner()),
                    };
                    self.finish_with(call(Box::new(stream)), Some(id)).await;
                    return Ok(());
                }
                Route::Packet(id, seq) => {
                    let Some(body) =
                        h1::read_body_limited(&mut reader, &request.body, self.max_post).await?
                    else {
                        return self.h1_status(reader.get_mut(), 413, true).await;
                    };
                    let status = match self.session(&id) {
                        Some(session) => match session.push_packet(seq, body.into()).await {
                            Ok(()) => 200,
                            Err(_) => 500,
                        },
                        None => 503,
                    };
                    let close = status != 200 || request.body.close;
                    self.h1_status(reader.get_mut(), status, close).await?;
                    if close {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn h1_status<W: AsyncWrite + Unpin>(
        &self,
        out: &mut W,
        status: u16,
        close: bool,
    ) -> io::Result<()> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            413 => "Payload Too Large",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        let connection = if close { "Connection: close\r\n" } else { "" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nX-Padding: {}\r\n{connection}\r\n",
            self.padding_header()
        );
        out.write_all(response.as_bytes()).await?;
        out.flush().await
    }
}

/// Drops session `id` if its download never came.
fn reap(server: Weak<XhttpServer>, id: &str) {
    let Some(server) = server.upgrade() else {
        return;
    };
    let mut sessions = server
        .sessions
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    if sessions.get(id).is_some_and(|entry| entry.upload.is_some()) {
        sessions.remove(id);
    }
}

impl Session {
    /// Queues upload `seq` and passes on every upload now in order. Waits
    /// while the download side is behind.
    async fn push_packet(&self, seq: u64, data: Bytes) -> io::Result<()> {
        let mut order = self.order.lock().await;
        if seq < order.next {
            return Ok(());
        }
        if seq - order.next >= MAX_BUFFERED_POSTS as u64 {
            return Err(io::Error::other("xhttp upload is too far ahead"));
        }
        order.pending.insert(seq, data);
        loop {
            let next = order.next;
            let Some(data) = order.pending.remove(&next) else {
                return Ok(());
            };
            order.next += 1;
            let tx = order.tx.clone().ok_or(io::ErrorKind::BrokenPipe)?;
            if !data.is_empty() {
                tx.send(data)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            }
        }
    }

    async fn push_stream(&self, data: Bytes) -> io::Result<()> {
        let order = self.order.lock().await;
        let tx = order.tx.clone().ok_or(io::ErrorKind::BrokenPipe)?;
        tx.send(data)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// Ends the upload side after a streaming upload.
    async fn finish(&self) {
        self.order.lock().await.tx = None;
    }
}

/// `Ok(None)` when the body is larger than `limit`.
async fn read_h2_body(mut body: RecvStream, limit: usize) -> io::Result<Option<Bytes>> {
    let mut data = BytesMut::new();
    while let Some(chunk) = next_chunk(&mut body).await? {
        let _ = body.flow_control().release_capacity(chunk.len());
        if data.len() + chunk.len() > limit {
            return Ok(None);
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Some(data.freeze()))
}

/// The length of the `x_padding` value in a query string.
fn padding_len(query: &str) -> usize {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("x_padding="))
        .map_or(0, str::len)
}

/// Compares hosts without their ports, ignoring case.
fn same_host(request: &str, expected: &str) -> bool {
    fn strip(host: &str) -> &str {
        if let Some(rest) = host.strip_prefix('[') {
            return rest.split(']').next().unwrap_or_default();
        }
        match host.rsplit_once(':') {
            Some((name, port))
                if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                name
            }
            _ => host,
        }
    }
    strip(request).eq_ignore_ascii_case(strip(expected))
}

/// Reads until the bytes either are the HTTP/2 preface or cannot be.
async fn sniff(mut stream: BoxStream) -> io::Result<(Prefixed, bool)> {
    let mut prefix = Vec::with_capacity(H2_PREFACE.len());
    let mut buf = [0u8; 24];
    while prefix.len() < H2_PREFACE.len() && H2_PREFACE.starts_with(&prefix) {
        let read = stream
            .read(&mut buf[..H2_PREFACE.len() - prefix.len()])
            .await?;
        if read == 0 {
            break;
        }
        prefix.extend_from_slice(&buf[..read]);
    }
    let h2 = prefix == H2_PREFACE;
    Ok((
        Prefixed {
            prefix: prefix.into(),
            inner: stream,
        },
        h2,
    ))
}

/// A stream with bytes already read from it put back in front.
struct Prefixed {
    prefix: Bytes,
    inner: BoxStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A proxied stream made of separate read and write sides.
struct Joined<R, W> {
    reader: R,
    writer: W,
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Joined<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Joined<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// The session's uploads, in order.
struct UploadReader {
    rx: mpsc::Receiver<Bytes>,
    current: Bytes,
}

impl UploadReader {
    fn new(rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            rx,
            current: Bytes::new(),
        }
    }
}

impl AsyncRead for UploadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.current.is_empty() {
            match ready!(self.rx.poll_recv(cx)) {
                Some(data) => self.current = data,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = self.current.len().min(buf.remaining());
        buf.put_slice(&self.current[..n]);
        self.current.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// An HTTP/2 request body (`stream-one`).
struct BodyReader {
    body: RecvStream,
    current: Bytes,
    eof: bool,
}

impl BodyReader {
    fn new(body: RecvStream) -> Self {
        Self {
            body,
            current: Bytes::new(),
            eof: false,
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.current.is_empty() {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.body.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    let _ = this.body.flow_control().release_capacity(chunk.len());
                    this.current = chunk;
                }
                Some(Err(err)) if err.reason() == Some(h2::Reason::NO_ERROR) => this.eof = true,
                Some(Err(err)) => return Poll::Ready(Err(h2_error(err))),
                None => this.eof = true,
            }
        }
        let n = this.current.len().min(buf.remaining());
        buf.put_slice(&this.current[..n]);
        this.current.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// An HTTP/2 response body as a byte sink, within flow control.
struct H2Writer {
    send: SendStream<Bytes>,
    shut: bool,
}

impl H2Writer {
    fn new(send: SendStream<Bytes>) -> Self {
        Self { send, shut: false }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
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
                Some(Err(err)) => return Poll::Ready(Err(h2_error(err))),
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shut {
            self.shut = true;
            self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        }
        Poll::Ready(Ok(()))
    }
}

/// An HTTP/1.1 chunked response body as a byte sink.
struct ChunkedWriter<W> {
    inner: W,
    /// Encoded bytes not yet written to `inner`.
    pending: BytesMut,
    finishing: bool,
}

impl<W: AsyncWrite + Unpin> ChunkedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            pending: BytesMut::new(),
            finishing: false,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.finishing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_WRITE);
        this.pending
            .extend_from_slice(format!("{n:x}\r\n").as_bytes());
        this.pending.extend_from_slice(&buf[..n]);
        this.pending.extend_from_slice(b"\r\n");
        // The chunk is accepted; what does not go out now goes with the next
        // write or flush.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.finishing {
            this.finishing = true;
            this.pending.extend_from_slice(b"0\r\n\r\n");
        }
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(mode: Mode, host: &str) -> Arc<XhttpServer> {
        XhttpServer::new(&XhttpSettings {
            path: "/xh".into(),
            host: host.into(),
            mode,
            ..XhttpSettings::default()
        })
        .unwrap()
    }

    #[test]
    fn requests_are_routed_like_xray() {
        let server = server(Mode::Auto, "");
        let pad = format!("x_padding={}", "X".repeat(200));
        let referer = format!("https://a.example/xh/s?{pad}");
        let route = |method, path, query: Option<&str>, referer: Option<&str>| {
            server.route(method, Some("a.example"), path, query, referer)
        };
        assert_eq!(
            route("GET", "/xh/s1", None, Some(referer.as_str())),
            Route::Download("s1".into())
        );
        assert_eq!(
            route("POST", "/xh/s1/7", Some(pad.as_str()), None),
            Route::Packet("s1".into(), 7)
        );
        assert_eq!(
            route("POST", "/xh/s1", Some(pad.as_str()), None),
            Route::StreamUp("s1".into())
        );
        assert_eq!(
            route("POST", "/xh/", Some(pad.as_str()), None),
            Route::StreamOne
        );
        assert_eq!(
            route("GET", "/other/s1", Some(pad.as_str()), None),
            Route::Reject(404)
        );
        assert_eq!(route("GET", "/xh/s1", None, None), Route::Reject(400));
        assert_eq!(
            route("GET", "/xh/s1", Some("x_padding=XX"), None),
            Route::Reject(400)
        );
        assert_eq!(
            route("POST", "/xh/s1/x", Some(pad.as_str()), None),
            Route::Reject(400)
        );
        assert_eq!(
            route("PUT", "/xh/s1", Some(pad.as_str()), None),
            Route::Reject(405)
        );
        assert_eq!(
            route("GET", "/xh/a%2f", Some(pad.as_str()), None),
            Route::Reject(400)
        );

        let packet_only = self::server(Mode::PacketUp, "a.example");
        assert_eq!(
            packet_only.route(
                "POST",
                Some("A.example:443"),
                "/xh/",
                Some(pad.as_str()),
                None
            ),
            Route::Reject(400)
        );
        assert_eq!(
            packet_only.route("GET", Some("b.example"), "/xh/s", Some(pad.as_str()), None),
            Route::Reject(404)
        );
        assert_eq!(
            packet_only.route("GET", None, "/xh/s", Some(pad.as_str()), None),
            Route::Reject(404)
        );
    }

    #[tokio::test]
    async fn uploads_come_out_in_order() {
        let server = server(Mode::Auto, "");
        let session = server.session("s").unwrap();
        let mut upload = UploadReader::new(server.take_upload("s").unwrap());
        assert!(
            server.take_upload("s").is_none(),
            "one download per session"
        );
        session
            .push_packet(1, Bytes::from_static(b"world"))
            .await
            .unwrap();
        session
            .push_packet(0, Bytes::from_static(b"hello "))
            .await
            .unwrap();
        session
            .push_packet(0, Bytes::from_static(b"again"))
            .await
            .unwrap();
        assert!(session
            .push_packet(2 + MAX_BUFFERED_POSTS as u64, Bytes::from_static(b"x"))
            .await
            .is_err());
        let mut text = [0u8; 11];
        upload.read_exact(&mut text).await.unwrap();
        assert_eq!(&text, b"hello world");
        session.finish().await;
        server.remove("s");
        drop(session);
        let mut rest = Vec::new();
        upload.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn hosts_compare_without_ports() {
        assert!(same_host("A.example:8443", "a.example"));
        assert!(same_host("[::1]:443", "::1"));
        assert!(!same_host("b.example", "a.example"));
    }

    #[tokio::test]
    async fn chunked_writer_frames_and_finishes() {
        let mut writer = ChunkedWriter::new(Vec::new());
        writer.write_all(b"abc").await.unwrap();
        writer.write_all(&[7u8; 20]).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut expected = b"3\r\nabc\r\n14\r\n".to_vec();
        expected.extend_from_slice(&[7u8; 20]);
        expected.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(writer.inner, expected);
    }
}
