//! XHTTP client transport: Xray-core's "SplitHTTP", wire compatible with its
//! servers, written from the public documentation (docs/protocols/xhttp.md).
//!
//! A proxied stream becomes ordinary HTTP requests. The download is the body
//! of one streaming response; the upload is, by [`Mode`]:
//!
//! * `packet-up`: numbered `POST {path}{session}/{seq}` requests, which the
//!   server puts back in order (HTTP/1.1 or HTTP/2);
//! * `stream-up`: one streaming `POST {path}{session}` (HTTP/2);
//! * `stream-one`: the request body of the same `POST {path}` whose response
//!   is the download (HTTP/2).
//!
//! Every request carries random padding in its `Referer` query
//! (`x_padding`), which the server checks against its range.
//!
//! [`XhttpConnector`] dials (and runs TLS) itself, because `packet-up` over
//! HTTP/1.1 needs a second connection for the uploads. Over HTTP/2 every
//! proxied stream uses its own connection, as over HTTP/3 (QUIC, see
//! [`Security::Quic`]). [`server::XhttpServer`] is the server side (HTTP/1.1
//! and HTTP/2).

mod h1;
mod http3;
pub mod server;
mod settings;

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use engine_outbound::{BoxFuture, BoxStream, Dialer};
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf, ReadHalf,
    WriteHalf,
};
use tokio::sync::watch;
use tokio::time::Instant;
use transport_quic::{Congestion, QuicConnector};
use transport_tls::{TlsConnector, TlsSettings};

use settings::invalid;
pub use settings::{
    session_id, Mode, Range, XhttpSettings, DEFAULT_MAX_EACH_POST_BYTES,
    DEFAULT_MIN_POSTS_INTERVAL_MS, DEFAULT_PADDING_BYTES, MIN_EACH_POST_BYTES,
};

/// `User-Agent` unless `headers` sets one.
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const STREAM_WINDOW: u32 = 1024 * 1024;
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
/// Bytes buffered between the proxied stream and the HTTP side in each
/// direction for the streaming modes; `packet-up` buffers one upload.
const STREAM_PIPE: usize = 256 * 1024;
const STREAM_CHUNK: usize = 32 * 1024;
/// First `packet-up` read buffer; it doubles while uploads fill it.
const FIRST_UPLOAD: usize = 16 * 1024;

/// The HTTP version of the requests, chosen from the TLS ALPN as Xray does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
    Http2,
    /// Over QUIC; the target's security must be [`Security::Quic`].
    Http3,
}

impl HttpVersion {
    /// No TLS: HTTP/1.1. TLS with exactly `http/1.1`: HTTP/1.1; exactly
    /// `h3`: HTTP/3. Otherwise HTTP/2, so a caller with an empty ALPN list
    /// should offer `h2`.
    pub fn select(tls_alpn: Option<&[String]>) -> io::Result<Self> {
        match tls_alpn {
            None => Ok(Self::Http11),
            Some([only]) if only == "http/1.1" => Ok(Self::Http11),
            Some([only]) if only == "h3" => Ok(Self::Http3),
            Some(_) => Ok(Self::Http2),
        }
    }
}

/// Where and how the connector reaches the server.
pub struct XhttpTarget {
    pub server: String,
    pub port: u16,
    /// The host used when the settings name none: the TLS server name or
    /// the server address.
    pub default_host: String,
    /// The layer over every connection.
    pub security: Security,
    pub version: HttpVersion,
    pub dialer: Arc<dyn Dialer>,
}

/// What runs over each connection before HTTP.
#[derive(Clone)]
pub enum Security {
    /// Plain HTTP.
    None,
    Tls(TlsConnector),
    /// Another handshake, such as REALITY; HTTP runs as `https`.
    Custom(Arc<dyn Handshake>),
    /// QUIC for HTTP/3; the dialer is not used.
    Quic(Arc<QuicConnector>),
}

impl Security {
    /// QUIC to `server` with `tls`, offering ALPN `h3`.
    pub fn quic(server: &str, port: u16, tls: &TlsSettings) -> io::Result<Self> {
        let mut tls = tls.clone();
        tls.alpn = vec!["h3".to_owned()];
        let connector = QuicConnector::new(server, port, &tls, &[], Congestion::default())?;
        Ok(Self::Quic(Arc::new(connector)))
    }
}

/// A secure layer that is not standard TLS.
pub trait Handshake: Send + Sync {
    fn handshake(&self, stream: BoxStream) -> BoxFuture<'_, io::Result<BoxStream>>;
}

/// Opens XHTTP sessions to one server.
#[derive(Clone)]
pub struct XhttpConnector {
    inner: Arc<Inner>,
}

struct Inner {
    server: String,
    port: u16,
    security: Security,
    dialer: Arc<dyn Dialer>,
    version: HttpVersion,
    mode: Mode,
    scheme: &'static str,
    authority: String,
    path: String,
    query: String,
    headers: Vec<(http::HeaderName, http::HeaderValue)>,
    padding: Range,
    max_post: Range,
    post_interval: Range,
    grpc_header: bool,
}

impl XhttpConnector {
    pub fn new(settings: &XhttpSettings, target: XhttpTarget) -> io::Result<Self> {
        settings.validate()?;
        if target.server.is_empty() || target.port == 0 {
            return Err(invalid("xhttp server address is empty"));
        }
        let mode = match settings.mode {
            Mode::Auto => Mode::PacketUp,
            mode => mode,
        };
        if target.version == HttpVersion::Http11 && mode != Mode::PacketUp {
            return Err(invalid("xhttp stream-up and stream-one need HTTP/2"));
        }
        if (target.version == HttpVersion::Http3) != matches!(target.security, Security::Quic(_)) {
            return Err(invalid(
                "xhttp over http/3 needs quic and quic needs http/3",
            ));
        }
        let secure = !matches!(target.security, Security::None);
        let scheme = if secure { "https" } else { "http" };
        let mut headers = Vec::new();
        let mut header_host = None;
        for (name, value) in &settings.headers {
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid("xhttp header name is invalid"))?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|_| invalid("xhttp header value is invalid"))?;
            if name == http::header::HOST {
                header_host = Some(value.to_str().unwrap_or_default().to_owned());
            } else if !matches!(
                name,
                http::header::CONTENT_LENGTH
                    | http::header::TRANSFER_ENCODING
                    | http::header::CONNECTION
                    | http::header::REFERER
            ) {
                headers.push((name, value));
            }
        }
        if !headers
            .iter()
            .any(|(name, _)| name == http::header::USER_AGENT)
        {
            headers.push((
                http::header::USER_AGENT,
                http::HeaderValue::from_static(DEFAULT_USER_AGENT),
            ));
        }
        let default_port = if secure { 443 } else { 80 };
        let authority = if !settings.host.is_empty() {
            settings.host.clone()
        } else if let Some(host) = header_host.filter(|host| !host.is_empty()) {
            host
        } else if target.port == default_port {
            target.default_host.clone()
        } else if target.default_host.contains(':') && !target.default_host.starts_with('[') {
            format!("[{}]:{}", target.default_host, target.port)
        } else {
            format!("{}:{}", target.default_host, target.port)
        };
        let path = settings.normalized_path();
        let probe = format!("{scheme}://{authority}{path}");
        let uri: http::Uri = probe
            .parse()
            .map_err(|_| invalid("xhttp host is invalid"))?;
        if uri.authority().map(|a| a.as_str()) != Some(authority.as_str()) {
            return Err(invalid("xhttp host is invalid"));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                server: target.server,
                port: target.port,
                security: target.security,
                dialer: target.dialer,
                version: target.version,
                mode,
                scheme,
                authority,
                path,
                query: settings.query().to_owned(),
                headers,
                padding: settings.x_padding_bytes,
                max_post: settings.sc_max_each_post_bytes,
                post_interval: settings.sc_min_posts_interval_ms,
                grpc_header: !settings.no_grpc_header,
            }),
        })
    }

    /// The mode in use (`auto` resolved).
    pub fn mode(&self) -> Mode {
        self.inner.mode
    }

    pub fn version(&self) -> HttpVersion {
        self.inner.version
    }

    /// `Host`/`:authority` of every request.
    pub fn authority(&self) -> &str {
        &self.inner.authority
    }

    /// The request target of the download in a session, e.g.
    /// `/xh/<uuid>?q=1`; `stream-one` uses `suffix = ""`.
    pub fn request_target(&self, suffix: &str) -> String {
        self.inner.target(suffix)
    }

    /// Opens one session and returns it as a byte stream. The connection
    /// carrying the download (and for HTTP/2 everything) is established
    /// before this returns; HTTP errors show up as the stream ending.
    pub async fn connect(&self) -> io::Result<BoxStream> {
        let inner = self.inner.clone();
        let pipe = match inner.mode {
            Mode::PacketUp => (inner.max_post.to as usize).max(STREAM_PIPE),
            _ => STREAM_PIPE,
        };
        let (user, tasks) = tokio::io::duplex(pipe);
        let (input, output) = tokio::io::split(tasks);
        let abort = Abort::new();
        match inner.version {
            HttpVersion::Http11 => {
                let session = session_id();
                let mut download = BufReader::new(inner.open().await?);
                let request = inner.h1_request("GET", &inner.target(&session), None);
                download.get_mut().write_all(&request).await?;
                download.get_mut().flush().await?;
                tokio::spawn(run_download(abort.clone(), output, Download::H1(download)));
                let chunker = Chunker::new(&inner, input);
                tokio::spawn(run_upload(
                    abort.clone(),
                    h1_packet_upload(inner, session, chunker),
                ));
            }
            HttpVersion::Http2 => {
                let mut sender = inner.h2_connect().await?;
                match inner.mode {
                    Mode::StreamOne => {
                        let request =
                            inner.h2_request(http::Method::POST, &inner.target(""), None)?;
                        let (response, send) =
                            sender.send_request(request, false).map_err(h2_error)?;
                        tokio::spawn(run_download(abort.clone(), output, Download::H2(response)));
                        tokio::spawn(run_upload(abort.clone(), h2_stream_upload(send, input)));
                    }
                    Mode::StreamUp => {
                        let target = inner.target(&session_id());
                        let request = inner.h2_request(http::Method::GET, &target, None)?;
                        let (response, _) = sender.send_request(request, true).map_err(h2_error)?;
                        tokio::spawn(run_download(abort.clone(), output, Download::H2(response)));
                        let mut sender = sender.ready().await.map_err(h2_error)?;
                        let request = inner.h2_request(http::Method::POST, &target, None)?;
                        let (response, send) =
                            sender.send_request(request, false).map_err(h2_error)?;
                        tokio::spawn(run_upload(abort.clone(), h2_stream_upload(send, input)));
                        // The server may pad this response to keep it alive.
                        tokio::spawn(run_upload(abort.clone(), h2_drain_response(response)));
                    }
                    Mode::PacketUp | Mode::Auto => {
                        let session = session_id();
                        let request =
                            inner.h2_request(http::Method::GET, &inner.target(&session), None)?;
                        let (response, _) = sender.send_request(request, true).map_err(h2_error)?;
                        tokio::spawn(run_download(abort.clone(), output, Download::H2(response)));
                        let chunker = Chunker::new(&inner, input);
                        tokio::spawn(run_upload(
                            abort.clone(),
                            h2_packet_upload(inner, session, sender, chunker),
                        ));
                    }
                }
            }
            HttpVersion::Http3 => {
                let Security::Quic(quic) = &inner.security else {
                    return Err(invalid("xhttp over http/3 needs quic"));
                };
                let mut sender = http3::connect(quic).await?;
                match inner.mode {
                    Mode::StreamOne => {
                        let request =
                            inner.h2_request(http::Method::POST, &inner.target(""), None)?;
                        let (send, recv) = http3::request(&mut sender, request).await?;
                        let download = Download::H3(recv, sender.clone());
                        tokio::spawn(run_download(abort.clone(), output, download));
                        tokio::spawn(run_upload(
                            abort.clone(),
                            http3::stream_upload(send, input, sender),
                        ));
                    }
                    Mode::StreamUp => {
                        let target = inner.target(&session_id());
                        let request = inner.h2_request(http::Method::GET, &target, None)?;
                        let recv = http3::get(&mut sender, request).await?;
                        let download = Download::H3(recv, sender.clone());
                        tokio::spawn(run_download(abort.clone(), output, download));
                        let request = inner.h2_request(http::Method::POST, &target, None)?;
                        let (send, recv) = http3::request(&mut sender, request).await?;
                        tokio::spawn(run_upload(
                            abort.clone(),
                            http3::stream_upload(send, input, sender.clone()),
                        ));
                        tokio::spawn(run_upload(
                            abort.clone(),
                            http3::drain_response(recv, sender),
                        ));
                    }
                    Mode::PacketUp | Mode::Auto => {
                        let session = session_id();
                        let request =
                            inner.h2_request(http::Method::GET, &inner.target(&session), None)?;
                        let recv = http3::get(&mut sender, request).await?;
                        let download = Download::H3(recv, sender.clone());
                        tokio::spawn(run_download(abort.clone(), output, download));
                        let chunker = Chunker::new(&inner, input);
                        tokio::spawn(run_upload(
                            abort.clone(),
                            http3::packet_upload(inner, session, sender, chunker),
                        ));
                    }
                }
            }
        }
        Ok(Box::new(XhttpStream { pipe: user, abort }))
    }
}

impl Inner {
    async fn open(&self) -> io::Result<BoxStream> {
        let stream = self.dialer.dial(&self.server, self.port).await?;
        match &self.security {
            Security::None => Ok(stream),
            Security::Tls(tls) => tls.connect(stream).await,
            Security::Custom(handshake) => handshake.handshake(stream).await,
            Security::Quic(_) => Err(invalid("xhttp over quic does not dial streams")),
        }
    }

    fn target(&self, suffix: &str) -> String {
        let mut target = format!("{}{}", self.path, suffix);
        if !self.query.is_empty() {
            target.push('?');
            target.push_str(&self.query);
        }
        target
    }

    /// `Referer: <scheme>://<host><path>?x_padding=XXX…`; `X` stays one
    /// byte under HPACK's Huffman code, so the length on the wire is random
    /// too.
    fn referer(&self, target: &str) -> String {
        let path = target.split('?').next().unwrap_or_default();
        let padding = self.padding.sample() as usize;
        format!(
            "{}://{}{}?x_padding={}",
            self.scheme,
            self.authority,
            path,
            "X".repeat(padding)
        )
    }

    fn h1_request(&self, method: &str, target: &str, content_length: Option<usize>) -> Vec<u8> {
        let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {}\r\n", self.authority);
        for (name, value) in &self.headers {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(value.to_str().unwrap_or_default());
            head.push_str("\r\n");
        }
        head.push_str("Referer: ");
        head.push_str(&self.referer(target));
        head.push_str("\r\n");
        if let Some(length) = content_length {
            head.push_str(&format!("Content-Length: {length}\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }

    fn h2_request(
        &self,
        method: http::Method,
        target: &str,
        content_length: Option<usize>,
    ) -> io::Result<http::Request<()>> {
        let streaming_post = method == http::Method::POST && content_length.is_none();
        let mut request = http::Request::builder()
            .method(method)
            .uri(format!("{}://{}{}", self.scheme, self.authority, target));
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        request = request.header(http::header::REFERER, self.referer(target));
        if let Some(length) = content_length {
            request = request.header(http::header::CONTENT_LENGTH, length);
        } else if streaming_post && self.grpc_header {
            // Makes CDNs pass the streaming body through unbuffered.
            request = request.header(http::header::CONTENT_TYPE, "application/grpc");
        }
        request
            .body(())
            .map_err(|_| invalid("xhttp request is invalid"))
    }

    async fn h2_connect(&self) -> io::Result<SendRequest<Bytes>> {
        let stream = self.open().await?;
        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(h2_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        send_request.ready().await.map_err(h2_error)
    }
}

/// The proxied stream: one end of a pipe whose other end the download and
/// upload tasks serve. Dropping it stops them.
struct XhttpStream {
    pipe: DuplexStream,
    abort: Abort,
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        self.abort.trigger();
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

/// Ends every task of a session: when the proxied stream is dropped, or when
/// the upload fails (the server lost the session).
#[derive(Clone)]
struct Abort(Arc<watch::Sender<bool>>);

impl Abort {
    fn new() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }

    fn trigger(&self) {
        self.0.send_replace(true);
    }

    async fn run<F: Future<Output = io::Result<()>>>(&self, work: F) -> io::Result<()> {
        let mut aborted = self.0.subscribe();
        tokio::select! {
            result = work => result,
            _ = aborted.wait_for(|aborted| *aborted) => {
                Err(io::ErrorKind::ConnectionAborted.into())
            }
        }
    }
}

/// Where a session's download comes from: the rest of an HTTP/1.1 response
/// on its connection, or an HTTP/2 response.
enum Download {
    H1(BufReader<BoxStream>),
    H2(ResponseFuture),
    /// The sender keeps the HTTP/3 connection open.
    H3(http3::RecvHalf, http3::Sender),
}

/// Runs a download into `output`, then ends the proxied stream's read side.
async fn run_download(abort: Abort, mut output: WriteHalf<DuplexStream>, download: Download) {
    let _ = abort.run(copy_download(download, &mut output)).await;
    let _ = output.shutdown().await;
}

/// Runs an upload; a failure ends the whole session.
async fn run_upload<F: Future<Output = io::Result<()>>>(abort: Abort, work: F) {
    if abort.run(work).await.is_err() {
        abort.trigger();
    }
}

async fn copy_download(download: Download, output: &mut WriteHalf<DuplexStream>) -> io::Result<()> {
    match download {
        Download::H1(mut reader) => {
            let head = h1::read_head(&mut reader).await?;
            if head.status != 200 {
                return Err(rejected(head.status));
            }
            h1::copy_body(&mut reader, &head, output).await
        }
        Download::H2(response) => {
            let response = response.await.map_err(h2_error)?;
            if response.status() != http::StatusCode::OK {
                return Err(rejected(response.status().as_u16()));
            }
            let mut body = response.into_body();
            while let Some(chunk) = next_chunk(&mut body).await? {
                output.write_all(&chunk).await?;
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Ok(())
        }
        Download::H3(mut recv, _sender) => http3::copy_response(&mut recv, output).await,
    }
}

/// Takes what the proxied stream wrote, at most one upload at a time and no
/// more often than the configured interval.
struct Chunker {
    input: ReadHalf<DuplexStream>,
    /// Grows up to `max` while uploads fill it.
    buf: Vec<u8>,
    max: usize,
    interval: Range,
    last: Option<Instant>,
}

impl Chunker {
    fn new(inner: &Inner, input: ReadHalf<DuplexStream>) -> Self {
        let max = inner.max_post.sample() as usize;
        Self {
            input,
            buf: vec![0; FIRST_UPLOAD.min(max)],
            max,
            interval: inner.post_interval,
            last: None,
        }
    }

    /// The next upload body, `None` once the proxied stream shut down.
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        if let Some(last) = self.last {
            let wait = Duration::from_millis(u64::from(self.interval.sample()));
            let elapsed = last.elapsed();
            if wait > elapsed {
                tokio::time::sleep(wait - elapsed).await;
            }
        }
        let read = self.input.read(&mut self.buf).await?;
        if read == 0 {
            return Ok(None);
        }
        self.last = Some(Instant::now());
        let chunk = Bytes::copy_from_slice(&self.buf[..read]);
        if read == self.buf.len() && read < self.max {
            self.buf.resize((read * 2).min(self.max), 0);
        }
        Ok(Some(chunk))
    }
}

async fn h1_packet_upload(
    inner: Arc<Inner>,
    session: String,
    mut chunker: Chunker,
) -> io::Result<()> {
    let mut connection: Option<BufReader<BoxStream>> = None;
    let mut seq = 0u64;
    while let Some(chunk) = chunker.next().await? {
        let mut stream = match connection.take() {
            Some(stream) => stream,
            None => BufReader::new(inner.open().await?),
        };
        let target = inner.target(&format!("{session}/{seq}"));
        let request = inner.h1_request("POST", &target, Some(chunk.len()));
        stream.get_mut().write_all(&request).await?;
        stream.get_mut().write_all(&chunk).await?;
        stream.get_mut().flush().await?;
        let head = h1::read_head(&mut stream).await?;
        if head.status != 200 {
            return Err(rejected(head.status));
        }
        h1::copy_body(&mut stream, &head, &mut tokio::io::sink()).await?;
        if !head.close {
            connection = Some(stream);
        }
        seq += 1;
    }
    Ok(())
}

async fn h2_packet_upload(
    inner: Arc<Inner>,
    session: String,
    mut sender: SendRequest<Bytes>,
    mut chunker: Chunker,
) -> io::Result<()> {
    let mut seq = 0u64;
    while let Some(chunk) = chunker.next().await? {
        let target = inner.target(&format!("{session}/{seq}"));
        let request = inner.h2_request(http::Method::POST, &target, Some(chunk.len()))?;
        sender = sender.ready().await.map_err(h2_error)?;
        let (response, mut send) = sender.send_request(request, false).map_err(h2_error)?;
        send_all(&mut send, chunk).await?;
        send.send_data(Bytes::new(), true).map_err(h2_error)?;
        h2_drain_response(response).await?;
        seq += 1;
    }
    Ok(())
}

async fn h2_stream_upload(
    mut send: SendStream<Bytes>,
    mut input: ReadHalf<DuplexStream>,
) -> io::Result<()> {
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let read = input.read(&mut buf).await?;
        if read == 0 {
            return send.send_data(Bytes::new(), true).map_err(h2_error);
        }
        send_all(&mut send, Bytes::copy_from_slice(&buf[..read])).await?;
    }
}

/// Waits for a `200` and reads the body to its end.
async fn h2_drain_response(response: ResponseFuture) -> io::Result<()> {
    let response = response.await.map_err(h2_error)?;
    if response.status() != http::StatusCode::OK {
        return Err(rejected(response.status().as_u16()));
    }
    let mut body = response.into_body();
    while let Some(chunk) = next_chunk(&mut body).await? {
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    Ok(())
}

/// The next DATA frame; a reset with `NO_ERROR` after the response counts as
/// the end.
async fn next_chunk(body: &mut RecvStream) -> io::Result<Option<Bytes>> {
    match body.data().await {
        None => Ok(None),
        Some(Ok(chunk)) => Ok(Some(chunk)),
        Some(Err(err)) if err.reason() == Some(h2::Reason::NO_ERROR) => Ok(None),
        Some(Err(err)) => Err(h2_error(err)),
    }
}

/// Sends `data` as the peer's flow control window allows.
async fn send_all(send: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let available = poll_fn(|cx| {
            let capacity = send.capacity();
            if capacity > 0 {
                return Poll::Ready(Ok(capacity));
            }
            match send.poll_capacity(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Ok(_))) => Poll::Ready(Ok(send.capacity())),
                Poll::Ready(Some(Err(err))) => Poll::Ready(Err(h2_error(err))),
                Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        })
        .await?;
        if available == 0 {
            continue;
        }
        let chunk = data.split_to(available.min(data.len()));
        send.send_data(chunk, false).map_err(h2_error)?;
    }
    Ok(())
}

fn rejected(status: u16) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("xhttp server answered {status}"),
    )
}

fn h2_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        return err.into_io().expect("is_io");
    }
    io::Error::other(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TcpDialer;

    fn connector(
        settings: &XhttpSettings,
        port: u16,
        version: HttpVersion,
    ) -> io::Result<XhttpConnector> {
        XhttpConnector::new(
            settings,
            XhttpTarget {
                server: "127.0.0.1".into(),
                port,
                default_host: "edge.example".into(),
                security: Security::None,
                version,
                dialer: Arc::new(TcpDialer),
            },
        )
    }

    #[test]
    fn versions_follow_the_alpn() {
        assert_eq!(HttpVersion::select(None).unwrap(), HttpVersion::Http11);
        let alpn = |list: &[&str]| list.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert_eq!(
            HttpVersion::select(Some(alpn(&["http/1.1"]).as_slice())).unwrap(),
            HttpVersion::Http11
        );
        assert_eq!(
            HttpVersion::select(Some(alpn(&[]).as_slice())).unwrap(),
            HttpVersion::Http2
        );
        assert_eq!(
            HttpVersion::select(Some(alpn(&["h2", "http/1.1"]).as_slice())).unwrap(),
            HttpVersion::Http2
        );
        assert_eq!(
            HttpVersion::select(Some(alpn(&["h3"]).as_slice())).unwrap(),
            HttpVersion::Http3
        );
    }

    #[test]
    fn requests_carry_host_path_and_padding() {
        let settings = XhttpSettings {
            path: "/xh?k=v".into(),
            headers: [("X-Edge".to_string(), "1".to_string())].into(),
            ..XhttpSettings::default()
        };
        let xhttp = connector(&settings, 8080, HttpVersion::Http11).unwrap();
        assert_eq!(xhttp.mode(), Mode::PacketUp);
        assert_eq!(xhttp.authority(), "edge.example:8080");
        assert_eq!(xhttp.request_target("abc/0"), "/xh/abc/0?k=v");
        let request =
            String::from_utf8(xhttp.inner.h1_request("POST", "/xh/abc/0?k=v", Some(5))).unwrap();
        assert!(request.starts_with("POST /xh/abc/0?k=v HTTP/1.1\r\nHost: edge.example:8080\r\n"));
        assert!(request.contains("\r\nx-edge: 1\r\n"));
        assert!(request.contains("\r\nuser-agent: Mozilla/5.0"));
        assert!(request.contains("\r\nContent-Length: 5\r\n\r\n"));
        let referer = request
            .lines()
            .find_map(|line| line.strip_prefix("Referer: "))
            .unwrap();
        let padding = referer
            .strip_prefix("http://edge.example:8080/xh/abc/0?x_padding=")
            .unwrap();
        assert!(DEFAULT_PADDING_BYTES.contains(padding.len()));
        assert!(padding.bytes().all(|byte| byte == b'X'));

        let h2 = connector(
            &XhttpSettings {
                host: "cdn.example".into(),
                mode: Mode::StreamOne,
                ..XhttpSettings::default()
            },
            443,
            HttpVersion::Http2,
        )
        .unwrap();
        let request = h2
            .inner
            .h2_request(http::Method::POST, &h2.request_target(""), None)
            .unwrap();
        assert_eq!(request.uri(), "http://cdn.example/");
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/grpc"
        );
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let stream_one = XhttpSettings {
            mode: Mode::StreamOne,
            ..XhttpSettings::default()
        };
        assert!(connector(&stream_one, 80, HttpVersion::Http11).is_err());
        assert!(connector(&stream_one, 80, HttpVersion::Http2).is_ok());
        let bad_host = XhttpSettings {
            host: "a b".into(),
            ..XhttpSettings::default()
        };
        assert!(connector(&bad_host, 80, HttpVersion::Http11).is_err());
        let bad_header = XhttpSettings {
            headers: [("X-A".to_string(), "a\r\nb".to_string())].into(),
            ..XhttpSettings::default()
        };
        assert!(connector(&bad_header, 80, HttpVersion::Http11).is_err());
    }
}
