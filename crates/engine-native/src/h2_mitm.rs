//! HTTP/2 data plane for the controlled TLS MITM session.
//!
//! The blocking listener keeps owning sockets and the bounded HTTP/1.1 path.
//! When the decrypted client offers `h2` in its ClientHello, the session first
//! completes the upstream TLS handshake with the client's `h2`/`http/1.1`
//! offers, then mirrors the upstream ALPN choice to the client. For `h2`, both
//! HTTP/2 connections run on a per-session current-thread Tokio runtime using
//! the maintained `h2` crate for framing, HPACK, and flow control. For
//! `http/1.1`, the negotiated TLS sessions are handed back to the blocking
//! HTTP/1.1 exchange loop unchanged.
//!
//! Every HTTP/2 stream is normalized into the same bounded
//! [`NativePlainHttpMessage`] rewrite model the HTTP/1.1 path uses, so plugins
//! see the same URL, lower-cased header, and body shape. Streams whose request
//! or response body exceeds the bound, or whose headers are not UTF-8, are
//! relayed without rewrite instead of being truncated.

use super::{
    engine_diagnostic, explicit_http_proxy_request_to_plain_http_message, http_url_authority,
    parse_script_absolute_url, passthrough_plain_http_rewrite_report,
    plain_http_proxy_response_to_plain_http_message, record_plain_http_live_rewrite_diagnostic,
    run_controlled_tls_http1_exchanges, NativeExplicitHttpProxyRequest, NativeHttpMitmPluginHook,
    NativePlainHttpMessage, NativePlainHttpProxyResponse, NativePlainHttpRewriteReport,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_AUTHORITY_MISMATCH_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_LIMIT_REACHED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_PASSTHROUGH_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_ALPN_NEGOTIATED_CODE, HTTP_PROXY_MAX_BODY_BYTES,
    HTTP_PROXY_MAX_HEADER_BYTES, SOURCE_ENGINE_NATIVE_MITM,
};
use bytes::Bytes;
use control_domain::{Diagnostic, DiagnosticSeverity, MetadataEntry};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use http::header::{CONTENT_LENGTH, COOKIE, HOST, LOCATION, TE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig, ServerConnection, StreamOwned};
use std::future::Future;
use std::net::TcpStream;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(crate) const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// Maximum concurrent client streams advertised to the decrypted client.
pub const CONTROLLED_H2_MAX_CONCURRENT_STREAMS: u32 = 32;
/// Streams accepted on one decrypted connection before a graceful GOAWAY.
pub const CONTROLLED_H2_MAX_STREAMS_PER_SESSION: usize = 256;
/// Upper bound for one stream, including passthrough relays of large bodies.
pub const CONTROLLED_H2_STREAM_TIMEOUT_MS: u64 = 120_000;
const CONTROLLED_H2_SHUTDOWN_GRACE_MS: u64 = 1000;
const H2_CONNECTION_SPECIFIC_HEADERS: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// Bounds and context for one decrypted HTTP/2 MITM session.
#[derive(Debug, Clone)]
pub struct NativeH2MitmSessionConfig {
    pub connect_request: NativeExplicitHttpProxyRequest,
    pub http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    pub max_body_bytes: usize,
    pub max_header_list_bytes: u32,
    pub max_concurrent_streams: u32,
    pub max_streams_per_session: usize,
    pub idle_timeout: Duration,
    pub stream_timeout: Duration,
}

impl NativeH2MitmSessionConfig {
    pub fn new(
        connect_request: NativeExplicitHttpProxyRequest,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    ) -> Self {
        Self {
            connect_request,
            http_mitm_hook,
            max_body_bytes: HTTP_PROXY_MAX_BODY_BYTES,
            max_header_list_bytes: HTTP_PROXY_MAX_HEADER_BYTES as u32,
            max_concurrent_streams: CONTROLLED_H2_MAX_CONCURRENT_STREAMS,
            max_streams_per_session: CONTROLLED_H2_MAX_STREAMS_PER_SESSION,
            idle_timeout: Duration::from_millis(super::CONTROLLED_TLS_SESSION_TIMEOUT_MS),
            stream_timeout: Duration::from_millis(CONTROLLED_H2_STREAM_TIMEOUT_MS),
        }
    }

    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    pub fn with_stream_timeout(mut self, stream_timeout: Duration) -> Self {
        self.stream_timeout = stream_timeout;
        self
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_max_streams_per_session(mut self, max_streams_per_session: usize) -> Self {
        self.max_streams_per_session = max_streams_per_session.max(1);
        self
    }
}

/// Outcome of one decrypted HTTP/2 MITM session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeH2MitmSessionReport {
    /// Both HTTP/2 handshakes completed.
    pub session_ready: bool,
    pub streams_accepted: usize,
    pub streams_completed: usize,
    pub streams_rewritten: usize,
    pub streams_passthrough: usize,
    pub streams_failed: usize,
    /// At least one stream sent response headers to the client.
    pub response_written: bool,
    pub diagnostics: Vec<Diagnostic>,
}

impl NativeH2MitmSessionReport {
    fn absorb(&mut self, stream: NativeH2MitmStreamReport) {
        if stream.completed {
            self.streams_completed += 1;
        }
        if stream.failed {
            self.streams_failed += 1;
        }
        if stream.rewritten {
            self.streams_rewritten += 1;
        }
        if stream.passthrough {
            self.streams_passthrough += 1;
        }
        self.response_written |= stream.response_started;
        self.diagnostics.extend(stream.diagnostics);
    }
}

#[derive(Debug, Default)]
struct NativeH2MitmStreamReport {
    completed: bool,
    failed: bool,
    rewritten: bool,
    passthrough: bool,
    response_started: bool,
    diagnostics: Vec<Diagnostic>,
}

impl NativeH2MitmStreamReport {
    fn absorb_rewrite(&mut self, rewrite_report: &NativePlainHttpRewriteReport) {
        self.diagnostics
            .extend(rewrite_report.diagnostics.iter().cloned());
        record_plain_http_live_rewrite_diagnostic(&mut self.diagnostics, rewrite_report);
        self.rewritten |= rewrite_report.applied;
    }

    fn mark_passthrough(&mut self, stream_id: u32, reason: &str) {
        self.passthrough = true;
        self.diagnostics.push(mitm_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_PASSTHROUGH_CODE,
            format!(
                "native controlled TLS HTTP/2 stream {stream_id} relayed without rewrite: {reason}"
            ),
        ));
    }
}

/// Runs one decrypted HTTP/2 MITM session between a client-facing transport
/// and an upstream transport that both already negotiated `h2`.
///
/// The future returns once the client closes the connection, the idle timeout
/// elapses with no active stream, the per-session stream budget is spent, or
/// either connection fails. Streams still in flight at that point are reset.
pub async fn run_native_h2_mitm_session<D, U>(
    downstream: D,
    upstream: U,
    config: NativeH2MitmSessionConfig,
) -> NativeH2MitmSessionReport
where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut report = NativeH2MitmSessionReport::default();
    let config = Arc::new(config);

    let upstream_handshake = h2::client::Builder::new()
        .enable_push(false)
        .max_header_list_size(config.max_header_list_bytes)
        .handshake::<_, Bytes>(upstream);
    let (send_request, upstream_connection) =
        match tokio::time::timeout(config.idle_timeout, upstream_handshake).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(error)) => {
                report.diagnostics.push(h2_session_failed(format!(
                    "native controlled TLS HTTP/2 upstream handshake failed: {error}"
                )));
                return report;
            }
            Err(_) => {
                report.diagnostics.push(h2_session_failed(
                    "native controlled TLS HTTP/2 upstream handshake timed out",
                ));
                return report;
            }
        };
    let upstream_driver = tokio::spawn(async move {
        let _ = upstream_connection.await;
    });

    let downstream_handshake = h2::server::Builder::new()
        .max_concurrent_streams(config.max_concurrent_streams)
        .max_header_list_size(config.max_header_list_bytes)
        .handshake::<_, Bytes>(downstream);
    let mut downstream_connection =
        match tokio::time::timeout(config.idle_timeout, downstream_handshake).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                upstream_driver.abort();
                report.diagnostics.push(h2_session_failed(format!(
                    "native controlled TLS HTTP/2 client handshake failed: {error}"
                )));
                return report;
            }
            Err(_) => {
                upstream_driver.abort();
                report.diagnostics.push(h2_session_failed(
                    "native controlled TLS HTTP/2 client handshake timed out",
                ));
                return report;
            }
        };
    report.session_ready = true;
    report.diagnostics.push(mitm_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE,
        "native controlled TLS HTTP/2 session completed client and upstream handshakes",
    ));

    let mut streams: JoinSet<NativeH2MitmStreamReport> = JoinSet::new();
    let mut accepting = true;
    let mut idle = Box::pin(tokio::time::sleep(config.idle_timeout));

    loop {
        let event = std::future::poll_fn(|cx| {
            if let Poll::Ready(Some(joined)) = streams.poll_join_next(cx) {
                return Poll::Ready(NativeH2SessionEvent::Joined(joined));
            }
            if let Poll::Ready(accepted) = downstream_connection.poll_accept(cx) {
                return Poll::Ready(NativeH2SessionEvent::Accepted(Box::new(accepted)));
            }
            if streams.is_empty() && idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(NativeH2SessionEvent::Idle);
            }
            Poll::Pending
        })
        .await;

        match event {
            NativeH2SessionEvent::Accepted(accepted) => match *accepted {
                Some(Ok((request, respond))) => {
                    report.streams_accepted += 1;
                    idle.as_mut()
                        .reset(tokio::time::Instant::now() + config.idle_timeout);
                    if accepting && report.streams_accepted >= config.max_streams_per_session {
                        accepting = false;
                        downstream_connection.graceful_shutdown();
                        report.diagnostics.push(mitm_diagnostic(
                        DiagnosticSeverity::Info,
                        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_LIMIT_REACHED_CODE,
                        format!(
                            "native controlled TLS HTTP/2 session reached its {} stream budget and sent GOAWAY",
                            config.max_streams_per_session
                        ),
                    ));
                    }
                    streams.spawn(handle_native_h2_mitm_stream(
                        request,
                        respond,
                        send_request.clone(),
                        Arc::clone(&config),
                    ));
                }
                Some(Err(error)) => {
                    if !error.is_go_away() && !error.is_io() {
                        report.diagnostics.push(h2_session_failed(format!(
                            "native controlled TLS HTTP/2 client connection failed: {error}"
                        )));
                    }
                    break;
                }
                None => break,
            },
            NativeH2SessionEvent::Joined(joined) => {
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + config.idle_timeout);
                report.absorb(stream_report_from_join(joined));
            }
            NativeH2SessionEvent::Idle => {
                if !accepting {
                    break;
                }
                accepting = false;
                downstream_connection.graceful_shutdown();
                idle.as_mut().reset(
                    tokio::time::Instant::now()
                        + Duration::from_millis(CONTROLLED_H2_SHUTDOWN_GRACE_MS),
                );
            }
        }
    }

    streams.abort_all();
    while let Some(joined) = streams.join_next().await {
        if let Ok(stream_report) = joined {
            report.absorb(stream_report);
        }
    }
    upstream_driver.abort();
    report
}

type NativeH2AcceptedStream = Option<Result<(Request<RecvStream>, SendResponse<Bytes>), h2::Error>>;

enum NativeH2SessionEvent {
    Accepted(Box<NativeH2AcceptedStream>),
    Joined(Result<NativeH2MitmStreamReport, JoinError>),
    Idle,
}

fn stream_report_from_join(
    joined: Result<NativeH2MitmStreamReport, JoinError>,
) -> NativeH2MitmStreamReport {
    joined.unwrap_or_else(|error| NativeH2MitmStreamReport {
        failed: true,
        diagnostics: vec![mitm_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_FAILED_CODE,
            format!("native controlled TLS HTTP/2 stream task stopped: {error}"),
        )],
        ..NativeH2MitmStreamReport::default()
    })
}

async fn handle_native_h2_mitm_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    upstream: SendRequest<Bytes>,
    config: Arc<NativeH2MitmSessionConfig>,
) -> NativeH2MitmStreamReport {
    let stream_id = respond.stream_id().as_u32();
    let mut report = NativeH2MitmStreamReport::default();
    let relay = relay_native_h2_mitm_stream(
        stream_id,
        request,
        &mut respond,
        upstream,
        &config,
        &mut report,
    );
    let failure = match tokio::time::timeout(config.stream_timeout, relay).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("stream timed out".to_string()),
    };
    match failure {
        None => {
            report.completed = true;
            report.diagnostics.push(mitm_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE,
                format!("native controlled TLS HTTP/2 stream {stream_id} completed"),
            ));
        }
        Some(error) => {
            respond.send_reset(Reason::INTERNAL_ERROR);
            report.failed = true;
            report.diagnostics.push(mitm_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_FAILED_CODE,
                format!("native controlled TLS HTTP/2 stream {stream_id} was reset: {error}"),
            ));
        }
    }
    report
}

async fn relay_native_h2_mitm_stream(
    stream_id: u32,
    request: Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    upstream: SendRequest<Bytes>,
    config: &NativeH2MitmSessionConfig,
    report: &mut NativeH2MitmStreamReport,
) -> Result<(), String> {
    let (parts, request_body) = request.into_parts();
    let connect_request = &config.connect_request;

    if parts.method == Method::CONNECT {
        report.response_started = true;
        return send_native_h2_response(
            respond,
            StatusCode::METHOD_NOT_ALLOWED,
            HeaderMap::new(),
            NativeH2Body::empty(),
            false,
        )
        .await;
    }
    if !native_h2_request_authority_matches_connect(&parts.uri, &parts.headers, connect_request) {
        report.diagnostics.push(mitm_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_AUTHORITY_MISMATCH_CODE,
            format!(
                "native controlled TLS HTTP/2 stream {stream_id} authority does not match the CONNECT authority"
            ),
        ));
        report.response_started = true;
        return send_native_h2_response(
            respond,
            StatusCode::MISDIRECTED_REQUEST,
            HeaderMap::new(),
            NativeH2Body::empty(),
            false,
        )
        .await;
    }

    let origin_path = parts
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .filter(|path| path.starts_with('/'))
        .unwrap_or("/")
        .to_string();
    let authority = http_url_authority(
        &connect_request.target_host,
        connect_request.target_port,
        443,
    );
    let target_url = format!("https://{authority}{origin_path}");
    let is_head = parts.method == Method::HEAD;
    let request_entries = native_h2_header_entries(&parts.headers);
    let request_body = collect_native_h2_body(
        request_body,
        declared_content_length(&parts.headers),
        config.max_body_bytes,
    )
    .await?;

    let mut request_headers = request_entries.clone().unwrap_or_default();
    request_headers.insert(
        0,
        MetadataEntry {
            key: HOST.as_str().to_string(),
            value: authority,
        },
    );
    let mut explicit_request = NativeExplicitHttpProxyRequest {
        request_id: format!(
            "native-https-connect-h2:{stream_id}:{}:{target_url}",
            parts.method
        ),
        method: parts.method.as_str().to_string(),
        target_url,
        target_host: connect_request.target_host.clone(),
        target_port: connect_request.target_port,
        origin_path: origin_path.clone(),
        version: "HTTP/2.0".to_string(),
        headers: request_headers,
        body: Vec::new(),
    };

    let (upstream_request, upstream_body) = match (request_entries, request_body) {
        (Some(_), NativeH2Body::Complete { body, trailers }) => {
            explicit_request.body = body;
            let request_message =
                explicit_http_proxy_request_to_plain_http_message(&explicit_request);
            let rewrite_report =
                plan_native_h2_rewrite(config.http_mitm_hook.as_ref(), request_message).await?;
            report.absorb_rewrite(&rewrite_report);
            if rewrite_report.terminal_action.is_some() {
                let status = native_h2_status(rewrite_report.final_status_code, StatusCode::OK);
                let headers = native_h2_terminal_response_headers(&rewrite_report);
                report.response_started = true;
                return send_native_h2_response(
                    respond,
                    status,
                    headers,
                    NativeH2Body::complete(rewrite_report.body, None),
                    is_head,
                )
                .await;
            }

            let origin_path = native_h2_rewritten_origin_path(&explicit_request, &rewrite_report);
            let mut headers = native_h2_header_map(&rewrite_report.headers);
            let had_content_length = parts.headers.contains_key(CONTENT_LENGTH);
            headers.remove(CONTENT_LENGTH);
            if !rewrite_report.body.is_empty() || had_content_length {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(rewrite_report.body.len()));
            }
            let request =
                native_h2_upstream_request(&parts.method, connect_request, &origin_path, headers)?;
            (
                request,
                NativeH2Body::complete(rewrite_report.body, trailers),
            )
        }
        (_, body) => {
            report.mark_passthrough(stream_id, native_h2_passthrough_reason(&body));
            let mut headers = parts.headers.clone();
            strip_native_h2_connection_headers(&mut headers);
            let request =
                native_h2_upstream_request(&parts.method, connect_request, &origin_path, headers)?;
            (request, body)
        }
    };

    let mut upstream = upstream
        .ready()
        .await
        .map_err(|error| format!("upstream HTTP/2 connection is not ready: {error}"))?;
    let end_of_stream = upstream_body.is_empty_without_trailers();
    let (response_future, mut upstream_send) = upstream
        .send_request(upstream_request, end_of_stream)
        .map_err(|error| format!("upstream HTTP/2 request could not be sent: {error}"))?;
    if !end_of_stream {
        send_native_h2_body(&mut upstream_send, upstream_body).await?;
    }

    let upstream_response = response_future
        .await
        .map_err(|error| format!("upstream HTTP/2 response failed: {error}"))?;
    let (response_parts, response_body) = upstream_response.into_parts();
    let response_entries = native_h2_header_entries(&response_parts.headers);
    let response_body = collect_native_h2_body(
        response_body,
        declared_content_length(&response_parts.headers),
        config.max_body_bytes,
    )
    .await?;

    match (response_entries, response_body) {
        (Some(headers), NativeH2Body::Complete { body, trailers }) => {
            let upstream_response = NativePlainHttpProxyResponse {
                version: "HTTP/2.0".to_string(),
                status_code: response_parts.status.as_u16(),
                reason_phrase: String::new(),
                headers,
                body,
            };
            let response_message = plain_http_proxy_response_to_plain_http_message(
                &explicit_request,
                &upstream_response,
            );
            let rewrite_report =
                plan_native_h2_rewrite(config.http_mitm_hook.as_ref(), response_message).await?;
            report.absorb_rewrite(&rewrite_report);
            let status = native_h2_status(rewrite_report.final_status_code, response_parts.status);
            let mut headers = native_h2_header_map(&rewrite_report.headers);
            if let Some(location) = rewrite_report
                .redirect_location
                .as_deref()
                .and_then(|location| HeaderValue::from_str(location).ok())
            {
                headers.insert(LOCATION, location);
            }
            if !is_head && status != StatusCode::NOT_MODIFIED {
                headers.remove(CONTENT_LENGTH);
                if native_h2_status_allows_body(status) {
                    headers.insert(CONTENT_LENGTH, HeaderValue::from(rewrite_report.body.len()));
                }
            }
            report.response_started = true;
            send_native_h2_response(
                respond,
                status,
                headers,
                NativeH2Body::complete(rewrite_report.body, trailers),
                is_head,
            )
            .await
        }
        (_, body) => {
            report.mark_passthrough(stream_id, native_h2_passthrough_reason(&body));
            let mut headers = response_parts.headers.clone();
            strip_native_h2_connection_headers(&mut headers);
            report.response_started = true;
            send_native_h2_response(respond, response_parts.status, headers, body, is_head).await
        }
    }
}

/// A buffered HTTP/2 body, or the bounded prefix of one that is relayed as a
/// stream after the prefix.
enum NativeH2Body {
    Complete {
        body: Vec<u8>,
        trailers: Option<HeaderMap>,
    },
    Overflow {
        prefix: Vec<u8>,
        rest: RecvStream,
    },
}

impl NativeH2Body {
    fn empty() -> Self {
        Self::complete(Vec::new(), None)
    }

    fn complete(body: Vec<u8>, trailers: Option<HeaderMap>) -> Self {
        Self::Complete { body, trailers }
    }

    fn is_empty_without_trailers(&self) -> bool {
        matches!(self, Self::Complete { body, trailers: None } if body.is_empty())
    }
}

fn native_h2_passthrough_reason(body: &NativeH2Body) -> &'static str {
    match body {
        NativeH2Body::Overflow { .. } => "body exceeds the bounded rewrite limit",
        NativeH2Body::Complete { .. } => "headers are not valid UTF-8",
    }
}

async fn collect_native_h2_body(
    mut body: RecvStream,
    declared_length: Option<usize>,
    max_body_bytes: usize,
) -> Result<NativeH2Body, String> {
    if declared_length.is_some_and(|length| length > max_body_bytes) {
        return Ok(NativeH2Body::Overflow {
            prefix: Vec::new(),
            rest: body,
        });
    }

    let mut buffered = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|error| format!("HTTP/2 body could not be read: {error}"))?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buffered.extend_from_slice(&chunk);
        if buffered.len() > max_body_bytes {
            return Ok(NativeH2Body::Overflow {
                prefix: buffered,
                rest: body,
            });
        }
    }
    let trailers = body
        .trailers()
        .await
        .map_err(|error| format!("HTTP/2 trailers could not be read: {error}"))?;
    Ok(NativeH2Body::Complete {
        body: buffered,
        trailers,
    })
}

async fn send_native_h2_response(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    headers: HeaderMap,
    body: NativeH2Body,
    is_head: bool,
) -> Result<(), String> {
    let mut response = Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|error| format!("HTTP/2 response head is invalid: {error}"))?;
    *response.headers_mut() = headers;
    let end_of_stream =
        is_head || !native_h2_status_allows_body(status) || body.is_empty_without_trailers();
    let mut send = respond
        .send_response(response, end_of_stream)
        .map_err(|error| format!("HTTP/2 response could not be sent: {error}"))?;
    if end_of_stream {
        return Ok(());
    }
    send_native_h2_body(&mut send, body).await
}

async fn send_native_h2_body(
    send: &mut SendStream<Bytes>,
    body: NativeH2Body,
) -> Result<(), String> {
    match body {
        NativeH2Body::Complete { body, trailers } => {
            send_native_h2_data(send, Bytes::from(body), trailers.is_none()).await?;
            if let Some(trailers) = trailers {
                send.send_trailers(trailers)
                    .map_err(|error| format!("HTTP/2 trailers could not be sent: {error}"))?;
            }
            Ok(())
        }
        NativeH2Body::Overflow { prefix, mut rest } => {
            send_native_h2_data(send, Bytes::from(prefix), false).await?;
            while let Some(chunk) = rest.data().await {
                let chunk =
                    chunk.map_err(|error| format!("HTTP/2 body could not be relayed: {error}"))?;
                let chunk_len = chunk.len();
                send_native_h2_data(send, chunk, false).await?;
                let _ = rest.flow_control().release_capacity(chunk_len);
            }
            match rest
                .trailers()
                .await
                .map_err(|error| format!("HTTP/2 trailers could not be relayed: {error}"))?
            {
                Some(trailers) => send
                    .send_trailers(trailers)
                    .map_err(|error| format!("HTTP/2 trailers could not be sent: {error}")),
                None => send_native_h2_data(send, Bytes::new(), true).await,
            }
        }
    }
}

async fn send_native_h2_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_of_stream: bool,
) -> Result<(), String> {
    if data.is_empty() {
        if end_of_stream {
            send.send_data(data, true)
                .map_err(|error| format!("HTTP/2 stream could not be closed: {error}"))?;
        }
        return Ok(());
    }

    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Err(format!("HTTP/2 send window failed: {error}")),
            None => return Err("HTTP/2 stream closed before its body was sent".to_string()),
        };
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, end_of_stream && data.is_empty())
            .map_err(|error| format!("HTTP/2 body could not be sent: {error}"))?;
    }
    Ok(())
}

async fn plan_native_h2_rewrite(
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    message: NativePlainHttpMessage,
) -> Result<NativePlainHttpRewriteReport, String> {
    let Some(hook) = http_mitm_hook.cloned() else {
        return Ok(passthrough_plain_http_rewrite_report(&message));
    };
    // Plugin planning and script dispatch block, so keep them off the
    // connection-driving thread.
    tokio::task::spawn_blocking(move || hook.plan_plain_http(&message))
        .await
        .map_err(|error| format!("HTTP/2 rewrite planning stopped: {error}"))
}

fn native_h2_upstream_request(
    method: &Method,
    connect_request: &NativeExplicitHttpProxyRequest,
    origin_path: &str,
    headers: HeaderMap,
) -> Result<Request<()>, String> {
    let authority = http_url_authority(
        &connect_request.target_host,
        connect_request.target_port,
        443,
    );
    let mut request = Request::builder()
        .method(method.clone())
        .uri(format!("https://{authority}{origin_path}"))
        .version(Version::HTTP_2)
        .body(())
        .map_err(|error| format!("upstream HTTP/2 request head is invalid: {error}"))?;
    *request.headers_mut() = headers;
    Ok(request)
}

fn native_h2_rewritten_origin_path(
    request: &NativeExplicitHttpProxyRequest,
    rewrite_report: &NativePlainHttpRewriteReport,
) -> String {
    parse_script_absolute_url(&rewrite_report.url)
        .filter(|(_, target)| {
            target
                .target_host
                .eq_ignore_ascii_case(&request.target_host)
                && target.target_port == request.target_port
        })
        .map(|(_, target)| target.origin_path)
        .unwrap_or_else(|| request.origin_path.clone())
}

fn native_h2_terminal_response_headers(rewrite_report: &NativePlainHttpRewriteReport) -> HeaderMap {
    let mut headers = native_h2_header_map(&rewrite_report.headers);
    if let Some(location) = rewrite_report
        .redirect_location
        .as_deref()
        .and_then(|location| HeaderValue::from_str(location).ok())
    {
        headers.insert(LOCATION, location);
    }
    headers.remove(CONTENT_LENGTH);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(rewrite_report.body.len()));
    headers
}

fn native_h2_status(status_code: Option<u16>, fallback: StatusCode) -> StatusCode {
    status_code
        .and_then(|code| StatusCode::from_u16(code).ok())
        .filter(|status| !status.is_informational())
        .unwrap_or(fallback)
}

fn native_h2_status_allows_body(status: StatusCode) -> bool {
    !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED)
}

fn native_h2_request_authority_matches_connect(
    uri: &http::Uri,
    headers: &HeaderMap,
    connect_request: &NativeExplicitHttpProxyRequest,
) -> bool {
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            headers
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .map(str::to_string)
        });
    let Some(authority) = authority else {
        return true;
    };
    let Ok(authority) = authority.parse::<http::uri::Authority>() else {
        return false;
    };
    let request_host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let connect_host = connect_request
        .target_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    !connect_host.is_empty()
        && request_host == connect_host
        && authority.port_u16().unwrap_or(443) == connect_request.target_port
}

fn declared_content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

/// Lower-cased header entries for the bounded rewrite model. Split `cookie`
/// fields are joined as RFC 9113 section 8.2.3 requires for HTTP/1.1
/// semantics. Returns `None` when a value is not UTF-8.
fn native_h2_header_entries(headers: &HeaderMap) -> Option<Vec<MetadataEntry>> {
    let mut entries = Vec::new();
    let mut cookies = Vec::new();
    for (name, value) in headers {
        let value = std::str::from_utf8(value.as_bytes()).ok()?.to_string();
        if *name == COOKIE {
            cookies.push(value);
        } else if !native_h2_connection_specific_header(name) {
            entries.push(MetadataEntry {
                key: name.as_str().to_string(),
                value,
            });
        }
    }
    if !cookies.is_empty() {
        entries.push(MetadataEntry {
            key: COOKIE.as_str().to_string(),
            value: cookies.join("; "),
        });
    }
    Some(entries)
}

/// Converts rewritten entries back to an HTTP/2 header block, dropping names
/// or values a plugin produced that HTTP/2 cannot carry.
fn native_h2_header_map(entries: &[MetadataEntry]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for entry in entries {
        let Ok(name) = HeaderName::from_bytes(entry.key.trim().as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(entry.value.trim().as_bytes()) else {
            continue;
        };
        if native_h2_connection_specific_header(&name)
            || (name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers"))
        {
            continue;
        }
        headers.append(name, value);
    }
    headers
}

fn strip_native_h2_connection_headers(headers: &mut HeaderMap) {
    for name in H2_CONNECTION_SPECIFIC_HEADERS {
        headers.remove(name);
    }
    let te_is_trailers = headers
        .get(TE)
        .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(b"trailers"));
    if !te_is_trailers {
        headers.remove(TE);
    }
}

fn native_h2_connection_specific_header(name: &HeaderName) -> bool {
    H2_CONNECTION_SPECIFIC_HEADERS.contains(&name.as_str())
}

fn h2_session_failed(message: impl Into<String>) -> Diagnostic {
    mitm_diagnostic(
        DiagnosticSeverity::Warning,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_FAILED_CODE,
        message,
    )
}

fn mitm_diagnostic(
    severity: DiagnosticSeverity,
    code: &str,
    message: impl Into<String>,
) -> Diagnostic {
    engine_diagnostic(severity, code, message, SOURCE_ENGINE_NATIVE_MITM)
}

/// Inputs for an ALPN-aware controlled TLS session whose client offered `h2`.
pub(crate) struct NativeControlledTlsAlpnSession<'a> {
    pub(crate) client_stream: TcpStream,
    pub(crate) outbound_stream: TcpStream,
    pub(crate) server_name: ServerName<'static>,
    pub(crate) connect_request: &'a NativeExplicitHttpProxyRequest,
    pub(crate) downstream_server_config: Arc<ServerConfig>,
    pub(crate) upstream_client_config: Arc<ClientConfig>,
    pub(crate) client_alpn_protocols: &'a [Vec<u8>],
    pub(crate) http_mitm_hook: Option<&'a NativeHttpMitmPluginHook>,
    pub(crate) session_timeout: Duration,
}

enum NativeNegotiatedTlsSession {
    Http2 {
        downstream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    },
    Http1 {
        downstream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    },
}

/// Negotiates ALPN upstream first, mirrors the result to the client, and runs
/// the matching HTTP/2 or bounded HTTP/1.1 exchange loop.
pub(crate) fn run_controlled_tls_alpn_session(
    session: NativeControlledTlsAlpnSession<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool, String> {
    let NativeControlledTlsAlpnSession {
        client_stream,
        outbound_stream,
        server_name,
        connect_request,
        downstream_server_config,
        upstream_client_config,
        client_alpn_protocols,
        http_mitm_hook,
        session_timeout,
    } = session;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("controlled TLS ALPN runtime could not start: {error}"))?;

    let negotiated = runtime.block_on(negotiate_controlled_tls_alpn(
        client_stream,
        outbound_stream,
        server_name,
        &downstream_server_config,
        &upstream_client_config,
        client_alpn_protocols,
        session_timeout,
    ))?;

    match negotiated {
        NativeNegotiatedTlsSession::Http2 {
            downstream,
            upstream,
        } => {
            diagnostics.push(alpn_negotiated_diagnostic("h2"));
            let config =
                NativeH2MitmSessionConfig::new(connect_request.clone(), http_mitm_hook.cloned())
                    .with_idle_timeout(session_timeout);
            let report = runtime.block_on(run_native_h2_mitm_session(downstream, upstream, config));
            let session_ready = report.session_ready;
            let response_written = report.response_written;
            diagnostics.extend(report.diagnostics);
            if !session_ready {
                return Err("controlled TLS HTTP/2 session could not start".to_string());
            }
            Ok(response_written)
        }
        NativeNegotiatedTlsSession::Http1 {
            downstream,
            upstream,
        } => {
            diagnostics.push(alpn_negotiated_diagnostic("http/1.1"));
            let (mut downstream_tls, mut upstream_tls) = {
                let _runtime_context = runtime.enter();
                let (downstream_io, downstream_connection) = downstream.into_inner();
                let (upstream_io, upstream_connection) = upstream.into_inner();
                (
                    StreamOwned::<ServerConnection, TcpStream>::new(
                        downstream_connection,
                        blocking_std_stream(downstream_io)?,
                    ),
                    StreamOwned::new(upstream_connection, blocking_std_stream(upstream_io)?),
                )
            };
            run_controlled_tls_http1_exchanges(
                &mut downstream_tls,
                &mut upstream_tls,
                connect_request,
                http_mitm_hook,
                session_timeout,
                diagnostics,
            )
        }
    }
}

async fn negotiate_controlled_tls_alpn(
    client_stream: TcpStream,
    outbound_stream: TcpStream,
    server_name: ServerName<'static>,
    downstream_server_config: &ServerConfig,
    upstream_client_config: &ClientConfig,
    client_alpn_protocols: &[Vec<u8>],
    handshake_timeout: Duration,
) -> Result<NativeNegotiatedTlsSession, String> {
    let client_stream = async_tcp_stream(client_stream)?;
    let outbound_stream = async_tcp_stream(outbound_stream)?;

    let mut upstream_config = upstream_client_config.clone();
    upstream_config.alpn_protocols = client_alpn_protocols
        .iter()
        .filter(|protocol| protocol.as_slice() == ALPN_H2 || protocol.as_slice() == ALPN_HTTP_1_1)
        .cloned()
        .collect();
    let upstream = tokio::time::timeout(
        handshake_timeout,
        TlsConnector::from(Arc::new(upstream_config)).connect(server_name, outbound_stream),
    )
    .await
    .map_err(|_| "controlled TLS upstream ALPN handshake timed out".to_string())?
    .map_err(|error| format!("controlled TLS upstream ALPN handshake failed: {error}"))?;
    let upstream_h2 = upstream.get_ref().1.alpn_protocol() == Some(ALPN_H2);

    let mut downstream_config = downstream_server_config.clone();
    downstream_config.alpn_protocols = vec![if upstream_h2 {
        ALPN_H2.to_vec()
    } else {
        ALPN_HTTP_1_1.to_vec()
    }];
    let downstream = tokio::time::timeout(
        handshake_timeout,
        TlsAcceptor::from(Arc::new(downstream_config)).accept(client_stream),
    )
    .await
    .map_err(|_| "controlled TLS downstream ALPN handshake timed out".to_string())?
    .map_err(|error| format!("controlled TLS downstream ALPN handshake failed: {error}"))?;
    let downstream_h2 = downstream.get_ref().1.alpn_protocol() == Some(ALPN_H2);

    match (upstream_h2, downstream_h2) {
        (true, true) => Ok(NativeNegotiatedTlsSession::Http2 {
            downstream,
            upstream,
        }),
        (false, false) => Ok(NativeNegotiatedTlsSession::Http1 {
            downstream,
            upstream,
        }),
        _ => Err("controlled TLS ALPN diverged between client and upstream".to_string()),
    }
}

fn async_tcp_stream(stream: TcpStream) -> Result<tokio::net::TcpStream, String> {
    stream
        .set_nonblocking(true)
        .and_then(|()| tokio::net::TcpStream::from_std(stream))
        .map_err(|error| format!("controlled TLS socket could not join the ALPN runtime: {error}"))
}

fn blocking_std_stream(stream: tokio::net::TcpStream) -> Result<TcpStream, String> {
    let stream = stream.into_std().map_err(|error| {
        format!("controlled TLS socket could not leave the ALPN runtime: {error}")
    })?;
    stream.set_nonblocking(false).map_err(|error| {
        format!("controlled TLS socket could not return to blocking mode: {error}")
    })?;
    Ok(stream)
}

fn alpn_negotiated_diagnostic(protocol: &str) -> Diagnostic {
    mitm_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_ALPN_NEGOTIATED_CODE,
        format!(
            "native controlled TLS session negotiated ALPN {protocol} with client and upstream"
        ),
    )
}
