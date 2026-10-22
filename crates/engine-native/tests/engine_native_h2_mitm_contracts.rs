//! Contracts for the HTTP/2 controlled TLS MITM data plane, the ClientHello
//! ALPN observer, and the UDP/443 QUIC rejection policy.

use bytes::Bytes;
use control_domain::{
    AuditEvent, Diagnostic, DomainResult, GrantedPermissions, HookPoint, HttpBodyMutation,
    HttpEvent, HttpHeaderMutation, HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent,
    HttpMitmOutcome, HttpMitmPhase, MitmHostnameDecision, MitmPluginService, PluginInstance,
    PluginManifest, PluginPackage, PluginPermission, PluginResult,
};
use engine_native::{
    observe_tls_client_hello_alpn_protocols, plan_native_udp_mitm_decision,
    read_explicit_http_proxy_request, run_native_h2_mitm_session, NativeExplicitHttpProxyRequest,
    NativeH2MitmSessionConfig, NativeH2MitmSessionReport, NativeHttpMitmPluginHook,
    NativeUdpMitmDecision, ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_AUTHORITY_MISMATCH_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_LIMIT_REACHED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_PASSTHROUGH_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_UDP_MITM_ALLOWED_CODE, ENGINE_NATIVE_RUNTIME_UDP_MITM_POLICY_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_UDP_MITM_QUIC_REJECTED_CODE,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;

const DUPLEX_BUFFER_BYTES: usize = 1 << 16;

#[test]
fn h2_session_rewrites_request_and_response_through_bounded_model() {
    let service = Arc::new(H2ContractPluginService::new(H2ContractMode::Rewrite));
    let origin = OriginBehavior::new(StatusCode::OK, b"{\"from\":\"upstream\"}".to_vec())
        .with_header("content-type", "application/json");
    let outcome = run_contract_session(
        session_config(Some(hook(service.clone()))),
        origin,
        vec![
            ClientRequest::new(Method::POST, "https://example.com/resource?q=1")
                .with_header("user-agent", "h2-contract")
                .with_header("cookie", "a=1")
                .with_header("cookie", "b=2")
                .with_body(b"client-body"),
        ],
    );

    let origin_requests = outcome.origin_requests();
    assert_eq!(origin_requests.len(), 1);
    let seen = &origin_requests[0];
    assert_eq!(seen.method, Method::POST);
    assert_eq!(seen.path, "/resource?q=1");
    assert_eq!(seen.authority.as_deref(), Some("example.com"));
    assert_eq!(seen.body, b"rewritten-request");
    assert_eq!(
        header(&seen.headers, "x-networkcore-phase"),
        Some("request")
    );
    assert_eq!(header(&seen.headers, "user-agent"), Some("h2-contract"));
    assert_eq!(
        header(&seen.headers, "content-length"),
        Some("rewritten-request".len().to_string().as_str())
    );
    assert!(seen.headers.get("host").is_none());

    let response = &outcome.client_responses[0];
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"rewritten-response");
    assert_eq!(
        header(&response.headers, "x-networkcore-phase"),
        Some("response")
    );
    assert_eq!(
        header(&response.headers, "content-type"),
        Some("application/json")
    );
    assert_eq!(
        header(&response.headers, "content-length"),
        Some("rewritten-response".len().to_string().as_str())
    );

    let events = service.events();
    let request_event = events
        .iter()
        .find(|event| event.phase == HttpMitmPhase::Request)
        .expect("request phase should reach the plugin");
    assert_eq!(request_event.url, "https://example.com/resource?q=1");
    assert_eq!(request_event.method.as_deref(), Some("POST"));
    assert_eq!(request_event.body, b"client-body");
    assert_eq!(
        metadata(&request_event.headers, "host"),
        Some("example.com")
    );
    assert_eq!(metadata(&request_event.headers, "cookie"), Some("a=1; b=2"));
    let response_event = events
        .iter()
        .find(|event| event.phase == HttpMitmPhase::Response)
        .expect("response phase should reach the plugin");
    assert_eq!(response_event.status_code, Some(200));
    assert_eq!(response_event.body, b"{\"from\":\"upstream\"}");

    let report = &outcome.report;
    assert!(report.session_ready);
    assert!(report.response_written);
    assert_eq!(report.streams_accepted, 1);
    assert_eq!(report.streams_completed, 1);
    assert_eq!(report.streams_rewritten, 1);
    assert_eq!(report.streams_failed, 0);
    assert_has_code(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE,
    );
    assert_has_code(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
    );
    assert_has_code(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE,
    );
}

#[test]
fn h2_session_applies_reject_terminal_action_without_contacting_upstream() {
    let service = Arc::new(H2ContractPluginService::new(H2ContractMode::RejectAds));
    let outcome = run_contract_session(
        session_config(Some(hook(service))),
        OriginBehavior::new(StatusCode::OK, b"origin".to_vec()),
        vec![
            ClientRequest::new(Method::GET, "https://example.com/ads/banner.js"),
            ClientRequest::new(Method::GET, "https://example.com/app.js"),
        ],
    );

    assert_eq!(outcome.client_responses[0].status, StatusCode::FORBIDDEN);
    assert!(outcome.client_responses[0].body.is_empty());
    assert_eq!(outcome.client_responses[1].status, StatusCode::OK);
    assert_eq!(outcome.client_responses[1].body, b"origin");
    let origin_requests = outcome.origin_requests();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].path, "/app.js");
    assert_eq!(outcome.report.streams_completed, 2);
}

#[test]
fn h2_session_relays_oversized_bodies_without_rewrite() {
    let service = Arc::new(H2ContractPluginService::new(H2ContractMode::Rewrite));
    let large_response = vec![b'r'; 4096];
    let large_request = vec![b'q'; 2048];
    let outcome = run_contract_session(
        session_config(Some(hook(service.clone()))).with_max_body_bytes(1024),
        OriginBehavior::new(StatusCode::OK, large_response.clone()),
        vec![
            ClientRequest::new(Method::PUT, "https://example.com/upload").with_body(&large_request),
        ],
    );

    let origin_requests = outcome.origin_requests();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].body, large_request);
    assert!(origin_requests[0]
        .headers
        .get("x-networkcore-phase")
        .is_none());
    let response = &outcome.client_responses[0];
    assert_eq!(response.body, large_response);
    assert!(response.headers.get("x-networkcore-phase").is_none());
    assert!(service.events().is_empty());
    assert_eq!(outcome.report.streams_passthrough, 1);
    assert_eq!(outcome.report.streams_rewritten, 0);
    assert_has_code(
        &outcome.report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_PASSTHROUGH_CODE,
    );
}

#[test]
fn h2_session_refuses_streams_for_another_authority() {
    let service = Arc::new(H2ContractPluginService::new(H2ContractMode::Rewrite));
    let outcome = run_contract_session(
        session_config(Some(hook(service.clone()))),
        OriginBehavior::new(StatusCode::OK, b"origin".to_vec()),
        vec![ClientRequest::new(Method::GET, "https://other.example/")],
    );

    assert_eq!(
        outcome.client_responses[0].status,
        StatusCode::MISDIRECTED_REQUEST
    );
    assert!(outcome.origin_requests().is_empty());
    assert!(service.events().is_empty());
    assert_has_code(
        &outcome.report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_AUTHORITY_MISMATCH_CODE,
    );
}

#[test]
fn h2_session_forwards_request_and_response_trailers() {
    let mut response_trailers = HeaderMap::new();
    response_trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-trailer", HeaderValue::from_static("done"));
    let outcome = run_contract_session(
        session_config(None),
        OriginBehavior::new(StatusCode::OK, b"\0\0\0\0\0".to_vec())
            .with_header("content-type", "application/grpc")
            .with_trailers(response_trailers),
        vec![
            ClientRequest::new(Method::POST, "https://example.com/pkg.Service/Call")
                .with_header("content-type", "application/grpc")
                .with_header("te", "trailers")
                .with_body(b"\0\0\0\0\0")
                .with_trailers(request_trailers),
        ],
    );

    let origin_requests = outcome.origin_requests();
    assert_eq!(header(&origin_requests[0].headers, "te"), Some("trailers"));
    assert_eq!(
        origin_requests[0]
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-request-trailer"))
            .and_then(|value| value.to_str().ok()),
        Some("done")
    );
    let response = &outcome.client_responses[0];
    assert_eq!(
        response
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

#[test]
fn h2_session_spends_stream_budget_then_sends_goaway() {
    let outcome = run_contract_session(
        session_config(None).with_max_streams_per_session(2),
        OriginBehavior::new(StatusCode::NO_CONTENT, Vec::new()),
        vec![
            ClientRequest::new(Method::GET, "https://example.com/1"),
            ClientRequest::new(Method::GET, "https://example.com/2"),
        ],
    );

    assert_eq!(outcome.client_responses.len(), 2);
    assert!(outcome
        .client_responses
        .iter()
        .all(|response| response.status == StatusCode::NO_CONTENT));
    assert_has_code(
        &outcome.report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_LIMIT_REACHED_CODE,
    );
}

#[test]
fn client_hello_alpn_observer_reads_offers_in_client_order() {
    let client_hello = rustls_client_hello(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert_eq!(
        observe_tls_client_hello_alpn_protocols(&client_hello),
        vec!["h2".to_string(), "http/1.1".to_string()]
    );

    let http1_only = rustls_client_hello(vec![b"http/1.1".to_vec()]);
    assert_eq!(
        observe_tls_client_hello_alpn_protocols(&http1_only),
        vec!["http/1.1".to_string()]
    );

    assert!(observe_tls_client_hello_alpn_protocols(&rustls_client_hello(Vec::new())).is_empty());
    assert!(
        observe_tls_client_hello_alpn_protocols(&client_hello[..client_hello.len() / 2]).is_empty()
    );
    assert!(observe_tls_client_hello_alpn_protocols(b"GET / HTTP/1.1\r\n\r\n").is_empty());
}

#[test]
fn udp_quic_to_mitm_hostnames_is_rejected_and_other_udp_is_allowed() {
    let service = H2ContractPluginService::new(H2ContractMode::Rewrite);
    let instance = plugin_instance();

    let rejected = plan_native_udp_mitm_decision("Quic.Example.", 443, &instance, &service);
    assert_eq!(rejected.decision, NativeUdpMitmDecision::RejectQuic);
    assert_has_code(
        &rejected.diagnostics,
        ENGINE_NATIVE_RUNTIME_UDP_MITM_QUIC_REJECTED_CODE,
    );

    let other_host = plan_native_udp_mitm_decision("dns.example", 443, &instance, &service);
    assert_eq!(other_host.decision, NativeUdpMitmDecision::Allow);
    assert_has_code(
        &other_host.diagnostics,
        ENGINE_NATIVE_RUNTIME_UDP_MITM_ALLOWED_CODE,
    );

    let other_port = plan_native_udp_mitm_decision("quic.example", 8443, &instance, &service);
    assert_eq!(other_port.decision, NativeUdpMitmDecision::Allow);
    assert!(other_port.diagnostics.is_empty());

    let failing = plan_native_udp_mitm_decision("policy-error.example", 443, &instance, &service);
    assert_eq!(failing.decision, NativeUdpMitmDecision::Allow);
    assert_has_code(
        &failing.diagnostics,
        ENGINE_NATIVE_RUNTIME_UDP_MITM_POLICY_FAILED_CODE,
    );
    assert_eq!(
        service.hostname_queries(),
        vec![
            "quic.example".to_string(),
            "dns.example".to_string(),
            "policy-error.example".to_string(),
        ]
    );

    let hook = hook(Arc::new(H2ContractPluginService::new(
        H2ContractMode::Rewrite,
    )));
    assert_eq!(
        hook.plan_udp_datagram("quic.example", 443).decision,
        NativeUdpMitmDecision::RejectQuic
    );
}

struct ContractOutcome {
    report: NativeH2MitmSessionReport,
    client_responses: Vec<ClientResponse>,
    origin_requests: Arc<Mutex<Vec<OriginRequest>>>,
}

impl ContractOutcome {
    fn origin_requests(&self) -> Vec<OriginRequest> {
        self.origin_requests
            .lock()
            .expect("origin request log should lock")
            .clone()
    }
}

fn run_contract_session(
    config: NativeH2MitmSessionConfig,
    origin: OriginBehavior,
    requests: Vec<ClientRequest>,
) -> ContractOutcome {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("contract runtime should start");
    runtime.block_on(async move {
        let (client_io, proxy_downstream) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
        let (proxy_upstream, origin_io) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
        let origin_requests = Arc::new(Mutex::new(Vec::new()));
        let origin_task = tokio::spawn(serve_origin(
            origin_io,
            Arc::new(origin),
            Arc::clone(&origin_requests),
        ));
        let client_task = tokio::spawn(run_client(client_io, requests));

        let report = tokio::time::timeout(
            Duration::from_secs(20),
            run_native_h2_mitm_session(proxy_downstream, proxy_upstream, config),
        )
        .await
        .expect("HTTP/2 MITM session should finish");
        let client_responses = client_task.await.expect("contract client should finish");
        origin_task.abort();

        ContractOutcome {
            report,
            client_responses,
            origin_requests,
        }
    })
}

fn session_config(hook: Option<NativeHttpMitmPluginHook>) -> NativeH2MitmSessionConfig {
    NativeH2MitmSessionConfig::new(connect_request(), hook)
        .with_idle_timeout(Duration::from_millis(500))
        .with_stream_timeout(Duration::from_secs(10))
}

fn connect_request() -> NativeExplicitHttpProxyRequest {
    let mut connect =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());
    read_explicit_http_proxy_request(&mut connect)
        .request
        .expect("contract CONNECT request should parse")
}

#[derive(Clone)]
struct ClientRequest {
    method: Method,
    uri: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

impl ClientRequest {
    fn new(method: Method, uri: &'static str) -> Self {
        Self {
            method,
            uri,
            headers: Vec::new(),
            body: Vec::new(),
            trailers: None,
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }

    fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    fn with_trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }
}

#[derive(Debug, Clone)]
struct ClientResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

async fn run_client(io: DuplexStream, requests: Vec<ClientRequest>) -> Vec<ClientResponse> {
    let (mut send_request, connection) = h2::client::handshake(io)
        .await
        .expect("contract client handshake should complete");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut responses = Vec::new();
    for request in requests {
        let mut head = Request::builder()
            .method(request.method.clone())
            .uri(request.uri);
        for (name, value) in &request.headers {
            head = head.header(*name, *value);
        }
        let head = head.body(()).expect("contract request head should build");
        let end_of_stream = request.body.is_empty() && request.trailers.is_none();
        send_request = send_request
            .ready()
            .await
            .expect("contract client should be ready");
        let (response, mut body) = send_request
            .send_request(head, end_of_stream)
            .expect("contract request should send");
        if !end_of_stream {
            body.send_data(
                Bytes::from(request.body.clone()),
                request.trailers.is_none(),
            )
            .expect("contract request body should send");
            if let Some(trailers) = request.trailers.clone() {
                body.send_trailers(trailers)
                    .expect("contract request trailers should send");
            }
        }
        let response = response.await.expect("contract response should arrive");
        let (parts, body) = response.into_parts();
        let (body, trailers) = collect_body(body).await;
        responses.push(ClientResponse {
            status: parts.status,
            headers: parts.headers,
            body,
            trailers,
        });
    }

    drop(send_request);
    let _ = connection_task.await;
    responses
}

struct OriginBehavior {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

impl OriginBehavior {
    fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
            trailers: None,
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }

    fn with_trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }
}

#[derive(Debug, Clone)]
struct OriginRequest {
    method: Method,
    authority: Option<String>,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

async fn serve_origin(
    io: DuplexStream,
    behavior: Arc<OriginBehavior>,
    seen: Arc<Mutex<Vec<OriginRequest>>>,
) {
    let mut connection = h2::server::handshake(io)
        .await
        .expect("contract origin handshake should complete");
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(answer_origin_request(
            request,
            respond,
            Arc::clone(&behavior),
            Arc::clone(&seen),
        ));
    }
}

async fn answer_origin_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    behavior: Arc<OriginBehavior>,
    seen: Arc<Mutex<Vec<OriginRequest>>>,
) {
    let (parts, body) = request.into_parts();
    let (body, trailers) = collect_body(body).await;
    seen.lock()
        .expect("origin request log should lock")
        .push(OriginRequest {
            method: parts.method,
            authority: parts.uri.authority().map(|authority| authority.to_string()),
            path: parts
                .uri
                .path_and_query()
                .map(|path| path.as_str().to_string())
                .unwrap_or_default(),
            headers: parts.headers,
            body,
            trailers,
        });

    let mut response = Response::builder().status(behavior.status);
    for (name, value) in &behavior.headers {
        response = response.header(*name, *value);
    }
    if !behavior.body.is_empty() {
        response = response.header("content-length", behavior.body.len());
    }
    let response = response
        .body(())
        .expect("origin response head should build");
    let end_of_stream = behavior.body.is_empty() && behavior.trailers.is_none();
    let mut send = respond
        .send_response(response, end_of_stream)
        .expect("origin response should send");
    if end_of_stream {
        return;
    }
    send.send_data(
        Bytes::from(behavior.body.clone()),
        behavior.trailers.is_none(),
    )
    .expect("origin response body should send");
    if let Some(trailers) = behavior.trailers.clone() {
        send.send_trailers(trailers)
            .expect("origin response trailers should send");
    }
}

async fn collect_body(mut body: h2::RecvStream) -> (Vec<u8>, Option<HeaderMap>) {
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("contract body chunk should arrive");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    let trailers = body
        .trailers()
        .await
        .expect("contract trailers should arrive");
    (collected, trailers)
}

#[derive(Debug, Clone, Copy)]
enum H2ContractMode {
    Rewrite,
    RejectAds,
}

struct H2ContractPluginService {
    mode: H2ContractMode,
    events: Mutex<Vec<HttpMitmEvent>>,
    hostname_queries: Mutex<Vec<String>>,
}

impl H2ContractPluginService {
    fn new(mode: H2ContractMode) -> Self {
        Self {
            mode,
            events: Mutex::new(Vec::new()),
            hostname_queries: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<HttpMitmEvent> {
        self.events
            .lock()
            .expect("plugin event log should lock")
            .clone()
    }

    fn hostname_queries(&self) -> Vec<String> {
        self.hostname_queries
            .lock()
            .expect("hostname query log should lock")
            .clone()
    }
}

impl MitmPluginService for H2ContractPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
            loaded_source: None,
        })
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn handle_http_mitm_event(
        &self,
        _plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        self.events
            .lock()
            .expect("plugin event log should lock")
            .push(http_event.clone());
        let mut outcome = HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: None,
            audits: Vec::new(),
            diagnostics: Vec::new(),
        };
        match self.mode {
            H2ContractMode::Rewrite => {
                let (phase, body): (&str, &[u8]) = match http_event.phase {
                    HttpMitmPhase::Request => ("request", b"rewritten-request"),
                    HttpMitmPhase::Response => ("response", b"rewritten-response"),
                };
                outcome.header_mutations.push(HttpHeaderMutation {
                    operation: HttpHeaderMutationOperation::Set,
                    name: "X-NetworkCore-Phase".to_string(),
                    value: Some(phase.to_string()),
                });
                outcome.body_mutation = Some(HttpBodyMutation {
                    body: body.to_vec(),
                    truncated: false,
                });
            }
            H2ContractMode::RejectAds => {
                if http_event.phase == HttpMitmPhase::Request && http_event.url.contains("/ads/") {
                    outcome.action = HttpMitmAction::Reject { status_code: 403 };
                }
            }
        }
        Ok(outcome)
    }

    fn evaluate_mitm_hostname(
        &self,
        _plugin_instance: &PluginInstance,
        hostname: &str,
        is_quic: bool,
    ) -> DomainResult<MitmHostnameDecision> {
        self.hostname_queries
            .lock()
            .expect("hostname query log should lock")
            .push(hostname.to_string());
        match hostname {
            "policy-error.example" => Err(control_domain::DomainError::new(
                "contract.policy_error",
                "contract policy error",
            )),
            "quic.example" if is_quic => Ok(MitmHostnameDecision::RejectQuic),
            "quic.example" => Ok(MitmHostnameDecision::Intercept),
            _ => Ok(MitmHostnameDecision::Bypass),
        }
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

fn plugin_instance() -> PluginInstance {
    PluginInstance {
        manifest: PluginManifest {
            id: "networkcore.h2-contract".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Request, HookPoint::Response],
        },
        loaded_source: None,
    }
}

fn hook(service: Arc<H2ContractPluginService>) -> NativeHttpMitmPluginHook {
    NativeHttpMitmPluginHook::new(plugin_instance(), service)
}

fn rustls_client_hello(alpn_protocols: Vec<Vec<u8>>) -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("contract rustls provider should support default versions")
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    let server_name = rustls::pki_types::ServerName::try_from("example.com")
        .expect("contract server name should parse");
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .expect("contract client connection should initialize");
    let mut client_hello = Vec::new();
    connection
        .write_tls(&mut client_hello)
        .expect("contract ClientHello should serialize");
    client_hello
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn metadata<'a>(entries: &'a [control_domain::MetadataEntry], name: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(name))
        .map(|entry| entry.value.as_str())
}

fn assert_has_code(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "expected diagnostic {code} in {diagnostics:#?}"
    );
}
