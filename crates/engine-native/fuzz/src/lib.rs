//! Shared harness for the engine-native HTTP/2 MITM fuzz targets.
//!
//! Each input runs one `run_native_h2_mitm_session` over in-memory duplex
//! pipes: a fuzz-driven client on one side and a small HTTP/2 origin that
//! echoes request bodies on the other. The session uses a small body bound so
//! inputs reach both the rewrite and the passthrough paths.

use arbitrary::Arbitrary;
use bytes::Bytes;
use control_domain::{GrantedPermissions, MitmPluginService};
use engine_native::{
    read_explicit_http_proxy_request, run_native_h2_mitm_session, NativeH2MitmSessionConfig,
    NativeHttpMitmPluginHook,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response};
use mitm_policy::{builtin_ad_block_plugin_package, AnixOpsMitmPluginService};
use std::future::Future;
use std::io::Cursor;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::DuplexStream;

pub const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A host the built-in ad block plugin rewrites, so request paths reach its
/// reject and rewrite rules.
const FUZZ_CONNECT_HOST: &str = "pubads.g.doubleclick.net";
const DUPLEX_BUFFER_BYTES: usize = 1 << 16;
const FUZZ_MAX_BODY_BYTES: usize = 256;
const FUZZ_MAX_REQUESTS: usize = 8;
const FUZZ_SESSION_DEADLINE: Duration = Duration::from_secs(5);
const FUZZ_IDLE_TIMEOUT: Duration = Duration::from_millis(50);
const FUZZ_STREAM_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Arbitrary)]
pub struct FuzzSession {
    pub requests: Vec<FuzzRequest>,
}

#[derive(Debug, Arbitrary)]
pub struct FuzzRequest {
    pub method: u8,
    pub path: String,
    pub foreign_authority: bool,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub trailer: Option<(String, String)>,
}

/// Runs one MITM session with `client` driving the decrypted client side.
pub fn run_session<C, F>(client: C)
where
    C: FnOnce(DuplexStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime should start");
    runtime.block_on(async move {
        let (client_io, proxy_downstream) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
        let (proxy_upstream, origin_io) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
        let origin = tokio::spawn(serve_echo_origin(origin_io));
        let client = tokio::spawn(client(client_io));
        let config = NativeH2MitmSessionConfig::new(connect_request(), Some(policy_hook()))
            .with_max_body_bytes(FUZZ_MAX_BODY_BYTES)
            .with_idle_timeout(FUZZ_IDLE_TIMEOUT)
            .with_stream_timeout(FUZZ_STREAM_TIMEOUT);
        let _ = tokio::time::timeout(
            FUZZ_SESSION_DEADLINE,
            run_native_h2_mitm_session(proxy_downstream, proxy_upstream, config),
        )
        .await;
        client.abort();
        origin.abort();
    });
}

/// Sends the fuzzed requests as a well-formed HTTP/2 client, skipping any
/// request head the `http` crate refuses to build.
pub async fn send_fuzz_requests(io: DuplexStream, session: FuzzSession) {
    let Ok((mut send_request, connection)) = h2::client::handshake(io).await else {
        return;
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    for request in session.requests.into_iter().take(FUZZ_MAX_REQUESTS) {
        let Some(head) = fuzz_request_head(&request) else {
            continue;
        };
        let Ok(ready) = send_request.ready().await else {
            break;
        };
        send_request = ready;
        let end_of_stream = request.body.is_empty() && request.trailer.is_none();
        let Ok((response, mut body)) = send_request.send_request(head, end_of_stream) else {
            break;
        };
        if !end_of_stream {
            let has_trailer = request.trailer.is_some();
            if body
                .send_data(Bytes::from(request.body), !has_trailer)
                .is_err()
            {
                continue;
            }
            if let Some((name, value)) = request.trailer {
                let mut trailers = HeaderMap::new();
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    trailers.insert(name, value);
                }
                let _ = body.send_trailers(trailers);
            }
        }
        let Ok(Ok(response)) = tokio::time::timeout(FUZZ_STREAM_TIMEOUT, response).await else {
            continue;
        };
        let mut body = response.into_body();
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
        }
    }

    drop(send_request);
    let _ = tokio::time::timeout(FUZZ_STREAM_TIMEOUT, driver).await;
}

fn fuzz_request_head(request: &FuzzRequest) -> Option<Request<()>> {
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"];
    let method =
        Method::from_bytes(METHODS[usize::from(request.method) % METHODS.len()].as_bytes()).ok()?;
    let authority = if request.foreign_authority {
        "other.example"
    } else {
        FUZZ_CONNECT_HOST
    };
    let path = if request.path.starts_with('/') {
        request.path.clone()
    } else {
        format!("/{}", request.path)
    };
    let mut head = Request::builder()
        .method(method)
        .uri(format!("https://{authority}{path}"))
        .body(())
        .ok()?;
    for (name, value) in &request.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            head.headers_mut().append(name, value);
        }
    }
    Some(head)
}

async fn serve_echo_origin(io: DuplexStream) {
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(echo_origin_request(request, respond));
    }
}

async fn echo_origin_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let mut body = request.into_body();
    let mut echoed = Vec::new();
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
        echoed.extend_from_slice(&chunk);
    }
    let Ok(response) = Response::builder()
        .status(200)
        .header("content-type", "text/plain")
        .header("content-length", echoed.len())
        .body(())
    else {
        return;
    };
    let end_of_stream = echoed.is_empty();
    if let Ok(mut send) = respond.send_response(response, end_of_stream) {
        if !end_of_stream {
            let _ = send.send_data(Bytes::from(echoed), true);
        }
    }
}

fn connect_request() -> engine_native::NativeExplicitHttpProxyRequest {
    let mut connect = Cursor::new(
        format!(
            "CONNECT {FUZZ_CONNECT_HOST}:443 HTTP/1.1\r\nHost: {FUZZ_CONNECT_HOST}:443\r\n\r\n"
        )
        .into_bytes(),
    );
    read_explicit_http_proxy_request(&mut connect)
        .request
        .expect("fuzz CONNECT request should parse")
}

fn policy_hook() -> NativeHttpMitmPluginHook {
    static HOOK: OnceLock<NativeHttpMitmPluginHook> = OnceLock::new();
    HOOK.get_or_init(|| {
        let package = builtin_ad_block_plugin_package();
        let service = AnixOpsMitmPluginService::new();
        let instance = service
            .load(
                &package,
                &GrantedPermissions {
                    permissions: package.manifest.permissions.clone(),
                },
            )
            .expect("built-in ad block plugin should load");
        NativeHttpMitmPluginHook::new(instance, Arc::new(service))
    })
    .clone()
}
