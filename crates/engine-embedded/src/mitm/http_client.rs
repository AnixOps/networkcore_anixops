//! `$httpClient` for MITM scripts. Each request opens one connection through
//! the tunnel's dispatcher, so it is routed like any other connection of the
//! device, and sends one HTTP/1.1 request with `Connection: close`. Answers
//! are read up to [`MAX_BODY_BYTES`]; redirects are returned to the script,
//! not followed. Errors are fixed strings without URLs or payloads.
//!
//! Scripts run on the blocking pool; a request is spawned on the tunnel's
//! runtime and the script thread waits for it, so the runtime thread keeps
//! serving the tunnel meanwhile.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use engine_native::{ScriptHttpClient, ScriptHttpClientRequest, ScriptResponse};
use engine_outbound::{TargetAddr, TcpOutbound};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use super::http1::{Body, Conn, Framing, Head};
use super::{remove, response_status, MAX_BODY_BYTES};

const UNAVAILABLE: &str = "networkcore: $httpClient is not available yet";
const INVALID_URL: &str = "networkcore: $httpClient needs an http or https URL";
const CONNECT_FAILED: &str = "networkcore: $httpClient could not connect";
const TIMED_OUT: &str = "networkcore: $httpClient request timed out";
const BAD_RESPONSE: &str = "networkcore: $httpClient got an invalid response";
const TOO_LARGE: &str = "networkcore: $httpClient response is too large";
/// Used when the script left the timeout to the dispatch budget and the
/// runtime passed none.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct TunnelScriptHttpClient {
    outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    tls: Arc<ClientConfig>,
}

impl TunnelScriptHttpClient {
    pub(super) fn new(
        outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
        tls: Arc<ClientConfig>,
    ) -> Self {
        Self { outbound, tls }
    }
}

impl ScriptHttpClient for TunnelScriptHttpClient {
    fn execute(&self, request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String> {
        let outbound = self.outbound.get().cloned().ok_or(UNAVAILABLE)?;
        let handle = tokio::runtime::Handle::try_current().map_err(|_| UNAVAILABLE)?;
        let url = RequestUrl::parse(&request.url).ok_or(INVALID_URL)?;
        let timeout = if request.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            request.timeout
        };
        let tls = self.tls.clone();
        let request = request.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        handle.spawn(async move {
            let result = tokio::time::timeout(timeout, exchange(&*outbound, &tls, &url, &request))
                .await
                .unwrap_or(Err(TIMED_OUT));
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(timeout + Duration::from_secs(1))
            .unwrap_or(Err(TIMED_OUT))
            .map_err(str::to_string)
    }
}

async fn exchange(
    outbound: &dyn TcpOutbound,
    tls: &Arc<ClientConfig>,
    url: &RequestUrl,
    request: &ScriptHttpClientRequest,
) -> Result<ScriptResponse, &'static str> {
    let stream = outbound
        .connect(&url.target())
        .await
        .map_err(|_| CONNECT_FAILED)?;
    if url.tls {
        let server_name = ServerName::try_from(url.host.clone()).map_err(|_| INVALID_URL)?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(server_name, stream)
            .await
            .map_err(|_| CONNECT_FAILED)?;
        send(Conn::new(stream, Vec::new()), url, request).await
    } else {
        send(Conn::new(stream, Vec::new()), url, request).await
    }
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut conn: Conn<S>,
    url: &RequestUrl,
    request: &ScriptHttpClientRequest,
) -> Result<ScriptResponse, &'static str> {
    let body = request.body.as_deref().unwrap_or("").as_bytes();
    let head = request_head(url, request, body.len());
    let io = |_: io::Error| BAD_RESPONSE;
    conn.write_all(&head.encode()).await.map_err(io)?;
    if !body.is_empty() {
        conn.write_all(body).await.map_err(io)?;
    }

    let response = loop {
        let head = conn.read_head().await.map_err(io)?.ok_or(BAD_RESPONSE)?;
        let status = response_status(&head.start_line).map_err(io)?;
        if (100..200).contains(&status) {
            continue;
        }
        break head;
    };
    let status = response_status(&response.start_line).map_err(io)?;
    let no_body = request.method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304;
    let framing = if no_body {
        Framing::Length(0)
    } else if response.header("Transfer-Encoding").is_none()
        && response.header("Content-Length").is_none()
    {
        Framing::UntilClose
    } else {
        response.framing().map_err(io)?
    };
    let body = match conn.read_body(framing, MAX_BODY_BYTES).await.map_err(io)? {
        Body::Complete(body) => body,
        Body::TooLarge(_) => return Err(TOO_LARGE),
    };
    Ok(ScriptResponse {
        status,
        headers: response.headers,
        body: Some(String::from_utf8_lossy(&body).into_owned()),
    })
}

/// The request head: the script's headers, minus the framing and connection
/// headers this client owns.
fn request_head(url: &RequestUrl, request: &ScriptHttpClientRequest, body_len: usize) -> Head {
    let mut headers = request.headers.clone();
    for name in [
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
        "Accept-Encoding",
        "Proxy-Connection",
        "Keep-Alive",
        "TE",
        "Upgrade",
    ] {
        remove(&mut headers, name);
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Host"))
    {
        headers.insert(0, ("Host".to_string(), url.host_header()));
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
    {
        headers.push(("User-Agent".to_string(), "NetworkCore".to_string()));
    }
    headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
    headers.push(("Connection".to_string(), "close".to_string()));
    let method = request.method.to_ascii_uppercase();
    if body_len > 0 || matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        headers.push(("Content-Length".to_string(), body_len.to_string()));
    }
    Head {
        start_line: format!("{method} {} HTTP/1.1", url.path),
        headers,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestUrl {
    tls: bool,
    host: String,
    port: u16,
    /// Path and query, starting with `/`.
    path: String,
}

impl RequestUrl {
    fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else {
            (false, url.strip_prefix("http://")?)
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let (authority, path) = match rest.find(['/', '?']) {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        };
        if authority.contains('@') || path.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return None;
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().ok()?,
                None if after.is_empty() => default_port,
                None => return None,
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), port.parse().ok()?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty()
            || port == 0
            || !host
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':'))
        {
            return None;
        }
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        Some(Self {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    fn target(&self) -> TargetAddr {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, self.port)),
            Err(_) => TargetAddr::Domain(self.host.clone(), self.port),
        }
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::{BoxFuture, BoxStream};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Every connection the canned outbound saw: target and request bytes.
    type Seen = Arc<Mutex<Vec<(TargetAddr, Vec<u8>)>>>;

    #[test]
    fn parses_urls_and_refuses_others() {
        let url = RequestUrl::parse("https://API.example.test/v1?x=1#frag").unwrap();
        assert_eq!(
            url,
            RequestUrl {
                tls: true,
                host: "api.example.test".to_string(),
                port: 443,
                path: "/v1?x=1".to_string(),
            }
        );
        assert_eq!(url.host_header(), "api.example.test");
        let url = RequestUrl::parse("http://[::1]:8080").unwrap();
        assert_eq!(url.path, "/");
        assert_eq!(url.host_header(), "[::1]:8080");
        assert!(matches!(url.target(), TargetAddr::Ip(addr) if addr.port() == 8080));
        for bad in [
            "ftp://example.test/",
            "https://user@example.test/",
            "https://example.test/a b",
            "https://:443/",
            "https://example.test:0/",
        ] {
            assert_eq!(RequestUrl::parse(bad), None, "{bad}");
        }
    }

    /// Answers every connection with one canned response and records the
    /// request bytes it received.
    struct Canned {
        response: &'static [u8],
        seen: Seen,
    }

    impl TcpOutbound for Canned {
        fn protocol(&self) -> &'static str {
            "canned"
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                let response = self.response;
                let seen = self.seen.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = server.read(&mut buf).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                    }
                    seen.lock().unwrap().push((target, request));
                    let _ = server.write_all(response).await;
                    let _ = server.shutdown().await;
                });
                Ok(Box::new(client) as BoxStream)
            })
        }
    }

    fn client(response: &'static [u8]) -> (TunnelScriptHttpClient, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let outbound = Arc::new(OnceLock::new());
        let _ = outbound.set(Arc::new(Canned {
            response,
            seen: seen.clone(),
        }) as Arc<dyn TcpOutbound>);
        (TunnelScriptHttpClient::new(outbound, client_tls()), seen)
    }

    fn request(method: &str, url: &str, body: Option<&str>) -> ScriptHttpClientRequest {
        ScriptHttpClientRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: vec![
                ("X-Script".to_string(), "1".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
            ],
            body: body.map(str::to_string),
            timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn sends_one_request_through_the_outbound_and_reads_the_answer() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (client, seen) = client(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n",
        );
        let response = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    client.execute(&request(
                        "post",
                        "http://api.example.test:8080/v1",
                        Some("x=1"),
                    ))
                })
                .await
            })
            .unwrap()
            .expect("request should succeed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_deref(), Some("{\"a\":1}"));
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "Content-Type" && value == "application/json"));

        let seen = seen.lock().unwrap();
        let (target, bytes) = &seen[0];
        assert_eq!(
            *target,
            TargetAddr::Domain("api.example.test".to_string(), 8080)
        );
        let text = String::from_utf8_lossy(bytes);
        assert!(
            text.starts_with("POST /v1 HTTP/1.1\r\nHost: api.example.test:8080\r\n"),
            "{text}"
        );
        assert!(text.contains("X-Script: 1\r\n"), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("keep-alive"), "{text}");
        assert!(text.contains("Content-Length: 3\r\n"), "{text}");
    }

    #[test]
    fn oversized_answers_and_missing_outbounds_are_errors() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (client, _) = client(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n");
        let result = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    client.execute(&request("GET", "http://big.example.test/", None))
                })
                .await
            })
            .unwrap();
        assert_eq!(result.unwrap_err(), TOO_LARGE);

        let unset = TunnelScriptHttpClient::new(Arc::new(OnceLock::new()), client_tls());
        let result = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    unset.execute(&request("GET", "http://api.example.test/", None))
                })
                .await
            })
            .unwrap();
        assert_eq!(result.unwrap_err(), UNAVAILABLE);
    }

    fn client_tls() -> Arc<ClientConfig> {
        Arc::new(
            transport_tls::client_config(&transport_tls::TlsSettings {
                server_name: String::new(),
                alpn: vec!["http/1.1".to_string()],
                insecure: false,
            })
            .unwrap(),
        )
    }
}
