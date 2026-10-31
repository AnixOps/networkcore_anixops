//! HTTP reverse proxy: each request is matched to a site by its `Host` and
//! to a route by the longest path prefix, then sent to one of the route's
//! upstreams, picked with the forward inbound's balancing, health checks
//! and circuit breaker ([`inbound_forward::balance`]).
//!
//! The proxy speaks HTTP/1.1 to both sides. TLS is the transport's
//! business: wrap the inbound in `tls` (a certificate that covers every
//! site's names, reloaded when its files change) and set
//! `forwarded_proto` to `https`. Upstreams are dialed through the
//! inbound's base outbound, so an origin can sit behind an ANX route.
//!
//! Bodies are relayed as they are framed and never buffered whole.
//! WebSocket and other upgrades are relayed as raw streams after the
//! upstream's `101`. Requests with ambiguous framing (both
//! `Transfer-Encoding` and `Content-Length`, conflicting lengths) are
//! refused with `400`, so they cannot be smuggled to an upstream.
//!
//! Each request gets `X-Forwarded-For` (the client appended), `X-Real-IP`,
//! `X-Forwarded-Proto` and `X-Forwarded-Host`; the `Host` sent upstream is
//! the client's by default.

mod factory;
pub mod http;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::ConnectionContext;
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TcpOutbound};
use inbound_forward::balance::{Lease, Targets};

use crate::http::{copy_body, framing, header, hop_by_hop, tokens, Body, Header, Side};

pub use factory::{ReverseProxyInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "reverse_proxy";

pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);

/// Which names a site answers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HostPattern {
    /// `example.com`
    Exact(String),
    /// `*.example.com`: any name under it, not the bare domain. Holds
    /// `.example.com`.
    Wildcard(String),
    /// `*`: any name, tried after every exact and wildcard site.
    Any,
}

impl HostPattern {
    pub fn parse(value: &str) -> Option<HostPattern> {
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if value == "*" {
            return Some(HostPattern::Any);
        }
        let (wildcard, name) = match value.strip_prefix("*.") {
            Some(rest) => (true, rest.to_string()),
            None => (false, value),
        };
        let valid = !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid {
            return None;
        }
        Some(if wildcard {
            HostPattern::Wildcard(format!(".{name}"))
        } else {
            HostPattern::Exact(name)
        })
    }

    fn rank(&self, host: &str) -> Option<usize> {
        match self {
            HostPattern::Exact(name) => (name == host).then_some(usize::MAX),
            HostPattern::Wildcard(suffix) => {
                host.ends_with(suffix.as_str()).then_some(suffix.len())
            }
            HostPattern::Any => Some(0),
        }
    }
}

/// The `Host` sent upstream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HostHeader {
    /// What the client sent.
    #[default]
    Client,
    /// The upstream's `host:port` as configured.
    Upstream,
    Custom(String),
}

pub struct Route {
    /// `/`, or a prefix without a trailing slash, matched on path segment
    /// boundaries: `/api` takes `/api`, `/api/x` and `/api?q`, not `/apix`.
    pub prefix: String,
    /// Removes `prefix` from the path sent upstream.
    pub strip_prefix: bool,
    pub host_header: HostHeader,
    /// Set on every request to the upstream, replacing what the client
    /// sent under the same names.
    pub set_headers: Vec<(String, String)>,
    pub targets: Arc<Targets>,
}

impl Route {
    fn matches(&self, path: &str) -> bool {
        if self.prefix == "/" {
            return true;
        }
        match path.strip_prefix(self.prefix.as_str()) {
            Some(rest) => rest.is_empty() || rest.starts_with('/') || rest.starts_with('?'),
            None => false,
        }
    }

    fn upstream_path(&self, path: &str) -> String {
        if !self.strip_prefix || self.prefix == "/" {
            return path.to_string();
        }
        let rest = &path[self.prefix.len()..];
        if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        }
    }
}

pub struct Site {
    pub hosts: Vec<HostPattern>,
    /// Longest prefix first.
    pub routes: Vec<Route>,
    /// Answers every request with a `308` to the same URL over https; for
    /// the plain-HTTP listener next to a TLS one.
    pub redirect_https: bool,
}

#[derive(Clone, Debug)]
pub struct Options {
    /// `X-Forwarded-Proto`: `http`, or `https` behind `tls`.
    pub forwarded_proto: &'static str,
    pub max_header_bytes: usize,
    /// How long a client connection may sit between requests.
    pub idle_timeout: Duration,
    /// How long an upstream may take to start its response.
    pub upstream_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            forwarded_proto: "http",
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            upstream_timeout: DEFAULT_UPSTREAM_TIMEOUT,
        }
    }
}

pub struct ReverseProxyInbound {
    sites: Vec<Site>,
    options: Options,
    users: Arc<UserStore>,
}

impl ReverseProxyInbound {
    /// Routes in each site are sorted longest prefix first here.
    pub fn new(mut sites: Vec<Site>, options: Options) -> Self {
        for site in &mut sites {
            site.routes
                .sort_by_key(|route| std::cmp::Reverse(route.prefix.len()));
        }
        Self {
            sites,
            options,
            users: Arc::new(UserStore::new(Some(Box::new(|_| {
                Err("reverse proxy inbounds have no users")
            })))),
        }
    }

    fn site(&self, host: &str) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (index, site) in self.sites.iter().enumerate() {
            for pattern in &site.hosts {
                if let Some(rank) = pattern.rank(host) {
                    if best.is_none_or(|(_, r)| rank > r) {
                        best = Some((index, rank));
                    }
                }
            }
        }
        best.map(|(index, _)| index)
    }

    fn all_targets(&self) -> impl Iterator<Item = &Arc<Targets>> {
        self.sites
            .iter()
            .flat_map(|site| site.routes.iter().map(|route| &route.targets))
    }
}

impl StreamInbound for ReverseProxyInbound {
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
        Box::pin(async { Err(Rejected::close("reverse proxy serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut client = Side::new(stream);
            let mut conn = Conn {
                inbound: self,
                context: &context,
                upstream: None,
            };
            let _ = conn.serve(&mut client).await;
        })
    }

    fn background(&self, outbound: Arc<dyn TcpOutbound>) -> Option<BoxFuture<'static, ()>> {
        let checks: Vec<_> = self
            .all_targets()
            .filter(|targets| targets.health().active)
            .map(|targets| targets.clone().check(outbound.clone()))
            .collect();
        (!checks.is_empty()).then(|| {
            Box::pin(async move {
                futures_util::future::join_all(checks).await;
            }) as BoxFuture<'static, ()>
        })
    }

    fn target_health(&self) -> Option<Vec<engine_inbound::health::TargetHealth>> {
        Some(self.all_targets().flat_map(|t| t.report()).collect())
    }
}

/// A kept-alive upstream connection and the route it was opened for.
struct Upstream {
    site: usize,
    route: usize,
    lease: Lease,
    side: Side,
}

struct Conn<'a, 'c> {
    inbound: &'a ReverseProxyInbound,
    context: &'a ConnectionContext<'c>,
    upstream: Option<Upstream>,
}

/// What the client asked, parsed from its request head.
struct Request {
    method: String,
    target: String,
    keep_alive: bool,
    headers: Vec<Header>,
}

enum Outcome {
    /// Serve the next request on this connection.
    Next,
    Close,
}

impl Conn<'_, '_> {
    async fn serve(&mut self, client: &mut Side) -> io::Result<()> {
        let inbound = self.inbound;
        let options = &inbound.options;
        loop {
            let head = match tokio::time::timeout(
                options.idle_timeout,
                client.read_head(options.max_header_bytes),
            )
            .await
            {
                Err(_) | Ok(Ok(None)) => return Ok(()),
                Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                    self.context.handshake_failed();
                    return respond(client, 431, "Request Header Fields Too Large").await;
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(Some(head))) => head,
            };
            let before = client.written;
            let outcome = self.request(client, &head).await;
            let down = client.written - before;
            self.context.count(None, 0, down);
            match outcome? {
                Outcome::Next => continue,
                Outcome::Close => return Ok(()),
            }
        }
    }

    async fn request(&mut self, client: &mut Side, head: &[u8]) -> io::Result<Outcome> {
        let mut parsed = [httparse::EMPTY_HEADER; http::MAX_HEADERS];
        let mut request = httparse::Request::new(&mut parsed);
        let status = request.parse(head);
        let (method, path, version) = match (status, request.method, request.path, request.version)
        {
            (Ok(httparse::Status::Complete(_)), Some(method), Some(path), Some(version)) => {
                (method.to_string(), path.to_string(), version)
            }
            (Err(httparse::Error::TooManyHeaders), ..) => {
                self.context.handshake_failed();
                respond(client, 431, "Request Header Fields Too Large").await?;
                return Ok(Outcome::Close);
            }
            _ => {
                self.context.handshake_failed();
                respond(client, 400, "Bad Request").await?;
                return Ok(Outcome::Close);
            }
        };
        let headers = http::owned_headers(request.headers);
        let connection = tokens(&headers, "connection");
        let keep_alive = match version {
            1 => !connection.iter().any(|t| t == "close"),
            _ => connection.iter().any(|t| t == "keep-alive"),
        };
        if method == "CONNECT" {
            respond(client, 405, "Method Not Allowed").await?;
            return Ok(Outcome::Close);
        }
        let (host, target) = match split_target(&path, header(&headers, "host")) {
            Some(parts) => parts,
            None => {
                respond(client, 400, "Bad Request").await?;
                return Ok(Outcome::Close);
            }
        };
        let body = match framing(&headers, false) {
            Ok(body) => body,
            Err(_) => {
                respond(client, 400, "Bad Request").await?;
                return Ok(Outcome::Close);
            }
        };
        let Some(site_index) = self.inbound.site(&host_name(&host)) else {
            respond(client, 421, "Misdirected Request").await?;
            return Ok(Outcome::Close);
        };
        let site = &self.inbound.sites[site_index];
        if site.redirect_https {
            let location = format!("https://{}{target}", without_port(&host));
            redirect(client, &location, keep_alive && body == Body::None).await?;
            return Ok(if keep_alive && body == Body::None {
                Outcome::Next
            } else {
                Outcome::Close
            });
        }
        let Some(route_index) = site.routes.iter().position(|r| r.matches(&target)) else {
            respond(client, 404, "Not Found").await?;
            return Ok(if body == Body::None && keep_alive {
                Outcome::Next
            } else {
                Outcome::Close
            });
        };
        let request = Request {
            method,
            target,
            keep_alive,
            headers,
        };
        self.proxy(client, site_index, route_index, &host, request, body)
            .await
    }

    async fn proxy(
        &mut self,
        client: &mut Side,
        site_index: usize,
        route_index: usize,
        host: &str,
        request: Request,
        body: Body,
    ) -> io::Result<Outcome> {
        let inbound = self.inbound;
        let route = &inbound.sites[site_index].routes[route_index];
        let upgrade = tokens(&request.headers, "connection")
            .iter()
            .any(|t| t == "upgrade")
            && header(&request.headers, "upgrade").is_some();
        let peer = self.context.peer.ip().to_canonical();

        // Reuse the kept-alive upstream when this request goes the same way.
        let reused = match self.upstream.take() {
            Some(upstream) if upstream.site == site_index && upstream.route == route_index => {
                Some(upstream)
            }
            _ => None,
        };
        let mut retried = false;
        let mut upstream = match reused {
            Some(upstream) => upstream,
            None => match self.dial(site_index, route_index, peer).await {
                Some(upstream) => upstream,
                None => {
                    respond(client, 502, "Bad Gateway").await?;
                    return Ok(Outcome::Close);
                }
            },
        };
        let was_reused = upstream.side.written > 0;
        let head = upstream_head(
            route,
            &request,
            host,
            upgrade,
            peer,
            self.inbound.options.forwarded_proto,
            &upstream.lease,
        );

        // A kept-alive upstream may have closed meanwhile: a request
        // without a body is sent again once on a fresh connection.
        let response_head = loop {
            let before = upstream.side.written;
            let sent = async {
                upstream.side.write_all(&head).await?;
                copy_body(client, &mut upstream.side, body).await?;
                upstream.side.flush().await
            }
            .await;
            self.context.count(None, upstream.side.written - before, 0);
            let read = match sent {
                Ok(()) => {
                    match tokio::time::timeout(
                        self.inbound.options.upstream_timeout,
                        read_final_head(
                            &mut upstream.side,
                            client,
                            self.inbound.options.max_header_bytes,
                        ),
                    )
                    .await
                    {
                        Ok(read) => read,
                        Err(_) => {
                            upstream.lease.failed();
                            respond(client, 504, "Gateway Timeout").await?;
                            return Ok(Outcome::Close);
                        }
                    }
                }
                Err(error) => Err(error),
            };
            match read {
                Ok(Some(head)) => break head,
                Ok(None) | Err(_) if was_reused && !retried && body == Body::None => {
                    retried = true;
                    match self.dial(site_index, route_index, peer).await {
                        Some(fresh) => upstream = fresh,
                        None => {
                            respond(client, 502, "Bad Gateway").await?;
                            return Ok(Outcome::Close);
                        }
                    }
                }
                _ => {
                    upstream.lease.failed();
                    respond(client, 502, "Bad Gateway").await?;
                    return Ok(Outcome::Close);
                }
            }
        };

        let mut parsed = [httparse::EMPTY_HEADER; http::MAX_HEADERS];
        let mut response = httparse::Response::new(&mut parsed);
        let (code, reason, version) = match response.parse(&response_head) {
            Ok(httparse::Status::Complete(_)) => (
                response.code.unwrap_or(502),
                response.reason.unwrap_or("").to_string(),
                response.version.unwrap_or(1),
            ),
            _ => {
                upstream.lease.failed();
                respond(client, 502, "Bad Gateway").await?;
                return Ok(Outcome::Close);
            }
        };
        let headers = http::owned_headers(response.headers);

        if code == 101 {
            if !upgrade {
                respond(client, 502, "Bad Gateway").await?;
                return Ok(Outcome::Close);
            }
            client
                .write_all(&response_out(code, &reason, &headers, true, false))
                .await?;
            client.flush().await?;
            return self.splice(client, upstream).await;
        }

        let no_body = request.method == "HEAD" || code == 204 || code == 304;
        let body = if no_body {
            Body::None
        } else {
            match framing(&headers, true) {
                Ok(body) => body,
                Err(_) => {
                    respond(client, 502, "Bad Gateway").await?;
                    return Ok(Outcome::Close);
                }
            }
        };
        let upstream_keeps = version == 1
            && !tokens(&headers, "connection").iter().any(|t| t == "close")
            && body != Body::UntilClose;
        let keep_alive = request.keep_alive && body != Body::UntilClose;
        client
            .write_all(&response_out(code, &reason, &headers, false, !keep_alive))
            .await?;
        copy_body(&mut upstream.side, client, body).await?;
        client.flush().await?;
        upstream.lease.succeeded();
        if upstream_keeps {
            self.upstream = Some(upstream);
        }
        Ok(if keep_alive {
            Outcome::Next
        } else {
            Outcome::Close
        })
    }

    async fn dial(&self, site: usize, route: usize, peer: IpAddr) -> Option<Upstream> {
        let targets = &self.inbound.sites[site].routes[route].targets;
        let mut tried = Vec::new();
        loop {
            let lease = targets.pick(peer, &tried)?;
            match self.context.connect(lease.target()).await {
                Ok(stream) => {
                    return Some(Upstream {
                        site,
                        route,
                        lease,
                        side: Side::new(stream),
                    })
                }
                Err(_) => {
                    lease.failed();
                    tried.push(lease.index());
                }
            }
        }
    }

    /// After a `101`: what each side sent past the heads, then raw bytes
    /// both ways until both end.
    async fn splice(&mut self, client: &mut Side, mut upstream: Upstream) -> io::Result<Outcome> {
        upstream.lease.succeeded();
        let early = client.take_buffered();
        upstream.side.write_all(&early).await?;
        let late = upstream.side.take_buffered();
        client.write_all(&late).await?;
        // What reaches the client is counted by the request loop.
        self.context.count(None, early.len() as u64, 0);
        let _ = self
            .context
            .relay(None, &mut client.stream, &mut upstream.side.stream)
            .await;
        Ok(Outcome::Close)
    }
}

/// Reads response heads, passing interim `1xx` ones (but `101`) on to the
/// client, until the final one.
async fn read_final_head(
    upstream: &mut Side,
    client: &mut Side,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        let Some(head) = upstream.read_head(max).await? else {
            return Ok(None);
        };
        let code = head
            .get(9..12)
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.parse::<u16>().ok());
        match code {
            Some(code) if (100..200).contains(&code) && code != 101 => {
                client.write_all(&head).await?;
                client.flush().await?;
            }
            _ => return Ok(Some(head)),
        }
    }
}

/// The request head sent upstream.
fn upstream_head(
    route: &Route,
    request: &Request,
    host: &str,
    upgrade: bool,
    peer: IpAddr,
    proto: &str,
    lease: &Lease,
) -> Vec<u8> {
    let drop: Vec<String> = hop_by_hop(&request.headers);
    let replaced = [
        "host",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-proto",
        "x-forwarded-host",
    ];
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(
        format!(
            "{} {} HTTP/1.1\r\n",
            request.method,
            route.upstream_path(&request.target)
        )
        .as_bytes(),
    );
    let host_value = match &route.host_header {
        HostHeader::Client => host.to_string(),
        HostHeader::Upstream => {
            let target = lease.target();
            match target.host().parse::<std::net::Ipv6Addr>() {
                Ok(_) => format!("[{}]:{}", target.host(), target.port()),
                Err(_) => format!("{}:{}", target.host(), target.port()),
            }
        }
        HostHeader::Custom(value) => value.clone(),
    };
    push_header(&mut out, "Host", host_value.as_bytes());
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if drop.contains(&lower)
            || replaced.contains(&lower.as_str())
            || route
                .set_headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            continue;
        }
        push_header(&mut out, name, value);
    }
    if upgrade {
        if let Some(value) = header(&request.headers, "upgrade") {
            push_header(&mut out, "Upgrade", value);
        }
        push_header(&mut out, "Connection", b"upgrade");
    }
    let forwarded_for = match header(&request.headers, "x-forwarded-for") {
        Some(previous) if !previous.is_empty() => {
            format!("{}, {peer}", String::from_utf8_lossy(previous))
        }
        _ => peer.to_string(),
    };
    push_header(&mut out, "X-Forwarded-For", forwarded_for.as_bytes());
    push_header(&mut out, "X-Real-IP", peer.to_string().as_bytes());
    push_header(&mut out, "X-Forwarded-Proto", proto.as_bytes());
    push_header(&mut out, "X-Forwarded-Host", host.as_bytes());
    for (name, value) in &route.set_headers {
        push_header(&mut out, name, value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The response head sent to the client.
fn response_out(
    code: u16,
    reason: &str,
    headers: &[Header],
    upgrade: bool,
    close: bool,
) -> Vec<u8> {
    let drop = hop_by_hop(headers);
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(format!("HTTP/1.1 {code} {reason}\r\n").as_bytes());
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if drop.contains(&lower) {
            continue;
        }
        push_header(&mut out, name, value);
    }
    if upgrade {
        if let Some(value) = header(headers, "upgrade") {
            push_header(&mut out, "Upgrade", value);
        }
        push_header(&mut out, "Connection", b"upgrade");
    } else if close {
        push_header(&mut out, "Connection", b"close");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn push_header(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    // A value cannot end a header line early.
    out.extend(value.iter().filter(|b| **b != b'\r' && **b != b'\n'));
    out.extend_from_slice(b"\r\n");
}

/// The authority and origin-form target of a request: from the `Host`
/// header, or from an absolute-form target, which wins (RFC 9112 3.2.2).
fn split_target(path: &str, host: Option<&[u8]>) -> Option<(String, String)> {
    let lower = path
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let rest = &path[path.find("://")? + 3..];
        let (authority, target) = match rest.find(['/', '?']) {
            Some(index) if rest.as_bytes()[index] == b'/' => {
                (&rest[..index], rest[index..].to_string())
            }
            Some(index) => (&rest[..index], format!("/{}", &rest[index..])),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        return Some((authority.to_string(), target));
    }
    if !path.starts_with('/') && path != "*" {
        return None;
    }
    let host = std::str::from_utf8(host?).ok()?.trim();
    if host.is_empty() || host.contains(['/', '@', ' ', ',']) {
        return None;
    }
    Some((host.to_string(), path.to_string()))
}

/// An authority without its port; IPv6 keeps its brackets.
fn without_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => &authority[..=end],
            None => authority,
        };
    }
    match authority.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => authority,
    }
}

/// The lowercased name of an authority, without port or IPv6 brackets.
fn host_name(authority: &str) -> String {
    let name = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        match authority.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
            _ => authority,
        }
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

async fn respond(client: &mut Side, code: u16, reason: &str) -> io::Result<()> {
    let body = format!("{code} {reason}\n");
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await?;
    client.write_all(body.as_bytes()).await?;
    client.flush().await
}

async fn redirect(client: &mut Side, location: &str, keep_alive: bool) -> io::Result<()> {
    let mut head = Vec::new();
    head.extend_from_slice(b"HTTP/1.1 308 Permanent Redirect\r\n");
    push_header(&mut head, "Location", location.as_bytes());
    push_header(&mut head, "Content-Length", b"0");
    if !keep_alive {
        push_header(&mut head, "Connection", b"close");
    }
    head.extend_from_slice(b"\r\n");
    client.write_all(&head).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_patterns() {
        assert_eq!(
            HostPattern::parse("Example.COM."),
            Some(HostPattern::Exact("example.com".into()))
        );
        assert_eq!(
            HostPattern::parse("*.example.com"),
            Some(HostPattern::Wildcard(".example.com".into()))
        );
        assert_eq!(HostPattern::parse("*"), Some(HostPattern::Any));
        assert_eq!(HostPattern::parse(""), None);
        assert_eq!(HostPattern::parse("a..b"), None);
        assert_eq!(HostPattern::parse("a b"), None);
        assert_eq!(HostPattern::parse("*.*.b"), None);
    }

    #[test]
    fn ranks_host_patterns() {
        let exact = HostPattern::parse("a.example.com").unwrap();
        let wildcard = HostPattern::parse("*.example.com").unwrap();
        assert!(exact.rank("a.example.com") > wildcard.rank("a.example.com"));
        assert_eq!(wildcard.rank("example.com"), None);
        assert!(wildcard.rank("x.y.example.com").is_some());
        assert!(HostPattern::Any.rank("x") < wildcard.rank("x.example.com"));
    }

    #[test]
    fn splits_targets() {
        assert_eq!(
            split_target("/a?b", Some(b"Example.com:8080")),
            Some(("Example.com:8080".into(), "/a?b".into()))
        );
        assert_eq!(
            split_target("http://h.example/x", Some(b"other")),
            Some(("h.example".into(), "/x".into()))
        );
        assert_eq!(
            split_target("https://h.example?q", None),
            Some(("h.example".into(), "/?q".into()))
        );
        assert_eq!(
            split_target("http://h.example", None),
            Some(("h.example".into(), "/".into()))
        );
        assert_eq!(split_target("/a", None), None);
        assert_eq!(split_target("a", Some(b"h")), None);
        assert_eq!(split_target("/", Some(b"a/b")), None);
        assert_eq!(split_target("http://u@h/", None), None);
    }

    #[test]
    fn names_hosts() {
        assert_eq!(host_name("Example.com:443"), "example.com");
        assert_eq!(host_name("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_name("example.com."), "example.com");
        assert_eq!(without_port("example.com:80"), "example.com");
        assert_eq!(without_port("[2001:db8::1]:80"), "[2001:db8::1]");
        assert_eq!(without_port("example.com"), "example.com");
    }

    fn route(prefix: &str, strip: bool) -> Route {
        use engine_outbound::TargetAddr;
        use inbound_forward::balance::{Health, Strategy, Target};
        Route {
            prefix: prefix.into(),
            strip_prefix: strip,
            host_header: HostHeader::Client,
            set_headers: Vec::new(),
            targets: Arc::new(Targets::new(
                vec![Target {
                    addr: TargetAddr::from_host("127.0.0.1", 80),
                    weight: 1,
                    priority: 0,
                }],
                Strategy::default(),
                Health::default(),
            )),
        }
    }

    #[test]
    fn matches_prefixes_on_segments() {
        let api = route("/api", true);
        assert!(api.matches("/api"));
        assert!(api.matches("/api/x"));
        assert!(api.matches("/api?q=1"));
        assert!(!api.matches("/apix"));
        assert!(!api.matches("/"));
        assert_eq!(api.upstream_path("/api"), "/");
        assert_eq!(api.upstream_path("/api/x?y"), "/x?y");
        assert_eq!(api.upstream_path("/api?q"), "/?q");
        let kept = route("/api", false);
        assert_eq!(kept.upstream_path("/api/x"), "/api/x");
        assert!(route("/", true).matches("*"));
    }

    #[test]
    fn strips_header_injection() {
        let mut out = Vec::new();
        push_header(&mut out, "X-A", b"a\r\nX-B: b");
        assert_eq!(out, b"X-A: aX-B: b\r\n");
    }
}
