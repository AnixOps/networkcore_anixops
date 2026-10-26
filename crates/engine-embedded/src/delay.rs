//! URL delay tests for desktop node lists, like a Clash `url-test`: the time
//! an outbound takes to connect to an HTTP(S) URL and return the first line of
//! its response.
//!
//! The test builds its own outbound from a config envelope, so a node can be
//! measured whether or not the local proxy runs, and it never goes through
//! the system proxy.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{BoxStream, Dialer, TargetAddr, TcpDialer, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport_tls::{TlsConnector, TlsSettings};

use crate::config::RuntimeConfig;
use crate::{protocols, RuntimeError};

/// Why a delay test failed. Fixed text, no node values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelayError {
    Config(RuntimeError),
    InvalidUrl,
    Timeout,
    /// The outbound, TLS or HTTP exchange failed.
    Failed(io::ErrorKind),
    /// The server answered with something other than HTTP/1.x.
    NotHttp,
}

impl fmt::Display for DelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelayError::Config(error) => write!(f, "delay test config rejected: {error}"),
            DelayError::InvalidUrl => f.write_str("delay test URL must be an http or https URL"),
            DelayError::Timeout => f.write_str("delay test timed out"),
            DelayError::Failed(kind) => write!(f, "delay test failed: {kind}"),
            DelayError::NotHttp => f.write_str("delay test response was not HTTP"),
        }
    }
}

impl std::error::Error for DelayError {}

/// Measures `url` through the outbound of `config` (an engine envelope).
pub fn measure_delay(config: &[u8], url: &str, timeout: Duration) -> Result<Duration, DelayError> {
    measure_delay_with(
        config,
        url,
        timeout,
        &protocols::default_registry(),
        Arc::new(TcpDialer),
    )
}

pub fn measure_delay_with(
    config: &[u8],
    url: &str,
    timeout: Duration,
    registry: &OutboundRegistry,
    dialer: Arc<dyn Dialer>,
) -> Result<Duration, DelayError> {
    let url = ProbeUrl::parse(url).ok_or(DelayError::InvalidUrl)?;
    let config = RuntimeConfig::from_json(config).map_err(DelayError::Config)?;
    let outbound = config
        .build_outbound(registry, dialer)
        .map_err(DelayError::Config)?;
    let tls = tls_for(&url)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| DelayError::Failed(error.kind()))?;
    runtime.block_on(timed_fetch(&*outbound, tls.as_ref(), &url, timeout))
}

/// Measures `url` through `outbound` on the caller's runtime, as policy group
/// health checks do.
pub async fn probe(
    outbound: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
) -> Result<Duration, DelayError> {
    let url = ProbeUrl::parse(url).ok_or(DelayError::InvalidUrl)?;
    let tls = tls_for(&url)?;
    timed_fetch(outbound, tls.as_ref(), &url, timeout).await
}

pub(crate) fn tls_for(url: &ProbeUrl) -> Result<Option<TlsConnector>, DelayError> {
    if !url.tls {
        return Ok(None);
    }
    TlsConnector::new(&TlsSettings {
        server_name: url.host.clone(),
        alpn: vec!["http/1.1".to_string()],
        insecure: false,
    })
    .map(Some)
    .map_err(|_| DelayError::InvalidUrl)
}

async fn timed_fetch(
    outbound: &dyn TcpOutbound,
    tls: Option<&TlsConnector>,
    url: &ProbeUrl,
    timeout: Duration,
) -> Result<Duration, DelayError> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, fetch_status_line(outbound, tls, url)).await {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(DelayError::Timeout),
    }
}

async fn fetch_status_line(
    outbound: &dyn TcpOutbound,
    tls: Option<&TlsConnector>,
    url: &ProbeUrl,
) -> Result<(), DelayError> {
    let failed = |error: io::Error| DelayError::Failed(error.kind());
    let mut stream: BoxStream = outbound.connect(&url.target()).await.map_err(failed)?;
    if let Some(tls) = tls {
        stream = tls.connect(stream).await.map_err(failed)?;
    }
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: networkcore-delay\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    );
    stream.write_all(request.as_bytes()).await.map_err(failed)?;
    stream.flush().await.map_err(failed)?;
    // "HTTP/1.1 204" is enough to know the server answered.
    let mut status = [0u8; 12];
    let mut filled = 0;
    while filled < status.len() {
        let read = stream.read(&mut status[filled..]).await.map_err(failed)?;
        if read == 0 {
            return Err(DelayError::Failed(io::ErrorKind::UnexpectedEof));
        }
        filled += read;
    }
    if !status.starts_with(b"HTTP/1.") || !status[9..].iter().all(u8::is_ascii_digit) {
        return Err(DelayError::NotHttp);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProbeUrl {
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Path and query, starting with `/`.
    pub(crate) path: String,
}

impl ProbeUrl {
    pub(crate) fn parse(url: &str) -> Option<Self> {
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
        if authority.contains('@') || path.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        let default_port = default_port(tls);
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            match after {
                "" => (host, default_port),
                _ => (host, after.strip_prefix(':')?.parse().ok()?),
            }
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, port.parse().ok()?),
                None => (authority, default_port),
            }
        };
        if host.is_empty()
            || port == 0
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        {
            return None;
        }
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Some(Self {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    pub(crate) fn target(&self) -> TargetAddr {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, self.port)),
            Err(_) => TargetAddr::Domain(self.host.clone(), self.port),
        }
    }

    pub(crate) fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port(self.tls) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn default_port(tls: bool) -> u16 {
    if tls {
        443
    } else {
        80
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_into_target_and_request_line() {
        let url = ProbeUrl::parse("https://www.gstatic.com/generate_204").unwrap();
        assert_eq!(
            url,
            ProbeUrl {
                tls: true,
                host: "www.gstatic.com".into(),
                port: 443,
                path: "/generate_204".into(),
            }
        );
        assert_eq!(url.host_header(), "www.gstatic.com");

        let url = ProbeUrl::parse("http://Example.com:8080?x=1#frag").unwrap();
        assert_eq!(url.path, "/?x=1");
        assert_eq!(url.host_header(), "example.com:8080");
        assert_eq!(url.target(), TargetAddr::Domain("example.com".into(), 8080));

        let url = ProbeUrl::parse("http://[::1]:81/").unwrap();
        assert_eq!(url.host_header(), "[::1]:81");
        assert_eq!(url.target(), TargetAddr::Ip("[::1]:81".parse().unwrap()));
        assert_eq!(ProbeUrl::parse("http://1.1.1.1").unwrap().path, "/");
    }

    #[test]
    fn unusable_urls_are_rejected() {
        for url in [
            "ftp://example.com/",
            "example.com",
            "http://",
            "http://user:pass@example.com/",
            "http://example.com:0/",
            "http://example.com:99999/",
            "http://exa mple.com/",
            "http://[not-ip]/",
            "http://example.com/a b",
        ] {
            assert!(ProbeUrl::parse(url).is_none(), "{url}");
        }
    }
}
