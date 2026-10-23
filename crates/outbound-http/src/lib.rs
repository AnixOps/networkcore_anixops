//! HTTP proxy TCP outbound: `CONNECT host:port` through an upstream HTTP
//! proxy, optionally over TLS (an HTTPS proxy) and with Basic credentials.
//!
//! The response head is read one byte at a time up to its blank line, so the
//! target's first bytes stay in the stream; the head is small and read once
//! per connection.
//!
//! [`HttpFactory`] registers the outbound under `"type": "http"`.

mod factory;

use std::io;
use std::sync::Arc;

use base64::Engine as _;
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use transport_tls::{TlsConnector, TlsSettings};

pub use factory::{HttpFactory, TYPE_NAME};

pub const PROTOCOL: &str = "http";

/// Longest response head accepted from the proxy.
pub const MAX_RESPONSE_HEAD_BYTES: usize = 8 * 1024;

/// Username and password for `Proxy-Authorization: Basic`. Has no `Debug` on
/// purpose.
#[derive(Clone)]
pub struct HttpCredentials {
    pub username: String,
    pub password: String,
}

pub struct HttpOutbound {
    server: String,
    port: u16,
    /// Pre-built `Proxy-Authorization` header line, CRLF included.
    authorization: Option<String>,
    tls: Option<TlsConnector>,
    dialer: Arc<dyn Dialer>,
}

impl HttpOutbound {
    /// `tls` makes this an HTTPS proxy: the CONNECT request goes over TLS.
    pub fn new(
        server: impl Into<String>,
        port: u16,
        credentials: Option<HttpCredentials>,
        tls: Option<&TlsSettings>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("http proxy server address is empty"));
        }
        let authorization = match credentials {
            Some(credentials) => {
                if credentials.username.is_empty() || credentials.username.contains(':') {
                    return Err(invalid("http proxy username is empty or contains ':'"));
                }
                let token = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", credentials.username, credentials.password));
                Some(format!("Proxy-Authorization: Basic {token}\r\n"))
            }
            None => None,
        };
        Ok(Self {
            server,
            port,
            authorization,
            tls: tls.map(TlsConnector::new).transpose()?,
            dialer,
        })
    }
}

impl TcpOutbound for HttpOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let request = connect_request(target, self.authorization.as_deref())?;
            let transport = self.dialer.dial(&self.server, self.port).await?;
            let mut stream = match &self.tls {
                Some(tls) => tls.connect(transport).await?,
                None => transport,
            };
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            read_response(&mut stream).await?;
            Ok(stream)
        })
    }
}

fn connect_request(target: &TargetAddr, authorization: Option<&str>) -> io::Result<String> {
    if let TargetAddr::Domain(domain, _) = target {
        let clean = !domain.is_empty()
            && domain
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'@');
        if !clean {
            return Err(invalid("http proxy target domain is invalid"));
        }
    }
    // `TargetAddr` puts IPv6 addresses in brackets, as authority-form needs.
    let authority = target.to_string();
    Ok(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
        authorization.unwrap_or_default()
    ))
}

async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD_BYTES {
            return Err(protocol_error("http proxy response head is too long"));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let status_line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    let mut parts = status_line.split(|byte| *byte == b' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with(b"HTTP/1.") {
        return Err(protocol_error("http proxy sent a malformed response"));
    }
    match parts.next().unwrap_or_default() {
        b"200" => Ok(()),
        b"407" => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "http proxy requires or rejected the credentials",
        )),
        code if code.len() == 3 && code.iter().all(u8::is_ascii_digit) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "http proxy could not connect to the target",
        )),
        _ => Err(protocol_error("http proxy sent a malformed response")),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
