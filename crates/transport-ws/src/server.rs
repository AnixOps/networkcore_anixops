//! WebSocket server handshake for inbound protocol crates.
//!
//! [`WsAcceptor::accept`] reads the client's upgrade request from an
//! accepted stream, checks the path (and the `Host` header when configured)
//! and answers `101 Switching Protocols`. The returned stream is the same
//! byte stream the client side gives: data frames in, unmasked binary frames
//! out. Requests for another path, or that are not WebSocket upgrades, get a
//! plain `404` or `400` and fail, so the port looks like an ordinary web
//! server to a prober.
//!
//! Early data: Xray-style clients (`?ed=`) send the first bytes base64url in
//! `Sec-WebSocket-Protocol`; they are returned before the first frame and the
//! header is echoed back, as Xray and sing-box servers do.

use std::io;

use base64::Engine as _;
use engine_outbound::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{accept_value, invalid, is_header_safe, protocol_error, Role, WsStream};

/// Longest upgrade request head accepted from a client.
pub const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
/// Early data accepted in the handshake unless configured otherwise.
pub const DEFAULT_MAX_EARLY_DATA: usize = 8 * 1024;
pub const DEFAULT_EARLY_DATA_HEADER: &str = "Sec-WebSocket-Protocol";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsServerSettings {
    /// Request path, `/` when empty. The query string is ignored.
    pub path: String,
    /// Required `Host` header (port ignored); any host when empty.
    pub host: String,
    /// Largest early data taken from the handshake; 0 turns it off.
    pub max_early_data: usize,
    /// Header that carries early data.
    pub early_data_header_name: String,
}

impl Default for WsServerSettings {
    fn default() -> Self {
        Self {
            path: "/".to_owned(),
            host: String::new(),
            max_early_data: DEFAULT_MAX_EARLY_DATA,
            early_data_header_name: DEFAULT_EARLY_DATA_HEADER.to_owned(),
        }
    }
}

pub struct WsAcceptor {
    path: String,
    host: String,
    max_early_data: usize,
    early_data_header: String,
}

impl WsAcceptor {
    pub fn new(settings: &WsServerSettings) -> io::Result<Self> {
        let path = if settings.path.is_empty() {
            "/"
        } else {
            settings.path.as_str()
        };
        if !path.starts_with('/') || !is_header_safe(path) || path.contains(' ') {
            return Err(invalid("websocket path is invalid"));
        }
        let path = path.split('?').next().unwrap_or(path);
        if !is_header_safe(&settings.host) || settings.host.contains(' ') {
            return Err(invalid("websocket host is invalid"));
        }
        let header = if settings.early_data_header_name.is_empty() {
            DEFAULT_EARLY_DATA_HEADER
        } else {
            settings.early_data_header_name.as_str()
        };
        if !header
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid("websocket early data header is invalid"));
        }
        Ok(Self {
            path: path.to_owned(),
            host: settings.host.to_ascii_lowercase(),
            max_early_data: settings.max_early_data,
            early_data_header: header.to_ascii_lowercase(),
        })
    }

    /// Runs the server side of the opening handshake on `transport`.
    pub async fn accept(&self, mut transport: BoxStream) -> io::Result<BoxStream> {
        let (head, rest) = read_head(&mut transport).await?;
        let request = match Request::parse(&head) {
            Some(request) => request,
            None => {
                let _ = respond(&mut transport, "400 Bad Request").await;
                return Err(protocol_error("websocket request is malformed"));
            }
        };
        if request.path != self.path || !self.host_matches(request.header("host")) {
            let _ = respond(&mut transport, "404 Not Found").await;
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "websocket request is for another path or host",
            ));
        }
        let key = request
            .header("sec-websocket-key")
            .filter(|key| {
                base64::engine::general_purpose::STANDARD
                    .decode(key)
                    .is_ok_and(|key| key.len() == 16)
            })
            .filter(|_| request.is_upgrade());
        let Some(key) = key else {
            let _ = respond(&mut transport, "400 Bad Request").await;
            return Err(protocol_error("request is not a websocket upgrade"));
        };

        let offered = request.header(&self.early_data_header);
        let early = offered
            .filter(|_| self.max_early_data > 0)
            .and_then(decode_early_data)
            .filter(|data| data.len() <= self.max_early_data)
            .unwrap_or_default();
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n",
            accept_value(key)
        );
        // Clients that offered a subprotocol expect it back.
        if let Some(protocol) = request.header("sec-websocket-protocol") {
            response.push_str("Sec-WebSocket-Protocol: ");
            response.push_str(protocol);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        transport.write_all(response.as_bytes()).await?;
        transport.flush().await?;

        let mut stream = WsStream::new(transport, Role::Server);
        stream.early = early;
        stream.rbuf = rest;
        Ok(Box::new(stream))
    }

    fn host_matches(&self, host: Option<&str>) -> bool {
        if self.host.is_empty() {
            return true;
        }
        let Some(host) = host else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        if host == self.host {
            return true;
        }
        // `name:port` or `[v6]:port`.
        host.rsplit_once(':').is_some_and(|(name, port)| {
            name == self.host && port.bytes().all(|b| b.is_ascii_digit())
        })
    }
}

/// Base64url without padding, as Xray sends it; padded and standard
/// alphabets are accepted too.
fn decode_early_data(value: &str) -> Option<Vec<u8>> {
    let value = value.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .ok()
}

/// Reads up to the end of the request head; returns the head and the bytes
/// read after it.
async fn read_head(stream: &mut BoxStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let rest = buf.split_off(end);
            return Ok((buf, rest));
        }
        if buf.len() >= MAX_REQUEST_HEAD_BYTES {
            return Err(protocol_error("websocket request head is too long"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

async fn respond(stream: &mut BoxStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    stream.shutdown().await
}

struct Request<'a> {
    path: &'a str,
    /// Lowercased names.
    headers: Vec<(String, &'a str)>,
}

impl<'a> Request<'a> {
    fn parse(head: &'a [u8]) -> Option<Self> {
        let text = std::str::from_utf8(head).ok()?;
        let mut lines = text.split("\r\n");
        let mut request_line = lines.next()?.split(' ');
        let (method, target, version) = (
            request_line.next()?,
            request_line.next()?,
            request_line.next()?,
        );
        if method != "GET" || version != "HTTP/1.1" || request_line.next().is_some() {
            return None;
        }
        let path = target.split('?').next()?;
        let mut headers = Vec::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':')?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim()));
        }
        Some(Self { path, headers })
    }

    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| *value)
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(header, _)| header == name)
            .flat_map(|(_, value)| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }

    fn is_upgrade(&self) -> bool {
        self.has_token("upgrade", "websocket")
            && self.has_token("connection", "upgrade")
            && self.header("sec-websocket-version") == Some("13")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_paths_and_headers() {
        let head = b"GET /ws?ed=2048 HTTP/1.1\r\nHost: a.example:443\r\nUpgrade: websocket\r\n\
                     Connection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let request = Request::parse(head).unwrap();
        assert_eq!(request.path, "/ws");
        assert_eq!(request.header("host"), Some("a.example:443"));
        assert!(request.is_upgrade());
        assert!(Request::parse(b"POST /ws HTTP/1.1\r\n\r\n").is_none());
        assert!(Request::parse(b"\x16\x03\x01\x02\x00\r\n\r\n").is_none());

        let acceptor = WsAcceptor::new(&WsServerSettings {
            host: "A.example".into(),
            ..WsServerSettings::default()
        })
        .unwrap();
        assert!(acceptor.host_matches(Some("a.example:443")));
        assert!(acceptor.host_matches(Some("a.EXAMPLE")));
        assert!(!acceptor.host_matches(Some("b.example")));
        assert!(!acceptor.host_matches(None));
    }

    #[test]
    fn early_data_decodes_xray_and_padded_forms() {
        assert_eq!(decode_early_data("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_early_data("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_early_data("-_8").unwrap(), [0xfb, 0xff]);
        assert!(decode_early_data("not base64!").is_none());
    }
}
