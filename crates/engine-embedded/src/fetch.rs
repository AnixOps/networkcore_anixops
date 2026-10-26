//! Downloads through an outbound: the plain HTTP/1.1 GET remote rule sets
//! use to refresh while the engine runs.
//!
//! One request per connection, `Connection: close`, no redirects and no
//! compression; the body ends at `Content-Length`, the last chunk of a
//! chunked answer, or the end of the stream. Errors are fixed codes without
//! URLs or payloads.

use std::io;
use std::time::Duration;

use engine_outbound::{BoxStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::delay::{tls_for, ProbeUrl};

/// Longest response head accepted.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Why a download failed, as a stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    InvalidUrl,
    Timeout,
    ConnectFailed,
    /// The answer was not HTTP/1.x or its framing was broken.
    BadResponse,
    /// An answer other than 200.
    Status,
    TooLarge,
}

impl FetchError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::Timeout => "timeout",
            Self::ConnectFailed => "connect_failed",
            Self::BadResponse => "bad_response",
            Self::Status => "http_status",
            Self::TooLarge => "too_large",
        }
    }
}

/// The body of a `200` answer to a GET of `url` through `outbound`, at most
/// `max_bytes` long, within `timeout`.
pub async fn fetch(
    outbound: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchError> {
    let url = ProbeUrl::parse(url).ok_or(FetchError::InvalidUrl)?;
    let tls = tls_for(&url).map_err(|_| FetchError::InvalidUrl)?;
    let exchange = async {
        let mut stream: BoxStream = outbound
            .connect(&url.target())
            .await
            .map_err(|_| FetchError::ConnectFailed)?;
        if let Some(tls) = &tls {
            stream = tls
                .connect(stream)
                .await
                .map_err(|_| FetchError::ConnectFailed)?;
        }
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: networkcore\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            url.path,
            url.host_header()
        );
        let io = |_: io::Error| FetchError::BadResponse;
        stream.write_all(request.as_bytes()).await.map_err(io)?;
        stream.flush().await.map_err(io)?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read = match stream.read(&mut buf).await {
                Ok(read) => read,
                // Many servers reset instead of closing TLS cleanly; what
                // arrived is judged by its framing below.
                Err(_) if !raw.is_empty() => 0,
                Err(_) => return Err(FetchError::BadResponse),
            };
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..read]);
            if raw.len() > MAX_HEAD_BYTES + max_bytes {
                return Err(FetchError::TooLarge);
            }
        }
        parse_response(&raw, max_bytes)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .unwrap_or(Err(FetchError::Timeout))
}

/// The body of a complete HTTP/1.x `200` response.
fn parse_response(raw: &[u8], max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(FetchError::BadResponse)?;
    if head_end > MAX_HEAD_BYTES {
        return Err(FetchError::BadResponse);
    }
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| FetchError::BadResponse)?;
    let body = &raw[head_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.") {
        return Err(FetchError::BadResponse);
    }
    match status.split(' ').nth(1) {
        Some("200") => {}
        Some(code) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
            return Err(FetchError::Status)
        }
        _ => return Err(FetchError::BadResponse),
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| FetchError::BadResponse)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else if let Some(length) = length {
        if body.len() < length {
            return Err(FetchError::BadResponse);
        }
        body[..length].to_vec()
    } else {
        body.to_vec()
    };
    if body.len() > max_bytes {
        return Err(FetchError::TooLarge);
    }
    Ok(body)
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(FetchError::BadResponse)?;
        let size = std::str::from_utf8(&body[..line_end]).map_err(|_| FetchError::BadResponse)?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| FetchError::BadResponse)?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err(FetchError::BadResponse);
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_follow_their_framing() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello trailing";
        assert_eq!(parse_response(plain, 64).unwrap(), b"hello");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked, 64).unwrap(), b"abcde");
        let until_close = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(parse_response(until_close, 64).unwrap(), b"all of it");
    }

    #[test]
    fn bad_answers_are_classified() {
        assert_eq!(
            parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n", 64),
            Err(FetchError::Status)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort", 64),
            Err(FetchError::BadResponse)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\ntoo long", 3),
            Err(FetchError::TooLarge)
        );
        assert_eq!(
            parse_response(b"SSH-2.0\r\n\r\n", 64),
            Err(FetchError::BadResponse)
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                64
            ),
            Err(FetchError::BadResponse)
        );
    }
}
