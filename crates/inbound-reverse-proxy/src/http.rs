//! HTTP/1.1 framing for the proxy: a buffered connection side that reads
//! message heads and copies bodies as they are framed (`Content-Length`,
//! chunked, or until close) without decoding them.

use std::io;

use engine_outbound::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Most headers a request or response may carry.
pub const MAX_HEADERS: usize = 128;

/// Longest chunk-size or trailer line.
const MAX_LINE: usize = 8 * 1024;

const READ_CHUNK: usize = 16 * 1024;

/// One end of a proxied exchange: reads are buffered so a head can be
/// split from what follows it, writes are counted.
pub struct Side {
    pub stream: BoxStream,
    buf: Vec<u8>,
    /// Bytes written to this side.
    pub written: u64,
}

impl Side {
    pub fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            written: 0,
        }
    }

    /// Bytes read from the stream but not consumed yet.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    pub fn take_buffered(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let read = self.stream.read(&mut self.buf[start..]).await;
        let n = *read.as_ref().unwrap_or(&0);
        self.buf.truncate(start + n);
        read
    }

    /// The next message head including its blank line; `None` when the
    /// peer closed before sending any byte of it.
    pub async fn read_head(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        let mut searched = 0;
        loop {
            if let Some(end) = find(&self.buf[searched.saturating_sub(3)..], b"\r\n\r\n") {
                let end = searched.saturating_sub(3) + end + 4;
                let rest = self.buf.split_off(end);
                return Ok(Some(std::mem::replace(&mut self.buf, rest)));
            }
            if self.buf.len() > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
            }
            searched = self.buf.len();
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    /// One line including its CRLF.
    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        let mut searched = 0;
        loop {
            if let Some(end) = find(&self.buf[searched.saturating_sub(1)..], b"\r\n") {
                let end = searched.saturating_sub(1) + end + 2;
                let rest = self.buf.split_off(end);
                return Ok(std::mem::replace(&mut self.buf, rest));
            }
            if self.buf.len() > MAX_LINE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            searched = self.buf.len();
            if self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.written += bytes.len() as u64;
        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }
}

/// How a message body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    None,
    Length(u64),
    Chunked,
    /// Until the sender closes (responses only).
    UntilClose,
}

/// Copies one body from `from` to `to` as it is framed.
pub async fn copy_body(from: &mut Side, to: &mut Side, body: Body) -> io::Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(n) => copy_exact(from, to, n).await,
        Body::Chunked => {
            loop {
                let line = from.read_line().await?;
                to.write_all(&line).await?;
                let size = chunk_size(&line)?;
                if size == 0 {
                    // Trailers, then the final blank line.
                    loop {
                        let line = from.read_line().await?;
                        to.write_all(&line).await?;
                        if line == b"\r\n" {
                            return Ok(());
                        }
                    }
                }
                copy_exact(from, to, size + 2).await?;
            }
        }
        Body::UntilClose => {
            let buffered = from.take_buffered();
            to.write_all(&buffered).await?;
            let mut chunk = vec![0; READ_CHUNK];
            loop {
                let n = from.stream.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                to.write_all(&chunk[..n]).await?;
            }
        }
    }
}

async fn copy_exact(from: &mut Side, to: &mut Side, mut n: u64) -> io::Result<()> {
    while n > 0 {
        if from.buf.is_empty() && from.fill().await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let take = from.buf.len().min(usize::try_from(n).unwrap_or(usize::MAX));
        let rest = from.buf.split_off(take);
        let part = std::mem::replace(&mut from.buf, rest);
        to.write_all(&part).await?;
        n -= take as u64;
    }
    Ok(())
}

fn chunk_size(line: &[u8]) -> io::Result<u64> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "bad chunk size");
    let line = line.strip_suffix(b"\r\n").ok_or_else(invalid)?;
    let size = line.split(|b| *b == b';').next().unwrap_or_default();
    let size = std::str::from_utf8(size).map_err(|_| invalid())?.trim();
    if size.is_empty() || size.len() > 15 {
        return Err(invalid());
    }
    u64::from_str_radix(size, 16).map_err(|_| invalid())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A parsed header: name as sent, value bytes.
pub type Header = (String, Vec<u8>);

pub fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// Comma-separated tokens of every `name` header, lowercased.
pub fn tokens(headers: &[Header], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The body framing of a message from its headers (RFC 9112 6.3). A
/// `Transfer-Encoding` that does not end in chunked, or one together with
/// `Content-Length`, or conflicting lengths are refused: those are how
/// requests get smuggled past a proxy.
pub fn framing(headers: &[Header], until_close: bool) -> Result<Body, &'static str> {
    let codings = tokens(headers, "transfer-encoding");
    let lengths: Vec<&[u8]> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_slice())
        .collect();
    if !codings.is_empty() {
        if !lengths.is_empty() {
            return Err("transfer-encoding with content-length");
        }
        return match codings.last().map(String::as_str) {
            Some("chunked") => Ok(Body::Chunked),
            _ if until_close => Ok(Body::UntilClose),
            _ => Err("transfer-encoding is not chunked"),
        };
    }
    let mut length = None;
    for value in lengths {
        for part in String::from_utf8_lossy(value).split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("bad content-length");
            }
            let n: u64 = part.parse().map_err(|_| "bad content-length")?;
            if length.is_some_and(|l| l != n) {
                return Err("conflicting content-length");
            }
            length = Some(n);
        }
    }
    Ok(match length {
        Some(0) => Body::None,
        Some(n) => Body::Length(n),
        None if until_close => Body::UntilClose,
        None => Body::None,
    })
}

/// Headers that apply to one connection only and are not forwarded, plus
/// any the `Connection` header names.
pub fn hop_by_hop(headers: &[Header]) -> Vec<String> {
    let mut names: Vec<String> = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for token in tokens(headers, "connection") {
        // Never let a client strip the framing headers.
        if token != "content-length" && token != "transfer-encoding" && token != "host" {
            names.push(token);
        }
    }
    names
}

pub fn owned_headers(parsed: &[httparse::Header<'_>]) -> Vec<Header> {
    parsed
        .iter()
        .map(|h| (h.name.to_string(), h.value.to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(list: &[(&str, &str)]) -> Vec<Header> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn frames_bodies() {
        assert_eq!(framing(&h(&[]), false), Ok(Body::None));
        assert_eq!(framing(&h(&[]), true), Ok(Body::UntilClose));
        assert_eq!(
            framing(&h(&[("Content-Length", "12")]), false),
            Ok(Body::Length(12))
        );
        assert_eq!(
            framing(&h(&[("Content-Length", "12, 12")]), false),
            Ok(Body::Length(12))
        );
        assert_eq!(
            framing(&h(&[("Transfer-Encoding", "gzip, chunked")]), false),
            Ok(Body::Chunked)
        );
        assert!(framing(
            &h(&[("Content-Length", "1"), ("Content-Length", "2")]),
            false
        )
        .is_err());
        assert!(framing(&h(&[("Content-Length", "-1")]), false).is_err());
        assert!(framing(&h(&[("Content-Length", "+1")]), false).is_err());
        assert!(framing(
            &h(&[("Transfer-Encoding", "chunked"), ("Content-Length", "3")]),
            false
        )
        .is_err());
        assert!(framing(&h(&[("Transfer-Encoding", "gzip")]), false).is_err());
        assert_eq!(
            framing(&h(&[("Transfer-Encoding", "gzip")]), true),
            Ok(Body::UntilClose)
        );
    }

    #[test]
    fn parses_chunk_sizes() {
        assert_eq!(chunk_size(b"1a\r\n").unwrap(), 26);
        assert_eq!(chunk_size(b"0;ext=1\r\n").unwrap(), 0);
        assert!(chunk_size(b"\r\n").is_err());
        assert!(chunk_size(b"zz\r\n").is_err());
        assert!(chunk_size(b"1a").is_err());
    }

    #[test]
    fn lists_hop_by_hop_headers() {
        let names = hop_by_hop(&h(&[("Connection", "close, X-Secret, Content-Length")]));
        assert!(names.contains(&"x-secret".to_string()));
        assert!(names.contains(&"upgrade".to_string()));
        assert!(!names.contains(&"content-length".to_string()));
    }
}
