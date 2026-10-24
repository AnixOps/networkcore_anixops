//! Minimal HTTP/1.1 framing for decrypted MITM flows: message heads, bodies
//! framed by `Content-Length`, chunked coding or connection close, all with
//! hard size limits. Bytes read past a message stay buffered for the next one.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message head (start line plus headers).
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const READ_CHUNK: usize = 8 * 1024;

pub struct Head {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }

    /// How the body that follows this head is delimited.
    pub fn framing(&self) -> io::Result<Framing> {
        if self.has_token("Transfer-Encoding", "chunked") {
            return Ok(Framing::Chunked);
        }
        if self.header("Transfer-Encoding").is_some() {
            return Err(invalid("unsupported transfer coding"));
        }
        match self.header("Content-Length") {
            Some(length) => length
                .trim()
                .parse::<usize>()
                .map(Framing::Length)
                .map_err(|_| invalid("invalid content length")),
            None => Ok(Framing::Length(0)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(self.start_line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        for (key, value) in &self.headers {
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Length(usize),
    Chunked,
    /// Response body that ends when the server closes the connection.
    UntilClose,
}

pub enum Body {
    Complete(Vec<u8>),
    /// Larger than the limit: the raw bytes consumed so far, still framed as
    /// on the wire. The rest of the message has not been read.
    TooLarge(Vec<u8>),
}

/// A stream with a read buffer.
pub struct Conn<S> {
    io: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(io: S, prefix: Vec<u8>) -> Self {
        Self { io, buf: prefix }
    }

    /// The stream and any bytes read but not consumed.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.io, self.buf)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.io.write_all(bytes).await?;
        self.io.flush().await
    }

    /// Reads one message head. `Ok(None)` means the peer closed cleanly
    /// between messages.
    pub async fn read_head(&mut self) -> io::Result<Option<Head>> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                let head = parse_head(&self.buf[..end])?;
                self.buf.drain(..end + 4);
                return Ok(Some(head));
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(invalid("message head is too large"));
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    pub async fn read_body(&mut self, framing: Framing, limit: usize) -> io::Result<Body> {
        match framing {
            Framing::Length(length) => {
                if length > limit {
                    return Ok(Body::TooLarge(Vec::new()));
                }
                while self.buf.len() < length {
                    if self.fill().await? == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                }
                Ok(Body::Complete(self.buf.drain(..length).collect()))
            }
            Framing::Chunked => self.read_chunked(limit).await,
            Framing::UntilClose => loop {
                if self.buf.len() > limit {
                    return Ok(Body::TooLarge(std::mem::take(&mut self.buf)));
                }
                if self.fill().await? == 0 {
                    return Ok(Body::Complete(std::mem::take(&mut self.buf)));
                }
            },
        }
    }

    async fn read_chunked(&mut self, limit: usize) -> io::Result<Body> {
        let mut raw = Vec::new();
        let mut body = Vec::new();
        loop {
            let line = self.read_line(&mut raw).await?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size =
                usize::from_str_radix(size_text, 16).map_err(|_| invalid("invalid chunk size"))?;
            if size == 0 {
                // Trailers end with an empty line.
                while !self.read_line(&mut raw).await?.is_empty() {}
                return Ok(Body::Complete(body));
            }
            if body.len() + size > limit {
                return Ok(Body::TooLarge(raw));
            }
            while self.buf.len() < size + 2 {
                if self.fill().await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            raw.extend_from_slice(&self.buf[..size + 2]);
            body.extend_from_slice(&self.buf[..size]);
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err(invalid("chunk is not terminated"));
            }
            self.buf.drain(..size + 2);
        }
    }

    /// One CRLF-terminated line without the CRLF; the raw bytes go to `raw`.
    async fn read_line(&mut self, raw: &mut Vec<u8>) -> io::Result<String> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                raw.extend_from_slice(&self.buf[..end + 2]);
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(invalid("chunk line is too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let read = self.io.read(&mut self.buf[start..]).await;
        let n = *read.as_ref().unwrap_or(&0);
        self.buf.truncate(start + n);
        read
    }
}

fn parse_head(bytes: &[u8]) -> io::Result<Head> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("message head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let start_line = lines.next().unwrap_or("").to_string();
    if start_line.is_empty() {
        return Err(invalid("empty start line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() == MAX_HEADERS {
            return Err(invalid("too many headers"));
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed header"))?;
        let key = key.trim();
        if key.is_empty() || key.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(invalid("malformed header name"));
        }
        headers.push((key.to_string(), value.trim().to_string()));
    }
    Ok(Head {
        start_line,
        headers,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffered(bytes: &[u8]) -> Conn<tokio::io::DuplexStream> {
        let (near, _far) = tokio::io::duplex(64);
        Conn::new(near, bytes.to_vec())
    }

    #[tokio::test]
    async fn reads_heads_and_length_bodies_back_to_back() {
        let mut conn = buffered(
            b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n",
        );
        let head = conn.read_head().await.unwrap().unwrap();
        assert_eq!(head.start_line, "POST /a HTTP/1.1");
        assert_eq!(head.header("host"), Some("x"));
        let Body::Complete(body) = conn.read_body(head.framing().unwrap(), 16).await.unwrap()
        else {
            panic!("body should fit");
        };
        assert_eq!(body, b"abc");
        let next = conn.read_head().await.unwrap().unwrap();
        assert_eq!(next.start_line, "GET /b HTTP/1.1");
        assert_eq!(next.framing().unwrap(), Framing::Length(0));
    }

    #[tokio::test]
    async fn decodes_chunked_bodies_and_reports_oversize() {
        let mut conn = buffered(b"4\r\nwiki\r\n5;x=1\r\npedia\r\n0\r\nTrailer: y\r\n\r\nrest");
        let Body::Complete(body) = conn.read_body(Framing::Chunked, 64).await.unwrap() else {
            panic!("body should fit");
        };
        assert_eq!(body, b"wikipedia");
        assert_eq!(conn.into_parts().1, b"rest");

        let mut conn = buffered(b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n");
        let Body::TooLarge(raw) = conn.read_body(Framing::Chunked, 6).await.unwrap() else {
            panic!("body should be too large");
        };
        assert_eq!(raw, b"4\r\nwiki\r\n5\r\n");
    }

    #[test]
    fn rejects_bad_framing() {
        let head = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: x").unwrap();
        assert!(head.framing().is_err());
        assert!(parse_head(b"GET / HTTP/1.1\r\nno colon").is_err());
    }
}
