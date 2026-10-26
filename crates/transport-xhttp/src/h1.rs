//! The HTTP/1.1 messages XHTTP needs: response heads for the client,
//! request heads for the server, and bodies delimited by `Content-Length`,
//! chunked coding, or the close.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite};

/// Largest message head accepted.
const MAX_HEAD: usize = 64 * 1024;
/// Largest chunk-size or trailer line accepted.
const MAX_LINE: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub status: u16,
    pub content_length: Option<u64>,
    pub chunked: bool,
    /// The server closes the connection after this response.
    pub close: bool,
}

/// Reads one final response head, skipping `1xx` interim responses.
pub(crate) async fn read_head<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Head> {
    let mut budget = MAX_HEAD;
    let mut line = Vec::new();
    loop {
        read_line(reader, &mut line, &mut budget).await?;
        if line.is_empty() {
            continue;
        }
        let (status, http10) = parse_status(&line)?;
        let mut head = Head {
            status,
            content_length: None,
            chunked: false,
            close: http10,
        };
        read_fields(reader, &mut line, &mut budget, &mut head, |_, _| {}).await?;
        if (100..200).contains(&status) {
            continue;
        }
        return Ok(head);
    }
}

/// A request head as the server sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub referer: Option<String>,
    /// Body framing; `status` is unused.
    pub body: Head,
}

/// Reads one request head; `Ok(None)` when the client closed the connection
/// before sending another request.
pub(crate) async fn read_request<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Request>> {
    let mut budget = MAX_HEAD;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut *reader)
            .take(budget as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            return Err(bad("request head is too large"));
        }
        budget -= read;
        if line.iter().any(|byte| !byte.is_ascii_whitespace()) {
            break;
        }
    }
    let text = std::str::from_utf8(&line).map_err(|_| bad("request line is not text"))?;
    let mut parts = text.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("request line is malformed"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(bad("client did not speak HTTP/1.x"));
    }
    let mut request = Request {
        method: method.to_owned(),
        target: target.to_owned(),
        host: None,
        referer: None,
        body: Head {
            status: 0,
            content_length: None,
            chunked: false,
            close: version == "HTTP/1.0",
        },
    };
    let mut host = None;
    let mut referer = None;
    read_fields(
        reader,
        &mut line,
        &mut budget,
        &mut request.body,
        |name, value| {
            if name.eq_ignore_ascii_case("host") {
                host = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("referer") {
                referer = Some(value.to_owned());
            }
        },
    )
    .await?;
    request.host = host;
    request.referer = referer;
    Ok(Some(request))
}

/// Header fields up to the empty line: the framing ones go into `head`, and
/// every field to `field`.
async fn read_fields<R, F>(
    reader: &mut R,
    line: &mut Vec<u8>,
    budget: &mut usize,
    head: &mut Head,
    mut field: F,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    F: FnMut(&str, &str),
{
    loop {
        read_line(reader, line, budget).await?;
        if line.is_empty() {
            return Ok(());
        }
        let text = std::str::from_utf8(line).map_err(|_| bad("header is not text"))?;
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| bad("header is malformed"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            head.content_length = Some(
                value
                    .parse()
                    .map_err(|_| bad("content-length is invalid"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value
                .rsplit(',')
                .next()
                .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|option| option.trim().eq_ignore_ascii_case("close"))
        {
            head.close = true;
        }
        field(name, value);
    }
}

/// Reads a request body of at most `limit` bytes; `Ok(None)` when it is
/// larger (the rest stays unread). A request without length has no body.
pub(crate) async fn read_body_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    head: &Head,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    if !head.chunked {
        let length = head.content_length.unwrap_or(0);
        if length > limit as u64 {
            return Ok(None);
        }
        let mut body = vec![0; length as usize];
        reader.read_exact(&mut body).await?;
        return Ok(Some(body));
    }
    let mut out = Limited {
        body: Vec::new(),
        limit,
        overflow: false,
    };
    match copy_body(reader, head, &mut out).await {
        Ok(()) => Ok(Some(out.body)),
        Err(_) if out.overflow => Ok(None),
        Err(err) => Err(err),
    }
}

/// A `Vec` writer that fails past `limit`.
struct Limited {
    body: Vec<u8>,
    limit: usize,
    overflow: bool,
}

impl AsyncWrite for Limited {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.body.len() + buf.len() > self.limit {
            self.overflow = true;
            return Poll::Ready(Err(io::Error::other("body is too large")));
        }
        self.body.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// `HTTP/1.x NNN reason`: the status and whether the version is 1.0.
fn parse_status(line: &[u8]) -> io::Result<(u16, bool)> {
    let text = std::str::from_utf8(line).map_err(|_| bad("status line is not text"))?;
    let mut parts = text.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(bad("server did not answer with HTTP/1.x"));
    }
    let status = parts
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| bad("status line is malformed"))?;
    Ok((status, version == "HTTP/1.0"))
}

/// One line without its `\r\n`, charged to `budget`.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    budget: &mut usize,
) -> io::Result<()> {
    line.clear();
    let read = (&mut *reader)
        .take(*budget as u64)
        .read_until(b'\n', line)
        .await?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "server closed inside a response head",
        ));
    }
    if line.last() != Some(&b'\n') {
        return Err(bad("response head is too large"));
    }
    *budget -= read;
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(())
}

/// Copies the body of a response with `head` from `reader` to `out`.
pub(crate) async fn copy_body<R, W>(reader: &mut R, head: &Head, out: &mut W) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if head.chunked {
        let mut line = Vec::new();
        loop {
            let mut budget = MAX_LINE;
            read_line(reader, &mut line, &mut budget).await?;
            let size = line
                .split(|byte| *byte == b';')
                .next()
                .and_then(|size| std::str::from_utf8(size).ok())
                .and_then(|size| u64::from_str_radix(size.trim(), 16).ok())
                .ok_or_else(|| bad("chunk size is malformed"))?;
            if size == 0 {
                // Trailers up to the empty line.
                loop {
                    let mut budget = MAX_LINE;
                    read_line(reader, &mut line, &mut budget).await?;
                    if line.is_empty() {
                        return Ok(());
                    }
                }
            }
            copy_exact(reader, size, out).await?;
            let mut budget = MAX_LINE;
            read_line(reader, &mut line, &mut budget).await?;
            if !line.is_empty() {
                return Err(bad("chunk is not followed by CRLF"));
            }
        }
    } else if let Some(length) = head.content_length {
        copy_exact(reader, length, out).await
    } else {
        tokio::io::copy_buf(reader, out).await.map(drop)
    }
}

async fn copy_exact<R, W>(reader: &mut R, length: u64, out: &mut W) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy_buf(&mut (&mut *reader).take(length), out).await?;
    if copied < length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "server closed inside a response body",
        ));
    }
    Ok(())
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(response: &[u8]) -> io::Result<(Head, Vec<u8>)> {
        let mut reader = response;
        let head = read_head(&mut reader).await?;
        let mut body = Vec::new();
        copy_body(&mut reader, &head, &mut body).await?;
        Ok((head, body))
    }

    #[tokio::test]
    async fn bodies_by_length_chunks_and_close() {
        let (head, body) = parse(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef",
        )
        .await
        .unwrap();
        assert_eq!(head.status, 200);
        assert!(!head.close);
        assert_eq!(body, b"abc");

        let (head, body) = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              3;ext=1\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\nX-Trailer: 1\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(head.chunked && head.close);
        assert_eq!(body, b"abc0123456789abcdef");

        let (head, body) = parse(b"HTTP/1.0 200 OK\r\n\r\nto the end").await.unwrap();
        assert!(head.close);
        assert_eq!(body, b"to the end");
    }

    #[tokio::test]
    async fn requests_and_limited_bodies() {
        let mut reader = &b"\r\nPOST /xh/s/0?k=v HTTP/1.1\r\nHost: a.example\r\n\
            Referer: https://a.example/xh/s/0?x_padding=XXX\r\nContent-Length: 4\r\n\r\nbodyGET / HTTP/1.1\r\n\
            Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n"[..];
        let request = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/xh/s/0?k=v");
        assert_eq!(request.host.as_deref(), Some("a.example"));
        assert!(request.referer.unwrap().ends_with("x_padding=XXX"));
        let body = read_body_limited(&mut reader, &request.body, 4)
            .await
            .unwrap();
        assert_eq!(body.unwrap(), b"body");
        let request = read_request(&mut reader).await.unwrap().unwrap();
        assert!(request.body.chunked && request.host.is_none());
        assert!(read_body_limited(&mut reader, &request.body, 7)
            .await
            .unwrap()
            .is_none());
        assert!(read_request(&mut &b""[..]).await.unwrap().is_none());
        assert!(read_request(&mut &b"GET /\r\n\r\n"[..]).await.is_err());
        let mut long = &b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\n"[..];
        let request = read_request(&mut long).await.unwrap().unwrap();
        assert!(read_body_limited(&mut long, &request.body, 8)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn malformed_responses_fail() {
        for response in [
            &b"SSH-2.0-OpenSSH\r\n\r\n"[..],
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            assert!(
                parse(response).await.is_err(),
                "{:?}",
                String::from_utf8_lossy(response)
            );
        }
        let huge = [
            b"HTTP/1.1 200 OK\r\nX: ".as_slice(),
            &[b'a'; MAX_HEAD],
            b"\r\n\r\n",
        ]
        .concat();
        assert!(parse(&huge).await.is_err());
    }
}
