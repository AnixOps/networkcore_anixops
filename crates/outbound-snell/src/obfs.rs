//! `obfs = http` for v1–v4 (spec §5.1): an HTTP upgrade header in front of
//! the first write in each direction. Both sides skip everything up to the
//! first blank line of the peer's first read without checking it.

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::{fill_random, invalid_data, random_u32};

pub const DEFAULT_HTTP_HOST: &str = "bing.com";
pub const DEFAULT_HTTP_URI: &str = "/";

/// Header bytes skipped before giving up on the peer's first read.
const MAX_HEADER: usize = 16 * 1024;

/// Which side of the connection writes which header.
#[derive(Clone, Debug)]
pub enum HttpObfsRole {
    Client { host: String, uri: String },
    Server,
}

/// Wraps a transport with the HTTP obfs headers.
pub struct HttpObfs<S> {
    inner: S,
    role: HttpObfsRole,
    header_written: bool,
    out: Vec<u8>,
    out_pos: usize,
    /// How much of `\r\n\r\n` the skipped input currently ends with; `None`
    /// once the peer's header is gone.
    skip_match: Option<usize>,
    skipped: usize,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl<S> HttpObfs<S> {
    pub fn new(inner: S, role: HttpObfsRole) -> Self {
        Self {
            inner,
            role,
            header_written: false,
            out: Vec::new(),
            out_pos: 0,
            skip_match: Some(0),
            skipped: 0,
            leftover: Vec::new(),
            leftover_pos: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Process-wide random User-Agent versions and WebSocket key.
struct ClientIdentity {
    mac_minor: u32,
    firefox: u32,
    websocket_key: String,
}

fn client_identity() -> &'static ClientIdentity {
    static IDENTITY: OnceLock<ClientIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let mut key = [0u8; 16];
        let _ = fill_random(&mut key);
        let a = random_u32().unwrap_or(0);
        let b = random_u32().unwrap_or(0);
        ClientIdentity {
            mac_minor: 9 + a % 6,
            firefox: 22 + b % 43,
            websocket_key: base64::engine::general_purpose::STANDARD.encode(key),
        }
    })
}

fn client_header(host: &str, uri: &str, content_length: usize) -> String {
    let identity = client_identity();
    format!(
        "GET {uri} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{}; rv:64.0) Gecko/20100101 Firefox/{}.0\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Content-Length: {content_length}\r\n\
         Sec-WebSocket-Key: {}\r\n\
         \r\n",
        identity.mac_minor, identity.firefox, identity.websocket_key
    )
}

fn server_header() -> String {
    let mut accept = [0u8; 20];
    let _ = fill_random(&mut accept);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Server: nginx/1.24.0\r\n\
         Date: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        http_date(SystemTime::now()),
        base64::engine::general_purpose::STANDARD.encode(accept)
    )
}

/// RFC 7231 IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(now: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

impl<S: AsyncWrite + Unpin> HttpObfs<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.header_written {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.header_written = true;
        let header = match &this.role {
            HttpObfsRole::Client { host, uri } => client_header(host, uri, buf.len()),
            HttpObfsRole::Server => server_header(),
        };
        this.out.extend_from_slice(header.as_bytes());
        this.out.extend_from_slice(buf);
        // Committed to `out`; a pending drain finishes on the next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.leftover_pos < this.leftover.len() {
            let available = &this.leftover[this.leftover_pos..];
            let n = available.len().min(buf.remaining());
            buf.put_slice(&available[..n]);
            this.leftover_pos += n;
            return Poll::Ready(Ok(()));
        }
        let Some(mut matched) = this.skip_match else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        const END: &[u8; 4] = b"\r\n\r\n";
        let mut scratch = [0u8; 2048];
        loop {
            let mut read = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let data = read.filled();
            if data.is_empty() {
                // End of stream inside the header.
                this.skip_match = Some(matched);
                return Poll::Ready(Ok(()));
            }
            for (i, &byte) in data.iter().enumerate() {
                matched = if byte == END[matched] {
                    matched + 1
                } else if byte == END[0] {
                    1
                } else {
                    0
                };
                if matched == END.len() {
                    this.skip_match = None;
                    this.leftover = data[i + 1..].to_vec();
                    this.leftover_pos = 0;
                    let n = this.leftover.len().min(buf.remaining());
                    buf.put_slice(&this.leftover[..n]);
                    this.leftover_pos = n;
                    if n > 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }
            }
            this.skipped += data.len();
            if this.skipped > MAX_HEADER {
                return Poll::Ready(Err(invalid_data("snell obfs header is too long")));
            }
            this.skip_match = Some(matched);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_and_server_strip_each_others_headers() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = HttpObfs::new(
            a,
            HttpObfsRole::Client {
                host: DEFAULT_HTTP_HOST.into(),
                uri: DEFAULT_HTTP_URI.into(),
            },
        );
        let mut server = HttpObfs::new(b, HttpObfsRole::Server);
        client.write_all(b"hello server").await.unwrap();
        client.write_all(b" again").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 18];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello server again");

        server.write_all(b"hello client").await.unwrap();
        server.flush().await.unwrap();
        let mut got = [0u8; 12];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello client");
    }

    #[test]
    fn client_header_has_content_length_and_websocket_upgrade() {
        let header = client_header("bing.com", "/", 123);
        assert!(header.starts_with("GET / HTTP/1.1\r\nHost: bing.com\r\n"));
        assert!(header.contains("\r\nContent-Length: 123\r\n"));
        assert!(header.contains("\r\nUpgrade: websocket\r\n"));
        assert!(header.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_dates_are_imf_fixdate() {
        let date = http_date(UNIX_EPOCH + std::time::Duration::from_secs(784_111_777));
        assert_eq!(date, "Sun, 06 Nov 1994 08:49:37 GMT");
    }
}
