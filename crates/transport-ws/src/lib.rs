//! WebSocket client transport (RFC 6455) for outbound protocol crates.
//!
//! [`WsConnector::connect`] runs the opening handshake over an existing
//! stream (plain TCP or TLS) and returns a byte stream: each write becomes one
//! masked binary frame, and reads return the payload of data frames in order.
//! Pings are answered, a close frame reads as end of stream, and the stream
//! never surfaces message boundaries, which is what V2Ray-style `ws`
//! transports expect.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use base64::Engine as _;
use engine_outbound::BoxStream;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Longest handshake response head accepted from the server.
pub const MAX_RESPONSE_HEAD_BYTES: usize = 8 * 1024;
/// Largest payload put in one frame; longer writes are accepted partially.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
const READ_CHUNK: usize = 16 * 1024;
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xa;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsSettings {
    /// Request path, `/` when empty.
    pub path: String,
    /// `Host` header; the caller passes the server name when empty.
    pub host: String,
    /// Extra request headers as (name, value), e.g. `User-Agent`.
    pub headers: Vec<(String, String)>,
}

pub struct WsConnector {
    request_target: String,
    host: String,
    headers: Vec<(String, String)>,
    random: SystemRandom,
}

impl WsConnector {
    /// `default_host` is used when `settings.host` is empty.
    pub fn new(settings: &WsSettings, default_host: &str) -> io::Result<Self> {
        let path = if settings.path.is_empty() {
            "/"
        } else {
            settings.path.as_str()
        };
        if !path.starts_with('/') || !is_header_safe(path) || path.contains(' ') {
            return Err(invalid("websocket path is invalid"));
        }
        let host = if settings.host.is_empty() {
            default_host
        } else {
            settings.host.as_str()
        };
        if host.is_empty() || !is_header_safe(host) || host.contains(' ') {
            return Err(invalid("websocket host is invalid"));
        }
        for (name, value) in &settings.headers {
            let name_ok = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
            if !name_ok || !is_header_safe(value) {
                return Err(invalid("websocket header is invalid"));
            }
        }
        Ok(Self {
            request_target: path.to_owned(),
            host: host.to_owned(),
            headers: settings.headers.clone(),
            random: SystemRandom::new(),
        })
    }

    pub async fn connect(&self, mut transport: BoxStream) -> io::Result<BoxStream> {
        let mut key_bytes = [0u8; 16];
        self.random
            .fill(&mut key_bytes)
            .map_err(|_| io::Error::other("system random source failed"))?;
        let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
            self.request_target, self.host
        );
        for (name, value) in &self.headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        transport.write_all(request.as_bytes()).await?;
        transport.flush().await?;

        let head = read_head(&mut transport).await?;
        check_response(&head, &key)?;

        let mut seed = [0u8; 8];
        self.random
            .fill(&mut seed)
            .map_err(|_| io::Error::other("system random source failed"))?;
        Ok(Box::new(WsStream::new(transport, u64::from_le_bytes(seed))))
    }
}

fn is_header_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

/// Reads one byte at a time so frame bytes after the head stay in the stream.
async fn read_head(stream: &mut BoxStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD_BYTES {
            return Err(protocol_error("websocket response head is too long"));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(head)
}

fn check_response(head: &[u8], key: &str) -> io::Result<()> {
    let text =
        std::str::from_utf8(head).map_err(|_| protocol_error("websocket response is not utf-8"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split(' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(protocol_error("websocket server sent a malformed response"));
    }
    if code != "101" {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "websocket server refused the upgrade",
        ));
    }
    let expected = accept_value(key);
    let accepted = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected
        })
    });
    if !accepted {
        return Err(protocol_error(
            "websocket server sent a wrong Sec-WebSocket-Accept",
        ));
    }
    Ok(())
}

/// `base64(SHA-1(key + GUID))`, as RFC 6455 section 4.2.2 defines it.
pub fn accept_value(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + ACCEPT_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(ACCEPT_GUID);
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// What the reader is in the middle of.
enum ReadState {
    /// Waiting for a frame header.
    Header,
    /// Inside a data frame's payload.
    Data {
        remaining: u64,
        mask: Option<[u8; 4]>,
        offset: usize,
    },
    /// A close frame arrived or the transport ended at a frame boundary.
    Closed,
}

struct WsStream {
    inner: BoxStream,
    /// Bytes read from `inner` and not parsed yet: `rbuf[rpos..]`.
    rbuf: Vec<u8>,
    rpos: usize,
    state: ReadState,
    /// Encoded frames not yet written to `inner`: `wbuf[wpos..]`.
    wbuf: Vec<u8>,
    wpos: usize,
    close_sent: bool,
    /// xorshift64* state for frame masks.
    mask_state: u64,
}

impl WsStream {
    fn new(inner: BoxStream, seed: u64) -> Self {
        Self {
            inner,
            rbuf: Vec::new(),
            rpos: 0,
            state: ReadState::Header,
            wbuf: Vec::new(),
            wpos: 0,
            close_sent: false,
            mask_state: seed | 1,
        }
    }

    fn next_mask(&mut self) -> [u8; 4] {
        let mut x = self.mask_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.mask_state = x;
        let value = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let bytes = value.to_le_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    }

    fn push_frame(&mut self, opcode: u8, payload: &[u8]) {
        let mask = self.next_mask();
        self.wbuf.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            self.wbuf.push(0x80 | len as u8);
        } else if len <= usize::from(u16::MAX) {
            self.wbuf.push(0x80 | 126);
            self.wbuf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            self.wbuf.push(0x80 | 127);
            self.wbuf.extend_from_slice(&(len as u64).to_be_bytes());
        }
        self.wbuf.extend_from_slice(&mask);
        self.wbuf.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % 4]),
        );
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    fn buffered(&self) -> &[u8] {
        &self.rbuf[self.rpos..]
    }

    fn consume(&mut self, n: usize) {
        self.rpos += n;
        if self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        }
    }

    /// Reads more bytes from `inner`. `Ok(false)` means end of stream.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.rpos > 0 {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }
        let start = self.rbuf.len();
        self.rbuf.resize(start + READ_CHUNK, 0);
        let mut read_buf = ReadBuf::new(&mut self.rbuf[start..]);
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut read_buf);
        let filled = read_buf.filled().len();
        self.rbuf.truncate(start + filled);
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(filled > 0)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Parses one frame header from the buffer. `None` means more bytes are
    /// needed. Control frames are handled whole and return `Some(None)`.
    fn parse_header(&mut self) -> io::Result<Option<Option<ReadState>>> {
        let buf = self.buffered();
        if buf.len() < 2 {
            return Ok(None);
        }
        let opcode = buf[0] & 0x0f;
        let masked = buf[1] & 0x80 != 0;
        let mut len = u64::from(buf[1] & 0x7f);
        let mut at = 2;
        if len == 126 {
            if buf.len() < at + 2 {
                return Ok(None);
            }
            len = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
            at += 2;
        } else if len == 127 {
            if buf.len() < at + 8 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[2..10]);
            len = u64::from_be_bytes(bytes);
            at += 8;
        }
        let mask = if masked {
            if buf.len() < at + 4 {
                return Ok(None);
            }
            let mask = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
            at += 4;
            Some(mask)
        } else {
            None
        };
        match opcode {
            OPCODE_CONTINUATION | OPCODE_TEXT | OPCODE_BINARY => {
                self.consume(at);
                Ok(Some(Some(ReadState::Data {
                    remaining: len,
                    mask,
                    offset: 0,
                })))
            }
            OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
                if len > 125 {
                    return Err(protocol_error("websocket control frame is too long"));
                }
                let len = len as usize;
                if buf.len() < at + len {
                    return Ok(None);
                }
                let mut payload = buf[at..at + len].to_vec();
                if let Some(mask) = mask {
                    for (i, byte) in payload.iter_mut().enumerate() {
                        *byte ^= mask[i % 4];
                    }
                }
                self.consume(at + len);
                match opcode {
                    OPCODE_CLOSE => Ok(Some(Some(ReadState::Closed))),
                    OPCODE_PING => {
                        self.push_frame(OPCODE_PONG, &payload);
                        Ok(Some(None))
                    }
                    _ => Ok(Some(None)),
                }
            }
            _ => Err(protocol_error("websocket frame has an unknown opcode")),
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // Pongs queued by the parser go out without blocking the reader.
            if this.wpos < this.wbuf.len() {
                if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
                    return Poll::Ready(Err(err));
                }
            }
            match this.state {
                ReadState::Closed => return Poll::Ready(Ok(())),
                ReadState::Data { remaining: 0, .. } => {
                    this.state = ReadState::Header;
                }
                ReadState::Data {
                    remaining,
                    mask,
                    offset,
                } if !this.buffered().is_empty() => {
                    let available = this.buffered().len();
                    let n = available
                        .min(buf.remaining())
                        .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                    let start = buf.filled().len();
                    buf.put_slice(&this.buffered()[..n]);
                    if let Some(mask) = mask {
                        for (i, byte) in buf.filled_mut()[start..].iter_mut().enumerate() {
                            *byte ^= mask[(offset + i) % 4];
                        }
                    }
                    this.consume(n);
                    this.state = ReadState::Data {
                        remaining: remaining - n as u64,
                        mask,
                        offset: (offset + n) % 4,
                    };
                    return Poll::Ready(Ok(()));
                }
                ReadState::Data { .. } => {
                    if !ready!(this.poll_fill(cx))? {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "websocket stream ended inside a frame",
                        )));
                    }
                }
                ReadState::Header => match this.parse_header()? {
                    Some(Some(state)) => this.state = state,
                    Some(None) => {}
                    None => {
                        if !ready!(this.poll_fill(cx))? {
                            if this.buffered().is_empty() {
                                this.state = ReadState::Closed;
                            } else {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "websocket stream ended inside a frame header",
                                )));
                            }
                        }
                    }
                },
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_FRAME_PAYLOAD);
        this.push_frame(OPCODE_BINARY, &buf[..n]);
        // The frame is accepted now; a send still pending finishes on the
        // next write, flush or shutdown.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if !this.close_sent {
            this.close_sent = true;
            // Status 1000, normal closure.
            this.push_frame(OPCODE_CLOSE, &1000u16.to_be_bytes());
            ready!(this.poll_drain(cx))?;
        }
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
