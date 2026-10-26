//! The VMess body stream, server side.
//!
//! Each direction is a sequence of chunks `size || payload || padding`. With
//! an AEAD security the payload is sealed with nonce `u16 count || iv[2..12]`;
//! with ChunkMasking the size is XORed with a SHAKE128 stream seeded by the
//! IV; with GlobalPadding each chunk also carries `next mask % 64` random
//! bytes, drawn from the same stream before the size mask. A chunk whose size
//! is only overhead and padding ends the direction. The downlink starts with
//! the sealed response header.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use engine_outbound::BoxStream;
use outbound_vmess::crypto::SizeMask;
use ring::aead::{Aad, LessSafeKey, Nonce, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TAG_LEN: usize = 16;
const MAX_PADDING: usize = 64;
/// Payload per outgoing chunk, so size, tag and padding fit in Xray's 8 KiB
/// buffer.
const MAX_PAYLOAD: usize = 8 * 1024 - 2 - TAG_LEN - MAX_PADDING;
const READ_CHUNK: usize = 16 * 1024;

/// One direction's chunk codec.
pub(crate) struct BodyCodec {
    /// `None` for security `none`: payloads travel unsealed.
    key: Option<LessSafeKey>,
    iv: [u8; 16],
    count: u16,
    /// Present with ChunkMasking.
    mask: Option<SizeMask>,
    padding: bool,
}

impl BodyCodec {
    pub(crate) fn new(
        key: Option<LessSafeKey>,
        iv: [u8; 16],
        masking: bool,
        padding: bool,
    ) -> Self {
        Self {
            key,
            iv,
            count: 0,
            mask: masking.then(|| SizeMask::new(&iv)),
            padding: padding && masking,
        }
    }

    fn overhead(&self) -> usize {
        if self.key.is_some() {
            TAG_LEN
        } else {
            0
        }
    }

    fn next_padding(&mut self) -> usize {
        match (&mut self.mask, self.padding) {
            (Some(mask), true) => usize::from(mask.next_mask()) % MAX_PADDING,
            _ => 0,
        }
    }

    fn size_mask(&mut self) -> u16 {
        self.mask.as_mut().map_or(0, SizeMask::next_mask)
    }

    fn seal_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let padding = self.next_padding();
        let size = (payload.len() + self.overhead() + padding) as u16;
        let mask = self.size_mask();
        out.extend_from_slice(&(size ^ mask).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(payload);
        if let Some(key) = &self.key {
            let nonce = next_nonce(&mut self.count, &self.iv);
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..])
                .map_err(|_| io::Error::other("vmess chunk sealing failed"))?;
            out.extend_from_slice(tag.as_ref());
        }
        if padding > 0 {
            let padding_start = out.len();
            out.resize(padding_start + padding, 0);
            SystemRandom::new()
                .fill(&mut out[padding_start..])
                .map_err(|_| io::Error::other("system random source failed"))?;
        }
        Ok(())
    }

    /// Opens one received chunk body in place and returns the payload length.
    fn open_chunk(&mut self, body: &mut [u8]) -> io::Result<usize> {
        let Some(key) = &self.key else {
            return Ok(body.len());
        };
        let nonce = next_nonce(&mut self.count, &self.iv);
        key.open_in_place(nonce, Aad::empty(), body)
            .map(|plain| plain.len())
            .map_err(|_| bad("vmess chunk failed to decrypt"))
    }
}

/// `u16 count || iv[2..12]`, then advances the count.
fn next_nonce(count: &mut u16, iv: &[u8; 16]) -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    *count = count.wrapping_add(1);
    Nonce::assume_unique_for_key(nonce)
}

enum ReadState {
    Size,
    /// Chunk size on the wire, and how much of it is padding.
    Body {
        size: usize,
        padding: usize,
    },
    Eof,
}

pub(crate) struct VmessServerStream {
    inner: BoxStream,
    reader: BodyCodec,
    writer: BodyCodec,
    /// Bytes not yet written to `inner`: `wbuf[wpos..]`.
    wbuf: Vec<u8>,
    wpos: usize,
    /// The sealed response header, until the first write or shutdown.
    response_header: Option<Vec<u8>>,
    eof_sent: bool,
    rbuf: Vec<u8>,
    rpos: usize,
    state: ReadState,
    plain: Vec<u8>,
    plain_pos: usize,
}

impl VmessServerStream {
    pub(crate) fn new(
        inner: BoxStream,
        reader: BodyCodec,
        writer: BodyCodec,
        response_header: Vec<u8>,
        buffered: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            reader,
            writer,
            wbuf: Vec::new(),
            wpos: 0,
            response_header: Some(response_header),
            eof_sent: false,
            rbuf: buffered,
            rpos: 0,
            state: ReadState::Size,
            plain: Vec::new(),
            plain_pos: 0,
        }
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

    /// Queues `payload` (empty for the end marker) behind the response
    /// header if that has not gone out yet.
    fn queue_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut out = std::mem::take(&mut self.wbuf);
        if let Some(header) = self.response_header.take() {
            out.extend_from_slice(&header);
        }
        let result = self.writer.seal_chunk(payload, &mut out);
        self.wbuf = out;
        result
    }

    fn buffered(&self) -> &[u8] {
        &self.rbuf[self.rpos..]
    }

    /// Reads more from `inner`. `Ok(false)` is end of stream.
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

    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buffered().len() < n {
            return None;
        }
        let out = self.rbuf[self.rpos..self.rpos + n].to_vec();
        self.rpos += n;
        Some(out)
    }

    /// Advances the read state with buffered bytes; `Ok(false)` needs more
    /// input.
    fn step(&mut self) -> io::Result<bool> {
        match self.state {
            ReadState::Eof => Ok(true),
            ReadState::Size => {
                let Some(raw) = self.take(2) else {
                    return Ok(false);
                };
                let padding = self.reader.next_padding();
                let size =
                    usize::from(u16::from_be_bytes([raw[0], raw[1]]) ^ self.reader.size_mask());
                let overhead = self.reader.overhead();
                self.state = if size == overhead + padding {
                    ReadState::Eof
                } else if size < overhead + padding {
                    return Err(bad("vmess chunk is shorter than its overhead"));
                } else {
                    ReadState::Body { size, padding }
                };
                Ok(true)
            }
            ReadState::Body { size, padding } => {
                let Some(mut body) = self.take(size) else {
                    return Ok(false);
                };
                body.truncate(size - padding);
                let len = self.reader.open_chunk(&mut body)?;
                body.truncate(len);
                self.plain = body;
                self.plain_pos = 0;
                self.state = ReadState::Size;
                Ok(true)
            }
        }
    }
}

impl AsyncRead for VmessServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if matches!(this.state, ReadState::Eof) {
                return Poll::Ready(Ok(()));
            }
            if this.step()? {
                continue;
            }
            if !ready!(this.poll_fill(cx))? {
                // A client that closes between chunks without the end marker
                // still ends the stream cleanly.
                if matches!(this.state, ReadState::Size) && this.buffered().is_empty() {
                    this.state = ReadState::Eof;
                    continue;
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vmess stream ended inside a chunk",
                )));
            }
        }
    }
}

impl AsyncWrite for VmessServerStream {
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
        let n = buf.len().min(MAX_PAYLOAD);
        this.queue_chunk(&buf[..n])?;
        // Accepted now; a send still pending finishes on the next call.
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
        if !this.eof_sent {
            ready!(this.poll_drain(cx))?;
            this.eof_sent = true;
            this.queue_chunk(&[])?;
        }
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
