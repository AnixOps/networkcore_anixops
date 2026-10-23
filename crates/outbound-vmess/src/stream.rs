//! The VMess AEAD body stream (options ChunkStream + ChunkMasking).
//!
//! Each direction is a sequence of chunks `masked u16 size || AEAD(payload)`
//! with nonce `u16 count || iv[2..12]`; an empty chunk ends the direction.
//! The downlink starts with the sealed response header.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use engine_outbound::BoxStream;
use ring::aead::{Aad, LessSafeKey, Nonce, NONCE_LEN};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::{self, SizeMask};

/// Xray's buffer size: one chunk, size field and tag included, fits in it.
const MAX_CHUNK: usize = 8 * 1024;
const TAG_LEN: usize = 16;
pub(crate) const MAX_PAYLOAD: usize = MAX_CHUNK - 2 - TAG_LEN;
const READ_CHUNK: usize = 16 * 1024;

/// One direction's body cipher.
pub(crate) struct BodyCipher {
    key: LessSafeKey,
    iv: [u8; 16],
    count: u16,
    mask: SizeMask,
}

impl BodyCipher {
    pub(crate) fn new(key: LessSafeKey, iv: [u8; 16]) -> Self {
        Self {
            key,
            iv,
            count: 0,
            mask: SizeMask::new(&iv),
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);
        Nonce::assume_unique_for_key(nonce)
    }

    fn seal_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let size = (payload.len() + TAG_LEN) as u16;
        out.extend_from_slice(&(size ^ self.mask.next_mask()).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(payload);
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..])
            .expect("chunk sealing does not fail for these sizes");
        out.extend_from_slice(tag.as_ref());
    }
}

enum ReadState {
    ResponseLength,
    ResponseHeader(usize),
    Size,
    Body(usize),
    Eof,
}

pub(crate) struct ResponseKeys {
    pub length_key: [u8; 16],
    pub length_iv: [u8; 32],
    pub header_key: [u8; 16],
    pub header_iv: [u8; 32],
    /// The `V` byte the server must echo.
    pub expected: u8,
}

pub(crate) struct VmessStream {
    inner: BoxStream,
    writer: BodyCipher,
    reader: BodyCipher,
    response: ResponseKeys,
    /// Bytes not yet written to `inner`: `wbuf[wpos..]`. Starts with the
    /// sealed request header, which goes out with the first chunk.
    wbuf: Vec<u8>,
    wpos: usize,
    header_sent: bool,
    /// Whether the first chunk was queued behind the request header.
    merged: bool,
    eof_sent: bool,
    rbuf: Vec<u8>,
    rpos: usize,
    state: ReadState,
    /// Decrypted payload not yet returned: `plain[plain_pos..]`.
    plain: Vec<u8>,
    plain_pos: usize,
}

impl VmessStream {
    pub(crate) fn new(
        inner: BoxStream,
        sealed_header: Vec<u8>,
        writer: BodyCipher,
        reader: BodyCipher,
        response: ResponseKeys,
    ) -> Self {
        Self {
            inner,
            writer,
            reader,
            response,
            wbuf: sealed_header,
            wpos: 0,
            header_sent: false,
            merged: false,
            eof_sent: false,
            rbuf: Vec::new(),
            rpos: 0,
            state: ReadState::ResponseLength,
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
        self.header_sent = true;
        Poll::Ready(Ok(()))
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

    /// Takes `n` buffered bytes, or `None` when fewer are buffered.
    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buffered().len() < n {
            return None;
        }
        let out = self.rbuf[self.rpos..self.rpos + n].to_vec();
        self.rpos += n;
        Some(out)
    }

    fn step(&mut self) -> io::Result<bool> {
        match self.state {
            ReadState::Eof => Ok(true),
            ReadState::ResponseLength => {
                let Some(mut sealed) = self.take(2 + TAG_LEN) else {
                    return Ok(false);
                };
                let keys = &self.response;
                crypto::open_aes_gcm(&keys.length_key, &keys.length_iv, &mut sealed)
                    .ok_or_else(|| bad("vmess response header length failed to decrypt"))?;
                let length = usize::from(u16::from_be_bytes([sealed[0], sealed[1]]));
                self.state = ReadState::ResponseHeader(length);
                Ok(true)
            }
            ReadState::ResponseHeader(length) => {
                let Some(mut sealed) = self.take(length + TAG_LEN) else {
                    return Ok(false);
                };
                let keys = &self.response;
                let plain_len =
                    crypto::open_aes_gcm(&keys.header_key, &keys.header_iv, &mut sealed)
                        .ok_or_else(|| bad("vmess response header failed to decrypt"))?;
                if plain_len < 4 || sealed[0] != keys.expected {
                    return Err(bad("vmess response header does not match the request"));
                }
                self.state = ReadState::Size;
                Ok(true)
            }
            ReadState::Size => {
                let Some(raw) = self.take(2) else {
                    return Ok(false);
                };
                let size = usize::from(
                    u16::from_be_bytes([raw[0], raw[1]]) ^ self.reader.mask.next_mask(),
                );
                self.state = match size {
                    TAG_LEN => ReadState::Eof,
                    size if size < TAG_LEN => {
                        return Err(bad("vmess chunk is shorter than its tag"));
                    }
                    size => ReadState::Body(size),
                };
                Ok(true)
            }
            ReadState::Body(size) => {
                let Some(mut sealed) = self.take(size) else {
                    return Ok(false);
                };
                let nonce = self.reader.next_nonce();
                let plain = self
                    .reader
                    .key
                    .open_in_place(nonce, Aad::empty(), &mut sealed)
                    .map_err(|_| bad("vmess chunk failed to decrypt"))?;
                let len = plain.len();
                sealed.truncate(len);
                self.plain = sealed;
                self.plain_pos = 0;
                self.state = ReadState::Size;
                Ok(true)
            }
        }
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // The server answers only after the request header arrives.
        if !this.header_sent {
            ready!(this.poll_drain(cx))?;
            ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        }
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
                // A server that closes between chunks without the empty
                // chunk still ends the stream cleanly.
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

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // The request header stays queued so it leaves with the first chunk.
        if this.merged {
            ready!(this.poll_drain(cx))?;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_PAYLOAD);
        this.merged = true;
        let mut chunk = std::mem::take(&mut this.wbuf);
        this.writer.seal_chunk(&buf[..n], &mut chunk);
        this.wbuf = chunk;
        // Accepted now; a send still pending finishes on the next write,
        // flush, read or shutdown.
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
            let mut chunk = std::mem::take(&mut this.wbuf);
            this.writer.seal_chunk(&[], &mut chunk);
            this.wbuf = chunk;
        }
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
