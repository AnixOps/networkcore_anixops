//! One client connection's framing state, and the byte stream of one TCP
//! request on it.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use engine_outbound::BoxStream;
use outbound_snell::request::{encode_error, ERROR_ONE_SHOT_EOF, ERROR_REMOTE_EOF, REPLY_TUNNEL};
use outbound_snell::{Decoder, Encoder, Frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub(crate) const READ_CHUNK: usize = 16 * 1024;

/// The client transport with both directions' framing state, which outlives
/// a reusable request (§4).
pub(crate) struct Conn {
    pub(crate) io: BoxStream,
    pub(crate) decoder: Decoder,
    pub(crate) encoder: Encoder,
}

impl Conn {
    /// The next frame, reading as needed; `None` at end of input. Cancel
    /// safe: bytes are fed to the decoder as soon as they are read.
    pub(crate) async fn next_frame(&mut self, raw: &mut [u8]) -> io::Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.decoder.next_frame()? {
                return Ok(Some(frame));
            }
            let n = self.io.read(raw).await?;
            if n == 0 {
                return Ok(None);
            }
            self.decoder.feed(&raw[..n]);
        }
    }

    /// Sends `data` as exactly one frame.
    pub(crate) async fn send_single(&mut self, data: &[u8]) -> io::Result<()> {
        let mut out = Vec::new();
        self.encoder.encode_single(&mut out, data)?;
        self.io.write_all(&out).await?;
        self.io.flush().await
    }
}

/// How a request stream ends its server-to-client direction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ending {
    /// The connection serves more requests: a zero chunk, transport kept.
    KeepOpen,
    /// The connection closes after this request: no zero chunk (so a
    /// reusing client does not pool it), transport shut down.
    Close,
}

/// The payload of one TCP request: reads return the client's data until its
/// zero chunk, writes are framed back with the lazy `0x00` reply in front.
pub(crate) struct RequestStream {
    conn: Conn,
    one_shot: bool,
    ending: Ending,
    plain: Vec<u8>,
    plain_pos: usize,
    read_done: bool,
    /// The read side ended with the client's zero chunk.
    client_zero: bool,
    replied: bool,
    /// Shutdown started.
    finished: bool,
    error_sent: bool,
    out: Vec<u8>,
    out_pos: usize,
}

impl RequestStream {
    /// `early` is client data that came in the request's frame.
    pub(crate) fn new(conn: Conn, one_shot: bool, ending: Ending, early: Vec<u8>) -> Self {
        Self {
            conn,
            one_shot,
            ending,
            plain: early,
            plain_pos: 0,
            read_done: false,
            client_zero: false,
            replied: false,
            finished: false,
            error_sent: false,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Whether both directions ended with zero chunks and the connection can
    /// carry the next request.
    pub(crate) fn reusable(&self) -> bool {
        self.ending == Ending::KeepOpen
            && !self.one_shot
            && self.client_zero
            && self.replied
            && self.finished
            && !self.error_sent
            && self.out_pos >= self.out.len()
    }

    pub(crate) fn into_conn(self) -> Conn {
        self.conn
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.conn.io).poll_write(cx, &self.out[self.out_pos..]))?;
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

impl AsyncRead for RequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain.len() {
                let available = &this.plain[this.plain_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_done {
                return Poll::Ready(Ok(()));
            }
            match this.conn.decoder.next_frame()? {
                Some(Frame::Data(data)) => {
                    this.plain = data;
                    this.plain_pos = 0;
                    continue;
                }
                Some(Frame::Zero) => {
                    this.read_done = true;
                    this.client_zero = true;
                    continue;
                }
                None => {}
            }
            let mut raw = [0u8; READ_CHUNK];
            let mut raw_buf = ReadBuf::new(&mut raw);
            ready!(Pin::new(&mut this.conn.io).poll_read(cx, &mut raw_buf))?;
            if raw_buf.filled().is_empty() {
                this.read_done = true;
                continue;
            }
            this.conn.decoder.feed(raw_buf.filled());
        }
    }
}

impl AsyncWrite for RequestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.replied {
            this.conn.encoder.encode(&mut this.out, buf)?;
        } else {
            let mut first = Vec::with_capacity(buf.len() + 1);
            first.push(REPLY_TUNNEL);
            first.extend_from_slice(buf);
            this.conn.encoder.encode(&mut this.out, &first)?;
            this.replied = true;
        }
        this.out_pos = 0;
        // The payload is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.conn.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.finished {
            this.finished = true;
            if !this.replied {
                // The target closed before sending anything (§3.2).
                let (code, message): (u8, &[u8]) = if this.one_shot {
                    (ERROR_ONE_SHOT_EOF, b"end of file")
                } else {
                    (ERROR_REMOTE_EOF, b"Remote EOF")
                };
                let mut reply = Vec::new();
                encode_error(&mut reply, code, message);
                this.conn.encoder.encode_single(&mut this.out, &reply)?;
                this.error_sent = true;
            } else if this.ending == Ending::KeepOpen && !this.one_shot {
                this.conn.encoder.encode_zero(&mut this.out)?;
            }
            this.out_pos = 0;
            ready!(this.poll_drain(cx))?;
        }
        ready!(Pin::new(&mut this.conn.io).poll_flush(cx))?;
        if this.ending == Ending::KeepOpen && !this.one_shot && !this.error_sent {
            // The client's zero chunk may still be on its way; the session
            // decides whether the connection carries another request.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.conn.io).poll_shutdown(cx)
    }
}
