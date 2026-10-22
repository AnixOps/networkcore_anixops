//! Post-handshake TLS 1.3 record stream.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::{invalid_data, CipherSuite, RecordCipher, MAX_CIPHERTEXT, MAX_PLAINTEXT};

const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;
const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;

/// An established TLS 1.3 connection over `S`.
///
/// Besides the usual stream behaviour it can hand the underlying transport
/// over to the caller one direction at a time ([`TlsStream::start_raw_read`],
/// [`TlsStream::start_raw_write`]); XTLS Vision uses this to stop wrapping
/// inner TLS traffic in a second layer of encryption.
pub struct TlsStream<S> {
    io: S,
    suite: CipherSuite,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    reader: RecordCipher,
    writer: RecordCipher,
    alpn: Option<Vec<u8>>,
    raw_in: Vec<u8>,
    plain_in: Vec<u8>,
    plain_pos: usize,
    handshake_in: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    read_closed: bool,
    close_notify_sent: bool,
    key_update_requested: bool,
    raw_read: bool,
    raw_write: bool,
}

impl<S> TlsStream<S> {
    pub(crate) fn new(
        io: S,
        suite: CipherSuite,
        write_secret: Vec<u8>,
        read_secret: Vec<u8>,
        alpn: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        Ok(Self {
            reader: RecordCipher::new(suite, &read_secret)?,
            writer: RecordCipher::new(suite, &write_secret)?,
            io,
            suite,
            read_secret,
            write_secret,
            alpn,
            raw_in: Vec::new(),
            plain_in: Vec::new(),
            plain_pos: 0,
            handshake_in: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            read_closed: false,
            close_notify_sent: false,
            key_update_requested: false,
            raw_read: false,
            raw_write: false,
        })
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// ALPN protocol selected by the server, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// From now on reads bypass TLS: buffered plaintext is returned first,
    /// then bytes already read but not yet decrypted, then the transport.
    pub fn start_raw_read(&mut self) {
        self.raw_read = true;
    }

    /// From now on writes bypass TLS. Pending encrypted output is written to
    /// the transport before any raw byte, so ordering is preserved.
    pub fn start_raw_write(&mut self) {
        self.raw_write = true;
    }

    pub fn is_raw_read(&self) -> bool {
        self.raw_read
    }

    pub fn is_raw_write(&self) -> bool {
        self.raw_write
    }

    fn take_record(&mut self) -> io::Result<Option<(u8, [u8; 5], Vec<u8>)>> {
        if self.raw_in.len() < 5 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([self.raw_in[3], self.raw_in[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(invalid_data("TLS record too large"));
        }
        if self.raw_in.len() < 5 + len {
            return Ok(None);
        }
        let mut header = [0u8; 5];
        header.copy_from_slice(&self.raw_in[..5]);
        let payload = self.raw_in[5..5 + len].to_vec();
        self.raw_in.drain(..5 + len);
        Ok(Some((header[0], header, payload)))
    }

    fn process_record(&mut self, header: [u8; 5], mut payload: Vec<u8>) -> io::Result<()> {
        match header[0] {
            CONTENT_CHANGE_CIPHER_SPEC => Ok(()),
            CONTENT_APPLICATION_DATA => {
                let content_type = self.reader.open(&header, &mut payload)?;
                match content_type {
                    CONTENT_APPLICATION_DATA => {
                        self.plain_in = payload;
                        self.plain_pos = 0;
                        Ok(())
                    }
                    CONTENT_HANDSHAKE => {
                        self.handshake_in.extend_from_slice(&payload);
                        self.process_post_handshake()
                    }
                    CONTENT_ALERT => self.process_alert(&payload),
                    _ => Err(invalid_data("unexpected TLS inner content type")),
                }
            }
            _ => Err(invalid_data("unexpected TLS record type after handshake")),
        }
    }

    fn process_alert(&mut self, payload: &[u8]) -> io::Result<()> {
        match payload {
            [_, 0] => {
                self.read_closed = true;
                Ok(())
            }
            [_, description] => Err(crate::alert_error(*description)),
            _ => Err(invalid_data("malformed TLS alert")),
        }
    }

    fn process_post_handshake(&mut self) -> io::Result<()> {
        while self.handshake_in.len() >= 4 {
            let len = ((self.handshake_in[1] as usize) << 16)
                | ((self.handshake_in[2] as usize) << 8)
                | self.handshake_in[3] as usize;
            if len > 64 * 1024 {
                return Err(invalid_data("post-handshake message too large"));
            }
            if self.handshake_in.len() < 4 + len {
                break;
            }
            let message: Vec<u8> = self.handshake_in.drain(..4 + len).collect();
            match message[0] {
                // NewSessionTicket: resumption is not used.
                4 => {}
                // KeyUpdate
                24 => {
                    if len != 1 || message[4] > 1 {
                        return Err(invalid_data("malformed TLS KeyUpdate"));
                    }
                    let hash = self.suite.hash();
                    self.read_secret =
                        hash.expand_label(&self.read_secret, "traffic upd", &[], hash.output_len());
                    self.reader = RecordCipher::new(self.suite, &self.read_secret)?;
                    if message[4] == 1 {
                        self.key_update_requested = true;
                    }
                }
                _ => return Err(invalid_data("unexpected post-handshake message")),
            }
        }
        Ok(())
    }

    fn queue_key_update(&mut self) -> io::Result<()> {
        if !self.key_update_requested || self.raw_write {
            return Ok(());
        }
        self.key_update_requested = false;
        self.writer
            .seal(CONTENT_HANDSHAKE, &[24, 0, 0, 1, 0], &mut self.out)?;
        let hash = self.suite.hash();
        self.write_secret =
            hash.expand_label(&self.write_secret, "traffic upd", &[], hash.output_len());
        self.writer = RecordCipher::new(self.suite, &self.write_secret)?;
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> TlsStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let written = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += written;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain_in.len() {
                let available = &this.plain_in[this.plain_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.plain_pos += n;
                if this.plain_pos == this.plain_in.len() {
                    this.plain_in.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.raw_read {
                if !this.raw_in.is_empty() {
                    let n = this.raw_in.len().min(buf.remaining());
                    buf.put_slice(&this.raw_in[..n]);
                    this.raw_in.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            if let Some((_, header, payload)) = this.take_record()? {
                this.process_record(header, payload)?;
                continue;
            }
            let mut chunk = [0u8; 8192];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut chunk_buf))?;
            let filled = chunk_buf.filled();
            if filled.is_empty() {
                if this.raw_in.is_empty() {
                    // Peer closed without close_notify; report EOF.
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS connection closed inside a record",
                )));
            }
            this.raw_in.extend_from_slice(filled);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.raw_write {
            return Pin::new(&mut this.io).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.queue_key_update()?;
        let n = data.len().min(MAX_PLAINTEXT);
        this.writer
            .seal(CONTENT_APPLICATION_DATA, &data[..n], &mut this.out)?;
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.queue_key_update()?;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.raw_write && !this.close_notify_sent {
            this.close_notify_sent = true;
            this.writer.seal(CONTENT_ALERT, &[1, 0], &mut this.out)?;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
