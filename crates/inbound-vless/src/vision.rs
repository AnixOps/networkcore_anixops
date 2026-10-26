//! XTLS Vision, server side (Xray `proxy/vless/inbound`).
//!
//! The framing is shared with the client (`outbound_vless::vision`): the
//! uplink is unpadded with a [`VisionReader`] and the downlink padded with a
//! [`VisionWriter`], both keyed by the user's UUID. One [`TrafficState`] sees
//! the inner ClientHello on the way up and the ServerHello on the way down.
//! When the inner traffic is TLS 1.3, each direction leaves the outer
//! REALITY TLS after its `direct` command and the inner records are copied
//! over the raw transport.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use outbound_vless::vision::{ReadStatus, TrafficState, VisionReader, VisionWriter};
use tls_mimic::TlsStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const READ_CHUNK: usize = 16 * 1024;
const MAX_WRITE: usize = 16 * 1024;

/// An accepted VLESS Vision connection over the REALITY TLS stream.
///
/// The response header `VER(0) ADDONS_LEN(0)` goes out with the first
/// payload, or alone at shutdown when the target sent nothing.
pub struct VisionStream<S> {
    tls: TlsStream<S>,
    traffic: TrafficState,
    writer: VisionWriter,
    reader: VisionReader,
    response_header: Option<[u8; 2]>,
    pending: Vec<u8>,
    pending_pos: usize,
    switch_to_raw_write: bool,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_eof: bool,
    scratch: Vec<u8>,
}

impl<S> VisionStream<S> {
    /// `payload` holds uplink bytes read together with the request header.
    pub fn new(tls: TlsStream<S>, uuid: [u8; 16], payload: &[u8]) -> Self {
        let mut stream = Self {
            tls,
            traffic: TrafficState::default(),
            writer: VisionWriter::new(uuid),
            reader: VisionReader::new(uuid),
            response_header: Some([0, 0]),
            pending: Vec::new(),
            pending_pos: 0,
            switch_to_raw_write: false,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            scratch: vec![0u8; READ_CHUNK],
        };
        stream.process_uplink(payload);
        stream
    }

    /// True once the downlink copies inner TLS records over the raw transport.
    pub fn is_direct_write(&self) -> bool {
        self.tls.is_raw_write()
    }

    /// True once the uplink reads inner TLS records from the raw transport.
    pub fn is_direct_read(&self) -> bool {
        self.tls.is_raw_read()
    }

    pub fn vision_state(&self) -> &TrafficState {
        &self.traffic
    }

    fn process_uplink(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let start = self.read_buf.len();
        let status = self.reader.feed(data, &mut self.read_buf);
        if self.traffic.packets_to_filter > 0 && self.read_buf.len() > start {
            self.traffic.filter(&self.read_buf[start..]);
        }
        if status == ReadStatus::Direct && !self.tls.is_raw_read() {
            self.tls.start_raw_read();
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let written =
                ready!(Pin::new(&mut self.tls).poll_write(cx, &self.pending[self.pending_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_pos += written;
        }
        self.pending.clear();
        self.pending_pos = 0;
        if self.switch_to_raw_write {
            self.switch_to_raw_write = false;
            self.tls.start_raw_write();
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let available = &this.read_buf[this.read_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.read_pos += n;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            let mut chunk_buf = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.tls).poll_read(cx, &mut chunk_buf))?;
            let filled = chunk_buf.filled().len();
            if filled == 0 {
                let held = this.reader.take_pending();
                this.read_buf.extend_from_slice(&held);
                this.read_eof = true;
                continue;
            }
            let chunk = this.scratch[..filled].to_vec();
            this.process_uplink(&chunk);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let data = &data[..data.len().min(MAX_WRITE)];
        if let Some(header) = this.response_header.take() {
            this.pending.extend_from_slice(&header);
        }
        if this.writer.is_padding() {
            if this
                .writer
                .encode(&mut this.traffic, data, &mut this.pending)?
            {
                this.switch_to_raw_write = true;
            }
        } else {
            this.pending.extend_from_slice(data);
        }
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(header) = this.response_header.take() {
            this.pending.extend_from_slice(&header);
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}
