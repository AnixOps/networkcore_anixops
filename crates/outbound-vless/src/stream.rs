//! The proxied VLESS stream, optionally with XTLS Vision.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tls_mimic::TlsStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::vision::{ReadStatus, TrafficState, VisionReader, VisionWriter, COMMAND_CONTINUE};

const READ_CHUNK: usize = 16 * 1024;
const MAX_WRITE: usize = 16 * 1024;

struct Vision {
    traffic: TrafficState,
    writer: VisionWriter,
    reader: VisionReader,
}

enum Response {
    Header(Vec<u8>),
    Done,
}

/// A VLESS connection over an established (REALITY) TLS stream.
///
/// The request header is sent lazily together with the first payload, as
/// Xray does; a read or flush before any payload sends the header alone
/// (with an empty Vision padding frame when Vision is enabled).
pub struct VlessStream<S> {
    tls: TlsStream<S>,
    request_header: Option<Vec<u8>>,
    vision: Option<Vision>,
    response: Response,
    pending: Vec<u8>,
    pending_pos: usize,
    switch_to_raw_write: bool,
    needs_flush: bool,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_eof: bool,
    scratch: Vec<u8>,
}

impl<S> VlessStream<S> {
    pub(crate) fn new(
        tls: TlsStream<S>,
        request_header: Vec<u8>,
        vision_uuid: Option<[u8; 16]>,
    ) -> Self {
        Self {
            tls,
            request_header: Some(request_header),
            vision: vision_uuid.map(|uuid| Vision {
                traffic: TrafficState::default(),
                writer: VisionWriter::new(uuid),
                reader: VisionReader::new(uuid),
            }),
            response: Response::Header(Vec::new()),
            pending: Vec::new(),
            pending_pos: 0,
            switch_to_raw_write: false,
            needs_flush: false,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            scratch: vec![0u8; READ_CHUNK],
        }
    }

    /// True once the uplink copies inner TLS records over the raw transport.
    pub fn is_direct_write(&self) -> bool {
        self.tls.is_raw_write()
    }

    /// True once the downlink reads inner TLS records from the raw transport.
    pub fn is_direct_read(&self) -> bool {
        self.tls.is_raw_read()
    }

    /// Inner-traffic classification made by Vision, if enabled.
    pub fn vision_state(&self) -> Option<&TrafficState> {
        self.vision.as_ref().map(|vision| &vision.traffic)
    }

    fn queue_header_only(&mut self) -> io::Result<()> {
        if let Some(header) = self.request_header.take() {
            self.pending.extend_from_slice(&header);
            if let Some(vision) = self.vision.as_mut() {
                vision
                    .writer
                    .pad(&[], COMMAND_CONTINUE, &mut self.pending)?;
            }
            self.needs_flush = true;
        }
        Ok(())
    }

    fn process_downlink(&mut self, chunk: &[u8]) -> io::Result<()> {
        let owned;
        let mut data = chunk;
        if let Response::Header(buffer) = &mut self.response {
            buffer.extend_from_slice(data);
            if buffer.len() < 2 {
                return Ok(());
            }
            let header_len = 2 + buffer[1] as usize;
            if buffer.len() < header_len {
                return Ok(());
            }
            if buffer[0] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected VLESS response version",
                ));
            }
            owned = buffer.split_off(header_len);
            data = &owned;
            self.response = Response::Done;
        }
        if data.is_empty() {
            return Ok(());
        }
        let start = self.read_buf.len();
        match self.vision.as_mut() {
            Some(vision) => {
                let status = vision.reader.feed(data, &mut self.read_buf);
                if vision.traffic.packets_to_filter > 0 && self.read_buf.len() > start {
                    vision.traffic.filter(&self.read_buf[start..]);
                }
                if status == ReadStatus::Direct && !self.tls.is_raw_read() {
                    self.tls.start_raw_read();
                }
            }
            None => self.read_buf.extend_from_slice(data),
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessStream<S> {
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
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
            this.queue_header_only()?;
            if this.needs_flush {
                ready!(this.poll_drain(cx))?;
                ready!(Pin::new(&mut this.tls).poll_flush(cx))?;
                this.needs_flush = false;
            }

            let mut chunk_buf = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.tls).poll_read(cx, &mut chunk_buf))?;
            let filled = chunk_buf.filled().len();
            if filled == 0 {
                if let Response::Header(_) = this.response {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS server closed the connection before responding",
                    )));
                }
                if let Some(vision) = this.vision.as_mut() {
                    let held = vision.reader.take_pending();
                    this.read_buf.extend_from_slice(&held);
                }
                this.read_eof = true;
                continue;
            }
            let chunk = this.scratch[..filled].to_vec();
            this.process_downlink(&chunk)?;
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
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
        if let Some(header) = this.request_header.take() {
            this.pending.extend_from_slice(&header);
        }
        match this.vision.as_mut() {
            Some(vision) if vision.writer.is_padding() => {
                if vision
                    .writer
                    .encode(&mut vision.traffic, data, &mut this.pending)?
                {
                    this.switch_to_raw_write = true;
                }
            }
            _ => this.pending.extend_from_slice(data),
        }
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.queue_header_only()?;
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.tls).poll_flush(cx))?;
        this.needs_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}
