//! Snell client: TCP streams with optional connection reuse (spec §4), UDP
//! over TCP (§4.1) and PING.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

use crate::codec::{Decoder, Encoder, Frame, Framing, V6Mode};
use crate::crypto::{invalid_data, invalid_input};
use crate::obfs::{HttpObfs, HttpObfsRole};
use crate::request::{
    encode_request, encode_udp_upstream, parse_reply, parse_udp_downstream, Command, Reply,
    ERROR_ONE_SHOT_EOF, ERROR_REMOTE_EOF,
};

pub const PROTOCOL: &str = "snell";

/// Plaintext bytes taken from one application write.
const MAX_WRITE: usize = 32 * 1024;
const READ_CHUNK: usize = 16 * 1024;
/// Connection pool reference values (§4).
const MAX_IDLE: usize = 10;
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// HTTP obfs settings (v1–v4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpObfsSettings {
    pub host: String,
    pub uri: String,
}

/// Client settings. Has no `Debug`: the PSK and user key are secrets.
#[derive(Clone)]
pub struct SnellOptions {
    /// 1–6; 5 runs as 4.
    pub version: u8,
    /// v6 only.
    pub mode: V6Mode,
    pub psk: Vec<u8>,
    /// v1–v4 only.
    pub obfs: Option<HttpObfsSettings>,
    /// Keep finished connections for later requests (v2+).
    pub reuse: bool,
    /// Multi-user server's user key; empty for single-user servers.
    pub user_key: Vec<u8>,
}

/// Snell outbound. It holds the PSK and never prints it.
pub struct SnellOutbound {
    server: String,
    port: u16,
    version: u8,
    framing: Framing,
    psk: Arc<[u8]>,
    obfs: Option<HttpObfsSettings>,
    reuse: bool,
    user_key: Arc<[u8]>,
    dialer: Arc<dyn Dialer>,
    pool: Arc<Pool>,
}

impl SnellOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        options: SnellOptions,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid_input("snell server address is empty"));
        }
        if !(1..=6).contains(&options.version) {
            return Err(invalid_input("snell version must be between 1 and 6"));
        }
        if options.psk.is_empty() {
            return Err(invalid_input("snell psk is empty"));
        }
        if options.obfs.is_some() && options.version > 4 {
            return Err(invalid_input("snell obfs needs version 4 or earlier"));
        }
        if options.user_key.len() > 255 {
            return Err(invalid_input("snell user key is longer than 255 bytes"));
        }
        let framing = Framing::for_version(options.version, options.mode, &options.psk)?;
        Ok(Self {
            server,
            port,
            version: options.version,
            framing,
            psk: options.psk.into(),
            obfs: options.obfs,
            reuse: options.reuse && options.version >= 2,
            user_key: options.user_key.into(),
            dialer,
            pool: Arc::new(Pool::default()),
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    fn command(&self) -> Command {
        match self.version {
            1 => Command::Connect,
            2 | 3 if !self.reuse => Command::Connect,
            _ => Command::ConnectV2,
        }
    }

    async fn open(&self) -> io::Result<SnellConn> {
        let inner = self.dialer.dial(&self.server, self.port).await?;
        let io: BoxStream = match &self.obfs {
            Some(obfs) => Box::new(HttpObfs::new(
                inner,
                HttpObfsRole::Client {
                    host: obfs.host.clone(),
                    uri: obfs.uri.clone(),
                },
            )),
            None => inner,
        };
        Ok(SnellConn {
            io,
            encoder: Encoder::new(self.framing.clone(), &self.psk)?,
            decoder: Decoder::new(self.framing.clone(), self.psk.clone()),
        })
    }

    /// Opens a stream to `target`. The request goes out with the first write.
    pub async fn connect_stream(&self, target: &TargetAddr) -> io::Result<SnellStream> {
        let command = self.command();
        let mut request = Vec::new();
        encode_request(&mut request, command, &self.user_key, Some(target))?;
        let reusable = command == Command::ConnectV2;
        let pool = (self.reuse && reusable).then(|| self.pool.clone());
        let conn = match pool.as_ref().and_then(|pool| pool.take()) {
            Some(conn) => conn,
            None => self.open().await?,
        };
        Ok(SnellStream::new(conn, request, reusable, pool))
    }

    /// Sends PING on a new connection and waits for PONG.
    pub async fn ping(&self) -> io::Result<()> {
        let mut conn = self.open().await?;
        let mut request = Vec::new();
        encode_request(&mut request, Command::Ping, &[], None)?;
        conn.send_single(&request).await?;
        match parse_reply(&conn.read_frame().await?)?.0 {
            Reply::Pong => Ok(()),
            _ => Err(invalid_data("snell server did not answer ping with pong")),
        }
    }

    /// Opens a UDP-over-TCP session (v3+).
    pub async fn udp(&self) -> io::Result<(SnellUdpSender, SnellUdpReceiver)> {
        if self.version < 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snell udp needs version 3 or later",
            ));
        }
        let mut conn = self.open().await?;
        let mut request = Vec::new();
        encode_request(&mut request, Command::Udp, &self.user_key, None)?;
        // The request must be a frame of its own.
        conn.send_single(&request).await?;
        let first = conn.read_frame().await?;
        let (reply, offset) = parse_reply(&first)?;
        match reply {
            Reply::Tunnel => {}
            Reply::Error { code, .. } => return Err(target_error(code)),
            Reply::Pong => return Err(invalid_data("snell server answered udp with pong")),
        }
        // Bytes after the reply in the same frame are the first datagram.
        let pending = (offset < first.len()).then(|| first[offset..].to_vec());
        let SnellConn {
            io,
            encoder,
            decoder,
        } = conn;
        let (reader, writer) = tokio::io::split(io);
        Ok((
            SnellUdpSender {
                writer,
                encoder,
                out: Vec::new(),
            },
            SnellUdpReceiver {
                reader,
                decoder,
                pending,
            },
        ))
    }
}

impl TcpOutbound for SnellOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { Ok(Box::new(self.connect_stream(target).await?) as BoxStream) })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let (sender, receiver) = self.udp().await?;
            Ok(UdpFlow::new(
                Box::new(FlowSend {
                    sender,
                    target: target.clone(),
                }),
                Box::new(receiver),
            ))
        })
    }
}

struct FlowSend {
    sender: SnellUdpSender,
    target: TargetAddr,
}

impl DatagramSend for FlowSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        // A datagram too large for one frame is dropped, as UDP would.
        Box::pin(async move { self.sender.send_to(&self.target, payload).await.map(|_| ()) })
    }
}

impl DatagramRecv for SnellUdpReceiver {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.recv_from().await?.1) })
    }
}

fn target_error(code: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("snell server could not reach the target (error {code})"),
    )
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "snell connection is closed")
}

/// A transport with both directions' framing state.
struct SnellConn {
    io: BoxStream,
    encoder: Encoder,
    decoder: Decoder,
}

impl SnellConn {
    async fn send_single(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut out = Vec::new();
        self.encoder.encode_single(&mut out, plaintext)?;
        self.io.write_all(&out).await?;
        self.io.flush().await
    }

    /// The next data frame; a zero chunk or end of stream is an error here.
    async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match self.decoder.next_frame()? {
                Some(Frame::Data(data)) => return Ok(data),
                Some(Frame::Zero) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell server ended the request without a reply",
                    ))
                }
                None => {
                    let n = self.io.read(&mut buf).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell server closed the connection",
                        ));
                    }
                    self.decoder.feed(&buf[..n]);
                }
            }
        }
    }

    /// Whether an idle connection can carry another request: nothing is
    /// buffered and the server has neither sent data nor closed it.
    fn is_reusable(&mut self) -> bool {
        if self.decoder.buffered() > 0 {
            return false;
        }
        let mut cx = Context::from_waker(Waker::noop());
        let mut probe = [0u8; 1];
        let mut buf = ReadBuf::new(&mut probe);
        Pin::new(&mut self.io)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    }
}

/// Idle reusable connections of one outbound.
#[derive(Default)]
struct Pool {
    idle: Mutex<Vec<(SnellConn, Instant)>>,
}

impl Pool {
    fn take(&self) -> Option<SnellConn> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while let Some((mut conn, since)) = idle.pop() {
            if since.elapsed() < IDLE_TIMEOUT && conn.is_reusable() {
                return Some(conn);
            }
        }
        None
    }

    fn put(&self, conn: SnellConn) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        idle.retain(|(_, since)| since.elapsed() < IDLE_TIMEOUT);
        if idle.len() < MAX_IDLE {
            idle.push((conn, Instant::now()));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyState {
    Waiting,
    Tunnel,
}

/// One Snell request as a byte stream.
pub struct SnellStream {
    conn: Option<SnellConn>,
    /// Where the connection goes back after a clean finish.
    pool: Option<Arc<Pool>>,
    /// CONNECTv2: each direction ends with a zero chunk.
    reusable: bool,
    /// Request plaintext; sent with the first write.
    request: Option<Vec<u8>>,
    out: Vec<u8>,
    out_pos: usize,
    reply: ReplyState,
    plain: Vec<u8>,
    plain_pos: usize,
    read_eof: bool,
    /// The read side ended with the server's zero chunk.
    clean_eof: bool,
    write_closed: bool,
    /// The connection must not be reused.
    broken: bool,
}

impl SnellStream {
    fn new(conn: SnellConn, request: Vec<u8>, reusable: bool, pool: Option<Arc<Pool>>) -> Self {
        Self {
            conn: Some(conn),
            pool,
            reusable,
            request: Some(request),
            out: Vec::new(),
            out_pos: 0,
            reply: ReplyState::Waiting,
            plain: Vec::new(),
            plain_pos: 0,
            read_eof: false,
            clean_eof: false,
            write_closed: false,
            broken: false,
        }
    }

    /// Queues the request on its own (no first write came).
    fn queue_request(&mut self) -> io::Result<()> {
        if let Some(request) = self.request.take() {
            let conn = self.conn.as_mut().ok_or_else(closed)?;
            conn.encoder.encode(&mut self.out, &request)?;
        }
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let Some(conn) = self.conn.as_mut() else {
                return Poll::Ready(Err(closed()));
            };
            match Pin::new(&mut conn.io).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    self.broken = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(err)) => {
                    self.broken = true;
                    return Poll::Ready(Err(err));
                }
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn on_data(&mut self, data: Vec<u8>) -> io::Result<()> {
        if self.reply == ReplyState::Tunnel {
            self.plain = data;
            self.plain_pos = 0;
            return Ok(());
        }
        let (reply, offset) = parse_reply(&data).inspect_err(|_| self.broken = true)?;
        match reply {
            Reply::Tunnel => {
                self.reply = ReplyState::Tunnel;
                self.plain = data;
                self.plain_pos = offset;
                Ok(())
            }
            Reply::Error { code, .. } => {
                // The server closes the connection after an error.
                self.broken = true;
                if code == ERROR_REMOTE_EOF || code == ERROR_ONE_SHOT_EOF {
                    self.read_eof = true;
                    Ok(())
                } else {
                    Err(target_error(code))
                }
            }
            Reply::Pong => {
                self.broken = true;
                Err(invalid_data("snell server answered a connect with pong"))
            }
        }
    }

    /// Returns the connection to the pool once both directions ended cleanly.
    fn maybe_release(&mut self) {
        if self.write_closed
            && self.read_eof
            && self.clean_eof
            && !self.broken
            && self.out_pos >= self.out.len()
        {
            if let (Some(pool), Some(conn)) = (self.pool.take(), self.conn.take()) {
                pool.put(conn);
            }
        }
    }
}

impl Drop for SnellStream {
    fn drop(&mut self) {
        self.maybe_release();
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(err) = std::task::ready!(this.poll_drain(cx)) {
            return Poll::Ready(Err(err));
        }
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_WRITE);
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Err(closed()));
        };
        let encoded = match this.request.take() {
            // 0-RTT: the request and the first data share one buffer.
            Some(mut request) => {
                request.extend_from_slice(&buf[..n]);
                conn.encoder.encode(&mut this.out, &request)
            }
            None => conn.encoder.encode(&mut this.out, &buf[..n]),
        };
        if let Err(err) = encoded {
            this.broken = true;
            return Poll::Ready(Err(err));
        }
        // Committed to `out`; a pending drain finishes on the next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        match this.conn.as_mut() {
            Some(conn) => Pin::new(&mut conn.io).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.conn.is_none() {
            return Poll::Ready(Ok(()));
        }
        if !this.write_closed {
            this.queue_request()?;
            this.write_closed = true;
            if this.reusable {
                let conn = this.conn.as_mut().ok_or_else(closed)?;
                if let Err(err) = conn.encoder.encode_zero(&mut this.out) {
                    this.broken = true;
                    return Poll::Ready(Err(err));
                }
            }
        }
        std::task::ready!(this.poll_drain(cx))?;
        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if !this.reusable {
            // One-shot CONNECT: the end of the TCP stream ends the request.
            return Pin::new(&mut conn.io).poll_shutdown(cx);
        }
        // CONNECTv2: the zero chunk ended this direction; the server may
        // still be sending, so the TCP stream stays open.
        std::task::ready!(Pin::new(&mut conn.io).poll_flush(cx))?;
        this.maybe_release();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.request.is_some() {
            // Reading before the first write: send the request alone.
            this.queue_request()?;
        }
        std::task::ready!(this.poll_drain(cx))?;
        loop {
            if this.plain_pos < this.plain.len() {
                let available = &this.plain[this.plain_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            let Some(conn) = this.conn.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match conn.decoder.next_frame() {
                Err(err) => {
                    this.broken = true;
                    return Poll::Ready(Err(err));
                }
                Ok(Some(Frame::Data(data))) => this.on_data(data)?,
                Ok(Some(Frame::Zero)) => {
                    this.read_eof = true;
                    if this.reply == ReplyState::Tunnel {
                        this.clean_eof = true;
                    } else {
                        this.broken = true;
                    }
                    this.maybe_release();
                }
                Ok(None) => {
                    let mut scratch = [0u8; READ_CHUNK];
                    let mut read = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut conn.io).poll_read(cx, &mut read) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.broken = true;
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {
                            let data = read.filled();
                            if data.is_empty() {
                                this.broken = true;
                                this.read_eof = true;
                                if this.reply == ReplyState::Waiting {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "snell server closed the connection before replying",
                                    )));
                                }
                                continue;
                            }
                            conn.decoder.feed(data);
                        }
                    }
                }
            }
        }
    }
}

/// Sending half of a UDP session.
pub struct SnellUdpSender {
    writer: WriteHalf<BoxStream>,
    encoder: Encoder,
    out: Vec<u8>,
}

impl SnellUdpSender {
    /// Sends one datagram. Returns `false` when it does not fit one frame and
    /// was dropped, as the protocol has no fragmentation.
    pub async fn send_to(&mut self, target: &TargetAddr, payload: &[u8]) -> io::Result<bool> {
        let mut frame = Vec::with_capacity(payload.len() + 32);
        encode_udp_upstream(&mut frame, target, payload)?;
        if frame.len() > self.encoder.framing().max_payload() {
            return Ok(false);
        }
        self.out.clear();
        self.encoder.encode_single(&mut self.out, &frame)?;
        self.writer.write_all(&self.out).await?;
        self.writer.flush().await?;
        Ok(true)
    }
}

/// Receiving half of a UDP session.
pub struct SnellUdpReceiver {
    reader: ReadHalf<BoxStream>,
    decoder: Decoder,
    pending: Option<Vec<u8>>,
}

impl SnellUdpReceiver {
    /// The next datagram and its source.
    pub async fn recv_from(&mut self) -> io::Result<(SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let frame = match self.pending.take() {
                Some(frame) => frame,
                None => match self.decoder.next_frame()? {
                    Some(Frame::Data(frame)) => frame,
                    Some(Frame::Zero) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    None => {
                        let n = self.reader.read(&mut buf).await?;
                        if n == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        self.decoder.feed(&buf[..n]);
                        continue;
                    }
                },
            };
            if let Some((source, payload)) = parse_udp_downstream(&frame)? {
                return Ok((source, payload.to_vec()));
            }
        }
    }
}
