//! sing-mux, the multiplexing of sing-box and mihomo (`multiplex` and `smux`
//! in their outbound options).
//!
//! The client asks any protocol that carries a destination for the name
//! [`DESTINATION`] (port 444) and then sends, on that connection,
//!
//! ```text
//! VERSION PROTOCOL [PADDING]        (PADDING from version 1 on)
//! ```
//!
//! and runs the multiplexer PROTOCOL names: 0 smux, 1 yamux, 2 h2mux. Every
//! stream the client opens starts with a request and is answered with a
//! status ahead of the first data:
//!
//! ```text
//! FLAGS(2) ATYP ADDR PORT           (client; a SOCKS address)
//! STATUS [LENGTH MESSAGE]           (server; 0, or 1 with a message)
//! ```
//!
//! FLAGS bit 0 makes the stream UDP: `LENGTH(2) PAYLOAD` packets to the
//! destination, and with bit 1 each packet behind its own `ATYP ADDR PORT`
//! (the destination, or the source of a reply). A stream that cannot be
//! served is closed without a status.
//!
//! smux (version 1) frames are `VERSION CMD LENGTH(2) STREAM(4)`, little
//! endian, with the commands SYN (0), FIN (1), PSH (2) and NOP (3). It has no
//! flow control, so a stream whose target is a window behind holds back the
//! reading of the whole connection, and no half-closed streams: FIN ends
//! both directions.
//!
//! yamux frames are `VERSION(0) TYPE FLAGS(2) STREAM(4) LENGTH(4)`, big
//! endian, with the types Data (0), WindowUpdate (1), Ping (2) and GoAway
//! (3) and the flags SYN (1), ACK (2), FIN (4) and RST (8). LENGTH is the
//! payload size of Data, the window increment of WindowUpdate and the value
//! of a Ping. Each direction of a stream starts with a 256 KiB window: the
//! server sends within the client's and reopens its own as the relay takes
//! the data. A stream the client resets is dropped at once.
//!
//! Each stream is relayed like a client connection of its own
//! ([`relay_stream`]): through the outbound or as a UDP session, counted
//! against the user and held to its speed limit. The connection ends when
//! the client closes it or the user is removed. Only connections the serve
//! loop relays get here: an inbound that connects its streams itself
//! (AnyTLS, Snell) dials the name like any other.
//!
//! Not supported, and closed when asked for: h2mux, padding. TCP Brutal is
//! not negotiated.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify, Semaphore};

use crate::addr::{read_addr_port, write_addr_port, SOCKS};
use crate::mux::write_frames;
use crate::server::{relay_stream, InboundStats, ServeSettings};
use crate::stream::PrefixedStream;
use crate::udp::{Datagram, DatagramCodec, DatagramReader, UdpOutbound};
use crate::{Accepted, UserEntry};

/// The destination a client names to open a multiplexed connection.
const DESTINATION: &str = "sp.mux.sing-box.arpa";

const SMUX_VERSION: u8 = 1;
const SMUX_SYN: u8 = 0;
const SMUX_FIN: u8 = 1;
const SMUX_PSH: u8 = 2;
const SMUX_NOP: u8 = 3;

const YAMUX_DATA: u8 = 0;
const YAMUX_WINDOW_UPDATE: u8 = 1;
const YAMUX_PING: u8 = 2;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;
/// The yamux window of each direction of a new stream, and the client data
/// held for a stream of either multiplexer.
const WINDOW: u32 = 256 * 1024;

const STREAM_UDP: u16 = 1;
const STREAM_ADDRESSED: u16 = 2;
const STATUS_OK: u8 = 0;

/// Streams open at once on one connection.
const MAX_STREAMS: usize = 256;
/// Payload bytes per frame toward the client.
const MAX_PAYLOAD: usize = 16 * 1024;
/// Frames queued toward the client.
const QUEUE: usize = 16;

/// Whether `target` asks for a multiplexed connection instead of naming a
/// destination.
pub(crate) fn requested(target: &TargetAddr) -> bool {
    matches!(target, TargetAddr::Domain(domain, _) if domain == DESTINATION)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Smux,
    Yamux,
}

/// One client frame, in the terms both multiplexers share.
#[derive(Debug, Default, PartialEq, Eq)]
struct Frame {
    stream: u32,
    /// The frame opens the stream.
    open: bool,
    data: Vec<u8>,
    /// yamux: what the client's window for the stream grew by.
    credit: u32,
    /// The client sends nothing more on the stream.
    fin: bool,
    /// The client dropped the stream.
    reset: bool,
    /// The answer to a yamux ping.
    reply: Option<Vec<u8>>,
}

impl Protocol {
    async fn read<R: AsyncRead + Unpin>(self, reader: &mut R) -> io::Result<Frame> {
        match self {
            Protocol::Smux => read_smux(reader).await,
            Protocol::Yamux => read_yamux(reader).await,
        }
    }

    fn data(self, stream: u32, data: &[u8]) -> Vec<u8> {
        let mut frame = match self {
            Protocol::Smux => smux_header(SMUX_PSH, stream, data.len() as u16),
            Protocol::Yamux => yamux_header(YAMUX_DATA, 0, stream, data.len() as u32),
        };
        frame.extend_from_slice(data);
        frame
    }

    /// The server sends nothing more on `stream`.
    fn fin(self, stream: u32) -> Vec<u8> {
        match self {
            Protocol::Smux => smux_header(SMUX_FIN, stream, 0),
            Protocol::Yamux => yamux_header(YAMUX_WINDOW_UPDATE, FLAG_FIN, stream, 0),
        }
    }

    /// The server dropped `stream`; smux says that with FIN too.
    fn reset(self, stream: u32) -> Vec<u8> {
        match self {
            Protocol::Smux => smux_header(SMUX_FIN, stream, 0),
            Protocol::Yamux => yamux_header(YAMUX_WINDOW_UPDATE, FLAG_RST, stream, 0),
        }
    }
}

fn smux_header(command: u8, stream: u32, length: u16) -> Vec<u8> {
    let mut header = vec![SMUX_VERSION, command];
    header.extend_from_slice(&length.to_le_bytes());
    header.extend_from_slice(&stream.to_le_bytes());
    header
}

fn yamux_header(kind: u8, flags: u16, stream: u32, length: u32) -> Vec<u8> {
    let mut header = vec![0, kind];
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&stream.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header
}

async fn read_smux<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;
    let mut data = vec![0u8; usize::from(u16::from_le_bytes([header[2], header[3]]))];
    reader.read_exact(&mut data).await?;
    let mut frame = Frame {
        stream: u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
        ..Frame::default()
    };
    match (header[0], header[1]) {
        (SMUX_VERSION, SMUX_SYN) => frame.open = true,
        (SMUX_VERSION, SMUX_FIN) => frame.fin = true,
        (SMUX_VERSION, SMUX_PSH) => frame.data = data,
        (SMUX_VERSION, SMUX_NOP) => {}
        _ => return Err(invalid("smux frame is not supported")),
    }
    Ok(frame)
}

async fn read_yamux<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let mut header = [0u8; 12];
    reader.read_exact(&mut header).await?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let mut frame = Frame {
        stream: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        open: flags & FLAG_SYN != 0,
        fin: flags & FLAG_FIN != 0,
        reset: flags & FLAG_RST != 0,
        ..Frame::default()
    };
    match (header[0], header[1]) {
        // A client never sends more than a window at once.
        (0, YAMUX_DATA) if length <= WINDOW => {
            frame.data = vec![0u8; length as usize];
            reader.read_exact(&mut frame.data).await?;
        }
        (0, YAMUX_WINDOW_UPDATE) => frame.credit = length,
        // SYN is the ping, ACK the answer to one of ours (none are sent).
        (0, YAMUX_PING) => {
            return Ok(Frame {
                reply: frame
                    .open
                    .then(|| yamux_header(YAMUX_PING, FLAG_ACK, 0, length)),
                ..Frame::default()
            })
        }
        // GoAway, or not yamux.
        _ => return Err(invalid("yamux session ended")),
    }
    Ok(frame)
}

/// Reads the session request and answers the multiplexer the client runs.
async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Protocol> {
    let version = reader.read_u8().await?;
    let protocol = reader.read_u8().await?;
    // Version 1 adds the padding flag; padded sessions are not supported.
    if version > 1 || (version == 1 && reader.read_u8().await? != 0) {
        return Err(invalid("sing-mux version or padding is not supported"));
    }
    match protocol {
        0 => Ok(Protocol::Smux),
        1 => Ok(Protocol::Yamux),
        _ => Err(invalid("sing-mux protocol is not supported")),
    }
}

/// Reads a stream's request: its flags and destination.
async fn read_stream_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(u16, TargetAddr)> {
    let flags = reader.read_u16().await?;
    Ok((flags, read_addr_port(reader, SOCKS).await?))
}

/// UDP on a stream: `LENGTH(2) PAYLOAD` per packet, all to the stream's
/// destination, or with `addressed` each behind its own `ATYP ADDR PORT`.
struct Datagrams {
    target: TargetAddr,
    addressed: bool,
}

impl Datagrams {
    /// The packet framing of a stream to `target` with `flags`; `None` for
    /// a TCP stream.
    fn of(flags: u16, target: &TargetAddr) -> Option<Box<dyn DatagramCodec>> {
        (flags & STREAM_UDP != 0).then(|| {
            Box::new(Datagrams {
                target: target.clone(),
                addressed: flags & STREAM_ADDRESSED != 0,
            }) as Box<dyn DatagramCodec>
        })
    }
}

impl DatagramCodec for Datagrams {
    fn read<'a>(
        &'a self,
        mut reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<Datagram>>> {
        Box::pin(async move {
            let packet = async {
                let target = if self.addressed {
                    read_addr_port(&mut reader, SOCKS).await?
                } else {
                    self.target.clone()
                };
                let mut payload = vec![0u8; usize::from(reader.read_u16().await?)];
                reader.read_exact(&mut payload).await?;
                Ok::<_, io::Error>((target, payload))
            };
            match packet.await {
                Ok(datagram) => Ok(Some(datagram)),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    fn encode(&self, source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "udp payload too large"))?;
        if self.addressed {
            write_addr_port(out, source, SOCKS);
        }
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }
}

/// One stream of a multiplexed connection, as the relay sees a client
/// connection: reads return what the read loop queued, writes become data
/// frames in the connection's queue.
struct MuxStream {
    id: u32,
    protocol: Protocol,
    /// Client data; the end of the queue is the client's FIN.
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    chunk: Vec<u8>,
    /// How much of `chunk` the relay has read.
    read: usize,
    /// The client sent its last byte.
    ended: bool,
    /// The bytes the read loop may still queue; closed with the stream.
    room: Arc<Semaphore>,
    frames: mpsc::Sender<Vec<u8>>,
    /// yamux: the bytes the client still takes.
    window: Option<Arc<Semaphore>>,
    /// yamux: bytes read since the client's window was last reopened.
    taken: u32,
    /// yamux: window updates on their way to the queue.
    updates: mpsc::UnboundedSender<Vec<u8>>,
    /// The frame on its way to the queue.
    sending: Option<BoxFuture<'static, bool>>,
    /// The server's FIN is out.
    shut: bool,
    /// Notified when the client resets the stream.
    dropped: Arc<Notify>,
}

impl MuxStream {
    /// Queues `frame` once the client's window has room for `credit` bytes.
    fn send(&mut self, frame: Vec<u8>, credit: usize) {
        let frames = self.frames.clone();
        let window = self.window.clone().filter(|_| credit > 0);
        self.sending = Some(Box::pin(async move {
            if let Some(window) = window {
                match window.acquire_many(credit as u32).await {
                    Ok(permit) => permit.forget(),
                    Err(_) => return false,
                }
            }
            frames.send(frame).await.is_ok()
        }));
    }

    /// Ready once the last frame is queued.
    fn poll_sent(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(sending) = &mut self.sending {
            let sent = ready!(sending.as_mut().poll(cx));
            self.sending = None;
            if !sent {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// yamux: reopens the client's window by what the relay has read, half
    /// a window at a time. The update waits for the queue in the
    /// connection's loop, not here: reads are polled only while the relay
    /// wants data, and a wait nobody polls keeps its place in the queue.
    fn grant(&mut self) {
        if self.taken >= WINDOW / 2 {
            let update = yamux_header(YAMUX_WINDOW_UPDATE, 0, self.id, self.taken);
            let _ = self.updates.send(update);
            self.taken = 0;
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read == this.chunk.len() && !this.ended {
            match ready!(this.input.poll_recv(cx)) {
                Some(chunk) => {
                    this.chunk = chunk;
                    this.read = 0;
                }
                // FIN, or the connection is gone.
                None => this.ended = true,
            }
        }
        let n = (this.chunk.len() - this.read).min(buf.remaining());
        buf.put_slice(&this.chunk[this.read..this.read + n]);
        this.read += n;
        this.room.add_permits(n);
        if this.window.is_some() {
            this.taken += n as u32;
            this.grant();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_sent(cx))?;
        // After a smux FIN the client reads nothing more.
        if this.ended && this.protocol == Protocol::Smux {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(MAX_PAYLOAD);
        this.send(this.protocol.data(this.id, &buf[..n]), n);
        // The bytes are in the frame; a pending send finishes on the next
        // call.
        if let Poll::Ready(Err(error)) = this.poll_sent(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_sent(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_sent(cx))?;
        if !this.shut {
            this.shut = true;
            this.send(this.protocol.fin(this.id), 0);
        }
        this.poll_sent(cx)
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.room.close();
    }
}

/// What the read loop keeps of a stream.
struct Handle {
    /// Gone once the client sent FIN.
    input: Option<mpsc::UnboundedSender<Vec<u8>>>,
    room: Arc<Semaphore>,
    window: Option<Arc<Semaphore>>,
    dropped: Arc<Notify>,
}

/// Serves a multiplexed connection until the client closes it, writing to
/// it fails or the user is removed.
pub(crate) async fn relay(
    stream: BoxStream,
    user: Option<Arc<UserEntry>>,
    outbound: &dyn TcpOutbound,
    udp: Option<&dyn UdpOutbound>,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let Ok(protocol) = read_request(&mut reader).await else {
        stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let (frames, mut outgoing) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (updates, mut granted) = mpsc::unbounded_channel::<Vec<u8>>();
    let (spawn, mut spawned) = mpsc::unbounded_channel::<MuxStream>();

    let read = read_loop(protocol, &mut reader, &frames, &updates, &spawn);
    let write = write_frames(&mut writer, &mut outgoing);
    // Window updates on their way to the queue; a client sends within its
    // window, so there are never many.
    let grant = async {
        while let Some(update) = granted.recv().await {
            let _ = frames.send(update).await;
        }
    };
    let revoked = async {
        match &user {
            Some(user) => user.revoked().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(read, write, grant, revoked);

    let mut running = FuturesUnordered::new();
    loop {
        tokio::select! {
            // The streams watch the user too; the connection goes first.
            biased;
            _ = &mut revoked => {
                stats.revoked.fetch_add(1, Ordering::Relaxed);
                break;
            }
            _ = &mut read => break,
            _ = &mut write => break,
            _ = &mut grant => break,
            Some(stream) = spawned.recv() => {
                running.push(serve_stream(stream, user.clone(), outbound, udp, settings, stats));
            }
            Some(()) = running.next(), if !running.is_empty() => {}
        }
    }
}

/// Reads client frames and hands their data to the streams. Returns when
/// the client closes the connection or sends a frame that is not valid.
async fn read_loop<R: AsyncRead + Unpin>(
    protocol: Protocol,
    reader: &mut R,
    frames: &mpsc::Sender<Vec<u8>>,
    updates: &mpsc::UnboundedSender<Vec<u8>>,
    spawn: &mpsc::UnboundedSender<MuxStream>,
) {
    let mut streams: HashMap<u32, Handle> = HashMap::new();
    while let Ok(frame) = protocol.read(reader).await {
        if let Some(reply) = frame.reply {
            if frames.send(reply).await.is_err() {
                return;
            }
        }
        if frame.open {
            // Streams count until their relay is gone.
            streams.retain(|_, stream| !stream.room.is_closed());
            if streams.len() >= MAX_STREAMS || streams.contains_key(&frame.stream) {
                if frames.send(protocol.reset(frame.stream)).await.is_err() {
                    return;
                }
                continue;
            }
            let (input, receiver) = mpsc::unbounded_channel();
            let room = Arc::new(Semaphore::new(WINDOW as usize));
            let window =
                (protocol == Protocol::Yamux).then(|| Arc::new(Semaphore::new(WINDOW as usize)));
            let dropped = Arc::new(Notify::new());
            let stream = MuxStream {
                id: frame.stream,
                protocol,
                input: receiver,
                chunk: Vec::new(),
                read: 0,
                ended: false,
                room: room.clone(),
                frames: frames.clone(),
                window: window.clone(),
                taken: 0,
                updates: updates.clone(),
                sending: None,
                shut: false,
                dropped: dropped.clone(),
            };
            if spawn.send(stream).is_err() {
                return;
            }
            let input = Some(input);
            streams.insert(
                frame.stream,
                Handle {
                    input,
                    room,
                    window,
                    dropped,
                },
            );
            // A yamux client waits for the stream to be acknowledged.
            let ack = yamux_header(YAMUX_WINDOW_UPDATE, FLAG_ACK, frame.stream, 0);
            if protocol == Protocol::Yamux && frames.send(ack).await.is_err() {
                return;
            }
        }
        if frame.reset {
            // Ends its relay, whatever that waits for; the stream counts
            // until the relay is gone.
            if let Some(stream) = streams.get(&frame.stream) {
                stream.dropped.notify_one();
            }
            continue;
        }
        let Some(stream) = streams.get_mut(&frame.stream) else {
            continue;
        };
        if let Some(window) = &stream.window {
            let room = Semaphore::MAX_PERMITS - window.available_permits();
            window.add_permits(room.min(frame.credit as usize));
        }
        if let (Some(input), false) = (&stream.input, frame.data.is_empty()) {
            // Waits for the relay when the stream is a window ahead of it,
            // which a yamux client never is; fails once the stream ended
            // on the server side.
            if let Ok(room) = stream.room.acquire_many(frame.data.len() as u32).await {
                room.forget();
                let _ = input.send(frame.data);
            }
        }
        if frame.fin {
            stream.input = None;
        }
    }
}

/// Reads the stream's request and relays it to its destination, until the
/// relay ends or the client resets the stream.
async fn serve_stream(
    mut stream: MuxStream,
    user: Option<Arc<UserEntry>>,
    outbound: &dyn TcpOutbound,
    udp: Option<&dyn UdpOutbound>,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    let (frames, reset) = (stream.frames.clone(), stream.protocol.reset(stream.id));
    let dropped = stream.dropped.clone();
    let serve = async {
        if let Ok((flags, target)) = read_stream_request(&mut stream).await {
            // The status goes out with the first payload.
            let stream = PrefixedStream::new(Box::new(stream)).with_write_prefix(vec![STATUS_OK]);
            let accepted = Accepted {
                user,
                udp: Datagrams::of(flags, &target),
                target,
                stream: Box::new(stream),
                mux: false,
            };
            relay_stream(accepted, outbound, udp, settings, stats).await;
        }
    };
    tokio::select! {
        _ = serve => {}
        _ = dropped.notified() => {}
    }
    // The client ignores it for a stream both sides have closed.
    let _ = frames.send(reset).await;
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(mut bytes: &[u8]) -> io::Result<Protocol> {
        read_request(&mut bytes).await
    }

    #[tokio::test]
    async fn reads_the_session_request() {
        assert!(requested(&TargetAddr::Domain(DESTINATION.into(), 444)));
        assert!(!requested(&TargetAddr::Domain("example.com".into(), 444)));
        // Version 0 has no padding flag.
        assert_eq!(request(&[0, 0]).await.unwrap(), Protocol::Smux);
        assert_eq!(request(&[1, 1, 0]).await.unwrap(), Protocol::Yamux);
        // h2mux, padding, a later version and a request cut short.
        for bad in [&[1, 2, 0][..], &[1, 0, 1, 0, 0], &[2, 0, 0], &[1, 0]] {
            assert!(request(bad).await.is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn smux_frames() {
        let mut bytes: &[u8] = &[
            1, 0, 0, 0, 3, 0, 0, 0, // SYN
            1, 2, 2, 0, 3, 0, 0, 0, b'h', b'i', // PSH
            1, 3, 0, 0, 0, 0, 0, 0, // NOP
            1, 1, 0, 0, 3, 0, 0, 0, // FIN
            2, 0, 0, 0, 5, 0, 0, 0, // version 2
        ];
        let stream = Frame {
            stream: 3,
            ..Frame::default()
        };
        let open = Protocol::Smux.read(&mut bytes).await.unwrap();
        assert_eq!(
            open,
            Frame {
                open: true,
                ..stream
            }
        );
        let data = Protocol::Smux.read(&mut bytes).await.unwrap();
        assert_eq!(data.data, b"hi");
        assert_eq!(data.stream, 3);
        let nop = Protocol::Smux.read(&mut bytes).await.unwrap();
        assert_eq!(nop, Frame::default());
        let fin = Protocol::Smux.read(&mut bytes).await.unwrap();
        assert_eq!(fin.stream, 3);
        assert!(fin.fin && !fin.open && !fin.reset);
        assert!(Protocol::Smux.read(&mut bytes).await.is_err());

        assert_eq!(
            Protocol::Smux.data(0x0102_0304, b"hi"),
            [1, 2, 2, 0, 4, 3, 2, 1, b'h', b'i']
        );
        assert_eq!(Protocol::Smux.fin(5), [1, 1, 0, 0, 5, 0, 0, 0]);
        assert_eq!(Protocol::Smux.reset(5), Protocol::Smux.fin(5));
    }

    #[tokio::test]
    async fn yamux_frames() {
        let mut bytes = yamux_header(YAMUX_WINDOW_UPDATE, FLAG_SYN, 1, 0);
        bytes.extend(yamux_header(YAMUX_DATA, FLAG_FIN, 1, 2));
        bytes.extend(b"hi");
        bytes.extend(yamux_header(YAMUX_WINDOW_UPDATE, FLAG_RST, 1, 9));
        bytes.extend(yamux_header(YAMUX_PING, FLAG_SYN, 0, 77));
        bytes.extend(yamux_header(YAMUX_PING, FLAG_ACK, 0, 77));
        // GoAway.
        bytes.extend(yamux_header(3, 0, 0, 0));
        let mut bytes = bytes.as_slice();

        let open = Protocol::Yamux.read(&mut bytes).await.unwrap();
        assert_eq!((open.stream, open.open, open.credit), (1, true, 0));
        let data = Protocol::Yamux.read(&mut bytes).await.unwrap();
        assert_eq!(data.data, b"hi");
        assert!(data.fin && !data.open && !data.reset);
        let reset = Protocol::Yamux.read(&mut bytes).await.unwrap();
        assert_eq!((reset.credit, reset.reset, reset.fin), (9, true, false));
        let ping = Protocol::Yamux.read(&mut bytes).await.unwrap();
        assert_eq!(ping.reply, Some(vec![0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 77]));
        assert!(!ping.open);
        let pong = Protocol::Yamux.read(&mut bytes).await.unwrap();
        assert_eq!(pong, Frame::default());
        assert!(Protocol::Yamux.read(&mut bytes).await.is_err());

        // More than a window in one frame, and another version.
        let large = yamux_header(YAMUX_DATA, 0, 1, WINDOW + 1);
        assert!(Protocol::Yamux.read(&mut large.as_slice()).await.is_err());
        let mut other: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(Protocol::Yamux.read(&mut other).await.is_err());

        assert_eq!(
            Protocol::Yamux.data(1, b"hi"),
            [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, b'h', b'i']
        );
        assert_eq!(Protocol::Yamux.fin(1), [0, 1, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            Protocol::Yamux.reset(1),
            [0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn stream_requests_and_udp_packets() {
        let mut tcp: &[u8] = &[0, 0, 3, 3, b'a', b'.', b'b', 1, 187, b'x'];
        let (flags, target) = read_stream_request(&mut tcp).await.unwrap();
        assert_eq!(target, TargetAddr::Domain("a.b".into(), 443));
        assert!(Datagrams::of(flags, &target).is_none());
        // The payload behind the request stays unread.
        assert_eq!(tcp, b"x");

        // UDP: every packet goes to the stream's destination.
        let mut plain: &[u8] = &[0, 1, 1, 10, 0, 0, 1, 0, 53];
        let (flags, target) = read_stream_request(&mut plain).await.unwrap();
        let codec = Datagrams::of(flags, &target).unwrap();
        let mut packets: &[u8] = &[0, 2, b'h', b'i'];
        let packet = codec.read(&mut packets).await.unwrap();
        assert_eq!(packet, Some((target, b"hi".to_vec())));
        assert_eq!(codec.read(&mut packets).await.unwrap(), None);
        let mut out = Vec::new();
        let source: SocketAddr = "10.0.0.2:80".parse().unwrap();
        codec.encode(source, b"ok", &mut out).unwrap();
        assert_eq!(out, [0, 2, b'o', b'k']);

        // With packet addresses each names its destination or source.
        let mut addressed: &[u8] = &[0, 3, 1, 10, 0, 0, 1, 0, 53];
        let (flags, target) = read_stream_request(&mut addressed).await.unwrap();
        let codec = Datagrams::of(flags, &target).unwrap();
        let mut packets: &[u8] = &[1, 10, 0, 0, 2, 0, 80, 0, 1, b'q'];
        let packet = codec.read(&mut packets).await.unwrap();
        assert_eq!(packet, Some((TargetAddr::Ip(source), b"q".to_vec())));
        out.clear();
        codec.encode(source, b"r", &mut out).unwrap();
        assert_eq!(out, [1, 10, 0, 0, 2, 0, 80, 0, 1, b'r']);
    }
}
