//! Snell server inbound (v1–v4 and v6), built from `docs/protocols/snell.md`.
//!
//! The first frame carries the request (§3.1). v1–v3 clients are accepted
//! with either cipher (§5); v4 also serves v5 clients, whose TCP framing is
//! the same (§6.3). v6 uses the configured mode (§7). With users configured,
//! the request's clientID must be one of their `password` values (the Surge
//! `userkey`); without users any clientID is accepted (§9).
//!
//! Server behaviour:
//!
//! * Frames that fail to decrypt, unknown commands and malformed requests
//!   close the connection without a reply (§9). The first salt (or v6 salt
//!   block) is remembered, and a repeat is closed the same way.
//! * PING is answered with PONG, then the connection closes.
//! * The TCP reply `0x00` is lazy: it goes out with the target's first bytes
//!   (§3.2). A target that closes before sending anything gets an ERROR
//!   reply instead (`0x65` for CONNECTv2, `0xFF` for one-shot CONNECT).
//! * The client's zero chunk ends the client-to-target direction (§4).
//!   Each connection serves one request: when the target closes, the
//!   connection closes without the server's zero chunk, so a reusing client
//!   never puts it back into its pool and opens a new one for the next
//!   request.
//!
//! Not yet supported: UDP over TCP (closed after the request), several
//! CONNECTv2 requests on one connection, and an ERROR reply when the target
//! cannot be reached (the serve loop closes the connection).

mod factory;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use engine_inbound::replay::ReplayCache;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::{BoxFuture, BoxStream};
use outbound_snell::obfs::{HttpObfs, HttpObfsRole};
use outbound_snell::request::{
    encode_error, parse_request, Command, ERROR_ONE_SHOT_EOF, ERROR_REMOTE_EOF, REPLY_PONG,
    REPLY_TUNNEL,
};
use outbound_snell::{Decoder, Encoder, Frame, Framing, V6Mode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub use factory::{SnellInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "snell";

/// How long first salts are remembered. Snell has no timestamp, so this
/// bounds how late a captured connection can still be replayed.
const SALT_TTL: Duration = Duration::from_secs(30 * 60);

const READ_CHUNK: usize = 16 * 1024;

/// Server settings. Has no `Debug`: `psk` is a key.
#[derive(Clone)]
pub struct SnellInboundOptions {
    /// Protocol version 1–6; 5 is served as 4.
    pub version: u8,
    /// v6 only.
    pub mode: V6Mode,
    pub psk: Vec<u8>,
    /// `obfs=http` (v1–v4).
    pub http_obfs: bool,
}

pub struct SnellInbound {
    users: Arc<UserStore>,
    index: UserIndex<Vec<u8>>,
    /// Client-to-server framing; v1–v3 detect the client's cipher.
    framing: Framing,
    psk: Arc<[u8]>,
    http_obfs: bool,
    replay: ReplayCache,
}

impl SnellInbound {
    pub fn new(options: SnellInboundOptions) -> io::Result<Self> {
        if options.psk.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell psk is empty",
            ));
        }
        if options.http_obfs && options.version > 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell obfs is only defined for versions 1 to 4",
            ));
        }
        let framing = match Framing::for_version(options.version, options.mode, &options.psk)? {
            Framing::Legacy(_) => Framing::LegacyAuto,
            framing => framing,
        };
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(key) if !key.is_empty() && key.len() <= 255 => Ok(()),
            _ => Err("snell user key (password) must be 1 to 255 bytes"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Ok(Self {
            index: UserIndex::new(users.clone(), user_key),
            users,
            framing,
            psk: options.psk.into(),
            http_obfs: options.http_obfs,
            replay: ReplayCache::new(SALT_TTL),
        })
    }

    async fn handshake(&self, stream: BoxStream) -> Result<Accepted, Rejected> {
        let mut stream: BoxStream = if self.http_obfs {
            Box::new(HttpObfs::new(stream, HttpObfsRole::Server))
        } else {
            stream
        };
        let mut decoder = Decoder::new(self.framing.clone(), self.psk.clone());
        let salt_len = self.framing.salt_len();
        let mut salt = Vec::with_capacity(salt_len);
        let mut buf = vec![0u8; READ_CHUNK];
        let first = loop {
            match decoder.next_frame() {
                Ok(Some(Frame::Data(data))) if !data.is_empty() => break data,
                Ok(Some(_)) => return Err(Rejected::close("snell first frame is empty")),
                Ok(None) => {}
                Err(_) => return Err(Rejected::close("snell first frame does not decrypt")),
            }
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(Rejected::close("client closed before the request"));
            }
            let take = n.min(salt_len - salt.len());
            salt.extend_from_slice(&buf[..take]);
            decoder.feed(&buf[..n]);
        };
        // Only authenticated salts are recorded, so garbage cannot fill the
        // cache.
        if salt_len > 0 && !self.replay.insert(&salt) {
            return Err(Rejected::close("snell salt was replayed"));
        }

        let Ok(Some((request, used))) = parse_request(&first) else {
            return Err(Rejected::close("snell request is malformed"));
        };
        let mut encoder = Encoder::new(decoder.peer_framing(), &self.psk)?;
        // PING carries no clientID (§3.1): it is answered for any user.
        if request.command == Command::Ping {
            let mut out = Vec::new();
            encoder.encode_single(&mut out, &[REPLY_PONG])?;
            stream.write_all(&out).await?;
            stream.flush().await?;
            return Err(Rejected::close("snell ping answered"));
        }
        let user = if self.users.is_empty() {
            None
        } else {
            match self.index.get(&request.client_id) {
                Some(user) => Some(user),
                None => return Err(Rejected::close("snell request is not for a known user")),
            }
        };
        match request.command {
            Command::Ping => unreachable!("answered above"),
            Command::Udp => Err(Rejected::close("snell udp is not supported yet")),
            Command::Connect | Command::ConnectV2 => {
                let Some(target) = request.target else {
                    return Err(Rejected::close("snell request is malformed"));
                };
                Ok(Accepted {
                    user,
                    target,
                    stream: Box::new(ServerStream {
                        inner: stream,
                        decoder,
                        encoder,
                        one_shot: request.command == Command::Connect,
                        plain: first[used..].to_vec(),
                        plain_pos: 0,
                        read_done: false,
                        replied: false,
                        finished: false,
                        out: Vec::new(),
                        out_pos: 0,
                    }),
                })
            }
        }
    }
}

impl StreamInbound for SnellInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(self.handshake(stream))
    }
}

fn user_key(user: &User) -> Option<Vec<u8>> {
    user.password.as_ref().map(|key| key.as_bytes().to_vec())
}

/// The payload stream of one accepted request: reads return the client's
/// data, writes are framed back to it.
struct ServerStream {
    inner: BoxStream,
    decoder: Decoder,
    encoder: Encoder,
    one_shot: bool,
    /// Decoded client data not yet read.
    plain: Vec<u8>,
    plain_pos: usize,
    /// The client's zero chunk (or EOF) arrived.
    read_done: bool,
    /// The `0x00` reply went out.
    replied: bool,
    /// Shutdown started (the ERROR reply, if any, is queued).
    finished: bool,
    out: Vec<u8>,
    out_pos: usize,
}

impl ServerStream {
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

impl AsyncRead for ServerStream {
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
            match this.decoder.next_frame()? {
                Some(Frame::Data(data)) => {
                    this.plain = data;
                    this.plain_pos = 0;
                    continue;
                }
                Some(Frame::Zero) => {
                    this.read_done = true;
                    continue;
                }
                None => {}
            }
            let mut raw = [0u8; READ_CHUNK];
            let mut raw_buf = ReadBuf::new(&mut raw);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut raw_buf))?;
            if raw_buf.filled().is_empty() {
                this.read_done = true;
                continue;
            }
            this.decoder.feed(raw_buf.filled());
        }
    }
}

impl AsyncWrite for ServerStream {
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
            this.encoder.encode(&mut this.out, buf)?;
        } else {
            let mut first = Vec::with_capacity(buf.len() + 1);
            first.push(REPLY_TUNNEL);
            first.extend_from_slice(buf);
            this.encoder.encode(&mut this.out, &first)?;
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
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.finished {
            this.finished = true;
            if !this.replied {
                let (code, message): (u8, &[u8]) = if this.one_shot {
                    (ERROR_ONE_SHOT_EOF, b"end of file")
                } else {
                    (ERROR_REMOTE_EOF, b"Remote EOF")
                };
                let mut reply = Vec::new();
                encode_error(&mut reply, code, message);
                this.encoder.encode_single(&mut this.out, &reply)?;
            }
            // No zero chunk after data: the connection closes next, and a
            // zero chunk would invite the client to reuse it.
            this.out_pos = 0;
            ready!(this.poll_drain(cx))?;
        }
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
