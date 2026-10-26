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
//!   (§3.2). A target that cannot be reached, or closes before sending
//!   anything, gets an ERROR reply and the connection closes.
//! * CONNECTv2 ends each direction with a zero chunk; the connection then
//!   waits for the next request (§4), closing after [`IDLE_TIMEOUT`].
//! * UDP over TCP (v3+, §4.1) relays one datagram per frame through the
//!   node's UDP egress; a datagram too large for one frame is dropped.

mod conn;
mod factory;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::replay::ReplayCache;
use engine_inbound::server::ConnectionContext;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, BoxStream};
use outbound_snell::obfs::{HttpObfs, HttpObfsRole};
use outbound_snell::request::{encode_error, parse_request, Command, REPLY_PONG};
use outbound_snell::{Decoder, Encoder, Frame, Framing, V6Mode};
use tokio::io::AsyncReadExt;

use crate::conn::{Conn, Ending, RequestStream, READ_CHUNK};

pub use factory::{SnellInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "snell";

/// How long first salts are remembered. Snell has no timestamp, so this
/// bounds how late a captured connection can still be replayed.
const SALT_TTL: Duration = Duration::from_secs(30 * 60);

/// How long a connection may wait for its next CONNECTv2 request; longer
/// than the clients' 180 s pool idle time (§4).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(240);

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

    /// Reads the first frame and authenticates the connection by it.
    async fn open(&self, stream: BoxStream) -> Result<(Conn, Vec<u8>), &'static str> {
        let mut io: BoxStream = if self.http_obfs {
            Box::new(HttpObfs::new(stream, HttpObfsRole::Server))
        } else {
            stream
        };
        let mut decoder = Decoder::new(self.framing.clone(), self.psk.clone());
        let salt_len = self.framing.salt_len();
        let mut salt = Vec::with_capacity(salt_len);
        let mut raw = vec![0u8; READ_CHUNK];
        let first = loop {
            match decoder.next_frame() {
                Ok(Some(Frame::Data(data))) if !data.is_empty() => break data,
                Ok(Some(_)) => return Err("snell first frame is empty"),
                Ok(None) => {}
                Err(_) => return Err("snell first frame does not decrypt"),
            }
            let n = io
                .read(&mut raw)
                .await
                .map_err(|_| "connection failed during the handshake")?;
            if n == 0 {
                return Err("client closed before the request");
            }
            let take = n.min(salt_len - salt.len());
            salt.extend_from_slice(&raw[..take]);
            decoder.feed(&raw[..n]);
        };
        // Only authenticated salts are recorded, so garbage cannot fill the
        // cache.
        if salt_len > 0 && !self.replay.insert(&salt) {
            return Err("snell salt was replayed");
        }
        let encoder = Encoder::new(decoder.peer_framing(), &self.psk)
            .map_err(|_| "connection failed during the handshake")?;
        Ok((
            Conn {
                io,
                decoder,
                encoder,
            },
            first,
        ))
    }

    /// The user a request's clientID names; `Err` for an unknown one.
    fn user_for(&self, client_id: &[u8]) -> Result<Option<Arc<UserEntry>>, &'static str> {
        if self.users.is_empty() {
            return Ok(None);
        }
        self.index
            .get(&client_id.to_vec())
            .map(Some)
            .ok_or("snell request is not for a known user")
    }

    /// Single-request path for callers that relay the stream themselves.
    async fn accept_one(&self, stream: BoxStream) -> Result<Accepted, Rejected> {
        let (mut conn, first) = self.open(stream).await.map_err(Rejected::close)?;
        let Ok(Some((request, used))) = parse_request(&first) else {
            return Err(Rejected::close("snell request is malformed"));
        };
        if request.command == Command::Ping {
            conn.send_single(&[REPLY_PONG]).await?;
            return Err(Rejected::close("snell ping answered"));
        }
        let user = self.user_for(&request.client_id).map_err(Rejected::close)?;
        let (Some(target), Command::Connect | Command::ConnectV2) =
            (request.target, request.command)
        else {
            return Err(Rejected::close("snell udp needs the serve loop"));
        };
        Ok(Accepted {
            user,
            target,
            stream: Box::new(RequestStream::new(
                conn,
                request.command == Command::Connect,
                Ending::Close,
                first[used..].to_vec(),
            )),
        })
    }

    async fn serve(&self, stream: BoxStream, context: ConnectionContext<'_>) {
        let opened = tokio::time::timeout(context.settings.handshake_timeout, self.open(stream));
        let Ok(Ok((mut conn, mut frame))) = opened.await else {
            context.handshake_failed();
            return;
        };
        let mut raw = vec![0u8; READ_CHUNK];
        let mut first_request = true;
        loop {
            let Ok(Some((request, used))) = parse_request(&frame) else {
                if first_request {
                    context.handshake_failed();
                }
                return;
            };
            if request.command == Command::Ping {
                let _ = conn.send_single(&[REPLY_PONG]).await;
                return;
            }
            let Ok(user) = self.user_for(&request.client_id) else {
                if first_request {
                    context.handshake_failed();
                }
                return;
            };
            if user.as_ref().is_some_and(|user| user.is_revoked()) {
                context.revoked();
                return;
            }
            first_request = false;
            let _online = user.as_ref().map(|user| user.connect(context.peer.ip()));
            let target = match (request.command, request.target) {
                (Command::Udp, _) => {
                    // The request must be a frame of its own (§4.1).
                    if used == frame.len() {
                        udp::relay(conn, user.as_ref(), &context).await;
                    }
                    return;
                }
                (_, Some(target)) => target,
                (_, None) => return,
            };
            let one_shot = request.command == Command::Connect;
            let mut remote = match context.connect(&target).await {
                Ok(remote) => remote,
                Err(err) => {
                    let mut reply = Vec::new();
                    let (code, message) = connect_error(&err);
                    encode_error(&mut reply, code, message);
                    let _ = conn.send_single(&reply).await;
                    return;
                }
            };
            let mut stream =
                RequestStream::new(conn, one_shot, Ending::KeepOpen, frame[used..].to_vec());
            let relayed = context.relay(user.as_ref(), &mut stream, &mut remote).await;
            drop(remote);
            if relayed.is_err() || !stream.reusable() {
                return;
            }
            conn = stream.into_conn();
            frame = match tokio::time::timeout(IDLE_TIMEOUT, conn.next_frame(&mut raw)).await {
                Ok(Ok(Some(Frame::Data(data)))) if !data.is_empty() => data,
                _ => return,
            };
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
        Box::pin(self.accept_one(stream))
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.serve(stream, context))
    }
}

/// ERROR reply for a target that could not be reached. Clients treat any
/// code as "target unreachable" (§3.2); refused connections use the code
/// official servers send.
fn connect_error(err: &io::Error) -> (u8, &'static [u8]) {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => (0x06, b"connection refused"),
        io::ErrorKind::TimedOut => (0x01, b"connection timed out"),
        _ => (0x01, b"connection failed"),
    }
}

fn user_key(user: &User) -> Option<Vec<u8>> {
    user.password.as_ref().map(|key| key.as_bytes().to_vec())
}
