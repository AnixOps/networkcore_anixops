//! AnyTLS server inbound (protocol version 2, as sing-box and mihomo
//! clients speak it).
//!
//! Inside TLS the client first sends `SHA-256(password) (32) | PADDING_LEN
//! (u16) | PADDING`, then both sides exchange frames
//!
//! ```text
//! CMD (1) | STREAM_ID (u32) | LEN (u16) | DATA (LEN)
//! ```
//!
//! with the commands Waste (0, padding), SYN (1, open a stream), PSH (2,
//! data), FIN (3, close a stream), Settings (4, client settings), Alert (5),
//! UpdatePaddingScheme (6), SYNACK (7), HeartRequest (8), HeartResponse (9)
//! and ServerSettings (10). Settings and server settings are `key=value`
//! lines. A stream's first bytes are its target (`ATYP ADDR PORT`, SOCKS
//! codes); the target `sp.v2.udp-over-tcp.arpa` asks for UDP over TCP
//! (version 2 of sing's framing).
//!
//! Server behaviour:
//!
//! * A first record that is not a known user's goes to the fallback, or is
//!   held open and drained without one.
//! * The client must send its settings before its first SYN, or gets an
//!   Alert. A client whose padding MD5 differs gets the server's scheme; a
//!   version 2 client gets server settings `v=2` and a SYNACK per stream
//!   once its target is connected, carrying the error when it is not.
//! * FIN from either side closes the whole stream. A session ends when the
//!   client closes it, sends an Alert or a malformed frame, or its user is
//!   removed.
//! * The server does not pad. Commands it does not know are skipped
//!   without their data, as the reference implementation does.

mod factory;
mod padding;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use engine_inbound::addr::{read_addr_port, write_addr_port, AddrCodes, SOCKS};
use engine_inbound::server::ConnectionContext;
use engine_inbound::stream::PrefixedStream;
use engine_inbound::udp::{relay_datagrams, Datagram, DatagramCodec, DatagramReader};
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{
    fallback_or_hold, read_first, Accepted, Rejected, StreamInbound, User, UserEntry, UserStore,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use futures_util::stream::{FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

pub use factory::{AnyTlsInboundFactory, TYPE_NAME};
pub use padding::{PaddingScheme, DEFAULT_PADDING_SCHEME};

pub const PROTOCOL: &str = "anytls";

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HASH_LEN: usize = 32;
const HEADER_LEN: usize = 7;
/// Open streams per session; clients pool sessions and use few at once.
const MAX_STREAMS: usize = 128;
/// Frames queued toward one stream, and toward the client.
const QUEUE: usize = 16;
/// Payload bytes per PSH frame toward the client.
const CHUNK: usize = 16 * 1024;
/// Buffer between a stream's frames and its relay.
const STREAM_BUFFER: usize = 64 * 1024;

/// The target that asks for UDP over TCP, version 2.
pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// Address codes of UDP-over-TCP packets.
const UOT: AddrCodes = AddrCodes {
    ipv4: 0,
    ipv6: 1,
    domain: 2,
};

pub struct AnyTlsInbound {
    users: Arc<UserStore>,
    index: UserIndex<[u8; HASH_LEN]>,
    padding: PaddingScheme,
    fallback: Option<TargetAddr>,
}

enum Auth {
    User(Arc<UserEntry>, BoxStream),
    Fallback(Accepted),
    Rejected(Rejected),
}

/// A stream the client opened, for the session to serve.
struct NewStream {
    id: u32,
    /// Whether the client wants a SYNACK (version 2).
    synack: bool,
    input: mpsc::Receiver<Vec<u8>>,
}

impl AnyTlsInbound {
    pub fn new(padding: PaddingScheme, fallback: Option<TargetAddr>) -> Self {
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("anytls user password is missing"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Self {
            index: UserIndex::new(users.clone(), user_hash),
            users,
            padding,
            fallback,
        }
    }

    async fn authenticate(&self, mut stream: BoxStream) -> Auth {
        let first = match read_first(&mut stream).await {
            Ok(first) if !first.is_empty() => first,
            _ => return Auth::Rejected(Rejected::close("client closed before authenticating")),
        };
        let user = if first.len() >= HASH_LEN + 2 {
            let mut hash = [0u8; HASH_LEN];
            hash.copy_from_slice(&first[..HASH_LEN]);
            self.index.get(&hash)
        } else {
            None
        };
        let Some(user) = user else {
            return match fallback_or_hold(
                self.fallback.as_ref(),
                first,
                stream,
                "anytls client is not a known user",
            ) {
                Ok(accepted) => Auth::Fallback(accepted),
                Err(rejected) => Auth::Rejected(rejected),
            };
        };
        let padding = usize::from(u16::from_be_bytes([first[HASH_LEN], first[HASH_LEN + 1]]));
        let frames_start = HASH_LEN + 2 + padding;
        let rest = if first.len() >= frames_start {
            first[frames_start..].to_vec()
        } else {
            // The padding goes on past the first record.
            let mut skipped = vec![0u8; frames_start - first.len()];
            if stream.read_exact(&mut skipped).await.is_err() {
                return Auth::Rejected(Rejected::close("anytls client closed in its padding"));
            }
            Vec::new()
        };
        let stream = Box::new(PrefixedStream::new(stream).with_read_prefix(rest));
        Auth::User(user, stream)
    }

    async fn serve(&self, stream: BoxStream, context: ConnectionContext<'_>) {
        let auth = tokio::time::timeout(
            context.settings.handshake_timeout,
            self.authenticate(stream),
        );
        let (user, stream) = match auth.await {
            Ok(Auth::User(user, stream)) => (user, stream),
            Ok(Auth::Fallback(accepted)) => {
                context.relay_accepted(accepted).await;
                return;
            }
            Ok(Auth::Rejected(rejected)) => {
                context.handshake_failed();
                if let Some(stream) = rejected.stream {
                    context.hold(stream).await;
                }
                return;
            }
            Err(_) => {
                context.handshake_failed();
                return;
            }
        };
        if user.is_revoked() {
            context.revoked();
            return;
        }
        let Some(_online) = user.try_connect(context.peer.ip()) else {
            context.stats.device_limited.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.session(stream, &user, &context).await;
    }

    /// Serves an authenticated session until the client ends it, writing to
    /// it fails or the user is removed.
    async fn session(
        &self,
        stream: BoxStream,
        user: &Arc<UserEntry>,
        context: &ConnectionContext<'_>,
    ) {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (frames, mut outgoing) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (spawn, mut spawned) = mpsc::unbounded_channel::<NewStream>();

        let read = read_loop(&mut reader, &frames, &spawn, &self.padding);
        let write = async {
            while let Some(frame) = outgoing.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    return;
                }
                if outgoing.is_empty() && writer.flush().await.is_err() {
                    return;
                }
            }
        };
        let revoked = user.revoked();
        tokio::pin!(read, write, revoked);

        let mut running = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = &mut read => break,
                _ = &mut write => break,
                _ = &mut revoked => {
                    context.revoked();
                    break;
                }
                Some(new) = spawned.recv() => {
                    running.push(self.stream(new, user, context, frames.clone()));
                }
                Some(()) = running.next(), if !running.is_empty() => {}
            }
        }
    }

    /// Carries one client stream: its frames in and out through a buffer,
    /// and the relay of what the buffer holds.
    async fn stream(
        &self,
        new: NewStream,
        user: &Arc<UserEntry>,
        context: &ConnectionContext<'_>,
        frames: mpsc::Sender<Vec<u8>>,
    ) {
        let NewStream {
            id,
            synack,
            mut input,
        } = new;
        let (app, buffer) = tokio::io::duplex(STREAM_BUFFER);
        let (mut buffer_reader, mut buffer_writer) = tokio::io::split(buffer);
        let from_client = async {
            while let Some(data) = input.recv().await {
                if buffer_writer.write_all(&data).await.is_err() {
                    break;
                }
            }
            // FIN from the client, or the session ended.
            let _ = buffer_writer.shutdown().await;
            std::future::pending::<()>().await
        };
        let to_client = async {
            let mut chunk = vec![0u8; CHUNK];
            loop {
                match buffer_reader.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if frames.send(frame(CMD_PSH, id, &chunk[..n])).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = frames.send(frame(CMD_FIN, id, &[])).await;
        };
        let relay = relay_stream(app, id, synack, user, context, &frames);
        tokio::select! {
            _ = async { tokio::join!(relay, to_client) } => {}
            _ = from_client => {}
        }
    }
}

/// Reads the stream's target and relays it; dropping `app` at the end
/// sends the client a FIN.
async fn relay_stream(
    mut app: DuplexStream,
    id: u32,
    synack: bool,
    user: &Arc<UserEntry>,
    context: &ConnectionContext<'_>,
    frames: &mpsc::Sender<Vec<u8>>,
) {
    let target = tokio::time::timeout(
        context.settings.handshake_timeout,
        read_addr_port(&mut app, SOCKS),
    )
    .await;
    let Ok(Ok(target)) = target else {
        context.handshake_failed();
        return;
    };
    if matches!(&target, TargetAddr::Domain(host, _) if host.as_str() == UOT_MAGIC_ADDRESS) {
        if synack && frames.send(frame(CMD_SYNACK, id, &[])).await.is_err() {
            return;
        }
        relay_uot(app, user, context).await;
        return;
    }
    match context.connect(&target).await {
        Ok(mut remote) => {
            if synack && frames.send(frame(CMD_SYNACK, id, &[])).await.is_err() {
                return;
            }
            let _ = context.relay(Some(user), &mut app, &mut remote).await;
        }
        Err(error) => {
            if synack {
                let message = error.to_string();
                let _ = frames.send(frame(CMD_SYNACK, id, message.as_bytes())).await;
            }
        }
    }
}

/// UDP over TCP, version 2: `IS_CONNECT (1) | ATYP ADDR PORT` (SOCKS
/// codes), then packets `[ATYP ADDR PORT] LENGTH (u16) PAYLOAD` in both
/// directions, the address left out in connect mode.
async fn relay_uot(mut app: DuplexStream, user: &Arc<UserEntry>, context: &ConnectionContext<'_>) {
    let request = tokio::time::timeout(context.settings.handshake_timeout, async {
        let connect = app.read_u8().await? != 0;
        let destination = read_addr_port(&mut app, SOCKS).await?;
        Ok::<_, io::Error>((connect, destination))
    })
    .await;
    let Ok(Ok((connect, destination))) = request else {
        context.handshake_failed();
        return;
    };
    let Some(udp) = context.udp() else {
        context.stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let codec = UotDatagrams {
        target: connect.then_some(destination),
    };
    relay_datagrams(
        Box::new(app),
        &codec,
        udp,
        Some(user.clone()),
        context.stats,
    )
    .await;
}

/// Reads client frames, answers the control commands and hands stream data
/// on. Returns when the client closes the session, sends an Alert or
/// breaks the protocol.
async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    frames: &mpsc::Sender<Vec<u8>>,
    spawn: &mpsc::UnboundedSender<NewStream>,
    padding: &PaddingScheme,
) {
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    // Set by the client's settings: whether it wants SYNACKs.
    let mut synack: Option<bool> = None;
    let mut header = [0u8; HEADER_LEN];
    loop {
        if reader.read_exact(&mut header).await.is_err() {
            return;
        }
        let command = header[0];
        let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = usize::from(u16::from_be_bytes([header[5], header[6]]));
        match command {
            CMD_PSH => {
                let Ok(data) = read_data(reader, len).await else {
                    return;
                };
                if data.is_empty() {
                    continue;
                }
                if let Some(stream) = streams.get(&id) {
                    if stream.send(data).await.is_err() {
                        streams.remove(&id);
                    }
                }
            }
            CMD_SYN => {
                let Some(synack) = synack else {
                    let alert = frame(CMD_ALERT, 0, b"client did not send its settings");
                    let _ = frames.send(alert).await;
                    return;
                };
                // Streams that ended on the server side.
                streams.retain(|_, stream| !stream.is_closed());
                if streams.contains_key(&id) {
                    continue;
                }
                if streams.len() >= MAX_STREAMS {
                    if frames.send(frame(CMD_FIN, id, &[])).await.is_err() {
                        return;
                    }
                    continue;
                }
                let (input, receiver) = mpsc::channel(QUEUE);
                let new = NewStream {
                    id,
                    synack,
                    input: receiver,
                };
                if spawn.send(new).is_err() {
                    return;
                }
                streams.insert(id, input);
            }
            CMD_FIN => {
                streams.remove(&id);
            }
            CMD_SETTINGS => {
                if len == 0 {
                    continue;
                }
                let Ok(data) = read_data(reader, len).await else {
                    return;
                };
                let settings = parse_settings(&data);
                if settings.get("padding-md5").copied() != Some(padding.md5()) {
                    let update = frame(CMD_UPDATE_PADDING_SCHEME, 0, padding.raw());
                    if frames.send(update).await.is_err() {
                        return;
                    }
                }
                let version = settings
                    .get("v")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                if version >= 2 {
                    let reply = frame(CMD_SERVER_SETTINGS, 0, b"v=2");
                    if frames.send(reply).await.is_err() {
                        return;
                    }
                }
                synack = Some(version >= 2);
            }
            CMD_ALERT if len > 0 => return,
            CMD_WASTE | CMD_SYNACK | CMD_UPDATE_PADDING_SCHEME | CMD_SERVER_SETTINGS
                if read_data(reader, len).await.is_err() =>
            {
                return;
            }
            CMD_HEART_REQUEST
                if frames
                    .send(frame(CMD_HEART_RESPONSE, id, &[]))
                    .await
                    .is_err() =>
            {
                return;
            }
            // HeartResponse and unknown commands carry no data; the arms
            // above fall through here once their data is handled.
            _ => {}
        }
    }
}

async fn read_data<R: AsyncRead + Unpin>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// `key=value` lines.
fn parse_settings(data: &[u8]) -> HashMap<&str, &str> {
    std::str::from_utf8(data)
        .unwrap_or_default()
        .split('\n')
        .filter_map(|line| line.split_once('='))
        .collect()
}

fn frame(command: u8, id: u32, data: &[u8]) -> Vec<u8> {
    // Payloads are at most CHUNK bytes, control data is short.
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let mut frame = Vec::with_capacity(HEADER_LEN + data.len());
    frame.push(command);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&data[..usize::from(len)]);
    frame
}

impl StreamInbound for AnyTlsInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async { Err(Rejected::close("anytls serves whole connections")) })
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

/// UDP-over-TCP packets; `target` is set in connect mode, where packets
/// carry no address.
struct UotDatagrams {
    target: Option<TargetAddr>,
}

impl DatagramCodec for UotDatagrams {
    fn read<'a>(
        &'a self,
        mut reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<Datagram>>> {
        Box::pin(async move {
            let target = match &self.target {
                Some(target) => target.clone(),
                None => match read_addr_port(&mut reader, UOT).await {
                    Ok(target) => target,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(error) => return Err(error),
                },
            };
            let len = match reader.read_u16().await {
                Ok(len) => usize::from(len),
                Err(error)
                    if error.kind() == io::ErrorKind::UnexpectedEof && self.target.is_some() =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error),
            };
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).await?;
            Ok(Some((target, payload)))
        })
    }

    fn encode(&self, source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "udp payload too large"))?;
        if self.target.is_none() {
            write_addr_port(out, source, UOT);
        }
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }
}

fn user_hash(user: &User) -> Option<[u8; HASH_LEN]> {
    user.password
        .as_deref()
        .map(|password| Sha256::digest(password.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_settings() {
        assert_eq!(frame(CMD_FIN, 7, &[]), vec![3, 0, 0, 0, 7, 0, 0]);
        assert_eq!(
            frame(CMD_PSH, 1, b"ab"),
            vec![2, 0, 0, 0, 1, 0, 2, b'a', b'b']
        );
        let settings = parse_settings(b"v=2\nclient=sing-box/1.12\npadding-md5=abc=d");
        assert_eq!(settings.get("v"), Some(&"2"));
        assert_eq!(settings.get("padding-md5"), Some(&"abc=d"));
    }
}
