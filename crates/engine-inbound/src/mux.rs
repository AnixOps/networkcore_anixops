//! Mux.Cool, the multiplexing of Xray and V2Ray, and XUDP on top of it.
//!
//! VLESS and VMess clients ask for it with command 3 (no target address).
//! The stream then carries frames in both directions:
//!
//! ```text
//! META_LEN(2) | SESSION(2) STATUS OPTION [NETWORK PORT ATYP ADDR [GLOBAL_ID(8)]]
//!             | [DATA_LEN(2) DATA]           (when OPTION has 0x01)
//! ```
//!
//! Statuses are New (1), Keep (2), End (3) and KeepAlive (4); option 0x02
//! marks an error on End. A New frame names the network (1 TCP, 2 UDP) and
//! the target; addresses use the VMess codes, port first. XUDP is a UDP
//! session whose Keep frames carry the datagram's address, in both
//! directions; Xray clients use it for UDP over VLESS and VMess, with one
//! session per connection. The global id (for full-cone reuse) is ignored.
//!
//! Each TCP session connects through the node's outbound; each UDP session
//! gets its own socket from the [`UdpOutbound`]. A session ends with an End
//! frame from either side; the whole connection ends when the client closes
//! it or the user is removed.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use engine_outbound::{BoxStream, TargetAddr, TcpOutbound};
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::addr::{read_port_addr, write_port_addr, VMESS};
use crate::server::{InboundStats, ServeSettings};
use crate::udp::{UdpOutbound, MAX_DATAGRAM, UDP_IDLE_TIMEOUT};
use crate::UserEntry;

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 2;
/// Concurrent sessions per connection; Xray clients open at most 8 TCP
/// (and 16 XUDP) by default.
const MAX_SESSIONS: usize = 128;
/// Payload bytes per downlink frame of a TCP session.
const TCP_CHUNK: usize = 8 * 1024;
/// Frames queued toward one session, and toward the client.
const QUEUE: usize = 16;

/// One parsed client frame.
struct Frame {
    session: u16,
    status: u8,
    /// New: the session's network and target. Keep: the datagram's address,
    /// for UDP sessions that send one.
    network: Option<u8>,
    target: Option<TargetAddr>,
    data: Option<Vec<u8>>,
}

/// Client data for one session: the bytes, and for XUDP the datagram's
/// target when it differs per packet.
struct Input {
    data: Vec<u8>,
    target: Option<TargetAddr>,
}

struct NewSession {
    id: u16,
    network: u8,
    target: TargetAddr,
    input: mpsc::Receiver<Input>,
}

/// Charges payload bytes to the inbound and the user.
struct Meter<'a> {
    stats: &'a InboundStats,
    user: Option<&'a Arc<UserEntry>>,
}

impl Meter<'_> {
    fn up(&self, bytes: usize) {
        self.stats
            .bytes_up
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if let Some(user) = self.user {
            user.add_up(bytes as u64);
        }
    }

    fn down(&self, bytes: usize) {
        self.stats
            .bytes_down
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if let Some(user) = self.user {
            user.add_down(bytes as u64);
        }
    }
}

/// Serves a Mux.Cool connection until the client closes it, writing to it
/// fails or the user is removed.
pub(crate) async fn relay_mux(
    stream: BoxStream,
    user: Option<Arc<UserEntry>>,
    outbound: &dyn TcpOutbound,
    udp: Option<&dyn UdpOutbound>,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    let meter = Meter {
        stats,
        user: user.as_ref(),
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames, mut outgoing) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (spawn, mut spawned) = mpsc::unbounded_channel::<NewSession>();

    let read = read_loop(&mut reader, &frames, &spawn);
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
    let revoked = async {
        match &user {
            Some(user) => user.revoked().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(read, write, revoked);

    let mut running = FuturesUnordered::new();
    loop {
        tokio::select! {
            _ = &mut read => break,
            _ = &mut write => break,
            _ = &mut revoked => {
                stats.revoked.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Some(session) = spawned.recv() => {
                let frames = frames.clone();
                let meter = &meter;
                running.push(async move {
                    match session.network {
                        NETWORK_TCP => {
                            tcp_session(session, outbound, settings, stats, meter, frames).await
                        }
                        _ => udp_session(session, udp, stats, meter, frames).await,
                    }
                });
            }
            Some(()) = running.next(), if !running.is_empty() => {}
        }
    }
}

/// Reads client frames and hands their data to the sessions. Returns when
/// the client closes the stream or sends a malformed frame.
async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    frames: &mpsc::Sender<Vec<u8>>,
    spawn: &mpsc::UnboundedSender<NewSession>,
) {
    let mut sessions: HashMap<u16, mpsc::Sender<Input>> = HashMap::new();
    while let Ok(frame) = read_frame(reader).await {
        match frame.status {
            STATUS_NEW => {
                let (Some(network), Some(target)) = (frame.network, frame.target) else {
                    return;
                };
                // Sessions that ended on the server side.
                sessions.retain(|_, session| !session.is_closed());
                if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&frame.session) {
                    if frames.send(end_frame(frame.session, true)).await.is_err() {
                        return;
                    }
                    continue;
                }
                let (input, receiver) = mpsc::channel(QUEUE);
                let started = spawn.send(NewSession {
                    id: frame.session,
                    network,
                    target,
                    input: receiver,
                });
                if started.is_err() {
                    return;
                }
                if let Some(data) = frame.data {
                    let _ = input.send(Input { data, target: None }).await;
                }
                sessions.insert(frame.session, input);
            }
            STATUS_KEEP => {
                let (Some(data), Some(session)) = (frame.data, sessions.get(&frame.session)) else {
                    continue;
                };
                let input = Input {
                    data,
                    target: frame.target,
                };
                if session.send(input).await.is_err() {
                    sessions.remove(&frame.session);
                }
            }
            STATUS_END => {
                sessions.remove(&frame.session);
            }
            STATUS_KEEP_ALIVE => {}
            _ => return,
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let meta_len = usize::from(reader.read_u16().await?);
    if meta_len < 4 {
        return Err(invalid("mux frame metadata is too short"));
    }
    let mut meta = vec![0u8; meta_len];
    reader.read_exact(&mut meta).await?;
    let session = u16::from_be_bytes([meta[0], meta[1]]);
    let (status, option) = (meta[2], meta[3]);
    let mut rest = &meta[4..];
    let (network, target) = match status {
        STATUS_NEW => {
            let network = *rest
                .first()
                .ok_or_else(|| invalid("mux frame has no network"))?;
            if network != NETWORK_TCP && network != NETWORK_UDP {
                return Err(invalid("mux frame network is unknown"));
            }
            rest = &rest[1..];
            (Some(network), Some(read_port_addr(&mut rest, VMESS).await?))
        }
        // XUDP: a Keep frame with room for an address names the datagram's.
        STATUS_KEEP if rest.first() == Some(&NETWORK_UDP) => {
            rest = &rest[1..];
            (
                Some(NETWORK_UDP),
                Some(read_port_addr(&mut rest, VMESS).await?),
            )
        }
        _ => (None, None),
    };
    // Whatever follows (an XUDP global id, padding) is ignored.
    let data = if option & OPTION_DATA != 0 {
        let len = usize::from(reader.read_u16().await?);
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;
        Some(data)
    } else {
        None
    };
    Ok(Frame {
        session,
        status,
        network,
        target,
        data,
    })
}

async fn tcp_session(
    session: NewSession,
    outbound: &dyn TcpOutbound,
    settings: &ServeSettings,
    stats: &InboundStats,
    meter: &Meter<'_>,
    frames: mpsc::Sender<Vec<u8>>,
) {
    let NewSession {
        id,
        target,
        input: mut inputs,
        ..
    } = session;
    let connected = tokio::time::timeout(settings.connect_timeout, outbound.connect(&target)).await;
    let Ok(Ok(remote)) = connected else {
        stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        let _ = frames.send(end_frame(id, true)).await;
        return;
    };
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    let up = async {
        while let Some(input) = inputs.recv().await {
            if remote_writer.write_all(&input.data).await.is_err() {
                return;
            }
            meter.up(input.data.len());
        }
        // The client ended the session.
        let _ = remote_writer.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; TCP_CHUNK];
        loop {
            let n = match remote_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if frames.send(data_frame(id, None, &buf[..n])).await.is_err() {
                return;
            }
            meter.down(n);
        }
        let _ = frames.send(end_frame(id, false)).await;
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

async fn udp_session(
    session: NewSession,
    udp: Option<&dyn UdpOutbound>,
    stats: &InboundStats,
    meter: &Meter<'_>,
    frames: mpsc::Sender<Vec<u8>>,
) {
    let socket = match udp {
        Some(udp) => udp.bind().await.ok(),
        None => None,
    };
    let NewSession {
        id,
        target,
        input: mut inputs,
        ..
    } = session;
    let Some(socket) = socket else {
        stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        let _ = frames.send(end_frame(id, true)).await;
        return;
    };
    let up = async {
        while let Some(input) = inputs.recv().await {
            let target = input.target.as_ref().unwrap_or(&target);
            meter.up(input.data.len());
            // A refused target drops this datagram only.
            let _ = socket.send_to(&input.data, target).await;
        }
    };
    let down = async {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let received = tokio::time::timeout(UDP_IDLE_TIMEOUT, socket.recv_from(&mut buf)).await;
            let Ok(Ok((n, source))) = received else {
                break;
            };
            if frames
                .send(data_frame(id, Some(source), &buf[..n]))
                .await
                .is_err()
            {
                return;
            }
            meter.down(n);
        }
        let _ = frames.send(end_frame(id, false)).await;
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

/// A Keep frame carrying `data`; for UDP sessions with the datagram's
/// source, as XUDP clients expect.
fn data_frame(session: u16, source: Option<SocketAddr>, data: &[u8]) -> Vec<u8> {
    let mut meta = Vec::with_capacity(4 + 1 + 2 + 1 + 16);
    meta.extend_from_slice(&session.to_be_bytes());
    meta.push(STATUS_KEEP);
    meta.push(OPTION_DATA);
    if let Some(source) = source {
        meta.push(NETWORK_UDP);
        write_port_addr(&mut meta, source, VMESS);
    }
    let mut frame = Vec::with_capacity(2 + meta.len() + 2 + data.len());
    frame.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    frame.extend_from_slice(&meta);
    // Datagrams are at most MAX_DATAGRAM and TCP chunks TCP_CHUNK bytes.
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn end_frame(session: u16, error: bool) -> Vec<u8> {
    let option = if error { OPTION_ERROR } else { 0 };
    let mut frame = vec![0, 4];
    frame.extend_from_slice(&session.to_be_bytes());
    frame.push(STATUS_END);
    frame.push(option);
    frame
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
