//! TUIC v5 UDP relay.
//!
//! A UDP packet is the command
//!
//! ```text
//! VER 0x05 | TYPE 0x02 (Packet) | ASSOC_ID u16 | PKT_ID u16 |
//! FRAG_TOTAL u8 | FRAG_ID u8 | SIZE u16 | ADDR | payload (SIZE bytes)
//! ```
//!
//! sent either as a QUIC datagram (`native` mode, fragmented to the datagram
//! limit) or alone on a unidirectional stream (`quic` mode). ADDR is the
//! target on the way to the server and the source on the way back; fragments
//! after the first carry the empty address `0xff`. `Dissociate` (`TYPE 0x03 |
//! ASSOC_ID`) on a unidirectional stream ends an association, and `Heartbeat`
//! (`TYPE 0x04`) datagrams keep the connection alive.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use engine_outbound::TargetAddr;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use transport_quic::{quic_error, quinn};

use crate::{ADDR_DOMAIN, ADDR_IPV4, ADDR_IPV6, VERSION};

pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
/// Address type of fragments after the first.
pub const ADDR_NONE: u8 = 0xff;
/// Largest Packet command read from a unidirectional stream.
pub const MAX_PACKET_COMMAND: usize = 2 + 8 + 1 + 1 + 255 + 2 + 65_535;
/// Replies queued per client association before new ones are dropped.
const SESSION_QUEUE: usize = 256;

/// One Packet command, or one fragment of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicPacket {
    pub assoc_id: u16,
    pub packet_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub address: Option<TargetAddr>,
    pub payload: Vec<u8>,
}

impl TuicPacket {
    /// Parses a whole Packet command, from `VER`; `None` when malformed.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 11 || data[0] != VERSION || data[1] != CMD_PACKET {
            return None;
        }
        let assoc_id = u16::from_be_bytes([data[2], data[3]]);
        let packet_id = u16::from_be_bytes([data[4], data[5]]);
        let frag_total = data[6];
        let frag_id = data[7];
        let size = usize::from(u16::from_be_bytes([data[8], data[9]]));
        let (address, rest) = parse_address(&data[10..])?;
        if rest.len() < size {
            return None;
        }
        Some(Self {
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            address,
            payload: rest[..size].to_vec(),
        })
    }
}

/// Encodes `payload` as Packet commands for `address`. With `max_size`
/// (native mode) the payload is fragmented under `packet_id` when it does
/// not fit; without it (quic mode) it is one command. Empty when it would
/// need more than 255 fragments or the header alone does not fit.
pub fn encode_packet(
    assoc_id: u16,
    packet_id: u16,
    address: &TargetAddr,
    payload: &[u8],
    max_size: Option<usize>,
) -> Vec<Bytes> {
    let mut first_address = Vec::new();
    if put_address(&mut first_address, Some(address)).is_err() {
        return Vec::new();
    }
    let header_len = 10 + first_address.len();
    let max_size = max_size.unwrap_or(header_len + payload.len());
    if header_len >= max_size || payload.len() > usize::from(u16::MAX) {
        return Vec::new();
    }
    let encode = |packet_id: u16, frag_total: u8, frag_id: u8, chunk: &[u8]| {
        let mut out = Vec::with_capacity(header_len + chunk.len());
        out.extend_from_slice(&[VERSION, CMD_PACKET]);
        out.extend_from_slice(&assoc_id.to_be_bytes());
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(frag_total);
        out.push(frag_id);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        if frag_id == 0 {
            out.extend_from_slice(&first_address);
        } else {
            out.push(ADDR_NONE);
        }
        out.extend_from_slice(chunk);
        Bytes::from(out)
    };
    if header_len + payload.len() <= max_size {
        return vec![encode(packet_id, 1, 0, payload)];
    }
    let chunk_len = max_size - header_len;
    let Ok(total) = u8::try_from(payload.len().div_ceil(chunk_len)) else {
        return Vec::new();
    };
    payload
        .chunks(chunk_len)
        .enumerate()
        .map(|(index, chunk)| encode(packet_id, total, index as u8, chunk))
        .collect()
}

/// The Dissociate command for `assoc_id`.
pub fn dissociate_command(assoc_id: u16) -> [u8; 4] {
    let id = assoc_id.to_be_bytes();
    [VERSION, CMD_DISSOCIATE, id[0], id[1]]
}

/// Reassembles the fragments of one association's packets; an unfinished
/// packet is dropped when the next one starts.
#[derive(Debug, Default)]
pub struct Defragger {
    packet_id: u16,
    frags: Vec<Option<TuicPacket>>,
    received: usize,
}

impl Defragger {
    /// Returns a whole packet once every fragment arrived.
    pub fn feed(&mut self, packet: TuicPacket) -> Option<TuicPacket> {
        if packet.frag_total <= 1 {
            return Some(packet);
        }
        if packet.frag_id >= packet.frag_total {
            return None;
        }
        let total = usize::from(packet.frag_total);
        if packet.packet_id != self.packet_id || self.frags.len() != total {
            self.packet_id = packet.packet_id;
            self.frags = vec![None; total];
            self.received = 0;
        }
        let slot = &mut self.frags[usize::from(packet.frag_id)];
        if slot.is_some() {
            return None;
        }
        *slot = Some(packet);
        self.received += 1;
        if self.received < total {
            return None;
        }
        let frags = std::mem::take(&mut self.frags);
        self.received = 0;
        let mut frags = frags.into_iter().flatten();
        let mut whole = frags.next()?;
        for frag in frags {
            whole.payload.extend_from_slice(&frag.payload);
        }
        whole.frag_id = 0;
        whole.frag_total = 1;
        Some(whole)
    }
}

/// A random packet id to start counting from.
pub fn random_packet_id() -> u16 {
    let mut id = [0u8; 2];
    let _ = SystemRandom::new().fill(&mut id);
    u16::from_be_bytes(id)
}

/// Appends a TUIC address with its port, or the empty address.
pub fn put_address(out: &mut Vec<u8>, address: Option<&TargetAddr>) -> io::Result<()> {
    let Some(address) = address else {
        out.push(ADDR_NONE);
        return Ok(());
    };
    match address {
        TargetAddr::Ip(addr) => match unmap(addr.ip()) {
            IpAddr::V4(ip) => {
                out.push(ADDR_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(ADDR_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tuic target domain length is invalid",
                    )
                })?;
            out.push(ADDR_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
    Ok(())
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn parse_address(data: &[u8]) -> Option<(Option<TargetAddr>, &[u8])> {
    let (kind, rest) = data.split_first()?;
    let (host, rest): (Result<IpAddr, String>, &[u8]) = match *kind {
        ADDR_NONE => return Some((None, rest)),
        ADDR_IPV4 => {
            let octets: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            (Ok(IpAddr::V4(Ipv4Addr::from(octets))), &rest[4..])
        }
        ADDR_IPV6 => {
            let octets: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            (Ok(IpAddr::V6(Ipv6Addr::from(octets))), &rest[16..])
        }
        ADDR_DOMAIN => {
            let (len, rest) = rest.split_first()?;
            let len = usize::from(*len);
            let domain = std::str::from_utf8(rest.get(..len)?).ok()?;
            if domain.is_empty() {
                return None;
            }
            (Err(domain.to_owned()), &rest[len..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
    let address = match host {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(domain) => TargetAddr::Domain(domain, port),
    };
    Some((Some(address), &rest[2..]))
}

/// A reply datagram: its source and payload.
type Reply = (TargetAddr, Vec<u8>);
type Replies = mpsc::Sender<Reply>;

/// Routes the server's packet datagrams on one connection to associations.
pub(crate) struct Dispatch {
    sessions: Mutex<HashMap<u16, (Replies, Defragger)>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl Dispatch {
    pub(crate) fn new(connection: quinn::Connection) -> Arc<Self> {
        let dispatch = Arc::new(Self {
            sessions: Mutex::default(),
            reader: Mutex::default(),
        });
        let weak = Arc::downgrade(&dispatch);
        let reader = tokio::spawn(async move {
            while let Ok(datagram) = connection.read_datagram().await {
                let Some(dispatch) = weak.upgrade() else {
                    return;
                };
                if let Some(packet) = TuicPacket::parse(&datagram) {
                    dispatch.deliver(packet);
                }
            }
        });
        *lock(&dispatch.reader) = Some(reader);
        dispatch
    }

    fn deliver(&self, packet: TuicPacket) {
        let mut sessions = lock(&self.sessions);
        let Some((replies, defragger)) = sessions.get_mut(&packet.assoc_id) else {
            return;
        };
        if let Some(whole) = defragger.feed(packet) {
            if let Some(source) = whole.address {
                let _ = replies.try_send((source, whole.payload));
            }
        }
    }

    fn register(&self) -> io::Result<(u16, mpsc::Receiver<Reply>)> {
        let rng = SystemRandom::new();
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let mut sessions = lock(&self.sessions);
        if sessions.len() >= usize::from(u16::MAX) {
            return Err(io::Error::other("tuic has no free association id"));
        }
        loop {
            let mut id = [0u8; 2];
            rng.fill(&mut id)
                .map_err(|_| io::Error::other("system random source failed"))?;
            let id = u16::from_be_bytes(id);
            if let std::collections::hash_map::Entry::Vacant(slot) = sessions.entry(id) {
                slot.insert((sender, Defragger::default()));
                return Ok((id, receiver));
            }
        }
    }

    fn unregister(&self, id: u16) {
        lock(&self.sessions).remove(&id);
    }
}

impl Drop for Dispatch {
    fn drop(&mut self) {
        if let Some(reader) = lock(&self.reader).take() {
            reader.abort();
        }
    }
}

/// A client UDP association relayed by a TUIC server in native mode, from
/// [`TuicOutbound::udp_session`](crate::TuicOutbound::udp_session).
///
/// The server keeps one socket per association; replies come back with
/// their source address. Dropping the session sends Dissociate.
pub struct TuicUdpSession {
    id: u16,
    connection: quinn::Connection,
    dispatch: Arc<Dispatch>,
    replies: tokio::sync::Mutex<mpsc::Receiver<Reply>>,
    next_packet_id: AtomicU16,
}

impl TuicUdpSession {
    pub(crate) fn new(connection: quinn::Connection, dispatch: Arc<Dispatch>) -> io::Result<Self> {
        let (id, replies) = dispatch.register()?;
        Ok(Self {
            id,
            connection,
            dispatch,
            replies: tokio::sync::Mutex::new(replies),
            next_packet_id: AtomicU16::new(random_packet_id()),
        })
    }

    /// Sends one datagram to `target`, in fragments when it is larger than
    /// the connection allows.
    pub fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> io::Result<()> {
        let max_size = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("tuic server does not accept datagrams"))?;
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let datagrams = encode_packet(self.id, packet_id, target, payload, Some(max_size));
        if datagrams.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic datagram is too large",
            ));
        }
        for datagram in datagrams {
            self.connection
                .send_datagram(datagram)
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    /// Receives the next reply: its length in `buf` (truncated when longer)
    /// and its source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut replies = self.replies.lock().await;
        tokio::select! {
            reply = replies.recv() => {
                let (source, payload) = reply.ok_or_else(closed)?;
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                Ok((n, source))
            }
            _ = self.connection.closed() => Err(closed()),
        }
    }
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.dispatch.unregister(self.id);
        let connection = self.connection.clone();
        let command = dissociate_command(self.id);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = send_command(&connection, &command).await;
            });
        }
    }
}

/// Opens a unidirectional stream and sends `command` on it.
pub(crate) async fn send_command(connection: &quinn::Connection, command: &[u8]) -> io::Result<()> {
    let mut stream = connection.open_uni().await.map_err(quic_error)?;
    stream.write_all(command).await?;
    stream
        .finish()
        .map_err(|_| io::Error::other("tuic command stream closed"))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "tuic connection closed")
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip() {
        let target = TargetAddr::Domain("example.com".into(), 53);
        let datagrams = encode_packet(9, 3, &target, b"query", Some(1200));
        assert_eq!(datagrams.len(), 1);
        assert_eq!(
            &datagrams[0][..10],
            &[VERSION, CMD_PACKET, 0, 9, 0, 3, 1, 0, 0, 5]
        );
        assert_eq!(
            TuicPacket::parse(&datagrams[0]).unwrap(),
            TuicPacket {
                assoc_id: 9,
                packet_id: 3,
                frag_total: 1,
                frag_id: 0,
                address: Some(target),
                payload: b"query".to_vec(),
            }
        );
        let v6 = TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap());
        let quic = encode_packet(1, 1, &v6, &[7; 3000], None);
        assert_eq!(quic.len(), 1);
        assert_eq!(TuicPacket::parse(&quic[0]).unwrap().address, Some(v6));
        let mapped = TargetAddr::Ip("[::ffff:10.0.0.1]:80".parse().unwrap());
        assert_eq!(
            TuicPacket::parse(&encode_packet(1, 1, &mapped, b"x", None)[0])
                .unwrap()
                .address,
            Some(TargetAddr::Ip("10.0.0.1:80".parse().unwrap()))
        );
    }

    #[test]
    fn large_packets_are_fragmented_and_reassembled() {
        let target = TargetAddr::Ip("127.0.0.1:9".parse().unwrap());
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let datagrams = encode_packet(2, 77, &target, &payload, Some(1200));
        assert_eq!(datagrams.len(), 5);
        assert!(datagrams.iter().all(|datagram| datagram.len() <= 1200));
        let mut packets: Vec<_> = datagrams
            .iter()
            .map(|datagram| TuicPacket::parse(datagram).unwrap())
            .collect();
        assert_eq!(packets[0].address, Some(target.clone()));
        assert!(packets[1..].iter().all(|packet| packet.address.is_none()));
        packets.reverse();
        let mut defragger = Defragger::default();
        let mut whole = None;
        for packet in packets {
            whole = defragger.feed(packet).or(whole);
        }
        let whole = whole.unwrap();
        assert_eq!(whole.payload, payload);
        assert_eq!(whole.address, Some(target));
    }

    #[test]
    fn malformed_packets_are_rejected() {
        assert!(TuicPacket::parse(&[VERSION, CMD_PACKET, 0, 1]).is_none());
        // SIZE larger than the payload.
        assert!(
            TuicPacket::parse(&[VERSION, CMD_PACKET, 0, 1, 0, 1, 1, 0, 0, 9, ADDR_NONE, 1])
                .is_none()
        );
        // Unknown address type.
        assert!(TuicPacket::parse(&[VERSION, CMD_PACKET, 0, 1, 0, 1, 1, 0, 0, 0, 7]).is_none());
        let target = TargetAddr::Ip("127.0.0.1:9".parse().unwrap());
        assert!(encode_packet(1, 1, &target, &[0; 70_000], None).is_empty());
        assert!(encode_packet(1, 1, &target, b"x", Some(10)).is_empty());
        assert_eq!(dissociate_command(0x0102), [VERSION, CMD_DISSOCIATE, 1, 2]);
    }
}
