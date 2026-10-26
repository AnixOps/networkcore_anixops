//! Hysteria2 UDP relay over QUIC datagrams.
//!
//! Every datagram in either direction carries one UDP message:
//!
//! ```text
//! u32 session id | u16 packet id | u8 fragment id | u8 fragment count |
//! varint len | "host:port" | payload
//! ```
//!
//! The address is the target on the way to the server and the source on the
//! way back. A message larger than the connection's datagram limit is split
//! into fragments that share a packet id and each repeat the header; the
//! receiver keeps the fragments of one packet per session and drops an
//! unfinished packet when the next one starts. An unfragmented message has
//! packet id 0 and fragment count 1.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use engine_outbound::TargetAddr;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use transport_quic::quinn;

use crate::put_varint;

/// Longest `host:port` accepted in a UDP message.
pub const MAX_UDP_ADDRESS_LEN: usize = 2048;
/// Replies queued per client session before new ones are dropped.
const SESSION_QUEUE: usize = 256;

/// One UDP message, or one fragment of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub address: String,
    pub payload: Vec<u8>,
}

impl UdpMessage {
    /// Parses one datagram; `None` when it is malformed.
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < 9 {
            return None;
        }
        let session_id = u32::from_be_bytes(datagram[0..4].try_into().ok()?);
        let packet_id = u16::from_be_bytes(datagram[4..6].try_into().ok()?);
        let frag_id = datagram[6];
        let frag_count = datagram[7];
        let (address_len, rest) = parse_varint(&datagram[8..])?;
        let address_len = usize::try_from(address_len).ok()?;
        if address_len == 0 || address_len > MAX_UDP_ADDRESS_LEN || rest.len() < address_len {
            return None;
        }
        let address = std::str::from_utf8(&rest[..address_len]).ok()?.to_owned();
        Some(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            address,
            payload: rest[address_len..].to_vec(),
        })
    }

    fn header_len(address: &str) -> usize {
        8 + varint_len(address.len() as u64) + address.len()
    }
}

/// Encodes `payload` as one datagram, or as fragments with `packet_id` when
/// it does not fit in `max_size`. Empty when it would need more than 255
/// fragments or the header alone does not fit.
pub fn encode_message(
    session_id: u32,
    packet_id: u16,
    address: &str,
    payload: &[u8],
    max_size: usize,
) -> Vec<Bytes> {
    let header_len = UdpMessage::header_len(address);
    if address.is_empty() || address.len() > MAX_UDP_ADDRESS_LEN || header_len >= max_size {
        return Vec::new();
    }
    let encode = |packet_id: u16, frag_id: u8, frag_count: u8, chunk: &[u8]| {
        let mut out = Vec::with_capacity(header_len + chunk.len());
        out.extend_from_slice(&session_id.to_be_bytes());
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(frag_id);
        out.push(frag_count);
        put_varint(&mut out, address.len() as u64);
        out.extend_from_slice(address.as_bytes());
        out.extend_from_slice(chunk);
        Bytes::from(out)
    };
    if header_len + payload.len() <= max_size {
        return vec![encode(0, 0, 1, payload)];
    }
    let chunk_len = max_size - header_len;
    let count = payload.len().div_ceil(chunk_len);
    let Ok(count) = u8::try_from(count) else {
        return Vec::new();
    };
    payload
        .chunks(chunk_len)
        .enumerate()
        .map(|(index, chunk)| encode(packet_id, index as u8, count, chunk))
        .collect()
}

/// Reassembles the fragments of one session's packets.
#[derive(Debug, Default)]
pub struct Defragger {
    packet_id: u16,
    frags: Vec<Option<UdpMessage>>,
    received: usize,
}

impl Defragger {
    /// Returns a whole message once every fragment of its packet arrived.
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        if message.frag_count <= 1 {
            return Some(message);
        }
        if message.frag_id >= message.frag_count {
            return None;
        }
        let count = usize::from(message.frag_count);
        if message.packet_id != self.packet_id || self.frags.len() != count {
            self.packet_id = message.packet_id;
            self.frags = vec![None; count];
            self.received = 0;
        }
        let slot = &mut self.frags[usize::from(message.frag_id)];
        if slot.is_some() {
            return None;
        }
        *slot = Some(message);
        self.received += 1;
        if self.received < count {
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
        whole.frag_count = 1;
        Some(whole)
    }
}

/// A random non-zero packet id for the next fragmented message.
pub fn random_packet_id() -> u16 {
    let mut id = [0u8; 2];
    let _ = SystemRandom::new().fill(&mut id);
    u16::from_be_bytes(id).max(1)
}

type Replies = mpsc::Sender<(String, Vec<u8>)>;

/// Routes the server's datagrams on one connection to client sessions.
pub(crate) struct Dispatch {
    sessions: Mutex<HashMap<u32, (Replies, Defragger)>>,
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
                if let Some(message) = UdpMessage::parse(&datagram) {
                    dispatch.deliver(message);
                }
            }
        });
        *lock(&dispatch.reader) = Some(reader);
        dispatch
    }

    fn deliver(&self, message: UdpMessage) {
        let mut sessions = lock(&self.sessions);
        let Some((replies, defragger)) = sessions.get_mut(&message.session_id) else {
            return;
        };
        if let Some(whole) = defragger.feed(message) {
            let _ = replies.try_send((whole.address, whole.payload));
        }
    }

    /// Registers a new session under a random unused id.
    fn register(&self) -> io::Result<(u32, mpsc::Receiver<(String, Vec<u8>)>)> {
        let rng = SystemRandom::new();
        let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
        let mut sessions = lock(&self.sessions);
        loop {
            let mut id = [0u8; 4];
            rng.fill(&mut id)
                .map_err(|_| io::Error::other("system random source failed"))?;
            let id = u32::from_be_bytes(id);
            if let std::collections::hash_map::Entry::Vacant(slot) = sessions.entry(id) {
                slot.insert((sender, Defragger::default()));
                return Ok((id, receiver));
            }
        }
    }

    fn unregister(&self, id: u32) {
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

/// A client UDP session relayed by a Hysteria2 server, from
/// [`Hysteria2Outbound::udp_session`](crate::Hysteria2Outbound::udp_session).
///
/// The server keeps one socket per session, so every target sees the same
/// source port; replies come back with their source address.
pub struct Hysteria2UdpSession {
    id: u32,
    connection: quinn::Connection,
    dispatch: Arc<Dispatch>,
    replies: tokio::sync::Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
    next_packet_id: AtomicU16,
}

impl Hysteria2UdpSession {
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
            .ok_or_else(|| io::Error::other("hysteria2 server does not accept datagrams"))?;
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed).max(1);
        let datagrams = encode_message(self.id, packet_id, &target.to_string(), payload, max_size);
        if datagrams.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 datagram is too large",
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
    /// and the source `host:port` the server reported.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, String)> {
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

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.dispatch.unregister(self.id);
    }
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "hysteria2 connection closed",
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

fn parse_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &data[1..len] {
        value = value << 8 | u64::from(*byte);
    }
    Some((value, &data[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_messages_are_one_datagram() {
        let datagrams = encode_message(7, 99, "example.com:53", b"query", 1200);
        assert_eq!(datagrams.len(), 1);
        let message = UdpMessage::parse(&datagrams[0]).unwrap();
        assert_eq!(
            message,
            UdpMessage {
                session_id: 7,
                packet_id: 0,
                frag_id: 0,
                frag_count: 1,
                address: "example.com:53".into(),
                payload: b"query".to_vec(),
            }
        );
        assert_eq!(&datagrams[0][..8], &[0, 0, 0, 7, 0, 0, 0, 1]);
        assert_eq!(datagrams[0][8], 14);
    }

    #[test]
    fn large_messages_are_fragmented_and_reassembled() {
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let datagrams = encode_message(1, 42, "[::1]:443", &payload, 1200);
        assert_eq!(datagrams.len(), 5);
        assert!(datagrams.iter().all(|datagram| datagram.len() <= 1200));
        let mut defragger = Defragger::default();
        let mut messages: Vec<_> = datagrams
            .iter()
            .map(|datagram| UdpMessage::parse(datagram).unwrap())
            .collect();
        assert!(messages.iter().all(|message| message.packet_id == 42));
        // Out of order, with a duplicate.
        messages.swap(0, 3);
        let duplicate = messages[1].clone();
        let mut whole = None;
        for (index, message) in messages.into_iter().enumerate() {
            if index == 2 {
                assert!(defragger.feed(duplicate.clone()).is_none());
            }
            whole = defragger.feed(message).or(whole);
        }
        let whole = whole.unwrap();
        assert_eq!(whole.payload, payload);
        assert_eq!(whole.address, "[::1]:443");
        assert_eq!((whole.frag_id, whole.frag_count), (0, 1));
    }

    #[test]
    fn a_new_packet_drops_the_unfinished_one() {
        let payload = [1u8; 3000];
        let first = encode_message(1, 1, "a:1", &payload, 1200);
        let second = encode_message(1, 2, "a:1", &payload, 1200);
        let mut defragger = Defragger::default();
        assert!(defragger
            .feed(UdpMessage::parse(&first[0]).unwrap())
            .is_none());
        let mut whole = None;
        for datagram in &second {
            whole = defragger.feed(UdpMessage::parse(datagram).unwrap());
        }
        assert_eq!(whole.unwrap().payload.len(), 3000);
        assert!(defragger
            .feed(UdpMessage::parse(&first[1]).unwrap())
            .is_none());
    }

    #[test]
    fn malformed_datagrams_are_rejected() {
        assert!(UdpMessage::parse(&[0; 8]).is_none());
        // Address length longer than the datagram.
        assert!(UdpMessage::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 20, b'a']).is_none());
        // Zero-length address.
        assert!(UdpMessage::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0]).is_none());
        assert!(encode_message(1, 1, "a:1", &[0u8; 300_000], 1200).is_empty());
        assert!(encode_message(1, 1, "a:1", b"x", 8).is_empty());
    }
}
