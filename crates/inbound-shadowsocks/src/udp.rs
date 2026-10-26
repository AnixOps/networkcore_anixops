//! Shadowsocks-2022 UDP relay on the inbound's port (SIP022).
//!
//! AES methods: each packet is
//!
//! ```text
//! AES-ECB(key, session id u64 | packet id u64) | [identity header] |
//! AEAD(session subkey, nonce = header[4..16], body)
//! ```
//!
//! where the session subkey is `BLAKE3-derive("shadowsocks 2022 session
//! subkey", key | session id)`. Multi-user clients encrypt the separate
//! header with the identity key and add `AES-ECB(iPSK, BLAKE3(uPSK)[..16] ^
//! separate header)`; the body uses the user key. ChaCha20 method: `nonce
//! (24) | XChaCha20-Poly1305(PSK, session id | packet id | body)`.
//!
//! Client bodies are `type 0 | timestamp | padding len | padding | address |
//! payload`; server bodies `type 1 | timestamp | client session id | padding
//! len | padding | address | payload` under the server's own session id.
//! Each client session gets its own socket through a [`SessionRelay`];
//! replies go to the client's latest address. Packets outside the 30 s
//! timestamp window or replayed within a session's window are dropped.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::KeyInit as _;
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use engine_inbound::addr::{write_addr_port, SOCKS};
use engine_inbound::server::InboundStats;
use engine_inbound::udp::{
    DatagramInbound, ReplySink, SessionRelay, UdpOutbound, MAX_DATAGRAM, MAX_SESSIONS,
};
use engine_inbound::users::UserIndex;
use engine_inbound::UserEntry;
use engine_outbound::{BoxFuture, TargetAddr};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use crate::{
    algorithm, decode_key, fill_random, parse_socks_address, unix_time_secs, Method, CLIENT_STREAM,
    IDENTITY_HEADER_LEN, MAX_TIMESTAMP_DIFF_SECS, SERVER_STREAM, SUBKEY_CONTEXT, TAG_LEN,
};

const XNONCE_LEN: usize = 24;
/// Packet ids remembered behind the highest one seen in a session.
const REPLAY_WINDOW: u64 = 1024;

/// The UDP side of a [`Ss2022Inbound`](crate::Ss2022Inbound).
pub(crate) struct Ss2022Datagrams {
    method: Method,
    server_key: Arc<[u8]>,
    multi_user: bool,
    index: UserIndex<[u8; IDENTITY_HEADER_LEN]>,
}

/// One authenticated client packet.
struct ClientPacket {
    session_id: u64,
    packet_id: u64,
    user: Option<Arc<UserEntry>>,
    key: Arc<[u8]>,
    target: TargetAddr,
    /// Payload range in the receive buffer.
    payload: std::ops::Range<usize>,
}

impl Ss2022Datagrams {
    pub(crate) fn new(
        method: Method,
        server_key: Arc<[u8]>,
        multi_user: bool,
        index: UserIndex<[u8; IDENTITY_HEADER_LEN]>,
    ) -> Self {
        Self {
            method,
            server_key,
            multi_user,
            index,
        }
    }

    /// Authenticates and decrypts one client packet in place.
    fn open(&self, buf: &mut [u8]) -> Option<ClientPacket> {
        if self.method == Method::ChaCha20Poly1305 {
            return self.open_chacha(buf);
        }
        let identity_len = if self.multi_user {
            IDENTITY_HEADER_LEN
        } else {
            0
        };
        if buf.len() < 16 + identity_len + 1 + 8 + 2 + TAG_LEN {
            return None;
        }
        let (header, rest) = buf.split_at_mut(16);
        aes_block(self.method, &self.server_key, header, false)?;
        let session_id = u64::from_be_bytes(header[..8].try_into().ok()?);
        let packet_id = u64::from_be_bytes(header[8..16].try_into().ok()?);
        let (user, key): (_, Arc<[u8]>) = if self.multi_user {
            let identity = &mut rest[..IDENTITY_HEADER_LEN];
            aes_block(self.method, &self.server_key, identity, false)?;
            let mut hash = [0u8; IDENTITY_HEADER_LEN];
            for (out, (a, b)) in hash.iter_mut().zip(identity.iter().zip(header.iter())) {
                *out = a ^ b;
            }
            let user = self.index.get(&hash)?;
            let key = decode_key(self.method, user.user().password.as_deref()?).ok()?;
            (Some(user), key.into())
        } else {
            (None, self.server_key.clone())
        };
        let body_start = 16 + identity_len;
        let nonce: [u8; 12] = header[4..16].try_into().ok()?;
        let cipher = session_cipher(self.method, &key, session_id).ok()?;
        let plaintext = cipher
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut rest[identity_len..],
            )
            .ok()?;
        let (target, offset) = parse_client_body(plaintext)?;
        let len = plaintext.len();
        Some(ClientPacket {
            session_id,
            packet_id,
            user,
            key,
            target,
            payload: body_start + offset..body_start + len,
        })
    }

    fn open_chacha(&self, buf: &mut [u8]) -> Option<ClientPacket> {
        if buf.len() < XNONCE_LEN + 16 + 1 + 8 + 2 + TAG_LEN {
            return None;
        }
        let (nonce, rest) = buf.split_at_mut(XNONCE_LEN);
        let (data, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        XChaCha20Poly1305::new_from_slice(&self.server_key)
            .ok()?
            .decrypt_in_place_detached(XNonce::from_slice(nonce), b"", data, Tag::from_slice(tag))
            .ok()?;
        let session_id = u64::from_be_bytes(data[..8].try_into().ok()?);
        let packet_id = u64::from_be_bytes(data[8..16].try_into().ok()?);
        let (target, offset) = parse_client_body(&data[16..])?;
        let start = XNONCE_LEN + 16;
        Some(ClientPacket {
            session_id,
            packet_id,
            user: None,
            key: self.server_key.clone(),
            target,
            payload: start + offset..start + data.len() - 16,
        })
    }
}

impl DatagramInbound for Ss2022Datagrams {
    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn UdpOutbound>,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(async move {
            socket.set_nonblocking(true)?;
            let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
            let sink = Arc::new(Replies {
                method: self.method,
                socket: socket.clone(),
                sessions: Mutex::default(),
            });
            let relay = SessionRelay::new(outbound, sink.clone(), stats.clone());
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(received) => received,
                    // A reply to an earlier peer that is gone (Windows reports
                    // ICMP port unreachable here); keep serving.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(error) => {
                        relay.close();
                        return Err(error);
                    }
                };
                let Some(packet) = self.open(&mut buf[..n]) else {
                    stats
                        .handshake_failed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                };
                if !sink.admit(&packet, peer, &relay) {
                    continue;
                }
                relay
                    .send(
                        packet.session_id,
                        packet.user.as_ref(),
                        &packet.target,
                        &buf[packet.payload.clone()],
                    )
                    .await;
            }
        })
    }
}

/// Server-side state of one client session.
struct ClientSession {
    /// The key the client used: its user key, or the server key.
    key: Arc<[u8]>,
    peer: SocketAddr,
    server_session_id: u64,
    next_packet_id: u64,
    downlink: Option<Arc<LessSafeKey>>,
    window: ReplayWindow,
}

/// Encrypts replies to each client session's latest address.
struct Replies {
    method: Method,
    socket: Arc<tokio::net::UdpSocket>,
    sessions: Mutex<HashMap<u64, ClientSession>>,
}

impl Replies {
    /// Records `packet` in its session: false when it is a replay or uses
    /// another key than the session started with.
    fn admit(&self, packet: &ClientPacket, peer: SocketAddr, relay: &SessionRelay) -> bool {
        let mut sessions = self.lock();
        if !sessions.contains_key(&packet.session_id) {
            if sessions.len() >= MAX_SESSIONS {
                sessions.retain(|id, _| relay.contains(*id));
                if sessions.len() >= MAX_SESSIONS {
                    return false;
                }
            }
            let mut id = [0u8; 8];
            if fill_random(&mut id).is_err() {
                return false;
            }
            sessions.insert(
                packet.session_id,
                ClientSession {
                    key: packet.key.clone(),
                    peer,
                    server_session_id: u64::from_be_bytes(id),
                    next_packet_id: 0,
                    downlink: None,
                    window: ReplayWindow::default(),
                },
            );
        }
        let Some(session) = sessions.get_mut(&packet.session_id) else {
            return false;
        };
        if session.key != packet.key || !session.window.accept(packet.packet_id) {
            return false;
        }
        session.peer = peer;
        true
    }

    fn seal(
        &self,
        session_id: u64,
        source: SocketAddr,
        payload: &[u8],
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let mut sessions = self.lock();
        let session = sessions.get_mut(&session_id)?;
        let packet_id = session.next_packet_id;
        session.next_packet_id = session.next_packet_id.wrapping_add(1);
        let mut body = Vec::with_capacity(16 + 1 + 8 + 8 + 2 + 19 + payload.len() + TAG_LEN);
        body.extend_from_slice(&session.server_session_id.to_be_bytes());
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.push(SERVER_STREAM);
        body.extend_from_slice(&unix_time_secs().to_be_bytes());
        body.extend_from_slice(&session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        write_addr_port(&mut body, source, SOCKS);
        body.extend_from_slice(payload);
        if self.method == Method::ChaCha20Poly1305 {
            let mut packet = vec![0u8; XNONCE_LEN];
            fill_random(&mut packet).ok()?;
            let tag = XChaCha20Poly1305::new_from_slice(&session.key)
                .ok()?
                .encrypt_in_place_detached(XNonce::from_slice(&packet), b"", &mut body)
                .ok()?;
            packet.extend_from_slice(&body);
            packet.extend_from_slice(&tag);
            return Some((packet, session.peer));
        }
        if session.downlink.is_none() {
            let cipher =
                session_cipher(self.method, &session.key, session.server_session_id).ok()?;
            session.downlink = Some(Arc::new(cipher));
        }
        let cipher = session.downlink.clone()?;
        let nonce: [u8; 12] = body[4..16].try_into().ok()?;
        let tag = cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut body[16..],
            )
            .ok()?;
        body.extend_from_slice(tag.as_ref());
        aes_block(self.method, &session.key, &mut body[..16], true)?;
        Some((body, session.peer))
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, ClientSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ReplySink for Replies {
    fn reply<'a>(
        &'a self,
        session: u64,
        source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some((packet, peer)) = self.seal(session, source, payload) else {
                return false;
            };
            // A failed send loses this reply only; the client may come back.
            let _ = self.socket.send_to(&packet, peer).await;
            true
        })
    }
}

/// Sliding window of the packet ids seen in one session.
#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    /// Bit `i` is packet id `highest - i`.
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl ReplayWindow {
    fn accept(&mut self, id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(id);
            self.seen = Default::default();
            self.set(0);
            return true;
        };
        if id > highest {
            self.shift(id - highest);
            self.highest = Some(id);
            self.set(0);
            return true;
        }
        let behind = highest - id;
        if behind >= REPLAY_WINDOW || self.get(behind) {
            return false;
        }
        self.set(behind);
        true
    }

    fn shift(&mut self, by: u64) {
        if by >= REPLAY_WINDOW {
            self.seen = Default::default();
            return;
        }
        let words = (by / 64) as usize;
        let bits = (by % 64) as u32;
        let len = self.seen.len();
        for index in (0..len).rev() {
            let source = index.checked_sub(words);
            let mut value = source.map_or(0, |source| self.seen[source] << bits);
            if bits > 0 {
                if let Some(carry) = source.and_then(|source| source.checked_sub(1)) {
                    value |= self.seen[carry] >> (64 - bits);
                }
            }
            self.seen[index] = value;
        }
    }

    fn get(&self, behind: u64) -> bool {
        self.seen[(behind / 64) as usize] & (1 << (behind % 64)) != 0
    }

    fn set(&mut self, behind: u64) {
        self.seen[(behind / 64) as usize] |= 1 << (behind % 64);
    }
}

/// `type 0 | timestamp | padding len | padding | address`: the target and
/// the payload offset.
fn parse_client_body(body: &[u8]) -> Option<(TargetAddr, usize)> {
    if body.len() < 1 + 8 + 2 || body[0] != CLIENT_STREAM {
        return None;
    }
    let timestamp = u64::from_be_bytes(body[1..9].try_into().ok()?);
    if unix_time_secs().abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
        return None;
    }
    let padding = usize::from(u16::from_be_bytes([body[9], body[10]]));
    let start = 11usize.checked_add(padding)?;
    let (target, len) = parse_socks_address(body.get(start..)?)?;
    Some((target, start + len))
}

fn session_cipher(method: Method, key: &[u8], session_id: u64) -> io::Result<LessSafeKey> {
    let mut hasher = blake3::Hasher::new_derive_key(SUBKEY_CONTEXT);
    hasher.update(key);
    hasher.update(&session_id.to_be_bytes());
    let mut subkey = [0u8; 32];
    hasher.finalize_xof().fill(&mut subkey[..method.key_len()]);
    let unbound = UnboundKey::new(algorithm(method), &subkey[..method.key_len()])
        .map_err(|_| io::Error::other("shadowsocks-2022 session key setup failed"))?;
    Ok(LessSafeKey::new(unbound))
}

/// AES-ECB on one 16-byte block in place.
fn aes_block(method: Method, key: &[u8], data: &mut [u8], encrypt: bool) -> Option<()> {
    let raw: [u8; 16] = (&*data).try_into().ok()?;
    let mut block = Block::from(raw);
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method::ChaCha20Poly1305 => return None,
    }
    data.copy_from_slice(block.as_slice());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_rejects_repeats_and_old_ids() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(5));
        assert!(!window.accept(5));
        assert!(window.accept(3));
        assert!(!window.accept(3));
        assert!(window.accept(100));
        assert!(window.accept(4));
        assert!(!window.accept(5));
        assert!(window.accept(1100));
        // 100 is now more than the window behind.
        assert!(!window.accept(100));
        assert!(window.accept(1099));
        assert!(!window.accept(1099));
        assert!(window.accept(1100 - 70));
        assert!(!window.accept(1100 - 70));
        assert!(window.accept(u64::MAX));
        assert!(!window.accept(1100));
    }

    #[test]
    fn replay_window_shifts_across_words() {
        let mut window = ReplayWindow::default();
        for id in 0..200 {
            assert!(window.accept(id));
        }
        assert!(window.accept(265));
        for id in 0..200 {
            assert!(!window.accept(id), "{id} was seen");
        }
        for id in 200..265 {
            assert!(window.accept(id), "{id} was not seen");
        }
    }
}
