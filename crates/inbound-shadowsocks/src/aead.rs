//! Shadowsocks AEAD (SIP004) TCP and UDP server inbound: the pre-2022
//! protocol that most panels and clients still offer next to SS2022.
//!
//! Supports `aes-128-gcm`, `aes-256-gcm` and `chacha20-ietf-poly1305`. A
//! user's key is `EVP_BytesToKey(password)`; each direction derives its
//! session key with HKDF-SHA1 from a random salt of key length and carries
//! `salt || chunks`, a chunk being `seal(u16 length) || seal(payload)` with
//! a little-endian nonce counter. The target address starts the first
//! client chunk. UDP packets are `salt || seal(address || payload)` with
//! nonce zero.
//!
//! SIP004 has no user identity on the wire, so the server finds the user by
//! trying each user's key on the first length chunk (on the whole packet
//! for UDP), the way other multi-user SIP004 servers do. The key that last
//! matched a client IP is tried first, so a busy node pays the full search
//! once per client. An inbound `password` adds one anonymous key that is
//! charged to no user.
//!
//! Salts of authenticated TCP requests are remembered for
//! [`SALT_TTL`] and a replay within that time is refused. A client that
//! fails authentication is held open and its input discarded.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use engine_inbound::addr::{write_addr_port, SOCKS};
use engine_inbound::replay::ReplayCache;
use engine_inbound::server::InboundStats;
use engine_inbound::udp::{
    DatagramInbound, ReplySink, SessionRelay, UdpOutbound, MAX_DATAGRAM, MAX_SESSIONS,
};
use engine_inbound::users::Validator;
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_shadowsocks::{evp_bytes_to_key, AeadMethod};
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::hkdf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::{
    fill_random, invalid_data, invalid_input, parse_socks_address, Cipher, ReadState, NONCE_LEN,
    TAG_LEN,
};

pub const AEAD_PROTOCOL: &str = "shadowsocks";

const SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];
/// SIP004 caps a chunk's payload at 0x3FFF bytes.
const MAX_PAYLOAD: usize = 0x3fff;
/// Plaintext bytes per outgoing chunk, below the protocol cap.
const MAX_CHUNK: usize = 8 * 1024;
/// SIP004 requests carry no timestamp; salts are kept this long.
pub const SALT_TTL: Duration = Duration::from_secs(600);
/// Client IPs whose matching key is remembered.
const MAX_HINTS: usize = 16 * 1024;

/// One key the server accepts: a user's, or the anonymous inbound key.
#[derive(Clone)]
struct Candidate {
    user: Option<Arc<UserEntry>>,
    key: Arc<[u8]>,
}

/// The keys of an inbound, derived once per user-store generation, and the
/// key that last matched each client IP.
struct KeyTable {
    method: AeadMethod,
    users: Arc<UserStore>,
    server_key: Option<Arc<[u8]>>,
    cache: Mutex<(u64, Arc<Vec<Candidate>>)>,
    hints: Mutex<HashMap<IpAddr, (u64, usize)>>,
}

impl KeyTable {
    fn current(&self) -> (u64, Arc<Vec<Candidate>>) {
        let generation = self.users.generation();
        let mut cache = lock(&self.cache);
        if cache.0 != generation {
            let (generation, entries) = self.users.snapshot();
            let mut list: Vec<Candidate> = entries
                .into_iter()
                .filter_map(|entry| {
                    let password = entry.user().password.clone()?;
                    let key = evp_bytes_to_key(password.as_bytes(), self.method.key_len());
                    Some(Candidate {
                        user: Some(entry),
                        key: key.into(),
                    })
                })
                .collect();
            if let Some(key) = &self.server_key {
                list.push(Candidate {
                    user: None,
                    key: key.clone(),
                });
            }
            *cache = (generation, Arc::new(list));
        }
        (cache.0, cache.1.clone())
    }

    /// Runs `attempt` on the keys, the one that last matched `ip` first,
    /// until one succeeds.
    fn find<T>(
        &self,
        ip: IpAddr,
        mut attempt: impl FnMut(&Candidate) -> Option<T>,
    ) -> Option<(Candidate, T)> {
        let (generation, list) = self.current();
        let hint = lock(&self.hints)
            .get(&ip)
            .filter(|(seen, index)| *seen == generation && *index < list.len())
            .map(|(_, index)| *index);
        if let Some(index) = hint {
            if let Some(found) = attempt(&list[index]) {
                return Some((list[index].clone(), found));
            }
        }
        for (index, candidate) in list.iter().enumerate() {
            if Some(index) == hint {
                continue;
            }
            if let Some(found) = attempt(candidate) {
                let mut hints = lock(&self.hints);
                if hints.len() >= MAX_HINTS {
                    hints.clear();
                }
                hints.insert(ip, (generation, index));
                return Some((candidate.clone(), found));
            }
        }
        None
    }
}

/// Shadowsocks AEAD server inbound. Holds derived keys and never prints them.
pub struct AeadInbound {
    method: AeadMethod,
    users: Arc<UserStore>,
    keys: Arc<KeyTable>,
    salts: ReplayCache,
    datagrams: Arc<AeadDatagrams>,
}

impl AeadInbound {
    /// `password`, when not empty, is a key every client may use without
    /// being a user. Users are matched by their `password`.
    pub fn new(method: AeadMethod, password: &str) -> io::Result<Self> {
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("shadowsocks user password is missing"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        let server_key = (!password.is_empty())
            .then(|| Arc::from(evp_bytes_to_key(password.as_bytes(), method.key_len())));
        let keys = Arc::new(KeyTable {
            method,
            users: users.clone(),
            server_key,
            cache: Mutex::new((u64::MAX, Arc::new(Vec::new()))),
            hints: Mutex::default(),
        });
        Ok(Self {
            method,
            users,
            datagrams: Arc::new(AeadDatagrams {
                method,
                keys: keys.clone(),
            }),
            keys,
            salts: ReplayCache::new(SALT_TTL),
        })
    }

    pub fn method(&self) -> AeadMethod {
        self.method
    }

    async fn handshake(&self, mut stream: BoxStream, peer: SocketAddr) -> Result<Accepted, Rejected> {
        let key_len = self.method.key_len();
        let mut head = vec![0u8; key_len + 2 + TAG_LEN];
        stream.read_exact(&mut head).await?;
        let (salt, sealed) = head.split_at(key_len);
        let method = self.method;
        let found = self.keys.find(peer.ip(), |candidate| {
            let mut cipher = session_cipher(method, &candidate.key, salt).ok()?;
            let mut length = [0u8; 2 + TAG_LEN];
            length.copy_from_slice(sealed);
            cipher.open_in_place(&mut length).ok()?;
            Some((cipher, usize::from(u16::from_be_bytes([length[0], length[1]]))))
        });
        let Some((candidate, (mut decryptor, length))) = found else {
            return Err(Rejected::hold("shadowsocks authentication failed", stream));
        };
        if length == 0 || length > MAX_PAYLOAD {
            return Err(Rejected::hold("shadowsocks chunk length is invalid", stream));
        }
        let mut first = vec![0u8; length + TAG_LEN];
        stream.read_exact(&mut first).await?;
        if decryptor.open_in_place(&mut first).is_err() {
            return Err(Rejected::hold("shadowsocks authentication failed", stream));
        }
        first.truncate(length);
        // Only authenticated salts enter the cache, so garbage cannot fill it.
        if !self.salts.insert(salt) {
            return Err(Rejected::hold("request salt was replayed", stream));
        }
        let Some((target, start)) = parse_socks_address(&first) else {
            return Err(Rejected::close("request header is invalid"));
        };
        first.drain(..start);
        let stream = AeadServerStream {
            inner: stream,
            method: self.method,
            key: candidate.key,
            decryptor,
            encryptor: None,
            out: Vec::new(),
            out_pos: 0,
            read_state: ReadState::Length,
            rbuf: Vec::new(),
            rfilled: 0,
            plain: first,
            plain_pos: 0,
        };
        Ok(Accepted {
            user: candidate.user,
            target,
            stream: Box::new(stream),
            udp: None,
            mux: false,
        })
    }
}

impl StreamInbound for AeadInbound {
    fn protocol(&self) -> &'static str {
        AEAD_PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(self.handshake(stream, peer))
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        Some(self.datagrams.clone() as Arc<dyn DatagramInbound>)
    }
}

fn algorithm(method: AeadMethod) -> &'static aead::Algorithm {
    match method {
        AeadMethod::Aes128Gcm => &aead::AES_128_GCM,
        AeadMethod::Aes256Gcm => &aead::AES_256_GCM,
        AeadMethod::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    }
}

/// The session cipher for one direction: HKDF-SHA1(key, salt, "ss-subkey").
fn session_cipher(method: AeadMethod, key: &[u8], salt: &[u8]) -> io::Result<Cipher> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(key);
    let okm = prk
        .expand(SUBKEY_INFO, algorithm(method))
        .map_err(|_| io::Error::other("shadowsocks session key setup failed"))?;
    Ok(Cipher {
        key: LessSafeKey::new(UnboundKey::from(okm)),
        nonce: [0u8; NONCE_LEN],
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Server side of one Shadowsocks AEAD TCP session, after the address.
struct AeadServerStream {
    inner: BoxStream,
    method: AeadMethod,
    key: Arc<[u8]>,
    decryptor: Cipher,
    /// `None` until the response salt is written with the first payload.
    encryptor: Option<Cipher>,
    out: Vec<u8>,
    out_pos: usize,
    read_state: ReadState,
    rbuf: Vec<u8>,
    rfilled: usize,
    plain: Vec<u8>,
    plain_pos: usize,
}

impl AeadServerStream {
    fn encode_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.encryptor.is_none() {
            let mut salt = vec![0u8; self.method.key_len()];
            fill_random(&mut salt)?;
            self.encryptor = Some(session_cipher(self.method, &self.key, &salt)?);
            self.out.extend_from_slice(&salt);
        }
        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or_else(|| io::Error::other("shadowsocks response state is invalid"))?;
        let length = (payload.len() as u16).to_be_bytes();
        encryptor.seal_into(&mut self.out, &length)?;
        encryptor.seal_into(&mut self.out, payload)
    }

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

    /// Reads until `rbuf` holds exactly `need` bytes. Returns `false` on a
    /// clean end of stream before any byte of this unit arrived.
    fn poll_fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        if self.rbuf.len() < need {
            self.rbuf.resize(need, 0);
        }
        while self.rfilled < need {
            let mut buf = ReadBuf::new(&mut self.rbuf[self.rfilled..need]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                if self.rfilled == 0 {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.rfilled += n;
        }
        self.rfilled = 0;
        Poll::Ready(Ok(true))
    }

    /// Advances the read state machine until plaintext is available or the
    /// stream ends.
    fn poll_next_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Length => {
                    let need = 2 + TAG_LEN;
                    if !ready!(self.poll_fill(cx, need))? {
                        self.read_state = ReadState::Eof;
                        continue;
                    }
                    self.decryptor.open_in_place(&mut self.rbuf[..need])?;
                    let length = usize::from(u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]));
                    if length == 0 || length > MAX_PAYLOAD {
                        return Poll::Ready(Err(invalid_data(
                            "shadowsocks chunk length is out of range",
                        )));
                    }
                    self.read_state = ReadState::Payload(length);
                }
                ReadState::Payload(length) => {
                    let need = length + TAG_LEN;
                    if !ready!(self.poll_fill(cx, need))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let mut buf = std::mem::take(&mut self.rbuf);
                    if let Err(err) = self.decryptor.open_in_place(&mut buf[..need]) {
                        self.rbuf = buf;
                        return Poll::Ready(Err(err));
                    }
                    buf.truncate(length);
                    // Hand the decrypted buffer to the reader and reuse the
                    // old one for input.
                    self.rbuf = std::mem::replace(&mut self.plain, buf);
                    self.plain_pos = 0;
                    self.read_state = ReadState::Length;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for AeadServerStream {
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
        let n = buf.len().min(MAX_CHUNK);
        this.encode_chunk(&buf[..n])?;
        // The chunk is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for AeadServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.plain_pos >= this.plain.len() {
            ready!(this.poll_next_plaintext(cx))?;
        }
        let available = &this.plain[this.plain_pos..];
        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        this.plain_pos += n;
        Poll::Ready(Ok(()))
    }
}

/// The UDP side of an [`AeadInbound`].
struct AeadDatagrams {
    method: AeadMethod,
    keys: Arc<KeyTable>,
}

/// One authenticated client packet.
struct ClientPacket {
    candidate: Candidate,
    target: TargetAddr,
    /// Payload range in the receive buffer.
    payload: std::ops::Range<usize>,
}

impl AeadDatagrams {
    /// Authenticates and decrypts one client packet in place.
    fn open(&self, buf: &mut [u8], peer: SocketAddr) -> Option<ClientPacket> {
        let key_len = self.method.key_len();
        if buf.len() < key_len + TAG_LEN + 1 {
            return None;
        }
        let (salt, sealed) = buf.split_at_mut(key_len);
        let method = self.method;
        // A failed open leaves the buffer unusable, so each try works on a
        // copy and the match is decrypted in place afterwards.
        let mut scratch = Vec::with_capacity(sealed.len());
        let (candidate, ()) = self.keys.find(peer.ip(), |candidate| {
            let mut cipher = session_cipher(method, &candidate.key, salt).ok()?;
            scratch.clear();
            scratch.extend_from_slice(sealed);
            cipher.open_in_place(&mut scratch).ok().map(|_| ())
        })?;
        let mut cipher = session_cipher(method, &candidate.key, salt).ok()?;
        let len = cipher.open_in_place(sealed).ok()?;
        let (target, offset) = parse_socks_address(&sealed[..len])?;
        Some(ClientPacket {
            candidate,
            target,
            payload: key_len + offset..key_len + len,
        })
    }
}

impl DatagramInbound for AeadDatagrams {
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
                hasher: RandomState::new(),
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
                let Some(packet) = self.open(&mut buf[..n], peer) else {
                    stats
                        .handshake_failed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                };
                let Some(session) = sink.admit(&packet.candidate, peer, &relay) else {
                    continue;
                };
                relay
                    .send(
                        session,
                        packet.candidate.user.as_ref(),
                        &packet.target,
                        &buf[packet.payload.clone()],
                    )
                    .await;
            }
        })
    }
}

/// One client association: SIP004 has no session id, so a session is a
/// client address and the key it used.
struct ClientSession {
    key: Arc<[u8]>,
    peer: SocketAddr,
}

/// Encrypts replies to each client session.
struct Replies {
    method: AeadMethod,
    socket: Arc<tokio::net::UdpSocket>,
    hasher: RandomState,
    sessions: Mutex<HashMap<u64, ClientSession>>,
}

impl Replies {
    /// The session of `peer` with `candidate`'s key, opened if new; `None`
    /// when the session table is full.
    fn admit(&self, candidate: &Candidate, peer: SocketAddr, relay: &SessionRelay) -> Option<u64> {
        let id = self.hasher.hash_one((peer, &*candidate.key));
        let mut sessions = lock(&self.sessions);
        if !sessions.contains_key(&id) {
            if sessions.len() >= MAX_SESSIONS {
                sessions.retain(|id, _| relay.contains(*id));
                if sessions.len() >= MAX_SESSIONS {
                    return None;
                }
            }
            sessions.insert(
                id,
                ClientSession {
                    key: candidate.key.clone(),
                    peer,
                },
            );
        }
        Some(id)
    }

    fn seal(&self, session: u64, source: SocketAddr, payload: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
        let (key, peer) = {
            let sessions = lock(&self.sessions);
            let session = sessions.get(&session)?;
            (session.key.clone(), session.peer)
        };
        let key_len = self.method.key_len();
        let mut packet = vec![0u8; key_len];
        fill_random(&mut packet).ok()?;
        let mut cipher = session_cipher(self.method, &key, &packet).ok()?;
        let mut body = Vec::with_capacity(19 + payload.len());
        write_addr_port(&mut body, source, SOCKS);
        body.extend_from_slice(payload);
        cipher.seal_into(&mut packet, &body).ok()?;
        Some((packet, peer))
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

/// Parses a SIP004 method name, refusing 2022 and stream ciphers.
pub fn parse_method(name: &str) -> io::Result<AeadMethod> {
    AeadMethod::parse(name).map_err(|_| invalid_input("unsupported shadowsocks method"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_need_a_password() {
        let inbound = AeadInbound::new(AeadMethod::Aes128Gcm, "").unwrap();
        assert!(inbound.users().add(User::with_uuid("a", "u")).is_err());
        assert!(inbound
            .users()
            .add(User::with_password("b", String::new()))
            .is_err());
        inbound
            .users()
            .add(User::with_password("c", "secret"))
            .unwrap();
        assert_eq!(inbound.users().names(), ["c"]);
    }

    #[test]
    fn keys_follow_the_user_store_and_hints_go_first() {
        let inbound = AeadInbound::new(AeadMethod::Aes256Gcm, "anonymous").unwrap();
        inbound.users().add(User::with_password("a", "one")).unwrap();
        inbound.users().add(User::with_password("b", "two")).unwrap();
        let (_, list) = inbound.keys.current();
        assert_eq!(list.len(), 3);
        assert!(list.last().unwrap().user.is_none(), "anonymous key last");

        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let wanted = evp_bytes_to_key(b"two", 32);
        let mut tried = 0;
        let (found, ()) = inbound
            .keys
            .find(ip, |candidate| {
                tried += 1;
                (*candidate.key == wanted[..]).then_some(())
            })
            .unwrap();
        assert_eq!(found.user.unwrap().name(), "b");
        assert_eq!(tried, 2);
        tried = 0;
        inbound
            .keys
            .find(ip, |candidate| {
                tried += 1;
                (*candidate.key == wanted[..]).then_some(())
            })
            .unwrap();
        assert_eq!(tried, 1, "the remembered key is tried first");

        inbound.users().remove("b");
        assert!(inbound
            .keys
            .find(ip, |candidate| (*candidate.key == wanted[..]).then_some(()))
            .is_none());
    }
}
