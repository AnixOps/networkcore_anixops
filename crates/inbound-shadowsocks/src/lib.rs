//! Shadowsocks-2022 (SIP022) TCP server inbound.
//!
//! Supports `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and
//! `2022-blake3-chacha20-poly1305`. Two modes, as in other SIP022 servers:
//!
//! - single key: no users; every client uses the server `password`;
//! - multi-user: the server `password` is the identity key (iPSK) and each
//!   user has its own key (uPSK). Clients send one extensible identity header
//!   (`iPSK:uPSK` passwords), which only the AES methods define.
//!
//! Requests are checked for the timestamp window (30 s) and replayed salts
//! (60 s). A client that fails authentication is held open and its input
//! discarded instead of being closed at once.
//!
//! UDP on the same port is relayed when the node has a UDP outbound (see
//! `src/udp.rs` for the packet format): one socket per client session, the same
//! timestamp window and a per-session packet id replay window.

mod factory;
mod udp;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use base64::Engine as _;
use engine_inbound::replay::ReplayCache;
use engine_inbound::udp::DatagramInbound;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub use factory::{ShadowsocksInboundFactory, TYPE_NAME};
pub use outbound_shadowsocks::Method;

pub const PROTOCOL: &str = "shadowsocks-2022";

const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
const IDENTITY_HEADER_LEN: usize = 16;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CLIENT_STREAM: u8 = 0;
const SERVER_STREAM: u8 = 1;
/// Request fixed header: type, timestamp, variable header length.
const REQUEST_FIXED_LEN: usize = 1 + 8 + 2;
const MAX_TIMESTAMP_DIFF_SECS: u64 = 30;
/// SIP022 asks servers to remember salts for at least twice the timestamp
/// window.
const SALT_TTL: Duration = Duration::from_secs(60);
/// Plaintext bytes per outgoing chunk; the protocol allows 0xFFFF.
const MAX_CHUNK: usize = 16 * 1024;

/// Shadowsocks-2022 server inbound. Holds decoded keys and never prints them.
pub struct Ss2022Inbound {
    method: Method,
    /// Single-key mode: the session key. Multi-user mode: the identity key.
    server_key: Arc<[u8]>,
    multi_user: bool,
    users: Arc<UserStore>,
    index: UserIndex<[u8; IDENTITY_HEADER_LEN]>,
    salts: ReplayCache,
    datagrams: Arc<udp::Ss2022Datagrams>,
}

impl Ss2022Inbound {
    /// `password` is the base64 server key. With `multi_user`, it is the
    /// identity key and clients are matched against [`StreamInbound::users`],
    /// whose `password` fields hold the base64 user keys.
    pub fn new(method: Method, password: &str, multi_user: bool) -> io::Result<Self> {
        let server_key = decode_key(method, password)?;
        if multi_user && method == Method::ChaCha20Poly1305 {
            return Err(invalid_input(
                "shadowsocks-2022 multi-user servers need an AES method",
            ));
        }
        let validator: Validator = Box::new(move |user: &User| {
            let password = user
                .password
                .as_deref()
                .ok_or("shadowsocks user password is missing")?;
            decode_key(method, password)
                .map(|_| ())
                .map_err(|_| "shadowsocks user key is invalid for the method")
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        let server_key: Arc<[u8]> = server_key.into();
        Ok(Self {
            method,
            server_key: server_key.clone(),
            multi_user,
            index: UserIndex::new(users.clone(), user_identity),
            datagrams: Arc::new(udp::Ss2022Datagrams::new(
                method,
                server_key,
                multi_user,
                UserIndex::new(users.clone(), user_identity),
            )),
            users,
            salts: ReplayCache::new(SALT_TTL),
        })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn is_multi_user(&self) -> bool {
        self.multi_user
    }

    async fn handshake(&self, mut stream: BoxStream) -> Result<Accepted, Rejected> {
        let key_len = self.method.key_len();
        let identity_len = if self.multi_user {
            IDENTITY_HEADER_LEN
        } else {
            0
        };
        let mut head = vec![0u8; key_len + identity_len + REQUEST_FIXED_LEN + TAG_LEN];
        stream.read_exact(&mut head).await?;
        let salt = head[..key_len].to_vec();

        let (user, session_key): (_, Arc<[u8]>) = if self.multi_user {
            let identity = &head[key_len..key_len + IDENTITY_HEADER_LEN];
            let hash = match decrypt_identity(self.method, &self.server_key, &salt, identity) {
                Ok(hash) => hash,
                Err(_) => return Err(Rejected::hold("identity header is invalid", stream)),
            };
            let Some(user) = self.index.get(&hash) else {
                return Err(Rejected::hold("unknown shadowsocks user", stream));
            };
            let key = user
                .user()
                .password
                .as_deref()
                .map(|password| decode_key(self.method, password));
            let Some(Ok(key)) = key else {
                return Err(Rejected::hold("unknown shadowsocks user", stream));
            };
            (Some(user), key.into())
        } else {
            (None, self.server_key.clone())
        };

        let mut decryptor = match Cipher::new(self.method, &session_key, &salt) {
            Ok(cipher) => cipher,
            Err(_) => return Err(Rejected::close("session key setup failed")),
        };
        let fixed = &mut head[key_len + identity_len..];
        if decryptor.open_in_place(fixed).is_err() {
            return Err(Rejected::hold("shadowsocks authentication failed", stream));
        }
        if fixed[0] != CLIENT_STREAM {
            return Err(Rejected::hold("request type is invalid", stream));
        }
        let timestamp = u64::from_be_bytes(fixed[1..9].try_into().expect("8 bytes"));
        if unix_time_secs().abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
            return Err(Rejected::hold("request timestamp is out of range", stream));
        }
        let variable_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
        // Only authenticated salts enter the cache, so garbage cannot fill it.
        if !self.salts.insert(&salt) {
            return Err(Rejected::hold("request salt was replayed", stream));
        }

        let mut variable = vec![0u8; variable_len + TAG_LEN];
        stream.read_exact(&mut variable).await?;
        if decryptor.open_in_place(&mut variable).is_err() {
            return Err(Rejected::hold("shadowsocks authentication failed", stream));
        }
        variable.truncate(variable_len);
        let Some((target, payload_start)) = parse_request_header(&variable) else {
            return Err(Rejected::close("request header is invalid"));
        };
        variable.drain(..payload_start);

        let stream = Ss2022ServerStream {
            inner: stream,
            method: self.method,
            session_key,
            request_salt: salt,
            decryptor,
            encryptor: None,
            out: Vec::new(),
            out_pos: 0,
            read_state: ReadState::Length,
            rbuf: Vec::new(),
            rfilled: 0,
            plain: variable,
            plain_pos: 0,
        };
        Ok(Accepted {
            user,
            target,
            stream: Box::new(stream),
            udp: None,
        })
    }
}

impl StreamInbound for Ss2022Inbound {
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

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        Some(self.datagrams.clone() as Arc<dyn DatagramInbound>)
    }
}

/// Index key of a user: the first 16 bytes of BLAKE3(uPSK), which is what an
/// identity header carries.
fn user_identity(user: &User) -> Option<[u8; IDENTITY_HEADER_LEN]> {
    let key = decode_base64(user.password.as_deref()?).ok()?;
    let mut out = [0u8; IDENTITY_HEADER_LEN];
    out.copy_from_slice(&blake3::hash(&key).as_bytes()[..IDENTITY_HEADER_LEN]);
    Some(out)
}

/// Reverses the client's identity header: AES-decrypts it under a subkey of
/// the identity key and the request salt.
fn decrypt_identity(
    method: Method,
    identity_key: &[u8],
    salt: &[u8],
    header: &[u8],
) -> io::Result<[u8; IDENTITY_HEADER_LEN]> {
    let mut hasher = blake3::Hasher::new_derive_key(IDENTITY_SUBKEY_CONTEXT);
    hasher.update(identity_key);
    hasher.update(salt);
    let subkey = hasher.finalize();
    let subkey = &subkey.as_bytes()[..method.key_len()];
    let mut raw = [0u8; IDENTITY_HEADER_LEN];
    raw.copy_from_slice(header);
    let mut block = Block::from(raw);
    let setup_failed = || io::Error::other("shadowsocks-2022 identity key setup failed");
    match method {
        Method::Aes128Gcm => Aes128::new_from_slice(subkey)
            .map_err(|_| setup_failed())?
            .decrypt_block(&mut block),
        Method::Aes256Gcm => Aes256::new_from_slice(subkey)
            .map_err(|_| setup_failed())?
            .decrypt_block(&mut block),
        Method::ChaCha20Poly1305 => {
            return Err(invalid_input(
                "shadowsocks-2022 identity headers need an AES method",
            ))
        }
    }
    let mut out = [0u8; IDENTITY_HEADER_LEN];
    out.copy_from_slice(block.as_slice());
    Ok(out)
}

/// Parses ATYP, address, port, padding length and padding. Returns the target
/// and the offset where the initial payload starts.
fn parse_request_header(header: &[u8]) -> Option<(TargetAddr, usize)> {
    let (target, mut pos) = parse_socks_address(header)?;
    let padding = usize::from(u16::from_be_bytes(
        header.get(pos..pos + 2)?.try_into().ok()?,
    ));
    pos += 2;
    if header.len() < pos + padding {
        return None;
    }
    Some((target, pos + padding))
}

/// Parses a SOCKS-style `ATYP ADDR PORT`; returns the address and its length.
fn parse_socks_address(header: &[u8]) -> Option<(TargetAddr, usize)> {
    Some(match *header.first()? {
        1 => {
            let raw: [u8; 4] = header.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(header.get(5..7)?.try_into().ok()?);
            let addr = SocketAddrV4::new(Ipv4Addr::from(raw), port);
            (TargetAddr::Ip(SocketAddr::V4(addr)), 7)
        }
        3 => {
            let len = usize::from(*header.get(1)?);
            let domain = std::str::from_utf8(header.get(2..2 + len)?).ok()?;
            if domain.is_empty() {
                return None;
            }
            let port = u16::from_be_bytes(header.get(2 + len..4 + len)?.try_into().ok()?);
            (TargetAddr::Domain(domain.to_owned(), port), 4 + len)
        }
        4 => {
            let raw: [u8; 16] = header.get(1..17)?.try_into().ok()?;
            let port = u16::from_be_bytes(header.get(17..19)?.try_into().ok()?);
            let addr = SocketAddrV6::new(Ipv6Addr::from(raw), port, 0, 0);
            (TargetAddr::Ip(SocketAddr::V6(addr)), 19)
        }
        _ => return None,
    })
}

/// Decodes one base64 key and checks its length against the method.
fn decode_key(method: Method, key: &str) -> io::Result<Vec<u8>> {
    let decoded = decode_base64(key)?;
    if decoded.len() != method.key_len() {
        return Err(invalid_input(
            "shadowsocks-2022 key length does not match the method",
        ));
    }
    Ok(decoded)
}

fn decode_base64(key: &str) -> io::Result<Vec<u8>> {
    let key = key.trim();
    if key.contains(['-', '_']) {
        URL_SAFE_KEY.decode(key)
    } else {
        STANDARD_KEY.decode(key)
    }
    .map_err(|_| invalid_input("shadowsocks-2022 key is not valid base64"))
}

const LENIENT_PADDING: base64::engine::GeneralPurposeConfig =
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
const STANDARD_KEY: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, LENIENT_PADDING);
const URL_SAFE_KEY: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, LENIENT_PADDING);

fn algorithm(method: Method) -> &'static aead::Algorithm {
    match method {
        Method::Aes128Gcm => &aead::AES_128_GCM,
        Method::Aes256Gcm => &aead::AES_256_GCM,
        Method::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    }
}

struct Cipher {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
}

impl Cipher {
    fn new(method: Method, psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        let mut hasher = blake3::Hasher::new_derive_key(SUBKEY_CONTEXT);
        hasher.update(psk);
        hasher.update(salt);
        let mut subkey = [0u8; 32];
        hasher.finalize_xof().fill(&mut subkey[..method.key_len()]);
        let unbound = UnboundKey::new(algorithm(method), &subkey[..method.key_len()])
            .map_err(|_| io::Error::other("shadowsocks-2022 session key setup failed"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce: [0u8; NONCE_LEN],
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        // Little-endian counter, as in libsodium's sodium_increment.
        for byte in self.nonce.iter_mut() {
            let (value, overflow) = byte.overflowing_add(1);
            *byte = value;
            if !overflow {
                break;
            }
        }
        nonce
    }

    fn seal_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plaintext);
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..])
            .map_err(|_| io::Error::other("shadowsocks encryption failed"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Decrypts `buf` (ciphertext followed by tag) in place and returns the
    /// plaintext length.
    fn open_in_place(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nonce = self.next_nonce();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), buf)
            .map_err(|_| invalid_data("shadowsocks authentication failed"))?;
        Ok(plaintext.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    Length,
    Payload(usize),
    Eof,
}

/// Server side of one Shadowsocks-2022 TCP session, after the request header.
struct Ss2022ServerStream {
    inner: BoxStream,
    method: Method,
    session_key: Arc<[u8]>,
    request_salt: Vec<u8>,
    decryptor: Cipher,
    /// `None` until the response header is written with the first payload.
    encryptor: Option<Cipher>,
    out: Vec<u8>,
    out_pos: usize,
    read_state: ReadState,
    rbuf: Vec<u8>,
    rfilled: usize,
    plain: Vec<u8>,
    plain_pos: usize,
}

impl Ss2022ServerStream {
    fn encode_response_header(&mut self, payload: &[u8]) -> io::Result<()> {
        let key_len = self.method.key_len();
        let mut salt = vec![0u8; key_len];
        fill_random(&mut salt)?;
        let mut encryptor = Cipher::new(self.method, &self.session_key, &salt)?;
        let mut fixed = Vec::with_capacity(1 + 8 + key_len + 2);
        fixed.push(SERVER_STREAM);
        fixed.extend_from_slice(&unix_time_secs().to_be_bytes());
        fixed.extend_from_slice(&self.request_salt);
        fixed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        self.out.extend_from_slice(&salt);
        encryptor.seal_into(&mut self.out, &fixed)?;
        encryptor.seal_into(&mut self.out, payload)?;
        self.encryptor = Some(encryptor);
        Ok(())
    }

    fn encode_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or_else(|| io::Error::other("shadowsocks-2022 response state is invalid"))?;
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
                    if length > 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Ss2022ServerStream {
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
        if this.encryptor.is_none() {
            this.encode_response_header(&buf[..n])?;
        } else {
            this.encode_chunk(&buf[..n])?;
        }
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

impl AsyncRead for Ss2022ServerStream {
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

fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| io::Error::other("system random source failed"))
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_headers_parse_targets_and_skip_padding() {
        let header = [1, 1, 2, 3, 4, 1, 187, 0, 2, 0, 0, b'h', b'i'];
        let (target, start) = parse_request_header(&header).unwrap();
        assert_eq!(target, TargetAddr::Ip("1.2.3.4:443".parse().unwrap()));
        assert_eq!(&header[start..], b"hi");

        let mut domain = vec![3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&[0, 80, 0, 0]);
        let (target, start) = parse_request_header(&domain).unwrap();
        assert_eq!(target, TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(start, domain.len());

        let mut v6 = vec![4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 53, 0, 0]);
        let (target, _) = parse_request_header(&v6).unwrap();
        assert_eq!(target, TargetAddr::Ip("[::1]:53".parse().unwrap()));

        assert!(parse_request_header(&[]).is_none());
        assert!(parse_request_header(&[9, 0, 0]).is_none());
        assert!(parse_request_header(&[3, 0, 0, 80, 0, 0]).is_none());
        // Padding longer than the header.
        assert!(parse_request_header(&[1, 1, 2, 3, 4, 0, 80, 0, 9]).is_none());
    }

    #[test]
    fn multi_user_needs_an_aes_method() {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(Ss2022Inbound::new(Method::ChaCha20Poly1305, &key, true).is_err());
        assert!(Ss2022Inbound::new(Method::ChaCha20Poly1305, &key, false).is_ok());
        assert!(Ss2022Inbound::new(Method::Aes256Gcm, &key, true).is_ok());
        assert!(Ss2022Inbound::new(Method::Aes128Gcm, &key, false).is_err());
    }

    #[test]
    fn user_keys_are_validated_without_echoing_them() {
        let server = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let inbound = Ss2022Inbound::new(Method::Aes128Gcm, &server, true).unwrap();
        let short = base64::engine::general_purpose::STANDARD.encode([2u8; 8]);
        let err = inbound
            .users()
            .add(User::with_password("a", short.clone()))
            .unwrap_err();
        assert!(!err.contains(&short));
        assert!(inbound
            .users()
            .add(User::with_uuid("b", "not-a-key"))
            .is_err());
        let good = base64::engine::general_purpose::STANDARD.encode([3u8; 16]);
        inbound.users().add(User::with_password("c", good)).unwrap();
        assert_eq!(inbound.users().names(), ["c"]);
    }

    #[test]
    fn identity_lookup_matches_the_client_header() {
        // The client encrypts BLAKE3(uPSK)[..16]; decrypting it must give the
        // index key of that user.
        use aes::cipher::BlockCipherEncrypt;
        let ipsk = [5u8; 16];
        let upsk = [6u8; 16];
        let salt = [8u8; 16];
        let mut hasher = blake3::Hasher::new_derive_key(IDENTITY_SUBKEY_CONTEXT);
        hasher.update(&ipsk);
        hasher.update(&salt);
        let subkey = hasher.finalize();
        let mut plain = [0u8; 16];
        plain.copy_from_slice(&blake3::hash(&upsk).as_bytes()[..16]);
        let mut block = Block::from(plain);
        Aes128::new_from_slice(&subkey.as_bytes()[..16])
            .unwrap()
            .encrypt_block(&mut block);

        let decrypted =
            decrypt_identity(Method::Aes128Gcm, &ipsk, &salt, block.as_slice()).unwrap();
        let user = User::with_password("u", base64::engine::general_purpose::STANDARD.encode(upsk));
        assert_eq!(Some(decrypted), user_identity(&user));
    }
}
