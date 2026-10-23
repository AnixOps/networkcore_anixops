//! Shadowsocks-2022 (SIP022) TCP client outbound.
//!
//! Supports `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and
//! `2022-blake3-chacha20-poly1305`. A password of the form `iPSK:...:uPSK`
//! adds extensible identity headers (SIP022 multi-user), which only the AES
//! methods define. Keys are standard or URL-safe base64, padding optional.
//!
//! The request header is sent together with the first payload write. If the
//! application reads before writing (server-speaks-first protocols), the header
//! is sent with random padding instead, as the specification requires.
//!
//! [`ShadowsocksFactory`] registers the outbound under `"type": "shadowsocks"`.

mod factory;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use base64::Engine as _;
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use factory::{ShadowsocksFactory, TYPE_NAME};

pub const PROTOCOL: &str = "shadowsocks-2022";

const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
const IDENTITY_HEADER_LEN: usize = 16;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CLIENT_STREAM: u8 = 0;
const SERVER_STREAM: u8 = 1;
const MAX_TIMESTAMP_DIFF_SECS: u64 = 30;
const MAX_PADDING: u16 = 900;
/// Plaintext bytes per outgoing chunk. The protocol allows 0xFFFF; a smaller
/// chunk keeps per-connection buffers small inside the Network Extension.
const MAX_CHUNK: usize = 8 * 1024;

/// AEAD-2022 method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Method::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Method::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Method::ChaCha20Poly1305),
            _ => Err(invalid_input("unsupported shadowsocks-2022 method")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Method::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Method::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            Method::Aes256Gcm | Method::ChaCha20Poly1305 => 32,
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Method::Aes128Gcm => &aead::AES_128_GCM,
            Method::Aes256Gcm => &aead::AES_256_GCM,
            Method::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

/// Shadowsocks-2022 outbound. It holds the decoded key and never prints it.
pub struct Ss2022Outbound {
    server: String,
    port: u16,
    method: Method,
    psk: Arc<[u8]>,
    identity_keys: Arc<[Box<[u8]>]>,
    dialer: Arc<dyn Dialer>,
}

impl Ss2022Outbound {
    /// `password` is the base64-encoded pre-shared key, or `iPSK:...:uPSK`
    /// for a server that identifies users by identity headers.
    pub fn new(
        server: impl Into<String>,
        port: u16,
        method: Method,
        password: &str,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid_input("shadowsocks-2022 server address is empty"));
        }
        let mut keys = password
            .trim()
            .split(':')
            .map(|key| decode_key(method, key))
            .collect::<io::Result<Vec<_>>>()?;
        let psk = keys.pop().expect("split yields at least one key");
        if !keys.is_empty() && method == Method::ChaCha20Poly1305 {
            return Err(invalid_input(
                "shadowsocks-2022 identity headers need an AES method",
            ));
        }
        Ok(Self {
            server,
            port,
            method,
            psk: psk.into(),
            identity_keys: keys.into_iter().map(Vec::into_boxed_slice).collect(),
            dialer,
        })
    }

    pub fn method(&self) -> Method {
        self.method
    }
}

impl TcpOutbound for Ss2022Outbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let address = encode_address(target)?;
            let inner = self.dialer.dial(&self.server, self.port).await?;
            let stream = Ss2022Stream::new(
                inner,
                self.method,
                self.psk.clone(),
                self.identity_keys.clone(),
                address,
            )?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// Decodes one base64 key and checks its length against the method.
fn decode_key(method: Method, key: &str) -> io::Result<Vec<u8>> {
    let key = key.trim();
    let decoded = if key.contains(['-', '_']) {
        URL_SAFE_KEY.decode(key)
    } else {
        STANDARD_KEY.decode(key)
    }
    .map_err(|_| invalid_input("shadowsocks-2022 key is not valid base64"))?;
    if decoded.len() != method.key_len() {
        return Err(invalid_input(
            "shadowsocks-2022 key length does not match the method",
        ));
    }
    Ok(decoded)
}

const LENIENT_PADDING: base64::engine::GeneralPurposeConfig =
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
const STANDARD_KEY: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, LENIENT_PADDING);
const URL_SAFE_KEY: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, LENIENT_PADDING);

/// One extensible identity header: the first 16 bytes of BLAKE3(`next_key`),
/// encrypted with AES under a subkey of `identity_key` and the request salt.
fn identity_header(
    method: Method,
    identity_key: &[u8],
    salt: &[u8],
    next_key: &[u8],
) -> io::Result<[u8; IDENTITY_HEADER_LEN]> {
    let mut hasher = blake3::Hasher::new_derive_key(IDENTITY_SUBKEY_CONTEXT);
    hasher.update(identity_key);
    hasher.update(salt);
    let subkey = hasher.finalize();
    let subkey = &subkey.as_bytes()[..method.key_len()];
    let mut plain = [0u8; IDENTITY_HEADER_LEN];
    plain.copy_from_slice(&blake3::hash(next_key).as_bytes()[..IDENTITY_HEADER_LEN]);
    let plain = Block::from(plain);
    let mut sealed = Block::from([0u8; IDENTITY_HEADER_LEN]);
    let setup_failed = || io::Error::other("shadowsocks-2022 identity key setup failed");
    match method {
        Method::Aes128Gcm => Aes128::new_from_slice(subkey)
            .map_err(|_| setup_failed())?
            .encrypt_block_b2b(&plain, &mut sealed),
        Method::Aes256Gcm => Aes256::new_from_slice(subkey)
            .map_err(|_| setup_failed())?
            .encrypt_block_b2b(&plain, &mut sealed),
        Method::ChaCha20Poly1305 => {
            return Err(invalid_input(
                "shadowsocks-2022 identity headers need an AES method",
            ))
        }
    }
    let mut out = [0u8; IDENTITY_HEADER_LEN];
    out.copy_from_slice(sealed.as_slice());
    Ok(out)
}

/// SOCKS-style address: ATYP, address, big-endian port.
fn encode_address(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 1 + 255 + 2);
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Domain(domain, _) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(invalid_input("target domain length is out of range"));
            }
            out.push(3);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
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
        let unbound = UnboundKey::new(method.algorithm(), &subkey[..method.key_len()])
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
            .map_err(|_| io::Error::other("shadowsocks-2022 encryption failed"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Decrypts `buf` (ciphertext followed by tag) in place and returns the plaintext length.
    fn open_in_place(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nonce = self.next_nonce();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), buf)
            .map_err(|_| invalid_data("shadowsocks-2022 authentication failed"))?;
        Ok(plaintext.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    Salt,
    FixedHeader,
    Length,
    Payload(usize),
    Eof,
}

/// Client side of one Shadowsocks-2022 TCP session.
pub struct Ss2022Stream {
    inner: BoxStream,
    method: Method,
    psk: Arc<[u8]>,
    identity_keys: Arc<[Box<[u8]>]>,
    /// Encoded target address; `Some` until the request header is written.
    pending_address: Option<Vec<u8>>,
    request_salt: Vec<u8>,
    encryptor: Cipher,
    decryptor: Option<Cipher>,
    out: Vec<u8>,
    out_pos: usize,
    read_state: ReadState,
    rbuf: Vec<u8>,
    rfilled: usize,
    plain: Vec<u8>,
    plain_pos: usize,
}

impl Ss2022Stream {
    fn new(
        inner: BoxStream,
        method: Method,
        psk: Arc<[u8]>,
        identity_keys: Arc<[Box<[u8]>]>,
        address: Vec<u8>,
    ) -> io::Result<Self> {
        let mut request_salt = vec![0u8; method.key_len()];
        fill_random(&mut request_salt)?;
        let encryptor = Cipher::new(method, &psk, &request_salt)?;
        Ok(Self {
            inner,
            method,
            psk,
            identity_keys,
            pending_address: Some(address),
            request_salt,
            encryptor,
            decryptor: None,
            out: Vec::new(),
            out_pos: 0,
            read_state: ReadState::Salt,
            rbuf: Vec::new(),
            rfilled: 0,
            plain: Vec::new(),
            plain_pos: 0,
        })
    }

    fn encode_request_header(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(address) = self.pending_address.take() else {
            return Ok(());
        };
        let padding_len = if payload.is_empty() {
            let mut raw = [0u8; 2];
            fill_random(&mut raw)?;
            u16::from_be_bytes(raw) % MAX_PADDING + 1
        } else {
            0
        };

        let mut variable =
            Vec::with_capacity(address.len() + 2 + usize::from(padding_len) + payload.len());
        variable.extend_from_slice(&address);
        variable.extend_from_slice(&padding_len.to_be_bytes());
        variable.resize(variable.len() + usize::from(padding_len), 0);
        variable.extend_from_slice(payload);

        let mut fixed = [0u8; 11];
        fixed[0] = CLIENT_STREAM;
        fixed[1..9].copy_from_slice(&unix_time_secs().to_be_bytes());
        fixed[9..11].copy_from_slice(&(variable.len() as u16).to_be_bytes());

        self.out.extend_from_slice(&self.request_salt);
        // Each identity key names the next one; the last names the user key.
        for (index, identity_key) in self.identity_keys.iter().enumerate() {
            let next_key = self
                .identity_keys
                .get(index + 1)
                .map_or(&self.psk[..], |key| &key[..]);
            let header = identity_header(self.method, identity_key, &self.request_salt, next_key)?;
            self.out.extend_from_slice(&header);
        }
        self.encryptor.seal_into(&mut self.out, &fixed)?;
        self.encryptor.seal_into(&mut self.out, &variable)
    }

    fn encode_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let length = (payload.len() as u16).to_be_bytes();
        self.encryptor.seal_into(&mut self.out, &length)?;
        self.encryptor.seal_into(&mut self.out, payload)
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

    /// Reads until `rbuf` holds exactly `need` bytes. Returns `false` on a clean
    /// end of stream before any byte of this unit arrived.
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

    fn decryptor(&mut self) -> io::Result<&mut Cipher> {
        self.decryptor
            .as_mut()
            .ok_or_else(|| io::Error::other("shadowsocks-2022 response state is invalid"))
    }

    /// Advances the read state machine until plaintext is available or the stream ends.
    fn poll_next_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let key_len = self.method.key_len();
        loop {
            match self.read_state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Salt => {
                    if !ready!(self.poll_fill(cx, key_len))? {
                        self.read_state = ReadState::Eof;
                        continue;
                    }
                    let cipher = Cipher::new(self.method, &self.psk, &self.rbuf[..key_len])?;
                    self.decryptor = Some(cipher);
                    self.read_state = ReadState::FixedHeader;
                }
                ReadState::FixedHeader => {
                    let need = 1 + 8 + key_len + 2 + TAG_LEN;
                    if !ready!(self.poll_fill(cx, need))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let mut header = std::mem::take(&mut self.rbuf);
                    let opened = self.decryptor()?.open_in_place(&mut header[..need]);
                    let result =
                        opened.and_then(|_| self.check_response_header(&header[..need - TAG_LEN]));
                    self.rbuf = header;
                    let length = result?;
                    self.read_state = ReadState::Payload(length);
                }
                ReadState::Length => {
                    let need = 2 + TAG_LEN;
                    if !ready!(self.poll_fill(cx, need))? {
                        self.read_state = ReadState::Eof;
                        continue;
                    }
                    let mut buf = std::mem::take(&mut self.rbuf);
                    let opened = self.decryptor()?.open_in_place(&mut buf[..need]);
                    let length = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
                    self.rbuf = buf;
                    opened?;
                    self.read_state = ReadState::Payload(length);
                }
                ReadState::Payload(length) => {
                    let need = length + TAG_LEN;
                    if !ready!(self.poll_fill(cx, need))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let mut buf = std::mem::take(&mut self.rbuf);
                    let opened = self.decryptor()?.open_in_place(&mut buf[..need]);
                    if let Err(err) = opened {
                        self.rbuf = buf;
                        return Poll::Ready(Err(err));
                    }
                    buf.truncate(length);
                    // Hand the decrypted buffer to the reader and reuse the old one for input.
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

    /// Validates the decrypted response header and returns the first payload length.
    fn check_response_header(&self, header: &[u8]) -> io::Result<usize> {
        let key_len = self.method.key_len();
        if header[0] != SERVER_STREAM {
            return Err(invalid_data("shadowsocks-2022 response type is invalid"));
        }
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&header[1..9]);
        let timestamp = u64::from_be_bytes(timestamp);
        if unix_time_secs().abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
            return Err(invalid_data(
                "shadowsocks-2022 response timestamp is out of range",
            ));
        }
        if header[9..9 + key_len] != self.request_salt[..] {
            return Err(invalid_data(
                "shadowsocks-2022 response does not match the request",
            ));
        }
        let length = &header[9 + key_len..11 + key_len];
        Ok(usize::from(u16::from_be_bytes([length[0], length[1]])))
    }
}

impl AsyncWrite for Ss2022Stream {
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
        if this.pending_address.is_some() {
            this.encode_request_header(&buf[..n])?;
        } else {
            this.encode_chunk(&buf[..n])?;
        }
        // The chunk is committed to `out`; a pending drain finishes on the next call.
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

impl AsyncRead for Ss2022Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_address.is_some() {
            // Reading before the first write: send the header with padding only.
            this.encode_request_header(&[])?;
        }
        ready!(this.poll_drain(cx))?;
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
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    #[test]
    fn methods_parse_and_report_key_length() {
        assert_eq!(
            Method::parse("2022-blake3-aes-128-gcm").unwrap().key_len(),
            16
        );
        assert_eq!(
            Method::parse("2022-blake3-aes-256-gcm").unwrap().key_len(),
            32
        );
        assert_eq!(
            Method::parse("2022-blake3-chacha20-poly1305")
                .unwrap()
                .key_len(),
            32
        );
        assert!(Method::parse("aes-128-gcm").is_err());
    }

    #[test]
    fn addresses_encode_like_socks() {
        let v4 = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443)));
        assert_eq!(encode_address(&v4).unwrap(), vec![1, 1, 2, 3, 4, 1, 187]);
        let v6 = TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            80,
            0,
            0,
        )));
        let encoded = encode_address(&v6).unwrap();
        assert_eq!(encoded[0], 4);
        assert_eq!(encoded.len(), 1 + 16 + 2);
        let domain = TargetAddr::Domain("example.com".into(), 80);
        let encoded = encode_address(&domain).unwrap();
        assert_eq!(&encoded[..2], &[3, 11]);
        assert_eq!(&encoded[13..], &[0, 80]);
        assert!(encode_address(&TargetAddr::Domain(String::new(), 80)).is_err());
    }

    #[test]
    fn nonce_counter_is_little_endian() {
        let mut cipher = Cipher::new(Method::Aes128Gcm, &[7u8; 16], &[9u8; 16]).unwrap();
        cipher.nonce[0] = 0xff;
        let _ = cipher.next_nonce();
        assert_eq!(&cipher.nonce[..2], &[0, 1]);
    }

    #[test]
    fn keys_accept_url_safe_and_unpadded_base64() {
        let key = [0xfbu8; 16];
        let standard = base64::engine::general_purpose::STANDARD.encode(key);
        let unpadded = standard.trim_end_matches('=').to_owned();
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        assert!(url_safe.contains(['-', '_']));
        for encoded in [standard, unpadded, url_safe] {
            assert_eq!(decode_key(Method::Aes128Gcm, &encoded).unwrap(), key);
        }
    }

    #[test]
    fn identity_keys_need_an_aes_method() {
        let dialer: Arc<dyn Dialer> = Arc::new(engine_outbound::TcpDialer);
        let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let multi_user = format!("{key}:{key}");
        let outbound = Ss2022Outbound::new(
            "example.com",
            8388,
            Method::Aes256Gcm,
            &multi_user,
            dialer.clone(),
        )
        .unwrap();
        assert_eq!(outbound.identity_keys.len(), 1);
        assert!(Ss2022Outbound::new(
            "example.com",
            8388,
            Method::ChaCha20Poly1305,
            &multi_user,
            dialer
        )
        .is_err());
    }

    #[test]
    fn keys_are_validated_without_echoing_secrets() {
        let dialer: Arc<dyn Dialer> = Arc::new(engine_outbound::TcpDialer);
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        let err = Ss2022Outbound::new(
            "example.com",
            8388,
            Method::Aes128Gcm,
            &short,
            dialer.clone(),
        )
        .err()
        .unwrap();
        assert!(!err.to_string().contains(&short));
        assert!(Ss2022Outbound::new(
            "example.com",
            8388,
            Method::Aes128Gcm,
            "a:b",
            dialer.clone()
        )
        .is_err());
        assert!(Ss2022Outbound::new(
            "example.com",
            8388,
            Method::Aes128Gcm,
            "not base64!",
            dialer
        )
        .is_err());
    }
}
