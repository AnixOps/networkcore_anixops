//! Shadowsocks AEAD (SIP004) TCP client, the pre-2022 protocol most
//! subscriptions still carry.
//!
//! Supports `aes-128-gcm`, `aes-256-gcm` and `chacha20-ietf-poly1305`. The
//! master key is `EVP_BytesToKey(password)`; each direction derives its
//! session key with HKDF-SHA1 from a random salt of key length and sends
//! `salt || chunks`, where a chunk is `seal(u16 length) || seal(payload)` with
//! a little-endian nonce counter. The target address is the start of the
//! first chunk, sent with the first payload write (or alone when the
//! application reads first).
//!
//! UDP sends `salt || seal(address || payload)` per datagram, nonce zero
//! ([`TcpOutbound::open_udp`], one socket per flow).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound, UdpFlow};
use md5::{Digest as _, Md5};
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::hkdf;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{encode_address, fill_random, invalid_data, invalid_input, Cipher, NONCE_LEN, TAG_LEN};

pub const PROTOCOL: &str = "shadowsocks";

const SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];
/// SIP004 caps a chunk's payload at 0x3FFF bytes.
const MAX_PAYLOAD: usize = 0x3fff;
/// Plaintext bytes per outgoing chunk, below the protocol cap.
const MAX_CHUNK: usize = 8 * 1024;

/// SIP004 AEAD method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadMethod {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(invalid_input("unsupported shadowsocks method")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// The session cipher for one direction: HKDF-SHA1(key, salt, "ss-subkey").
    pub(crate) fn session_cipher(self, key: &[u8], salt: &[u8]) -> io::Result<Cipher> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(key);
        let okm = prk
            .expand(SUBKEY_INFO, self.algorithm())
            .map_err(|_| io::Error::other("shadowsocks session key setup failed"))?;
        Ok(Cipher {
            key: LessSafeKey::new(UnboundKey::from(okm)),
            nonce: [0u8; NONCE_LEN],
        })
    }
}

/// OpenSSL `EVP_BytesToKey` with MD5 and no salt, the SIP004 password KDF.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

/// Shadowsocks AEAD outbound. It holds the derived key and never prints it.
pub struct AeadOutbound {
    server: String,
    port: u16,
    method: AeadMethod,
    key: Arc<[u8]>,
    dialer: Arc<dyn Dialer>,
}

impl AeadOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        method: AeadMethod,
        password: &str,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid_input("shadowsocks server address is empty"));
        }
        if password.is_empty() {
            return Err(invalid_input("shadowsocks password is empty"));
        }
        Ok(Self {
            server,
            port,
            method,
            key: evp_bytes_to_key(password.as_bytes(), method.key_len()).into(),
            dialer,
        })
    }

    pub fn method(&self) -> AeadMethod {
        self.method
    }
}

impl TcpOutbound for AeadOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let address = encode_address(target)?;
            let inner = self.dialer.dial(&self.server, self.port).await?;
            let stream = AeadStream::new(inner, self.method, self.key.clone(), address)?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let address = encode_address(target)?;
            let socket = self.dialer.open_datagram(&self.server, self.port).await?;
            Ok(crate::udp::aead_flow(
                socket,
                self.method,
                self.key.clone(),
                address,
            ))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    Salt,
    Length,
    Payload(usize),
    Eof,
}

struct AeadStream {
    inner: BoxStream,
    method: AeadMethod,
    key: Arc<[u8]>,
    /// Encoded target address; `Some` until the first chunk is written.
    pending_address: Option<Vec<u8>>,
    /// Request salt; written in front of the first chunk.
    salt: Option<Vec<u8>>,
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

impl AeadStream {
    fn new(
        inner: BoxStream,
        method: AeadMethod,
        key: Arc<[u8]>,
        address: Vec<u8>,
    ) -> io::Result<Self> {
        let mut salt = vec![0u8; method.key_len()];
        fill_random(&mut salt)?;
        let encryptor = method.session_cipher(&key, &salt)?;
        Ok(Self {
            inner,
            method,
            key,
            pending_address: Some(address),
            salt: Some(salt),
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

    /// Queues one chunk; the first one carries the salt and target address.
    fn encode_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        if let Some(salt) = self.salt.take() {
            self.out.extend_from_slice(&salt);
        }
        let chunk = match self.pending_address.take() {
            Some(mut address) => {
                address.extend_from_slice(payload);
                address
            }
            None => payload.to_vec(),
        };
        let length = (chunk.len() as u16).to_be_bytes();
        self.encryptor.seal_into(&mut self.out, &length)?;
        self.encryptor.seal_into(&mut self.out, &chunk)
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
            .ok_or_else(|| io::Error::other("shadowsocks response state is invalid"))
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
                    let cipher = self
                        .method
                        .session_cipher(&self.key, &self.rbuf[..key_len])?;
                    self.decryptor = Some(cipher);
                    self.read_state = ReadState::Length;
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
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for AeadStream {
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

impl AsyncRead for AeadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_address.is_some() {
            // Reading before the first write: send the address on its own.
            this.encode_chunk(&[])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // `openssl enc -aes-256-cbc -k foobar -nosalt -md md5 -P` prints this key.
        let key = evp_bytes_to_key(b"foobar", 32);
        assert_eq!(
            key.iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>(),
            "3858F62230AC3C915F300C664312C63F568378529614D22DDB49237D2F60BFDF"
        );
        assert_eq!(evp_bytes_to_key(b"foobar", 16), key[..16]);
    }

    #[test]
    fn methods_parse_with_their_aliases() {
        assert_eq!(AeadMethod::parse("aes-128-gcm").unwrap().key_len(), 16);
        assert_eq!(AeadMethod::parse("aes-256-gcm").unwrap().key_len(), 32);
        assert_eq!(
            AeadMethod::parse("chacha20-poly1305").unwrap(),
            AeadMethod::ChaCha20Poly1305
        );
        assert!(AeadMethod::parse("aes-128-cfb").is_err());
        assert!(AeadMethod::parse("2022-blake3-aes-128-gcm").is_err());
    }
}
