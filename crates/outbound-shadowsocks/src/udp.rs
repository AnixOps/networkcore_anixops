//! Shadowsocks UDP clients: one datagram path to the server per flow, from
//! [`engine_outbound::Dialer::open_datagram`] (a connected UDP socket unless
//! the node runs through a `via`).
//!
//! SIP004: each packet is `salt | AEAD(HKDF-SHA1(key, salt), nonce 0,
//! address | payload)` in both directions.
//!
//! SIP022 AES methods: `AES-ECB(key, session id | packet id) | [identity
//! headers] | AEAD(session subkey, nonce = header[4..16], body)`, where the
//! client body is `type 0 | timestamp | padding len | padding | address |
//! payload` and the server body `type 1 | timestamp | client session id |
//! padding len | padding | address | payload` under the server's session id.
//! With identity keys the separate header is encrypted with the first one,
//! and each identity header is `AES-ECB(iPSK, BLAKE3(next key)[..16] ^
//! separate header)`. The ChaCha20 method sends `nonce (24) |
//! XChaCha20-Poly1305(PSK, session id | packet id | body)`.
//!
//! Replies that fail to authenticate, or belong to another session, are
//! skipped rather than ending the flow.

use std::io;
use std::sync::Arc;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::KeyInit as _;
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use engine_outbound::{BoxFuture, DatagramRecv, DatagramSend, UdpFlow};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use crate::sip004::AeadMethod;
use crate::{
    fill_random, invalid_input, unix_time_secs, Method, CLIENT_STREAM, IDENTITY_HEADER_LEN,
    MAX_TIMESTAMP_DIFF_SECS, SERVER_STREAM, SUBKEY_CONTEXT, TAG_LEN,
};

const XNONCE_LEN: usize = 24;

/// A SIP004 flow to the target encoded in `address`.
pub(crate) fn aead_flow(
    server: UdpFlow,
    method: AeadMethod,
    key: Arc<[u8]>,
    address: Vec<u8>,
) -> UdpFlow {
    UdpFlow::new(
        Box::new(AeadSend {
            server: server.send,
            method,
            key: key.clone(),
            address,
        }),
        Box::new(AeadRecv {
            server: server.recv,
            method,
            key,
        }),
    )
}

struct AeadSend {
    server: Box<dyn DatagramSend>,
    method: AeadMethod,
    key: Arc<[u8]>,
    address: Vec<u8>,
}

impl DatagramSend for AeadSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut packet = vec![0u8; self.method.key_len()];
            fill_random(&mut packet)?;
            let mut cipher = self.method.session_cipher(&self.key, &packet)?;
            let mut plaintext = Vec::with_capacity(self.address.len() + payload.len());
            plaintext.extend_from_slice(&self.address);
            plaintext.extend_from_slice(payload);
            cipher.seal_into(&mut packet, &plaintext)?;
            self.server.send(&packet).await
        })
    }
}

struct AeadRecv {
    server: Box<dyn DatagramRecv>,
    method: AeadMethod,
    key: Arc<[u8]>,
}

impl AeadRecv {
    fn open(&self, packet: &mut [u8]) -> Option<Vec<u8>> {
        let salt_len = self.method.key_len();
        if packet.len() < salt_len + TAG_LEN {
            return None;
        }
        let (salt, body) = packet.split_at_mut(salt_len);
        let mut cipher = self.method.session_cipher(&self.key, salt).ok()?;
        let len = cipher.open_in_place(body).ok()?;
        let offset = address_len(&body[..len])?;
        Some(body[offset..len].to_vec())
    }
}

impl DatagramRecv for AeadRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            loop {
                let mut packet = self.server.recv().await?;
                if let Some(payload) = self.open(&mut packet) {
                    return Ok(payload);
                }
            }
        })
    }
}

/// A SIP022 flow to the target encoded in `address`.
pub(crate) fn ss2022_flow(
    server: UdpFlow,
    method: Method,
    psk: Arc<[u8]>,
    identity_keys: Arc<[Box<[u8]>]>,
    address: Vec<u8>,
) -> io::Result<UdpFlow> {
    let mut id = [0u8; 8];
    fill_random(&mut id)?;
    let session_id = u64::from_be_bytes(id);
    let uplink = match method {
        Method::ChaCha20Poly1305 => None,
        _ => Some(session_cipher(method, &psk, session_id)?),
    };
    Ok(UdpFlow::new(
        Box::new(Ss2022Send {
            server: server.send,
            method,
            psk: psk.clone(),
            identity_keys,
            session_id,
            packet_id: 0,
            uplink,
            address,
        }),
        Box::new(Ss2022Recv {
            server: server.recv,
            method,
            psk,
            session_id,
            downlink: None,
        }),
    ))
}

struct Ss2022Send {
    server: Box<dyn DatagramSend>,
    method: Method,
    psk: Arc<[u8]>,
    identity_keys: Arc<[Box<[u8]>]>,
    session_id: u64,
    packet_id: u64,
    uplink: Option<LessSafeKey>,
    address: Vec<u8>,
}

impl Ss2022Send {
    fn seal(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&self.session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());
        let mut body = Vec::with_capacity(1 + 8 + 2 + self.address.len() + payload.len() + TAG_LEN);
        body.push(CLIENT_STREAM);
        body.extend_from_slice(&unix_time_secs().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&self.address);
        body.extend_from_slice(payload);

        let Some(uplink) = &self.uplink else {
            let mut plaintext = header.to_vec();
            plaintext.extend_from_slice(&body);
            let mut packet = vec![0u8; XNONCE_LEN];
            fill_random(&mut packet)?;
            let tag = XChaCha20Poly1305::new_from_slice(&self.psk)
                .map_err(|_| setup_failed())?
                .encrypt_in_place_detached(XNonce::from_slice(&packet), b"", &mut plaintext)
                .map_err(|_| setup_failed())?;
            packet.extend_from_slice(&plaintext);
            packet.extend_from_slice(&tag);
            return Ok(packet);
        };

        let nonce: [u8; 12] = header[4..16].try_into().expect("12-byte slice");
        let tag = uplink
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut body,
            )
            .map_err(|_| io::Error::other("shadowsocks encryption failed"))?;
        body.extend_from_slice(tag.as_ref());

        let mut packet =
            Vec::with_capacity(16 + IDENTITY_HEADER_LEN * self.identity_keys.len() + body.len());
        let mut sealed = header;
        let header_key = self.identity_keys.first().map_or(&*self.psk, |key| &**key);
        aes_block(self.method, header_key, &mut sealed, true)?;
        packet.extend_from_slice(&sealed);
        for (index, key) in self.identity_keys.iter().enumerate() {
            let next = self
                .identity_keys
                .get(index + 1)
                .map_or(&*self.psk, |key| &**key);
            let mut identity = [0u8; IDENTITY_HEADER_LEN];
            let hash = blake3::hash(next);
            for (out, (a, b)) in identity
                .iter_mut()
                .zip(hash.as_bytes().iter().zip(header.iter()))
            {
                *out = a ^ b;
            }
            aes_block(self.method, key, &mut identity, true)?;
            packet.extend_from_slice(&identity);
        }
        packet.extend_from_slice(&body);
        Ok(packet)
    }
}

impl DatagramSend for Ss2022Send {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let packet = self.seal(payload)?;
            self.server.send(&packet).await
        })
    }
}

struct Ss2022Recv {
    server: Box<dyn DatagramRecv>,
    method: Method,
    psk: Arc<[u8]>,
    session_id: u64,
    /// The server session id and its cipher, kept while it stays the same.
    downlink: Option<(u64, LessSafeKey)>,
}

impl Ss2022Recv {
    /// The payload of one server packet, or `None` to skip it.
    fn open(&mut self, packet: &mut [u8]) -> Option<Vec<u8>> {
        let n = packet.len();
        let body = if self.method == Method::ChaCha20Poly1305 {
            if n < XNONCE_LEN + 16 + TAG_LEN {
                return None;
            }
            let (nonce, rest) = packet.split_at_mut(XNONCE_LEN);
            let (data, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
            XChaCha20Poly1305::new_from_slice(&self.psk)
                .ok()?
                .decrypt_in_place_detached(
                    XNonce::from_slice(nonce),
                    b"",
                    data,
                    Tag::from_slice(tag),
                )
                .ok()?;
            &data[16..]
        } else {
            if n < 16 + TAG_LEN {
                return None;
            }
            let (header, rest) = packet.split_at_mut(16);
            aes_block(self.method, &self.psk, header, false).ok()?;
            let server_session = u64::from_be_bytes(header[..8].try_into().ok()?);
            if self.downlink.as_ref().map(|(id, _)| *id) != Some(server_session) {
                let cipher = session_cipher(self.method, &self.psk, server_session).ok()?;
                self.downlink = Some((server_session, cipher));
            }
            let (_, cipher) = self.downlink.as_ref()?;
            let nonce: [u8; 12] = header[4..16].try_into().ok()?;
            &*cipher
                .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), rest)
                .ok()?
        };
        // type | timestamp | client session id | padding len | padding | address | payload
        if body.len() < 1 + 8 + 8 + 2 || body[0] != SERVER_STREAM {
            return None;
        }
        let timestamp = u64::from_be_bytes(body[1..9].try_into().ok()?);
        if unix_time_secs().abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
            return None;
        }
        if u64::from_be_bytes(body[9..17].try_into().ok()?) != self.session_id {
            return None;
        }
        let padding = usize::from(u16::from_be_bytes([body[17], body[18]]));
        let start = 19usize.checked_add(padding)?;
        let rest = body.get(start..)?;
        let offset = address_len(rest)?;
        Some(rest[offset..].to_vec())
    }
}

impl DatagramRecv for Ss2022Recv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            loop {
                let mut packet = self.server.recv().await?;
                if let Some(payload) = self.open(&mut packet) {
                    return Ok(payload);
                }
            }
        })
    }
}

/// Length of the SOCKS address (`ATYP ADDR PORT`) at the start of `data`.
fn address_len(data: &[u8]) -> Option<usize> {
    let len = match *data.first()? {
        1 => 1 + 4 + 2,
        3 => 1 + 1 + usize::from(*data.get(1)?) + 2,
        4 => 1 + 16 + 2,
        _ => return None,
    };
    (data.len() >= len).then_some(len)
}

fn session_cipher(method: Method, key: &[u8], session_id: u64) -> io::Result<LessSafeKey> {
    let mut hasher = blake3::Hasher::new_derive_key(SUBKEY_CONTEXT);
    hasher.update(key);
    hasher.update(&session_id.to_be_bytes());
    let mut subkey = [0u8; 32];
    hasher.finalize_xof().fill(&mut subkey[..method.key_len()]);
    let unbound = UnboundKey::new(method.algorithm(), &subkey[..method.key_len()])
        .map_err(|_| setup_failed())?;
    Ok(LessSafeKey::new(unbound))
}

/// AES-ECB on one 16-byte block in place.
fn aes_block(method: Method, key: &[u8], data: &mut [u8], encrypt: bool) -> io::Result<()> {
    let raw: [u8; 16] = (&*data)
        .try_into()
        .map_err(|_| invalid_input("shadowsocks-2022 header block is not 16 bytes"))?;
    let mut block = Block::from(raw);
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| setup_failed())?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| setup_failed())?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method::ChaCha20Poly1305 => {
            return Err(invalid_input(
                "shadowsocks-2022 separate headers need an AES method",
            ))
        }
    }
    data.copy_from_slice(block.as_slice());
    Ok(())
}

fn setup_failed() -> io::Error {
    io::Error::other("shadowsocks-2022 udp key setup failed")
}
