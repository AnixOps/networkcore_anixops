//! Salamander packet obfuscation (Hysteria2 `obfs.type: salamander`).
//!
//! Every UDP datagram becomes `salt (8 random bytes) || payload XOR key`,
//! where the key is BLAKE2b-256 of the password followed by the salt, repeated
//! over the payload. Datagrams too short to carry a salt are dropped.
//!
//! [`SalamanderSocket`] wraps the socket quinn sends through, so the QUIC
//! stack itself is unchanged.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use ring::rand::{SecureRandom, SystemRandom};

pub const SALT_LEN: usize = 8;
/// Shortest password Hysteria accepts.
pub const MIN_PASSWORD_LEN: usize = 4;

/// The obfuscator for one password.
#[derive(Clone)]
pub struct Salamander {
    password: Vec<u8>,
    rng: SystemRandom,
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

impl Salamander {
    pub fn new(password: impl Into<Vec<u8>>) -> io::Result<Self> {
        let password = password.into();
        if password.len() < MIN_PASSWORD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander password is too short",
            ));
        }
        Ok(Self {
            password,
            rng: SystemRandom::new(),
        })
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(&self.password);
        hasher.update(salt);
        hasher.finalize().into()
    }

    /// Appends the obfuscated form of `packet` to `out`.
    pub fn obfuscate(&self, packet: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut salt = [0u8; SALT_LEN];
        self.rng
            .fill(&mut salt)
            .map_err(|_| io::Error::other("system random source failed"))?;
        let key = self.key(&salt);
        out.reserve(SALT_LEN + packet.len());
        out.extend_from_slice(&salt);
        out.extend(packet.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k));
        Ok(())
    }

    /// Restores the datagram in `buf` in place at its start and returns its
    /// length, or `None` if it is too short to carry a salt.
    pub fn deobfuscate(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() <= SALT_LEN {
            return None;
        }
        let key = self.key(&buf[..SALT_LEN]);
        let len = buf.len() - SALT_LEN;
        buf.copy_within(SALT_LEN.., 0);
        for (byte, k) in buf[..len].iter_mut().zip(key.iter().cycle()) {
            *byte ^= k;
        }
        Some(len)
    }
}

/// A UDP socket that applies [`Salamander`] to every datagram.
#[derive(Debug)]
pub struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    salamander: Salamander,
}

impl SalamanderSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, salamander: Salamander) -> Arc<Self> {
        Arc::new(Self { inner, salamander })
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so a transmit is one datagram.
        let mut packet = Vec::new();
        self.salamander.obfuscate(transmit.contents, &mut packet)?;
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            let (len, stride) =
                deobfuscate_batch(&self.salamander, &mut buf[..meta.len], meta.stride);
            meta.len = len;
            meta.stride = stride;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Deobfuscates the datagrams of one receive buffer (several when the
/// socket coalesced them, `stride` bytes apart) and packs them at the new
/// stride. Returns the new length and stride; a datagram too short to carry
/// a salt ends the batch (only the last one can be short).
pub fn deobfuscate_batch(salamander: &Salamander, buf: &mut [u8], stride: usize) -> (usize, usize) {
    let stride = if stride == 0 { buf.len() } else { stride };
    if stride <= SALT_LEN {
        return (0, stride);
    }
    let new_stride = stride - SALT_LEN;
    let mut written = 0;
    let mut start = 0;
    while start < buf.len() {
        let end = (start + stride).min(buf.len());
        let Some(len) = salamander.deobfuscate(&mut buf[start..end]) else {
            break;
        };
        buf.copy_within(start..start + len, written);
        written += len;
        start = end;
    }
    (written, new_stride)
}
