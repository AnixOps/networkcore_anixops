//! Session keys and the AEAD with its nonce counter (spec §2).

use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// The AEAD of a session: ChaCha20-Poly1305 for v1, AES-128-GCM for v2+.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

/// Argon2id(PSK, salt, t = 3, m = 8 KiB, p = 1), 32 bytes.
pub(crate) fn derive_key(psk: &[u8], salt: &[u8]) -> io::Result<[u8; 32]> {
    let params = Params::new(8, 3, 1, Some(32))
        .map_err(|_| io::Error::other("snell key derivation setup failed"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut key)
        .map_err(|_| io::Error::other("snell key derivation failed"))?;
    Ok(key)
}

/// One direction's AEAD. The nonce is a little-endian counter in the first
/// 8 bytes, bumped on every seal and open.
pub(crate) struct Cipher {
    key: LessSafeKey,
    counter: u64,
}

impl Cipher {
    pub(crate) fn new(kind: CipherKind, psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        Self::from_key(kind, &derive_key(psk, salt)?)
    }

    pub(crate) fn from_key(kind: CipherKind, key: &[u8; 32]) -> io::Result<Self> {
        let (algorithm, len) = match kind {
            CipherKind::Aes128Gcm => (&aead::AES_128_GCM, 16),
            CipherKind::ChaCha20Poly1305 => (&aead::CHACHA20_POLY1305, 32),
        };
        let unbound = UnboundKey::new(algorithm, &key[..len])
            .map_err(|_| io::Error::other("snell session key setup failed"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            counter: 0,
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        Nonce::assume_unique_for_key(nonce)
    }

    /// Appends `seal(plaintext) || tag` to `out`.
    pub(crate) fn seal_into(
        &mut self,
        out: &mut Vec<u8>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plaintext);
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut out[start..])
            .map_err(|_| io::Error::other("snell encryption failed"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Decrypts `buf` (ciphertext followed by the tag) in place and returns
    /// the plaintext length.
    pub(crate) fn open_in_place(&mut self, buf: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|_| invalid_data("snell authentication failed"))?;
        Ok(plain.len())
    }
}

pub(crate) fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| io::Error::other("system random source failed"))
}

pub(crate) fn random_u32() -> io::Result<u32> {
    let mut raw = [0u8; 4];
    fill_random(&mut raw)?;
    Ok(u32::from_le_bytes(raw))
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_counter_is_little_endian_and_seal_open_round_trips() {
        let key = derive_key(b"test-psk", &[7u8; SALT_LEN]).unwrap();
        for kind in [CipherKind::Aes128Gcm, CipherKind::ChaCha20Poly1305] {
            let mut sealer = Cipher::from_key(kind, &key).unwrap();
            let mut opener = Cipher::from_key(kind, &key).unwrap();
            sealer.counter = 0xff;
            opener.counter = 0xff;
            let mut out = Vec::new();
            sealer.seal_into(&mut out, b"hello", b"aad").unwrap();
            assert_eq!(sealer.counter, 0x100);
            assert_eq!(out.len(), 5 + TAG_LEN);
            let n = opener.open_in_place(&mut out, b"aad").unwrap();
            assert_eq!(&out[..n], b"hello");
            let mut wrong = Vec::new();
            sealer.seal_into(&mut wrong, b"x", b"").unwrap();
            assert!(opener.open_in_place(&mut wrong, b"other").is_err());
        }
    }

    #[test]
    fn key_derivation_depends_on_psk_and_salt() {
        let a = derive_key(b"psk", &[1u8; SALT_LEN]).unwrap();
        assert_eq!(a, derive_key(b"psk", &[1u8; SALT_LEN]).unwrap());
        assert_ne!(a, derive_key(b"psk2", &[1u8; SALT_LEN]).unwrap());
        assert_ne!(a, derive_key(b"psk", &[2u8; SALT_LEN]).unwrap());
    }
}
