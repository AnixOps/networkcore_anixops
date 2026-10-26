//! Keys, nonces and the AEAD (spec §1–§2).

use std::io;
use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use ring::digest::{digest, Context, SHA256};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Bytes of the first nonce that are printable ASCII (§2).
const PRINTABLE_NONCE_PREFIX: usize = 12;
const PBKDF2_ITERATIONS: u32 = 64;
/// Key time slot, seconds.
const TIME_SLOT: u64 = 120;

pub(crate) fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| io::Error::other("system random source failed"))
}

pub(crate) fn random_u32() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Overwrites `buf` with random printable ASCII (0x20..=0x7e).
pub(crate) fn fill_printable(buf: &mut [u8]) -> io::Result<()> {
    fill_random(buf)?;
    for byte in buf.iter_mut() {
        *byte = 0x20 + *byte % 95;
    }
    Ok(())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// `SHA-256(password || 0x00 || username)`.
pub fn hashed_password(username: &[u8], password: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(password);
    context.update(&[0]);
    context.update(username);
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

/// `unix_secs` rounded to the nearest multiple of 120.
pub fn rounded_time(unix_secs: u64) -> u64 {
    (unix_secs + TIME_SLOT / 2) / TIME_SLOT * TIME_SLOT
}

/// The key for an already rounded time slot.
pub fn slot_key(hashed: &[u8; 32], slot: u64) -> [u8; KEY_LEN] {
    let salt = digest(&SHA256, &slot.to_be_bytes());
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).expect("non-zero iterations"),
        salt.as_ref(),
        hashed,
        &mut key,
    );
    key
}

/// The key a sender uses at `unix_secs`.
pub fn derive_key(hashed: &[u8; 32], unix_secs: u64) -> [u8; KEY_LEN] {
    slot_key(hashed, rounded_time(unix_secs))
}

/// The keys a receiver tries at `unix_secs`: current slot first, then the
/// previous and the next one.
pub fn candidate_keys(hashed: &[u8; 32], unix_secs: u64) -> [[u8; KEY_LEN]; 3] {
    let slot = rounded_time(unix_secs);
    [
        slot_key(hashed, slot),
        slot_key(hashed, slot.saturating_sub(TIME_SLOT)),
        slot_key(hashed, slot + TIME_SLOT),
    ]
}

/// First 4 bytes of `SHA-256(username || nonce[0..16])`.
pub fn user_hint(username: &[u8], nonce: &[u8; NONCE_LEN]) -> [u8; 4] {
    let mut context = Context::new(&SHA256);
    context.update(username);
    context.update(&nonce[..16]);
    let mut hint = [0u8; 4];
    hint.copy_from_slice(&context.finish().as_ref()[..4]);
    hint
}

/// A fresh first nonce: printable prefix, random middle, user hint.
pub fn new_nonce(username: &[u8]) -> io::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce[PRINTABLE_NONCE_PREFIX..20])?;
    fill_printable(&mut nonce[..PRINTABLE_NONCE_PREFIX])?;
    let hint = user_hint(username, &nonce);
    nonce[20..].copy_from_slice(&hint);
    Ok(nonce)
}

/// Adds 1 to the nonce as one 24-byte big-endian integer.
pub fn increment(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
}

/// One direction's AEAD state: every seal or open uses the current nonce and
/// then increments it.
pub struct Cipher {
    aead: XChaCha20Poly1305,
    nonce: [u8; NONCE_LEN],
}

impl Cipher {
    pub fn new(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            aead: XChaCha20Poly1305::new(Key::from_slice(key)),
            nonce,
        }
    }

    /// Appends `seal(plain)` (ciphertext and tag) to `out`.
    pub fn seal_into(&mut self, out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = self
            .aead
            .encrypt_in_place_detached(XNonce::from_slice(&self.nonce), &[], &mut out[start..])
            .map_err(|_| io::Error::other("mieru encryption failed"))?;
        out.extend_from_slice(&tag);
        increment(&mut self.nonce);
        Ok(())
    }

    /// Opens `sealed` (ciphertext followed by its tag) in place and returns
    /// the plaintext length. The nonce advances only on success.
    pub fn open_in_place(&mut self, sealed: &mut [u8]) -> io::Result<usize> {
        if sealed.len() < TAG_LEN {
            return Err(invalid_data("mieru segment is too short"));
        }
        let length = sealed.len() - TAG_LEN;
        let (body, tag) = sealed.split_at_mut(length);
        self.aead
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                &[],
                body,
                Tag::from_slice(tag),
            )
            .map_err(|_| invalid_data("mieru segment failed authentication"))?;
        increment(&mut self.nonce);
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_to_the_nearest_two_minutes() {
        assert_eq!(rounded_time(1_792_986_120), 1_792_986_120);
        assert_eq!(rounded_time(1_792_986_179), 1_792_986_120);
        assert_eq!(rounded_time(1_792_986_180), 1_792_986_240);
        assert_eq!(rounded_time(59), 0);
    }

    #[test]
    fn increments_the_whole_nonce_big_endian() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[23] = 0xff;
        nonce[22] = 0xff;
        increment(&mut nonce);
        assert_eq!(nonce[21..], [1, 0, 0]);
        let mut all = [0xffu8; NONCE_LEN];
        increment(&mut all);
        assert_eq!(all, [0u8; NONCE_LEN]);
    }

    #[test]
    fn new_nonce_is_printable_and_carries_the_user_hint() {
        let nonce = new_nonce(b"alice").unwrap();
        assert!(nonce[..12].iter().all(|byte| (0x20..=0x7e).contains(byte)));
        assert_eq!(nonce[20..], user_hint(b"alice", &nonce));
        assert_ne!(nonce[20..], user_hint(b"bob", &nonce));
    }

    #[test]
    fn seal_and_open_advance_the_same_nonce_sequence() {
        let hashed = hashed_password(b"alice", b"secret");
        let key = derive_key(&hashed, 1_792_986_100);
        assert_eq!(key, candidate_keys(&hashed, 1_792_986_130)[0]);
        let nonce = new_nonce(b"alice").unwrap();
        let mut sender = Cipher::new(&key, nonce);
        let mut receiver = Cipher::new(&key, nonce);
        let mut wire = Vec::new();
        sender.seal_into(&mut wire, b"first").unwrap();
        sender.seal_into(&mut wire, b"second").unwrap();
        let (first, second) = wire.split_at_mut(5 + TAG_LEN);
        assert_eq!(receiver.open_in_place(first).unwrap(), 5);
        assert_eq!(&first[..5], b"first");
        assert_eq!(receiver.open_in_place(second).unwrap(), 6);
        assert_eq!(&second[..6], b"second");

        let mut other = Cipher::new(&derive_key(&hashed, 1_792_986_300), nonce);
        let mut again = Vec::new();
        Cipher::new(&key, nonce)
            .seal_into(&mut again, b"first")
            .unwrap();
        assert!(other.open_in_place(&mut again).is_err());
    }
}
