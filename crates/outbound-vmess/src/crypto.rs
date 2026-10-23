//! VMess AEAD primitives: the nested-HMAC KDF, AuthID, the sealed request
//! header, the response header keys, and the chunk size mask.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use md5::{Digest as _, Md5};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

pub const KDF_SALT: &[u8] = b"VMess AEAD KDF";
pub const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
pub const HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub const HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
pub const HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
pub const HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";
pub const RESPONSE_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const RESPONSE_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const RESPONSE_KEY: &[u8] = b"AEAD Resp Header Key";
pub const RESPONSE_IV: &[u8] = b"AEAD Resp Header IV";

const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const HMAC_BLOCK: usize = 64;

/// `MD5(uuid || "c48619fe-...")`, the per-user key.
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_16(&[uuid.as_slice(), CMD_KEY_SALT].concat())
}

fn md5_16(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Md5::digest(data));
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// `KDF(key, path...)`: HMAC-SHA256 keyed with "VMess AEAD KDF", then one
/// more HMAC layer per path element, each using the previous layer as its
/// hash function; the innermost input is `key`.
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    layer(path.len(), path, key)
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// The hash function of layer `level` applied to `data`. Layer 0 is
/// HMAC-SHA256 with the fixed salt; layer `n` is HMAC with layer `n - 1` as
/// the hash and `path[n - 1]` as the key.
fn layer(level: usize, path: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if level == 0 {
        return hmac_with(KDF_SALT, data, sha256);
    }
    hmac_with(path[level - 1], data, |input| layer(level - 1, path, input))
}

/// RFC 2104 HMAC over a 64-byte-block hash `hash`.
fn hmac_with(key: &[u8], data: &[u8], hash: impl Fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    let mut block = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        block[..32].copy_from_slice(&hash(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK + data.len());
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(data);
    let inner_digest = hash(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK + 32);
    outer.extend(block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_digest);
    hash(&outer)
}

/// `AES-128(KDF16(cmd_key, "AES Auth ID Encryption"), time || random || crc32)`.
pub fn auth_id(cmd_key: &[u8; 16], unix_time: u64, random: [u8; 4]) -> [u8; 16] {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_time.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let crc = crc32fast::hash(&plain[..12]);
    plain[12..].copy_from_slice(&crc.to_be_bytes());
    let key = kdf16(cmd_key, &[AUTH_ID_KEY]);
    let cipher = Aes128::new_from_slice(&key).expect("16-byte key");
    let plain = Block::from(plain);
    let mut sealed = Block::from([0u8; 16]);
    cipher.encrypt_block_b2b(&plain, &mut sealed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&sealed);
    out
}

pub fn seal_aes_gcm(key: &[u8; 16], nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) {
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).expect("16-byte key"));
    let nonce = Nonce::try_assume_unique_for_key(&nonce[..12]).expect("12-byte nonce");
    key.seal_in_place_append_tag(nonce, Aad::from(aad), data)
        .expect("AES-GCM sealing does not fail for these sizes");
}

/// Opens `data` (ciphertext and tag) in place; returns the plaintext length.
pub fn open_aes_gcm(key: &[u8; 16], nonce: &[u8], data: &mut [u8]) -> Option<usize> {
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(&nonce[..12]).ok()?;
    key.open_in_place(nonce, Aad::empty(), data)
        .ok()
        .map(|plain| plain.len())
}

/// `authid || seal(len) || connection nonce || seal(header)`.
pub fn seal_request_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    header: &[u8],
) -> Vec<u8> {
    let path = |label: &'static [u8]| -> [&[u8]; 3] { [label, auth_id, connection_nonce] };
    let mut length = (header.len() as u16).to_be_bytes().to_vec();
    seal_aes_gcm(
        &kdf16(cmd_key, &path(HEADER_LENGTH_KEY)),
        &kdf(cmd_key, &path(HEADER_LENGTH_NONCE)),
        auth_id,
        &mut length,
    );
    let mut sealed_header = header.to_vec();
    seal_aes_gcm(
        &kdf16(cmd_key, &path(HEADER_KEY)),
        &kdf(cmd_key, &path(HEADER_NONCE)),
        auth_id,
        &mut sealed_header,
    );
    let mut out = Vec::with_capacity(16 + length.len() + 8 + sealed_header.len());
    out.extend_from_slice(auth_id);
    out.extend_from_slice(&length);
    out.extend_from_slice(connection_nonce);
    out.extend_from_slice(&sealed_header);
    out
}

/// FNV-1a 32-bit, the request header checksum.
pub fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

/// `MD5(key) || MD5(MD5(key))`, the ChaCha20-Poly1305 body key.
pub fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5_16(key);
    let second = md5_16(&first);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

/// The first 16 bytes of SHA-256, used to derive response keys and IVs.
pub fn sha256_16(data: &[u8; 16]) -> [u8; 16] {
    let digest = sha256(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// SHAKE128 stream seeded with a body IV; each chunk length is XORed with
/// its next two bytes (option `ChunkMasking`).
pub struct SizeMask {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

impl SizeMask {
    pub fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    pub fn next_mask(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}
