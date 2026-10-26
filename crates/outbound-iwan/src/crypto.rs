//! The password block (spec §4.2) and the XOR mask (spec §6.2). Neither is
//! real encryption; see spec §9.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use md5::{Digest, Md5};

/// Password bytes carried in the OPEN password TLV.
pub const PASSWORD_BLOCK: usize = 16;
/// Length of the XOR key.
pub const XOR_KEY_LEN: usize = 8;

/// MD5 over the concatenation of `parts`.
pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// `AES-128-ECB(MD5("mw" ‖ username), password truncated or zero-padded to 16 bytes)`.
pub fn encrypt_password(username: &[u8], password: &[u8]) -> [u8; PASSWORD_BLOCK] {
    let key = md5(&[b"mw", username]);
    let mut plain = [0u8; PASSWORD_BLOCK];
    let len = password.len().min(PASSWORD_BLOCK);
    plain[..len].copy_from_slice(&password[..len]);
    let cipher = Aes128::new_from_slice(&key).expect("16-byte key");
    let plain = Block::from(plain);
    let mut sealed = Block::from([0u8; PASSWORD_BLOCK]);
    cipher.encrypt_block_b2b(&plain, &mut sealed);
    let mut out = [0u8; PASSWORD_BLOCK];
    out.copy_from_slice(&sealed);
    out
}

/// The data-plane mask: the first 8 bytes of `MD5(username ‖ password)`, with
/// the full password.
#[derive(Clone)]
pub struct XorKey([u8; XOR_KEY_LEN]);

impl XorKey {
    pub fn new(username: &[u8], password: &[u8]) -> Self {
        let digest = md5(&[username, password]);
        let mut key = [0u8; XOR_KEY_LEN];
        key.copy_from_slice(&digest[..XOR_KEY_LEN]);
        Self(key)
    }

    /// Masks or unmasks `data` in place; the key restarts at every packet.
    pub fn apply(&self, data: &mut [u8]) {
        for (index, byte) in data.iter_mut().enumerate() {
            *byte ^= self.0[index % XOR_KEY_LEN];
        }
    }

    pub fn bytes(&self) -> [u8; XOR_KEY_LEN] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn password_block_matches_aes_ecb_vector() {
        // AES-128-ECB with key MD5("mwalice") = 5acd89bb480d20049e8748818c912b47.
        assert_eq!(
            hex(&encrypt_password(b"alice", b"secret")),
            "567e3c4f58d08532529f8191a0ae0d9d"
        );
    }

    #[test]
    fn long_password_is_truncated_to_one_block() {
        assert_eq!(
            encrypt_password(b"alice", b"0123456789abcdefXYZ"),
            encrypt_password(b"alice", b"0123456789abcdef")
        );
        assert_eq!(
            hex(&encrypt_password(b"alice", b"0123456789abcdef")),
            "709f4b1bd3fcfb3adf0ae94445fd5e6a"
        );
    }

    #[test]
    fn xor_key_is_md5_prefix_and_restarts_per_packet() {
        let key = XorKey::new(b"alice", b"secret");
        assert_eq!(hex(&key.bytes()), "c4e31313222cf05f");
        let mut data = [0u8; 10];
        key.apply(&mut data);
        assert_eq!(hex(&data), "c4e31313222cf05fc4e3");
        key.apply(&mut data);
        assert_eq!(data, [0u8; 10]);
    }
}
