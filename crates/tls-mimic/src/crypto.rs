//! TLS 1.3 key schedule and record protection primitives (RFC 8446 §7).

use std::io;

use ring::{aead, digest, hmac};

/// TLS 1.3 cipher suites this client can negotiate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn id(self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::Aes256GcmSha384 => 0x1302,
            CipherSuite::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn hash(self) -> HashAlg {
        match self {
            CipherSuite::Aes256GcmSha384 => HashAlg::Sha384,
            _ => HashAlg::Sha256,
        }
    }

    fn aead_algorithm(self) -> &'static aead::Algorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => &aead::AES_128_GCM,
            CipherSuite::Aes256GcmSha384 => &aead::AES_256_GCM,
            CipherSuite::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    pub fn key_len(self) -> usize {
        self.aead_algorithm().key_len()
    }
}

/// Hash used by the HKDF key schedule and the transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    fn digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            HashAlg::Sha256 => &digest::SHA256,
            HashAlg::Sha384 => &digest::SHA384,
        }
    }

    pub(crate) fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            HashAlg::Sha256 => hmac::HMAC_SHA256,
            HashAlg::Sha384 => hmac::HMAC_SHA384,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        digest::digest(self.digest_algorithm(), data)
            .as_ref()
            .to_vec()
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(self.hmac_algorithm(), key);
        hmac::sign(&key, data).as_ref().to_vec()
    }

    /// HKDF-Extract (RFC 5869). An empty salt means `HashLen` zero bytes.
    pub fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        if salt.is_empty() {
            self.hmac(&vec![0u8; self.output_len()], ikm)
        } else {
            self.hmac(salt, ikm)
        }
    }

    /// HKDF-Expand (RFC 5869).
    pub fn hkdf_expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut block: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while out.len() < len {
            let mut input = Vec::with_capacity(block.len() + info.len() + 1);
            input.extend_from_slice(&block);
            input.extend_from_slice(info);
            input.push(counter);
            block = self.hmac(prk, &input);
            out.extend_from_slice(&block);
            counter = counter.wrapping_add(1);
        }
        out.truncate(len);
        out
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1).
    pub fn expand_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let full_label_len = 6 + label.len();
        let mut info = Vec::with_capacity(4 + full_label_len + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full_label_len as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.hkdf_expand(secret, &info, len)
    }

    /// Derive-Secret (RFC 8446 §7.1) with an already computed transcript hash.
    pub fn derive_secret(self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.output_len())
    }
}

/// AEAD protection for one direction of TLS 1.3 records.
pub struct RecordCipher {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

pub(crate) const MAX_PLAINTEXT: usize = 16 * 1024;
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

impl RecordCipher {
    pub fn new(suite: CipherSuite, traffic_secret: &[u8]) -> io::Result<Self> {
        let hash = suite.hash();
        let key = hash.expand_label(traffic_secret, "key", &[], suite.key_len());
        let iv_bytes = hash.expand_label(traffic_secret, "iv", &[], 12);
        let unbound = aead::UnboundKey::new(suite.aead_algorithm(), &key)
            .map_err(|_| invalid_data("invalid TLS traffic key"))?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            iv,
            seq: 0,
        })
    }

    fn next_nonce(&mut self) -> io::Result<aead::Nonce> {
        let mut nonce = self.iv;
        for (slot, byte) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *slot ^= byte;
        }
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| invalid_data("TLS record sequence number exhausted"))?;
        Ok(aead::Nonce::assume_unique_for_key(nonce))
    }

    /// Encrypts one record (`content_type` is the inner type) and appends the
    /// complete wire record to `out`.
    pub fn seal(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(invalid_data("TLS record plaintext too large"));
        }
        let tag_len = self.key.algorithm().tag_len();
        let mut inner = Vec::with_capacity(plaintext.len() + 1 + tag_len);
        inner.extend_from_slice(plaintext);
        inner.push(content_type);
        let len = inner.len() + tag_len;
        let header = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let nonce = self.next_nonce()?;
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(header), &mut inner)
            .map_err(|_| invalid_data("TLS record encryption failed"))?;
        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        Ok(())
    }

    /// Decrypts `payload` in place (record header given separately) and
    /// returns the inner content type; `payload` is truncated to the content.
    pub fn open(&mut self, header: &[u8; 5], payload: &mut Vec<u8>) -> io::Result<u8> {
        let nonce = self.next_nonce()?;
        let plain_len = self
            .key
            .open_in_place(nonce, aead::Aad::from(*header), payload.as_mut_slice())
            .map_err(|_| invalid_data("TLS record authentication failed"))?
            .len();
        payload.truncate(plain_len);
        while let Some(&last) = payload.last() {
            if last != 0 {
                break;
            }
            payload.pop();
        }
        payload
            .pop()
            .ok_or_else(|| invalid_data("TLS record without content type"))
    }
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| io::Error::other("system random generator failed"))
}

pub(crate) fn random_u32() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}
