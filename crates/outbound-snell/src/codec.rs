//! Frame encoder and decoder for every Snell framing (spec §5–§7).
//!
//! Both are sans-IO and direction-agnostic: a client encodes its upstream
//! and decodes the server's downstream with the same types a server uses the
//! other way round. Each direction has its own salt, key, nonce, sequence
//! number and shaping state, so one connection holds one [`Encoder`] and one
//! [`Decoder`].

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::{
    derive_key, fill_random, invalid_data, invalid_input, random_u32, Cipher, CipherKind, SALT_LEN,
    TAG_LEN,
};
use crate::profile::{Profile, SenderState};

/// Largest payload of one v1–v5 frame.
pub const MAX_LEGACY_PAYLOAD: usize = 0x3FFF;
/// Largest payload of one v6 frame.
pub const MAX_V6_PAYLOAD: usize = 0xFFFF;

const FRAME_HEADER_LEN: usize = 7;
const FRAME_VERSION: u8 = 0x04;

/// v4 shaping constants (§6.2).
const V4_FRAME: usize = 1460;
const V4_FIRST_OVERHEAD: usize = 55;
const V4_OVERHEAD: usize = 39;
const V4_GROWTH: usize = 1421;
const V4_IDLE_RESET: Duration = Duration::from_secs(31);

/// v6 `mode` (§7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6Mode {
    Default,
    Unshaped,
    UnsafeRaw,
}

impl V6Mode {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "default" => Some(V6Mode::Default),
            "unshaped" => Some(V6Mode::Unshaped),
            "unsafe-raw" => Some(V6Mode::UnsafeRaw),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            V6Mode::Default => "default",
            V6Mode::Unshaped => "unshaped",
            V6Mode::UnsafeRaw => "unsafe-raw",
        }
    }
}

/// How one direction of a connection is framed.
#[derive(Clone, Debug)]
pub enum Framing {
    /// v1–v3: length-prefixed AEAD chunks.
    Legacy(CipherKind),
    /// v1–v3 server side: the first frame decides between AES-128-GCM and
    /// ChaCha20-Poly1305. Decoder only.
    LegacyAuto,
    /// v4 and v5: header frames with first-frame padding.
    V4,
    /// v6 `default`: profile-shaped frames.
    V6Default(Arc<Profile>),
    /// v6 `unshaped`.
    V6Unshaped,
    /// v6 `unsafe-raw`: no encryption.
    V6UnsafeRaw,
}

impl Framing {
    /// Framing of protocol `version` (1–6; 5 is framed like 4).
    pub fn for_version(version: u8, mode: V6Mode, psk: &[u8]) -> io::Result<Self> {
        Ok(match version {
            1 => Framing::Legacy(CipherKind::ChaCha20Poly1305),
            2 | 3 => Framing::Legacy(CipherKind::Aes128Gcm),
            4 | 5 => Framing::V4,
            6 => match mode {
                V6Mode::Default => Framing::V6Default(Arc::new(Profile::new(psk))),
                V6Mode::Unshaped => Framing::V6Unshaped,
                V6Mode::UnsafeRaw => Framing::V6UnsafeRaw,
            },
            _ => return Err(invalid_input("snell version must be between 1 and 6")),
        })
    }

    /// Largest payload one frame can carry.
    pub fn max_payload(&self) -> usize {
        match self {
            Framing::Legacy(_) | Framing::LegacyAuto | Framing::V4 => MAX_LEGACY_PAYLOAD,
            Framing::V6Default(_) | Framing::V6Unshaped | Framing::V6UnsafeRaw => MAX_V6_PAYLOAD,
        }
    }

    fn cipher_kind(&self) -> Option<CipherKind> {
        match self {
            Framing::Legacy(kind) => Some(*kind),
            Framing::V4 | Framing::V6Default(_) | Framing::V6Unshaped => {
                Some(CipherKind::Aes128Gcm)
            }
            Framing::LegacyAuto | Framing::V6UnsafeRaw => None,
        }
    }
}

/// One decoded frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Data(Vec<u8>),
    /// A zero chunk: end of the current request in this direction.
    Zero,
}

/// Encodes one direction. The salt (or salt block) goes in front of the
/// first frame.
pub struct Encoder {
    framing: Framing,
    cipher: Option<Cipher>,
    salt: [u8; SALT_LEN],
    started: bool,
    last_write: Option<Instant>,
    /// v4: first-frame padding length and the next call's payload limit.
    pad0: usize,
    v4_limit: Option<usize>,
    /// v6 default: frame sequence number and frame sizing.
    seq: u64,
    sizing: SenderState,
}

impl Encoder {
    pub fn new(framing: Framing, psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let cipher = match &framing {
            Framing::LegacyAuto => {
                return Err(invalid_input(
                    "snell encoder needs a concrete cipher, not auto-detection",
                ))
            }
            framing => match framing.cipher_kind() {
                Some(kind) => Some(Cipher::new(kind, psk, &salt)?),
                None => None,
            },
        };
        let pad0 = 256 + (random_u32()? % 256) as usize;
        Ok(Self {
            framing,
            cipher,
            salt,
            started: false,
            last_write: None,
            pad0,
            v4_limit: None,
            seq: 0,
            sizing: SenderState::default(),
        })
    }

    pub fn framing(&self) -> &Framing {
        &self.framing
    }

    /// Encodes one application write, split into frames as the framing's
    /// shaping rules say. An empty `data` writes nothing.
    pub fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self.framing.clone() {
            Framing::Legacy(_) => {
                for chunk in data.chunks(MAX_LEGACY_PAYLOAD) {
                    self.legacy_frame(out, chunk)?;
                }
            }
            Framing::V4 => {
                let limit = self.v4_limit();
                for chunk in data.chunks(limit) {
                    self.v4_frame(out, chunk)?;
                }
            }
            Framing::V6Default(profile) => {
                let mut rest = data;
                while !rest.is_empty() {
                    let limit = self.v6_limit(&profile);
                    let (chunk, tail) = rest.split_at(limit.min(rest.len()));
                    self.v6_default_frame(out, &profile, chunk)?;
                    rest = tail;
                }
            }
            Framing::V6Unshaped | Framing::V6UnsafeRaw => {
                for chunk in data.chunks(MAX_V6_PAYLOAD) {
                    self.v6_plain_frame(out, chunk)?;
                }
            }
            Framing::LegacyAuto => unreachable!("rejected in Encoder::new"),
        }
        Ok(())
    }

    /// Encodes `data` as exactly one frame (a UDP request or datagram).
    pub fn encode_single(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        if data.is_empty() || data.len() > self.framing.max_payload() {
            return Err(invalid_input("snell frame payload size is out of range"));
        }
        self.encode_one(out, data)
    }

    /// Writes a zero chunk: the end of the current request in this direction.
    pub fn encode_zero(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.encode_one(out, &[])
    }

    fn encode_one(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        match self.framing.clone() {
            Framing::Legacy(_) => self.legacy_frame(out, data),
            Framing::V4 => {
                self.v4_limit();
                self.v4_frame(out, data)
            }
            Framing::V6Default(profile) => {
                self.v6_limit(&profile);
                self.v6_default_frame(out, &profile, data)
            }
            Framing::V6Unshaped | Framing::V6UnsafeRaw => self.v6_plain_frame(out, data),
            Framing::LegacyAuto => unreachable!("rejected in Encoder::new"),
        }
    }

    fn cipher(&mut self) -> io::Result<&mut Cipher> {
        self.cipher
            .as_mut()
            .ok_or_else(|| io::Error::other("snell encoder has no cipher"))
    }

    /// Writes the salt in front of the first frame.
    fn start(&mut self, out: &mut Vec<u8>) {
        if !self.started {
            self.started = true;
            if self.cipher.is_some() && !matches!(self.framing, Framing::V6Default(_)) {
                out.extend_from_slice(&self.salt);
            }
        }
    }

    fn legacy_frame(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        self.start(out);
        let cipher = self.cipher()?;
        cipher.seal_into(out, &(payload.len() as u16).to_be_bytes(), &[])?;
        if !payload.is_empty() {
            cipher.seal_into(out, payload, &[])?;
        }
        Ok(())
    }

    /// Payload limit for one v4 application write (§6.2).
    fn v4_limit(&mut self) -> usize {
        let now = Instant::now();
        let recent = self
            .last_write
            .is_some_and(|last| now.duration_since(last) < V4_IDLE_RESET);
        let limit = if !self.started {
            V4_FRAME - V4_FIRST_OVERHEAD - self.pad0
        } else {
            match self.v4_limit {
                Some(limit) if recent => limit,
                _ => V4_FRAME - V4_OVERHEAD,
            }
        };
        self.v4_limit = Some((limit + V4_GROWTH).min(MAX_LEGACY_PAYLOAD));
        self.last_write = Some(now);
        limit
    }

    fn v4_frame(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        let first = !self.started;
        self.start(out);
        let padding_len = if first && !payload.is_empty() {
            self.pad0
        } else {
            0
        };
        let header = frame_header(padding_len, payload.len());
        let cipher = self.cipher()?;
        cipher.seal_into(out, &header, &[])?;
        if payload.is_empty() {
            return Ok(());
        }
        let mut ciphertext = Vec::with_capacity(payload.len() + TAG_LEN);
        cipher.seal_into(&mut ciphertext, payload, &[])?;
        if padding_len > 0 {
            let mut padding = balanced_padding(&ciphertext, padding_len)?;
            interleave(&mut padding, &mut ciphertext);
            out.extend_from_slice(&padding);
        }
        out.extend_from_slice(&ciphertext);
        Ok(())
    }

    fn v6_limit(&mut self, profile: &Profile) -> usize {
        let now = Instant::now();
        let idle = self.last_write.is_none_or(|last| {
            now.duration_since(last) > Duration::from_secs(profile.idle_reset_secs())
        });
        self.last_write = Some(now);
        profile.next_limit(&mut self.sizing, self.seq, idle)
    }

    fn v6_default_frame(
        &mut self,
        out: &mut Vec<u8>,
        profile: &Profile,
        payload: &[u8],
    ) -> io::Result<()> {
        let seq = self.seq;
        let first = !self.started;
        self.started = true;
        if first {
            out.extend_from_slice(&profile.salt_block(&self.salt));
        }
        let prefix_len = profile.prefix_len(seq);
        let prefix = profile.fill(seq, prefix_len);
        out.extend_from_slice(&prefix);
        let padding_len = profile.padding_len(seq, payload.len(), prefix_len, first);
        let header = frame_header(padding_len, payload.len());
        let mut padding = profile.fill(seq, padding_len);
        let cipher = self.cipher()?;
        cipher.seal_into(out, &header, &prefix)?;
        if payload.is_empty() {
            out.extend_from_slice(&padding);
        } else {
            let mut ciphertext = Vec::with_capacity(payload.len() + TAG_LEN);
            cipher.seal_into(&mut ciphertext, payload, &padding)?;
            profile.mix(seq, &mut padding, &mut ciphertext);
            out.extend_from_slice(&padding);
            out.extend_from_slice(&ciphertext);
        }
        self.seq += 1;
        Ok(())
    }

    /// v6 `unshaped` and `unsafe-raw` frames.
    fn v6_plain_frame(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        self.start(out);
        let header = frame_header(0, payload.len());
        match self.cipher.as_mut() {
            Some(cipher) => {
                cipher.seal_into(out, &header, &[])?;
                if !payload.is_empty() {
                    cipher.seal_into(out, payload, &[])?;
                }
            }
            None => {
                out.extend_from_slice(&header);
                out.extend_from_slice(payload);
            }
        }
        Ok(())
    }
}

fn frame_header(padding_len: usize, payload_len: usize) -> [u8; FRAME_HEADER_LEN] {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = FRAME_VERSION;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header
}

/// Swaps the even-indexed bytes of v4 padding and ciphertext (§6.1). Running
/// it twice restores both.
fn interleave(padding: &mut [u8], ciphertext: &mut [u8]) {
    let n = padding.len().min(ciphertext.len());
    for i in (0..n).step_by(2) {
        std::mem::swap(&mut padding[i], &mut ciphertext[i]);
    }
}

/// v4 first-frame padding that skews the packet's bit balance (§6.2).
fn balanced_padding(ciphertext: &[u8], len: usize) -> io::Result<Vec<u8>> {
    let mut random = vec![0u8; len];
    fill_random(&mut random)?;
    let counted = ciphertext.len() / 4 * 4;
    let ones: i64 = ciphertext[..counted]
        .iter()
        .map(|byte| i64::from(byte.count_ones()))
        .sum();
    let zeros = 8 * ciphertext.len() as i64 - ones;
    if zeros <= 0 {
        return Ok(random);
    }
    let ratio = ones as f64 / zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return Ok(random);
    }
    let r = f64::from(random_u32()?) / 4_294_967_296.0;
    let base = if zeros >= ones { 1.6 } else { 0.4 };
    let target = base + r / 10.0;
    let total_bits = (8 * (len + ciphertext.len())) as f64;
    let wanted = (total_bits * target / (target + 1.0)).floor() as i64 - ones;
    let bits = 8 * len;
    if !(0..=bits as i64).contains(&wanted) {
        return Ok(random);
    }
    // Exactly `wanted` one bits, shuffled uniformly over the padding.
    let mut positions: Vec<bool> = (0..bits).map(|i| (i as i64) < wanted).collect();
    let mut entropy = vec![0u8; 4 * bits];
    fill_random(&mut entropy)?;
    for i in (1..bits).rev() {
        let raw = u32::from_le_bytes([
            entropy[4 * i],
            entropy[4 * i + 1],
            entropy[4 * i + 2],
            entropy[4 * i + 3],
        ]);
        let j = raw as usize % (i + 1);
        positions.swap(i, j);
    }
    let mut padding = vec![0u8; len];
    for (bit, set) in positions.into_iter().enumerate() {
        if set {
            padding[bit / 8] |= 1 << (bit % 8);
        }
    }
    Ok(padding)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeState {
    Salt,
    /// Legacy: the sealed length. Others: the (prefix and) sealed header.
    Head,
    /// Padding and payload lengths read from the header.
    Body {
        padding: usize,
        payload: usize,
    },
}

/// Decodes one direction.
pub struct Decoder {
    framing: Framing,
    psk: Arc<[u8]>,
    cipher: Option<Cipher>,
    /// LegacyAuto: the second candidate until the first frame decides.
    fallback: Option<Cipher>,
    detected: Option<CipherKind>,
    state: DecodeState,
    seq: u64,
    buf: Vec<u8>,
    pos: usize,
}

impl Decoder {
    pub fn new(framing: Framing, psk: Arc<[u8]>) -> Self {
        let state = match framing {
            Framing::V6UnsafeRaw => DecodeState::Head,
            _ => DecodeState::Salt,
        };
        Self {
            framing,
            psk,
            cipher: None,
            fallback: None,
            detected: None,
            state,
            seq: 0,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// The framing the peer used: for [`Framing::LegacyAuto`], the detected
    /// cipher once the first frame is decoded.
    pub fn peer_framing(&self) -> Framing {
        match (&self.framing, self.detected) {
            (Framing::LegacyAuto, Some(kind)) => Framing::Legacy(kind),
            (framing, _) => framing.clone(),
        }
    }

    /// Whether the salt has arrived and been accepted.
    pub fn salt_received(&self) -> bool {
        self.state != DecodeState::Salt
    }

    /// Bytes received but not yet decoded.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn feed(&mut self, data: &[u8]) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 && self.pos * 2 > self.buf.len() {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next complete frame, or `None` when more input is needed.
    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        loop {
            let available = self.buf.len() - self.pos;
            match self.state {
                DecodeState::Salt => {
                    let need = match &self.framing {
                        Framing::V6Default(profile) => profile.salt_block_len(),
                        _ => SALT_LEN,
                    };
                    if available < need {
                        return Ok(None);
                    }
                    let unit = &self.buf[self.pos..self.pos + need];
                    let salt: [u8; SALT_LEN] = match &self.framing {
                        Framing::V6Default(profile) => profile.salt_from_block(unit),
                        _ => {
                            let mut salt = [0u8; SALT_LEN];
                            salt.copy_from_slice(unit);
                            salt
                        }
                    };
                    self.pos += need;
                    self.accept_salt(&salt)?;
                    self.state = DecodeState::Head;
                }
                DecodeState::Head => {
                    if !self.decode_head(available)? {
                        return Ok(None);
                    }
                }
                DecodeState::Body { padding, payload } => {
                    let need = padding
                        + if payload > 0 {
                            payload + self.tag_len()
                        } else {
                            0
                        };
                    if available < need {
                        return Ok(None);
                    }
                    let start = self.pos;
                    self.pos += need;
                    self.state = DecodeState::Head;
                    if payload == 0 {
                        // Padding of a v6 default zero chunk is discarded.
                        self.seq += 1;
                        return Ok(Some(Frame::Zero));
                    }
                    let frame = self.decode_body(start, padding, payload)?;
                    self.seq += 1;
                    return Ok(Some(Frame::Data(frame)));
                }
            }
        }
    }

    fn tag_len(&self) -> usize {
        match self.framing {
            Framing::V6UnsafeRaw => 0,
            _ => TAG_LEN,
        }
    }

    fn accept_salt(&mut self, salt: &[u8; SALT_LEN]) -> io::Result<()> {
        match &self.framing {
            Framing::LegacyAuto => {
                let key = derive_key(&self.psk, salt)?;
                self.cipher = Some(Cipher::from_key(CipherKind::Aes128Gcm, &key)?);
                self.fallback = Some(Cipher::from_key(CipherKind::ChaCha20Poly1305, &key)?);
            }
            framing => {
                if let Some(kind) = framing.cipher_kind() {
                    self.cipher = Some(Cipher::new(kind, &self.psk, salt)?);
                }
            }
        }
        Ok(())
    }

    fn cipher(&mut self) -> io::Result<&mut Cipher> {
        self.cipher
            .as_mut()
            .ok_or_else(|| io::Error::other("snell decoder has no cipher"))
    }

    /// Decodes a frame head. Returns `false` when more input is needed.
    fn decode_head(&mut self, available: usize) -> io::Result<bool> {
        match self.framing.clone() {
            Framing::Legacy(_) | Framing::LegacyAuto => {
                let need = 2 + TAG_LEN;
                if available < need {
                    return Ok(false);
                }
                let start = self.pos;
                let mut unit = [0u8; 2 + TAG_LEN];
                unit.copy_from_slice(&self.buf[start..start + need]);
                self.pos += need;
                self.open_legacy_length(&mut unit)?;
                let len = usize::from(u16::from_be_bytes([unit[0], unit[1]]));
                self.state = DecodeState::Body {
                    padding: 0,
                    payload: len,
                };
                Ok(true)
            }
            Framing::V4 | Framing::V6Unshaped | Framing::V6UnsafeRaw => {
                let need = FRAME_HEADER_LEN + self.tag_len();
                if available < need {
                    return Ok(false);
                }
                let start = self.pos;
                let mut unit = [0u8; FRAME_HEADER_LEN + TAG_LEN];
                unit[..need].copy_from_slice(&self.buf[start..start + need]);
                self.pos += need;
                if !matches!(self.framing, Framing::V6UnsafeRaw) {
                    self.cipher()?.open_in_place(&mut unit[..need], &[])?;
                }
                let (padding, payload) = parse_header(&unit[..FRAME_HEADER_LEN]);
                if !matches!(self.framing, Framing::V4)
                    && (padding != 0 || unit[1] != 0 || unit[2] != 0)
                {
                    return Err(invalid_data("snell frame header is invalid"));
                }
                if payload == 0 && padding != 0 {
                    return Err(invalid_data("snell zero chunk carries padding"));
                }
                self.state = DecodeState::Body { padding, payload };
                Ok(true)
            }
            Framing::V6Default(profile) => {
                let prefix_len = profile.prefix_len(self.seq);
                let need = prefix_len + FRAME_HEADER_LEN + TAG_LEN;
                if available < need {
                    return Ok(false);
                }
                let start = self.pos;
                let prefix = self.buf[start..start + prefix_len].to_vec();
                let mut unit = [0u8; FRAME_HEADER_LEN + TAG_LEN];
                unit.copy_from_slice(&self.buf[start + prefix_len..start + need]);
                self.pos += need;
                self.cipher()?.open_in_place(&mut unit, &prefix)?;
                let (padding, payload) = parse_header(&unit[..FRAME_HEADER_LEN]);
                self.state = DecodeState::Body { padding, payload };
                Ok(true)
            }
        }
    }

    /// Opens a v1–v3 length, choosing the cipher on the first frame for
    /// [`Framing::LegacyAuto`].
    fn open_legacy_length(&mut self, unit: &mut [u8; 2 + TAG_LEN]) -> io::Result<()> {
        let Some(mut fallback) = self.fallback.take() else {
            self.cipher()?.open_in_place(unit, &[])?;
            return Ok(());
        };
        let copy = *unit;
        if self.cipher()?.open_in_place(unit, &[]).is_ok() {
            self.detected = Some(CipherKind::Aes128Gcm);
            return Ok(());
        }
        *unit = copy;
        fallback.open_in_place(unit, &[])?;
        self.cipher = Some(fallback);
        self.detected = Some(CipherKind::ChaCha20Poly1305);
        Ok(())
    }

    fn decode_body(&mut self, start: usize, padding: usize, payload: usize) -> io::Result<Vec<u8>> {
        let tag = self.tag_len();
        let end = start + padding + payload + tag;
        let framing = self.framing.clone();
        let seq = self.seq;
        let mut pad = self.buf[start..start + padding].to_vec();
        let mut body = self.buf[start + padding..end].to_vec();
        match framing {
            Framing::V6UnsafeRaw => return Ok(body),
            Framing::V4 => interleave(&mut pad, &mut body),
            Framing::V6Default(profile) => profile.mix(seq, &mut pad, &mut body),
            _ => {}
        }
        let aad: &[u8] = match self.framing {
            Framing::V6Default(_) => &pad,
            _ => &[],
        };
        let aad = aad.to_vec();
        let n = self.cipher()?.open_in_place(&mut body, &aad)?;
        body.truncate(n);
        Ok(body)
    }
}

fn parse_header(header: &[u8]) -> (usize, usize) {
    let padding = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let payload = usize::from(u16::from_be_bytes([header[5], header[6]]));
    (padding, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &[u8] = b"codec test psk 0123";

    fn framings() -> Vec<Framing> {
        let mut all = Vec::new();
        for version in 1..=6 {
            for mode in [V6Mode::Default, V6Mode::Unshaped, V6Mode::UnsafeRaw] {
                if version < 6 && mode != V6Mode::Default {
                    continue;
                }
                all.push(Framing::for_version(version, mode, PSK).unwrap());
            }
        }
        all
    }

    /// Decodes everything in `wire`, feeding it in `step`-byte pieces.
    fn decode_all(decoder: &mut Decoder, wire: &[u8], step: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        for piece in wire.chunks(step) {
            decoder.feed(piece);
            while let Some(frame) = decoder.next_frame().unwrap() {
                frames.push(frame);
            }
        }
        assert_eq!(decoder.buffered(), 0);
        frames
    }

    fn joined(frames: &[Frame]) -> Vec<u8> {
        let mut data = Vec::new();
        for frame in frames {
            if let Frame::Data(chunk) = frame {
                data.extend_from_slice(chunk);
            }
        }
        data
    }

    #[test]
    fn every_framing_round_trips_writes_and_zero_chunks() {
        let big: Vec<u8> = (0..200_000).map(|i| (i * 31 % 251) as u8).collect();
        for framing in framings() {
            let mut encoder = Encoder::new(framing.clone(), PSK).unwrap();
            let mut wire = Vec::new();
            encoder.encode(&mut wire, b"first write").unwrap();
            encoder.encode(&mut wire, &big).unwrap();
            encoder.encode_zero(&mut wire).unwrap();
            encoder.encode(&mut wire, b"next request").unwrap();
            encoder.encode_zero(&mut wire).unwrap();
            for step in [1, 7, 1460, wire.len()] {
                let mut decoder = Decoder::new(framing.clone(), PSK.into());
                let frames = decode_all(&mut decoder, &wire, step);
                let zero = frames.iter().position(|f| *f == Frame::Zero).unwrap();
                let mut expected = b"first write".to_vec();
                expected.extend_from_slice(&big);
                assert_eq!(joined(&frames[..zero]), expected, "{framing:?}");
                assert_eq!(joined(&frames[zero + 1..]), b"next request");
                assert_eq!(frames.last(), Some(&Frame::Zero));
            }
        }
    }

    #[test]
    fn frames_respect_payload_limits() {
        for framing in framings() {
            let max = framing.max_payload();
            let mut encoder = Encoder::new(framing.clone(), PSK).unwrap();
            let mut wire = Vec::new();
            encoder.encode(&mut wire, &vec![7u8; 3 * max + 5]).unwrap();
            let mut decoder = Decoder::new(framing, PSK.into());
            for frame in decode_all(&mut decoder, &wire, wire.len()) {
                if let Frame::Data(chunk) = frame {
                    assert!(!chunk.is_empty() && chunk.len() <= max);
                }
            }
        }
    }

    #[test]
    fn v4_first_packet_fits_one_segment() {
        let mut encoder = Encoder::new(Framing::V4, PSK).unwrap();
        let mut wire = Vec::new();
        encoder.encode(&mut wire, &[1u8; 5000]).unwrap();
        let first_frame = SALT_LEN + FRAME_HEADER_LEN + TAG_LEN + encoder.pad0;
        let first_payload = V4_FRAME - V4_FIRST_OVERHEAD - encoder.pad0;
        assert_eq!(first_frame + first_payload + TAG_LEN, V4_FRAME);
        assert!((256..512).contains(&encoder.pad0));
    }

    #[test]
    fn single_frames_reject_oversized_payloads() {
        let mut encoder = Encoder::new(Framing::V4, PSK).unwrap();
        let mut out = Vec::new();
        assert!(encoder
            .encode_single(&mut out, &vec![0u8; MAX_LEGACY_PAYLOAD + 1])
            .is_err());
        assert!(encoder.encode_single(&mut out, &[]).is_err());
        encoder.encode_single(&mut out, &[0u8; 100]).unwrap();
    }

    #[test]
    fn legacy_auto_detects_v1_and_v2_clients() {
        for (version, kind) in [
            (1, CipherKind::ChaCha20Poly1305),
            (3, CipherKind::Aes128Gcm),
        ] {
            let framing = Framing::for_version(version, V6Mode::Default, PSK).unwrap();
            let mut encoder = Encoder::new(framing, PSK).unwrap();
            let mut wire = Vec::new();
            encoder.encode(&mut wire, b"hello").unwrap();
            let mut decoder = Decoder::new(Framing::LegacyAuto, PSK.into());
            decoder.feed(&wire);
            assert_eq!(
                decoder.next_frame().unwrap(),
                Some(Frame::Data(b"hello".to_vec()))
            );
            assert!(matches!(decoder.peer_framing(), Framing::Legacy(k) if k == kind));
        }
    }

    #[test]
    fn wrong_psk_fails_authentication() {
        for framing in framings() {
            if matches!(framing, Framing::V6UnsafeRaw | Framing::V6Default(_)) {
                continue;
            }
            let mut encoder = Encoder::new(framing.clone(), PSK).unwrap();
            let mut wire = Vec::new();
            encoder.encode(&mut wire, b"hello").unwrap();
            let mut decoder = Decoder::new(framing, Arc::from(&b"other psk"[..]));
            decoder.feed(&wire);
            assert!(decoder.next_frame().is_err());
        }
        // v6 default: the other PSK has another profile and key.
        let mut encoder =
            Encoder::new(Framing::for_version(6, V6Mode::Default, PSK).unwrap(), PSK).unwrap();
        let mut wire = Vec::new();
        encoder.encode(&mut wire, &[5u8; 4000]).unwrap();
        let other = Framing::for_version(6, V6Mode::Default, b"other psk value").unwrap();
        let mut decoder = Decoder::new(other, Arc::from(&b"other psk value"[..]));
        decoder.feed(&wire);
        assert!(decoder.next_frame().is_err());
    }

    #[test]
    fn balanced_padding_skews_bit_density() {
        // 3.5 one bits per byte: inside the balanced range, more zeros than ones.
        let ciphertext: Vec<u8> = [0x0f, 0x07].repeat(450);
        let padding = balanced_padding(&ciphertext, 600).unwrap();
        assert_eq!(padding.len(), 600);
        let ones: u32 = ciphertext
            .iter()
            .chain(padding.iter())
            .map(|b| b.count_ones())
            .sum();
        let per_byte = f64::from(ones) / 1500.0;
        assert!(per_byte > 4.6, "{per_byte}");
    }
}
