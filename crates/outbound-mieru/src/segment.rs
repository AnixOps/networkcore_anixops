//! Segment framing (spec §3), for either direction.
//!
//! [`SegmentWriter`] appends a direction's nonce and sealed segments to an
//! output buffer. [`SegmentReader`] parses them back from an input buffer as
//! bytes arrive.

use std::io;

use crate::crypto::{
    fill_printable, invalid_data, random_u32, unix_now, Cipher, KEY_LEN, NONCE_LEN, TAG_LEN,
};

pub const METADATA_LEN: usize = 32;
pub const SEALED_METADATA_LEN: usize = METADATA_LEN + TAG_LEN;
/// Largest payload of a session segment (types 2–5).
pub const MAX_SESSION_PAYLOAD: usize = 1024;
/// Largest payload of a data segment (types 6–9).
pub const MAX_DATA_PAYLOAD: usize = 32 * 1024;
/// Window size the official peers send on TCP.
pub const TCP_WINDOW: u16 = 4096;
/// Suffix padding is drawn from `0..MAX_SUFFIX`.
const MAX_SUFFIX: u32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    OpenSessionRequest,
    OpenSessionResponse,
    CloseSessionRequest,
    CloseSessionResponse,
    DataClientToServer,
    DataServerToClient,
    AckClientToServer,
    AckServerToClient,
}

impl Kind {
    pub fn code(self) -> u8 {
        match self {
            Kind::OpenSessionRequest => 2,
            Kind::OpenSessionResponse => 3,
            Kind::CloseSessionRequest => 4,
            Kind::CloseSessionResponse => 5,
            Kind::DataClientToServer => 6,
            Kind::DataServerToClient => 7,
            Kind::AckClientToServer => 8,
            Kind::AckServerToClient => 9,
        }
    }

    fn from_code(code: u8) -> io::Result<Self> {
        match code {
            2 => Ok(Kind::OpenSessionRequest),
            3 => Ok(Kind::OpenSessionResponse),
            4 => Ok(Kind::CloseSessionRequest),
            5 => Ok(Kind::CloseSessionResponse),
            6 => Ok(Kind::DataClientToServer),
            7 => Ok(Kind::DataServerToClient),
            8 => Ok(Kind::AckClientToServer),
            9 => Ok(Kind::AckServerToClient),
            10 | 11 => Err(invalid_data("mieru low entropy segments are not supported")),
            _ => Err(invalid_data("mieru segment type is unknown")),
        }
    }

    /// Session metadata layout (§3.1) rather than data metadata (§3.2).
    pub fn is_session(self) -> bool {
        matches!(
            self,
            Kind::OpenSessionRequest
                | Kind::OpenSessionResponse
                | Kind::CloseSessionRequest
                | Kind::CloseSessionResponse
        )
    }

    pub fn max_payload(self) -> usize {
        if self.is_session() {
            MAX_SESSION_PAYLOAD
        } else {
            MAX_DATA_PAYLOAD
        }
    }
}

/// Decoded segment metadata. Data-only fields are zero for session kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub kind: Kind,
    /// Unix minutes.
    pub timestamp: u32,
    pub session_id: u32,
    pub sequence: u32,
    /// Session kinds only.
    pub status: u8,
    pub unack_sequence: u32,
    pub window: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

impl Metadata {
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        let mut out = [0u8; METADATA_LEN];
        out[0] = self.kind.code();
        out[2..6].copy_from_slice(&self.timestamp.to_be_bytes());
        out[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.sequence.to_be_bytes());
        if self.kind.is_session() {
            out[14] = self.status;
            out[15..17].copy_from_slice(&self.payload_len.to_be_bytes());
            out[17] = self.suffix_len;
        } else {
            out[14..18].copy_from_slice(&self.unack_sequence.to_be_bytes());
            out[18..20].copy_from_slice(&self.window.to_be_bytes());
            out[20] = self.fragment;
            out[21] = self.prefix_len;
            out[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
            out[24] = self.suffix_len;
        }
        out
    }

    pub fn decode(raw: &[u8; METADATA_LEN]) -> io::Result<Self> {
        let kind = Kind::from_code(raw[0])?;
        let u32_at =
            |at: usize| u32::from_be_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let u16_at = |at: usize| u16::from_be_bytes([raw[at], raw[at + 1]]);
        let mut metadata = Metadata {
            kind,
            timestamp: u32_at(2),
            session_id: u32_at(6),
            sequence: u32_at(10),
            status: 0,
            unack_sequence: 0,
            window: 0,
            fragment: 0,
            prefix_len: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        if kind.is_session() {
            metadata.status = raw[14];
            metadata.payload_len = u16_at(15);
            metadata.suffix_len = raw[17];
        } else {
            metadata.unack_sequence = u32_at(14);
            metadata.window = u16_at(18);
            metadata.fragment = raw[20];
            metadata.prefix_len = raw[21];
            metadata.payload_len = u16_at(22);
            metadata.suffix_len = raw[24];
        }
        if usize::from(metadata.payload_len) > kind.max_payload() {
            return Err(invalid_data("mieru segment payload is too long"));
        }
        Ok(metadata)
    }
}

pub fn unix_minutes() -> u32 {
    (unix_now() / 60) as u32
}

/// One session's outgoing direction.
pub struct SegmentWriter {
    cipher: Cipher,
    /// Sent in front of the first segment.
    nonce: Option<[u8; NONCE_LEN]>,
    session_id: u32,
    sequence: u32,
}

impl SegmentWriter {
    pub fn new(key: &[u8; KEY_LEN], nonce: [u8; NONCE_LEN], session_id: u32) -> Self {
        Self {
            cipher: Cipher::new(key, nonce),
            nonce: Some(nonce),
            session_id,
            sequence: 0,
        }
    }

    /// Appends one segment of `kind` carrying `payload` (at most
    /// [`Kind::max_payload`] bytes) to `out`.
    pub fn write(&mut self, out: &mut Vec<u8>, kind: Kind, payload: &[u8]) -> io::Result<()> {
        if payload.len() > kind.max_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mieru segment payload is too long",
            ));
        }
        if let Some(nonce) = self.nonce.take() {
            out.extend_from_slice(&nonce);
        }
        let suffix_len = (random_u32()? % MAX_SUFFIX) as u8;
        let metadata = Metadata {
            kind,
            timestamp: unix_minutes(),
            session_id: self.session_id,
            sequence: self.sequence,
            status: 0,
            unack_sequence: 0,
            window: if kind.is_session() { 0 } else { TCP_WINDOW },
            fragment: 0,
            prefix_len: 0,
            payload_len: payload.len() as u16,
            suffix_len,
        };
        self.cipher.seal_into(out, &metadata.encode())?;
        if !payload.is_empty() {
            self.cipher.seal_into(out, payload)?;
        }
        let start = out.len();
        out.resize(start + usize::from(suffix_len), 0);
        fill_printable(&mut out[start..])?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
    }
}

/// A parsed segment.
#[derive(Debug)]
pub struct Segment {
    pub metadata: Metadata,
    pub payload: Vec<u8>,
}

/// One incoming direction. The key is not known up front: the first segment
/// is tried with each candidate key (spec §1) and the one that opens it is
/// kept.
pub struct SegmentReader {
    keys: Vec<[u8; KEY_LEN]>,
    cipher: Option<Cipher>,
    nonce: Option<[u8; NONCE_LEN]>,
    pending: Option<Metadata>,
}

impl SegmentReader {
    pub fn new(keys: Vec<[u8; KEY_LEN]>) -> Self {
        Self {
            keys,
            cipher: None,
            nonce: None,
            pending: None,
        }
    }

    /// The peer's first nonce, once it has arrived.
    pub fn peer_nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        self.nonce.as_ref()
    }

    /// Whether a segment has been started but not completed.
    pub fn is_mid_segment(&self) -> bool {
        self.pending.is_some()
    }

    fn open_metadata(&mut self, sealed: &mut [u8]) -> io::Result<Metadata> {
        let mut raw = [0u8; METADATA_LEN];
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.open_in_place(sealed)?;
            raw.copy_from_slice(&sealed[..METADATA_LEN]);
            return Metadata::decode(&raw);
        }
        let nonce = self
            .nonce
            .ok_or_else(|| invalid_data("mieru nonce is missing"))?;
        for key in &self.keys {
            let mut attempt = [0u8; SEALED_METADATA_LEN];
            attempt.copy_from_slice(sealed);
            let mut cipher = Cipher::new(key, nonce);
            if cipher.open_in_place(&mut attempt).is_ok() {
                raw.copy_from_slice(&attempt[..METADATA_LEN]);
                self.cipher = Some(cipher);
                self.keys.clear();
                return Metadata::decode(&raw);
            }
        }
        Err(invalid_data("mieru segment failed authentication"))
    }

    /// Consumes one complete segment from the front of `input`, or returns
    /// `None` when more bytes are needed. Leaves an incomplete tail in place.
    pub fn next_segment(&mut self, input: &mut Vec<u8>) -> io::Result<Option<Segment>> {
        if self.nonce.is_none() {
            if input.len() < NONCE_LEN {
                return Ok(None);
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&input[..NONCE_LEN]);
            input.drain(..NONCE_LEN);
            self.nonce = Some(nonce);
        }
        if self.pending.is_none() {
            if input.len() < SEALED_METADATA_LEN {
                return Ok(None);
            }
            let metadata = self.open_metadata(&mut input[..SEALED_METADATA_LEN])?;
            input.drain(..SEALED_METADATA_LEN);
            self.pending = Some(metadata);
        }
        let metadata = self.pending.as_ref().expect("pending metadata");
        let prefix = usize::from(metadata.prefix_len);
        let payload_len = usize::from(metadata.payload_len);
        let sealed_len = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        let total = prefix + sealed_len + usize::from(metadata.suffix_len);
        if input.len() < total {
            return Ok(None);
        }
        let metadata = self.pending.take().expect("pending metadata");
        let mut payload = Vec::new();
        if sealed_len > 0 {
            let cipher = self.cipher.as_mut().expect("cipher after metadata");
            let sealed = &mut input[prefix..prefix + sealed_len];
            cipher.open_in_place(sealed)?;
            payload.extend_from_slice(&sealed[..payload_len]);
        }
        input.drain(..total);
        Ok(Some(Segment { metadata, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{candidate_keys, derive_key, hashed_password, new_nonce};

    #[test]
    fn metadata_round_trips_both_layouts() {
        let session = Metadata {
            kind: Kind::OpenSessionRequest,
            timestamp: 29_883_101,
            session_id: 0xb04a_ea04,
            sequence: 0,
            status: 0,
            unack_sequence: 0,
            window: 0,
            fragment: 0,
            prefix_len: 0,
            payload_len: 10,
            suffix_len: 37,
        };
        let raw = session.encode();
        assert_eq!(raw[0], 2);
        assert_eq!(raw[15..18], [0, 10, 37]);
        assert_eq!(Metadata::decode(&raw).unwrap(), session);

        let data = Metadata {
            kind: Kind::DataServerToClient,
            window: TCP_WINDOW,
            prefix_len: 3,
            payload_len: 32768,
            suffix_len: 139,
            sequence: 2,
            ..session
        };
        let raw = data.encode();
        assert_eq!(raw[18..25], [0x10, 0, 0, 3, 0x80, 0, 139]);
        assert_eq!(Metadata::decode(&raw).unwrap(), data);
    }

    #[test]
    fn rejects_low_entropy_unknown_and_oversized_segments() {
        let mut raw = [0u8; METADATA_LEN];
        raw[0] = 11;
        assert!(Metadata::decode(&raw).is_err());
        raw[0] = 1;
        assert!(Metadata::decode(&raw).is_err());
        raw[0] = 2;
        raw[15..17].copy_from_slice(&1025u16.to_be_bytes());
        assert!(Metadata::decode(&raw).is_err());
    }

    #[test]
    fn reader_parses_writer_output_byte_by_byte() {
        let hashed = hashed_password(b"alice", b"secret");
        let now = unix_now();
        let mut writer =
            SegmentWriter::new(&derive_key(&hashed, now), new_nonce(b"alice").unwrap(), 7);
        let mut wire = Vec::new();
        writer
            .write(
                &mut wire,
                Kind::OpenSessionRequest,
                b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50",
            )
            .unwrap();
        writer
            .write(
                &mut wire,
                Kind::DataClientToServer,
                &[0xab; MAX_DATA_PAYLOAD],
            )
            .unwrap();
        writer
            .write(&mut wire, Kind::CloseSessionRequest, &[])
            .unwrap();
        assert!(writer
            .write(&mut wire, Kind::OpenSessionRequest, &[0; 1025])
            .is_err());

        let mut keys = candidate_keys(&hashed, now).to_vec();
        keys.rotate_left(1);
        let mut reader = SegmentReader::new(keys);
        let mut input = Vec::new();
        let mut segments = Vec::new();
        for byte in wire {
            input.push(byte);
            while let Some(segment) = reader.next_segment(&mut input).unwrap() {
                segments.push(segment);
            }
        }
        assert!(input.is_empty());
        assert!(!reader.is_mid_segment());
        let kinds: Vec<Kind> = segments.iter().map(|s| s.metadata.kind).collect();
        assert_eq!(
            kinds,
            [
                Kind::OpenSessionRequest,
                Kind::DataClientToServer,
                Kind::CloseSessionRequest
            ]
        );
        assert_eq!(segments[0].payload.len(), 10);
        assert_eq!(segments[1].payload, vec![0xab; MAX_DATA_PAYLOAD]);
        assert_eq!(segments[1].metadata.window, TCP_WINDOW);
        let sequences: Vec<u32> = segments.iter().map(|s| s.metadata.sequence).collect();
        assert_eq!(sequences, [0, 1, 2]);
        assert!(segments.iter().all(|s| s.metadata.session_id == 7));
    }

    #[test]
    fn reader_rejects_a_wrong_password() {
        let now = unix_now();
        let mut writer = SegmentWriter::new(
            &derive_key(&hashed_password(b"alice", b"secret"), now),
            new_nonce(b"alice").unwrap(),
            7,
        );
        let mut wire = Vec::new();
        writer
            .write(&mut wire, Kind::OpenSessionRequest, b"hello")
            .unwrap();
        let mut reader =
            SegmentReader::new(candidate_keys(&hashed_password(b"alice", b"guess"), now).to_vec());
        assert!(reader.next_segment(&mut wire).is_err());
    }
}
