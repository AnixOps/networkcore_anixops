//! XTLS Vision framing (Xray `proxy/proxy.go`), client side.
//!
//! While the proxied connection carries an inner TLS handshake, every write is
//! wrapped in a padding frame:
//!
//! ```text
//! [user UUID, first frame only] command(1) content_len(2) padding_len(2)
//! content padding
//! ```
//!
//! Commands: 0 continue, 1 end (padding stops, outer TLS continues), 2 direct
//! (padding stops and the direction leaves the outer TLS: the inner TLS 1.3
//! records are copied over the raw transport).

use std::io;

pub const COMMAND_CONTINUE: u8 = 0;
pub const COMMAND_END: u8 = 1;
pub const COMMAND_DIRECT: u8 = 2;

const BUFFER_SIZE: usize = 8192;
/// Largest content carried in one frame (header 5 + UUID 16 must fit).
pub const MAX_FRAME_CONTENT: usize = BUFFER_SIZE - 21;
const LONG_PADDING_THRESHOLD: usize = 900;
const LONG_PADDING_RANDOM: u32 = 500;
const LONG_PADDING_BASE: usize = 900;
const SHORT_PADDING_RANDOM: u32 = 256;
const PACKETS_TO_FILTER: i32 = 8;

const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// What Vision has learned about the inner (proxied) traffic.
#[derive(Debug, Clone)]
pub struct TrafficState {
    pub packets_to_filter: i32,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub enable_xtls: bool,
    pub cipher: u16,
    remaining_server_hello: i32,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self {
            packets_to_filter: PACKETS_TO_FILTER,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }
}

impl TrafficState {
    /// Inspects one packet of inner traffic (Xray `XtlsFilterTls`).
    pub fn filter(&mut self, packet: &[u8]) {
        self.packets_to_filter -= 1;
        if packet.len() >= 6 {
            if packet[..3] == TLS_SERVER_HANDSHAKE_START && packet[5] == 2 {
                self.remaining_server_hello = (((packet[3] as i32) << 8) | packet[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if packet.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = packet[43] as usize;
                    let at = 43 + session_id_len + 1;
                    if packet.len() >= at + 2 {
                        self.cipher = u16::from_be_bytes([packet[at], packet[at + 1]]);
                    }
                }
            } else if packet[..2] == TLS_CLIENT_HANDSHAKE_START && packet[5] == 1 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(packet.len());
            self.remaining_server_hello -= packet.len() as i32;
            if contains(&packet[..end], &TLS13_SUPPORTED_VERSIONS) {
                // TLS_AES_128_CCM_8_SHA256 (0x1305) is excluded, as in Xray.
                if (0x1301..=0x1304).contains(&self.cipher) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn random_below(bound: u32) -> io::Result<usize> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 4];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("system random generator failed"))?;
    Ok((u32::from_be_bytes(bytes) % bound) as usize)
}

/// Uplink padding (Xray `VisionWriter`).
#[derive(Debug)]
pub struct VisionWriter {
    uuid_once: Option<[u8; 16]>,
    padding: bool,
}

impl VisionWriter {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid_once: Some(uuid),
            padding: true,
        }
    }

    pub fn is_padding(&self) -> bool {
        self.padding
    }

    /// Appends one padding frame (Xray `XtlsPadding`).
    pub fn pad(&mut self, content: &[u8], command: u8, out: &mut Vec<u8>) -> io::Result<()> {
        debug_assert!(content.len() <= MAX_FRAME_CONTENT);
        let content_len = content.len();
        let mut padding_len = if content_len < LONG_PADDING_THRESHOLD {
            random_below(LONG_PADDING_RANDOM)? + LONG_PADDING_BASE - content_len
        } else {
            random_below(SHORT_PADDING_RANDOM)?
        };
        padding_len = padding_len.min(BUFFER_SIZE - 21 - content_len);
        if let Some(uuid) = self.uuid_once.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len, 0);
        Ok(())
    }

    /// Frames `data` (one write) into `out`. Returns `true` when the uplink
    /// must leave the outer TLS after these bytes were sent.
    pub fn encode(
        &mut self,
        traffic: &mut TrafficState,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> io::Result<bool> {
        if !self.padding {
            out.extend_from_slice(data);
            return Ok(false);
        }
        let chunks: Vec<&[u8]> = data.chunks(MAX_FRAME_CONTENT).collect();
        for chunk in &chunks {
            traffic.filter(chunk);
        }
        let mut direct = false;
        let mut is_padding = true;
        let last_index = chunks.len().saturating_sub(1);
        for (index, chunk) in chunks.iter().enumerate() {
            let last = index == last_index;
            let final_command = if traffic.enable_xtls {
                COMMAND_DIRECT
            } else {
                COMMAND_END
            };
            if traffic.is_tls && chunk.len() >= 6 && chunk[..3] == TLS_APPLICATION_DATA_START {
                if traffic.enable_xtls {
                    direct = true;
                }
                let command = if last {
                    final_command
                } else {
                    COMMAND_CONTINUE
                };
                self.pad(chunk, command, out)?;
                is_padding = false;
                continue;
            } else if !traffic.is_tls12_or_above && traffic.packets_to_filter <= 1 {
                // Finish padding one packet early for older receivers.
                is_padding = false;
                self.pad(chunk, COMMAND_END, out)?;
                for rest in &chunks[index + 1..] {
                    out.extend_from_slice(rest);
                }
                break;
            }
            let command = if last && !is_padding {
                final_command
            } else {
                COMMAND_CONTINUE
            };
            self.pad(chunk, command, out)?;
        }
        self.padding = is_padding;
        Ok(direct)
    }
}

/// Outcome of feeding downlink bytes to a [`VisionReader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStatus {
    /// Still inside padded frames.
    Padding,
    /// Padding ended; following bytes arrive unframed over the outer TLS.
    End,
    /// Padding ended; following bytes arrive over the raw transport.
    Direct,
}

/// Downlink unpadding (Xray `XtlsUnpadding`).
#[derive(Debug)]
pub struct VisionReader {
    uuid: [u8; 16],
    started: bool,
    prefix: Vec<u8>,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    finished: Option<ReadStatus>,
}

impl VisionReader {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            started: false,
            prefix: Vec::new(),
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            finished: None,
        }
    }

    pub fn finished(&self) -> Option<ReadStatus> {
        self.finished
    }

    /// Returns bytes held back while waiting for the frame prefix (call at EOF).
    pub fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.prefix)
    }

    /// Removes framing from `input`, appending content bytes to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> ReadStatus {
        if let Some(status) = self.finished {
            out.extend_from_slice(input);
            return status;
        }
        let owned;
        let mut data: &[u8] = input;
        if !self.started {
            self.prefix.extend_from_slice(input);
            if self.prefix.len() < 21 {
                return ReadStatus::Padding;
            }
            if self.prefix[..16] != self.uuid {
                // The server is not padding: everything is plain data.
                out.extend_from_slice(&self.prefix);
                self.prefix.clear();
                self.finished = Some(ReadStatus::End);
                return ReadStatus::End;
            }
            self.started = true;
            self.remaining_command = 5;
            owned = std::mem::take(&mut self.prefix);
            data = &owned[16..];
        }

        let mut index = 0;
        while index < data.len() {
            if self.remaining_command > 0 {
                let byte = data[index] as i32;
                index += 1;
                match self.remaining_command {
                    5 => self.current_command = byte as u8,
                    4 => self.remaining_content = byte << 8,
                    3 => self.remaining_content |= byte,
                    2 => self.remaining_padding = byte << 8,
                    _ => self.remaining_padding |= byte,
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(data.len() - index);
                out.extend_from_slice(&data[index..index + n]);
                index += n;
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding.max(0) as usize).min(data.len() - index);
                index += n;
                self.remaining_padding -= n as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == COMMAND_CONTINUE {
                    self.remaining_command = 5;
                } else {
                    let status = if self.current_command == COMMAND_DIRECT {
                        ReadStatus::Direct
                    } else {
                        ReadStatus::End
                    };
                    out.extend_from_slice(&data[index..]);
                    self.finished = Some(status);
                    return status;
                }
            }
        }
        ReadStatus::Padding
    }
}
