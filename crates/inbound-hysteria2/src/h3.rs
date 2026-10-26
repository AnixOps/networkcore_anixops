//! The part of HTTP/3 a Hysteria2 server needs: one request (the auth
//! `POST`) per stream, a static-table-only QPACK decoder with Huffman
//! strings, and a HEADERS-only response.
//!
//! Hysteria2 runs raw TCP-request streams (first varint 0x401) on the same
//! QUIC connection as HTTP/3, so a stock HTTP/3 server cannot be used: it
//! would treat those streams as malformed requests. The server never allows
//! a QPACK dynamic table (its SETTINGS are empty), so clients encode every
//! field with the static table or as literals.

use std::io;
use std::sync::OnceLock;

use outbound_hysteria2::{put_varint, read_varint};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// Largest frame read while looking for the request headers.
const MAX_FRAME: u64 = 64 * 1024;
/// Static table index of `:status: 103`, used as the name of other statuses.
const STATUS_NAME_INDEX: u64 = 24;

/// The server control stream: stream type, then empty SETTINGS.
pub fn control_stream_preface() -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, STREAM_TYPE_CONTROL);
    put_varint(&mut out, FRAME_SETTINGS);
    put_varint(&mut out, 0);
    out
}

/// Reads frames until HEADERS, whose first varint (the frame type) the
/// caller already read, and returns the decoded fields. Unknown frame types
/// (GREASE) are skipped.
pub async fn read_request_headers<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut frame_type: u64,
) -> io::Result<Vec<(String, String)>> {
    loop {
        let len = read_varint(reader).await?;
        if len > MAX_FRAME {
            return Err(invalid("http/3 frame is too large"));
        }
        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload).await?;
        match frame_type {
            FRAME_HEADERS => {
                return decode_field_section(&payload)
                    .ok_or_else(|| invalid("http/3 request headers are invalid"))
            }
            FRAME_DATA => return Err(invalid("http/3 data before headers")),
            _ => frame_type = read_varint(reader).await?,
        }
    }
}

/// A HEADERS frame with `:status` and literal `headers` (lowercase names).
pub fn response_frame(status: u16, headers: &[(&str, &str)]) -> Vec<u8> {
    // Required insert count 0, base 0.
    let mut block = vec![0, 0];
    // Literal with static name reference: 01 N=0 T=1, 4-bit index.
    put_prefix_int(&mut block, 0x50, 4, STATUS_NAME_INDEX);
    put_string(&mut block, status.to_string().as_bytes());
    for (name, value) in headers {
        // Literal with literal name: 001 N=0 H=0, 3-bit length.
        put_prefix_int(&mut block, 0x20, 3, name.len() as u64);
        block.extend_from_slice(name.as_bytes());
        put_string(&mut block, value.as_bytes());
    }
    let mut frame = Vec::with_capacity(block.len() + 8);
    put_varint(&mut frame, FRAME_HEADERS);
    put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

/// The value of `name` in decoded fields.
pub fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
}

/// Decodes a QPACK field section that uses only the static table.
fn decode_field_section(block: &[u8]) -> Option<Vec<(String, String)>> {
    let mut pos = 0;
    let required_insert_count = read_prefix_int(block, &mut pos, 8)?;
    if required_insert_count != 0 {
        return None;
    }
    read_prefix_int(block, &mut pos, 7)?;
    let mut fields = Vec::new();
    while pos < block.len() {
        let first = block[pos];
        if first & 0x80 != 0 {
            // Indexed field line: 1 T index(6).
            if first & 0x40 == 0 {
                return None;
            }
            let (name, value) = STATIC_TABLE.get(read_prefix_int(block, &mut pos, 6)? as usize)?;
            fields.push(((*name).to_owned(), (*value).to_owned()));
        } else if first & 0x40 != 0 {
            // Literal with name reference: 01 N T index(4).
            if first & 0x10 == 0 {
                return None;
            }
            let (name, _) = STATIC_TABLE.get(read_prefix_int(block, &mut pos, 4)? as usize)?;
            let value = read_string(block, &mut pos, 7)?;
            fields.push(((*name).to_owned(), value));
        } else if first & 0x20 != 0 {
            // Literal with literal name: 001 N H length(3).
            let name = read_string(block, &mut pos, 3)?.to_ascii_lowercase();
            let value = read_string(block, &mut pos, 7)?;
            fields.push((name, value));
        } else {
            // Post-base references need the dynamic table.
            return None;
        }
    }
    Some(fields)
}

/// RFC 7541 section 5.1 integer with an `prefix`-bit prefix at `block[pos]`.
fn read_prefix_int(block: &[u8], pos: &mut usize, prefix: u8) -> Option<u64> {
    let max = (1u64 << prefix) - 1;
    let mut value = u64::from(*block.get(*pos)?) & max;
    *pos += 1;
    if value < max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *block.get(*pos)?;
        *pos += 1;
        if shift > 56 {
            return None;
        }
        value += u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

fn put_prefix_int(out: &mut Vec<u8>, flags: u8, prefix: u8, value: u64) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// A string literal: Huffman flag just above the `prefix`-bit length.
fn read_string(block: &[u8], pos: &mut usize, prefix: u8) -> Option<String> {
    let huffman = *block.get(*pos)? & (1 << prefix) != 0;
    let len = read_prefix_int(block, pos, prefix)? as usize;
    let raw = block.get(*pos..pos.checked_add(len)?)?;
    *pos += len;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).ok()
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    put_prefix_int(out, 0, 7, value.len() as u64);
    out.extend_from_slice(value);
}

struct Huffman {
    /// Per code length: first code, index of its symbol in `symbols`, count.
    first_code: [u32; 31],
    first_index: [usize; 31],
    count: [u32; 31],
    /// Symbols sorted by (length, symbol).
    symbols: Vec<u16>,
}

fn huffman() -> &'static Huffman {
    static TABLE: OnceLock<Huffman> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut symbols: Vec<u16> = (0..257).collect();
        symbols.sort_by_key(|symbol| (HUFFMAN_LENGTHS[usize::from(*symbol)], *symbol));
        let mut table = Huffman {
            first_code: [0; 31],
            first_index: [0; 31],
            count: [0; 31],
            symbols,
        };
        let mut code = 0u32;
        let mut previous_len = 0u8;
        for (index, symbol) in table.symbols.iter().enumerate() {
            let len = HUFFMAN_LENGTHS[usize::from(*symbol)];
            if index > 0 {
                code = (code + 1) << (len - previous_len);
            }
            let slot = usize::from(len);
            if table.count[slot] == 0 {
                table.first_code[slot] = code;
                table.first_index[slot] = index;
            }
            table.count[slot] += 1;
            previous_len = len;
        }
        table
    })
}

fn huffman_decode(input: &[u8]) -> Option<Vec<u8>> {
    let table = huffman();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code = 0u32;
    let mut len = 0usize;
    for byte in input {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return None;
            }
            let offset = code.wrapping_sub(table.first_code[len]);
            if table.count[len] > 0 && code >= table.first_code[len] && offset < table.count[len] {
                let symbol = table.symbols[table.first_index[len] + offset as usize];
                if symbol == 256 {
                    return None;
                }
                out.push(symbol as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // Padding: fewer than 8 bits, all ones (the EOS prefix).
    if len >= 8 || code != (1u32 << len) - 1 {
        return None;
    }
    Some(out)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Code lengths of the HPACK/QPACK Huffman code (RFC 7541 Appendix B),
/// symbols 0 to 255 and EOS. The code is canonical, so the lengths define it.
#[rustfmt::skip]
const HUFFMAN_LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
];

/// The QPACK static table (RFC 9204 Appendix A).
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_decodes_rfc_examples() {
        // RFC 7541 C.4.1: "www.example.com".
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&encoded).unwrap(), b"www.example.com");
        // RFC 7541 C.4.2: "no-cache".
        let encoded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(huffman_decode(&encoded).unwrap(), b"no-cache");
        // Padding that is not all ones is invalid.
        assert!(huffman_decode(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xfe
        ])
        .is_none());
    }

    #[test]
    fn decodes_static_and_literal_fields() {
        let mut block = vec![0, 0];
        // :method POST (static 20).
        block.push(0xc0 | 20);
        // :path with literal value "/auth" (static name 1).
        block.push(0x50 | 1);
        put_string(&mut block, b"/auth");
        // Literal name "hysteria-auth", Huffman value "www.example.com".
        put_prefix_int(&mut block, 0x20, 3, 13);
        block.extend_from_slice(b"Hysteria-Auth");
        block.push(0x80 | 12);
        block.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        let fields = decode_field_section(&block).unwrap();
        assert_eq!(field(&fields, ":method"), Some("POST"));
        assert_eq!(field(&fields, ":path"), Some("/auth"));
        assert_eq!(field(&fields, "hysteria-auth"), Some("www.example.com"));

        // Dynamic table references are refused.
        assert!(decode_field_section(&[1, 0]).is_none());
        assert!(decode_field_section(&[0, 0, 0x80]).is_none());
    }

    #[test]
    fn response_round_trips_through_the_decoder() {
        let frame = response_frame(233, &[("hysteria-udp", "false")]);
        assert_eq!(frame[0], FRAME_HEADERS as u8);
        let fields = decode_field_section(&frame[2..]).unwrap();
        assert_eq!(field(&fields, ":status"), Some("233"));
        assert_eq!(field(&fields, "hysteria-udp"), Some("false"));
    }

    #[test]
    fn prefix_ints_round_trip() {
        for value in [0u64, 5, 14, 15, 16, 127, 128, 300, 1 << 20] {
            let mut out = Vec::new();
            put_prefix_int(&mut out, 0x20, 3, value);
            let mut pos = 0;
            assert_eq!(read_prefix_int(&out, &mut pos, 3), Some(value));
            assert_eq!(pos, out.len());
        }
    }
}
