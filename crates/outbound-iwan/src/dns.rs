//! Minimal DNS A lookups for domain targets, sent through the tunnel to the
//! DNS servers from OPENACK or the config (spec §11).

use std::net::Ipv4Addr;

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const MAX_NAME_LEN: usize = 253;

/// A recursive query for the A records of `name`, or `None` when the name is
/// not a valid DNS name.
pub fn query(id: u16, name: &str) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    // RD set; one question.
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(out)
}

/// The answer to a [`query`]: the A records and the smallest TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub addresses: Vec<Ipv4Addr>,
    pub ttl: u32,
}

/// Parses the response to the query with `id`. `None` means the datagram is
/// not that response; an answer without A records has no addresses.
pub fn parse_response(id: u16, response: &[u8]) -> Option<Answer> {
    if response.len() < HEADER_LEN || response[..2] != id.to_be_bytes() {
        return None;
    }
    // QR must be set.
    if response[2] & 0x80 == 0 {
        return None;
    }
    let rcode = response[3] & 0x0F;
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    let mut answer = Answer {
        addresses: Vec::new(),
        ttl: u32::MAX,
    };
    if rcode != 0 {
        return Some(answer);
    }
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = skip_name(response, at)? + 4;
    }
    for _ in 0..answers {
        at = skip_name(response, at)?;
        let fixed = response.get(at..at + 10)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data = response.get(at + 10..at + 10 + len)?;
        if kind == TYPE_A && class == CLASS_IN && len == 4 {
            answer
                .addresses
                .push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            answer.ttl = answer.ttl.min(ttl);
        }
        at += 10 + len;
    }
    if answer.addresses.is_empty() {
        answer.ttl = 0;
    }
    Some(answer)
}

/// The offset just past the name at `at`; a compression pointer ends it.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        match len {
            0 => return Some(at + 1),
            len if len & 0xC0 == 0xC0 => {
                message.get(at + 1)?;
                return Some(at + 2);
            }
            len if len & 0xC0 == 0 => at += 1 + usize::from(len),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let query = query(0x1234, "a.example.").unwrap();
        assert_eq!(
            query,
            [
                &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
                &[1, b'a', 7],
                b"example",
                &[0, 0, 1, 0, 1],
            ]
            .concat()
        );
        assert!(query_is_none("a..b"));
        assert!(query_is_none(""));
        assert!(query_is_none(&"x".repeat(64)));
    }

    fn query_is_none(name: &str) -> bool {
        query(1, name).is_none()
    }

    fn response(id: u16, rcode: u8, records: &[(u16, &[u8], u32)]) -> Vec<u8> {
        let mut out = query(id, "a.example").unwrap();
        out[2] = 0x81;
        out[3] = 0x80 | rcode;
        out[7] = records.len() as u8;
        for (kind, data, ttl) in records {
            out.extend_from_slice(&[0xC0, 12]);
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn parses_a_records_after_a_cname() {
        let cname = [1, b'b', 0xC0, 12];
        let message = response(
            7,
            0,
            &[
                (5, &cname, 300),
                (1, &[192, 0, 2, 1], 120),
                (1, &[192, 0, 2, 2], 60),
            ],
        );
        assert_eq!(
            parse_response(7, &message),
            Some(Answer {
                addresses: vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)],
                ttl: 60,
            })
        );
        assert_eq!(parse_response(8, &message), None);
    }

    #[test]
    fn errors_and_truncation() {
        let nxdomain = response(7, 3, &[]);
        assert!(parse_response(7, &nxdomain).unwrap().addresses.is_empty());
        let message = response(7, 0, &[(1, &[192, 0, 2, 1], 120)]);
        assert_eq!(parse_response(7, &message[..message.len() - 1]), None);
        let mut query_only = query(7, "a.example").unwrap();
        assert_eq!(parse_response(7, &query_only), None);
        query_only[2] |= 0x80;
        assert!(parse_response(7, &query_only).unwrap().addresses.is_empty());
    }
}
