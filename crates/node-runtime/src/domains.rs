//! Addresses mapped back to the domain names they were resolved from.
//!
//! A client that resolves names itself (or a layer-3 inbound such as iWAN)
//! asks the node for an IP address, so domain egress routes need the name
//! the address came from. Every DNS answer relayed through the node (UDP
//! replies from port 53) is recorded here; an inbound with its own resolver
//! records its answers with [`DomainCache::record`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entries kept at most; the oldest-expiring go first when full.
const MAX_ENTRIES: usize = 65_536;
/// Clients keep answers a little past their TTL; a short TTL still gets this.
const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = Duration::from_secs(6 * 3600);

#[derive(Default)]
pub struct DomainCache {
    entries: Mutex<HashMap<IpAddr, (String, Instant)>>,
}

impl DomainCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps `ip` to `domain` for `ttl` (clamped to one minute .. six hours).
    pub fn record(&self, ip: IpAddr, domain: &str, ttl: Duration) {
        let Some(domain) = normalize(domain) else {
            return;
        };
        let ip = ip.to_canonical();
        let expires = Instant::now() + ttl.clamp(MIN_TTL, MAX_TTL);
        let mut entries = self.lock();
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&ip) {
            let now = Instant::now();
            entries.retain(|_, (_, expires)| *expires > now);
            if entries.len() >= MAX_ENTRIES {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, (_, expires))| *expires)
                    .map(|(ip, _)| *ip)
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(ip, (domain, expires));
    }

    /// The domain `ip` was last resolved from, while its answer is fresh.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let ip = ip.to_canonical();
        let mut entries = self.lock();
        match entries.get(&ip) {
            Some((domain, expires)) if *expires > Instant::now() => Some(domain.clone()),
            Some(_) => {
                entries.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// Records the A and AAAA answers of a DNS response under the name the
    /// client asked for (not a CNAME target), so a rule for the name the
    /// user typed matches. Anything that is not a response is ignored.
    pub fn record_response(&self, message: &[u8]) {
        for (ip, domain, ttl) in answers(message).unwrap_or_default() {
            self.record(ip, &domain, ttl);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, (String, Instant)>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A host name as routes match it: lowercase, without the final dot; `None`
/// for an address or anything that is not a name.
pub(crate) fn normalize(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.');
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && name.parse::<IpAddr>().is_err();
    valid.then(|| name.to_ascii_lowercase())
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// `(address, question name, ttl)` for each A/AAAA answer of a response.
fn answers(message: &[u8]) -> Option<Vec<(IpAddr, String, Duration)>> {
    let header = message.get(..12)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    // A response (QR) without an error code.
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answer_count = u16::from_be_bytes([header[6], header[7]]);
    if questions != 1 || answer_count == 0 {
        return None;
    }
    let (question, mut position) = read_name(message, 12)?;
    position += 4; // type, class
    let mut found = Vec::new();
    for _ in 0..answer_count {
        let (_, after_name) = read_name(message, position)?;
        let fixed = message.get(after_name..after_name + 10)?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data = message.get(after_name + 10..after_name + 10 + length)?;
        position = after_name + 10 + length;
        let ip = match (kind, class, data.len()) {
            (TYPE_A, CLASS_IN, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let octets: [u8; 16] = data.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => continue,
        };
        found.push((ip, question.clone(), Duration::from_secs(u64::from(ttl))));
    }
    Some(found)
}

/// Reads a possibly compressed name at `start`; returns it and the offset
/// right after it in the message (after the first pointer, if any).
fn read_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut position = start;
    let mut end = None;
    for _ in 0..128 {
        let length = *message.get(position)?;
        match length & 0xc0 {
            0x00 if length == 0 => {
                return Some((name, end.unwrap_or(position + 1)));
            }
            0x00 => {
                let label = message.get(position + 1..position + 1 + usize::from(length))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(std::str::from_utf8(label).ok()?);
                if name.len() > 253 {
                    return None;
                }
                position += 1 + usize::from(length);
            }
            0xc0 => {
                let low = *message.get(position + 1)?;
                end.get_or_insert(position + 2);
                position = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// A response for `question` with a CNAME and then one A and one AAAA.
    fn response(question: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        name(&mut message, question);
        message.extend_from_slice(&[0, 1, 0, 1]);
        // CNAME: question (pointer to offset 12) -> edge.cdn.test
        message.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30]);
        let mut target = Vec::new();
        name(&mut target, "edge.cdn.test");
        message.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let cname_at = message.len();
        message.extend_from_slice(&target);
        // A for the CNAME target, by pointer.
        message.extend_from_slice(&[0xc0, cname_at as u8, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        message.extend_from_slice(&[203, 0, 113, 7]);
        message.extend_from_slice(&[0xc0, cname_at as u8, 0, 28, 0, 1, 0, 0, 0x0e, 0x10, 0, 16]);
        message.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        message
    }

    #[test]
    fn maps_answers_to_the_question_name() {
        let cache = DomainCache::new();
        cache.record_response(&response("Chat.Example.test"));
        assert_eq!(
            cache.lookup("203.0.113.7".parse().unwrap()).as_deref(),
            Some("chat.example.test")
        );
        assert_eq!(
            cache.lookup("2001:db8::7".parse().unwrap()).as_deref(),
            Some("chat.example.test")
        );
        // An IPv4-mapped address is the same address.
        assert_eq!(
            cache
                .lookup("::ffff:203.0.113.7".parse().unwrap())
                .as_deref(),
            Some("chat.example.test")
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn ignores_queries_errors_and_garbage() {
        let cache = DomainCache::new();
        let mut query = response("a.example.test");
        query[2] = 0x01; // QR clear
        cache.record_response(&query);
        let mut failed = response("a.example.test");
        failed[3] = 0x83; // NXDOMAIN
        cache.record_response(&failed);
        let full = response("a.example.test");
        cache.record_response(&full[..full.len() - 3]);
        cache.record_response(&[0xff; 40]);
        cache.record_response(&[]);
        assert!(cache.is_empty());
    }

    #[test]
    fn refuses_pointer_loops() {
        let mut message = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(&[0xc0, 12]);
        assert!(answers(&message).is_none());
    }

    #[test]
    fn records_names_not_addresses() {
        let cache = DomainCache::new();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        cache.record(ip, "192.0.2.1", Duration::from_secs(60));
        cache.record(ip, "bad name", Duration::from_secs(60));
        assert!(cache.lookup(ip).is_none());
        cache.record(ip, "Api.Example.test.", Duration::from_secs(1));
        assert_eq!(cache.lookup(ip).as_deref(), Some("api.example.test"));
    }
}
