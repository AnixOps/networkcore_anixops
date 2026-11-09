//! Answers kept between DNS queries, and upstream connections kept between
//! exchanges.
//!
//! Every forwarded query used to open a connection to its upstream through
//! the outbound (and a TLS session for DoT / DoH), so a page that resolved
//! six names paid six proxy round trips plus handshakes before its first
//! request. The tunnel now:
//!
//! * answers from [`DnsCache`] while a record's TTL (clamped to
//!   [`MIN_TTL`]..[`MAX_TTL`]) lasts;
//! * after that, for up to [`STALE_WINDOW`], answers the old record with a
//!   [`STALE_TTL`] and refreshes it in the background (RFC 8767);
//! * joins a query to an exchange already in flight for the same question
//!   instead of sending it again;
//! * keeps idle upstream connections in [`UpstreamPool`] for the next query.
//!
//! Only standard answers are kept: `NOERROR` or `NXDOMAIN`, not truncated,
//! for the question that was asked. No address or name leaves this module.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use engine_outbound::BoxStream;

use crate::dns::Question;

/// Shortest time an answer is kept, whatever its TTL says.
pub const MIN_TTL: Duration = Duration::from_secs(30);
/// Longest time an answer is kept fresh.
pub const MAX_TTL: Duration = Duration::from_secs(3600);
/// How long `NXDOMAIN` / no-data answers are kept at most.
pub const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// How long after expiry an answer may still be served while it refreshes.
pub const STALE_WINDOW: Duration = Duration::from_secs(3600);
/// TTL written into a stale answer, so the app asks again soon.
pub const STALE_TTL: u32 = 30;
/// Most answers kept.
pub const MAX_ENTRIES: usize = 4096;
/// Queries that may wait on one exchange in flight.
pub const MAX_WAITERS: usize = 32;

const HEADER_LEN: usize = 12;
const TYPE_OPT: u16 = 41;

/// What a cached answer is for: the question, the server that answers it and
/// whether that server is reached through the proxy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub server: usize,
    pub proxied: bool,
}

/// The result of [`DnsCache::lookup`].
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A reply to the query, from an answer that is still fresh.
    Fresh(Vec<u8>),
    /// A reply from an expired answer; the caller should refresh it.
    Stale(Vec<u8>),
    Miss,
}

struct Entry {
    response: Vec<u8>,
    stored: Instant,
    ttl: Duration,
}

/// Who asked a query that waits on an exchange in flight.
#[derive(Clone, Debug)]
pub struct Waiter {
    pub query: Vec<u8>,
    pub question_end: usize,
    pub app: SocketAddr,
    pub resolver: SocketAddr,
}

/// Cached answers and the exchanges in flight, behind one lock.
#[derive(Default)]
pub struct DnsCache {
    entries: HashMap<CacheKey, Entry>,
    inflight: HashMap<CacheKey, Vec<Waiter>>,
}

impl DnsCache {
    /// A reply to `query` (whose question ends at `question_end`) from the
    /// answer kept for `key`, as of `now`.
    pub fn lookup(
        &mut self,
        key: &CacheKey,
        query: &[u8],
        question_end: usize,
        now: Instant,
    ) -> Lookup {
        let Some(entry) = self.entries.get(key) else {
            return Lookup::Miss;
        };
        let age = now.saturating_duration_since(entry.stored);
        if age < entry.ttl {
            let left = (entry.ttl - age).as_secs().max(1) as u32;
            return match reply_from(&entry.response, query, question_end, Some(left)) {
                Some(reply) => Lookup::Fresh(reply),
                None => Lookup::Miss,
            };
        }
        if age < entry.ttl + STALE_WINDOW {
            return match reply_from(&entry.response, query, question_end, Some(STALE_TTL)) {
                Some(reply) => Lookup::Stale(reply),
                None => Lookup::Miss,
            };
        }
        self.entries.remove(key);
        Lookup::Miss
    }

    /// Keeps `response` for `key` when it is a cacheable answer to `question`.
    pub fn insert(&mut self, key: CacheKey, question: &Question, response: &[u8], now: Instant) {
        let Some(ttl) = cacheable_ttl(response, question) else {
            return;
        };
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
            self.evict(now);
        }
        self.entries.insert(
            key,
            Entry {
                response: response.to_vec(),
                stored: now,
                ttl,
            },
        );
    }

    /// Drops answers past their stale window; if none are, the one that
    /// expires first.
    fn evict(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.stored) < entry.ttl + STALE_WINDOW
        });
        if self.entries.len() < MAX_ENTRIES {
            return;
        }
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.stored + entry.ttl)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Starts an exchange for `key`, or joins `waiter` (if any) to the one in
    /// flight. `true` when the caller should send the query.
    pub fn begin(&mut self, key: &CacheKey, waiter: Option<Waiter>) -> bool {
        if let Some(waiters) = self.inflight.get_mut(key) {
            if let Some(waiter) = waiter {
                if waiters.len() < MAX_WAITERS {
                    waiters.push(waiter);
                }
            }
            return false;
        }
        self.inflight.insert(key.clone(), Vec::new());
        true
    }

    /// Ends the exchange for `key` and returns the queries that waited on it.
    pub fn finish(&mut self, key: &CacheKey) -> Vec<Waiter> {
        self.inflight.remove(key).unwrap_or_default()
    }
}

/// `response` turned into a reply to `query`: its id and question bytes, and
/// (with `ttl`) every record's TTL set to it. `None` if the question
/// sections differ in length (another name) or the response does not walk.
pub fn reply_from(
    response: &[u8],
    query: &[u8],
    question_end: usize,
    ttl: Option<u32>,
) -> Option<Vec<u8>> {
    if question_end > query.len() || question_end > response.len() || question_end < HEADER_LEN {
        return None;
    }
    let mut reply = response.to_vec();
    reply[..2].copy_from_slice(&query[..2]);
    // The question with the asker's letter case; names later in the message
    // point at offsets inside it, which stay where they were.
    reply[HEADER_LEN..question_end].copy_from_slice(&query[HEADER_LEN..question_end]);
    let offsets = record_ttl_offsets(&reply)?;
    if let Some(ttl) = ttl {
        for at in offsets {
            reply[at..at + 4].copy_from_slice(&ttl.to_be_bytes());
        }
    }
    Some(reply)
}

/// How long `response` may be kept as the answer to `question`, or `None`
/// if it may not.
pub fn cacheable_ttl(response: &[u8], question: &Question) -> Option<Duration> {
    if response.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xF;
    let truncated = flags & 0x0200 != 0;
    let rcode = flags & 0xF;
    if !is_response || opcode != 0 || truncated || !(rcode == 0 || rcode == 3) {
        return None;
    }
    let asked = crate::dns::question(&as_query(response))?;
    if asked.name != question.name || asked.qtype != question.qtype || asked.end != question.end {
        return None;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let records = records(response)?;
    let ttl = records
        .iter()
        .filter(|record| record.section < 2 && record.rtype != TYPE_OPT)
        .map(|record| record.ttl)
        .min();
    let negative = rcode == 3 || ancount == 0;
    let ttl = Duration::from_secs(u64::from(ttl.unwrap_or(0)));
    Some(if negative {
        ttl.clamp(MIN_TTL, MAX_NEGATIVE_TTL)
    } else {
        ttl.clamp(MIN_TTL, MAX_TTL)
    })
}

/// The first address `response` gives for `question` (an A or AAAA
/// question), with how long it may be kept; `None` for an error, a reply to
/// another question or no address.
pub fn first_address(response: &[u8], question: &Question) -> Option<(IpAddr, Duration)> {
    let ttl = cacheable_ttl(response, question)?;
    if response[3] & 0xF != 0 {
        return None;
    }
    records(response)?
        .into_iter()
        .filter(|record| record.section == 0 && record.rtype == question.qtype)
        .find_map(|record| {
            let data = response.get(record.data_at..record.data_at + record.data_len)?;
            match (record.rtype, data.len()) {
                (crate::dns::TYPE_A, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
                (crate::dns::TYPE_AAAA, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
                _ => None,
            }
        })
        .map(|address| (address, ttl))
}

/// A copy of `response` with the QR bit clear, so the question parser takes it.
fn as_query(response: &[u8]) -> Vec<u8> {
    let mut query = response.to_vec();
    query[2] &= 0x07;
    query[3] = 0;
    query
}

struct Record {
    /// 0 answer, 1 authority, 2 additional.
    section: u8,
    rtype: u16,
    ttl: u32,
    ttl_at: usize,
    /// Where the record's data starts, and its length.
    data_at: usize,
    data_len: usize,
}

fn record_ttl_offsets(message: &[u8]) -> Option<Vec<usize>> {
    Some(
        records(message)?
            .into_iter()
            .filter(|record| record.rtype != TYPE_OPT)
            .map(|record| record.ttl_at)
            .collect(),
    )
}

/// Walks every resource record of `message`.
fn records(message: &[u8]) -> Option<Vec<Record>> {
    let count = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
    if message.len() < HEADER_LEN {
        return None;
    }
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut at = HEADER_LEN;
    for _ in 0..qd {
        at = skip_name(message, at)? + 4;
    }
    let mut out = Vec::with_capacity(usize::from(an) + usize::from(ns) + usize::from(ar));
    for (section, n) in [(0u8, an), (1, ns), (2, ar)] {
        for _ in 0..n {
            at = skip_name(message, at)?;
            let fixed = message.get(at..at + 10)?;
            let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
            let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
            let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
            out.push(Record {
                section,
                rtype,
                ttl,
                ttl_at: at + 4,
                data_at: at + 10,
                data_len: rdlength,
            });
            at += 10 + rdlength;
            if at > message.len() {
                return None;
            }
        }
    }
    Some(out)
}

/// The offset just past the name at `at`.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *message.get(at)?;
        match length {
            0 => return Some(at + 1),
            l if l & 0xC0 == 0xC0 => {
                message.get(at + 1)?;
                return Some(at + 2);
            }
            l if l > 63 => return None,
            l => at += 1 + usize::from(l),
        }
    }
}

/// Idle upstream connections, per server and outbound.
#[derive(Default)]
pub struct UpstreamPool {
    idle: HashMap<PoolKey, Vec<(BoxStream, Instant)>>,
}

/// A server index and the outbound (by address) its connections run through.
pub type PoolKey = (usize, usize);

/// Idle connections kept per key.
pub const MAX_IDLE_PER_UPSTREAM: usize = 4;
/// An idle connection older than this is not reused (servers close idle
/// DoT / DoH connections after 10–60 s).
pub const MAX_IDLE: Duration = Duration::from_secs(20);

impl UpstreamPool {
    pub fn take(&mut self, key: PoolKey, now: Instant) -> Option<BoxStream> {
        let idle = self.idle.get_mut(&key)?;
        while let Some((stream, since)) = idle.pop() {
            if now.saturating_duration_since(since) < MAX_IDLE {
                return Some(stream);
            }
        }
        None
    }

    pub fn put(&mut self, key: PoolKey, stream: BoxStream, now: Instant) {
        let idle = self.idle.entry(key).or_default();
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < MAX_IDLE);
        if idle.len() < MAX_IDLE_PER_UPSTREAM {
            idle.push((stream, now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &[u8]) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        query
    }

    /// An answer to `query` with one A record of `ttl` and an OPT record.
    fn answer(query: &[u8], ttl: u32, rcode: u8) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response[3] = 0x80 | rcode;
        response[7] = 1; // ancount
        response[11] = 1; // arcount
        response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&[0, 4, 93, 184, 216, 34]);
        // OPT: root name, type 41, payload size 1232, ext-rcode/flags 0.
        response.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        response
    }

    fn key(name: &str) -> CacheKey {
        CacheKey {
            name: name.into(),
            qtype: 1,
            server: 0,
            proxied: true,
        }
    }

    #[test]
    fn answers_are_served_with_the_askers_id_and_case() {
        let first = query(0x1111, b"\x07example\x03com\x00");
        let question = crate::dns::question(&first).unwrap();
        let mut cache = DnsCache::default();
        let now = Instant::now();
        cache.insert(key("example.com"), &question, &answer(&first, 300, 0), now);

        let second = query(0x2222, b"\x07ExAmPlE\x03com\x00");
        let Lookup::Fresh(reply) = cache.lookup(
            &key("example.com"),
            &second,
            question.end,
            now + Duration::from_secs(100),
        ) else {
            panic!("fresh");
        };
        assert_eq!(&reply[..2], &[0x22, 0x22]);
        assert_eq!(&reply[12..question.end], &second[12..]);
        let ttl_at = question.end + 6;
        assert_eq!(&reply[ttl_at..ttl_at + 4], &200u32.to_be_bytes());
        // The OPT record's TTL field (extended flags) is untouched.
        assert_eq!(&reply[reply.len() - 6..reply.len() - 2], &[0, 0, 0, 0]);
    }

    #[test]
    fn expired_answers_are_stale_then_gone() {
        let q = query(1, b"\x01a\x00");
        let question = crate::dns::question(&q).unwrap();
        let mut cache = DnsCache::default();
        let now = Instant::now();
        cache.insert(key("a"), &question, &answer(&q, 5, 0), now);
        // Clamped up to the 30 s floor.
        assert!(matches!(
            cache.lookup(&key("a"), &q, question.end, now + Duration::from_secs(20)),
            Lookup::Fresh(_)
        ));
        let Lookup::Stale(reply) =
            cache.lookup(&key("a"), &q, question.end, now + Duration::from_secs(40))
        else {
            panic!("stale");
        };
        let ttl_at = question.end + 6;
        assert_eq!(&reply[ttl_at..ttl_at + 4], &STALE_TTL.to_be_bytes());
        assert_eq!(
            cache.lookup(&key("a"), &q, question.end, now + MIN_TTL + STALE_WINDOW),
            Lookup::Miss
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn only_standard_answers_are_kept() {
        let q = query(1, b"\x01a\x00");
        let question = crate::dns::question(&q).unwrap();
        let ok = answer(&q, 600, 0);
        assert_eq!(
            cacheable_ttl(&ok, &question),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            cacheable_ttl(&answer(&q, 86_400, 0), &question),
            Some(MAX_TTL)
        );
        assert_eq!(
            cacheable_ttl(&answer(&q, 600, 3), &question),
            Some(MAX_NEGATIVE_TTL)
        );
        assert_eq!(
            cacheable_ttl(&answer(&q, 600, 2), &question),
            None,
            "SERVFAIL"
        );
        let mut truncated = ok.clone();
        truncated[2] |= 0x02;
        assert_eq!(cacheable_ttl(&truncated, &question), None);
        let other = query(1, b"\x01b\x00");
        assert_eq!(cacheable_ttl(&answer(&other, 600, 0), &question), None);
        assert_eq!(
            cacheable_ttl(&ok[..ok.len() - 3], &question),
            None,
            "cut short"
        );
        assert_eq!(cacheable_ttl(&q, &question), None, "not a response");
    }

    #[test]
    fn queries_join_the_exchange_in_flight() {
        let mut cache = DnsCache::default();
        let waiter = Waiter {
            query: vec![0; 12],
            question_end: 12,
            app: "10.0.0.2:5353".parse().unwrap(),
            resolver: "10.0.0.1:53".parse().unwrap(),
        };
        assert!(cache.begin(&key("a"), None));
        assert!(!cache.begin(&key("a"), Some(waiter.clone())));
        assert!(!cache.begin(&key("a"), Some(waiter)));
        assert_eq!(cache.finish(&key("a")).len(), 2);
        assert!(cache.begin(&key("a"), None));
    }

    #[test]
    fn a_full_cache_evicts() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        for i in 0..=MAX_ENTRIES {
            let name = format!("n{i}");
            let mut wire = vec![name.len() as u8];
            wire.extend_from_slice(name.as_bytes());
            wire.push(0);
            let q = query(1, &wire);
            let question = crate::dns::question(&q).unwrap();
            cache.insert(key(&name), &question, &answer(&q, 60 + i as u32, 0), now);
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert_eq!(
            cache.lookup(&key("n0"), &query(1, b"\x02n0\x00"), 20, now),
            Lookup::Miss,
            "the answer expiring first went"
        );
    }
}
