//! Each user's traffic by destination, for the panel's destination
//! statistics (anix-agent's `destinations.v1`).
//!
//! A relayed TCP connection of a user opens one [`DestinationGuard`] on its
//! first byte, keyed by the destination host and the sniffed protocol, and
//! adds its bytes to it until it ends. The host is the domain the client
//! asked for; for an address target, the TLS SNI or HTTP `Host` of the
//! client's first bytes when there is one, else the address. The agent
//! reads and resets the counters once per report window
//! (`GET /v1/inbounds/{tag}/destinations?reset=true`) and folds hosts into
//! registrable domains itself.
//!
//! UDP flows ([`UdpDestinations`]) count the same way per target, over
//! `quic` when the client's first datagram is a QUIC Initial and `udp`
//! otherwise. For an address target the SNI of the QUIC ClientHello
//! ([`crate::quic`]) names the host; until it shows (at most a few
//! datagrams) the flow's bytes wait. Replies are charged to the flow whose
//! address they come from, else to the session's last flow.
//!
//! TCP sessions of a Mux.Cool connection count like connections, its UDP
//! sessions like flows.
//!
//! A user keeps at most [`MAX_PER_USER`] hosts in a window; the bytes of
//! further hosts count under an empty host ("other").

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use engine_outbound::{sniff, TargetAddr};
use serde::{Deserialize, Serialize};

use crate::quic::{self, QuicHello, Sniffed};
use crate::UserEntry;

/// Hosts one user keeps in a window before the rest count as "other".
pub const MAX_PER_USER: usize = 256;
/// Longest host kept; a longer one counts as "other".
const MAX_HOST_LENGTH: usize = 253;

/// One user's traffic to one host over one protocol since the last reset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationTraffic {
    /// The user's name.
    pub name: String,
    /// The domain or address; empty for hosts beyond [`MAX_PER_USER`].
    pub host: String,
    /// `tls`, `http`, `bittorrent`, or empty when the first bytes tell
    /// nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// Client to server.
    pub up: u64,
    /// Server to client.
    pub down: u64,
    /// Connections opened in the window.
    pub connections: u64,
}

#[derive(Default)]
struct Stat {
    up: AtomicU64,
    down: AtomicU64,
    connections: AtomicU64,
    /// Open connections; changed under the table lock only.
    open: AtomicU64,
}

type Key = (String, &'static str);

/// The destinations of one user.
#[derive(Default)]
pub(crate) struct Destinations {
    stats: Mutex<HashMap<Key, Arc<Stat>>>,
}

impl Destinations {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Arc<Stat>>> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Counts one connection to `host` over `protocol`.
    pub(crate) fn open(self: &Arc<Self>, host: String, protocol: &'static str) -> DestinationGuard {
        let mut stats = self.lock();
        let host = if host.len() > MAX_HOST_LENGTH
            || (stats.len() >= MAX_PER_USER && !stats.contains_key(&(host.clone(), protocol)))
        {
            String::new()
        } else {
            host
        };
        let stat = stats.entry((host, protocol)).or_default().clone();
        stat.connections.fetch_add(1, Ordering::Relaxed);
        stat.open.fetch_add(1, Ordering::Relaxed);
        DestinationGuard {
            table: self.clone(),
            stat,
        }
    }

    /// The traffic of every destination with a byte or a connection. With
    /// `reset` the counters restart and destinations without open
    /// connections are dropped, so the next window starts empty.
    pub(crate) fn traffic(&self, name: &str, reset: bool, out: &mut Vec<DestinationTraffic>) {
        let mut stats = self.lock();
        for ((host, protocol), stat) in stats.iter() {
            let (up, down, connections) = if reset {
                (
                    stat.up.swap(0, Ordering::Relaxed),
                    stat.down.swap(0, Ordering::Relaxed),
                    stat.connections.swap(0, Ordering::Relaxed),
                )
            } else {
                (
                    stat.up.load(Ordering::Relaxed),
                    stat.down.load(Ordering::Relaxed),
                    stat.connections.load(Ordering::Relaxed),
                )
            };
            if up == 0 && down == 0 && connections == 0 {
                continue;
            }
            out.push(DestinationTraffic {
                name: name.to_owned(),
                host: host.clone(),
                protocol: (*protocol).to_owned(),
                up,
                down,
                connections,
            });
        }
        if reset {
            stats.retain(|_, stat| stat.open.load(Ordering::Relaxed) > 0);
        }
    }
}

/// One open connection's share of a destination; ends it when dropped.
pub(crate) struct DestinationGuard {
    table: Arc<Destinations>,
    stat: Arc<Stat>,
}

impl DestinationGuard {
    pub(crate) fn add_up(&self, bytes: u64) {
        self.stat.up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, bytes: u64) {
        self.stat.down.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for DestinationGuard {
    fn drop(&mut self) {
        let _stats = self.table.lock();
        self.stat.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The destination of one relayed byte stream (a TCP connection or a
/// Mux.Cool TCP session) of a user: the target until the first byte decides
/// it, then its counters.
pub(crate) enum StreamDestination {
    Pending(Arc<UserEntry>, Option<TargetAddr>),
    Counting(DestinationGuard),
    None,
}

impl StreamDestination {
    pub(crate) fn new(user: Option<&Arc<UserEntry>>, target: Option<&TargetAddr>) -> Self {
        match user {
            Some(user) => Self::Pending(user.clone(), target.cloned()),
            None => Self::None,
        }
    }

    /// Charges `first.len()` client bytes; the first ones decide.
    pub(crate) fn up(&mut self, first: &[u8]) {
        if let Some(guard) = self.decide(first) {
            guard.add_up(first.len() as u64);
        }
    }

    /// Charges `bytes` sent to the client.
    pub(crate) fn down(&mut self, bytes: u64) {
        if bytes > 0 {
            if let Some(guard) = self.decide(&[]) {
                guard.add_down(bytes);
            }
        }
    }

    fn decide(&mut self, first: &[u8]) -> Option<&DestinationGuard> {
        if let Self::Pending(user, target) = self {
            *self = match host_of(target.as_ref(), first) {
                Some(host) => Self::Counting(user.open_destination(host, protocol_of(first))),
                None => Self::None,
            };
        }
        match self {
            Self::Counting(guard) => Some(guard),
            _ => None,
        }
    }
}

/// Flows one UDP session tracks; the rest count as "other".
const MAX_FLOWS: usize = 64;

/// The destinations of one user's UDP session: a flow per target.
pub(crate) struct UdpDestinations {
    user: Option<Arc<UserEntry>>,
    flows: HashMap<TargetAddr, Flow>,
    /// The flow of each address target, for replies.
    by_source: HashMap<SocketAddr, TargetAddr>,
    last: Option<TargetAddr>,
    other: Option<DestinationGuard>,
}

enum Flow {
    /// Waiting for the SNI of a QUIC ClientHello to an address.
    Sniffing {
        hello: QuicHello,
        address: String,
        up: u64,
        down: u64,
    },
    Counting(DestinationGuard),
}

impl UdpDestinations {
    pub(crate) fn new(user: Option<Arc<UserEntry>>) -> Self {
        Self {
            user,
            flows: HashMap::new(),
            by_source: HashMap::new(),
            last: None,
            other: None,
        }
    }

    /// Charges a client datagram to `target`.
    pub(crate) fn up(&mut self, target: &TargetAddr, payload: &[u8]) {
        let Some(user) = &self.user else {
            return;
        };
        let bytes = payload.len() as u64;
        if !self.flows.contains_key(target) {
            if self.flows.len() >= MAX_FLOWS {
                let other = self
                    .other
                    .get_or_insert_with(|| user.open_destination(String::new(), "udp"));
                other.add_up(bytes);
                return;
            }
            let protocol = if quic::is_initial(payload) {
                "quic"
            } else {
                "udp"
            };
            let flow = match target {
                TargetAddr::Domain(..) => match host_of(Some(target), &[]) {
                    Some(host) => Flow::Counting(user.open_destination(host, protocol)),
                    None => return,
                },
                TargetAddr::Ip(address) => {
                    let source = SocketAddr::new(canonical(address.ip()), address.port());
                    self.by_source.insert(source, target.clone());
                    let host = canonical(address.ip()).to_string();
                    if protocol == "quic" {
                        Flow::Sniffing {
                            hello: QuicHello::default(),
                            address: host,
                            up: 0,
                            down: 0,
                        }
                    } else {
                        Flow::Counting(user.open_destination(host, protocol))
                    }
                }
            };
            self.flows.insert(target.clone(), flow);
        }
        self.last = Some(target.clone());
        let Some(flow) = self.flows.get_mut(target) else {
            return;
        };
        let decided = match flow {
            Flow::Counting(guard) => {
                guard.add_up(bytes);
                None
            }
            Flow::Sniffing {
                hello,
                address,
                up,
                down,
            } => {
                *up += bytes;
                let host = match hello.push(payload) {
                    Sniffed::Pending => return,
                    Sniffed::Name(name) => name,
                    Sniffed::None => std::mem::take(address),
                };
                let guard = user.open_destination(host, "quic");
                guard.add_up(*up);
                guard.add_down(*down);
                Some(guard)
            }
        };
        if let Some(guard) = decided {
            *flow = Flow::Counting(guard);
        }
    }

    /// Charges a reply datagram from `source`.
    pub(crate) fn down(&mut self, source: SocketAddr, bytes: u64) {
        if self.user.is_none() {
            return;
        }
        let source = SocketAddr::new(canonical(source.ip()), source.port());
        let key = self.by_source.get(&source).or(self.last.as_ref());
        match key.and_then(|key| self.flows.get_mut(key)) {
            Some(Flow::Counting(guard)) => guard.add_down(bytes),
            Some(Flow::Sniffing { down, .. }) => *down += bytes,
            None => {
                if let Some(other) = &self.other {
                    other.add_down(bytes);
                }
            }
        }
    }
}

/// The protocol the client's first bytes show, `""` when they show none.
pub(crate) fn protocol_of(first: &[u8]) -> &'static str {
    if first.len() >= 20 && first[0] == 19 && &first[1..20] == b"BitTorrent protocol" {
        "bittorrent"
    } else if first.len() >= 3 && first[0] == 0x16 && first[1] == 0x03 {
        "tls"
    } else if sniff::http_host(first).is_some() {
        "http"
    } else {
        ""
    }
}

/// The host a connection to `target` counts under: the domain the client
/// asked for, else the name its first bytes announce, else the address.
pub(crate) fn host_of(target: Option<&TargetAddr>, first: &[u8]) -> Option<String> {
    if let Some(TargetAddr::Domain(domain, _)) = target {
        return normalize(domain);
    }
    if let Some(host) = sniff::host(first).and_then(|host| normalize(&host)) {
        return Some(host);
    }
    match target {
        Some(TargetAddr::Ip(address)) => Some(canonical(address.ip()).to_string()),
        _ => None,
    }
}

fn normalize(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(address) => Some(canonical(address).to_string()),
        Err(_) => Some(host),
    }
}

fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(table: &Destinations, reset: bool) -> Vec<DestinationTraffic> {
        let mut out = Vec::new();
        table.traffic("u", reset, &mut out);
        out.sort_by(|a, b| (&a.host, &a.protocol).cmp(&(&b.host, &b.protocol)));
        out
    }

    #[test]
    fn counts_bytes_and_connections_per_host_and_protocol() {
        let table = Arc::new(Destinations::default());
        let a = table.open("example.com".into(), "tls");
        let b = table.open("example.com".into(), "tls");
        a.add_up(10);
        b.add_down(20);
        let c = table.open("example.com".into(), "");
        c.add_down(5);
        let got = snapshot(&table, false);
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].protocol.as_str(), got[0].down, got[0].connections),
            ("", 5, 1)
        );
        assert_eq!(
            (
                got[1].protocol.as_str(),
                got[1].up,
                got[1].down,
                got[1].connections
            ),
            ("tls", 10, 20, 2)
        );
    }

    #[test]
    fn a_reset_keeps_open_destinations_and_drops_closed_ones() {
        let table = Arc::new(Destinations::default());
        let open = table.open("open.example".into(), "");
        let closed = table.open("closed.example".into(), "");
        open.add_up(1);
        closed.add_up(1);
        drop(closed);
        assert_eq!(snapshot(&table, true).len(), 2);
        assert!(snapshot(&table, false).is_empty());
        assert_eq!(table.lock().len(), 1);
        open.add_down(7);
        let got = snapshot(&table, true);
        assert_eq!(
            (got[0].host.as_str(), got[0].down, got[0].connections),
            ("open.example", 7, 0)
        );
    }

    #[test]
    fn hosts_beyond_the_cap_count_as_other() {
        let table = Arc::new(Destinations::default());
        let guards: Vec<_> = (0..MAX_PER_USER + 3)
            .map(|i| table.open(format!("h{i}.example"), ""))
            .collect();
        let got = snapshot(&table, false);
        assert_eq!(got.len(), MAX_PER_USER + 1);
        let other = got.iter().find(|entry| entry.host.is_empty()).unwrap();
        assert_eq!(other.connections, 3);
        drop(guards);
    }

    #[test]
    fn hosts_come_from_the_target_then_the_first_bytes() {
        let domain = TargetAddr::Domain("WWW.Example.COM.".into(), 443);
        assert_eq!(
            host_of(Some(&domain), b"").as_deref(),
            Some("www.example.com")
        );
        let address = TargetAddr::Ip("[::ffff:198.51.100.7]:80".parse().unwrap());
        assert_eq!(
            host_of(Some(&address), b"").as_deref(),
            Some("198.51.100.7")
        );
        let request = b"GET / HTTP/1.1\r\nHost: Video.Example:8080\r\n\r\n";
        assert_eq!(
            host_of(Some(&address), request).as_deref(),
            Some("video.example")
        );
        assert_eq!(protocol_of(request), "http");
        assert_eq!(protocol_of(&[0x16, 0x03, 0x01, 0x00]), "tls");
        assert_eq!(protocol_of(b"\x13BitTorrent protocol"), "bittorrent");
        assert_eq!(protocol_of(b"SSH-2.0"), "");
        assert_eq!(host_of(None, b"SSH-2.0"), None);
    }
}
