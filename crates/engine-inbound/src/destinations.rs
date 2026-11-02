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
//! A user keeps at most [`MAX_PER_USER`] hosts in a window; the bytes of
//! further hosts count under an empty host ("other"). Mux.Cool sessions and
//! UDP are not counted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use engine_outbound::{sniff, TargetAddr};
use serde::{Deserialize, Serialize};

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
