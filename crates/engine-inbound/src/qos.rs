//! Traffic priorities: a connection's class (high, normal or low) from its
//! destination, and the scheduling that makes lower classes yield when the
//! node's link or a user's speed limit is full.
//!
//! The panel classifies traffic into categories (video, download, ...),
//! gives each a priority and may cap some destinations per user (Steam
//! downloads at 5 Mbit/s); the agent sends the domains, networks and
//! protocols of each class as a [`QosConfig`] (`PUT /v1/qos`). A connection
//! is classed when it is relayed:
//!
//! 1. a sniffed protocol of the client's first bytes with a class
//!    (`bittorrent`);
//! 2. the longest class domain the target's name, or the TLS SNI / HTTP
//!    `Host` of the client's first bytes, ends with;
//! 3. the most specific class network containing an address target;
//! 4. anything else is normal, without a cap.
//!
//! A class with [`QosClass::limit_mbps`] holds each user's connections of
//! the class to that rate together (connections without a user share one
//! limit), on top of the user's own speed limit.
//!
//! Only the download direction (bytes written to the client) is scheduled.
//! Every [`Scheduler`] measures each class's rate over short windows and
//! lets a class use what the classes above it leave of its capacity,
//! [`QosConfig::min_share_percent`] at least: idle, a low class runs at the
//! full capacity; when high traffic needs the link, low traffic backs off
//! within a few windows. High traffic is never held. Two schedulers apply:
//! the node's, with [`QosConfig::egress_mbps`] as capacity (none when 0),
//! and each user's with a speed limit, the limit as capacity.
//!
//! The policy is process-wide ([`set`], [`current`]): a kernel serves one
//! node. Connections keep the class and policy they started with. Mux.Cool
//! sessions and UDP are not scheduled.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use engine_outbound::{sniff, TargetAddr};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::limit::RateLimiter;

/// Most domains and networks a configuration may hold.
pub const MAX_ENTRIES: usize = 500_000;
/// Length of a measuring window.
const WINDOW: Duration = Duration::from_millis(100);
/// Share of the capacity the classes aim at together, leaving room for the
/// higher classes to grow into.
const TARGET_UTILIZATION: f64 = 0.95;
/// Longest single wait.
const MAX_WAIT: Duration = Duration::from_millis(500);
const DEFAULT_MIN_SHARE_PERCENT: u8 = 10;

fn normal() -> Priority {
    Priority::Normal
}

/// A connection's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    Normal,
    Low,
}

impl Priority {
    fn index(self) -> usize {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
        }
    }
}

/// `PUT /v1/qos`. `{}` turns priorities off. Unknown fields are ignored so
/// a newer agent can add some.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct QosConfig {
    /// The node's download capacity in Mbit/s, for the node-wide
    /// scheduling; 0 schedules within the users' speed limits only.
    #[serde(default)]
    pub egress_mbps: u64,
    /// The least share of a capacity a lower class keeps, 1 to 90; 0 means
    /// the default, 10.
    #[serde(default)]
    pub min_share_percent: u8,
    /// The destinations of the high and low classes; the rest is normal.
    #[serde(default)]
    pub classes: Vec<QosClass>,
}

/// The destinations of one class.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct QosClass {
    /// The panel's name for the class, for status answers.
    #[serde(default)]
    pub name: String,
    #[serde(default = "normal")]
    pub priority: Priority,
    /// Each user's cap on the class's download, Mbit/s; 0 for none.
    #[serde(default)]
    pub limit_mbps: u64,
    /// Names; each also matches its subdomains.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Addresses or CIDRs.
    #[serde(default)]
    pub networks: Vec<String>,
    /// Sniffed protocols: `bittorrent`, `tls`, `http`.
    #[serde(default)]
    pub protocols: Vec<String>,
}

/// A sniffed protocol a class can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Protocol {
    BitTorrent,
    Http,
    Tls,
}

impl Protocol {
    fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "bittorrent" | "bt" => Ok(Self::BitTorrent),
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            other => Err(format!(
                "unknown protocol {other:?} (bittorrent, http or tls)"
            )),
        }
    }

    fn of(first: &[u8]) -> Option<Self> {
        if first.len() >= 20 && first[0] == 19 && &first[1..20] == b"BitTorrent protocol" {
            Some(Self::BitTorrent)
        } else if first.len() >= 3 && first[0] == 0x16 && first[1] == 0x03 {
            Some(Self::Tls)
        } else if sniff::http_host(first).is_some() {
            Some(Self::Http)
        } else {
            None
        }
    }
}

/// A compiled [`QosConfig`].
pub struct Policy {
    config: QosConfig,
    /// The class index of each rule.
    domains: HashMap<String, usize>,
    /// Network rules by prefix length, longest first.
    networks: Vec<(u8, HashMap<IpAddr, usize>)>,
    protocols: HashMap<Protocol, usize>,
    min_share: f64,
    node: Option<Scheduler>,
    /// Each capped class's limiters by user name ("" without a user).
    limits: Vec<Mutex<HashMap<String, Arc<RateLimiter>>>>,
    /// The schedulers of the users with a speed limit, by name.
    users: Mutex<HashMap<String, Arc<Scheduler>>>,
}

/// Most users a policy keeps limiters and schedulers for; beyond it the
/// tables start over.
const MAX_TRACKED_USERS: usize = 100_000;

impl Policy {
    /// Checks and compiles `config`; nothing applies when an entry is
    /// invalid.
    pub fn compile(config: &QosConfig) -> Result<Self, String> {
        let entries: usize = config
            .classes
            .iter()
            .map(|class| class.domains.len() + class.networks.len())
            .sum();
        if entries > MAX_ENTRIES {
            return Err(format!("qos: at most {MAX_ENTRIES} domains and networks"));
        }
        let min_share_percent = match config.min_share_percent {
            0 => DEFAULT_MIN_SHARE_PERCENT,
            percent @ 1..=90 => percent,
            _ => return Err("qos: min_share_percent must be between 1 and 90".into()),
        };
        let mut domains = HashMap::new();
        let mut networks: HashMap<u8, HashMap<IpAddr, usize>> = HashMap::new();
        let mut protocols = HashMap::new();
        for (index, class) in config.classes.iter().enumerate() {
            for domain in &class.domains {
                let name = normalize_domain(domain)
                    .ok_or_else(|| format!("qos: invalid domain {domain:?}"))?;
                domains.insert(name, index);
            }
            for network in &class.networks {
                let (address, bits) = parse_network(network)
                    .ok_or_else(|| format!("qos: invalid network {network:?}"))?;
                networks.entry(bits).or_default().insert(address, index);
            }
            for name in &class.protocols {
                protocols.insert(
                    Protocol::parse(name).map_err(|message| format!("qos: {message}"))?,
                    index,
                );
            }
        }
        let mut networks: Vec<_> = networks.into_iter().collect();
        networks.sort_by(|a, b| b.0.cmp(&a.0));
        let min_share = f64::from(min_share_percent) / 100.0;
        Ok(Self {
            config: config.clone(),
            domains,
            networks,
            protocols,
            min_share,
            node: Scheduler::from_mbps(config.egress_mbps, min_share),
            limits: config.classes.iter().map(|_| Mutex::default()).collect(),
            users: Mutex::default(),
        })
    }

    /// The priority of a class index, normal for none.
    fn priority_of(&self, class: Option<usize>) -> Priority {
        class
            .and_then(|index| self.config.classes.get(index))
            .map_or(Priority::Normal, |class| class.priority)
    }

    /// The limiter of `user` in a capped class.
    fn limiter(&self, class: usize, user: &str) -> Option<Arc<RateLimiter>> {
        let mbps = self.config.classes.get(class)?.limit_mbps;
        let mut limiters = self
            .limits
            .get(class)?
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(limiter) = limiters.get(user) {
            return Some(limiter.clone());
        }
        if limiters.len() >= MAX_TRACKED_USERS {
            limiters.clear();
        }
        let limiter = Arc::new(RateLimiter::from_mbps(mbps)?);
        limiters.insert(user.to_string(), limiter.clone());
        Some(limiter)
    }

    /// The scheduler of a user with a speed limit of `mbps`.
    fn user_scheduler(&self, user: &str, mbps: u64) -> Option<Arc<Scheduler>> {
        let capacity = mbps.saturating_mul(1_000_000 / 8) as f64;
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(scheduler) = users.get(user).filter(|s| s.capacity == capacity) {
            return Some(scheduler.clone());
        }
        if users.len() >= MAX_TRACKED_USERS {
            users.clear();
        }
        let scheduler = Arc::new(Scheduler::from_mbps(mbps, self.min_share)?);
        users.insert(user.to_string(), scheduler.clone());
        Some(scheduler)
    }

    /// The node scheduler's state and each class's rules, for `GET
    /// /v1/qos`.
    pub fn status(&self) -> QosStatus {
        QosStatus {
            active: self.is_active(),
            egress_mbps: self.config.egress_mbps,
            node: self.node.as_ref().map(Scheduler::status),
            classes: self
                .config
                .classes
                .iter()
                .map(|class| QosClassStatus {
                    name: class.name.clone(),
                    priority: class.priority,
                    limit_mbps: class.limit_mbps,
                    domains: class.domains.len(),
                    networks: class.networks.len(),
                    protocols: class.protocols.len(),
                })
                .collect(),
        }
    }

    /// The configuration it was compiled from.
    pub fn config(&self) -> &QosConfig {
        &self.config
    }

    /// Whether any destination has a class other than normal.
    pub fn is_active(&self) -> bool {
        !(self.domains.is_empty() && self.networks.is_empty() && self.protocols.is_empty())
    }

    /// The node's scheduler, `None` without a capacity.
    pub fn node(&self) -> Option<&Scheduler> {
        self.node.as_ref()
    }

    /// The least share of a capacity a lower class keeps.
    pub fn min_share(&self) -> f64 {
        self.min_share
    }

    /// The class of a target by its name or address: `Some(None)` for a
    /// name no rule names (normal), `None` when the target does not decide
    /// it (an address no network names, whose first bytes may still show
    /// a name).
    pub fn classify_target(&self, target: &TargetAddr) -> Option<Option<usize>> {
        match target {
            TargetAddr::Domain(host, _) => Some(self.classify_host(host)),
            TargetAddr::Ip(address) => self.classify_address(address.ip()).map(Some),
        }
    }

    /// The priority of a target, normal when nothing decides it.
    pub fn target_priority(&self, target: &TargetAddr) -> Priority {
        self.priority_of(self.classify_target(target).flatten())
    }

    /// The class from the client's first bytes: their protocol, then the
    /// name they carry; `None` when they decide nothing.
    pub fn classify_first(&self, first: &[u8]) -> Option<usize> {
        if let Some(class) = Protocol::of(first).and_then(|protocol| self.protocols.get(&protocol))
        {
            return Some(*class);
        }
        sniff::host(first).and_then(|host| self.classify_host(&host))
    }

    /// The priority the first bytes give, `None` when they decide nothing.
    pub fn first_priority(&self, first: &[u8]) -> Option<Priority> {
        self.classify_first(first)
            .map(|class| self.priority_of(Some(class)))
    }

    /// Whether the first bytes can change a class the target decided: only
    /// with protocol rules.
    pub fn sniffs_protocols(&self) -> bool {
        !self.protocols.is_empty()
    }

    fn classify_host(&self, host: &str) -> Option<usize> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Ok(address) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            return self.classify_address(address);
        }
        let mut name = host.as_str();
        loop {
            if let Some(class) = self.domains.get(name) {
                return Some(*class);
            }
            match name.find('.') {
                Some(dot) => name = &name[dot + 1..],
                None => return None,
            }
        }
    }

    fn classify_address(&self, address: IpAddr) -> Option<usize> {
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
            v4 => v4,
        };
        for (bits, rules) in &self.networks {
            let Some(masked) = mask(address, *bits) else {
                continue;
            };
            if let Some(class) = rules.get(&masked) {
                return Some(*class);
            }
        }
        None
    }
}

fn normalize_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().to_ascii_lowercase();
    let domain = domain
        .trim_start_matches("*.")
        .trim_start_matches("+.")
        .trim_start_matches('.')
        .trim_end_matches('.');
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then(|| domain.to_string())
}

/// An address or CIDR as its masked address and prefix length.
fn parse_network(raw: &str) -> Option<(IpAddr, u8)> {
    let raw = raw.trim();
    let (address, bits) = match raw.split_once('/') {
        Some((address, bits)) => (address.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?),
        None => {
            let address = raw.parse::<IpAddr>().ok()?;
            let bits = if address.is_ipv4() { 32 } else { 128 };
            (address, bits)
        }
    };
    let address = match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if bits >= 96 => return Some((mask(IpAddr::V4(v4), bits - 96)?, bits - 96)),
            _ => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    Some((mask(address, bits)?, bits))
}

/// `address` with all but its first `bits` bits cleared; `None` when the
/// length does not fit the family.
fn mask(address: IpAddr, bits: u8) -> Option<IpAddr> {
    match address {
        IpAddr::V4(v4) if bits <= 32 => {
            let keep = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            Some(IpAddr::V4((u32::from(v4) & keep).into()))
        }
        IpAddr::V6(v6) if bits <= 128 => {
            let keep = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            Some(IpAddr::V6((u128::from(v6) & keep).into()))
        }
        _ => None,
    }
}

/// Lets each class use what the classes above it leave of a capacity.
pub struct Scheduler {
    capacity: f64,
    min_share: f64,
    state: Mutex<SchedulerState>,
}

struct SchedulerState {
    window_start: Instant,
    /// Bytes of each class in the current window.
    window_bytes: [u64; 3],
    /// Each class's smoothed rate, bytes per second.
    rate: [f64; 3],
    /// The token balance of the normal and low classes (negative while
    /// overdrawn) and when it was last refilled.
    tokens: [f64; 3],
    updated: Instant,
}

/// What a scheduler answers about its classes.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SchedulerStatus {
    pub capacity_bytes_per_sec: u64,
    /// Smoothed rates of the high, normal and low classes, bytes per
    /// second.
    pub high_bytes_per_sec: u64,
    pub normal_bytes_per_sec: u64,
    pub low_bytes_per_sec: u64,
}

/// `GET /v1/qos`: whether priorities apply, the node scheduler's rates
/// and each class's rule counts.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QosStatus {
    pub active: bool,
    pub egress_mbps: u64,
    pub node: Option<SchedulerStatus>,
    pub classes: Vec<QosClassStatus>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QosClassStatus {
    pub name: String,
    pub priority: Priority,
    pub limit_mbps: u64,
    pub domains: usize,
    pub networks: usize,
    pub protocols: usize,
}

impl Scheduler {
    /// A scheduler of `bytes_per_sec`; `None` for 0.
    pub fn new(bytes_per_sec: u64, min_share: f64) -> Option<Self> {
        if bytes_per_sec == 0 {
            return None;
        }
        let now = Instant::now();
        let capacity = bytes_per_sec as f64;
        Some(Self {
            capacity,
            min_share,
            state: Mutex::new(SchedulerState {
                window_start: now,
                window_bytes: [0; 3],
                rate: [0.0; 3],
                tokens: [
                    0.0,
                    capacity * WINDOW.as_secs_f64(),
                    capacity * WINDOW.as_secs_f64(),
                ],
                updated: now,
            }),
        })
    }

    /// A scheduler of `mbps` Mbit/s; `None` for 0.
    pub fn from_mbps(mbps: u64, min_share: f64) -> Option<Self> {
        Self::new(mbps.saturating_mul(1_000_000 / 8), min_share)
    }

    /// The rate `priority` may use now: what the classes above it leave of
    /// the capacity, the minimum share at least.
    fn allowance(&self, state: &SchedulerState, priority: Priority) -> f64 {
        let above: f64 = state.rate[..priority.index()].iter().sum();
        (self.capacity * TARGET_UTILIZATION - above).max(self.capacity * self.min_share)
    }

    /// Charges `bytes` that moved in `priority` and answers how long its
    /// connection should wait before moving more; high traffic never waits.
    pub fn charge(&self, priority: Priority, bytes: usize) -> Option<Duration> {
        self.charge_at(priority, bytes, Instant::now())
    }

    fn charge_at(&self, priority: Priority, bytes: usize, now: Instant) -> Option<Duration> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.saturating_duration_since(state.window_start);
        if elapsed >= WINDOW {
            let seconds = elapsed.as_secs_f64();
            let long_idle = elapsed > WINDOW * 10;
            let SchedulerState {
                window_bytes, rate, ..
            } = &mut *state;
            for (rate, bytes) in rate.iter_mut().zip(window_bytes.iter_mut()) {
                let measured = *bytes as f64 / seconds;
                // A window long past counts as idle.
                *rate = if long_idle {
                    measured
                } else {
                    0.5 * *rate + 0.5 * measured
                };
                *bytes = 0;
            }
            state.window_start = now;
        }
        let index = priority.index();
        state.window_bytes[index] += bytes as u64;
        if priority == Priority::High {
            return None;
        }
        let since = now.saturating_duration_since(state.updated).as_secs_f64();
        state.updated = now;
        let burst = self.capacity * WINDOW.as_secs_f64();
        for class in [Priority::Normal, Priority::Low] {
            let allowance = self.allowance(&state, class);
            let tokens = &mut state.tokens[class.index()];
            *tokens = (*tokens + since * allowance).min(burst);
        }
        let allowance = self.allowance(&state, priority);
        let tokens = &mut state.tokens[index];
        *tokens -= bytes as f64;
        if *tokens >= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64(-*tokens / allowance).min(MAX_WAIT))
    }

    pub fn status(&self) -> SchedulerStatus {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        SchedulerStatus {
            capacity_bytes_per_sec: self.capacity as u64,
            high_bytes_per_sec: state.rate[0] as u64,
            normal_bytes_per_sec: state.rate[1] as u64,
            low_bytes_per_sec: state.rate[2] as u64,
        }
    }
}

static POLICY: RwLock<Option<Arc<Policy>>> = RwLock::new(None);

/// Replaces the process's policy; connections already open keep theirs.
pub fn set(policy: Option<Policy>) {
    *POLICY.write().unwrap_or_else(|e| e.into_inner()) = policy.map(Arc::new);
}

/// The status of the process's policy, inactive when none is set.
pub fn status() -> QosStatus {
    match POLICY.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(policy) => policy.status(),
        None => QosStatus {
            active: false,
            egress_mbps: 0,
            node: None,
            classes: Vec::new(),
        },
    }
}

/// The process's policy, when one with classes is set.
pub fn current() -> Option<Arc<Policy>> {
    POLICY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .filter(|policy| policy.is_active())
}

/// The class state of one relayed connection's download.
pub(crate) struct Classing {
    policy: Arc<Policy>,
    /// The class index; `None` is normal.
    class: Option<usize>,
    /// Whether the client's first bytes are still to be looked at.
    sniff: bool,
    /// The limiter and the user scheduler, looked up once the class is
    /// final.
    resolved: Option<(Option<Arc<RateLimiter>>, Option<Arc<Scheduler>>)>,
}

impl Classing {
    /// The class state for a connection to `target` (`None` when the
    /// protocol does not tell), `None` without an active policy.
    pub(crate) fn start(target: Option<&TargetAddr>) -> Option<Self> {
        let policy = current()?;
        let decided = target.and_then(|target| policy.classify_target(target));
        let sniff = decided.is_none() || policy.sniffs_protocols();
        Some(Self {
            policy,
            class: decided.flatten(),
            sniff,
            resolved: None,
        })
    }

    /// Looks at the client's first bytes once.
    pub(crate) fn first_bytes(&mut self, first: &[u8]) {
        if !self.sniff || first.is_empty() {
            return;
        }
        self.sniff = false;
        if let Some(class) = self.policy.classify_first(first) {
            self.class = Some(class);
        }
    }

    pub(crate) fn priority(&self) -> Priority {
        self.policy.priority_of(self.class)
    }

    /// Charges `bytes` written to the client of `user` (name and speed
    /// limit in Mbit/s) and answers the longest wait the class's cap, the
    /// user's scheduler and the node's ask for.
    pub(crate) fn charge(&mut self, user: Option<(&str, u64)>, bytes: usize) -> Option<Duration> {
        if bytes == 0 {
            return None;
        }
        // A server-first connection never sends first bytes: its class is
        // final at its first download.
        self.sniff = false;
        let priority = self.priority();
        let (limiter, scheduler) = self.resolved.get_or_insert_with(|| {
            let name = user.map_or("", |(name, _)| name);
            let limiter = self
                .class
                .and_then(|class| self.policy.limiter(class, name));
            let scheduler = user
                .filter(|(_, mbps)| *mbps > 0)
                .and_then(|(name, mbps)| self.policy.user_scheduler(name, mbps));
            (limiter, scheduler)
        });
        let waits = [
            limiter.as_ref().and_then(|limiter| limiter.charge(bytes)),
            scheduler
                .as_ref()
                .and_then(|scheduler| scheduler.charge(priority, bytes)),
            self.policy
                .node()
                .and_then(|node| node.charge(priority, bytes)),
        ];
        waits.into_iter().flatten().max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn policy() -> Policy {
        Policy::compile(&QosConfig {
            egress_mbps: 80,
            min_share_percent: 0,
            classes: vec![
                QosClass {
                    name: "download".into(),
                    priority: Priority::Low,
                    limit_mbps: 0,
                    domains: vec!["steamcontent.com".into(), "*.Mega.NZ".into()],
                    networks: vec!["203.0.113.0/24".into()],
                    protocols: vec!["bittorrent".into()],
                },
                QosClass {
                    name: "messaging".into(),
                    priority: Priority::High,
                    limit_mbps: 0,
                    domains: vec!["zoom.us".into(), "cdn.steamcontent.com".into()],
                    networks: vec!["203.0.113.7".into()],
                    protocols: vec![],
                },
            ],
        })
        .unwrap()
    }

    fn domain(host: &str) -> TargetAddr {
        TargetAddr::Domain(host.into(), 443)
    }

    fn address(ip: &str) -> TargetAddr {
        TargetAddr::Ip(SocketAddr::new(ip.parse().unwrap(), 443))
    }

    #[test]
    fn targets_are_classed_by_the_longest_domain_and_the_most_specific_network() {
        let policy = policy();
        assert!(policy.is_active());
        let low = Priority::Low;
        let high = Priority::High;
        assert_eq!(policy.target_priority(&domain("steamcontent.com")), low);
        assert_eq!(
            policy.target_priority(&domain("a.b.steamcontent.com.")),
            low
        );
        assert_eq!(
            policy.target_priority(&domain("cdn.steamcontent.com")),
            high
        );
        assert_eq!(policy.target_priority(&domain("mega.nz")), low);
        assert_eq!(
            policy.target_priority(&domain("notmega.nz")),
            Priority::Normal
        );
        assert_eq!(
            policy.target_priority(&domain("example.com")),
            Priority::Normal
        );
        assert_eq!(policy.target_priority(&address("203.0.113.9")), low);
        assert_eq!(policy.target_priority(&address("203.0.113.7")), high);
        assert_eq!(policy.target_priority(&address("::ffff:203.0.113.9")), low);
        assert_eq!(policy.classify_target(&address("198.51.100.1")), None);
        assert_eq!(policy.classify_target(&domain("example.com")), Some(None));
    }

    #[test]
    fn first_bytes_show_the_protocol_and_the_name() {
        let policy = policy();
        let mut handshake = vec![19u8];
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0; 8]);
        assert_eq!(policy.first_priority(&handshake), Some(Priority::Low));
        assert_eq!(
            policy.first_priority(b"GET / HTTP/1.1\r\nHost: zoom.us\r\n\r\n"),
            Some(Priority::High)
        );
        assert_eq!(policy.first_priority(b"\x00\x01"), None);
    }

    #[test]
    fn invalid_entries_refuse_the_whole_config() {
        let class = |domains: Vec<&str>, networks: Vec<&str>, protocols: Vec<&str>| QosConfig {
            classes: vec![QosClass {
                name: String::new(),
                priority: Priority::Low,
                limit_mbps: 0,
                domains: domains.into_iter().map(String::from).collect(),
                networks: networks.into_iter().map(String::from).collect(),
                protocols: protocols.into_iter().map(String::from).collect(),
            }],
            ..QosConfig::default()
        };
        assert!(Policy::compile(&class(vec!["bad domain"], vec![], vec![])).is_err());
        assert!(Policy::compile(&class(vec![], vec!["10.0.0.0/33"], vec![])).is_err());
        assert!(Policy::compile(&class(vec![], vec![], vec!["quic"])).is_err());
        assert!(Policy::compile(&QosConfig {
            min_share_percent: 95,
            ..QosConfig::default()
        })
        .is_err());
        let empty = Policy::compile(&QosConfig::default()).unwrap();
        assert!(!empty.is_active());
        assert!(empty.node().is_none());
    }

    #[test]
    fn a_low_class_runs_free_when_idle_and_yields_to_high_traffic() {
        // 1 MB/s, so a 100 ms window holds 100 kB.
        let scheduler = Scheduler::new(1_000_000, 0.1).unwrap();
        let start = Instant::now();
        // Alone, low traffic gets about the whole capacity: 95 kB in each
        // 100 ms passes without a long wait.
        let mut at = start;
        for _ in 0..10 {
            at += WINDOW;
            let wait = scheduler.charge_at(Priority::Low, 90_000, at);
            assert!(
                wait.is_none_or(|wait| wait < Duration::from_millis(50)),
                "{wait:?}"
            );
        }
        // High traffic is never held and pushes low traffic to its share.
        for _ in 0..10 {
            at += WINDOW;
            assert_eq!(scheduler.charge_at(Priority::High, 100_000, at), None);
        }
        at += WINDOW;
        let wait = scheduler.charge_at(Priority::Low, 150_000, at).unwrap();
        // 50 kB beyond the burst at the 100 kB/s minimum share is about
        // half a second.
        assert!(wait >= Duration::from_millis(300), "{wait:?}");
        let status = scheduler.status();
        assert!(status.high_bytes_per_sec > 800_000, "{status:?}");
    }

    #[tokio::test]
    async fn classing_waits_for_the_first_bytes_and_caps_each_user() {
        let mut config = policy().config().clone();
        config.egress_mbps = 0;
        config.classes.push(QosClass {
            name: "steam".into(),
            priority: Priority::Low,
            limit_mbps: 8,
            domains: vec!["steamserver.net".into()],
            networks: vec![],
            protocols: vec![],
        });
        set(Some(Policy::compile(&config).unwrap()));
        let mut classing = Classing::start(Some(&address("198.51.100.1"))).unwrap();
        assert_eq!(classing.priority(), Priority::Normal);
        classing.first_bytes(b"GET / HTTP/1.1\r\nHost: mega.nz\r\n\r\n");
        assert_eq!(classing.priority(), Priority::Low);

        // 8 Mbit/s is 1 MB/s for each user: the second megabyte of one
        // user waits, another user's first does not.
        let mut first = Classing::start(Some(&domain("cache1.steamserver.net"))).unwrap();
        assert_eq!(first.charge(Some(("alice", 0)), 1_000_000), None);
        assert!(first.charge(Some(("alice", 0)), 500_000).is_some());
        let mut again = Classing::start(Some(&domain("steamserver.net"))).unwrap();
        assert!(again.charge(Some(("alice", 0)), 1).is_some());
        let mut other = Classing::start(Some(&domain("steamserver.net"))).unwrap();
        assert_eq!(other.charge(Some(("bob", 0)), 1_000_000), None);
        // Uncapped classes do not wait without a scheduler.
        let mut web = Classing::start(Some(&domain("example.com"))).unwrap();
        assert_eq!(web.charge(Some(("alice", 0)), 5_000_000), None);

        set(None);
        assert!(Classing::start(Some(&domain("mega.nz"))).is_none());
    }
}
