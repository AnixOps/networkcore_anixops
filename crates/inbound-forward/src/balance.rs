//! Several targets behind one forward: the balancing strategy, active
//! health checks and the circuit breaker (forward.v1 `Policy`).
//!
//! Health checks and the breaker share one state per target: a failure in a
//! row (an active check or a dial) counts toward `failure_threshold`, which
//! opens the breaker; the target is then skipped for `open_ms`, after which
//! one connection (or check) may try it. Any success closes it. When every
//! target is open, all of them are candidates again rather than none.
//!
//! [`Targets::report`] answers each target's state with the round trip and
//! time of its last active check, for the management API.

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use engine_inbound::health::{TargetHealth, TargetState};
use engine_outbound::{TargetAddr, TcpOutbound};
use tokio::time::Instant;

/// Defaults of forward.v1 `HealthCheck` and `CircuitBreaker`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(5000);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2000);
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
pub const DEFAULT_OPEN: Duration = Duration::from_millis(30000);

/// How a new connection picks its target (forward.v1 `BalanceStrategy`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Strategy {
    /// Weighted round robin (smooth, as nginx does it).
    #[default]
    RoundRobin,
    /// Weighted random.
    Random,
    /// Keeps a client address on one target while that target is up.
    IpHash,
    /// The target with the fewest live connections.
    LeastConn,
    /// The up target with the lowest `priority`, in list order on a tie.
    Failover,
}

impl Strategy {
    /// `round_robin`, `random`, `ip_hash`, `least_conn` or `failover`; the
    /// forward.v1 enum names (`BALANCE_STRATEGY_IP_HASH`) are accepted too,
    /// and `UNSPECIFIED` is round robin.
    pub fn parse(value: &str) -> Option<Strategy> {
        let value = value.trim();
        let name = value
            .strip_prefix("BALANCE_STRATEGY_")
            .unwrap_or(value)
            .to_ascii_lowercase();
        Some(match name.as_str() {
            "round_robin" | "unspecified" => Strategy::RoundRobin,
            "random" => Strategy::Random,
            "ip_hash" => Strategy::IpHash,
            "least_conn" => Strategy::LeastConn,
            "failover" => Strategy::Failover,
            _ => return None,
        })
    }
}

/// One configured target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub addr: TargetAddr,
    /// Share for round robin and random; at least 1.
    pub weight: u32,
    /// Order for failover: lower first.
    pub priority: u32,
}

/// Active checks and breaker settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Health {
    /// Active checks: a probe through the forward's outbound
    /// ([`TcpOutbound::probe`]) every `interval`, within `timeout`. Off for a UDP-only forward; passive
    /// failures still count. A single target is checked too, for its
    /// health and round trip, though it is dialed whatever its state.
    pub active: bool,
    pub interval: Duration,
    pub timeout: Duration,
    pub failure_threshold: u32,
    pub open: Duration,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            active: true,
            interval: DEFAULT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            open: DEFAULT_OPEN,
        }
    }
}

#[derive(Default)]
struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
    /// The one trial after `open_until` is out.
    trial: bool,
}

struct State {
    target: Target,
    breaker: Mutex<Breaker>,
    /// Live connections and UDP sessions.
    active: AtomicUsize,
    /// Smooth weighted round robin's running weight.
    current: Mutex<i64>,
    /// A check or dial has tried the target.
    seen: AtomicBool,
    /// The last active check.
    probe: Mutex<Probe>,
}

/// One active check's outcome.
#[derive(Clone, Copy, Default)]
struct Probe {
    /// Microseconds; 0 when it failed.
    rtt_us: u32,
    checked_at_unix_ms: u64,
}

/// The targets of one forward and their state.
pub struct Targets {
    states: Vec<State>,
    strategy: Strategy,
    health: Health,
    /// Random seed and counter for [`Strategy::Random`].
    seed: RandomState,
    draws: AtomicU64,
}

/// A target in use; counts as one of its live connections until dropped.
pub struct Lease {
    targets: Arc<Targets>,
    index: usize,
}

impl Lease {
    /// The target's place in the configured list.
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn target(&self) -> &TargetAddr {
        &self.targets.states[self.index].target.addr
    }

    pub fn succeeded(&self) {
        self.targets.succeeded(self.index);
    }

    pub fn failed(&self) {
        self.targets.failed(self.index, Instant::now());
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.targets.states[self.index]
            .active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl Targets {
    /// `targets` must not be empty.
    pub fn new(targets: Vec<Target>, strategy: Strategy, health: Health) -> Self {
        assert!(!targets.is_empty(), "a forward needs a target");
        Self {
            states: targets
                .into_iter()
                .map(|target| State {
                    target,
                    breaker: Mutex::default(),
                    active: AtomicUsize::new(0),
                    current: Mutex::new(0),
                    seen: AtomicBool::new(false),
                    probe: Mutex::default(),
                })
                .collect(),
            strategy,
            health,
            seed: RandomState::new(),
            draws: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    pub fn health(&self) -> Health {
        self.health
    }

    pub fn first(&self) -> &TargetAddr {
        &self.states[0].target.addr
    }

    pub fn addrs(&self) -> impl Iterator<Item = &TargetAddr> {
        self.states.iter().map(|state| &state.target.addr)
    }

    /// Whether the target's breaker is closed now (for status and tests).
    pub fn is_up(&self, index: usize) -> bool {
        lock(&self.states[index].breaker).open_until.is_none()
    }

    /// Picks a target for a client at `client`, skipping `tried`; `None`
    /// when every target was tried.
    pub fn pick(self: &Arc<Self>, client: IpAddr, tried: &[usize]) -> Option<Lease> {
        let now = Instant::now();
        let untried: Vec<usize> = (0..self.states.len())
            .filter(|index| !tried.contains(index))
            .collect();
        if untried.is_empty() {
            return None;
        }
        let up: Vec<usize> = untried
            .iter()
            .copied()
            .filter(|&index| self.available(index, now))
            .collect();
        let candidates = if up.is_empty() { &untried } else { &up };
        let index = self.choose(candidates, client);
        self.take_trial(index, now);
        self.states[index].active.fetch_add(1, Ordering::Relaxed);
        Some(Lease {
            targets: self.clone(),
            index,
        })
    }

    fn available(&self, index: usize, now: Instant) -> bool {
        let breaker = lock(&self.states[index].breaker);
        match breaker.open_until {
            None => true,
            Some(until) => now >= until && !breaker.trial,
        }
    }

    /// Marks the half-open trial of `index` as taken.
    fn take_trial(&self, index: usize, now: Instant) {
        let mut breaker = lock(&self.states[index].breaker);
        if breaker.open_until.is_some_and(|until| now >= until) {
            breaker.trial = true;
        }
    }

    fn choose(&self, candidates: &[usize], client: IpAddr) -> usize {
        if candidates.len() == 1 {
            return candidates[0];
        }
        match self.strategy {
            Strategy::RoundRobin => self.round_robin(candidates),
            Strategy::Random => {
                let total: u64 = candidates.iter().map(|&i| self.weight(i)).sum();
                let draw = self.draws.fetch_add(1, Ordering::Relaxed);
                let mut draw = self.seed.hash_one(draw) % total;
                for &index in candidates {
                    let weight = self.weight(index);
                    if draw < weight {
                        return index;
                    }
                    draw -= weight;
                }
                candidates[candidates.len() - 1]
            }
            // Rendezvous hashing: a client moves only when its target is
            // down, and comes back when it is up again.
            Strategy::IpHash => *candidates
                .iter()
                .max_by_key(|&&index| {
                    let mut hasher = DefaultHasher::new();
                    client.hash(&mut hasher);
                    self.states[index].target.addr.hash(&mut hasher);
                    hasher.finish()
                })
                .expect("candidates are not empty"),
            Strategy::LeastConn => *candidates
                .iter()
                .min_by_key(|&&index| self.states[index].active.load(Ordering::Relaxed))
                .expect("candidates are not empty"),
            Strategy::Failover => *candidates
                .iter()
                .min_by_key(|&&index| self.states[index].target.priority)
                .expect("candidates are not empty"),
        }
    }

    fn weight(&self, index: usize) -> u64 {
        u64::from(self.states[index].target.weight.max(1))
    }

    fn round_robin(&self, candidates: &[usize]) -> usize {
        let total: i64 = candidates.iter().map(|&i| self.weight(i) as i64).sum();
        let mut best = candidates[0];
        let mut best_current = i64::MIN;
        for &index in candidates {
            let mut current = lock(&self.states[index].current);
            *current += self.weight(index) as i64;
            if *current > best_current {
                best_current = *current;
                best = index;
            }
        }
        *lock(&self.states[best].current) -= total;
        best
    }

    fn succeeded(&self, index: usize) {
        self.states[index].seen.store(true, Ordering::Relaxed);
        *lock(&self.states[index].breaker) = Breaker::default();
    }

    fn failed(&self, index: usize, now: Instant) {
        self.states[index].seen.store(true, Ordering::Relaxed);
        let mut breaker = lock(&self.states[index].breaker);
        breaker.failures = breaker.failures.saturating_add(1);
        breaker.trial = false;
        if breaker.failures >= self.health.failure_threshold.max(1) {
            breaker.open_until = Some(now + self.health.open);
        }
    }

    /// Checks every target through `outbound` each interval, until dropped.
    /// A target whose breaker is open is checked only once its open time is
    /// out, as its trial.
    pub async fn check(self: Arc<Self>, outbound: Arc<dyn TcpOutbound>) {
        let mut ticker = tokio::time::interval(self.health.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let checks = (0..self.states.len())
                .filter(|&index| self.available(index, now))
                .map(|index| {
                    self.take_trial(index, now);
                    let (targets, outbound) = (self.clone(), outbound.clone());
                    async move {
                        let addr = &targets.states[index].target.addr;
                        let timeout = targets.health.timeout;
                        // The outbound waits for the far end within the
                        // timeout; the outer bound only guards one that
                        // does not.
                        let probed =
                            tokio::time::timeout(timeout, outbound.probe(addr, timeout)).await;
                        let rtt_us = match probed {
                            Ok(Ok(rtt)) => {
                                targets.succeeded(index);
                                // At least 1: 0 means the check failed.
                                u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX).max(1)
                            }
                            _ => {
                                targets.failed(index, Instant::now());
                                0
                            }
                        };
                        *lock(&targets.states[index].probe) = Probe {
                            rtt_us,
                            checked_at_unix_ms: unix_ms(SystemTime::now()),
                        };
                    }
                });
            futures_util::future::join_all(checks).await;
        }
    }
}

impl Targets {
    /// Each target's state, in the configured order.
    pub fn report(&self) -> Vec<TargetHealth> {
        let (now, wall) = (Instant::now(), SystemTime::now());
        self.states
            .iter()
            .map(|state| {
                let breaker = lock(&state.breaker);
                let probe = *lock(&state.probe);
                let (status, open_until) = match breaker.open_until {
                    Some(until) => (
                        TargetState::CircuitOpen,
                        unix_ms(wall + until.saturating_duration_since(now)),
                    ),
                    None if breaker.failures > 0 => (TargetState::Unhealthy, 0),
                    None if state.seen.load(Ordering::Relaxed) => (TargetState::Healthy, 0),
                    None => (TargetState::Unknown, 0),
                };
                TargetHealth {
                    address: state.target.addr.host(),
                    port: state.target.addr.port(),
                    state: status,
                    consecutive_failures: breaker.failures,
                    circuit_open_until_unix_ms: open_until,
                    rtt_us: probe.rtt_us,
                    checked_at_unix_ms: probe.checked_at_unix_ms,
                }
            })
            .collect()
    }
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::Ipv4Addr;

    fn targets(n: u16, strategy: Strategy) -> Arc<Targets> {
        let list = (0..n)
            .map(|i| Target {
                addr: TargetAddr::Ip(std::net::SocketAddr::new(
                    Ipv4Addr::new(192, 0, 2, 1).into(),
                    1000 + i,
                )),
                weight: 1,
                priority: u32::from(n - i),
            })
            .collect();
        Arc::new(Targets::new(list, strategy, Health::default()))
    }

    fn client(last: u8) -> IpAddr {
        Ipv4Addr::new(198, 51, 100, last).into()
    }

    fn pick(targets: &Arc<Targets>, client: IpAddr) -> usize {
        let lease = targets.pick(client, &[]).unwrap();
        lease.index
    }

    #[test]
    fn parses_strategies() {
        assert_eq!(Strategy::parse("ip_hash"), Some(Strategy::IpHash));
        assert_eq!(
            Strategy::parse("BALANCE_STRATEGY_LEAST_CONN"),
            Some(Strategy::LeastConn)
        );
        assert_eq!(
            Strategy::parse("BALANCE_STRATEGY_UNSPECIFIED"),
            Some(Strategy::RoundRobin)
        );
        assert_eq!(Strategy::parse("sticky"), None);
    }

    #[test]
    fn round_robin_follows_weights() {
        let mut list: Vec<Target> = (0..2)
            .map(|i| Target {
                addr: TargetAddr::Domain(format!("t{i}.example"), 80),
                weight: 1,
                priority: 0,
            })
            .collect();
        list[1].weight = 3;
        let targets = Arc::new(Targets::new(list, Strategy::RoundRobin, Health::default()));
        let picks: Vec<usize> = (0..8).map(|_| pick(&targets, client(1))).collect();
        assert_eq!(picks.iter().filter(|&&i| i == 1).count(), 6);
        // Smooth: never the light target twice in a row.
        assert!(picks.windows(2).all(|w| !(w[0] == 0 && w[1] == 0)));
    }

    #[test]
    fn random_spreads() {
        let targets = targets(3, Strategy::Random);
        let mut seen = [0; 3];
        for _ in 0..300 {
            seen[pick(&targets, client(1))] += 1;
        }
        assert!(seen.iter().all(|&n| n > 30), "{seen:?}");
    }

    #[test]
    fn ip_hash_is_sticky_and_moves_only_when_down() {
        let targets = targets(4, Strategy::IpHash);
        let home = pick(&targets, client(7));
        assert!((0..10).all(|_| pick(&targets, client(7)) == home));
        let spread: std::collections::HashSet<usize> =
            (0..64).map(|last| pick(&targets, client(last))).collect();
        assert!(spread.len() > 1);
        let now = Instant::now();
        for _ in 0..3 {
            targets.failed(home, now);
        }
        let moved = pick(&targets, client(7));
        assert_ne!(moved, home);
        targets.succeeded(home);
        assert_eq!(pick(&targets, client(7)), home);
    }

    #[test]
    fn least_conn_prefers_idle_targets() {
        let targets = targets(3, Strategy::LeastConn);
        let first = targets.pick(client(1), &[]).unwrap();
        let second = targets.pick(client(1), &[]).unwrap();
        let third = targets.pick(client(1), &[]).unwrap();
        let mut used = vec![first.index, second.index, third.index];
        used.sort();
        assert_eq!(used, vec![0, 1, 2]);
        let freed = second.index;
        drop(second);
        assert_eq!(pick(&targets, client(1)), freed);
    }

    #[test]
    fn failover_takes_the_lowest_priority_that_is_up() {
        // priority: index 0 → 3, 1 → 2, 2 → 1.
        let targets = targets(3, Strategy::Failover);
        assert_eq!(pick(&targets, client(1)), 2);
        let now = Instant::now();
        for _ in 0..3 {
            targets.failed(2, now);
        }
        assert!(!targets.is_up(2));
        assert_eq!(pick(&targets, client(1)), 1);
        // Tried targets are skipped: a failed dial moves on.
        let lease = targets.pick(client(1), &[1]).unwrap();
        assert_eq!(lease.index, 0);
        assert!(targets.pick(client(1), &[0, 1, 2]).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_opens_then_allows_one_trial() {
        let targets = targets(2, Strategy::Failover);
        let now = Instant::now();
        for _ in 0..2 {
            targets.failed(1, now);
        }
        assert!(targets.is_up(1), "below the threshold");
        targets.failed(1, now);
        assert!(!targets.is_up(1));
        assert_eq!(pick(&targets, client(1)), 0);
        tokio::time::advance(DEFAULT_OPEN).await;
        // The trial goes to the preferred target once, not twice.
        let trial = targets.pick(client(1), &[]).unwrap();
        assert_eq!(trial.index, 1);
        assert_eq!(pick(&targets, client(1)), 0);
        trial.succeeded();
        assert!(targets.is_up(1));
        assert_eq!(pick(&targets, client(1)), 1);
    }

    /// An outbound whose `connect` would fail and whose `probe` answers.
    struct Probed(io::Result<Duration>);

    impl TcpOutbound for Probed {
        fn protocol(&self) -> &'static str {
            "probed"
        }

        fn connect<'a>(
            &'a self,
            _target: &'a TargetAddr,
        ) -> engine_outbound::BoxFuture<'a, io::Result<engine_outbound::BoxStream>> {
            Box::pin(async { Err(io::Error::other("checks probe, not connect")) })
        }

        fn probe<'a>(
            &'a self,
            _target: &'a TargetAddr,
            _timeout: Duration,
        ) -> engine_outbound::BoxFuture<'a, io::Result<Duration>> {
            let result = match &self.0 {
                Ok(rtt) => Ok(*rtt),
                Err(error) => Err(io::Error::new(error.kind(), "probe failed")),
            };
            Box::pin(async move { result })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn checks_report_the_probe_round_trip() {
        let up = targets(1, Strategy::RoundRobin);
        let check = tokio::spawn(
            up.clone()
                .check(Arc::new(Probed(Ok(Duration::from_millis(30))))),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        check.abort();
        let report = up.report();
        assert_eq!(report[0].state, TargetState::Healthy);
        assert_eq!(report[0].rtt_us, 30_000);

        let down = targets(1, Strategy::RoundRobin);
        let check = tokio::spawn(down.clone().check(Arc::new(Probed(Err(io::Error::from(
            io::ErrorKind::ConnectionReset,
        ))))));
        tokio::time::sleep(Duration::from_millis(10)).await;
        check.abort();
        let report = down.report();
        assert_eq!(report[0].state, TargetState::Unhealthy);
        assert_eq!(report[0].rtt_us, 0);
        assert!(report[0].checked_at_unix_ms > 0);
    }

    #[test]
    fn reports_each_target() {
        let targets = targets(3, Strategy::RoundRobin);
        let now = Instant::now();
        targets.succeeded(0);
        targets.failed(1, now);
        for _ in 0..3 {
            targets.failed(2, now);
        }
        let report = targets.report();
        assert_eq!(report.len(), 3);
        assert_eq!(report[0].address, "192.0.2.1");
        assert_eq!(report[0].port, 1000);
        assert_eq!(report[0].state, TargetState::Healthy);
        assert_eq!(report[1].state, TargetState::Unhealthy);
        assert_eq!(report[1].consecutive_failures, 1);
        assert_eq!(report[2].state, TargetState::CircuitOpen);
        assert!(report[2].circuit_open_until_unix_ms > unix_ms(SystemTime::now()));
        assert_eq!(report[0].checked_at_unix_ms, 0, "no active check ran");
        let fresh = super::Targets::new(
            vec![Target {
                addr: TargetAddr::Domain("t.example".into(), 80),
                weight: 1,
                priority: 0,
            }],
            Strategy::RoundRobin,
            Health::default(),
        );
        assert_eq!(fresh.report()[0].state, TargetState::Unknown);
        assert_eq!(fresh.report()[0].address, "t.example");
    }

    #[test]
    fn all_down_still_picks() {
        let targets = targets(2, Strategy::RoundRobin);
        let now = Instant::now();
        for index in 0..2 {
            for _ in 0..3 {
                targets.failed(index, now);
            }
        }
        assert!(targets.pick(client(1), &[]).is_some());
    }
}
