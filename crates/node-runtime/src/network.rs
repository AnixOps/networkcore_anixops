//! The network model on one device: ingresses, egresses and the paths
//! between them (anix-control `docs/design/network-model`, §6.3).
//!
//! The agent hands down the device's `NetworkPlan` (anix-control
//! `sdk/api/network/v1`, golden samples in `contracts/network/v1/`) as is;
//! the kernel reads the members below and ignores the rest (lines,
//! routing tables, transport keys, forwarding):
//!
//! - `egresses`: each is an outbound named `egress:<id>`, a direct outbound
//!   bound to the egress `source` (TCP `bind` then `connect`, UDP
//!   `bind(source:0)`); the agent's `ip rule from <source>` picks its line.
//!   With a `health` check the kernel probes the `targets` from that source
//!   (decision N2) and marks the egress down after `failure_threshold`
//!   failures in a row, up again after `recovery_threshold` successes.
//! - `ingresses`: an inbound joins one with its `ingress` key. Its
//!   `pairing` orders the egresses its traffic may take: `SAME_LINE` and
//!   `CROSS` name one, `FAILOVER` several in order. `RULES` is refused for
//!   now (domain rules still come through `PUT /v1/egress`).
//! - `paths`: the device view of a path, from an ingress either to a local
//!   egress (`egress_id`, or a `local` transport and `final_egress_id`) or
//!   into the first transport (`transport_id`), which leaves through the
//!   outbound the binary registered as `<kind>:<transport id>` (`anx_line`
//!   → `anx-line:<id>`). `forwarding` (relay hops) is not read: the
//!   transport's server (anx-server) hands relayed traffic to its egress.
//! - `transports`: only `id` and `kind` are read, to name that outbound.
//!
//! A connection takes the ingress's active path, chosen when it opens:
//! the first healthy one in pairing order; after a failover a path earlier
//! in the order is taken back once its egress has been healthy for
//! `failback_delay_ms`. Paths through a transport have no probe here and
//! count as healthy. When nothing is healthy the first path is tried.
//! Connections already open keep the path they took.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use engine_inbound::udp::{UdpOutbound, UdpSession};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::task::JoinHandle;

use crate::{DirectOutbound, NodeOutbound};

/// The outbound name prefix of an egress.
pub const EGRESS_PREFIX: &str = "egress:";
const MAX_ITEMS: usize = 256;
const MAX_TARGETS: usize = 8;
const DEFAULT_INTERVAL_MS: u64 = 10_000;
const DEFAULT_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_THRESHOLD: u64 = 3;
const DEFAULT_RECOVERY: u64 = 2;

const MODE_SAME_LINE: &str = "PAIRING_MODE_SAME_LINE";
const MODE_CROSS: &str = "PAIRING_MODE_CROSS";
const MODE_FAILOVER: &str = "PAIRING_MODE_FAILOVER";

/// The members of a device's `NetworkPlan` the kernel uses. Field names
/// are accepted as proto names and as protojson's lowerCamelCase, 64-bit
/// numbers as numbers or strings. Has no `Debug`: a plan can carry keys
/// (they are ignored, not kept).
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct NetworkPlan {
    #[serde(default, deserialize_with = "number")]
    pub generation: u64,
    #[serde(default)]
    pub egresses: Vec<PlanEgress>,
    #[serde(default)]
    pub ingresses: Vec<PlanIngress>,
    #[serde(default)]
    pub paths: Vec<PlanPath>,
    #[serde(default)]
    pub transports: Vec<PlanTransport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlanEgress {
    pub id: String,
    /// An IP address; empty or `auto` (which the agent should have
    /// resolved) leaves the source to the routing table.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub health: Option<HealthCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct HealthCheck {
    /// `host:port` (`[v6]:port`) targets; a probe succeeds when one of them
    /// accepts a TCP connection from the egress source.
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default, alias = "intervalMs", deserialize_with = "number")]
    pub interval_ms: u64,
    #[serde(default, alias = "timeoutMs", deserialize_with = "number")]
    pub timeout_ms: u64,
    #[serde(default, alias = "failureThreshold", deserialize_with = "number")]
    pub failure_threshold: u64,
    #[serde(default, alias = "recoveryThreshold", deserialize_with = "number")]
    pub recovery_threshold: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PlanIngress {
    pub id: String,
    #[serde(default)]
    pub pairing: Pairing,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Pairing {
    /// `PAIRING_MODE_SAME_LINE` (also when empty), `_CROSS` or `_FAILOVER`.
    #[serde(default)]
    pub mode: String,
    /// Final egresses, in failover order.
    #[serde(default, alias = "egressIds")]
    pub egress_ids: Vec<String>,
    #[serde(default, alias = "failbackDelayMs", deserialize_with = "number")]
    pub failback_delay_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PlanPath {
    pub id: String,
    #[serde(alias = "ingressId")]
    pub ingress_id: String,
    /// A local egress: the path ends on this device.
    #[serde(default, alias = "egressId")]
    pub egress_id: String,
    /// The first transport: the path continues on another device.
    #[serde(default, alias = "transportId")]
    pub transport_id: String,
    /// The final egress of a path through a transport, for the pairing
    /// order; a local path's is `egress_id`.
    #[serde(default, alias = "finalEgressId")]
    pub final_egress_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PlanTransport {
    pub id: String,
    /// `anx_line`, `wireguard`, ...; protojson enum prefixes are dropped.
    pub kind: String,
}

/// Accepts a JSON number or a decimal string (protojson's 64-bit form).
fn number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Number(u64),
        Text(String),
    }
    match Number::deserialize(deserializer)? {
        Number::Number(value) => Ok(value),
        Number::Text(text) => text.parse().map_err(serde::de::Error::custom),
    }
}

/// Where a path's traffic leaves this device.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Hop {
    /// A local egress, by id.
    Egress(String),
    /// A registered outbound into a transport, by name.
    Outbound(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    path_id: String,
    /// The final egress, when known.
    egress_id: Option<String>,
    hop: Hop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledEgress {
    source: Option<IpAddr>,
    health: Option<HealthCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledIngress {
    candidates: Vec<Candidate>,
    failback: Duration,
}

#[derive(Default)]
struct Compiled {
    generation: u64,
    egresses: BTreeMap<String, CompiledEgress>,
    ingresses: BTreeMap<String, CompiledIngress>,
}

/// Checks the whole plan; nothing is applied when an entry is invalid.
/// `registered` are the outbound names the binary registered.
fn compile(plan: &NetworkPlan, registered: &BTreeSet<String>) -> Result<Compiled, String> {
    if plan.egresses.len() > MAX_ITEMS
        || plan.ingresses.len() > MAX_ITEMS
        || plan.paths.len() > MAX_ITEMS * 4
        || plan.transports.len() > MAX_ITEMS
    {
        return Err(format!("network: at most {MAX_ITEMS} entries of each kind"));
    }
    let mut egresses = BTreeMap::new();
    for egress in &plan.egresses {
        let fail = |message: String| format!("network egress {:?}: {message}", egress.id);
        check_id(&egress.id).map_err(fail)?;
        let source = match egress.source.trim() {
            "" | "auto" => None,
            source => Some(
                source
                    .parse::<IpAddr>()
                    .map_err(|_| fail(format!("source {source:?} is not an IP address")))?
                    .to_canonical(),
            ),
        };
        let health = egress
            .health
            .clone()
            .map(normalize_health)
            .transpose()
            .map_err(fail)?;
        if egresses
            .insert(egress.id.clone(), CompiledEgress { source, health })
            .is_some()
        {
            return Err(fail("the id is repeated".into()));
        }
    }
    let mut transports = BTreeMap::new();
    for transport in &plan.transports {
        let fail = |message: String| format!("network transport {:?}: {message}", transport.id);
        check_id(&transport.id).map_err(fail)?;
        let kind = transport
            .kind
            .trim()
            .trim_start_matches("TRANSPORT_KIND_")
            .to_ascii_lowercase()
            .replace('_', "-");
        if kind.is_empty() {
            return Err(fail("the kind is missing".into()));
        }
        if transports.insert(transport.id.clone(), kind).is_some() {
            return Err(fail("the id is repeated".into()));
        }
    }
    let mut ingress_ids = BTreeSet::new();
    for ingress in &plan.ingresses {
        check_id(&ingress.id)
            .map_err(|message| format!("network ingress {:?}: {message}", ingress.id))?;
        if !ingress_ids.insert(ingress.id.as_str()) {
            return Err(format!(
                "network ingress {:?}: the id is repeated",
                ingress.id
            ));
        }
    }
    // Paths by ingress, in plan order.
    let mut paths: BTreeMap<&str, Vec<Candidate>> = BTreeMap::new();
    let mut path_ids = BTreeSet::new();
    for path in &plan.paths {
        let fail = |message: String| format!("network path {:?}: {message}", path.id);
        check_id(&path.id).map_err(fail)?;
        if !path_ids.insert(path.id.as_str()) {
            return Err(fail("the id is repeated".into()));
        }
        if !ingress_ids.contains(path.ingress_id.as_str()) {
            return Err(fail(format!(
                "ingress {:?} is not in the plan",
                path.ingress_id
            )));
        }
        let candidate = match (path.egress_id.as_str(), path.transport_id.as_str()) {
            (egress, "") if !egress.is_empty() => {
                if !egresses.contains_key(egress) {
                    return Err(fail(format!("egress {egress:?} is not in the plan")));
                }
                Candidate {
                    path_id: path.id.clone(),
                    egress_id: Some(egress.to_owned()),
                    hop: Hop::Egress(egress.to_owned()),
                }
            }
            ("", transport) if !transport.is_empty() => {
                let kind = transports
                    .get(transport)
                    .ok_or_else(|| fail(format!("transport {transport:?} is not in the plan")))?;
                if kind == "local" {
                    // In-process forwarding: the path ends at a local egress.
                    let egress = path.final_egress_id.as_str();
                    if !egresses.contains_key(egress) {
                        return Err(fail(format!(
                            "a local transport needs a local final egress, not {egress:?}"
                        )));
                    }
                    paths
                        .entry(path.ingress_id.as_str())
                        .or_default()
                        .push(Candidate {
                            path_id: path.id.clone(),
                            egress_id: Some(egress.to_owned()),
                            hop: Hop::Egress(egress.to_owned()),
                        });
                    continue;
                }
                let name = format!("{kind}:{transport}");
                if !registered.contains(&name) {
                    return Err(fail(format!("this kernel has no outbound {name:?}")));
                }
                Candidate {
                    path_id: path.id.clone(),
                    egress_id: (!path.final_egress_id.is_empty())
                        .then(|| path.final_egress_id.clone()),
                    hop: Hop::Outbound(name),
                }
            }
            _ => return Err(fail("exactly one of egress_id and transport_id".into())),
        };
        paths
            .entry(path.ingress_id.as_str())
            .or_default()
            .push(candidate);
    }
    let mut ingresses = BTreeMap::new();
    for ingress in &plan.ingresses {
        let fail = |message: String| format!("network ingress {:?}: {message}", ingress.id);
        let pairing = &ingress.pairing;
        let mode = match pairing.mode.trim() {
            "" => MODE_SAME_LINE,
            mode => mode,
        };
        let single = match mode {
            MODE_SAME_LINE | MODE_CROSS => true,
            MODE_FAILOVER => false,
            other => return Err(fail(format!("pairing mode {other:?} is not supported"))),
        };
        if single && pairing.egress_ids.len() > 1 {
            return Err(fail(format!("{mode} pairs one egress")));
        }
        let mut available = paths.remove(ingress.id.as_str()).unwrap_or_default();
        let mut candidates = Vec::new();
        for egress in &pairing.egress_ids {
            let taken: Vec<Candidate> = available
                .iter()
                .filter(|candidate| candidate.egress_id.as_deref() == Some(egress.as_str()))
                .cloned()
                .collect();
            if taken.is_empty() {
                if !egresses.contains_key(egress) {
                    return Err(fail(format!("no path reaches egress {egress:?}")));
                }
                // A local egress the plan sent no path for.
                candidates.push(Candidate {
                    path_id: String::new(),
                    egress_id: Some(egress.clone()),
                    hop: Hop::Egress(egress.clone()),
                });
            }
            available.retain(|candidate| !taken.contains(candidate));
            candidates.extend(taken);
        }
        candidates.extend(available);
        if single {
            candidates.truncate(1);
        }
        ingresses.insert(
            ingress.id.clone(),
            CompiledIngress {
                candidates,
                failback: Duration::from_millis(pairing.failback_delay_ms),
            },
        );
    }
    Ok(Compiled {
        generation: plan.generation,
        egresses,
        ingresses,
    })
}

fn check_id(id: &str) -> Result<(), String> {
    if crate::valid_tag(id) {
        Ok(())
    } else {
        Err("the id must be 1-64 letters, digits, '.', '_' or '-'".into())
    }
}

/// Fills defaults and checks a health check.
fn normalize_health(mut health: HealthCheck) -> Result<HealthCheck, String> {
    if health.targets.is_empty() || health.targets.len() > MAX_TARGETS {
        return Err(format!("the health check needs 1 to {MAX_TARGETS} targets"));
    }
    for target in &health.targets {
        parse_target(target).ok_or_else(|| format!("health target {target:?} is not host:port"))?;
    }
    let default = |value: &mut u64, fallback: u64| {
        if *value == 0 {
            *value = fallback;
        }
    };
    default(&mut health.interval_ms, DEFAULT_INTERVAL_MS);
    default(&mut health.timeout_ms, DEFAULT_TIMEOUT_MS);
    default(&mut health.failure_threshold, DEFAULT_THRESHOLD);
    default(&mut health.recovery_threshold, DEFAULT_RECOVERY);
    if health.interval_ms < 1_000 || health.timeout_ms > health.interval_ms {
        return Err(
            "the health interval must be at least 1000 ms and not shorter than the timeout".into(),
        );
    }
    Ok(health)
}

/// `host:port` or `[v6]:port`.
fn parse_target(target: &str) -> Option<TargetAddr> {
    let (host, port) = target.trim().rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|port| *port != 0)?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() || (host.contains(':') && host.parse::<IpAddr>().is_err()) {
        return None;
    }
    Some(TargetAddr::from_host(host, port))
}

/// What the probes know of one egress.
struct Health {
    up: AtomicBool,
    /// When the egress last became healthy (or was applied).
    since: Mutex<Instant>,
    changed_at_unix_ms: AtomicU64,
    /// The last successful probe's connect time; 0 when none.
    rtt_ms: AtomicU64,
    detail: Mutex<Option<String>>,
}

impl Health {
    fn new() -> Self {
        Self {
            up: AtomicBool::new(true),
            since: Mutex::new(Instant::now()),
            changed_at_unix_ms: AtomicU64::new(unix_ms()),
            rtt_ms: AtomicU64::new(0),
            detail: Mutex::new(None),
        }
    }

    fn set(&self, up: bool) {
        if self.up.swap(up, Ordering::Relaxed) != up {
            if up {
                *lock(&self.since) = Instant::now();
            }
            self.changed_at_unix_ms.store(unix_ms(), Ordering::Relaxed);
        }
    }
}

struct Probed {
    egress: CompiledEgress,
    health: Arc<Health>,
    task: Option<JoinHandle<()>>,
}

/// The device's network plan, shared by every inbound.
pub struct Network {
    allow_private: bool,
    compiled: RwLock<Arc<Compiled>>,
    probed: Mutex<BTreeMap<String, Probed>>,
    /// The active candidate of each ingress.
    active: Mutex<HashMap<String, usize>>,
    /// Serializes [`Network::apply`].
    applying: tokio::sync::Mutex<()>,
}

impl Network {
    pub(crate) fn new(allow_private: bool) -> Self {
        Self {
            allow_private,
            compiled: RwLock::default(),
            probed: Mutex::default(),
            active: Mutex::default(),
            applying: tokio::sync::Mutex::new(()),
        }
    }

    /// Replaces the plan. Egresses whose source and health check did not
    /// change keep their probe and state.
    pub(crate) async fn apply(
        &self,
        plan: &NetworkPlan,
        registered: &BTreeSet<String>,
    ) -> Result<NetworkStatus, String> {
        let compiled = compile(plan, registered)?;
        let _applying = self.applying.lock().await;
        {
            let mut probed = lock(&self.probed);
            probed.retain(|id, probe| {
                let keep = compiled.egresses.get(id) == Some(&probe.egress);
                if !keep {
                    if let Some(task) = &probe.task {
                        task.abort();
                    }
                }
                keep
            });
            for (id, egress) in &compiled.egresses {
                if probed.contains_key(id) {
                    continue;
                }
                let health = Arc::new(Health::new());
                let task = egress
                    .health
                    .clone()
                    .map(|check| tokio::spawn(probe_loop(egress.source, check, health.clone())));
                probed.insert(
                    id.clone(),
                    Probed {
                        egress: egress.clone(),
                        health,
                        task,
                    },
                );
            }
        }
        let previous = self.compiled();
        lock(&self.active).retain(|id, _| {
            previous
                .ingresses
                .get(id)
                .map(|ingress| &ingress.candidates)
                == compiled
                    .ingresses
                    .get(id)
                    .map(|ingress| &ingress.candidates)
        });
        *self.compiled.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(compiled);
        Ok(self.status())
    }

    fn compiled(&self) -> Arc<Compiled> {
        self.compiled
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Health of a final egress: `None` when it is not probed here.
    fn health(&self, egress: Option<&str>) -> Option<(bool, Instant)> {
        let probed = lock(&self.probed);
        let probe = probed.get(egress?)?;
        probe.egress.health.as_ref()?;
        Some((
            probe.health.up.load(Ordering::Relaxed),
            *lock(&probe.health.since),
        ))
    }

    /// The candidate an ingress's next connection takes.
    fn select(&self, compiled: &Compiled, ingress: &str) -> Option<(usize, Candidate)> {
        let entry = compiled.ingresses.get(ingress)?;
        let health: Vec<Option<(bool, Instant)>> = entry
            .candidates
            .iter()
            .map(|candidate| self.health(candidate.egress_id.as_deref()))
            .collect();
        let mut active = lock(&self.active);
        let current = active.get(ingress).copied();
        let index = choose(&health, current, Instant::now(), entry.failback)?;
        active.insert(ingress.to_owned(), index);
        Some((index, entry.candidates[index].clone()))
    }

    /// The outbound a candidate's hop leaves through.
    fn hop_outbound(
        &self,
        compiled: &Compiled,
        hop: &Hop,
        allowed: &[(String, u16)],
        registered: &BTreeMap<String, NodeOutbound>,
    ) -> io::Result<NodeOutbound> {
        match hop {
            Hop::Egress(id) => self.egress_outbound(compiled, id, allowed),
            Hop::Outbound(name) => registered.get(name).cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "transport outbound is gone")
            }),
        }
    }

    fn egress_outbound(
        &self,
        compiled: &Compiled,
        id: &str,
        allowed: &[(String, u16)],
    ) -> io::Result<NodeOutbound> {
        let egress = compiled.egresses.get(id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "egress is not in the network plan")
        })?;
        Ok(NodeOutbound::direct(
            DirectOutbound::new(self.allow_private, allowed.to_vec()).with_source(egress.source),
        ))
    }

    /// What the plan runs now.
    pub fn status(&self) -> NetworkStatus {
        let compiled = self.compiled();
        let egresses = {
            let probed = lock(&self.probed);
            compiled
                .egresses
                .iter()
                .map(|(id, egress)| {
                    let probe = probed.get(id);
                    let up = probe.is_none_or(|probe| probe.health.up.load(Ordering::Relaxed));
                    EgressState {
                        id: id.clone(),
                        source: egress.source,
                        state: if up { STATE_APPLIED } else { STATE_DOWN },
                        checked: egress.health.is_some(),
                        rtt_ms: probe
                            .map(|probe| probe.health.rtt_ms.load(Ordering::Relaxed))
                            .filter(|rtt| *rtt > 0),
                        detail: probe.and_then(|probe| lock(&probe.health.detail).clone()),
                        changed_at_unix_ms: probe
                            .map(|probe| probe.health.changed_at_unix_ms.load(Ordering::Relaxed))
                            .unwrap_or_default(),
                    }
                })
                .collect()
        };
        let ingresses = compiled
            .ingresses
            .keys()
            .map(|id| match self.select(&compiled, id) {
                Some((index, candidate)) => {
                    let healthy = self
                        .health(candidate.egress_id.as_deref())
                        .is_none_or(|(up, _)| up);
                    IngressState {
                        id: id.clone(),
                        state: match (healthy, index) {
                            (false, _) => STATE_DOWN,
                            (true, 0) => STATE_APPLIED,
                            (true, _) => STATE_DEGRADED,
                        },
                        active_egress_id: candidate.egress_id,
                        active_path_id: Some(candidate.path_id).filter(|id| !id.is_empty()),
                    }
                }
                None => IngressState {
                    id: id.clone(),
                    state: STATE_DOWN,
                    active_egress_id: None,
                    active_path_id: None,
                },
            })
            .collect();
        NetworkStatus {
            generation: compiled.generation,
            egresses,
            ingresses,
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for probe in lock(&self.probed).values() {
            if let Some(task) = &probe.task {
                task.abort();
            }
        }
    }
}

/// Picks a candidate: keep a healthy `current` unless an earlier one has
/// been healthy for `failback`; else the first healthy; else the first.
/// `None` health is a candidate without a probe, always healthy.
fn choose(
    health: &[Option<(bool, Instant)>],
    current: Option<usize>,
    now: Instant,
    failback: Duration,
) -> Option<usize> {
    if health.is_empty() {
        return None;
    }
    let healthy = |index: usize| health[index].is_none_or(|(up, _)| up);
    if let Some(current) = current.filter(|current| *current < health.len() && healthy(*current)) {
        let back = (0..current).find(|index| match health[*index] {
            None => true,
            Some((up, since)) => up && now.saturating_duration_since(since) >= failback,
        });
        return Some(back.unwrap_or(current));
    }
    Some((0..health.len()).find(|index| healthy(*index)).unwrap_or(0))
}

async fn probe_loop(source: Option<IpAddr>, check: HealthCheck, health: Arc<Health>) {
    // Operator targets: the private-target filter does not apply.
    let direct = DirectOutbound::new(true, Vec::new()).with_source(source);
    let targets: Vec<TargetAddr> = check
        .targets
        .iter()
        .filter_map(|target| parse_target(target.as_str()))
        .collect();
    let timeout = Duration::from_millis(check.timeout_ms);
    let (mut failures, mut successes) = (0u64, 0u64);
    loop {
        let mut error = None;
        let mut rtt = None;
        for target in &targets {
            let started = Instant::now();
            match tokio::time::timeout(timeout, direct.connect(target)).await {
                Ok(Ok(_stream)) => {
                    rtt = Some(started.elapsed());
                    break;
                }
                Ok(Err(failure)) => error = Some(format!("{target}: {failure}")),
                Err(_) => error = Some(format!("{target}: timed out")),
            }
        }
        match rtt {
            Some(rtt) => {
                failures = 0;
                successes += 1;
                health
                    .rtt_ms
                    .store((rtt.as_millis() as u64).max(1), Ordering::Relaxed);
                *lock(&health.detail) = None;
                if successes >= check.recovery_threshold {
                    health.set(true);
                }
            }
            None => {
                successes = 0;
                failures += 1;
                *lock(&health.detail) = error;
                if failures >= check.failure_threshold {
                    health.set(false);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(check.interval_ms)).await;
    }
}

const STATE_APPLIED: &str = "applied";
const STATE_DEGRADED: &str = "degraded";
const STATE_DOWN: &str = "down";

/// `GET /v1/network`, in the shape of the agent's `NetworkStatus`
/// components.
#[derive(Clone, Debug, Serialize)]
pub struct NetworkStatus {
    pub generation: u64,
    pub egresses: Vec<EgressState>,
    pub ingresses: Vec<IngressState>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EgressState {
    pub id: String,
    pub source: Option<IpAddr>,
    /// `applied` (healthy, or not checked) or `down`.
    pub state: &'static str,
    /// Whether the kernel probes it.
    pub checked: bool,
    /// The last successful probe's connect time.
    pub rtt_ms: Option<u64>,
    /// Why the last probe failed.
    pub detail: Option<String>,
    pub changed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct IngressState {
    pub id: String,
    /// `applied` (first path), `degraded` (failed over) or `down`.
    pub state: &'static str,
    pub active_egress_id: Option<String>,
    pub active_path_id: Option<String>,
}

impl fmt::Display for Hop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hop::Egress(id) => write!(f, "{EGRESS_PREFIX}{id}"),
            Hop::Outbound(name) => f.write_str(name),
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// The base outbound `egress:<id>`: the egress's direct outbound, looked
/// up in the plan when a connection opens.
#[derive(Clone)]
pub(crate) struct EgressOutbound {
    network: Arc<Network>,
    egress: String,
    allowed: Vec<(String, u16)>,
}

impl EgressOutbound {
    pub(crate) fn node_outbound(
        network: Arc<Network>,
        egress: String,
        allowed: Vec<(String, u16)>,
    ) -> NodeOutbound {
        let outbound = Arc::new(Self {
            network,
            egress,
            allowed,
        });
        NodeOutbound::new(outbound.clone(), outbound)
    }

    fn resolve(&self) -> io::Result<NodeOutbound> {
        let compiled = self.network.compiled();
        self.network
            .egress_outbound(&compiled, &self.egress, &self.allowed)
    }
}

impl TcpOutbound for EgressOutbound {
    fn protocol(&self) -> &'static str {
        "egress"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.resolve()?.tcp.connect(target).await })
    }
}

impl UdpOutbound for EgressOutbound {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move { self.resolve()?.udp.bind().await })
    }
}

/// The base outbound of an inbound in an ingress: the ingress's active
/// path when a connection or UDP session opens.
#[derive(Clone)]
pub(crate) struct IngressOutbound {
    network: Arc<Network>,
    ingress: String,
    allowed: Vec<(String, u16)>,
    registered: BTreeMap<String, NodeOutbound>,
}

impl IngressOutbound {
    pub(crate) fn node_outbound(
        network: Arc<Network>,
        ingress: String,
        allowed: Vec<(String, u16)>,
        registered: BTreeMap<String, NodeOutbound>,
    ) -> NodeOutbound {
        let outbound = Arc::new(Self {
            network,
            ingress,
            allowed,
            registered,
        });
        NodeOutbound::new(outbound.clone(), outbound)
    }

    fn resolve(&self) -> io::Result<NodeOutbound> {
        let compiled = self.network.compiled();
        let (_, candidate) = self
            .network
            .select(&compiled, &self.ingress)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "ingress has no path in the network plan",
                )
            })?;
        self.network
            .hop_outbound(&compiled, &candidate.hop, &self.allowed, &self.registered)
    }
}

impl TcpOutbound for IngressOutbound {
    fn protocol(&self) -> &'static str {
        "ingress"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.resolve()?.tcp.connect(target).await })
    }
}

impl UdpOutbound for IngressOutbound {
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>> {
        Box::pin(async move { self.resolve()?.udp.bind().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan(value: serde_json::Value) -> NetworkPlan {
        serde_json::from_value(value).unwrap()
    }

    fn registered(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn compiles_failover_in_pairing_order() {
        let compiled = compile(
            &plan(json!({
                "generation": "7",
                "egresses": [
                    {"id": "cn2-v4", "source": "203.0.113.5", "kind": "EGRESS_KIND_NAT_DIRECT",
                     "health": {"targets": ["1.1.1.1:443"], "intervalMs": "5000"}},
                    {"id": "9929-v4", "source": "198.51.100.7"}
                ],
                "ingresses": [{"id": "cn2-v6", "pairing": {
                    "mode": "PAIRING_MODE_FAILOVER",
                    "egress_ids": ["jp-exit", "9929-v4", "cn2-v4"],
                    "failback_delay_ms": 300000}}],
                "transports": [{"id": "7", "kind": "TRANSPORT_KIND_ANX_LINE",
                                "anx_line": {"link_key": "secret"}}],
                "paths": [
                    {"id": "p-local", "ingress_id": "cn2-v6", "egress_id": "cn2-v4"},
                    {"id": "p-jp", "ingressId": "cn2-v6", "transportId": "7",
                     "final_egress_id": "jp-exit"}
                ],
                "lines": [{"id": "cn2"}]
            })),
            &registered(&["anx-line:7"]),
        )
        .unwrap();
        assert_eq!(compiled.generation, 7);
        let cn2 = &compiled.egresses["cn2-v4"];
        assert_eq!(cn2.source, Some("203.0.113.5".parse().unwrap()));
        let health = cn2.health.as_ref().unwrap();
        assert_eq!(
            (health.interval_ms, health.timeout_ms),
            (5000, DEFAULT_TIMEOUT_MS)
        );
        let ingress = &compiled.ingresses["cn2-v6"];
        let hops: Vec<String> = ingress
            .candidates
            .iter()
            .map(|c| c.hop.to_string())
            .collect();
        assert_eq!(hops, ["anx-line:7", "egress:9929-v4", "egress:cn2-v4"]);
        assert_eq!(ingress.failback, Duration::from_secs(300));
    }

    #[test]
    fn refuses_invalid_plans() {
        let egress = json!({"id": "e", "source": "203.0.113.5"});
        let cases = [
            json!({"egresses": [{"id": "e", "source": "10.0.0.300"}]}),
            json!({"egresses": [egress.clone(), egress.clone()]}),
            json!({"egresses": [{"id": "e", "health": {"targets": []}}]}),
            json!({"egresses": [{"id": "e", "health": {"targets": ["1.1.1.1"]}}]}),
            json!({"egresses": [{"id": "e", "health": {"targets": ["a:1"], "interval_ms": 10}}]}),
            json!({"egresses": [egress.clone()], "ingresses": [{"id": "i",
                "pairing": {"mode": "PAIRING_MODE_RULES"}}]}),
            json!({"egresses": [egress.clone()], "ingresses": [{"id": "i",
                "pairing": {"mode": "PAIRING_MODE_CROSS", "egress_ids": ["e", "e"]}}]}),
            json!({"ingresses": [{"id": "i", "pairing": {"egress_ids": ["missing"]}}]}),
            json!({"ingresses": [{"id": "i"}], "transports": [{"id": "9", "kind": "anx_line"}],
                   "paths": [{"id": "p", "ingress_id": "i", "transport_id": "9"}]}),
            json!({"egresses": [egress.clone()], "ingresses": [{"id": "i"}],
                   "paths": [{"id": "p", "ingress_id": "i"}]}),
            json!({"egresses": [egress], "ingresses": [{"id": "i"}],
                   "paths": [{"id": "p", "ingress_id": "other", "egress_id": "e"}]}),
            json!({"egresses": [{"id": "a/b"}]}),
        ];
        for case in cases {
            let text = case.to_string();
            let error = compile(&plan(case), &BTreeSet::new()).err().expect(&text);
            assert!(error.starts_with("network "), "{error}");
        }
    }

    #[test]
    fn chooses_with_failback_delay() {
        let now = Instant::now();
        let long_ago = now - Duration::from_secs(600);
        let delay = Duration::from_secs(300);
        let up = |since| Some((true, since));
        let down = Some((false, long_ago));
        assert_eq!(choose(&[], None, now, delay), None);
        assert_eq!(
            choose(&[up(long_ago), up(long_ago)], None, now, delay),
            Some(0)
        );
        assert_eq!(choose(&[down, up(long_ago)], Some(0), now, delay), Some(1));
        // Recovered just now: stay on the second until the delay passed.
        assert_eq!(
            choose(&[up(now), up(long_ago)], Some(1), now, delay),
            Some(1)
        );
        assert_eq!(
            choose(&[up(long_ago), up(long_ago)], Some(1), now, delay),
            Some(0)
        );
        // Nothing healthy: the first is tried.
        assert_eq!(choose(&[down, down], Some(1), now, delay), Some(0));
        // Unprobed candidates count as healthy.
        assert_eq!(choose(&[down, None], None, now, delay), Some(1));
    }

    #[tokio::test]
    async fn probes_from_the_source_and_fails_over() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive = listener.local_addr().unwrap();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let dead = {
            let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            closed.local_addr().unwrap()
        };
        let health = |target: std::net::SocketAddr| {
            json!({"targets": [target.to_string()], "interval_ms": 1000, "timeout_ms": 500,
                   "failure_threshold": 1, "recovery_threshold": 1})
        };
        let network = Network::new(true);
        let status = network
            .apply(
                &plan(json!({
                    "generation": 1,
                    "egresses": [
                        {"id": "a", "source": "127.0.0.1", "health": health(dead)},
                        {"id": "b", "source": "127.0.0.1", "health": health(alive)}
                    ],
                    "ingresses": [{"id": "i", "pairing": {
                        "mode": "PAIRING_MODE_FAILOVER", "egress_ids": ["a", "b"]}}]
                })),
                &BTreeSet::new(),
            )
            .await
            .unwrap();
        assert_eq!(status.ingresses[0].active_egress_id.as_deref(), Some("a"));
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            let status = network.status();
            if status.ingresses[0].active_egress_id.as_deref() == Some("b")
                || Instant::now() > deadline
            {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(status.ingresses[0].active_egress_id.as_deref(), Some("b"));
        assert_eq!(status.ingresses[0].state, STATE_DEGRADED);
        assert_eq!(status.egresses[0].state, STATE_DOWN);
        assert!(status.egresses[0].detail.is_some());
        assert_eq!(status.egresses[1].state, STATE_APPLIED);
    }
}
