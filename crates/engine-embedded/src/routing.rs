//! Rule-based outbound: picks a node per connection with the shared
//! `config-core` routing model.
//!
//! The tunnel only sees destination addresses, so domain rules match only
//! when a caller passes a [`TargetAddr::Domain`] (the desktop local proxy
//! does); FakeIP and sniffing are not wired yet. A domain target that reaches
//! an IP rule without `no-resolve` is resolved once with the
//! [`DomainResolver`] (the system resolver by default), and that address is
//! matched by every later IP rule; the connection itself still goes out by
//! name, so a proxy node resolves it remotely. A failed lookup rejects the
//! connection, the same result sing-box gives. GeoIP rules never match
//! because the runtime ships no GeoIP database. `RULE-SET` rules match the
//! named [`RuleSet`] from the config, never resolving a domain for its
//! networks. Select groups use their configured default (or first member).
//! url-test and fallback groups use the latencies measured by
//! [`RoutedOutbound::run_health_checks`] (the desktop local proxy runs it):
//! url-test takes the fastest member, fallback the first that answered, and
//! both use their first member until a check has finished.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use config_core::routing::{
    PolicyTarget, RouteMatch, RouteOutcome, RouteQuery, RouteResolution, RoutingEnvironment,
    RoutingModel, RoutingSpec, RuleMatcher,
};
use config_core::rule_set::RuleSet;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};

use crate::{RuntimeError, RuntimeErrorCode};

pub const PROTOCOL: &str = "routed";

pub struct RoutedOutbound {
    model: RoutingModel,
    rule_sets: RuleSets,
    direct: Arc<dyn TcpOutbound>,
    nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    resolver: Arc<dyn DomainResolver>,
    latencies: Arc<RwLock<Latencies>>,
}

/// Last measured latency per url-test or fallback group, keyed by member name.
/// A member that failed its last check is absent.
type Latencies = BTreeMap<String, BTreeMap<String, u32>>;

/// Looks up a domain for IP rules that allow resolution.
pub trait DomainResolver: Send + Sync {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>>;
}

/// The operating system resolver (`getaddrinfo`), first address returned.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl DomainResolver for SystemResolver {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        Box::pin(async move {
            tokio::net::lookup_host((domain, 0))
                .await?
                .next()
                .map(|addr| addr.ip())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain has no address"))
        })
    }
}

/// The configured rule sets, by name.
struct RuleSets(BTreeMap<String, RuleSet>);

/// What the model sees while routing one connection: the rule sets, the
/// group latencies, and the address looked up for it, if any.
struct QueryEnvironment<'a> {
    rule_sets: &'a RuleSets,
    latencies: &'a Latencies,
    resolved: Option<IpAddr>,
}

impl RoutingEnvironment for QueryEnvironment<'_> {
    fn rule_set_matches(&self, name: &str, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        self.rule_sets
            .0
            .get(name)
            .is_some_and(|set| set.matches(domain, ip))
    }

    fn resolve(&self, _domain: &str) -> Option<IpAddr> {
        self.resolved
    }

    fn member_latency_ms(&self, group_id: &str, member: &PolicyTarget) -> Option<u32> {
        self.latencies.get(group_id)?.get(member.name()).copied()
    }
}

impl RoutedOutbound {
    /// Validates `spec` against the node ids in `nodes`. The error message is
    /// fixed so rule text and node settings never reach status or logs.
    pub fn new(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    ) -> Result<Self, RuntimeError> {
        Self::with_rule_sets(spec, direct, nodes, BTreeMap::new())
    }

    /// As [`RoutedOutbound::new`], with the sets `RULE-SET` rules name; a rule
    /// naming a missing set is rejected.
    pub fn with_rule_sets(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
        rule_sets: BTreeMap<String, RuleSet>,
    ) -> Result<Self, RuntimeError> {
        let node_ids = nodes.keys().cloned().collect();
        let model = RoutingModel::from_spec(spec, &node_ids).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "routing rules or policy groups are invalid",
            )
        })?;
        let unknown_set = model.rules.iter().any(|rule| {
            matches!(&rule.matcher, RuleMatcher::RuleSet(name) if !rule_sets.contains_key(name))
        });
        if unknown_set {
            return Err(RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "a routing rule names a rule set that is not configured",
            ));
        }
        Ok(Self {
            model,
            rule_sets: RuleSets(rule_sets),
            direct,
            nodes,
            resolver: Arc::new(SystemResolver),
            latencies: Arc::default(),
        })
    }

    /// Replaces the resolver used for IP rules (tests inject a fixed one).
    pub fn with_resolver(mut self, resolver: Arc<dyn DomainResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    pub fn model(&self) -> &RoutingModel {
        &self.model
    }

    /// Where a connection to `target` goes without resolving its domain: a
    /// domain that reaches an IP rule without `no-resolve` is rejected.
    pub fn route(&self, target: &TargetAddr) -> RouteOutcome {
        self.decide(&query(target), None).outcome
    }

    fn decide(&self, query: &RouteQuery, resolved: Option<IpAddr>) -> RouteResolution {
        let latencies = self
            .latencies
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let environment = QueryEnvironment {
            rule_sets: &self.rule_sets,
            latencies: &latencies,
            resolved,
        };
        self.model.decide(query, &environment)
    }

    /// Records a health check result for a group member; `None` marks it
    /// failed.
    pub fn record_latency(&self, group_id: &str, member: &str, latency_ms: Option<u32>) {
        let mut latencies = self
            .latencies
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let group = latencies.entry(group_id.to_string()).or_default();
        match latency_ms {
            Some(latency) => group.insert(member.to_string(), latency),
            None => group.remove(member),
        };
    }

    /// Where a connection to `target` goes, resolving its domain only when an
    /// IP rule asks for an address before another rule matches.
    pub async fn route_resolving(&self, target: &TargetAddr) -> RouteOutcome {
        let query = query(target);
        let first = self.decide(&query, None);
        let (TargetAddr::Domain(domain, _), RouteMatch::ResolveFailed(_)) = (target, first.matched)
        else {
            return first.outcome;
        };
        let Ok(resolved) = self.resolver.resolve(domain).await else {
            return first.outcome;
        };
        self.decide(&query, Some(resolved)).outcome
    }

    /// Measures every member of the url-test and fallback groups through its
    /// outbound, then again after the shortest group interval, forever. Group
    /// members that are groups themselves or REJECT are not measured. Never
    /// returns when no group needs checks.
    #[cfg(feature = "local-proxy")]
    pub async fn run_health_checks(self: Arc<Self>) {
        use config_core::routing::PolicyGroupKind;
        use std::time::Duration;

        const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
        let checked: Vec<_> = self
            .model
            .groups
            .iter()
            .filter(|group| group.kind != PolicyGroupKind::Select)
            .filter_map(|group| Some((group, group.health_check.clone()?)))
            .collect();
        let Some(interval) = checked
            .iter()
            .map(|(_, check)| check.interval_secs.max(30))
            .min()
        else {
            return std::future::pending().await;
        };
        loop {
            let mut probes = tokio::task::JoinSet::new();
            for (group, check) in &checked {
                for member in &group.members {
                    let outbound = match member {
                        PolicyTarget::Node(id) => self.nodes.get(id).cloned(),
                        PolicyTarget::Direct => Some(self.direct.clone()),
                        PolicyTarget::Reject | PolicyTarget::Group(_) => None,
                    };
                    let Some(outbound) = outbound else { continue };
                    let (group_id, name, url) = (
                        group.id.clone(),
                        member.name().to_string(),
                        check.url.clone(),
                    );
                    probes.spawn(async move {
                        let latency = crate::delay::probe(&*outbound, &url, PROBE_TIMEOUT)
                            .await
                            .ok()
                            .map(|elapsed| u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX));
                        (group_id, name, latency)
                    });
                }
            }
            while let Some(result) = probes.join_next().await {
                if let Ok((group_id, member, latency)) = result {
                    self.record_latency(&group_id, &member, latency);
                }
            }
            tokio::time::sleep(Duration::from_secs(u64::from(interval))).await;
        }
    }
}

fn query(target: &TargetAddr) -> RouteQuery {
    match target {
        TargetAddr::Ip(addr) => RouteQuery::ip(addr.ip()),
        TargetAddr::Domain(domain, _) => RouteQuery::domain(domain.clone()),
    }
}

impl TcpOutbound for RoutedOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let outbound = match self.route_resolving(target).await {
                RouteOutcome::Reject => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "connection rejected by routing rule",
                    ))
                }
                RouteOutcome::Direct => &self.direct,
                RouteOutcome::Node(id) => self.nodes.get(&id).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "routed node is not configured")
                })?,
            };
            outbound.connect(target).await
        })
    }
}
