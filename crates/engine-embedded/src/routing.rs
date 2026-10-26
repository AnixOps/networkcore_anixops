//! Rule-based outbound: picks a node per connection with the shared
//! `config-core` routing model.
//!
//! The tunnel only sees destination addresses, so domain rules match a
//! [`TargetAddr::Domain`] (the desktop local proxy passes one) or the host
//! name the tunnel sniffed from the flow, given to
//! [`RoutedOutbound::route_flow`]; FakeIP is not wired yet. A domain target that reaches
//! an IP rule without `no-resolve` is resolved once with the
//! [`DomainResolver`] (the system resolver by default), and that address is
//! matched by every later IP rule; the connection itself still goes out by
//! name, so a proxy node resolves it remotely. A failed lookup rejects the
//! connection, the same result sing-box gives. GeoIP rules never match
//! because the runtime ships no GeoIP database. `RULE-SET` rules match the
//! named [`RuleSet`] from the config, never resolving a domain for its
//! networks. Select groups use their configured default (or first member)
//! until [`RoutedOutbound::select`] switches them while the engine runs. The
//! global mode skips the rules for one target ([`RoutedOutbound::with_global`]).
//! url-test and fallback groups use the latencies measured by
//! [`RoutedOutbound::run_health_checks`] (the desktop local proxy runs it):
//! url-test takes the fastest member, fallback the first that answered, and
//! both use their first member until a check has finished.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use config_core::routing::{
    PolicyGroupKind, PolicyTarget, RouteMatch, RouteOutcome, RouteQuery, RouteResolution,
    RoutingEnvironment, RoutingModel, RoutingSpec, RuleMatcher,
};
use config_core::rule_set::RuleSet;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound, UdpFlow};
use serde::Serialize;

use crate::{RuntimeError, RuntimeErrorCode};

pub const PROTOCOL: &str = "routed";

pub struct RoutedOutbound {
    model: RoutingModel,
    rule_sets: RuleSets,
    direct: Arc<dyn TcpOutbound>,
    nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    resolver: Arc<dyn DomainResolver>,
    latencies: Arc<RwLock<Latencies>>,
    /// Members picked at runtime in select groups, by group id.
    selected: RwLock<BTreeMap<String, String>>,
    /// Where the global mode sends every connection.
    global: PolicyTarget,
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

/// Why a flow went where it did: the matched rule (`FINAL` when none did),
/// the policy groups passed through and the outbound picked, ending with it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RouteInfo {
    pub rule: String,
    pub chain: Vec<String>,
    /// A node id, `DIRECT` or `REJECT`.
    pub outbound: String,
}

/// The configured rule sets, by name.
struct RuleSets(BTreeMap<String, RuleSet>);

/// What the model sees while routing one connection: the rule sets, the
/// group latencies, and the address looked up for it, if any.
struct QueryEnvironment<'a> {
    rule_sets: &'a RuleSets,
    latencies: &'a Latencies,
    selected: &'a BTreeMap<String, String>,
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

    fn selected_member(&self, group_id: &str) -> Option<String> {
        self.selected.get(group_id).cloned()
    }
}

/// One policy group as the client's policy page shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupView {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The member the group picks now.
    pub now: String,
    pub members: Vec<MemberView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberView {
    pub name: String,
    /// Last health check result of a url-test or fallback member; `None`
    /// when untested, failed, or in a select group.
    pub latency_ms: Option<u32>,
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
        let global = match model.groups.first() {
            Some(group) => PolicyTarget::Group(group.id.clone()),
            None => nodes
                .keys()
                .next()
                .map_or(PolicyTarget::Direct, |id| PolicyTarget::Node(id.clone())),
        };
        Ok(Self {
            model,
            rule_sets: RuleSets(rule_sets),
            direct,
            nodes,
            resolver: Arc::new(SystemResolver),
            latencies: Arc::default(),
            selected: RwLock::default(),
            global,
        })
    }

    /// Sets where the global mode sends connections: a policy group, a node
    /// or DIRECT. Without one it is the first group, else the first node.
    pub fn with_global(mut self, name: &str) -> Result<Self, RuntimeError> {
        let node_ids = self.nodes.keys().cloned().collect();
        self.global = match self.model.target_named(name, &node_ids) {
            Some(PolicyTarget::Reject) | None => {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::ConfigRejected,
                    "the global target must be a policy group, a node or DIRECT",
                ))
            }
            Some(target) => target,
        };
        Ok(self)
    }

    /// The outbound for connections that skip the rules (the direct mode).
    pub fn direct(&self) -> &Arc<dyn TcpOutbound> {
        &self.direct
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
        self.with_environment(resolved, |environment| {
            self.model.decide(query, environment)
        })
    }

    fn with_environment<T>(
        &self,
        resolved: Option<IpAddr>,
        body: impl FnOnce(&QueryEnvironment<'_>) -> T,
    ) -> T {
        let latencies = self
            .latencies
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let selected = self
            .selected
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        body(&QueryEnvironment {
            rule_sets: &self.rule_sets,
            latencies: &latencies,
            selected: &selected,
            resolved,
        })
    }

    /// Picks `member` in the select group `group_id` for every later
    /// connection, without restarting. Returns the member's name.
    pub fn select(&self, group_id: &str, member: &str) -> Result<String, RuntimeError> {
        let invalid = |message| RuntimeError::new(RuntimeErrorCode::InvalidArgument, message);
        let group = self
            .model
            .group(group_id)
            .ok_or_else(|| invalid("no policy group has that id"))?;
        if group.kind != PolicyGroupKind::Select {
            return Err(invalid("only select groups can be switched"));
        }
        let member = group
            .members
            .iter()
            .find(|candidate| candidate.name() == member.trim())
            .ok_or_else(|| invalid("the policy group has no such member"))?;
        self.selected
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group.id.clone(), member.name().to_string());
        Ok(member.name().to_string())
    }

    /// Every policy group with the member it picks now and the members'
    /// last measured latencies, in configuration order.
    pub fn groups(&self) -> Vec<GroupView> {
        self.with_environment(None, |environment| {
            self.model
                .groups
                .iter()
                .map(|group| GroupView {
                    id: group.id.clone(),
                    kind: group.kind.as_str(),
                    now: self
                        .model
                        .group_member(&group.id, environment)
                        .map(|member| member.name().to_string())
                        .unwrap_or_default(),
                    members: group
                        .members
                        .iter()
                        .map(|member| MemberView {
                            name: member.name().to_string(),
                            latency_ms: environment.member_latency_ms(&group.id, member),
                        })
                        .collect(),
                })
                .collect()
        })
    }

    /// Routes a flow of the global mode: every connection to the global
    /// target, through its groups.
    pub fn route_global(&self) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let resolution = self.with_environment(None, |environment| {
            self.model.route_to(&self.global, environment)
        });
        let mut route = self.describe(&resolution);
        route.rule = "MODE,global".to_string();
        (route, self.outbound_of(&resolution.outcome))
    }

    fn outbound_of(&self, outcome: &RouteOutcome) -> Option<Arc<dyn TcpOutbound>> {
        match outcome {
            RouteOutcome::Reject => None,
            RouteOutcome::Direct => Some(self.direct.clone()),
            RouteOutcome::Node(id) => self.nodes.get(id).cloned(),
        }
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
        self.resolve_query(&query(target)).await.outcome
    }

    /// Routes a flow to `target` and says why. For an address target,
    /// `sniffed` (a TLS SNI or HTTP `Host`) is matched by the domain rules
    /// while IP rules keep matching the address; the flow still connects to
    /// the address. A rejected flow gets no outbound.
    pub async fn route_flow(
        &self,
        target: &TargetAddr,
        sniffed: Option<&str>,
    ) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let mut query = query(target);
        if query.domain.is_none() {
            query.domain = sniffed.map(str::to_string);
        }
        let resolution = self.resolve_query(&query).await;
        let outbound = self.outbound_of(&resolution.outcome);
        (self.describe(&resolution), outbound)
    }

    async fn resolve_query(&self, query: &RouteQuery) -> RouteResolution {
        let first = self.decide(query, None);
        let (Some(domain), RouteMatch::ResolveFailed(_)) = (query.domain.as_deref(), first.matched)
        else {
            return first;
        };
        let Ok(resolved) = self.resolver.resolve(domain).await else {
            return first;
        };
        self.decide(query, Some(resolved))
    }

    /// The rule, group path and outbound of a decision, as the connection
    /// list shows them.
    fn describe(&self, resolution: &RouteResolution) -> RouteInfo {
        let rule = match resolution.matched {
            RouteMatch::Rule(index) => self.model.rules[index].matcher.to_string(),
            RouteMatch::ResolveFailed(index) => {
                format!("{} (resolve failed)", self.model.rules[index].matcher)
            }
            RouteMatch::Final => "FINAL".to_string(),
        };
        let outbound = match &resolution.outcome {
            RouteOutcome::Direct => "DIRECT".to_string(),
            RouteOutcome::Reject => "REJECT".to_string(),
            RouteOutcome::Node(id) => id.clone(),
        };
        let mut chain = resolution.group_path.clone();
        chain.push(outbound.clone());
        RouteInfo {
            rule,
            chain,
            outbound,
        }
    }

    /// Measures every member of the url-test and fallback groups through its
    /// outbound, then again after the shortest group interval, forever. Group
    /// members that are groups themselves or REJECT are not measured. Never
    /// returns when no group needs checks.
    #[cfg(feature = "local-proxy")]
    pub async fn run_health_checks(self: Arc<Self>) {
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
        Box::pin(async move { self.outbound_for(target).await?.connect(target).await })
    }

    /// UDP follows the same rules as TCP, decided once per flow.
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move { self.outbound_for(target).await?.open_udp(target).await })
    }
}

impl RoutedOutbound {
    async fn outbound_for(&self, target: &TargetAddr) -> io::Result<&Arc<dyn TcpOutbound>> {
        match self.route_resolving(target).await {
            RouteOutcome::Reject => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connection rejected by routing rule",
            )),
            RouteOutcome::Direct => Ok(&self.direct),
            RouteOutcome::Node(id) => self.nodes.get(&id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "routed node is not configured")
            }),
        }
    }
}
