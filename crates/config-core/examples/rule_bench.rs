//! Rule decision benchmark: how long [`RoutingModel::decide`] takes for one
//! connection against a large rule list.
//!
//! The list is synthetic but shaped like real subscriptions: mostly
//! DOMAIN-SUFFIX and DOMAIN lines, a block of `no-resolve` IP-CIDR lines,
//! some DOMAIN-KEYWORD, DOMAIN-WILDCARD, DST-PORT and AND lines, then
//! `GEOIP,CN` (which resolves a domain) and FINAL. Queries hit rules at
//! every position, and a share misses every rule, the worst case: the whole
//! list is walked, the domain is resolved and FINAL decides.
//!
//! ```text
//! cargo run --release -p config-core --example rule_bench -- \
//!     --rules 10000 --queries 200000 --max-p99-us 50 --json rules.json
//! ```
//!
//! Options: `--rules N`, `--queries N` (timed decisions per round),
//! `--rounds N` (the round with the median p99 is reported), `--miss-share F`
//! (share of queries that match no rule, 0..1), `--max-p99-us F` (exit 1 when
//! the p99 of all queries is above it), `--json PATH`.
//!
//! `.github/workflows/perf.yml` runs it on pull requests that touch routing.

use std::collections::{BTreeSet, HashMap};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use config_core::routing::{
    PolicyGroupSpec, RouteMatch, RouteNetwork, RouteQuery, RoutingEnvironment, RoutingModel,
    RoutingSpec,
};

const TLDS: [&str; 8] = ["com", "net", "org", "io", "cn", "jp", "dev", "app"];

/// Deterministic xorshift64*, so every run benchmarks the same list.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn chance(&mut self, share: f64) -> bool {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= share
    }
}

/// Resolves every domain to a documentation address and knows no country,
/// so `GEOIP,CN` costs one resolve and never matches.
struct BenchEnvironment;

impl RoutingEnvironment for BenchEnvironment {
    fn resolve(&self, domain: &str) -> Option<IpAddr> {
        let low = domain.len() as u8;
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, low)))
    }
}

/// What a query is expected to hit, for the per-kind breakdown.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    Suffix,
    Exact,
    Keyword,
    Ip,
    Miss,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Suffix => "domain_suffix",
            Kind::Exact => "domain",
            Kind::Keyword => "domain_keyword",
            Kind::Ip => "ip_cidr",
            Kind::Miss => "miss",
        }
    }
}

struct RuleList {
    lines: Vec<String>,
    suffixes: Vec<String>,
    exacts: Vec<String>,
    keywords: Vec<String>,
    v4_nets: Vec<Ipv4Addr>,
}

fn domain_label(rng: &mut Rng, index: usize) -> String {
    // Letters keep the names apart from keywords, which use digits only.
    let mut label = String::new();
    let mut value = index + 1;
    while value > 0 {
        label.push((b'a' + (value % 26) as u8) as char);
        value /= 26;
    }
    for _ in 0..(3 + rng.below(6)) {
        label.push((b'a' + rng.below(26) as u8) as char);
    }
    format!("{label}.{}", TLDS[rng.below(TLDS.len())])
}

fn build_rules(count: usize, rng: &mut Rng) -> RuleList {
    let targets = ["Proxy", "DIRECT", "REJECT", "hk-1"];
    let mut list = RuleList {
        lines: Vec::with_capacity(count + 2),
        suffixes: Vec::new(),
        exacts: Vec::new(),
        keywords: Vec::new(),
        v4_nets: Vec::new(),
    };
    let body = count.saturating_sub(1);
    for index in 0..body {
        let target = targets[rng.below(targets.len())];
        let roll = rng.below(1000);
        let line = if roll < 550 {
            let suffix = domain_label(rng, index);
            let line = format!("DOMAIN-SUFFIX,{suffix},{target}");
            list.suffixes.push(suffix);
            line
        } else if roll < 700 {
            let domain = format!("www.{}", domain_label(rng, index));
            let line = format!("DOMAIN,{domain},{target}");
            list.exacts.push(domain);
            line
        } else if roll < 730 {
            let keyword = format!("k{index}x");
            let line = format!("DOMAIN-KEYWORD,{keyword},{target}");
            list.keywords.push(keyword);
            line
        } else if roll < 740 {
            format!(
                "DOMAIN-WILDCARD,*.w{index}?.{},{target}",
                TLDS[rng.below(TLDS.len())]
            )
        } else if roll < 940 {
            // 10.0.0.0/8 and above, outside the 192.0.2.0/24 the
            // environment resolves to.
            let net = Ipv4Addr::new(
                10 + rng.below(80) as u8,
                rng.below(256) as u8,
                rng.below(256) as u8,
                0,
            );
            list.v4_nets.push(net);
            format!("IP-CIDR,{net}/24,{target},no-resolve")
        } else if roll < 970 {
            let net = Ipv6Addr::new(0x2001, 0x0db8, rng.below(65536) as u16, 0, 0, 0, 0, 0);
            format!("IP-CIDR6,{net}/48,{target},no-resolve")
        } else if roll < 990 {
            let port = 10_000 + rng.below(50_000);
            format!("DST-PORT,{port},{target}")
        } else {
            format!(
                "AND,((DOMAIN-SUFFIX,a{index}.{}),(DST-PORT,443)),{target}",
                TLDS[rng.below(TLDS.len())]
            )
        };
        list.lines.push(line);
    }
    list.lines.push("GEOIP,CN,DIRECT".to_string());
    list.lines.push("FINAL,Proxy".to_string());
    list
}

fn model(lines: Vec<String>) -> RoutingModel {
    let nodes = BTreeSet::from(["hk-1".to_string(), "jp-1".to_string()]);
    let spec = RoutingSpec {
        rules: lines,
        groups: vec![PolicyGroupSpec {
            id: "Proxy".to_string(),
            kind: "select".to_string(),
            members: vec!["hk-1".to_string(), "jp-1".to_string(), "DIRECT".to_string()],
            default: None,
            url: None,
            interval_secs: None,
            tolerance_ms: None,
        }],
    };
    RoutingModel::from_spec(&spec, &nodes).expect("benchmark rules are valid")
}

fn build_queries(
    list: &RuleList,
    count: usize,
    miss_share: f64,
    rng: &mut Rng,
) -> Vec<(Kind, RouteQuery)> {
    let mut queries = Vec::with_capacity(count);
    for _ in 0..count {
        let port = 443;
        let (kind, query) = if rng.chance(miss_share) {
            let domain = format!(
                "q{}.miss-{}.example",
                rng.below(1 << 20),
                rng.below(1 << 20)
            );
            (Kind::Miss, RouteQuery::domain(domain))
        } else {
            match rng.below(100) {
                0..=54 if !list.suffixes.is_empty() => {
                    let suffix = &list.suffixes[rng.below(list.suffixes.len())];
                    (
                        Kind::Suffix,
                        RouteQuery::domain(format!("api{}.{suffix}", rng.below(100))),
                    )
                }
                55..=74 if !list.exacts.is_empty() => {
                    let domain = list.exacts[rng.below(list.exacts.len())].clone();
                    (Kind::Exact, RouteQuery::domain(domain))
                }
                75..=79 if !list.keywords.is_empty() => {
                    let keyword = &list.keywords[rng.below(list.keywords.len())];
                    (
                        Kind::Keyword,
                        RouteQuery::domain(format!("cdn.{keyword}y.example")),
                    )
                }
                _ if !list.v4_nets.is_empty() => {
                    let net = list.v4_nets[rng.below(list.v4_nets.len())].octets();
                    let ip = Ipv4Addr::new(net[0], net[1], net[2], 1 + rng.below(250) as u8);
                    (Kind::Ip, RouteQuery::ip(IpAddr::V4(ip)))
                }
                _ => (Kind::Miss, RouteQuery::domain("only.miss.example")),
            }
        };
        queries.push((kind, query.with_port(port).with_network(RouteNetwork::Tcp)));
    }
    queries
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index]
}

fn stats(samples: &mut [f64]) -> serde_json::Value {
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len().max(1) as f64;
    serde_json::json!({
        "count": samples.len(),
        "mean_us": mean,
        "p50_us": percentile(samples, 0.5),
        "p90_us": percentile(samples, 0.9),
        "p99_us": percentile(samples, 0.99),
        "p999_us": percentile(samples, 0.999),
        "max_us": samples.last().copied().unwrap_or(0.0),
    })
}

/// Microseconds per decision: all queries, by kind, and how many decisions
/// hit when a miss was expected or the other way round.
type Round = (Vec<f64>, HashMap<Kind, Vec<f64>>, usize);

/// One timed pass over `queries`: microseconds per decision, by kind.
fn round(model: &RoutingModel, queries: &[(Kind, RouteQuery)]) -> Round {
    let environment = BenchEnvironment;
    let mut all = Vec::with_capacity(queries.len());
    let mut by_kind: HashMap<Kind, Vec<f64>> = HashMap::new();
    let mut unexpected = 0;
    for (kind, query) in queries {
        let begin = Instant::now();
        let resolution = black_box(model.decide(black_box(query), &environment));
        let micros = begin.elapsed().as_secs_f64() * 1e6;
        let missed = matches!(resolution.matched, RouteMatch::Final);
        if missed != (*kind == Kind::Miss) {
            unexpected += 1;
        }
        all.push(micros);
        by_kind.entry(*kind).or_default().push(micros);
    }
    (all, by_kind, unexpected)
}

fn main() {
    let mut args: HashMap<String, String> = HashMap::new();
    let mut argv = std::env::args().skip(1);
    while let Some(key) = argv.next() {
        let value = argv.next().unwrap_or_default();
        args.insert(key.trim_start_matches("--").to_string(), value);
    }
    let number = |key: &str, default: f64| -> f64 {
        args.get(key).map_or(default, |value| {
            value.parse().unwrap_or_else(|_| {
                eprintln!("rule_bench: --{key} is not a number");
                std::process::exit(2);
            })
        })
    };
    let rules = number("rules", 10_000.0) as usize;
    let count = number("queries", 200_000.0) as usize;
    let rounds = (number("rounds", 3.0) as usize).max(1);
    let miss_share = number("miss-share", 0.1).clamp(0.0, 1.0);
    let max_p99_us = args.get("max-p99-us").map(|_| number("max-p99-us", 0.0));

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let list = build_rules(rules, &mut rng);
    let built = Instant::now();
    let model = model(list.lines.clone());
    let build_ms = built.elapsed().as_secs_f64() * 1e3;
    let queries = build_queries(&list, count, miss_share, &mut rng);

    // Warm caches and the branch predictor on a different slice of queries.
    let warmup = &queries[..queries.len().min(20_000)];
    let _ = round(&model, warmup);

    let mut results = Vec::new();
    for _ in 0..rounds {
        results.push(round(&model, &queries));
    }
    let mut p99s: Vec<(f64, usize)> = results
        .iter()
        .enumerate()
        .map(|(index, (all, _, _))| {
            let mut sorted = all.clone();
            sorted.sort_by(f64::total_cmp);
            (percentile(&sorted, 0.99), index)
        })
        .collect();
    p99s.sort_by(|a, b| a.0.total_cmp(&b.0));
    let median = p99s[p99s.len() / 2].1;
    let (mut all, mut by_kind, unexpected) = results.swap_remove(median);

    let mut kinds = serde_json::Map::new();
    for kind in [
        Kind::Suffix,
        Kind::Exact,
        Kind::Keyword,
        Kind::Ip,
        Kind::Miss,
    ] {
        if let Some(samples) = by_kind.get_mut(&kind) {
            kinds.insert(kind.name().to_string(), stats(samples));
        }
    }
    let overall = stats(&mut all);
    let p99 = overall["p99_us"].as_f64().unwrap_or(f64::MAX);
    let report = serde_json::json!({
        "rules": model.rules.len() + 1,
        "queries": count,
        "rounds": rounds,
        "miss_share": miss_share,
        "build_ms": build_ms,
        "all": overall,
        "by_kind": kinds,
        "unexpected_results": unexpected,
        "max_p99_us": max_p99_us,
        "pass": max_p99_us.is_none_or(|limit| p99 <= limit),
    });
    let text = serde_json::to_string_pretty(&report).expect("report serializes");
    println!("{text}");
    if let Some(path) = args.get("json") {
        if let Err(err) = std::fs::write(path, &text) {
            eprintln!("rule_bench: cannot write {path}: {err}");
            std::process::exit(2);
        }
    }
    if unexpected > 0 {
        eprintln!("rule_bench: {unexpected} decisions disagreed with the expected hit or miss");
        std::process::exit(1);
    }
    if let Some(limit) = max_p99_us {
        if p99 > limit {
            eprintln!("rule_bench: p99 {p99:.2} us is above the {limit} us limit");
            std::process::exit(1);
        }
    }
}
