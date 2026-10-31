//! Registry entry for `"type": "reverse_proxy"` inbound config entries.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::StreamInbound;
use engine_outbound::TargetAddr;
use inbound_forward::balance::{Health, Strategy, Target, Targets};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;

use crate::{HostHeader, HostPattern, Options, ReverseProxyInbound, Route, Site};

pub const TYPE_NAME: &str = "reverse_proxy";

/// ```json
/// {"sites": [{"hosts": ["example.com", "*.example.com"],
///             "routes": [{"path": "/api", "strip_prefix": true,
///                         "upstreams": [{"server": "10.0.0.2", "server_port": 8080}],
///                         "balance": "least_conn", "host_header": "upstream",
///                         "headers": {"X-Site": "a"}},
///                        {"path": "/", "upstreams": [{"server": "10.0.0.3", "server_port": 3000}]}]}],
///  "tls": {"certificate": "-----BEGIN CERTIFICATE-----...", "key": "..."},
///  "forwarded_proto": "https", "max_header_bytes": 65536,
///  "idle_timeout_ms": 60000, "upstream_timeout_ms": 60000}
/// ```
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseProxySettings {
    sites: Vec<SiteSettings>,
    /// Terminates TLS; ALPN defaults to `http/1.1`, the only HTTP version
    /// the proxy speaks.
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    /// `http`, or `https`; defaults to `https` with `tls`, else `http`.
    #[serde(default)]
    forwarded_proto: Option<String>,
    #[serde(default)]
    max_header_bytes: u32,
    #[serde(default)]
    idle_timeout_ms: u32,
    #[serde(default)]
    upstream_timeout_ms: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteSettings {
    hosts: Vec<String>,
    #[serde(default)]
    routes: Vec<RouteSettings>,
    #[serde(default)]
    redirect_https: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSettings {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    strip_prefix: bool,
    /// `client` (default) or `upstream`.
    #[serde(default)]
    host_header: Option<String>,
    /// A fixed `Host`; overrides `host_header`.
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    upstreams: Vec<UpstreamSettings>,
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    health: HealthSettings,
    #[serde(default)]
    circuit_breaker: BreakerSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamSettings {
    server: String,
    server_port: u16,
    #[serde(default)]
    weight: u32,
    #[serde(default)]
    priority: u32,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthSettings {
    #[serde(default)]
    interval_ms: u32,
    #[serde(default)]
    timeout_ms: u32,
    #[serde(default)]
    disabled: bool,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakerSettings {
    #[serde(default)]
    failure_threshold: u32,
    #[serde(default)]
    open_ms: u32,
}

pub struct ReverseProxyInboundFactory;

fn or_default(ms: u32, default: Duration) -> Duration {
    match ms {
        0 => default,
        ms => Duration::from_millis(u64::from(ms)),
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn build_route(settings: &RouteSettings) -> Result<Route, BuildError> {
    let prefix = settings.path.as_deref().unwrap_or("/").trim().to_string();
    if !prefix.starts_with('/')
        || (prefix.len() > 1 && prefix.ends_with('/'))
        || prefix.contains(['?', '#', ' ', '\t'])
    {
        return Err("reverse proxy route path must start with / and not end with /");
    }
    if settings.upstreams.is_empty() {
        return Err("reverse proxy route needs upstreams");
    }
    let targets = settings
        .upstreams
        .iter()
        .map(|upstream| {
            let server = upstream.server.trim();
            if server.is_empty() {
                return Err("reverse proxy upstream server is missing");
            }
            if upstream.server_port == 0 {
                return Err("reverse proxy upstream server_port must not be 0");
            }
            Ok(Target {
                addr: TargetAddr::from_host(server, upstream.server_port),
                weight: upstream.weight.max(1),
                priority: upstream.priority,
            })
        })
        .collect::<Result<Vec<_>, BuildError>>()?;
    let strategy = match settings.balance.as_deref() {
        None => Strategy::default(),
        Some(value) => Strategy::parse(value).ok_or(
            "reverse proxy balance must be round_robin, random, ip_hash, least_conn or failover",
        )?,
    };
    let defaults = Health::default();
    let health = Health {
        active: !settings.health.disabled,
        interval: or_default(settings.health.interval_ms, defaults.interval),
        timeout: or_default(settings.health.timeout_ms, defaults.timeout),
        failure_threshold: match settings.circuit_breaker.failure_threshold {
            0 => defaults.failure_threshold,
            n => n,
        },
        open: or_default(settings.circuit_breaker.open_ms, defaults.open),
    };
    let host_header = match (&settings.host, settings.host_header.as_deref()) {
        (Some(host), _) => {
            let host = host.trim();
            if host.is_empty() || !valid_header_value(host) {
                return Err("reverse proxy route host is invalid");
            }
            HostHeader::Custom(host.to_string())
        }
        (None, None | Some("client")) => HostHeader::Client,
        (None, Some("upstream")) => HostHeader::Upstream,
        (None, Some(_)) => return Err("reverse proxy host_header must be client or upstream"),
    };
    let mut set_headers = Vec::new();
    for (name, value) in &settings.headers {
        let lower = name.to_ascii_lowercase();
        if !valid_header_name(name) || !valid_header_value(value) {
            return Err("reverse proxy route header is invalid");
        }
        if matches!(
            lower.as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "upgrade"
        ) {
            return Err("reverse proxy route headers cannot set host or framing headers");
        }
        set_headers.push((name.clone(), value.clone()));
    }
    Ok(Route {
        prefix,
        strip_prefix: settings.strip_prefix,
        host_header,
        set_headers,
        targets: Arc::new(Targets::new(targets, strategy, health)),
    })
}

impl InboundFactory for ReverseProxyInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: ReverseProxySettings = parse_settings(
            settings,
            "reverse proxy inbound settings are missing or invalid",
        )?;
        if settings.sites.is_empty() {
            return Err("reverse proxy needs sites");
        }
        let mut seen_hosts = HashSet::new();
        let mut sites = Vec::new();
        for site in &settings.sites {
            if site.hosts.is_empty() {
                return Err("reverse proxy site needs hosts");
            }
            let mut hosts = Vec::new();
            for host in &site.hosts {
                let pattern =
                    HostPattern::parse(host).ok_or("reverse proxy site host is invalid")?;
                if !seen_hosts.insert(pattern.clone()) {
                    return Err("reverse proxy host is listed twice");
                }
                hosts.push(pattern);
            }
            if site.routes.is_empty() && !site.redirect_https {
                return Err("reverse proxy site needs routes");
            }
            let mut prefixes = HashSet::new();
            let mut routes = Vec::new();
            for route in &site.routes {
                let route = build_route(route)?;
                if !prefixes.insert(route.prefix.clone()) {
                    return Err("reverse proxy route path is listed twice");
                }
                routes.push(route);
            }
            sites.push(Site {
                hosts,
                routes,
                redirect_https: site.redirect_https,
            });
        }
        let defaults = Options::default();
        let options = Options {
            forwarded_proto: match settings.forwarded_proto.as_deref() {
                None if settings.tls.is_some() => "https",
                None | Some("http") => "http",
                Some("https") => "https",
                Some(_) => return Err("reverse proxy forwarded_proto must be http or https"),
            },
            max_header_bytes: match settings.max_header_bytes {
                0 => defaults.max_header_bytes,
                n if n < 1024 => return Err("reverse proxy max_header_bytes is below 1024"),
                n => n as usize,
            },
            idle_timeout: or_default(settings.idle_timeout_ms, defaults.idle_timeout),
            upstream_timeout: or_default(settings.upstream_timeout_ms, defaults.upstream_timeout),
        };
        let inbound: Arc<dyn StreamInbound> = Arc::new(ReverseProxyInbound::new(sites, options));
        match settings.tls {
            Some(mut tls) => {
                if tls.alpn.is_empty() {
                    tls.alpn = vec!["http/1.1".to_string()];
                }
                if tls.alpn.iter().any(|protocol| protocol != "http/1.1") {
                    return Err("reverse proxy tls alpn must be http/1.1");
                }
                inbound_transport::wrap(inbound, Some(&tls))
            }
            None => Ok(inbound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        ReverseProxyInboundFactory.build(&settings)
    }

    const UP: &str = r#"[{"server":"127.0.0.1","server_port":3000}]"#;

    #[test]
    fn builds_sites() {
        let inbound = build(&format!(
            r#"{{"sites":[{{"hosts":["a.example","*.b.example"],
                "routes":[{{"path":"/api","strip_prefix":true,"upstreams":{UP},
                            "balance":"least_conn","host_header":"upstream",
                            "headers":{{"X-Site":"a"}}}},
                          {{"upstreams":{UP},"host":"origin.example"}}]}},
                {{"hosts":["c.example"],"redirect_https":true}}],
              "forwarded_proto":"https","idle_timeout_ms":5000}}"#
        ))
        .unwrap();
        assert_eq!(inbound.protocol(), "reverse_proxy");
        assert!(inbound.serves_connections());
        assert!(inbound.datagram().is_none());
        assert_eq!(inbound.target_health().unwrap().len(), 2);
    }

    #[test]
    fn rejects_invalid_settings() {
        let route = format!(r#"{{"upstreams":{UP}}}"#);
        let bad = [
            r#"{"sites":[]}"#.to_string(),
            r#"{"sites":[{"hosts":[],"routes":[]}]}"#.to_string(),
            r#"{"sites":[{"hosts":["a"]}]}"#.to_string(),
            format!(r#"{{"sites":[{{"hosts":["a b"],"routes":[{route}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{route}]}},{{"hosts":["A"],"routes":[{route}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{route},{route}]}}]}}"#),
            r#"{"sites":[{"hosts":["a"],"routes":[{"upstreams":[]}]}]}"#.to_string(),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{{"path":"api","upstreams":{UP}}}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{{"path":"/api/","upstreams":{UP}}}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{{"upstreams":{UP},"headers":{{"Host":"x"}}}}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{{"upstreams":{UP},"headers":{{"X-A":"a\nb"}}}}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{{"upstreams":{UP},"host_header":"origin"}}]}}]}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{route}]}}],"forwarded_proto":"ftp"}}"#),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{route}]}}],"max_header_bytes":10}}"#),
            r#"{"sites":[{"hosts":["a"],"routes":[{"upstreams":[{"server":"x","server_port":0}]}]}]}"#.to_string(),
            format!(r#"{{"sites":[{{"hosts":["a"],"routes":[{route}]}}],"users":[]}}"#),
        ];
        for json in bad {
            assert!(build(&json).is_err(), "{json}");
        }
    }
}
