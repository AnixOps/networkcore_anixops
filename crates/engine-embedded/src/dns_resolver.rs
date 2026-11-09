//! Resolving a name for routing rules with the config's own DNS.
//!
//! A domain target that reaches an IP rule (`IP-CIDR`, `GEOIP`) without
//! `no-resolve` needs an address before the rule can match. The system
//! resolver would send that name in the clear to the local network's
//! resolver, which in a censored network both reveals the site and returns a
//! poisoned answer, even when the connection itself then goes through the
//! proxy. [`PolicyResolver`] asks the `dns` section instead: hosts answer
//! locally, DNS rules pick the server, a `proxy` server is reached through
//! [`RoutedOutbound::dns_outbound`] (never DIRECT by a rule) and a `direct`
//! one through the DIRECT outbound, the same way the tunnel forwards an app's
//! query. Answers are kept for their TTL.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use engine_outbound::{BoxFuture, TcpOutbound};

use crate::config::DnsVia;
use crate::dns::{self, TYPE_A, TYPE_AAAA};
use crate::dns_cache::{self, UpstreamPool};
use crate::dns_policy::{DnsPolicy, Plan};
use crate::routing::{DomainResolver, RoutedOutbound};

/// Most names kept.
const MAX_CACHED: usize = 1024;
/// Longest time a resolved address is kept for routing.
const MAX_CACHE_TTL: Duration = Duration::from_secs(600);

/// Resolves names for IP rules through the `dns` section; see the module
/// docs. Bind it to the routed outbound that uses it with
/// [`PolicyResolver::bind`]; until then every lookup fails, which rejects the
/// connection rather than falling back to the system resolver.
pub struct PolicyResolver {
    policy: Arc<DnsPolicy>,
    routed: OnceLock<Weak<RoutedOutbound>>,
    pool: Mutex<UpstreamPool>,
    cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
    next_id: AtomicU16,
}

impl PolicyResolver {
    pub fn new(policy: Arc<DnsPolicy>) -> Arc<Self> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos() as u16);
        Arc::new(Self {
            policy,
            routed: OnceLock::new(),
            pool: Mutex::default(),
            cache: Mutex::default(),
            next_id: AtomicU16::new(seed),
        })
    }

    /// Uses `routed` for the rule sets of DNS rules and for its outbounds.
    pub fn bind(&self, routed: &Arc<RoutedOutbound>) {
        let _ = self.routed.set(Arc::downgrade(routed));
    }

    async fn lookup(&self, domain: &str) -> io::Result<IpAddr> {
        let name = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        if let Some((address, expires)) = self.cached(&name) {
            if expires > now {
                return Ok(address);
            }
        }
        let routed =
            self.routed.get().and_then(Weak::upgrade).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "resolver is not bound")
            })?;
        for qtype in [TYPE_A, TYPE_AAAA] {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let query = dns::query(id, &name, qtype)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid domain"))?;
            let Some(question) = dns::question(&query) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid domain",
                ));
            };
            let response = match self.policy.plan(&query, Some(routed.rule_sets())) {
                Plan::Local(response) => response,
                Plan::Forward(server) => self.forward(&routed, server, &query).await?,
            };
            if let Some((address, ttl)) = dns_cache::first_address(&response, &question) {
                self.remember(name, address, now + ttl.min(MAX_CACHE_TTL));
                return Ok(address);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "domain has no address",
        ))
    }

    async fn forward(
        &self,
        routed: &RoutedOutbound,
        server: usize,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let config = &self.policy.servers()[server];
        let outbound: Arc<dyn TcpOutbound> = match config.via {
            DnsVia::Direct => routed.direct().clone(),
            DnsVia::Proxy => routed
                .dns_outbound(config.upstream.target())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "dns server rejected by routing",
                    )
                })?,
        };
        let pool_key = (server, Arc::as_ptr(&outbound) as *const () as usize);
        dns::exchange(
            &config.upstream,
            outbound.as_ref(),
            query,
            self.policy.timeout(),
            Some((&self.pool, pool_key)),
        )
        .await
        .map_err(|failure| io::Error::other(failure.as_str()))
    }

    fn cached(&self, name: &str) -> Option<(IpAddr, Instant)> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .copied()
    }

    fn remember(&self, name: String, address: IpAddr, expires: Instant) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_CACHED && !cache.contains_key(&name) {
            let now = Instant::now();
            cache.retain(|_, (_, expires)| *expires > now);
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
        }
        cache.insert(name, (address, expires));
    }
}

impl DomainResolver for PolicyResolver {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        Box::pin(self.lookup(domain))
    }
}
