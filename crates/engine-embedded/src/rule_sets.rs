//! The rule sets of a routing config: inline lists, and remote lists the
//! engine downloads again on a schedule while it runs.
//!
//! `RULE-SET,<name>` rules match the set `<name>`; `GEOSITE,<category>` rules
//! the set `geosite-<category>` and `GEOIP,<CC>` rules the set `geoip-<cc>`
//! (lower case), so a client supplies GeoSite and GeoIP data as ordinary
//! lists. A remote set starts with its inline entries (the client's cached
//! copy, possibly empty), is downloaded right away when it starts empty, and
//! is replaced atomically after each successful download; a failed one keeps
//! the previous entries and is retried sooner. URLs never appear in status.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use config_core::rule_set::{BareDomain, RuleSet};
use serde::Serialize;
use tokio::sync::Notify;

/// Shortest refresh interval accepted for a remote set.
pub const MIN_UPDATE_INTERVAL_SECS: u32 = 600;
pub const DEFAULT_UPDATE_INTERVAL_SECS: u32 = 86_400;
/// How soon a failed download is tried again, at most.
pub const RETRY_INTERVAL_SECS: u32 = 300;

/// A list the engine downloads itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRuleSet {
    pub name: String,
    pub url: String,
    pub interval_secs: u32,
    pub bare: BareDomain,
    /// The outbound the download goes through: a policy group, a node or
    /// `DIRECT`.
    pub via: String,
}

/// One rule set as the client's rule page shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleSetStatus {
    pub name: String,
    /// `inline` or `remote`.
    pub source: &'static str,
    pub entries: usize,
    /// Unix milliseconds of the last successful download.
    pub updated_at_ms: Option<u64>,
    /// Why the last download failed, cleared by the next success.
    pub last_error: Option<&'static str>,
}

pub struct RuleSetStore {
    sets: RwLock<BTreeMap<String, Arc<RuleSet>>>,
    remotes: Vec<RemoteRuleSet>,
    status: Mutex<BTreeMap<String, RuleSetStatus>>,
    refresh: Notify,
}

impl RuleSetStore {
    pub fn new(sets: BTreeMap<String, RuleSet>, remotes: Vec<RemoteRuleSet>) -> Self {
        let mut sets: BTreeMap<String, Arc<RuleSet>> = sets
            .into_iter()
            .map(|(name, set)| (name, Arc::new(set)))
            .collect();
        for remote in &remotes {
            sets.entry(remote.name.clone()).or_default();
        }
        let status = sets
            .iter()
            .map(|(name, set)| {
                let remote = remotes.iter().any(|remote| &remote.name == name);
                let status = RuleSetStatus {
                    name: name.clone(),
                    source: if remote { "remote" } else { "inline" },
                    entries: set.len(),
                    updated_at_ms: None,
                    last_error: None,
                };
                (name.clone(), status)
            })
            .collect();
        Self {
            sets: RwLock::new(sets),
            remotes,
            status: Mutex::new(status),
            refresh: Notify::new(),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.read().contains_key(name)
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, BTreeMap<String, Arc<RuleSet>>> {
        self.sets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn remotes(&self) -> &[RemoteRuleSet] {
        &self.remotes
    }

    /// Every set with its entry count and download state, by name.
    pub fn status(&self) -> Vec<RuleSetStatus> {
        lock(&self.status).values().cloned().collect()
    }

    /// Asks the updater to download every remote set now; returns how many
    /// there are.
    pub fn refresh_now(&self) -> usize {
        if !self.remotes.is_empty() {
            self.refresh.notify_one();
        }
        self.remotes.len()
    }

    /// Completes when [`RuleSetStore::refresh_now`] was called.
    pub async fn refresh_requested(&self) {
        self.refresh.notified().await;
    }

    /// Installs a downloaded set for every later connection.
    pub fn replace(&self, name: &str, set: RuleSet) {
        let entries = set.len();
        self.sets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(name.to_string(), Arc::new(set));
        if let Some(status) = lock(&self.status).get_mut(name) {
            status.entries = entries;
            status.updated_at_ms = Some(unix_millis());
            status.last_error = None;
        }
    }

    pub fn record_failure(&self, name: &str, error: &'static str) {
        if let Some(status) = lock(&self.status).get_mut(name) {
            status.last_error = Some(error);
        }
    }

    pub fn is_empty_set(&self, name: &str) -> bool {
        self.read().get(name).is_none_or(|set| set.is_empty())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
