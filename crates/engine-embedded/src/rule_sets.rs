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
//!
//! A remote set may carry an Ed25519 `public_key`: each download then also
//! fetches the detached signature (`signature_url`, `<url>.sig` by default)
//! and installs the list only when the signature over its exact bytes
//! verifies ([`verify_list_signature`]). A missing or wrong signature keeps
//! the previous entries like any failed download.

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
    /// When set, a list is installed only with a valid signature.
    pub signature: Option<RuleSetSignature>,
}

/// How a remote set's downloads are verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSetSignature {
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// Where the detached signature of the list is.
    pub url: String,
}

/// Largest signature file accepted: a base64 signature with some slack for
/// a trailing newline or a minisign-style comment line.
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// Checks an Ed25519 signature over the exact bytes of a downloaded list.
///
/// `signature` is the signature file: the 64-byte signature in standard or
/// URL-safe base64 (padding optional) on its own line. Blank lines and lines
/// starting with `#` or `untrusted comment:` are skipped, so a file with a
/// comment header works too.
#[cfg(feature = "local-proxy")]
pub fn verify_list_signature(
    public_key: &[u8; 32],
    body: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let text = std::str::from_utf8(signature).map_err(|_| "signature_malformed")?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty() && !line.starts_with('#') && !line.starts_with("untrusted comment:")
        })
        .ok_or("signature_malformed")?;
    let bytes = decode_base64(line).ok_or("signature_malformed")?;
    if bytes.len() != 64 {
        return Err("signature_malformed");
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(body, &bytes)
        .map_err(|_| "signature_invalid")
}

/// Standard or URL-safe base64, with or without padding.
#[cfg(feature = "local-proxy")]
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let text = text.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok())
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
    /// Whether downloads must carry a valid signature.
    pub signed: bool,
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
                let remote = remotes.iter().find(|remote| &remote.name == name);
                let status = RuleSetStatus {
                    name: name.clone(),
                    source: if remote.is_some() { "remote" } else { "inline" },
                    entries: set.len(),
                    updated_at_ms: None,
                    last_error: None,
                    signed: remote.is_some_and(|remote| remote.signature.is_some()),
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

#[cfg(all(test, feature = "local-proxy"))]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key_pair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
        pair.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn accepts_a_valid_signature_in_any_base64_shape() {
        let pair = key_pair();
        let body = b"DOMAIN-SUFFIX,example.com\n";
        let signature = pair.sign(body);
        let plain = STANDARD.encode(signature.as_ref());
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, plain.as_bytes()),
            Ok(())
        );
        let commented = format!(
            "untrusted comment: list\n\n{}\n",
            plain.trim_end_matches('=')
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, commented.as_bytes()),
            Ok(())
        );
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref());
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, url_safe.as_bytes()),
            Ok(())
        );
    }

    #[test]
    fn refuses_a_changed_list_another_key_and_junk() {
        let pair = key_pair();
        let body = b"DOMAIN-SUFFIX,example.com\n";
        let signature = STANDARD.encode(pair.sign(body).as_ref());
        assert_eq!(
            verify_list_signature(
                &public_key(&pair),
                b"DOMAIN-SUFFIX,evil.example\n",
                signature.as_bytes()
            ),
            Err("signature_invalid")
        );
        assert_eq!(
            verify_list_signature(&public_key(&key_pair()), body, signature.as_bytes()),
            Err("signature_invalid")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, b""),
            Err("signature_malformed")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, b"not base64!"),
            Err("signature_malformed")
        );
        let short = STANDARD.encode([0u8; 32]);
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, short.as_bytes()),
            Err("signature_malformed")
        );
        assert_eq!(
            verify_list_signature(&public_key(&pair), body, &[0xff, 0xfe]),
            Err("signature_malformed")
        );
    }
}
