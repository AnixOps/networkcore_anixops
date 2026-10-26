//! Replay protection: nonces (salts, auth IDs) seen within a time window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PRUNE_INTERVAL: Duration = Duration::from_secs(5);

/// Remembers nonces for `ttl`. Protocols with a timestamp window should keep
/// nonces for at least twice that window.
pub struct ReplayCache {
    ttl: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    seen: HashMap<Box<[u8]>, Instant>,
    last_prune: Instant,
}

impl ReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Records `nonce`; returns `false` when it was already seen within the
    /// TTL.
    pub fn insert(&self, nonce: &[u8]) -> bool {
        self.insert_at(nonce, Instant::now())
    }

    fn insert_at(&self, nonce: &[u8], now: Instant) -> bool {
        let ttl = self.ttl;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.saturating_duration_since(inner.last_prune) >= PRUNE_INTERVAL {
            inner
                .seen
                .retain(|_, seen| now.saturating_duration_since(*seen) < ttl);
            inner.last_prune = now;
        }
        match inner.seen.get(nonce) {
            Some(seen) if now.saturating_duration_since(*seen) < ttl => false,
            _ => {
                inner.seen.insert(nonce.into(), now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_repeats_within_the_ttl() {
        const SALT_TTL: Duration = Duration::from_secs(60);
        let cache = ReplayCache::new(SALT_TTL);
        let start = Instant::now();
        assert!(cache.insert_at(b"salt-a", start));
        assert!(!cache.insert_at(b"salt-a", start + Duration::from_secs(1)));
        assert!(cache.insert_at(b"salt-b", start + Duration::from_secs(1)));
        assert!(cache.insert_at(b"salt-a", start + SALT_TTL + Duration::from_secs(1)));
        let len = cache.inner.lock().unwrap().seen.len();
        assert!(len <= 2);
    }
}
