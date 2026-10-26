//! Replay protection: request salts seen within the last minute.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// SIP022 asks servers to remember salts for at least twice the timestamp
/// window.
const SALT_TTL: Duration = Duration::from_secs(60);
const PRUNE_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct SaltCache {
    inner: Mutex<Inner>,
}

struct Inner {
    seen: HashMap<Box<[u8]>, Instant>,
    last_prune: Instant,
}

impl Default for SaltCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }
}

impl SaltCache {
    /// Records `salt`; returns `false` when it was already seen within the TTL.
    pub(crate) fn insert(&self, salt: &[u8]) -> bool {
        self.insert_at(salt, Instant::now())
    }

    fn insert_at(&self, salt: &[u8], now: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.saturating_duration_since(inner.last_prune) >= PRUNE_INTERVAL {
            inner
                .seen
                .retain(|_, seen| now.saturating_duration_since(*seen) < SALT_TTL);
            inner.last_prune = now;
        }
        match inner.seen.get(salt) {
            Some(seen) if now.saturating_duration_since(*seen) < SALT_TTL => false,
            _ => {
                inner.seen.insert(salt.into(), now);
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
        let cache = SaltCache::default();
        let start = Instant::now();
        assert!(cache.insert_at(b"salt-a", start));
        assert!(!cache.insert_at(b"salt-a", start + Duration::from_secs(1)));
        assert!(cache.insert_at(b"salt-b", start + Duration::from_secs(1)));
        assert!(cache.insert_at(b"salt-a", start + SALT_TTL + Duration::from_secs(1)));
        let len = cache.inner.lock().unwrap().seen.len();
        assert!(len <= 2);
    }
}
