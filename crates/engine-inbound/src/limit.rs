//! Per-user speed limits: one token bucket per direction, shared by every
//! connection of the user.
//!
//! Bytes are charged after they moved and a transfer that overdraws the
//! bucket waits before the next one, so a single read or write is never
//! split and a limit only adds delay.

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::time::{Instant, Sleep};

/// Longest single wait; a large overdraft is paid off in several waits so a
/// changed clock or a huge datagram cannot stall a connection for long.
const MAX_WAIT: Duration = Duration::from_secs(1);

/// Token bucket of `rate` bytes per second holding at most one second of
/// tokens.
pub struct RateLimiter {
    rate: f64,
    state: Mutex<Bucket>,
}

struct Bucket {
    /// Negative while overdrawn.
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    /// A limiter of `bytes_per_sec`; `None` for 0 (no limit).
    pub fn new(bytes_per_sec: u64) -> Option<Self> {
        if bytes_per_sec == 0 {
            return None;
        }
        let rate = bytes_per_sec as f64;
        Some(Self {
            rate,
            state: Mutex::new(Bucket {
                tokens: rate,
                updated: Instant::now(),
            }),
        })
    }

    /// A limiter for a panel speed limit in Mbit/s; `None` for 0.
    pub fn from_mbps(mbps: u64) -> Option<Self> {
        Self::new(mbps.saturating_mul(1_000_000 / 8))
    }

    /// Charges `bytes` and answers how long the caller should wait before
    /// moving more, `None` when the bucket is not overdrawn.
    pub fn charge(&self, bytes: usize) -> Option<Duration> {
        self.charge_at(bytes, Instant::now())
    }

    fn charge_at(&self, bytes: usize, now: Instant) -> Option<Duration> {
        let mut bucket = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.rate);
        bucket.updated = now;
        bucket.tokens -= bytes as f64;
        if bucket.tokens >= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64(-bucket.tokens / self.rate).min(MAX_WAIT))
    }
}

/// The pending wait of one direction of a connection.
#[derive(Default)]
pub struct Throttle {
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Throttle {
    /// Ready once the last overdraft has been waited out.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(sleep) = self.sleep.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
        }
        Poll::Ready(())
    }

    /// Charges `bytes` to `limiter` and arms the wait for an overdraft.
    pub fn charge(&mut self, limiter: Option<&RateLimiter>, bytes: usize) {
        if bytes == 0 {
            return;
        }
        if let Some(wait) = limiter.and_then(|limiter| limiter.charge(bytes)) {
            self.sleep = Some(Box::pin(tokio::time::sleep(wait)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_no_limit() {
        assert!(RateLimiter::new(0).is_none());
        assert!(RateLimiter::from_mbps(0).is_none());
        assert_eq!(RateLimiter::from_mbps(8).unwrap().rate, 1_000_000.0);
    }

    #[test]
    fn overdraft_asks_for_a_proportional_wait() {
        let limiter = RateLimiter::new(1000).unwrap();
        let start = Instant::now();
        assert_eq!(limiter.charge_at(1000, start), None, "a full bucket");
        let wait = limiter.charge_at(500, start).unwrap();
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6);
        // Half a second later the debt is paid.
        assert_eq!(limiter.charge_at(0, start + Duration::from_millis(500)), None);
        // Tokens never exceed one second's worth.
        let later = start + Duration::from_secs(60);
        assert_eq!(limiter.charge_at(1000, later), None);
        assert!(limiter.charge_at(1, later).is_some());
        // Waits are capped.
        assert_eq!(limiter.charge_at(1_000_000, later).unwrap(), MAX_WAIT);
    }

    #[tokio::test]
    async fn throttle_waits_out_the_overdraft() {
        let limiter = RateLimiter::new(100_000).unwrap();
        let mut throttle = Throttle::default();
        throttle.charge(Some(&limiter), 120_000);
        let start = Instant::now();
        std::future::poll_fn(|cx| throttle.poll_ready(cx)).await;
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(190), "{waited:?}");
        throttle.charge(None, 10_000);
        std::future::poll_fn(|cx| throttle.poll_ready(cx)).await;
    }
}
