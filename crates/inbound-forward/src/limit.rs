//! Per-rule limits (forward.v1 `Limits`): a bandwidth cap per direction
//! shared by all of a forward's connections and UDP sessions.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// A token bucket in bytes. Takes may run it into debt; the taker then
/// waits until the debt is paid, so a burst never exceeds one second of
/// rate.
pub struct Bucket {
    /// Bytes per second.
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl Bucket {
    /// `bits_per_second` as forward.v1 `bandwidth_bps` gives it; `None`
    /// for 0 (no cap).
    pub fn from_bps(bits_per_second: u64) -> Option<Arc<Bucket>> {
        if bits_per_second == 0 {
            return None;
        }
        let rate = (bits_per_second / 8).max(1) as f64;
        Some(Arc::new(Bucket {
            rate,
            state: Mutex::new((rate, Instant::now())),
        }))
    }

    /// Charges `bytes` and returns how long to wait before the next take.
    pub fn take(&self, bytes: usize) -> Duration {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let (tokens, last) = *state;
        let refilled = (tokens + now.duration_since(last).as_secs_f64() * self.rate).min(self.rate);
        let left = refilled - bytes as f64;
        *state = (left, now);
        if left >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-left / self.rate)
        }
    }
}

/// A client stream whose reads (client to target) and writes (target to
/// client) are paced by the forward's buckets.
pub struct Limited<S> {
    inner: S,
    up: Option<Arc<Bucket>>,
    down: Option<Arc<Bucket>>,
    read_wait: Option<Pin<Box<Sleep>>>,
    write_wait: Option<Pin<Box<Sleep>>>,
}

impl<S> Limited<S> {
    pub fn new(inner: S, up: Option<Arc<Bucket>>, down: Option<Arc<Bucket>>) -> Self {
        Self {
            inner,
            up,
            down,
            read_wait: None,
            write_wait: None,
        }
    }
}

/// Polls a pending wait; `Pending` while it runs.
fn wait(slot: &mut Option<Pin<Box<Sleep>>>, cx: &mut Context<'_>) -> Poll<()> {
    if let Some(sleep) = slot {
        if sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        *slot = None;
    }
    Poll::Ready(())
}

fn charge(bucket: &Option<Arc<Bucket>>, bytes: usize, slot: &mut Option<Pin<Box<Sleep>>>) {
    if let Some(bucket) = bucket {
        let delay = bucket.take(bytes);
        if !delay.is_zero() {
            *slot = Some(Box::pin(tokio::time::sleep(delay)));
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Limited<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if wait(&mut this.read_wait, cx).is_pending() {
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            charge(&this.up, read, &mut this.read_wait);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Limited<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if wait(&mut this.write_wait, cx).is_pending() {
            return Poll::Pending;
        }
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            if written > 0 {
                charge(&this.down, written, &mut this.write_wait);
            }
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn bucket_paces_after_one_second_of_burst() {
        // 8000 bit/s = 1000 B/s.
        let bucket = Bucket::from_bps(8000).unwrap();
        assert!(Bucket::from_bps(0).is_none());
        assert_eq!(bucket.take(1000), Duration::ZERO);
        assert_eq!(bucket.take(500), Duration::from_millis(500));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(bucket.take(0), Duration::ZERO);
        tokio::time::advance(Duration::from_secs(10)).await;
        // Refill stops at one second's worth.
        assert_eq!(bucket.take(1000), Duration::ZERO);
        assert!(bucket.take(1) > Duration::ZERO);
    }
}
