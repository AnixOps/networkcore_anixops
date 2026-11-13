//! The frame queue in front of a multiplexed connection, built so that one
//! busy stream cannot hold back the others (no head-of-line blocking above
//! TCP).
//!
//! Every stream has a lane of its own, capped at a few frames: a stream
//! whose lane is full waits, so a bulk upload never has more than the cap
//! queued ahead of anyone. The writer takes control frames (window updates,
//! pings, resets) first and then, under [`Discipline::Fair`], the lane that
//! sent the fewest bytes lately: each lane's byte count halves every
//! [`HALF_LIFE`], so a short request or an interactive stream overtakes a
//! download that has been running for a while, and two downloads share the
//! connection evenly. [`Discipline::Fifo`] sends frames in the order they
//! were queued, with deep lanes, the way a plain multiplexer does; it is
//! kept for comparison in tests and benchmarks.
//!
//! Frames of one stream always leave in the order they were queued.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// How fast a lane's byte count is forgotten.
pub const HALF_LIFE: Duration = Duration::from_millis(500);

/// Bytes a lane holds under [`Discipline::Fair`] before its stream waits:
/// two full frames, enough to keep the connection busy.
pub const FAIR_LANE_CAP: usize = 32 * 1024;
/// Bytes a lane holds under [`Discipline::Fifo`]: a whole yamux window.
pub const FIFO_LANE_CAP: usize = 256 * 1024;

/// How the writer picks the next frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Discipline {
    /// The lane with the fewest recent bytes first.
    #[default]
    Fair,
    /// Queue order.
    Fifo,
}

impl Discipline {
    /// The name in settings.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "fair" => Some(Self::Fair),
            "fifo" => Some(Self::Fifo),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Fair => "fair",
            Self::Fifo => "fifo",
        }
    }

    fn lane_cap(self) -> usize {
        match self {
            Self::Fair => FAIR_LANE_CAP,
            Self::Fifo => FIFO_LANE_CAP,
        }
    }
}

/// Frames waiting for one connection.
pub struct FairQueue {
    state: Mutex<State>,
    /// Wakes the writer; a notification sent while it is busy is kept.
    ready: Notify,
    discipline: Discipline,
    lane_cap: usize,
}

struct State {
    control: VecDeque<Vec<u8>>,
    lanes: HashMap<u32, Lane>,
    /// Queue order of data frames, for [`Discipline::Fifo`] and ties.
    seq: u64,
    closed: bool,
}

struct Lane {
    frames: VecDeque<(u64, Vec<u8>)>,
    queued: usize,
    /// Bytes sent, decayed to `stamp`.
    served: f64,
    stamp: Instant,
    /// The stream waiting for room.
    waiting: Option<Waker>,
    /// The stream is gone: the lane goes once it is empty.
    retired: bool,
}

impl Lane {
    fn new(now: Instant) -> Self {
        Self {
            frames: VecDeque::new(),
            queued: 0,
            served: 0.0,
            stamp: now,
            waiting: None,
            retired: false,
        }
    }

    fn served_at(&self, now: Instant) -> f64 {
        let age = now.saturating_duration_since(self.stamp).as_secs_f64();
        self.served * 0.5f64.powf(age / HALF_LIFE.as_secs_f64())
    }
}

impl FairQueue {
    pub fn new(discipline: Discipline) -> Self {
        Self {
            state: Mutex::new(State {
                control: VecDeque::new(),
                lanes: HashMap::new(),
                seq: 0,
                closed: false,
            }),
            ready: Notify::new(),
            discipline,
            lane_cap: discipline.lane_cap(),
        }
    }

    pub fn discipline(&self) -> Discipline {
        self.discipline
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queues a frame that belongs to no stream's order (a window update, a
    /// ping, a reset); these leave before any data. `false` once closed.
    pub fn push_control(&self, frame: Vec<u8>) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.control.push_back(frame);
        drop(state);
        self.ready.notify_one();
        true
    }

    /// Ready with `true` once `lane` has room for another frame, `false`
    /// once the queue is closed.
    pub fn poll_room(&self, cx: &mut Context<'_>, lane: u32) -> Poll<bool> {
        let mut state = self.lock();
        if state.closed {
            return Poll::Ready(false);
        }
        let cap = self.lane_cap;
        let lane = state
            .lanes
            .entry(lane)
            .or_insert_with(|| Lane::new(Instant::now()));
        if lane.queued < cap {
            Poll::Ready(true)
        } else {
            lane.waiting = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// Queues `frame` behind the earlier frames of `lane`, whether or not
    /// the lane has room. `false` once closed.
    pub fn push(&self, lane: u32, frame: Vec<u8>) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.seq += 1;
        let seq = state.seq;
        let lane = state
            .lanes
            .entry(lane)
            .or_insert_with(|| Lane::new(Instant::now()));
        lane.retired = false;
        lane.queued += frame.len();
        lane.frames.push_back((seq, frame));
        drop(state);
        self.ready.notify_one();
        true
    }

    /// Bytes waiting in every lane.
    pub fn queued(&self) -> usize {
        self.lock().lanes.values().map(|lane| lane.queued).sum()
    }

    /// The stream of `lane` is gone; what it queued still leaves.
    pub fn retire(&self, lane: u32) {
        let mut state = self.lock();
        if let Some(entry) = state.lanes.get_mut(&lane) {
            if entry.frames.is_empty() {
                state.lanes.remove(&lane);
            } else {
                entry.retired = true;
            }
        }
    }

    /// Drops `lane` with whatever it still holds (the stream was reset).
    pub fn discard(&self, lane: u32) {
        let removed = self.lock().lanes.remove(&lane);
        if let Some(waker) = removed.and_then(|lane| lane.waiting) {
            waker.wake();
        }
    }

    /// Ends the queue: pushes fail, waiting streams and the writer wake.
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.control.clear();
        let wakers: Vec<Waker> = state
            .lanes
            .drain()
            .filter_map(|(_, lane)| lane.waiting)
            .collect();
        drop(state);
        for waker in wakers {
            waker.wake();
        }
        self.ready.notify_one();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// The next bytes to write: every control frame, then data frames in
    /// the discipline's order until about `limit` bytes. `None` once the
    /// queue is closed.
    pub async fn next_batch(&self, limit: usize) -> Option<Vec<u8>> {
        loop {
            if let Some(batch) = self.try_batch(limit) {
                return batch;
            }
            self.ready.notified().await;
        }
    }

    /// `None` when there is nothing to send yet; `Some(None)` once closed.
    fn try_batch(&self, limit: usize) -> Option<Option<Vec<u8>>> {
        let mut state = self.lock();
        if state.closed {
            return Some(None);
        }
        let mut batch = Vec::new();
        while let Some(frame) = state.control.pop_front() {
            batch.extend_from_slice(&frame);
        }
        let now = Instant::now();
        let mut woken = Vec::new();
        while batch.len() < limit {
            let Some(id) = self.pick(&state, now) else {
                break;
            };
            let cap = self.lane_cap;
            let lane = state.lanes.get_mut(&id).expect("picked lane exists");
            let (_, frame) = lane.frames.pop_front().expect("picked lane has a frame");
            lane.queued -= frame.len();
            lane.served = lane.served_at(now) + frame.len() as f64;
            lane.stamp = now;
            if lane.queued < cap {
                if let Some(waker) = lane.waiting.take() {
                    woken.push(waker);
                }
            }
            if lane.retired && lane.frames.is_empty() {
                state.lanes.remove(&id);
            }
            batch.extend_from_slice(&frame);
        }
        drop(state);
        for waker in woken {
            waker.wake();
        }
        (!batch.is_empty()).then_some(Some(batch))
    }

    fn pick(&self, state: &State, now: Instant) -> Option<u32> {
        let waiting = state
            .lanes
            .iter()
            .filter_map(|(id, lane)| lane.frames.front().map(|(seq, _)| (*id, lane, *seq)));
        match self.discipline {
            Discipline::Fifo => waiting.min_by_key(|(_, _, seq)| *seq).map(|(id, _, _)| id),
            Discipline::Fair => waiting
                .map(|(id, lane, seq)| (id, lane.served_at(now), seq))
                .min_by(|a, b| a.1.total_cmp(&b.1).then(a.2.cmp(&b.2)))
                .map(|(id, _, _)| id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(len: usize) -> Vec<u8> {
        vec![7; len]
    }

    /// Queues `count` 16 KiB frames on lane 1 (a bulk stream), then one
    /// small frame on lane 3, and returns how many bulk bytes leave before
    /// the small frame.
    fn bulk_ahead_of_small(discipline: Discipline, count: usize) -> usize {
        let queue = FairQueue::new(discipline);
        // The bulk stream has already been sending for a while.
        queue.push(1, frame(16 * 1024));
        let first = queue.try_batch(1).unwrap().unwrap();
        assert_eq!(first.len(), 16 * 1024);
        for _ in 0..count {
            queue.push(1, frame(16 * 1024));
        }
        queue.push(3, vec![1; 40]);
        let mut ahead = 0;
        loop {
            let batch = queue.try_batch(1).unwrap().unwrap();
            if batch == vec![1; 40] {
                return ahead;
            }
            ahead += batch.len();
        }
    }

    #[test]
    fn a_small_frame_overtakes_a_bulk_lane() {
        assert_eq!(bulk_ahead_of_small(Discipline::Fair, 16), 0);
        assert_eq!(bulk_ahead_of_small(Discipline::Fifo, 16), 16 * 16 * 1024);
    }

    #[test]
    fn frames_of_one_lane_keep_their_order_and_control_goes_first() {
        let queue = FairQueue::new(Discipline::Fair);
        queue.push(5, vec![1]);
        queue.push(5, vec![2]);
        queue.push_control(vec![9]);
        queue.push(7, vec![3]);
        let batch = queue.try_batch(1024).unwrap().unwrap();
        assert_eq!(batch[0], 9);
        let lane5: Vec<u8> = batch
            .iter()
            .copied()
            .filter(|b| *b == 1 || *b == 2)
            .collect();
        assert_eq!(lane5, [1, 2]);
        assert_eq!(batch.len(), 4);
        assert!(queue.try_batch(1024).is_none());
    }

    #[test]
    fn two_bulk_lanes_share_evenly() {
        // The lane of each frame shows in its length.
        let queue = FairQueue::new(Discipline::Fair);
        for _ in 0..64 {
            queue.push(1, frame(1000));
            queue.push(3, frame(999));
        }
        let mut sent = [0usize; 2];
        for _ in 0..64 {
            let batch = queue.try_batch(1).unwrap().unwrap();
            sent[usize::from(batch.len() == 999)] += 1;
        }
        assert!(sent[0].abs_diff(sent[1]) <= 2, "{sent:?}");
    }

    #[test]
    fn full_lanes_wait_and_wake() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::Wake;

        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);

        let queue = FairQueue::new(Discipline::Fair);
        assert_eq!(queue.poll_room(&mut cx, 1), Poll::Ready(true));
        queue.push(1, frame(FAIR_LANE_CAP));
        assert_eq!(queue.poll_room(&mut cx, 1), Poll::Pending);
        // Another lane is not held back.
        assert_eq!(queue.poll_room(&mut cx, 3), Poll::Ready(true));
        queue.try_batch(1).unwrap().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(queue.poll_room(&mut cx, 1), Poll::Ready(true));

        queue.push(1, frame(FAIR_LANE_CAP));
        assert_eq!(queue.poll_room(&mut cx, 1), Poll::Pending);
        queue.close();
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        assert_eq!(queue.poll_room(&mut cx, 1), Poll::Ready(false));
        assert!(!queue.push(1, frame(1)));
        assert_eq!(queue.try_batch(1), Some(None));
    }

    #[test]
    fn retired_lanes_drain_then_go_and_discarded_lanes_go_at_once() {
        let queue = FairQueue::new(Discipline::Fair);
        queue.push(1, vec![1]);
        queue.retire(1);
        assert_eq!(queue.queued(), 1);
        assert_eq!(queue.try_batch(16).unwrap().unwrap(), [1]);
        assert!(queue.lock().lanes.is_empty());

        queue.push(3, vec![3]);
        queue.discard(3);
        assert_eq!(queue.queued(), 0);
        assert!(queue.try_batch(16).is_none());
    }
}
