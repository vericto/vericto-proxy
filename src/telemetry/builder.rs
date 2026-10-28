// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Telemetry events built off the query path (4.19.0,
//! `VERICTO_TELEMETRY_BUILD_QUEUE`).
//!
//! Building an event is most of what telemetry costs a statement: in sanitized
//! mode the query text is normalized again (libpg_query for PostgreSQL, the
//! sqlparser tokenizer for MySQL), the violations are mapped and redacted, and an
//! event id is drawn. Measured with the callgrind gate (4.18.0), sanitized mode
//! alone adds 7,500 instructions to a `BEGIN` and 35,000 to 71,000 to the
//! statements of the policy mix, 6 to 15% of their cost. [`DeferredQueue`] moves
//! that work to one thread of its own: the query path hands it a closure that
//! builds the event from what the statement already owns (its SQL, its decision,
//! its identity, the telemetry mode and the time it was recorded), through a
//! bounded queue, and goes on.
//!
//! - **Never blocks the query path.** A full channel drops the event and counts
//!   it (`dropped_queue_full`, with a rate-limited warning), exactly like a full
//!   channel to the disk writer. Handing an event over takes a lock and, while
//!   the builder is busy, no system call: it collects events for a few
//!   milliseconds at a time instead of being woken for each one.
//! - **Never touches the verdict.** The decision was reached and acted on before
//!   the event is built; the closure works on a copy.
//! - **Same content.** The closure calls the same builder with the same inputs,
//!   and the time of the event is taken on the query path: the event is the one
//!   the query path would have built (only `event_id`, random either way,
//!   differs).
//! - **Same order.** One thread builds the events in the order they were handed
//!   over, and events pushed ready-made ([`EventQueue::push`]) take the same way.
//! - **Nothing lost at shutdown.** [`EventQueue::flush`] waits for the events
//!   handed over before it to be built and pushed, then flushes the queue below.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use super::TelemetryEvent;
use super::queue::{Batch, EventQueue, QueueStats, WarnLimiter};

/// What the query path hands over: a closure that builds one event.
pub type BuildJob = Box<dyn FnOnce() -> TelemetryEvent + Send>;

/// Default of `VERICTO_TELEMETRY_BUILD_QUEUE`: events waiting to be built.
///
/// The builder keeps up with far more than a proxy evaluates (an event takes it
/// 2 to 20 µs, the statement behind it 10 µs or more on the query path), so the
/// queue only fills when the builder thread is starved of CPU. 4,096 events hold
/// a few hundred milliseconds of a busy proxy's traffic, at a few MB.
pub const DEFAULT_BUILD_QUEUE: usize = 4096;

/// How long the builder lets events collect while it has work: a busy proxy
/// wakes it once per tick, never once per event, so handing an event over costs
/// the query path a lock and no system call. An idle builder (a whole tick
/// without an event) sleeps until the next one. Events wait at most this long
/// to be built, against the reporter's flush interval of seconds.
const TICK: Duration = Duration::from_millis(25);

/// An [`EventQueue`] in front of another one that builds the events on its own
/// thread. Everything but `push`, `stats` and `flush` goes to the queue below as
/// is.
pub struct DeferredQueue {
    inner: Arc<dyn EventQueue>,
    shared: Arc<Shared>,
    capacity: usize,
}

struct Shared {
    /// Jobs waiting for the builder (at most `capacity`).
    jobs: Mutex<VecDeque<BuildJob>>,
    /// Wakes the builder: a job for an idle builder, a full half of the queue,
    /// or a flush.
    wake: Condvar,
    /// The builder waits for `wake` with no timeout (nothing to do).
    idle: AtomicBool,
    /// A flush is waiting: the builder does not wait for its tick.
    flushing: AtomicU64,
    /// Jobs accepted.
    accepted: AtomicU64,
    /// Jobs built and pushed below, under the lock `flush` waits on.
    done: Mutex<u64>,
    built: Condvar,
    /// Jobs refused because the queue was full.
    dropped: AtomicU64,
    warn: WarnLimiter,
}

impl DeferredQueue {
    /// Starts the builder thread in front of `inner`, with room for `capacity`
    /// events waiting to be built (at least 1).
    pub fn new(inner: Arc<dyn EventQueue>, capacity: usize) -> std::io::Result<Self> {
        let capacity = capacity.max(1);
        let shared = Arc::new(Shared {
            jobs: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            idle: AtomicBool::new(false),
            flushing: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            done: Mutex::new(0),
            built: Condvar::new(),
            dropped: AtomicU64::new(0),
            warn: WarnLimiter::new(),
        });
        let (below, state) = (Arc::clone(&inner), Arc::clone(&shared));
        std::thread::Builder::new()
            .name("vericto-telemetry-build".into())
            .spawn(move || run_builder(&*below, &state))?;
        Ok(Self {
            inner,
            shared,
            capacity,
        })
    }

    /// Hands `job` to the builder thread. Never blocks on the builder: when
    /// `capacity` events are already waiting the event is dropped and counted.
    pub fn submit(&self, job: BuildJob) {
        let len = {
            let mut jobs = lock(&self.shared.jobs);
            if jobs.len() >= self.capacity {
                None
            } else {
                jobs.push_back(job);
                Some(jobs.len())
            }
        };
        let Some(len) = len else {
            let total = self.shared.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if self.shared.warn.allow() {
                tracing::warn!(
                    dropped_total = total,
                    capacity = self.capacity,
                    "Telemetry build queue full — dropping events (VERICTO_TELEMETRY_BUILD_QUEUE)"
                );
            }
            return;
        };
        self.shared.accepted.fetch_add(1, Ordering::Release);
        // A busy builder picks the job up at its next tick: no wake-up, so no
        // system call here. An idle one, or a queue half full, is woken.
        if self.shared.idle.load(Ordering::Acquire) || len * 2 >= self.capacity {
            self.shared.wake.notify_one();
        }
    }

    /// Waits until every job accepted before the call is built, at most
    /// `timeout`. `true` when it is.
    fn wait_built(&self, timeout: Duration) -> bool {
        let target = self.shared.accepted.load(Ordering::Acquire);
        let deadline = Instant::now() + timeout;
        self.shared.flushing.fetch_add(1, Ordering::AcqRel);
        self.shared.wake.notify_one();
        let mut done = lock(&self.shared.done);
        let reached = loop {
            if *done >= target {
                break true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break false;
            }
            done = self
                .shared
                .built
                .wait_timeout(done, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        };
        drop(done);
        self.shared.flushing.fetch_sub(1, Ordering::AcqRel);
        reached
    }

    /// Events handed over and not built yet.
    pub fn pending(&self) -> u64 {
        let done = *lock(&self.shared.done);
        self.shared
            .accepted
            .load(Ordering::Acquire)
            .saturating_sub(done)
    }
}

/// The builder thread: takes every waiting job at once, builds and pushes them
/// in order, then waits for the next tick (work was found) or for a wake-up
/// (none was). Runs for the life of the process.
fn run_builder(below: &dyn EventQueue, state: &Shared) {
    let mut batch: Vec<BuildJob> = Vec::new();
    loop {
        {
            let mut jobs = lock(&state.jobs);
            if jobs.is_empty() {
                state.idle.store(true, Ordering::Release);
                while jobs.is_empty() {
                    jobs = state.wake.wait(jobs).unwrap_or_else(|e| e.into_inner());
                }
                state.idle.store(false, Ordering::Release);
            }
            batch.extend(jobs.drain(..));
        }
        let n = batch.len() as u64;
        for job in batch.drain(..) {
            below.push(job());
        }
        {
            let mut done = lock(&state.done);
            *done += n;
        }
        state.built.notify_all();
        // Let the next events collect, unless a flush is waiting for them.
        if state.flushing.load(Ordering::Acquire) == 0 {
            let jobs = lock(&state.jobs);
            let _ = state.wake.wait_timeout(jobs, TICK);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl EventQueue for DeferredQueue {
    /// A ready-made event takes the builder's way too, so it keeps its place
    /// among the events handed over before it.
    fn push(&self, event: TelemetryEvent) {
        self.submit(Box::new(move || event));
    }

    fn drain_batch(&self, max: usize) -> Batch {
        self.inner.drain_batch(max)
    }

    fn ack(&self, batch: &Batch) {
        self.inner.ack(batch)
    }

    fn nack(&self, batch: Batch) {
        self.inner.nack(batch)
    }

    fn available(&self) -> usize {
        self.inner.available()
    }

    /// The queue's counters, with the events waiting to be built in
    /// `queue_depth` and those the full queue dropped in `dropped_queue_full`.
    fn stats(&self) -> QueueStats {
        let mut stats = self.inner.stats();
        stats.queue_depth += self.pending() as usize;
        stats.dropped_queue_full += self.shared.dropped.load(Ordering::Relaxed);
        stats
    }

    fn oldest_buffered_at(&self) -> Option<SystemTime> {
        self.inner.oldest_buffered_at()
    }

    fn spool_dir(&self) -> Option<PathBuf> {
        self.inner.spool_dir()
    }

    fn adopt(&self, dir: &Path) -> std::io::Result<(usize, usize)> {
        self.inner.adopt(dir)
    }

    /// Builds what was handed over before the call, then flushes the queue
    /// below, within `timeout` in total.
    fn flush(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        let built = self.wait_built(timeout);
        built && self.inner.flush(timeout.saturating_sub(started.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::queue::MemoryQueue;
    use std::sync::Barrier;
    use std::sync::mpsc;

    fn event(id: &str) -> TelemetryEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": id, "database_id": "db-1", "query_text": "SELECT 1",
            "dialect": "postgres", "status": "ALLOWED", "occurred_at": "2026-10-26T00:00:00Z"
        }))
        .unwrap()
    }

    fn ids(q: &MemoryQueue) -> Vec<String> {
        q.drain_batch(1000)
            .events
            .into_iter()
            .map(|e| e.event_id)
            .collect()
    }

    /// Jobs and ready-made events come out in the order they went in, and a
    /// flush returns once all of them are in the queue below.
    #[test]
    fn builds_in_order_and_flush_waits_for_every_event() {
        let below = Arc::new(MemoryQueue::new(1000));
        let q = DeferredQueue::new(below.clone(), 64).unwrap();
        for i in 0..50 {
            if i % 2 == 0 {
                let id = format!("e{i}");
                q.submit(Box::new(move || event(&id)));
            } else {
                q.push(event(&format!("e{i}")));
            }
        }
        assert!(q.flush(Duration::from_secs(5)));
        let want: Vec<String> = (0..50).map(|i| format!("e{i}")).collect();
        assert_eq!(ids(&below), want);
        assert_eq!(q.stats().queue_depth, 0);
        assert_eq!(q.stats().enqueued, 50);
    }

    /// A full channel drops the event and counts it, without blocking; the
    /// events it accepted are still built, and a flush that cannot finish in
    /// time says so.
    #[test]
    fn a_full_channel_drops_and_counts_without_blocking() {
        let below = Arc::new(MemoryQueue::new(1000));
        let q = DeferredQueue::new(below.clone(), 1).unwrap();
        // The first job holds the builder until the test lets it go.
        let (started_tx, started_rx) = mpsc::channel();
        let gate = Arc::new(Barrier::new(2));
        let held = Arc::clone(&gate);
        q.submit(Box::new(move || {
            started_tx.send(()).unwrap();
            held.wait();
            event("first")
        }));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // The builder is busy: one more fits in the queue, the rest do not.
        q.push(event("second"));
        let t = Instant::now();
        for i in 0..10 {
            q.submit(Box::new(move || event(&format!("late{i}"))));
        }
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "submit never blocks"
        );
        assert_eq!(q.stats().dropped_queue_full, 10);
        assert_eq!(
            q.stats().queue_depth,
            2,
            "first and second wait to be built"
        );
        assert!(
            !q.flush(Duration::from_millis(50)),
            "the builder is still held"
        );
        gate.wait();
        assert!(q.flush(Duration::from_secs(5)));
        assert_eq!(ids(&below), ["first", "second"]);
        assert_eq!(q.stats().queue_depth, 0);
    }
}
