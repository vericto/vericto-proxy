// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Event queue abstraction with two implementations selected by config:
//!   - MemoryQueue: bounded in-memory ring buffer (default).
//!   - DiskQueue: on-disk spool that survives restarts; entries are removed only
//!     after the API acknowledges delivery (at-least-once).
//!
//! Both are bounded, and neither ever makes the caller wait on I/O. `push` runs
//! on the query path, before the statement is forwarded, so whatever it costs is
//! added to every statement: it is a constant-time, in-memory operation in both
//! modes. When a buffer is full the excess is dropped, counted, and reported in a
//! warning at most every [`DROP_WARN_EVERY`].
//!
//! ## Disk spool (since 4.9.1)
//!
//! Up to 4.9.0 `DiskQueue::push` created, wrote and renamed one file per event on
//! the query path. On a network filesystem (EFS) each of those is a round trip,
//! and the kernel holds the spool directory's lock across create, rename and
//! unlink, so every connection queued behind every other one: throughput through
//! the proxy was capped at about 40 statements per second whatever the
//! concurrency. Now:
//!
//! - `push` hands the event to a bounded channel (`try_send`, never blocks).
//! - A writer thread drains the channel and writes the events as one *segment*
//!   file, `seg-<seq>-<count>.jsonl` (one JSON event per line), when it holds
//!   `batch_size` events or `flush_every` after its first event, whichever comes
//!   first: written to a hidden temporary name, fsynced, renamed into place, and
//!   the directory fsynced. A segment is in the spool only once it is durable.
//! - The spool index (segments, event counts, how much of each was delivered)
//!   lives in memory. The directory is listed once, at startup, to rebuild it;
//!   segment names carry a monotonic sequence number and their event count.
//! - Single-event `*.json` files left by earlier versions are read back as
//!   segments of one event, oldest first, so an upgrade loses nothing.
//!
//! ## Batches in flight (since 4.11.0)
//!
//! The reporter keeps several requests outstanding, so `drain_batch` is called
//! again before earlier batches are settled. Each segment records the line ranges
//! batches hold (`leased`) and the ranges acked ahead of an earlier, still
//! unanswered batch (`acked`). A drain skips held lines, so two batches never carry
//! the same event; an ack folds its range into the delivered prefix once every
//! range before it is acked too, and a segment is removed only when all of it is;
//! a nack releases its range for the next drain. None of this is on disk: after a
//! restart, whatever was not fully delivered is sent again (at-least-once).
//!
//! ## Bounded by bytes (since 4.12.0)
//!
//! Up to 4.11 the spool held at most `VERICTO_TELEMETRY_MEMORY_CAPACITY` events
//! (10,000): at 1,500 statements per second that is under 7 seconds of an API
//! outage. It is now bounded by the bytes it holds on disk,
//! `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` (default [`DEFAULT_SPOOL_MAX_BYTES`]), and
//! by an event count only when one is configured (`VERICTO_TELEMETRY_SPOOL_MAX_EVENTS`,
//! or `VERICTO_TELEMETRY_MEMORY_CAPACITY` as before). It also holds at most
//! [`MAX_SPOOL_SEGMENTS`] files, which bounds the in-memory index when traffic is
//! so low that every segment carries one event. Past any bound the oldest segments
//! go, as before. A segment's size is in its name (`seg-<seq>-<count>-<bytes>.jsonl`),
//! so the index is rebuilt at startup from one directory listing, without a `stat`
//! per file; a segment named by 4.9.1–4.11 (`seg-<seq>-<count>.jsonl`) or a legacy
//! `*.json` file is measured once with `stat`.

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::config::{BufferMode, ControlPlaneConfig};
use crate::telemetry::TelemetryEvent;

/// Shortest interval between two "events dropped" warnings of one queue. The
/// counters keep the exact figures; the warning only says that it is happening.
pub const DROP_WARN_EVERY: Duration = Duration::from_secs(10);

/// How often the disk writer looks at its channel while it collects a batch.
const WRITER_POLL: Duration = Duration::from_millis(5);

/// Default bound of the disk spool, in bytes: 1 GiB. See `docs/CONFIGURATION.md`
/// ("Disk spool size") for the arithmetic: about 28 minutes of an API outage at
/// 1,500 events per second of the measured average event size (417 bytes), and 5% of
/// Fargate's default 20 GiB of ephemeral storage.
pub const DEFAULT_SPOOL_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Most segment files the spool holds. A segment is written every
/// `VERICTO_TELEMETRY_SPOOL_FLUSH_MS` (50 ms) when it is not full, so at low
/// traffic each one carries a single event; this keeps the in-memory index (about
/// 200 bytes per segment) and the directory listed at startup bounded then. At
/// 1,500 events per second a segment carries ~75 events and the byte bound is
/// reached long before this one.
pub const MAX_SPOOL_SEGMENTS: usize = 100_000;

/// A batch drained for delivery, with an opaque handle to ack/remove it.
pub struct Batch {
    pub events: Vec<TelemetryEvent>,
    /// Disk spool segments backing this batch (empty for memory mode).
    spans: Vec<Span>,
}

/// The part of one spool segment a batch carries: its lines `start..end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    id: u64,
    start: usize,
    end: usize,
}

/// Counters of a queue, for the periodic stats log and for tests. Totals are
/// since the process started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueStats {
    /// Events in memory waiting for delivery (memory mode) or for the disk
    /// writer (disk mode).
    pub queue_depth: usize,
    /// Undelivered events on disk (disk mode).
    pub spooled: usize,
    /// Bytes of the spool files holding undelivered events (disk mode). A file
    /// counts until all of it is delivered.
    pub spool_bytes: u64,
    /// Events accepted by `push`.
    pub enqueued: u64,
    /// Events refused by `push` because the channel to the disk writer was full,
    /// or (since 4.19.0) the channel to the event builder (`telemetry::builder`).
    pub dropped_queue_full: u64,
    /// Oldest events discarded to stay within the buffer's bounds (events, and
    /// bytes and files for the disk spool).
    pub evicted_oldest: u64,
    /// Events lost because their segment could not be written.
    pub write_failures: u64,
    /// Events not enqueued while telemetry was paused for the monthly quota
    /// (`telemetry::quota`). Filled in by the gated queue around this one.
    pub dropped_quota: u64,
    /// Segments written (one write + fsync each).
    pub batches_written: u64,
    /// Wall time of the last segment write, including both fsyncs.
    pub last_batch_write_us: u64,
    /// Longest segment write so far.
    pub max_batch_write_us: u64,
}

pub trait EventQueue: Send + Sync {
    /// Enqueue an event. Never blocks and never does I/O; drops when full.
    fn push(&self, event: TelemetryEvent);
    /// Take up to `max` events for delivery. Several batches may be out at once:
    /// a batch never contains an event another undelivered batch holds, and the
    /// events of a batch stay buffered until it is acked.
    fn drain_batch(&self, max: usize) -> Batch;
    /// Confirm a batch was delivered (removes it durably for disk mode). Batches
    /// may be acked in any order.
    fn ack(&self, batch: &Batch);
    /// Return events to the queue when delivery failed (memory mode re-buffers;
    /// disk mode releases the batch's lines, which the next drain offers again).
    fn nack(&self, batch: Batch);
    /// Events a `drain_batch` could hand out now: buffered and not held by a
    /// batch in flight.
    fn available(&self) -> usize;
    /// Current counters.
    fn stats(&self) -> QueueStats;
    /// When the oldest event still buffered (delivered or not yet) was recorded,
    /// `None` when nothing is buffered (since 4.12.0, for the delivery-lag metric).
    /// In-memory reads, plus at most one `stat` per head segment of the disk spool;
    /// never a scan of the spool. Events a batch in flight holds are the
    /// reporter's to account for in memory mode (they left the ring).
    fn oldest_buffered_at(&self) -> Option<SystemTime> {
        None
    }
    /// The directory of a disk spool, `None` for a memory buffer (also when the
    /// disk spool could not be opened and the proxy fell back to memory).
    fn spool_dir(&self) -> Option<PathBuf> {
        None
    }
    /// Takes over another proxy's spool directory, already moved out of its
    /// owner's reach (see [`DiskQueue::adopt_dir`]). Disk spool only.
    fn adopt(&self, dir: &Path) -> std::io::Result<(usize, usize)> {
        let _ = dir;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not a disk spool",
        ))
    }
    /// Persist everything accepted before this call, waiting at most `timeout`.
    /// `true` when it is persisted (always, for a queue with nothing to persist).
    /// Blocks the calling thread: shutdown and tests only, never the query path.
    fn flush(&self, timeout: Duration) -> bool {
        let _ = timeout;
        true
    }
}

pub fn new_queue(cfg: &ControlPlaneConfig) -> Box<dyn EventQueue> {
    match cfg.buffer_mode {
        BufferMode::Memory => Box::new(MemoryQueue::new(cfg.memory_capacity)),
        BufferMode::Disk => {
            let opts = DiskOptions::new(
                cfg.spool.max_events.unwrap_or(usize::MAX),
                cfg.spool.max_bytes,
                cfg.spool.queue_capacity,
                cfg.spool.segment_max,
                cfg.spool.flush_every,
            );
            match DiskQueue::with_options(&cfg.disk_spool_path, opts) {
                Ok(q) => Box::new(q),
                Err(e) => {
                    // Disk spool unavailable (permissions, missing dir): degrade to
                    // memory rather than failing — telemetry must never break the proxy.
                    tracing::error!(error = %e, "Disk spool init failed; falling back to in-memory telemetry buffer");
                    Box::new(MemoryQueue::new(cfg.memory_capacity))
                }
            }
        }
    }
}

/// Rate limit for a warning emitted from the query path: lets one through per
/// `DROP_WARN_EVERY`, lock-free.
pub(crate) struct WarnLimiter {
    /// Milliseconds since `epoch()` of the last warning, plus one; 0 = never.
    last: AtomicU64,
}

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

impl WarnLimiter {
    pub(crate) const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
        }
    }

    pub(crate) fn allow(&self) -> bool {
        let now = epoch().elapsed().as_millis() as u64 + 1;
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < DROP_WARN_EVERY.as_millis() as u64 {
            return false;
        }
        self.last
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

/// An event's `occurred_at` (RFC 3339) as a time; now when it does not parse,
/// which reads as "no lag" rather than inventing one.
pub fn event_time(occurred_at: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(occurred_at)
        .map(SystemTime::from)
        .unwrap_or_else(|_| SystemTime::now())
}

// ─── In-memory ───────────────────────────────────────────────────────────────

pub struct MemoryQueue {
    capacity: usize,
    inner: Mutex<VecDeque<TelemetryEvent>>,
    enqueued: AtomicU64,
    evicted: AtomicU64,
    warn: WarnLimiter,
}

impl MemoryQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            enqueued: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            warn: WarnLimiter::new(),
        }
    }

    fn note_evicted(&self, n: u64) {
        let total = self.evicted.fetch_add(n, Ordering::Relaxed) + n;
        if self.warn.allow() {
            tracing::warn!(
                evicted_total = total,
                capacity = self.capacity,
                "Telemetry memory buffer full — dropping the oldest events"
            );
        }
    }
}

impl EventQueue for MemoryQueue {
    fn push(&self, event: TelemetryEvent) {
        // The critical section is a constant-time ring operation. The warning (a
        // write to stdout) used to be emitted inside it, on every event, for as
        // long as the buffer stayed full; it is now outside and rate-limited.
        let evicted = {
            let mut q = self.inner.lock().unwrap();
            let evicted = if q.len() >= self.capacity {
                q.pop_front();
                true
            } else {
                false
            };
            q.push_back(event);
            evicted
        };
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        if evicted {
            self.note_evicted(1);
        }
    }

    fn drain_batch(&self, max: usize) -> Batch {
        let mut q = self.inner.lock().unwrap();
        let take = q.len().min(max);
        let events = q.drain(..take).collect();
        Batch {
            events,
            spans: Vec::new(),
        }
    }

    fn ack(&self, _batch: &Batch) {
        // Memory mode: already removed by drain_batch.
    }

    fn nack(&self, batch: Batch) {
        // Re-buffer at the front so order is roughly preserved; respect capacity.
        let total = batch.events.len();
        let mut kept = 0;
        {
            let mut q = self.inner.lock().unwrap();
            for event in batch.events.into_iter().rev() {
                if q.len() >= self.capacity {
                    break; // drop rather than exceed the bound
                }
                q.push_front(event);
                kept += 1;
            }
        }
        if kept < total {
            self.note_evicted((total - kept) as u64);
        }
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    fn oldest_buffered_at(&self) -> Option<SystemTime> {
        // FIFO: the front is the oldest (a nacked batch goes back to the front).
        let q = self.inner.lock().unwrap();
        q.front().map(|ev| event_time(&ev.occurred_at))
    }

    fn stats(&self) -> QueueStats {
        QueueStats {
            queue_depth: self.inner.lock().unwrap().len(),
            enqueued: self.enqueued.load(Ordering::Relaxed),
            evicted_oldest: self.evicted.load(Ordering::Relaxed),
            ..QueueStats::default()
        }
    }
}

// ─── On-disk spool ─────────────────────────────────────────────────────────

/// How a [`DiskQueue`] is sized and paced.
#[derive(Debug, Clone)]
pub struct DiskOptions {
    /// Undelivered events kept on disk; past it the oldest segments go.
    /// `usize::MAX` (the default) = bounded by bytes only.
    pub capacity: usize,
    /// Bytes of spool files kept on disk; past it the oldest segments go.
    pub max_bytes: u64,
    /// Segment files kept on disk; past it the oldest go.
    pub max_segments: usize,
    /// Events the channel in front of the writer holds; past it `push` drops.
    pub queue_capacity: usize,
    /// Most events per segment, i.e. per write and fsync. Independent of the
    /// delivery batch size: a segment is delivered in as many POSTs as it takes.
    pub batch_max: usize,
    /// Longest an event waits in the channel before its segment is written.
    pub flush_every: Duration,
    /// Test hook: extra time each segment write takes, to stand in for a slow disk.
    #[cfg(test)]
    pub write_delay: Duration,
}

impl DiskOptions {
    pub fn new(
        capacity: usize,
        max_bytes: u64,
        queue_capacity: usize,
        batch_max: usize,
        flush_every: Duration,
    ) -> Self {
        Self {
            capacity,
            max_bytes,
            max_segments: MAX_SPOOL_SEGMENTS,
            queue_capacity,
            batch_max,
            flush_every,
            #[cfg(test)]
            write_delay: Duration::ZERO,
        }
    }
}

impl Default for DiskOptions {
    fn default() -> Self {
        let tuning = crate::config::SpoolTuning::default();
        Self::new(
            tuning.max_events.unwrap_or(usize::MAX),
            tuning.max_bytes,
            tuning.queue_capacity,
            tuning.segment_max,
            tuning.flush_every,
        )
    }
}

/// Undelivered events on disk, in segments, oldest first. See the module docs.
///
/// An event holds the query text (raw unless the workspace chose sanitized
/// reporting), the database user and the client address, so the spool is
/// private to the proxy's user: the directory is `0700` and every file `0600`,
/// as the rules cache already is (src/tcp/rules_cache.rs).
pub struct DiskQueue {
    shared: Arc<DiskShared>,
    /// `None` only while dropping, so the writer sees the channel close.
    tx: Option<SyncSender<WriterMsg>>,
    writer: Option<JoinHandle<()>>,
}

enum WriterMsg {
    /// Boxed so the channel's slots stay small (an event is ~450 bytes).
    Event(Box<TelemetryEvent>),
    /// Write what came before, then answer.
    Flush(SyncSender<()>),
}

struct DiskShared {
    dir: PathBuf,
    capacity: usize,
    max_bytes: u64,
    max_segments: usize,
    queue_capacity: usize,
    index: Mutex<SpoolIndex>,
    /// Serializes `drain_batch`: between reading a segment and recording what it
    /// took, no other drain may hand out the same lines.
    drain_lock: Mutex<()>,
    /// The segment `drain_batch` read last (ids are never reused).
    head_cache: Mutex<Option<(u64, Arc<Vec<u8>>)>>,
    /// Events accepted by `push` and not yet written (or lost) by the writer.
    pending: AtomicUsize,
    enqueued: AtomicU64,
    dropped_queue_full: AtomicU64,
    evicted_oldest: AtomicU64,
    write_failures: AtomicU64,
    batches_written: AtomicU64,
    last_batch_write_us: AtomicU64,
    max_batch_write_us: AtomicU64,
    warn_full: WarnLimiter,
    warn_evict: WarnLimiter,
    warn_write: WarnLimiter,
}

#[derive(Default)]
struct SpoolIndex {
    segments: VecDeque<Segment>,
    /// Undelivered events across `segments`.
    events: usize,
    /// Bytes of the files in `segments`.
    bytes: u64,
    /// In-memory identity of the next segment entry (stable across evictions).
    next_id: u64,
    /// Sequence number of the next segment file.
    next_seq: u64,
}

struct Segment {
    id: u64,
    path: PathBuf,
    /// Events in the file.
    count: usize,
    /// Size of the file.
    bytes: u64,
    /// Leading events already delivered (acked). In memory only: after a
    /// restart a partly delivered segment is sent again from its start, which is
    /// what at-least-once allows.
    delivered: usize,
    /// Line ranges held by batches in flight (since 4.11.0, several at once).
    leased: Vec<(usize, usize)>,
    /// Line ranges past `delivered` already acked: a later batch can be acked
    /// before an earlier one. Folded into `delivered` once the gap closes.
    acked: Vec<(usize, usize)>,
    /// When the file was written: set for segments this process wrote, and read
    /// once from the file's mtime for a segment found at startup or adopted, the
    /// first time it is the oldest one (delivery-lag metric).
    written_at: Option<SystemTime>,
}

/// Lines of `ranges` below `limit`.
fn lines_below(ranges: &[(usize, usize)], limit: usize) -> usize {
    ranges
        .iter()
        .map(|&(a, b)| b.min(limit).saturating_sub(a))
        .sum()
}

impl Segment {
    fn new(id: u64, path: PathBuf, count: usize, bytes: u64) -> Self {
        Self {
            id,
            path,
            count,
            bytes,
            delivered: 0,
            leased: Vec::new(),
            acked: Vec::new(),
            written_at: None,
        }
    }

    /// Undelivered events (in flight or not).
    fn remaining(&self) -> usize {
        self.count
            .saturating_sub(self.delivered)
            .saturating_sub(lines_below(&self.acked, self.count))
    }

    /// Undelivered events not held by a batch in flight.
    fn available(&self) -> usize {
        self.remaining()
            .saturating_sub(lines_below(&self.leased, self.count))
    }

    fn release(&mut self, span: &Span) {
        if let Some(pos) = self
            .leased
            .iter()
            .position(|&r| r == (span.start, span.end))
        {
            self.leased.swap_remove(pos);
        }
    }

    /// Marks `span` delivered and advances `delivered` over every acked range
    /// that now touches it.
    fn ack(&mut self, span: &Span) {
        self.release(span);
        if span.end > self.delivered {
            self.acked.push((span.start.max(self.delivered), span.end));
        }
        self.acked.sort_unstable();
        let mut i = 0;
        while i < self.acked.len() {
            let (a, b) = self.acked[i];
            if a <= self.delivered {
                self.delivered = self.delivered.max(b);
                self.acked.remove(i);
                i = 0; // a range past it may touch the new end
            } else {
                i += 1;
            }
        }
    }

    fn complete(&self) -> bool {
        self.delivered >= self.count && self.leased.is_empty()
    }
}

const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".jsonl";

/// `seg-<seq>-<count>-<bytes>.jsonl` (since 4.12.0; the size lets the index be
/// rebuilt without a `stat` per file).
fn segment_name(seq: u64, count: usize, bytes: u64) -> String {
    format!("{SEGMENT_PREFIX}{seq:020}-{count}-{bytes}{SEGMENT_SUFFIX}")
}

/// `(seq, count, bytes)` from a segment file name. `bytes` is `None` for a
/// segment named by 4.9.1–4.11 (`seg-<seq>-<count>.jsonl`), which has no size in
/// its name.
fn parse_segment_name(name: &str) -> Option<(u64, usize, Option<u64>)> {
    let core = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    let mut parts = core.split('-');
    let seq = parts.next()?.parse().ok()?;
    let count = parts.next()?.parse().ok()?;
    let bytes = match parts.next() {
        Some(b) => Some(b.parse().ok()?),
        None => None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((seq, count, bytes))
}

/// Size of a spool file whose name does not carry it (legacy or pre-4.12 names).
/// 0 when it cannot be read: the file is then discarded at its first drain anyway.
fn file_bytes(entry: &fs::DirEntry) -> u64 {
    entry.metadata().map(|m| m.len()).unwrap_or(0)
}

impl DiskQueue {
    /// A spool with default pacing and `capacity` events.
    #[cfg(test)]
    pub fn new(dir: String, capacity: usize) -> std::io::Result<Self> {
        Self::with_options(
            dir,
            DiskOptions {
                capacity,
                ..DiskOptions::default()
            },
        )
    }

    pub fn with_options(dir: impl Into<PathBuf>, opts: DiskOptions) -> std::io::Result<Self> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        let started = Instant::now();
        let (index, legacy) = rebuild_index(&dir)?;
        let capacity = opts.capacity.max(1);
        let shared = Arc::new(DiskShared {
            dir,
            capacity,
            max_bytes: opts.max_bytes.max(1),
            max_segments: opts.max_segments.max(1),
            queue_capacity: opts.queue_capacity.max(1),
            index: Mutex::new(index),
            drain_lock: Mutex::new(()),
            head_cache: Mutex::new(None),
            pending: AtomicUsize::new(0),
            enqueued: AtomicU64::new(0),
            dropped_queue_full: AtomicU64::new(0),
            evicted_oldest: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            batches_written: AtomicU64::new(0),
            last_batch_write_us: AtomicU64::new(0),
            max_batch_write_us: AtomicU64::new(0),
            warn_full: WarnLimiter::new(),
            warn_evict: WarnLimiter::new(),
            warn_write: WarnLimiter::new(),
        });
        // A spool written with a larger capacity (or by many restarts) is brought
        // within this one's bound before anything new arrives.
        shared.evict_to_fit(0, 0);
        {
            let index = shared.index.lock().unwrap();
            tracing::info!(
                dir = %shared.dir.display(),
                segments = index.segments.len(),
                legacy_files = legacy,
                events = index.events,
                bytes = index.bytes,
                max_bytes = shared.max_bytes,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Telemetry spool index rebuilt"
            );
        }

        let (tx, rx) = mpsc::sync_channel(shared.queue_capacity);
        let writer = {
            let shared = Arc::clone(&shared);
            let batch_max = opts.batch_max.clamp(1, capacity);
            let flush_every = opts.flush_every;
            #[cfg(test)]
            let write_delay = opts.write_delay;
            #[cfg(not(test))]
            let write_delay = Duration::ZERO;
            std::thread::Builder::new()
                .name("vericto-spool-writer".into())
                .spawn(move || writer_loop(&shared, rx, batch_max, flush_every, write_delay))?
        };
        Ok(Self {
            shared,
            tx: Some(tx),
            writer: Some(writer),
        })
    }

    /// Takes over the spool in `dir`, another proxy's (since 4.12.0,
    /// `telemetry::spool_dir`), which the caller has already moved where nobody
    /// else reads it: its files join this spool's index ahead of this spool's own
    /// (they are older), keep their paths, and are delivered, bounded and evicted
    /// like the rest. Returns the segments and events adopted.
    pub fn adopt_dir(&self, dir: &Path) -> std::io::Result<(usize, usize)> {
        let (files, _, _) = collect_spool(dir, 1)?;
        let (segments, mut events) = (files.len(), 0);
        {
            let mut index = self.shared.index.lock().unwrap();
            for (path, count, bytes) in files.into_iter().rev() {
                let id = index.next_id;
                index.next_id += 1;
                index.events += count;
                index.bytes += bytes;
                events += count;
                index
                    .segments
                    .push_front(Segment::new(id, path, count, bytes));
            }
        }
        self.shared.evict_to_fit(0, 0);
        Ok((segments, events))
    }

    /// Spool files on disk right now (`.json` legacy files and segments). Lists
    /// the directory: tests and diagnostics only.
    #[cfg(test)]
    fn files_on_disk(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.shared.dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap().to_string_lossy();
                !name.starts_with('.') && (name.ends_with(".json") || name.ends_with(".jsonl"))
            })
            .collect();
        files.sort();
        files
    }
}

impl Drop for DiskQueue {
    fn drop(&mut self) {
        // Closing the channel lets the writer persist what is queued and exit.
        drop(self.tx.take());
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// Name of the subdirectory of a spool that holds spools adopted from other
/// proxies (since 4.12.0, `telemetry::spool_dir`): `adopted/<name>/`, each one a
/// spool of its own, possibly with an `adopted/` of its own.
pub const ADOPTED_DIR: &str = "adopted";

/// How deep `adopted/` directories are followed: a chain of restarts each adopting
/// the previous spool nests one level per restart, and each is pruned once drained.
const MAX_ADOPTED_DEPTH: usize = 16;

/// A spool file to index: `(path, events, bytes)`.
type SpoolFile = (PathBuf, usize, u64);

/// The spool files of one directory, oldest first.
struct Listing {
    /// Legacy `*.json` files (one event each, named by timestamp), in name order.
    legacy: Vec<(PathBuf, u64)>,
    /// Segments in sequence order: `(seq, count, bytes, path)`.
    segments: Vec<(u64, usize, u64, PathBuf)>,
    /// The directory has an `adopted/` subdirectory.
    adopted: bool,
}

/// Lists `dir` once. Hidden files (temporaries, the rules cache, a lease) and
/// anything else are left alone.
fn list_spool(dir: &Path) -> std::io::Result<Listing> {
    let mut listing = Listing {
        legacy: Vec::new(),
        segments: Vec::new(),
        adopted: false,
    };
    for entry in fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if name == ADOPTED_DIR {
            listing.adopted = entry.file_type().is_ok_and(|t| t.is_dir());
            continue;
        }
        if let Some((seq, count, bytes)) = parse_segment_name(name) {
            let bytes = bytes.unwrap_or_else(|| file_bytes(&entry));
            listing.segments.push((seq, count, bytes, path));
        } else if name.ends_with(".json") {
            let bytes = file_bytes(&entry);
            listing.legacy.push((path, bytes));
        }
    }
    listing.legacy.sort(); // lexical = chronological (timestamped names)
    listing.segments.sort_by_key(|(seq, _, _, _)| *seq);
    Ok(listing)
}

/// Every spool file of `dir` and of the spools adopted into it, oldest first:
/// adopted spools (older than this one's own files), then legacy files, then
/// segments. `(path, events, bytes)`, plus the number of legacy files and the
/// listing of `dir` itself.
fn collect_spool(dir: &Path, depth: usize) -> std::io::Result<(Vec<SpoolFile>, usize, Listing)> {
    let mut listing = list_spool(dir)?;
    let mut files = Vec::new();
    let mut legacy_files = listing.legacy.len();
    if listing.adopted {
        if depth >= MAX_ADOPTED_DEPTH {
            tracing::warn!(dir = %dir.display(), "Adopted telemetry spools nested too deep; the deepest are not read");
        } else {
            let mut children: Vec<PathBuf> = fs::read_dir(dir.join(ADOPTED_DIR))?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect();
            children.sort();
            for child in children {
                match collect_spool(&child, depth + 1) {
                    Ok((more, legacy, _)) => {
                        files.extend(more);
                        legacy_files += legacy;
                    }
                    Err(e) => {
                        tracing::warn!(dir = %child.display(), error = %e, "Adopted telemetry spool unreadable; skipped")
                    }
                }
            }
        }
    }
    files.extend(
        listing
            .legacy
            .drain(..)
            .map(|(path, bytes)| (path, 1, bytes)),
    );
    files.extend(
        listing
            .segments
            .iter()
            .map(|(_, count, bytes, path)| (path.clone(), *count, *bytes)),
    );
    Ok((files, legacy_files, listing))
}

/// Lists the spool once and returns its index and how many legacy files it has.
/// Spools adopted from other proxies (`adopted/`) come first, then legacy `*.json`
/// files in name order, then segments in sequence order. Hidden files
/// (temporaries, the rules cache, a lease) and anything else are left alone.
fn rebuild_index(dir: &Path) -> std::io::Result<(SpoolIndex, usize)> {
    let (files, legacy_files, listing) = collect_spool(dir, 0)?;
    let mut index = SpoolIndex {
        next_seq: listing
            .segments
            .last()
            .map(|(seq, _, _, _)| seq + 1)
            .unwrap_or(1),
        ..SpoolIndex::default()
    };
    for (path, count, bytes) in files {
        index.add(path, count, bytes);
    }
    Ok((index, legacy_files))
}

impl SpoolIndex {
    fn add(&mut self, path: PathBuf, count: usize, bytes: u64) {
        let id = self.next_id;
        self.next_id += 1;
        self.events += count;
        self.bytes += bytes;
        self.segments
            .push_back(Segment::new(id, path, count, bytes));
    }

    fn position(&self, id: u64) -> Option<usize> {
        // Batches come from the head, so this ends within the first few entries.
        self.segments.iter().position(|s| s.id == id)
    }

    /// Removes a segment from the index; returns its path and undelivered events.
    fn remove(&mut self, id: u64) -> Option<(PathBuf, usize)> {
        let pos = self.position(id)?;
        let seg = self.segments.remove(pos)?;
        let remaining = seg.remaining();
        self.events = self.events.saturating_sub(remaining);
        self.bytes = self.bytes.saturating_sub(seg.bytes);
        Some((seg.path, remaining))
    }
}

/// The disk writer: one thread, the only one that creates spool files.
fn writer_loop(
    shared: &DiskShared,
    rx: Receiver<WriterMsg>,
    batch_max: usize,
    flush_every: Duration,
    write_delay: Duration,
) {
    let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(batch_max);
    let mut waiters: Vec<SyncSender<()>> = Vec::new();
    loop {
        // Idle until something arrives; a closed channel ends the thread once it
        // has been drained (std's channel delivers what is buffered first).
        let Ok(first) = rx.recv() else { return };
        let mut closed = false;
        let deadline = Instant::now() + flush_every;
        accept(first, &mut batch, &mut waiters);
        // Collect by polling in short sleeps rather than blocking in `recv`: a
        // blocked receiver makes every `push` wake this thread (a futex call and
        // a context switch per statement); a sleeping one costs `push` nothing.
        loop {
            while batch.len() < batch_max && waiters.is_empty() {
                match rx.try_recv() {
                    Ok(msg) => accept(msg, &mut batch, &mut waiters),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if closed || batch.len() >= batch_max || !waiters.is_empty() || left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(WRITER_POLL));
        }
        if !batch.is_empty() {
            let events = std::mem::replace(&mut batch, Vec::with_capacity(batch_max));
            shared.write_segment(events, write_delay);
        }
        for waiter in waiters.drain(..) {
            let _ = waiter.send(());
        }
        if closed {
            return;
        }
    }
}

fn accept(msg: WriterMsg, batch: &mut Vec<TelemetryEvent>, waiters: &mut Vec<SyncSender<()>>) {
    match msg {
        WriterMsg::Event(event) => batch.push(*event),
        WriterMsg::Flush(done) => waiters.push(done),
    }
}

impl DiskShared {
    /// Writes `events` as one durable segment and adds it to the index.
    fn write_segment(&self, events: Vec<TelemetryEvent>, write_delay: Duration) {
        let started = Instant::now();
        let accepted = events.len();
        let mut body = Vec::with_capacity(accepted * 512);
        let mut count = 0;
        for event in &events {
            match serde_json::to_vec(event) {
                Ok(bytes) => {
                    body.extend_from_slice(&bytes);
                    body.push(b'\n');
                    count += 1;
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to serialize telemetry event for spool");
                    self.write_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(events);
        if count == 0 {
            self.pending.fetch_sub(accepted, Ordering::Relaxed);
            return;
        }

        let seq = {
            let mut index = self.index.lock().unwrap();
            let seq = index.next_seq;
            index.next_seq += 1;
            seq
        };
        let bytes = body.len() as u64;
        let name = segment_name(seq, count, bytes);
        let path = self.dir.join(&name);
        // Written under a hidden temporary name, fsynced, then renamed: `rename`
        // within one directory is atomic, so a reader never observes a partially
        // written segment, and a crash before the rename leaves only an ignored
        // temporary. The directory fsync makes the rename itself durable.
        let tmp = self.dir.join(format!(".{name}.tmp"));
        if !write_delay.is_zero() {
            std::thread::sleep(write_delay);
        }
        let wrote = create_private_file(&tmp)
            .and_then(|mut f| {
                f.write_all(&body)?;
                f.sync_all()
            })
            .and_then(|()| fs::rename(&tmp, &path));
        if let Err(e) = wrote {
            let _ = fs::remove_file(&tmp);
            let total = self
                .write_failures
                .fetch_add(count as u64, Ordering::Relaxed)
                + count as u64;
            if self.warn_write.allow() {
                tracing::warn!(error = %e, events = count, lost_total = total, "Failed to write telemetry segment to spool; events dropped");
            }
            self.pending.fetch_sub(accepted, Ordering::Relaxed);
            return;
        }
        sync_dir(&self.dir);

        self.evict_to_fit(count, bytes);
        {
            let mut index = self.index.lock().unwrap();
            index.add(path, count, bytes);
            if let Some(seg) = index.segments.back_mut() {
                seg.written_at = Some(SystemTime::now());
            }
        }
        self.pending.fetch_sub(accepted, Ordering::Relaxed);

        let us = started.elapsed().as_micros() as u64;
        self.batches_written.fetch_add(1, Ordering::Relaxed);
        self.last_batch_write_us.store(us, Ordering::Relaxed);
        self.max_batch_write_us.fetch_max(us, Ordering::Relaxed);
    }

    /// Drops the oldest segments until one more segment of `incoming` events and
    /// `incoming_bytes` bytes fits every bound: events, bytes and files (`0, 0`:
    /// until the spool is within them). A segment larger than the byte bound on
    /// its own is still written, into an otherwise empty spool. Files are removed
    /// outside the index lock.
    fn evict_to_fit(&self, incoming: usize, incoming_bytes: u64) {
        let mut doomed = Vec::new();
        let mut evicted = 0usize;
        let new_segment = usize::from(incoming > 0);
        {
            let mut index = self.index.lock().unwrap();
            while index.events.saturating_add(incoming) > self.capacity
                || index.bytes.saturating_add(incoming_bytes) > self.max_bytes
                || index.segments.len() + new_segment > self.max_segments
            {
                let Some(seg) = index.segments.pop_front() else {
                    break;
                };
                let remaining = seg.remaining();
                index.events = index.events.saturating_sub(remaining);
                index.bytes = index.bytes.saturating_sub(seg.bytes);
                evicted += remaining;
                doomed.push(seg.path);
            }
        }
        for path in doomed {
            let _ = fs::remove_file(path);
        }
        if evicted > 0 {
            let total = self
                .evicted_oldest
                .fetch_add(evicted as u64, Ordering::Relaxed)
                + evicted as u64;
            if self.warn_evict.allow() {
                tracing::warn!(
                    evicted_total = total,
                    max_bytes = self.max_bytes,
                    max_events = (self.capacity != usize::MAX).then_some(self.capacity),
                    "Telemetry disk spool full — dropped the oldest events"
                );
            }
        }
    }

    /// The bytes of a segment, from the one-entry cache when it is the segment
    /// read last: a segment larger than a delivery batch is read once, not once
    /// per POST. Called by the reporter only.
    fn read_segment(&self, id: u64, path: &Path) -> std::io::Result<Arc<Vec<u8>>> {
        let mut cache = self.head_cache.lock().unwrap();
        if let Some((cached, bytes)) = cache.as_ref() {
            if *cached == id {
                return Ok(Arc::clone(bytes));
            }
        }
        let bytes = Arc::new(fs::read(path)?);
        *cache = Some((id, Arc::clone(&bytes)));
        Ok(bytes)
    }

    /// Discards a segment that cannot be read, so the queue can advance.
    fn discard(&self, id: u64) {
        let removed = self.index.lock().unwrap().remove(id);
        if let Some((path, _)) = removed {
            let _ = fs::remove_file(path);
        }
    }
}

impl EventQueue for DiskQueue {
    fn push(&self, event: TelemetryEvent) {
        let Some(tx) = &self.tx else { return };
        // Counted before the send so the writer's decrement can never run first.
        self.shared.pending.fetch_add(1, Ordering::Relaxed);
        match tx.try_send(WriterMsg::Event(Box::new(event))) {
            Ok(()) => {
                self.shared.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.pending.fetch_sub(1, Ordering::Relaxed);
                let total = self
                    .shared
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                if self.shared.warn_full.allow() {
                    tracing::warn!(
                        dropped_total = total,
                        queue_capacity = self.shared.queue_capacity,
                        "Telemetry queue full — dropping new events; queries are not held back"
                    );
                }
            }
        }
    }

    fn drain_batch(&self, max: usize) -> Batch {
        let max = max.max(1);
        let _drain = self.shared.drain_lock.lock().unwrap();
        loop {
            // Snapshot the segments that have lines to hand out; files are read
            // without the index lock. Lines held by a batch in flight are skipped,
            // so concurrent batches never carry the same event.
            #[allow(clippy::type_complexity)]
            let heads: Vec<(u64, PathBuf, usize, Vec<(usize, usize)>, bool)> = {
                let index = self.shared.index.lock().unwrap();
                let mut covered = 0;
                let mut heads = Vec::new();
                for seg in &index.segments {
                    if covered >= max {
                        break;
                    }
                    let available = seg.available();
                    let idle = seg.leased.is_empty();
                    if available == 0 && !idle {
                        continue; // all of it is in flight
                    }
                    covered += available;
                    let mut taken: Vec<(usize, usize)> =
                        seg.leased.iter().chain(seg.acked.iter()).copied().collect();
                    taken.push((0, seg.delivered));
                    heads.push((seg.id, seg.path.clone(), seg.count, taken, idle));
                }
                heads
            };
            let mut batch = Batch {
                events: Vec::new(),
                spans: Vec::new(),
            };
            for (id, path, count, taken, idle) in heads {
                if batch.events.len() >= max {
                    break;
                }
                // An unreadable segment must NOT be left where it is. The spool is
                // drained oldest-first, so skipping it parks it at the head of the
                // queue permanently: every later tick re-reads it and the reporter
                // stops when the batch comes back empty. One bad file would block
                // every good event behind it, across restarts too, since the spool
                // is durable by design. That is what happened on staging — the
                // `violations` round-trip bug made 283 files unreadable and
                // telemetry went quiet for nine hours with nothing logged.
                //
                // So: report it once, and discard it. The log says which file, so
                // the loss is auditable.
                let bytes = match self.shared.read_segment(id, &path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(file = %path.display(), error = %e, "Telemetry spool file unreadable; discarding so the queue can advance");
                        self.shared.discard(id);
                        continue;
                    }
                };
                let is_taken = |i: usize| taken.iter().any(|&(a, b)| a <= i && i < b);
                let mut runs: Vec<(usize, usize)> = Vec::new();
                let mut line_no = 0;
                let mut full = false;
                let valid_before = batch.events.len();
                for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    let i = line_no;
                    if is_taken(i) {
                        line_no += 1;
                        continue;
                    }
                    if batch.events.len() >= max {
                        full = true;
                        break;
                    }
                    match runs.last_mut() {
                        Some(run) if run.1 == i => run.1 = i + 1,
                        _ => runs.push((i, i + 1)),
                    }
                    match serde_json::from_slice::<TelemetryEvent>(line) {
                        Ok(ev) => batch.events.push(ev),
                        // A line that does not parse is carried by the batch (and
                        // retired with its ack) without being sent, like an
                        // unreadable file, and for the same reason.
                        Err(e) => {
                            tracing::error!(file = %path.display(), line = i + 1, error = %e, "Telemetry spool event failed to deserialize; discarding so the queue can advance")
                        }
                    }
                    line_no += 1;
                }
                if !full && idle && batch.events.len() == valid_before {
                    // Nothing left in it that can be delivered (only lines that do
                    // not parse, or none) and nothing in flight: gone now, not at
                    // the next ack, so it cannot sit at the head of the queue.
                    self.shared.discard(id);
                    continue;
                }
                if runs.is_empty() {
                    continue;
                }
                // Read to the end: the run that reaches it retires the rest of the
                // segment too, even if it held fewer lines than its name says.
                if !full {
                    if let Some(last) = runs.last_mut() {
                        if last.1 == line_no {
                            last.1 = line_no.max(count);
                        }
                    }
                }
                let mut index = self.shared.index.lock().unwrap();
                let pos = index.position(id);
                for (start, end) in runs {
                    batch.spans.push(Span { id, start, end });
                    if let Some(pos) = pos {
                        index.segments[pos].leased.push((start, end));
                    }
                }
            }
            if batch.events.is_empty() && !batch.spans.is_empty() {
                // Nothing deliverable in what was read (only bad lines): retire it
                // and look further, rather than return an empty batch, which the
                // reporter takes for an empty queue.
                self.ack(&batch);
                continue;
            }
            return batch;
        }
    }

    fn ack(&self, batch: &Batch) {
        // Delivered: advance each segment, and remove the ones fully delivered.
        let mut done = Vec::new();
        {
            let mut index = self.shared.index.lock().unwrap();
            for span in &batch.spans {
                let Some(pos) = index.position(span.id) else {
                    continue; // evicted meanwhile
                };
                let seg = &mut index.segments[pos];
                let before = seg.remaining();
                seg.ack(span);
                let after = seg.remaining();
                let complete = seg.complete();
                index.events = index.events.saturating_sub(before - after);
                if complete {
                    if let Some(seg) = index.segments.remove(pos) {
                        index.bytes = index.bytes.saturating_sub(seg.bytes);
                        done.push(seg.path);
                    }
                }
            }
        }
        if !done.is_empty() {
            // Do not keep a delivered segment's bytes alive.
            *self.shared.head_cache.lock().unwrap() = None;
        }
        for path in done {
            let _ = fs::remove_file(path);
        }
    }

    fn nack(&self, batch: Batch) {
        // The segments stay in place; their lines are released, so the next
        // drain offers them again (oldest first).
        let mut index = self.shared.index.lock().unwrap();
        for span in &batch.spans {
            if let Some(pos) = index.position(span.id) {
                index.segments[pos].release(span);
            }
        }
    }

    fn available(&self) -> usize {
        let index = self.shared.index.lock().unwrap();
        index.segments.iter().map(Segment::available).sum()
    }

    fn spool_dir(&self) -> Option<PathBuf> {
        Some(self.shared.dir.clone())
    }

    fn adopt(&self, dir: &Path) -> std::io::Result<(usize, usize)> {
        self.adopt_dir(dir)
    }

    fn oldest_buffered_at(&self) -> Option<SystemTime> {
        let (id, path, at) = {
            let index = self.shared.index.lock().unwrap();
            let seg = index.segments.iter().find(|s| s.remaining() > 0)?;
            (seg.id, seg.path.clone(), seg.written_at)
        };
        if at.is_some() {
            return at;
        }
        // A segment this process did not write: its mtime, read once, outside the
        // index lock (one round trip on EFS, once per such head segment).
        let at = fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let mut index = self.shared.index.lock().unwrap();
        if let Some(pos) = index.position(id) {
            index.segments[pos].written_at = Some(at);
        }
        Some(at)
    }

    fn stats(&self) -> QueueStats {
        let s = &self.shared;
        let (spooled, spool_bytes) = {
            let index = s.index.lock().unwrap();
            (index.events, index.bytes)
        };
        QueueStats {
            queue_depth: s.pending.load(Ordering::Relaxed),
            spooled,
            spool_bytes,
            enqueued: s.enqueued.load(Ordering::Relaxed),
            dropped_queue_full: s.dropped_queue_full.load(Ordering::Relaxed),
            evicted_oldest: s.evicted_oldest.load(Ordering::Relaxed),
            write_failures: s.write_failures.load(Ordering::Relaxed),
            batches_written: s.batches_written.load(Ordering::Relaxed),
            last_batch_write_us: s.last_batch_write_us.load(Ordering::Relaxed),
            max_batch_write_us: s.max_batch_write_us.load(Ordering::Relaxed),
            dropped_quota: 0,
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        let Some(tx) = &self.tx else { return true };
        let deadline = Instant::now() + timeout;
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let mut msg = WriterMsg::Flush(done_tx);
        // The marker queues behind every event accepted so far.
        loop {
            match tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = m;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        done_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

/// Makes a rename in `dir` durable. Not every filesystem supports fsync on a
/// directory; the segment's own fsync already made its contents durable, so a
/// failure here is not an error.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Creates the spool directory (and any missing parent) owner-only. A directory
/// that already exists, such as a mounted volume, is narrowed to `0700` when it
/// is open to others; if that is not allowed (not its owner), the spool still
/// works, its files are `0600` regardless, and the failure is logged.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!(dir = %dir.display(), error = %e, "Telemetry spool directory is readable by other users and could not be narrowed to 0700");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Creates (or truncates) a spool file readable and writable by its owner only.
fn create_private_file(path: &std::path::Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetryEvent;

    /// A unique scratch directory per test. `tempfile` is deliberately not added as a
    /// dev-dependency for this — the repo keeps its dependency surface small and a
    /// counter plus the process id is enough for a handful of tests.
    fn scratch(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vericto-spool-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The shape that broke: a query that violated nothing, so `violations` is empty.
    fn allowed_event(id: &str) -> TelemetryEvent {
        TelemetryEvent {
            event_id: id.to_string(),
            database_id: "db-1".to_string(),
            query_text: "SELECT 1".to_string(),
            dialect: "postgres".to_string(),
            status: "ALLOWED".to_string(),
            rule_code: None,
            ast_node_path: None,
            severity: None,
            enforcement_action: None,
            parse_error: None,
            latency_ms: Some(0.1),
            client_ip: None,
            occurred_at: format!("2026-10-01T03:52:5{}.000000000+00:00", id.len() % 10),
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            db_user: None,
            access_policy_mode: None,
            access_denied: Vec::new(),
            principal_id: None,
            principal_type: None,
            principal_trust: None,
            principal_via: None,
            application_name: None,
            policy_bundle_version: None,
            ticket_id: None,
            session_tenant: None,
            kill_switch_id: None,
        }
    }

    const FLUSH: Duration = Duration::from_secs(10);

    fn opts(capacity: usize) -> DiskOptions {
        DiskOptions {
            capacity,
            ..DiskOptions::default()
        }
    }

    fn open(dir: &Path, o: DiskOptions) -> DiskQueue {
        DiskQueue::with_options(dir, o).unwrap()
    }

    fn drain_ids(q: &dyn EventQueue, max: usize) -> Vec<String> {
        let batch = q.drain_batch(max);
        let ids = batch.events.iter().map(|e| e.event_id.clone()).collect();
        q.ack(&batch);
        ids
    }

    /// The regression test for the defect that silenced telemetry for nine hours.
    ///
    /// `DiskQueue` is the only queue that reads back what it wrote, so it is the only
    /// one that depends on `TelemetryEvent` round-tripping through its own serializer.
    /// `skip_serializing_if = "Vec::is_empty"` omits `violations` for an ALLOWED event,
    /// and without `serde(default)` the read fails with "missing field". Every test of
    /// the *serializer* passed, because the payload the API receives was always correct.
    #[test]
    fn disk_queue_round_trips_an_event_with_no_violations() {
        let dir = scratch("roundtrip");
        let q = open(&dir, opts(100));

        q.push(allowed_event("e1"));
        assert!(q.flush(FLUSH));
        let batch = q.drain_batch(10);

        assert_eq!(
            batch.events.len(),
            1,
            "an ALLOWED event written to the spool must be readable again"
        );
        assert_eq!(batch.events[0].event_id, "e1");
        assert!(batch.events[0].violations.is_empty());
    }

    /// Why the bug cost everything rather than just the unreadable events.
    ///
    /// The spool drains oldest-first. A file that cannot be parsed must not be left in
    /// place: it would sit at the head of the queue and every later drain would return
    /// the same short batch, so the reporter stops as soon as that batch is empty and no
    /// event behind it is ever delivered — including across restarts, since the spool is
    /// durable on purpose.
    #[test]
    fn an_unparseable_file_does_not_block_the_queue() {
        let dir = scratch("poison");
        // Lexically first, so it is the oldest and drains first. The index is
        // rebuilt at startup, which is when a file left by a crash is found.
        fs::write(dir.join("0000-oldest__corrupt.json"), b"{ truncated").unwrap();
        let q = open(&dir, opts(100));
        q.push(allowed_event("good"));
        assert!(q.flush(FLUSH));

        let batch = q.drain_batch(10);

        assert_eq!(
            batch.events.len(),
            1,
            "the good event behind the corrupt one must still be delivered"
        );
        assert_eq!(batch.events[0].event_id, "good");
        assert!(
            !dir.join("0000-oldest__corrupt.json").exists(),
            "the corrupt file must be discarded, or it blocks the queue again next tick"
        );
    }

    /// A bad line inside a segment costs that event only.
    #[test]
    fn a_bad_line_in_a_segment_costs_only_that_event() {
        let dir = scratch("badline");
        let good = serde_json::to_string(&allowed_event("after")).unwrap();
        fs::write(
            dir.join(segment_name(7, 2, 0)),
            format!("{{ not json\n{good}\n"),
        )
        .unwrap();
        let q = open(&dir, opts(100));
        assert_eq!(drain_ids(&q, 10), vec!["after".to_string()]);
        assert!(q.files_on_disk().is_empty());
        assert_eq!(q.stats().spooled, 0);
    }

    /// ack is what makes delivery durable: the file disappears only after the API
    /// confirmed it, so a crash between POST and ack re-sends rather than loses.
    #[test]
    fn ack_removes_and_nack_keeps() {
        let dir = scratch("ackmack");
        let q = open(&dir, opts(100));
        q.push(allowed_event("a"));
        assert!(q.flush(FLUSH));

        let batch = q.drain_batch(10);
        assert_eq!(q.files_on_disk().len(), 1);

        q.nack(batch);
        assert_eq!(
            q.files_on_disk().len(),
            1,
            "nack must leave the event on disk to retry"
        );

        let batch = q.drain_batch(10);
        assert_eq!(batch.events.len(), 1, "a nacked event is offered again");
        q.ack(&batch);
        assert_eq!(
            q.files_on_disk().len(),
            0,
            "ack must remove the delivered event"
        );
    }

    /// The temp file used for the atomic write must never be picked up as an event.
    #[test]
    fn partial_writes_are_invisible_to_readers() {
        let dir = scratch("atomic");
        fs::write(dir.join(".something__x.json.tmp"), b"{ half written").unwrap();
        fs::write(dir.join(".seg-00000000000000000001-1.jsonl.tmp"), b"{ half").unwrap();
        let q = open(&dir, opts(100));
        q.push(allowed_event("z"));
        assert!(q.flush(FLUSH));

        let batch = q.drain_batch(10);
        assert_eq!(
            batch.events.len(),
            1,
            "a .tmp file in flight must not be read as a spooled event"
        );
        assert_eq!(batch.events[0].event_id, "z");
    }

    /// Memory mode never serializes, which is why it was unaffected and why the A/B
    /// against it isolated the bug to the disk path.
    #[test]
    fn memory_queue_round_trips_the_same_event() {
        let q = MemoryQueue::new(10);
        q.push(allowed_event("m"));
        let batch = q.drain_batch(10);
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].event_id, "m");
    }

    /// The spool holds query text, database users and client addresses: nobody
    /// but the proxy's user may read it.
    #[cfg(unix)]
    #[test]
    fn spool_dir_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = scratch("perms");
        let dir = parent.join("spool");
        let q = open(&dir, opts(100));
        q.push(allowed_event("p"));
        assert!(q.flush(FLUSH));

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "spool directory must be 0700");
        let files = q.files_on_disk();
        assert_eq!(files.len(), 1);
        let file_mode = fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "spool files must be 0600");
    }

    /// An existing directory open to others (a volume mounted 0755) is narrowed.
    #[cfg(unix)]
    #[test]
    fn an_existing_open_spool_dir_is_narrowed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("narrow");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _q = open(&dir, opts(100));
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// The capacity holds without listing the directory on every push, and
    /// across a restart, where the index is rebuilt from the spool.
    #[test]
    fn capacity_is_enforced_and_survives_a_restart() {
        let dir = scratch("cap");
        let small = || DiskOptions {
            capacity: 3,
            batch_max: 1,
            ..DiskOptions::default()
        };
        let q = open(&dir, small());
        for i in 0..5 {
            q.push(allowed_event(&format!("c{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().spooled, 3, "never more than capacity events");
        assert_eq!(q.stats().evicted_oldest, 2);
        assert_eq!(q.files_on_disk().len(), 3);
        drop(q);

        let q = open(&dir, small());
        assert_eq!(q.stats().spooled, 3, "the index is rebuilt from the spool");
        q.push(allowed_event("after-restart"));
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().spooled, 3, "the bound holds after a restart");
        assert_eq!(
            drain_ids(&q, 10),
            vec!["c3", "c4", "after-restart"],
            "the oldest went, order is kept"
        );
        assert_eq!(q.stats().spooled, 0, "ack keeps the count in step");
        assert!(q.files_on_disk().is_empty());
    }

    // ─── 4.9.1: the asynchronous pipeline ───────────────────────────────────

    /// The defect this release fixes: with a slow spool (EFS), `push` used to do
    /// three round trips to the filesystem on the query path. Now a writer that
    /// takes 300 ms per segment must not slow `push` down at all.
    #[test]
    fn push_does_not_wait_on_a_slow_disk() {
        let dir = scratch("slow");
        let q = open(
            &dir,
            DiskOptions {
                capacity: 10_000,
                queue_capacity: 2_000,
                write_delay: Duration::from_millis(300),
                ..DiskOptions::default()
            },
        );
        let started = Instant::now();
        let mut slowest = Duration::ZERO;
        for i in 0..1_000 {
            let t = Instant::now();
            q.push(allowed_event(&format!("s{i}")));
            slowest = slowest.max(t.elapsed());
        }
        let total = started.elapsed();
        assert!(
            total < Duration::from_millis(250),
            "1,000 pushes took {total:?} with a 300 ms disk: push is waiting on the writer"
        );
        assert!(
            slowest < Duration::from_millis(50),
            "slowest push {slowest:?}"
        );
        assert_eq!(q.stats().dropped_queue_full, 0);
        assert!(q.flush(Duration::from_secs(30)));
        assert_eq!(
            q.stats().spooled,
            1_000,
            "every event still reaches the disk"
        );
    }

    /// Events are written in batches: one segment (one write and fsync) per
    /// `batch_max` events, not one file per event.
    #[test]
    fn events_are_written_in_batches() {
        let dir = scratch("batch");
        let q = open(
            &dir,
            DiskOptions {
                batch_max: 100,
                flush_every: Duration::from_secs(5),
                ..DiskOptions::default()
            },
        );
        for i in 0..250 {
            q.push(allowed_event(&format!("b{i}")));
        }
        assert!(q.flush(FLUSH));
        let files = q.files_on_disk();
        let counts: Vec<usize> = files
            .iter()
            .map(|p| {
                parse_segment_name(&p.file_name().unwrap().to_string_lossy())
                    .unwrap()
                    .1
            })
            .collect();
        assert_eq!(
            counts,
            vec![100, 100, 50],
            "segments by count, then the flush"
        );
        assert_eq!(q.stats().batches_written, 3);
        assert_eq!(q.stats().spooled, 250);

        // Delivery batches line up with segments, in order.
        let first = drain_ids(&q, 100);
        assert_eq!(first.len(), 100);
        assert_eq!(first[0], "b0");
        assert_eq!(q.files_on_disk().len(), 2, "a delivered segment is removed");
    }

    /// A segment is also written when the interval elapses, without a flush.
    #[test]
    fn a_partial_batch_is_written_after_the_interval() {
        let dir = scratch("interval");
        let q = open(
            &dir,
            DiskOptions {
                flush_every: Duration::from_millis(20),
                ..DiskOptions::default()
            },
        );
        q.push(allowed_event("lone"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while q.stats().spooled == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(q.stats().spooled, 1);
    }

    /// A delivery batch smaller than a segment: the segment stays until all of it
    /// is delivered, and the remainder is offered next.
    #[test]
    fn a_segment_can_be_delivered_in_parts() {
        let dir = scratch("parts");
        let q = open(&dir, opts(100));
        for i in 0..5 {
            q.push(allowed_event(&format!("p{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(drain_ids(&q, 2), vec!["p0", "p1"]);
        assert_eq!(q.files_on_disk().len(), 1);
        assert_eq!(q.stats().spooled, 3);
        assert_eq!(drain_ids(&q, 10), vec!["p2", "p3", "p4"]);
        assert!(q.files_on_disk().is_empty());
    }

    /// Restart: the index is rebuilt from one listing, legacy one-event files
    /// written by 4.9.0 and earlier drain first, sequence numbers continue, and
    /// a partly delivered segment is sent again whole (at-least-once).
    #[test]
    fn restart_rebuilds_the_index_from_legacy_files_and_segments() {
        let dir = scratch("restart");
        // As 4.9.0 named them.
        for id in ["old1", "old2"] {
            let ev = allowed_event(id);
            let name = format!(
                "{}__{}.json",
                ev.occurred_at.replace([':', '.'], "-"),
                ev.event_id
            );
            fs::write(dir.join(name), serde_json::to_vec(&ev).unwrap()).unwrap();
        }
        let q = open(&dir, opts(100));
        for i in 0..3 {
            q.push(allowed_event(&format!("n{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().spooled, 5);
        assert_eq!(drain_ids(&q, 3), vec!["old1", "old2", "n0"]);
        drop(q);

        let q = open(&dir, opts(100));
        assert_eq!(
            q.stats().spooled,
            3,
            "n0..n2: the partial ack was not persisted"
        );
        q.push(allowed_event("n3"));
        assert!(q.flush(FLUSH));
        let names: Vec<String> = q
            .files_on_disk()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let seqs: Vec<u64> = names
            .iter()
            .map(|n| parse_segment_name(n).unwrap().0)
            .collect();
        assert_eq!(seqs.len(), 2);
        assert!(
            seqs[1] > seqs[0],
            "sequence numbers continue after a restart"
        );
        assert_eq!(drain_ids(&q, 10), vec!["n0", "n1", "n2", "n3"]);
    }

    /// Backpressure: when the channel to a stalled writer is full, `push` drops
    /// the event, counts it, and returns at once.
    #[test]
    fn a_full_queue_drops_and_counts() {
        let dir = scratch("full");
        let q = open(
            &dir,
            DiskOptions {
                queue_capacity: 4,
                batch_max: 1,
                write_delay: Duration::from_millis(500),
                ..DiskOptions::default()
            },
        );
        let started = Instant::now();
        for i in 0..100 {
            q.push(allowed_event(&format!("f{i}")));
        }
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "push never waits"
        );
        let s = q.stats();
        assert!(
            s.dropped_queue_full >= 90,
            "dropped {}",
            s.dropped_queue_full
        );
        assert_eq!(s.enqueued + s.dropped_queue_full, 100);
        assert!(q.flush(Duration::from_secs(30)));
        assert_eq!(
            q.stats().spooled as u64,
            s.enqueued,
            "what was accepted is kept"
        );
    }

    /// Shutdown: `flush` persists everything accepted before it, so a new process
    /// on the same spool finds it.
    #[test]
    fn flush_persists_everything_accepted_before_it() {
        let dir = scratch("shutdown");
        let q = open(
            &dir,
            DiskOptions {
                flush_every: Duration::from_secs(60),
                ..DiskOptions::default()
            },
        );
        for i in 0..42 {
            q.push(allowed_event(&format!("x{i}")));
        }
        assert!(q.flush(FLUSH), "flush must finish within its deadline");
        assert_eq!(q.stats().queue_depth, 0);
        // Simulate the process ending without dropping the queue.
        std::mem::forget(q);

        let q = open(&dir, opts(100));
        assert_eq!(q.stats().spooled, 42);
    }

    /// `flush` honours its deadline when the disk does not answer in time.
    #[test]
    fn flush_gives_up_at_its_deadline() {
        let dir = scratch("deadline");
        let q = open(
            &dir,
            DiskOptions {
                write_delay: Duration::from_millis(1_500),
                ..DiskOptions::default()
            },
        );
        q.push(allowed_event("slow"));
        let started = Instant::now();
        assert!(!q.flush(Duration::from_millis(100)));
        assert!(started.elapsed() < Duration::from_millis(1_000));
    }

    /// Memory mode: a full ring drops the oldest and counts it, still without
    /// waiting.
    /// The delivery lag reads the oldest buffered event in constant time: the
    /// head segment's write time (its mtime after a restart), the ring's front.
    #[test]
    fn the_oldest_buffered_event_is_known_without_a_scan() {
        let dir = scratch("oldest");
        let before = SystemTime::now() - Duration::from_secs(1);
        {
            let q = open(&dir, opts(100));
            assert_eq!(q.oldest_buffered_at(), None);
            q.push(allowed_event("a"));
            assert!(q.flush(FLUSH));
            assert!(q.oldest_buffered_at().unwrap() >= before);
            let batch = q.drain_batch(10);
            assert!(
                q.oldest_buffered_at().is_some(),
                "a batch in flight is still undelivered"
            );
            q.ack(&batch);
            assert_eq!(q.oldest_buffered_at(), None);
            q.push(allowed_event("b"));
            assert!(q.flush(FLUSH));
        }
        let q = open(&dir, opts(100));
        let at = q.oldest_buffered_at().unwrap();
        assert!(
            at >= before && at <= SystemTime::now(),
            "from the file's mtime"
        );

        let m = MemoryQueue::new(10);
        assert_eq!(m.oldest_buffered_at(), None);
        m.push(allowed_event("m"));
        assert_eq!(
            m.oldest_buffered_at(),
            Some(event_time(&allowed_event("m").occurred_at))
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn memory_queue_counts_what_it_evicts() {
        let q = MemoryQueue::new(3);
        for i in 0..10 {
            q.push(allowed_event(&format!("m{i}")));
        }
        let s = q.stats();
        assert_eq!(s.queue_depth, 3);
        assert_eq!(s.enqueued, 10);
        assert_eq!(s.evicted_oldest, 7);
        assert_eq!(drain_ids(&q, 10), vec!["m7", "m8", "m9"]);
    }

    // ─── 4.11.0: several batches in flight ──────────────────────────────────

    fn ids(batch: &Batch) -> Vec<String> {
        batch.events.iter().map(|e| e.event_id.clone()).collect()
    }

    /// Batches drained while others are in flight never share an event, acks may
    /// arrive in any order, and an event leaves the disk only when the batch that
    /// carried it is acked.
    #[test]
    fn concurrent_batches_are_disjoint_and_acked_in_any_order() {
        let dir = scratch("lease");
        let q = open(
            &dir,
            DiskOptions {
                batch_max: 6,
                ..opts(100)
            },
        );
        for i in 0..10 {
            q.push(allowed_event(&format!("l{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(q.files_on_disk().len(), 2, "segments of 6 and 4");

        let a = q.drain_batch(4); // l0..l3, first segment
        let b = q.drain_batch(4); // l4, l5 (rest of the first), l6, l7
        let c = q.drain_batch(4); // l8, l9
        assert_eq!(ids(&a), vec!["l0", "l1", "l2", "l3"]);
        assert_eq!(ids(&b), vec!["l4", "l5", "l6", "l7"]);
        assert_eq!(ids(&c), vec!["l8", "l9"]);
        assert!(
            q.drain_batch(4).events.is_empty(),
            "everything is in flight"
        );
        assert_eq!(q.available(), 0);
        assert_eq!(q.stats().spooled, 10, "nothing delivered yet");

        // The later batches answer first.
        q.ack(&c);
        q.ack(&b);
        assert_eq!(q.stats().spooled, 4, "only a's events are left");
        assert_eq!(
            q.files_on_disk().len(),
            1,
            "the second segment is done; the first still holds a"
        );

        q.ack(&a);
        assert_eq!(q.stats().spooled, 0);
        assert!(q.files_on_disk().is_empty());
    }

    /// A failed batch in the middle is offered again, alone, while the batches
    /// around it stay in flight; nothing is lost and nothing is sent twice.
    #[test]
    fn a_nacked_batch_is_offered_again_without_its_neighbours() {
        let dir = scratch("nack-middle");
        let q = open(&dir, opts(100));
        for i in 0..9 {
            q.push(allowed_event(&format!("n{i}")));
        }
        assert!(q.flush(FLUSH));
        let a = q.drain_batch(3);
        let b = q.drain_batch(3);
        let c = q.drain_batch(3);
        q.nack(b);
        assert_eq!(q.available(), 3);
        let again = q.drain_batch(10);
        assert_eq!(ids(&again), vec!["n3", "n4", "n5"]);
        q.ack(&c);
        q.ack(&again);
        assert_eq!(q.stats().spooled, 3);
        assert_eq!(q.files_on_disk().len(), 1, "a is still in flight");
        q.ack(&a);
        assert!(q.files_on_disk().is_empty());
        assert_eq!(q.stats().spooled, 0);
    }

    /// In-flight state is in memory: after a restart, whatever was not acked is
    /// sent again (at-least-once), including what was acked out of order.
    #[test]
    fn a_restart_resends_what_was_not_acked() {
        let dir = scratch("lease-restart");
        let q = open(&dir, opts(100));
        for i in 0..6 {
            q.push(allowed_event(&format!("r{i}")));
        }
        assert!(q.flush(FLUSH));
        let _a = q.drain_batch(3);
        let b = q.drain_batch(3);
        q.ack(&b); // acked out of order; the segment stays for a
        drop(q);

        let q = open(&dir, opts(100));
        assert_eq!(q.stats().spooled, 6);
        assert_eq!(drain_ids(&q, 10), vec!["r0", "r1", "r2", "r3", "r4", "r5"]);
        assert!(q.files_on_disk().is_empty());
    }

    /// Eviction may take a segment that a batch in flight holds; its ack is then a
    /// no-op and the counters stay right.
    #[test]
    fn eviction_of_a_segment_in_flight_keeps_the_counters_right() {
        let dir = scratch("lease-evict");
        let q = open(
            &dir,
            DiskOptions {
                batch_max: 2,
                ..opts(4)
            },
        );
        for i in 0..4 {
            q.push(allowed_event(&format!("e{i}")));
        }
        assert!(q.flush(FLUSH));
        let a = q.drain_batch(2); // e0, e1 (oldest segment)
        for i in 4..6 {
            q.push(allowed_event(&format!("e{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().evicted_oldest, 2, "the oldest segment went");
        q.ack(&a);
        assert_eq!(q.stats().spooled, 4);
        assert_eq!(drain_ids(&q, 10), vec!["e2", "e3", "e4", "e5"]);
        assert_eq!(q.stats().spooled, 0);
    }

    #[test]
    fn memory_queue_batches_are_disjoint_and_nack_rebuffers() {
        let q = MemoryQueue::new(10);
        for i in 0..6 {
            q.push(allowed_event(&format!("m{i}")));
        }
        let a = q.drain_batch(3);
        let b = q.drain_batch(3);
        assert_eq!(ids(&a), vec!["m0", "m1", "m2"]);
        assert_eq!(ids(&b), vec!["m3", "m4", "m5"]);
        assert_eq!(q.available(), 0);
        q.nack(a);
        assert_eq!(q.available(), 3);
        assert_eq!(drain_ids(&q, 10), vec!["m0", "m1", "m2"]);
    }

    // ─── 4.12.0: bounded by bytes ───────────────────────────────────────────

    /// One spool line of `allowed_event(id)`, as the writer lays it out.
    fn line_bytes(id: &str) -> u64 {
        serde_json::to_vec(&allowed_event(id)).unwrap().len() as u64 + 1
    }

    /// The byte bound evicts the oldest segments, keeps the newest, and counts
    /// what it evicted; with no event bound, the count alone never evicts.
    #[test]
    fn the_spool_is_bounded_by_bytes() {
        let dir = scratch("bytes");
        let per_segment = line_bytes("b0");
        let opts = || DiskOptions {
            capacity: usize::MAX,
            max_bytes: per_segment * 3,
            batch_max: 1,
            ..DiskOptions::default()
        };
        let q = open(&dir, opts());
        for i in 0..5 {
            q.push(allowed_event(&format!("b{i}")));
        }
        assert!(q.flush(FLUSH));
        let stats = q.stats();
        assert_eq!(stats.spooled, 3);
        assert_eq!(stats.spool_bytes, per_segment * 3);
        assert_eq!(stats.evicted_oldest, 2);
        let on_disk: u64 = q
            .files_on_disk()
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum();
        assert_eq!(on_disk, stats.spool_bytes, "the index matches the disk");
        drop(q);

        // After a restart the sizes come from the names, and the bound still holds.
        let q = open(&dir, opts());
        assert_eq!(q.stats().spool_bytes, per_segment * 3);
        q.push(allowed_event("b5"));
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().spool_bytes, per_segment * 3);
        assert_eq!(drain_ids(&q, 10), vec!["b3", "b4", "b5"]);
        let stats = q.stats();
        assert_eq!(
            (stats.spooled, stats.spool_bytes),
            (0, 0),
            "ack frees the bytes"
        );
        assert!(q.files_on_disk().is_empty());
    }

    /// A segment named by 4.9.1–4.11 (no size in its name) and a legacy file are
    /// measured at startup and count against the byte bound like any other.
    #[test]
    fn files_written_before_4_12_count_against_the_byte_bound() {
        let dir = scratch("bytes-upgrade");
        let line = serde_json::to_vec(&allowed_event("old-seg")).unwrap();
        let mut body = line.clone();
        body.push(b'\n');
        fs::write(dir.join("seg-00000000000000000003-1.jsonl"), &body).unwrap();
        let legacy = serde_json::to_vec(&allowed_event("legacy")).unwrap();
        fs::write(dir.join("2026-10-01T00-00-00__legacy.json"), &legacy).unwrap();

        let q = open(
            &dir,
            DiskOptions {
                capacity: usize::MAX,
                max_bytes: 1 << 20,
                ..DiskOptions::default()
            },
        );
        assert_eq!(q.stats().spooled, 2);
        assert_eq!(q.stats().spool_bytes, (body.len() + legacy.len()) as u64);
        q.push(allowed_event("new"));
        assert!(q.flush(FLUSH));
        assert_eq!(drain_ids(&q, 10), vec!["legacy", "old-seg", "new"]);
        assert_eq!(q.stats().spool_bytes, 0);
    }

    /// A segment larger than the whole bound is still written (into an empty
    /// spool) rather than lost on arrival.
    #[test]
    fn a_segment_larger_than_the_bound_replaces_everything_before_it() {
        let dir = scratch("bytes-big");
        let q = open(
            &dir,
            DiskOptions {
                capacity: usize::MAX,
                max_bytes: 10,
                batch_max: 1,
                ..DiskOptions::default()
            },
        );
        q.push(allowed_event("x0"));
        q.push(allowed_event("x1"));
        assert!(q.flush(FLUSH));
        assert_eq!(q.stats().spooled, 1);
        assert_eq!(q.stats().evicted_oldest, 1);
        assert_eq!(drain_ids(&q, 10), vec!["x1"]);
    }

    /// At low traffic every segment holds one event; the file bound keeps the
    /// index and the startup listing bounded then.
    #[test]
    fn the_number_of_segment_files_is_bounded() {
        let dir = scratch("segments");
        let q = open(
            &dir,
            DiskOptions {
                capacity: usize::MAX,
                max_bytes: 1 << 30,
                max_segments: 2,
                batch_max: 1,
                ..DiskOptions::default()
            },
        );
        for i in 0..4 {
            q.push(allowed_event(&format!("s{i}")));
        }
        assert!(q.flush(FLUSH));
        assert_eq!(q.files_on_disk().len(), 2);
        assert_eq!(q.stats().evicted_oldest, 2);
        assert_eq!(drain_ids(&q, 10), vec!["s2", "s3"]);
    }

    /// The default disk spool has no event bound: 4.11's 10,000 no longer caps it.
    #[test]
    fn the_default_disk_spool_is_not_bounded_by_10000_events() {
        let o = DiskOptions::default();
        assert_eq!(o.capacity, usize::MAX);
        assert_eq!(o.max_bytes, DEFAULT_SPOOL_MAX_BYTES);
        assert_eq!(o.max_segments, MAX_SPOOL_SEGMENTS);
    }

    #[test]
    fn warnings_are_rate_limited() {
        let w = WarnLimiter::new();
        assert!(w.allow());
        assert!(!w.allow());
        assert!(!w.allow());
    }

    #[test]
    fn segment_names_round_trip_and_sort_by_sequence() {
        assert_eq!(
            parse_segment_name(&segment_name(42, 100, 51_200)),
            Some((42, 100, Some(51_200)))
        );
        // As 4.9.1–4.11 named them: no size.
        assert_eq!(
            parse_segment_name("seg-00000000000000000042-100.jsonl"),
            Some((42, 100, None))
        );
        assert_eq!(parse_segment_name("seg-1-2-3-4.jsonl"), None);
        assert!(segment_name(9, 1, 900) < segment_name(10, 1, 10));
        assert_eq!(parse_segment_name("2026-10-01T03-52-50__e1.json"), None);
    }
}
