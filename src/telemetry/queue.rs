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

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::config::{BufferMode, ControlPlaneConfig};
use crate::telemetry::TelemetryEvent;

/// Shortest interval between two "events dropped" warnings of one queue. The
/// counters keep the exact figures; the warning only says that it is happening.
pub const DROP_WARN_EVERY: Duration = Duration::from_secs(10);

/// How often the disk writer looks at its channel while it collects a batch.
const WRITER_POLL: Duration = Duration::from_millis(5);

/// A batch drained for delivery, with an opaque handle to ack/remove it.
pub struct Batch {
    pub events: Vec<TelemetryEvent>,
    /// Disk spool segments backing this batch (empty for memory mode).
    spans: Vec<Span>,
}

/// The part of one spool segment a batch carries: its lines up to `end`.
#[derive(Debug, Clone, Copy)]
struct Span {
    id: u64,
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
    /// Events accepted by `push`.
    pub enqueued: u64,
    /// Events refused by `push` because the channel to the disk writer was full.
    pub dropped_queue_full: u64,
    /// Oldest events discarded to stay within the buffer's capacity.
    pub evicted_oldest: u64,
    /// Events lost because their segment could not be written.
    pub write_failures: u64,
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
    /// Take up to `max` events for delivery.
    fn drain_batch(&self, max: usize) -> Batch;
    /// Confirm a batch was delivered (removes it durably for disk mode).
    fn ack(&self, batch: &Batch);
    /// Return events to the queue when delivery failed (memory mode re-buffers;
    /// disk mode leaves the segments in place so they retry next cycle).
    fn nack(&self, batch: Batch);
    /// Current counters.
    fn stats(&self) -> QueueStats;
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
                cfg.memory_capacity,
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
struct WarnLimiter {
    /// Milliseconds since `epoch()` of the last warning, plus one; 0 = never.
    last: AtomicU64,
}

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

impl WarnLimiter {
    const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
        }
    }

    fn allow(&self) -> bool {
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
    pub capacity: usize,
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
        queue_capacity: usize,
        batch_max: usize,
        flush_every: Duration,
    ) -> Self {
        Self {
            capacity,
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
            10_000,
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
    queue_capacity: usize,
    index: Mutex<SpoolIndex>,
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
    /// Leading events already delivered (acked). In memory only: after a
    /// restart a partly delivered segment is sent again from its start, which is
    /// what at-least-once allows.
    delivered: usize,
}

impl Segment {
    fn remaining(&self) -> usize {
        self.count.saturating_sub(self.delivered)
    }
}

const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".jsonl";

fn segment_name(seq: u64, count: usize) -> String {
    format!("{SEGMENT_PREFIX}{seq:020}-{count}{SEGMENT_SUFFIX}")
}

/// `(seq, count)` from a segment file name.
fn parse_segment_name(name: &str) -> Option<(u64, usize)> {
    let core = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    let (seq, count) = core.split_once('-')?;
    Some((seq.parse().ok()?, count.parse().ok()?))
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
            queue_capacity: opts.queue_capacity.max(1),
            index: Mutex::new(index),
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
        shared.evict_to_fit(0);
        {
            let index = shared.index.lock().unwrap();
            tracing::info!(
                dir = %shared.dir.display(),
                segments = index.segments.len(),
                legacy_files = legacy,
                events = index.events,
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

/// Lists the spool once and returns its index and how many legacy files it has.
/// Legacy `*.json` files (one event each, named by timestamp) come first in name
/// order, then segments in sequence order. Hidden files (temporaries, the rules
/// cache) and anything else are left alone.
fn rebuild_index(dir: &Path) -> std::io::Result<(SpoolIndex, usize)> {
    let mut legacy: Vec<PathBuf> = Vec::new();
    let mut segments: Vec<(u64, usize, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if let Some((seq, count)) = parse_segment_name(name) {
            segments.push((seq, count, path));
        } else if name.ends_with(".json") {
            legacy.push(path);
        }
    }
    legacy.sort(); // lexical = chronological (timestamped names)
    segments.sort_by_key(|(seq, _, _)| *seq);

    let mut index = SpoolIndex {
        next_seq: segments.last().map(|(seq, _, _)| seq + 1).unwrap_or(1),
        ..SpoolIndex::default()
    };
    let legacy_files = legacy.len();
    for path in legacy {
        index.add(path, 1);
    }
    for (_, count, path) in segments {
        index.add(path, count);
    }
    Ok((index, legacy_files))
}

impl SpoolIndex {
    fn add(&mut self, path: PathBuf, count: usize) {
        let id = self.next_id;
        self.next_id += 1;
        self.events += count;
        self.segments.push_back(Segment {
            id,
            path,
            count,
            delivered: 0,
        });
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
        let name = segment_name(seq, count);
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

        self.evict_to_fit(count);
        self.index.lock().unwrap().add(path, count);
        self.pending.fetch_sub(accepted, Ordering::Relaxed);

        let us = started.elapsed().as_micros() as u64;
        self.batches_written.fetch_add(1, Ordering::Relaxed);
        self.last_batch_write_us.store(us, Ordering::Relaxed);
        self.max_batch_write_us.fetch_max(us, Ordering::Relaxed);
    }

    /// Drops the oldest segments until `incoming` more events fit the capacity.
    /// Files are removed outside the index lock.
    fn evict_to_fit(&self, incoming: usize) {
        let mut doomed = Vec::new();
        let mut evicted = 0usize;
        {
            let mut index = self.index.lock().unwrap();
            while index.events + incoming > self.capacity {
                let Some(seg) = index.segments.pop_front() else {
                    break;
                };
                let remaining = seg.remaining();
                index.events = index.events.saturating_sub(remaining);
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
                    capacity = self.capacity,
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
        loop {
            // Snapshot the head of the index; files are read without the lock.
            let heads: Vec<(u64, PathBuf, usize, usize)> = {
                let index = self.shared.index.lock().unwrap();
                let mut covered = 0;
                let mut heads = Vec::new();
                for seg in &index.segments {
                    if covered >= max {
                        break;
                    }
                    covered += seg.remaining();
                    heads.push((seg.id, seg.path.clone(), seg.delivered, seg.count));
                }
                heads
            };
            let mut batch = Batch {
                events: Vec::new(),
                spans: Vec::new(),
            };
            for (id, path, delivered, count) in heads {
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
                let mut line_no = 0;
                let mut full = false;
                let valid_before = batch.events.len();
                for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    if line_no < delivered {
                        line_no += 1;
                        continue;
                    }
                    if batch.events.len() >= max {
                        full = true;
                        break;
                    }
                    match serde_json::from_slice::<TelemetryEvent>(line) {
                        Ok(ev) => batch.events.push(ev),
                        // A line that does not parse is discarded with the batch's
                        // ack, like an unreadable file, and for the same reason.
                        Err(e) => {
                            tracing::error!(file = %path.display(), line = line_no + 1, error = %e, "Telemetry spool event failed to deserialize; discarding so the queue can advance")
                        }
                    }
                    line_no += 1;
                }
                if !full && batch.events.len() == valid_before {
                    // Nothing left in it that can be delivered: gone now, not at
                    // the next ack, so it cannot sit at the head of the queue.
                    self.shared.discard(id);
                    continue;
                }
                // Read to the end: the ack retires the whole segment, even if it
                // held fewer lines than its name says.
                let end = if full { line_no } else { line_no.max(count) };
                batch.spans.push(Span { id, end });
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
                seg.delivered = seg.delivered.max(span.end);
                let after = seg.remaining();
                let complete = after == 0;
                index.events = index.events.saturating_sub(before - after);
                if complete {
                    if let Some(seg) = index.segments.remove(pos) {
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

    fn nack(&self, _batch: Batch) {
        // Leave segments in place; they retry on the next flush cycle.
    }

    fn stats(&self) -> QueueStats {
        let s = &self.shared;
        QueueStats {
            queue_depth: s.pending.load(Ordering::Relaxed),
            spooled: s.index.lock().unwrap().events,
            enqueued: s.enqueued.load(Ordering::Relaxed),
            dropped_queue_full: s.dropped_queue_full.load(Ordering::Relaxed),
            evicted_oldest: s.evicted_oldest.load(Ordering::Relaxed),
            write_failures: s.write_failures.load(Ordering::Relaxed),
            batches_written: s.batches_written.load(Ordering::Relaxed),
            last_batch_write_us: s.last_batch_write_us.load(Ordering::Relaxed),
            max_batch_write_us: s.max_batch_write_us.load(Ordering::Relaxed),
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
            dir.join(segment_name(7, 2)),
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

    #[test]
    fn warnings_are_rate_limited() {
        let w = WarnLimiter::new();
        assert!(w.allow());
        assert!(!w.allow());
        assert!(!w.allow());
    }

    #[test]
    fn segment_names_round_trip_and_sort_by_sequence() {
        assert_eq!(parse_segment_name(&segment_name(42, 100)), Some((42, 100)));
        assert!(segment_name(9, 1) < segment_name(10, 1));
        assert_eq!(parse_segment_name("2026-10-01T03-52-50__e1.json"), None);
    }
}
