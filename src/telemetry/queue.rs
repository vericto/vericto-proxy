//! Event queue abstraction with two implementations selected by config:
//!   - MemoryQueue: bounded in-memory ring buffer (default).
//!   - DiskQueue: append-to-disk spool that survives restarts; entries are
//!     removed only after the API acknowledges delivery (at-least-once).
//!
//! Both are bounded: when full, the oldest events are dropped and the drop is
//! logged. Neither ever blocks the caller.

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::config::{BufferMode, ControlPlaneConfig};
use crate::telemetry::TelemetryEvent;

/// A batch drained for delivery, with an opaque handle to ack/remove it.
pub struct Batch {
    pub events: Vec<TelemetryEvent>,
    /// Disk spool file names backing this batch (empty for memory mode).
    files: Vec<PathBuf>,
}

pub trait EventQueue: Send + Sync {
    /// Enqueue an event. Never blocks; drops oldest when full.
    fn push(&self, event: TelemetryEvent);
    /// Take up to `max` events for delivery.
    fn drain_batch(&self, max: usize) -> Batch;
    /// Confirm a batch was delivered (removes it durably for disk mode).
    fn ack(&self, batch: &Batch);
    /// Return events to the queue when delivery failed (memory mode re-buffers;
    /// disk mode leaves the files in place so they retry next cycle).
    fn nack(&self, batch: Batch);
}

pub fn new_queue(cfg: &ControlPlaneConfig) -> Box<dyn EventQueue> {
    match cfg.buffer_mode {
        BufferMode::Memory => Box::new(MemoryQueue::new(cfg.memory_capacity)),
        BufferMode::Disk => {
            match DiskQueue::new(cfg.disk_spool_path.clone(), cfg.memory_capacity) {
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

// ─── In-memory ───────────────────────────────────────────────────────────────

pub struct MemoryQueue {
    capacity: usize,
    inner: Mutex<VecDeque<TelemetryEvent>>,
}

impl MemoryQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
        }
    }
}

impl EventQueue for MemoryQueue {
    fn push(&self, event: TelemetryEvent) {
        let mut q = self.inner.lock().unwrap();
        if q.len() >= self.capacity {
            q.pop_front();
            tracing::warn!("Telemetry memory buffer full — dropped oldest event");
        }
        q.push_back(event);
    }

    fn drain_batch(&self, max: usize) -> Batch {
        let mut q = self.inner.lock().unwrap();
        let take = q.len().min(max);
        let events = q.drain(..take).collect();
        Batch {
            events,
            files: Vec::new(),
        }
    }

    fn ack(&self, _batch: &Batch) {
        // Memory mode: already removed by drain_batch.
    }

    fn nack(&self, batch: Batch) {
        // Re-buffer at the front so order is roughly preserved; respect capacity.
        let mut q = self.inner.lock().unwrap();
        for event in batch.events.into_iter().rev() {
            if q.len() >= self.capacity {
                break; // drop rather than exceed the bound
            }
            q.push_front(event);
        }
    }
}

// ─── On-disk spool ─────────────────────────────────────────────────────────

/// One file per event under the spool dir. Simple and crash-safe: a file exists
/// iff the event is undelivered. Bounded by `capacity` files.
///
/// An event holds the query text (raw unless the workspace chose sanitized
/// reporting), the database user and the client address, so the spool is
/// private to the proxy's user: the directory is `0700` and every file `0600`,
/// as the rules cache already is (src/tcp/rules_cache.rs).
pub struct DiskQueue {
    dir: PathBuf,
    capacity: usize,
    /// Files currently in the spool, as far as this process knows. Kept so that
    /// `push`, which runs on the query path, does not list the directory on every
    /// event; the directory is listed only when this reaches `capacity`, and the
    /// count is resynchronised from that listing.
    count: Mutex<usize>,
}

impl DiskQueue {
    pub fn new(dir: String, capacity: usize) -> std::io::Result<Self> {
        let dir = PathBuf::from(dir);
        create_private_dir(&dir)?;
        let queue = Self {
            dir,
            capacity,
            count: Mutex::new(0),
        };
        *queue.count.lock().unwrap() = queue.spool_files().len();
        Ok(queue)
    }

    fn spool_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort(); // lexical = chronological (timestamped names)
        files
    }
}

impl EventQueue for DiskQueue {
    fn push(&self, event: TelemetryEvent) {
        // Make room and reserve a slot under the lock; the write itself happens
        // outside it, so concurrent sessions do not queue behind each other's I/O.
        {
            let mut count = self.count.lock().unwrap();
            if *count >= self.capacity {
                let files = self.spool_files();
                *count = files.len();
                if files.len() >= self.capacity {
                    if let Some(oldest) = files.first() {
                        if fs::remove_file(oldest).is_ok() {
                            *count -= 1;
                        }
                        tracing::warn!("Telemetry disk spool full — dropped oldest event");
                    }
                }
            }
            *count += 1;
        }
        // Name: <occurred_at-ish ordering via event_id is not monotonic>, so use
        // a high-resolution-ish prefix from the event's occurred_at + event_id.
        let name = format!(
            "{}__{}.json",
            event.occurred_at.replace([':', '.'], "-"),
            event.event_id
        );
        let path = self.dir.join(&name);
        match serde_json::to_vec(&event) {
            Ok(bytes) => {
                // Write to a temporary name and rename into place. `rename` within one
                // directory is atomic, so a reader never observes a partially written
                // file. Creating the final name directly and writing into it leaves a
                // truncated file if the task dies mid-write — and a truncated file is
                // invalid JSON, which is exactly the condition that used to wedge the
                // whole queue. Cheap insurance against reintroducing that by a different
                // route than the serde bug.
                let tmp = self.dir.join(format!(".{name}.tmp"));
                let wrote = create_private_file(&tmp)
                    .and_then(|mut f| f.write_all(&bytes))
                    .and_then(|()| fs::rename(&tmp, &path));
                if let Err(e) = wrote {
                    tracing::warn!(error = %e, "Failed to write telemetry event to spool");
                    let _ = fs::remove_file(&tmp);
                    self.release_slot();
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize telemetry event for spool");
                self.release_slot();
            }
        }
    }

    fn drain_batch(&self, max: usize) -> Batch {
        let files = self.spool_files();
        let mut events = Vec::new();
        let mut taken = Vec::new();
        for path in files.into_iter().take(max) {
            // An unreadable file must NOT be left where it is. The spool is drained
            // oldest-first, so silently skipping one parks it at the head of the queue
            // permanently: every later tick re-reads it, produces a short or empty batch,
            // and the reporter stops when the batch comes back empty. One bad file
            // therefore blocks every good event behind it, forever, and survives a
            // restart because the spool is durable by design. That is what happened on
            // staging — the `violations` round-trip bug made 283 files unreadable and
            // telemetry went quiet for nine hours with nothing logged.
            //
            // So: report it once, and discard it. Discarding loses one event, which is
            // strictly better than losing every event that follows it, and the log says
            // which file, so the loss is auditable.
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "Telemetry spool file unreadable; discarding so the queue can advance");
                    self.remove(&path);
                    continue;
                }
            };
            match serde_json::from_slice::<TelemetryEvent>(&bytes) {
                Ok(ev) => {
                    events.push(ev);
                    taken.push(path);
                }
                Err(e) => {
                    tracing::error!(file = %path.display(), error = %e, "Telemetry spool file failed to deserialize; discarding so the queue can advance");
                    self.remove(&path);
                }
            }
        }
        Batch {
            events,
            files: taken,
        }
    }

    fn ack(&self, batch: &Batch) {
        // Delivered: remove the spool files durably.
        for path in &batch.files {
            self.remove(path);
        }
    }

    fn nack(&self, _batch: Batch) {
        // Leave files in place; they retry on the next flush cycle.
    }
}

impl DiskQueue {
    /// Removes one spool file and keeps `count` in step.
    fn remove(&self, path: &std::path::Path) {
        if fs::remove_file(path).is_ok() {
            self.release_slot();
        }
    }

    fn release_slot(&self) {
        let mut count = self.count.lock().unwrap();
        *count = count.saturating_sub(1);
    }
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
        use std::sync::atomic::{AtomicUsize, Ordering};
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
        let q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();

        q.push(allowed_event("e1"));
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
        let q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();

        // Lexically first, so it is the oldest and drains first.
        fs::write(dir.join("0000-oldest__corrupt.json"), b"{ truncated").unwrap();
        q.push(allowed_event("good"));

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

    /// ack is what makes delivery durable: the file disappears only after the API
    /// confirmed it, so a crash between POST and ack re-sends rather than loses.
    #[test]
    fn ack_removes_and_nack_keeps() {
        let dir = scratch("ackmack");
        let q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();
        q.push(allowed_event("a"));

        let batch = q.drain_batch(10);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        q.nack(batch);
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "nack must leave the event on disk to retry"
        );

        let batch = q.drain_batch(10);
        q.ack(&batch);
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            0,
            "ack must remove the delivered event"
        );
    }

    /// The temp file used for the atomic write must never be picked up as an event.
    #[test]
    fn partial_writes_are_invisible_to_readers() {
        let dir = scratch("atomic");
        let q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();
        fs::write(dir.join(".something__x.json.tmp"), b"{ half written").unwrap();
        q.push(allowed_event("z"));

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
        let q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();
        q.push(allowed_event("p"));

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "spool directory must be 0700");
        let files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
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
        let _q = DiskQueue::new(dir.to_string_lossy().into_owned(), 100).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// The capacity still holds without listing the directory on every push,
    /// including across a restart (the count is read back from the spool).
    #[test]
    fn capacity_is_enforced_and_survives_a_restart() {
        let dir = scratch("cap");
        let path = dir.to_string_lossy().into_owned();
        let q = DiskQueue::new(path.clone(), 3).unwrap();
        for i in 0..5 {
            q.push(allowed_event(&format!("c{i}")));
        }
        assert_eq!(q.spool_files().len(), 3, "never more than capacity files");

        let q = DiskQueue::new(path, 3).unwrap();
        q.push(allowed_event("after-restart"));
        assert_eq!(q.spool_files().len(), 3, "the bound holds after a restart");

        let batch = q.drain_batch(10);
        q.ack(&batch);
        assert_eq!(*q.count.lock().unwrap(), 0, "ack keeps the count in step");
    }
}
