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
pub struct DiskQueue {
    dir: PathBuf,
    capacity: usize,
}

impl DiskQueue {
    pub fn new(dir: String, capacity: usize) -> std::io::Result<Self> {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, capacity })
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
        let files = self.spool_files();
        if files.len() >= self.capacity {
            if let Some(oldest) = files.first() {
                let _ = fs::remove_file(oldest);
                tracing::warn!("Telemetry disk spool full — dropped oldest event");
            }
        }
        // Name: <occurred_at-ish ordering via event_id is not monotonic>, so use
        // a high-resolution-ish prefix from the event's occurred_at + event_id.
        let name = format!(
            "{}__{}.json",
            event.occurred_at.replace([':', '.'], "-"),
            event.event_id
        );
        let path = self.dir.join(name);
        match serde_json::to_vec(&event) {
            Ok(bytes) => {
                if let Ok(mut f) = fs::File::create(&path) {
                    let _ = f.write_all(&bytes);
                }
            }
            Err(e) => tracing::error!(error = %e, "Failed to serialize telemetry event for spool"),
        }
    }

    fn drain_batch(&self, max: usize) -> Batch {
        let files = self.spool_files();
        let mut events = Vec::new();
        let mut taken = Vec::new();
        for path in files.into_iter().take(max) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(ev) = serde_json::from_slice::<TelemetryEvent>(&bytes) {
                    events.push(ev);
                    taken.push(path);
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
            let _ = fs::remove_file(path);
        }
    }

    fn nack(&self, _batch: Batch) {
        // Leave files in place; they retry on the next flush cycle.
    }
}
