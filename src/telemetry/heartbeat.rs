//! The telemetry pipeline's counters, sent with every rule sync (since 4.12.0).
//!
//! Up to 4.11 the only place a proxy said how many events it had dropped was its
//! own `Telemetry pipeline stats` log line, which the Vericto API never sees: an
//! event evicted from a full spool was lost without anyone outside the proxy's
//! logs knowing. Every proxy already polls `GET /api/v1/sync/rules` (the API's
//! heartbeat for it, every 5 minutes by default), so that request now carries the
//! cumulative counters in one header, [`STATS_HEADER`], as compact JSON.
//!
//! Compatibility both ways: an API that does not know the header ignores it (an
//! unknown request header changes nothing in the response), and the API treats a
//! sync without it, from 4.11 or older, exactly as before. The counters are totals
//! since this process started, under an `instance_id` drawn at startup, so the API
//! can tell a restart (new instance, counters from zero) from new drops.

use std::sync::Arc;

use serde::Serialize;

use crate::config::BufferMode;
use crate::telemetry::queue::EventQueue;
use crate::telemetry::quota::QuotaGate;
use crate::telemetry::reporter::Reporter;

/// The request header that carries [`HeartbeatStats`] on `GET /sync/rules`.
pub const STATS_HEADER: &str = "X-Vericto-Telemetry-Stats";

/// Version of the header's JSON shape. Fields are only ever added.
pub const STATS_VERSION: u8 = 1;

/// The header's payload. Every counter is a total since the process started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeartbeatStats {
    pub v: u8,
    /// Random per process: a new value means the counters started again from 0.
    pub instance_id: String,
    pub proxy_version: &'static str,
    /// "memory" | "disk".
    pub buffer: &'static str,
    /// Events accepted into the buffer.
    pub enqueued: u64,
    /// Events the API answered 2xx for.
    pub delivered: u64,
    /// Dropped because the channel to the disk writer was full (disk mode).
    pub dropped_queue_full: u64,
    /// Oldest events evicted to stay within the buffer's bounds.
    pub evicted_oldest: u64,
    /// Refused by the API for good (400/413/415/422) and dropped.
    pub dropped_permanent: u64,
    /// Lost because their spool segment could not be written (disk mode).
    pub write_failures: u64,
    /// Events buffered and not yet delivered right now (memory ring, or the spool
    /// plus what waits for the disk writer).
    pub spooled_events: u64,
    /// Bytes of spool files right now (0 in memory mode).
    pub spool_bytes: u64,
    /// Not enqueued while telemetry was paused for the monthly quota.
    pub dropped_quota: u64,
    /// Telemetry is paused now because the workspace is over its monthly quota.
    pub quota_paused: bool,
    /// When that pause ends on its own (RFC 3339), while paused.
    pub quota_resets_at: Option<String>,
}

/// Reads the counters of a running pipeline for the rule syncer.
#[derive(Clone)]
pub struct StatsSource {
    instance_id: String,
    buffer: &'static str,
    queue: Arc<dyn EventQueue>,
    reporter: Reporter,
    quota: Arc<QuotaGate>,
}

impl StatsSource {
    /// A source with a fresh random instance id.
    pub fn new(buffer: BufferMode, queue: Arc<dyn EventQueue>, reporter: Reporter) -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().to_string(),
            buffer: match buffer {
                BufferMode::Memory => "memory",
                BufferMode::Disk => "disk",
            },
            queue,
            quota: reporter.quota_gate(),
            reporter,
        }
    }

    /// The quota gate the reporter and the queue share, for the rule syncer.
    pub fn quota_gate(&self) -> Arc<QuotaGate> {
        Arc::clone(&self.quota)
    }

    /// The counters right now. In-memory reads only: cheap enough for every sync.
    pub fn snapshot(&self) -> HeartbeatStats {
        let q = self.queue.stats();
        let d = self.reporter.delivery_counters();
        HeartbeatStats {
            v: STATS_VERSION,
            instance_id: self.instance_id.clone(),
            proxy_version: env!("CARGO_PKG_VERSION"),
            buffer: self.buffer,
            enqueued: q.enqueued,
            delivered: d.delivered,
            dropped_queue_full: q.dropped_queue_full,
            evicted_oldest: q.evicted_oldest,
            dropped_permanent: d.dropped_permanent,
            write_failures: q.write_failures,
            spooled_events: (q.spooled + q.queue_depth) as u64,
            spool_bytes: q.spool_bytes,
            dropped_quota: q.dropped_quota,
            quota_paused: self.quota.is_paused(),
            quota_resets_at: self.quota.resets_at().map(|t| t.to_rfc3339()),
        }
    }

    /// [`snapshot`](Self::snapshot) as the header value: compact JSON, ASCII only
    /// (a UUID, a version and numbers), so always a valid header value.
    pub fn header_value(&self) -> String {
        serde_json::to_string(&self.snapshot()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::queue::MemoryQueue;

    fn cfg() -> crate::config::ControlPlaneConfig {
        crate::config::ControlPlaneConfig {
            api_url: "http://127.0.0.1:9".into(),
            api_key: "vk_test".into(),
            database_id: None,
            rules_sync_interval: std::time::Duration::from_secs(3600),
            rules_cache_path: None,
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 2,
            batch_size: 10,
            flush_interval: std::time::Duration::from_secs(5),
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        }
    }

    fn event(id: &str) -> crate::telemetry::TelemetryEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": id, "database_id": "db-1", "query_text": "SELECT 1",
            "dialect": "postgres", "status": "ALLOWED", "occurred_at": "2026-10-14T00:00:00Z"
        }))
        .unwrap()
    }

    #[test]
    fn the_header_carries_the_pipeline_counters() {
        let queue: Arc<dyn EventQueue> = Arc::new(MemoryQueue::new(2));
        let reporter = Reporter::new(cfg(), Arc::clone(&queue));
        let source = StatsSource::new(BufferMode::Memory, Arc::clone(&queue), reporter);
        for i in 0..3 {
            queue.push(event(&format!("e{i}")));
        }
        let json: serde_json::Value = serde_json::from_str(&source.header_value()).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["buffer"], "memory");
        assert_eq!(json["proxy_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["enqueued"], 3);
        assert_eq!(json["evicted_oldest"], 1, "a ring of 2 evicts the third");
        assert_eq!(json["spooled_events"], 2);
        assert_eq!(json["delivered"], 0);
        assert_eq!(json["dropped_permanent"], 0);
        assert_eq!(json["dropped_queue_full"], 0);
        assert_eq!(json["write_failures"], 0);
        assert_eq!(json["spool_bytes"], 0);
        assert_eq!(json["dropped_quota"], 0);
        assert_eq!(json["quota_paused"], false);
        assert!(json["quota_resets_at"].is_null());
        assert!(uuid::Uuid::parse_str(json["instance_id"].as_str().unwrap()).is_ok());
        assert!(source.header_value().is_ascii());
        // Same process, same instance: the API computes deltas against it.
        let again: serde_json::Value = serde_json::from_str(&source.header_value()).unwrap();
        assert_eq!(again["instance_id"], json["instance_id"]);
    }

    #[test]
    fn every_process_gets_its_own_instance_id() {
        let queue: Arc<dyn EventQueue> = Arc::new(MemoryQueue::new(2));
        let a = StatsSource::new(
            BufferMode::Memory,
            Arc::clone(&queue),
            Reporter::new(cfg(), Arc::clone(&queue)),
        );
        let b = StatsSource::new(
            BufferMode::Memory,
            Arc::clone(&queue),
            Reporter::new(cfg(), Arc::clone(&queue)),
        );
        assert_ne!(a.snapshot().instance_id, b.snapshot().instance_id);
    }
}
