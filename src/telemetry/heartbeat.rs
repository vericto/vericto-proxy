// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
//!
//! Since 4.12.0 the header also says how far behind delivery is:
//! `oldest_undelivered_age_s` (0 when nothing waits), `last_delivery_at` and the
//! spool's bound, `spool_max_bytes`. Fields are only ever added, so `v` stays 1 and
//! an API that does not know them ignores them. The same figures feed `/metrics`
//! and the CloudWatch EMF line (`telemetry::metrics`).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};

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
    /// Seconds since the oldest event still undelivered was recorded; 0 when
    /// nothing waits (since 4.12.0).
    pub oldest_undelivered_age_s: u64,
    /// When the API last answered 2xx to a telemetry request (RFC 3339); `None`
    /// before the first since the process started (since 4.12.0).
    pub last_delivery_at: Option<String>,
    /// The disk spool's byte bound; 0 for the memory buffer (since 4.12.0).
    pub spool_max_bytes: u64,
}

/// Everything the pipeline can say about itself at one instant (since 4.12.0):
/// the counters of [`HeartbeatStats`] plus the delivery lag. In-memory reads, and
/// at most one `stat` of the spool's head segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineSnapshot {
    pub buffer: &'static str,
    pub enqueued: u64,
    pub delivered: u64,
    pub dropped_queue_full: u64,
    pub evicted_oldest: u64,
    pub dropped_permanent: u64,
    pub write_failures: u64,
    pub dropped_quota: u64,
    pub spooled_events: u64,
    pub spool_bytes: u64,
    pub spool_max_bytes: u64,
    pub quota_paused: bool,
    pub quota_resets_at: Option<DateTime<Utc>>,
    /// Seconds since the oldest undelivered event was recorded; 0 when none waits.
    pub oldest_undelivered_age_s: u64,
    /// Seconds delivery has made no progress while events wait: since the later
    /// of the last 2xx, the oldest waiting event and the process start; 0 when
    /// nothing waits.
    pub seconds_since_last_delivery: u64,
    pub last_delivery_at: Option<DateTime<Utc>>,
    /// Telemetry requests outstanding.
    pub in_flight: u64,
}

/// Whole seconds from `earlier` to `now`; 0 when `earlier` is not before it.
fn secs_between(earlier: SystemTime, now: SystemTime) -> u64 {
    now.duration_since(earlier)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Reads the counters of a running pipeline for the rule syncer.
#[derive(Clone)]
pub struct StatsSource {
    instance_id: String,
    buffer: &'static str,
    queue: Arc<dyn EventQueue>,
    reporter: Reporter,
    quota: Arc<QuotaGate>,
    spool_max_bytes: u64,
    started_at: SystemTime,
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
            spool_max_bytes: 0,
            started_at: SystemTime::now(),
        }
    }

    /// The disk spool's byte bound, reported as `spool_max_bytes` (0 by default:
    /// the memory buffer, or a disk spool that fell back to memory).
    pub fn with_spool_max_bytes(mut self, bytes: u64) -> Self {
        self.spool_max_bytes = bytes;
        self
    }

    /// The pipeline right now.
    pub fn pipeline(&self) -> PipelineSnapshot {
        self.pipeline_at(SystemTime::now())
    }

    fn pipeline_at(&self, now: SystemTime) -> PipelineSnapshot {
        let q = self.queue.stats();
        let d = self.reporter.delivery_counters();
        let state = self.reporter.delivery_state();
        let oldest = match (self.queue.oldest_buffered_at(), state.oldest_in_flight) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let spooled_events = (q.spooled + q.queue_depth) as u64;
        // Something waits only if an event is buffered or in flight; a spool whose
        // head time is known but whose counts read 0 a moment later has drained.
        let waiting = oldest.filter(|_| spooled_events > 0 || state.in_flight > 0);
        let (age, stalled) = match waiting {
            None => (0, 0),
            Some(oldest) => {
                let progress = [state.last_delivery_at, Some(oldest), Some(self.started_at)]
                    .into_iter()
                    .flatten()
                    .max()
                    .unwrap_or(now);
                (secs_between(oldest, now), secs_between(progress, now))
            }
        };
        PipelineSnapshot {
            buffer: self.buffer,
            enqueued: q.enqueued,
            delivered: d.delivered,
            dropped_queue_full: q.dropped_queue_full,
            evicted_oldest: q.evicted_oldest,
            dropped_permanent: d.dropped_permanent,
            write_failures: q.write_failures,
            dropped_quota: q.dropped_quota,
            spooled_events,
            spool_bytes: q.spool_bytes,
            spool_max_bytes: self.spool_max_bytes,
            quota_paused: self.quota.is_paused(),
            quota_resets_at: self.quota.resets_at(),
            oldest_undelivered_age_s: age,
            seconds_since_last_delivery: stalled,
            last_delivery_at: state.last_delivery_at.map(DateTime::<Utc>::from),
            in_flight: state.in_flight as u64,
        }
    }

    /// The quota gate the reporter and the queue share, for the rule syncer.
    pub fn quota_gate(&self) -> Arc<QuotaGate> {
        Arc::clone(&self.quota)
    }

    /// The counters right now. In-memory reads only: cheap enough for every sync.
    pub fn snapshot(&self) -> HeartbeatStats {
        let p = self.pipeline();
        HeartbeatStats {
            v: STATS_VERSION,
            instance_id: self.instance_id.clone(),
            proxy_version: env!("CARGO_PKG_VERSION"),
            buffer: p.buffer,
            enqueued: p.enqueued,
            delivered: p.delivered,
            dropped_queue_full: p.dropped_queue_full,
            evicted_oldest: p.evicted_oldest,
            dropped_permanent: p.dropped_permanent,
            write_failures: p.write_failures,
            spooled_events: p.spooled_events,
            spool_bytes: p.spool_bytes,
            dropped_quota: p.dropped_quota,
            quota_paused: p.quota_paused,
            quota_resets_at: p.quota_resets_at.map(|t| t.to_rfc3339()),
            oldest_undelivered_age_s: p.oldest_undelivered_age_s,
            last_delivery_at: p.last_delivery_at.map(|t| t.to_rfc3339()),
            spool_max_bytes: p.spool_max_bytes,
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
        // Delivery lag (4.12.0): nothing was delivered yet; the age is a number
        // (its value is covered by the test below).
        assert!(json["last_delivery_at"].is_null());
        assert_eq!(json["spool_max_bytes"], 0);
        assert!(json["oldest_undelivered_age_s"].is_u64());
        assert!(uuid::Uuid::parse_str(json["instance_id"].as_str().unwrap()).is_ok());
        assert!(source.header_value().is_ascii());
        // Same process, same instance: the API computes deltas against it.
        let again: serde_json::Value = serde_json::from_str(&source.header_value()).unwrap();
        assert_eq!(again["instance_id"], json["instance_id"]);
    }

    /// The lag is measured from the oldest event waiting, and reads 0 once
    /// nothing waits: an idle proxy is not "behind".
    #[test]
    fn the_delivery_lag_is_the_age_of_the_oldest_waiting_event() {
        let queue: Arc<dyn EventQueue> = Arc::new(MemoryQueue::new(10));
        let reporter = Reporter::new(cfg(), Arc::clone(&queue));
        let source = StatsSource::new(BufferMode::Memory, Arc::clone(&queue), reporter);
        let now = SystemTime::now();
        let idle = source.pipeline_at(now);
        assert_eq!(idle.oldest_undelivered_age_s, 0);
        assert_eq!(idle.seconds_since_last_delivery, 0);

        let at =
            |secs_ago: i64| (chrono::Utc::now() - chrono::Duration::seconds(secs_ago)).to_rfc3339();
        for (id, ago) in [("old", 400), ("new", 10)] {
            let mut ev = event(id);
            ev.occurred_at = at(ago);
            queue.push(ev);
        }
        let p = source.pipeline_at(now);
        assert!((399..=401).contains(&p.oldest_undelivered_age_s), "{p:?}");
        // Nothing delivered yet: stalled since the process started, which is
        // later than the oldest event here.
        assert!(p.seconds_since_last_delivery <= p.oldest_undelivered_age_s);
        assert_eq!(p.spooled_events, 2);
        let _ = queue.drain_batch(10);
        assert_eq!(source.pipeline_at(now).oldest_undelivered_age_s, 0);
    }

    #[test]
    fn the_spool_bound_is_reported_when_set() {
        let queue: Arc<dyn EventQueue> = Arc::new(MemoryQueue::new(2));
        let source = StatsSource::new(
            BufferMode::Disk,
            Arc::clone(&queue),
            Reporter::new(cfg(), Arc::clone(&queue)),
        )
        .with_spool_max_bytes(1 << 30);
        assert_eq!(source.snapshot().spool_max_bytes, 1 << 30);
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
