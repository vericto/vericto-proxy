//! Telemetry paused while the workspace is over its monthly query quota (since
//! 4.12.0).
//!
//! On a plan with a hard monthly limit the Vericto API refuses telemetry past it:
//! `POST /api/v1/ingest/events` answers 429 with `code: "QUOTA_EXCEEDED"` until
//! the quota resets (the start of next month) or the plan is upgraded. Up to 4.11
//! the proxy treated that 429 like any other: it kept every event, retried with
//! backoff all month, and its spool filled and evicted — the loss was silent and
//! the retries were load for nothing.
//!
//! Now the proxy pauses its telemetry instead:
//!
//! - **Entering.** A 429 whose body says `QUOTA_EXCEEDED` and carries when the
//!   quota resets (`resets_at`, or a `Retry-After` header), or a rule sync saying
//!   `telemetry_quota: "exceeded"` with `telemetry_quota_resets_at`.
//! - **While paused.** Queries are evaluated and enforced exactly as before. No
//!   telemetry request is sent or retried, and new events are not enqueued: they
//!   are counted as `dropped_quota` (pipeline stats and the rule-sync heartbeat).
//!   Events already buffered stay buffered and are delivered after resuming.
//! - **Leaving.** A rule sync saying `telemetry_quota: "ok"` (an upgrade, or the
//!   new month), or the reset time passing.
//!
//! One WARN on entering and one INFO on leaving; nothing per event. A 429 without
//! that code or without a reset time (an older API, a rate limit) keeps the
//! backoff and retries of 4.11.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};

use crate::telemetry::TelemetryEvent;
use crate::telemetry::queue::{Batch, EventQueue, QueueStats};

/// The `error.code` of the API's quota 429.
pub const QUOTA_EXCEEDED_CODE: &str = "QUOTA_EXCEEDED";

/// A reset further away than this is not believed (a quota period is a month):
/// the pause ends at this horizon instead, and the next 429 or sync says more.
const MAX_PAUSE: Duration = Duration::from_secs(32 * 24 * 3600);

/// Shared by the queue (drops while paused), the reporter (stops sending, enters
/// on a quota 429), the rule syncer (enters and leaves on the API's word) and the
/// heartbeat (reports the state).
#[derive(Debug, Default)]
pub struct QuotaGate {
    paused: AtomicBool,
    /// Unix seconds when the pause ends on its own; meaningful while paused.
    resets_at: AtomicI64,
    /// Events not enqueued while paused, since the process started.
    dropped: AtomicU64,
    /// `dropped` when the current pause began, for the log line on leaving it.
    dropped_at_pause: AtomicU64,
}

impl QuotaGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pauses until `resets_at`, said by `source` ("ingest" | "rules_sync").
    /// A reset already past changes nothing. `true` when this call paused.
    pub fn pause(&self, resets_at: DateTime<Utc>, source: &'static str) -> bool {
        self.pause_at(resets_at, source, Utc::now())
    }

    fn pause_at(&self, resets_at: DateTime<Utc>, source: &'static str, now: DateTime<Utc>) -> bool {
        if resets_at <= now {
            return false;
        }
        let horizon = now + chrono::Duration::from_std(MAX_PAUSE).unwrap_or_default();
        let resets_at = resets_at.min(horizon);
        self.resets_at
            .store(resets_at.timestamp(), Ordering::Relaxed);
        if self
            .paused
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false; // already paused; the reset time is updated
        }
        self.dropped_at_pause
            .store(self.dropped.load(Ordering::Relaxed), Ordering::Relaxed);
        tracing::warn!(
            resets_at = %resets_at.to_rfc3339(),
            source,
            "Telemetry paused: the workspace reached its monthly query quota. Queries are \
             still evaluated and enforced; new events are not recorded (counted as \
             dropped_quota) until the quota resets or the plan is upgraded"
        );
        true
    }

    /// Resumes, for `reason` ("rules_sync" | "reset_time_passed"). `true` when
    /// this call resumed.
    pub fn resume(&self, reason: &'static str) -> bool {
        if self
            .paused
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let dropped = self.dropped.load(Ordering::Relaxed)
            - self
                .dropped_at_pause
                .load(Ordering::Relaxed)
                .min(self.dropped.load(Ordering::Relaxed));
        tracing::info!(
            reason,
            dropped_while_paused = dropped,
            "Telemetry resumed: the monthly query quota allows recording again"
        );
        true
    }

    /// Whether telemetry is paused now. A pause whose reset time has passed ends
    /// here. Two atomic loads when not paused: cheap enough for the query path.
    pub fn is_paused(&self) -> bool {
        self.is_paused_at(Utc::now())
    }

    fn is_paused_at(&self, now: DateTime<Utc>) -> bool {
        if !self.paused.load(Ordering::Acquire) {
            return false;
        }
        if now.timestamp() >= self.resets_at.load(Ordering::Relaxed) {
            self.resume("reset_time_passed");
            return false;
        }
        true
    }

    /// Counts one event not enqueued because of the pause.
    pub fn note_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Events not enqueued while paused, since the process started.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// When the current pause ends, or `None` when not paused.
    pub fn resets_at(&self) -> Option<DateTime<Utc>> {
        if !self.is_paused() {
            return None;
        }
        Utc.timestamp_opt(self.resets_at.load(Ordering::Relaxed), 0)
            .single()
    }
}

/// When the quota resets, from a 429's `resets_at` (RFC 3339) or, failing that,
/// its `Retry-After` seconds. `None` when neither says (an older API).
pub fn reset_time(
    resets_at: Option<&str>,
    retry_after_secs: Option<u64>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if let Some(t) = resets_at.and_then(|s| DateTime::parse_from_rfc3339(s).ok()) {
        return Some(t.with_timezone(&Utc));
    }
    retry_after_secs.map(|s| now + chrono::Duration::seconds(s.min(MAX_PAUSE.as_secs()) as i64))
}

/// The buffer in front of the reporter, gated by a [`QuotaGate`]: while paused,
/// `push` drops the event and counts it instead of buffering it, so the spool does
/// not fill with events the API would refuse. Everything else is the inner queue's.
pub struct QuotaGatedQueue {
    inner: Box<dyn EventQueue>,
    gate: Arc<QuotaGate>,
}

impl QuotaGatedQueue {
    pub fn new(inner: Box<dyn EventQueue>, gate: Arc<QuotaGate>) -> Self {
        Self { inner, gate }
    }
}

impl EventQueue for QuotaGatedQueue {
    fn push(&self, event: TelemetryEvent) {
        if self.gate.is_paused() {
            self.gate.note_dropped();
            return;
        }
        self.inner.push(event);
    }

    fn drain_batch(&self, max: usize) -> Batch {
        self.inner.drain_batch(max)
    }

    fn ack(&self, batch: &Batch) {
        self.inner.ack(batch);
    }

    fn nack(&self, batch: Batch) {
        self.inner.nack(batch);
    }

    fn available(&self) -> usize {
        self.inner.available()
    }

    fn stats(&self) -> QueueStats {
        QueueStats {
            dropped_quota: self.gate.dropped(),
            ..self.inner.stats()
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.inner.flush(timeout)
    }

    fn oldest_buffered_at(&self) -> Option<std::time::SystemTime> {
        self.inner.oldest_buffered_at()
    }

    fn spool_dir(&self) -> Option<std::path::PathBuf> {
        self.inner.spool_dir()
    }

    fn adopt(&self, dir: &std::path::Path) -> std::io::Result<(usize, usize)> {
        self.inner.adopt(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn pause_and_resume_happen_once_each() {
        let g = QuotaGate::new();
        let now = at("2026-10-20T10:00:00Z");
        assert!(g.pause_at(at("2026-11-01T00:00:00Z"), "ingest", now));
        assert!(
            !g.pause_at(at("2026-11-01T00:00:00Z"), "rules_sync", now),
            "already paused: no second WARN"
        );
        assert!(g.is_paused_at(now));
        assert!(g.resume("rules_sync"));
        assert!(!g.resume("rules_sync"), "already resumed: no second INFO");
        assert!(!g.is_paused_at(now));
    }

    #[test]
    fn the_pause_ends_when_the_reset_time_passes() {
        let g = QuotaGate::new();
        assert!(g.pause_at(
            at("2026-11-01T00:00:00Z"),
            "ingest",
            at("2026-10-31T23:00:00Z")
        ));
        assert!(g.is_paused_at(at("2026-10-31T23:59:59Z")));
        assert!(!g.is_paused_at(at("2026-11-01T00:00:00Z")));
        assert!(!g.is_paused_at(at("2026-11-01T00:00:01Z")));
    }

    #[test]
    fn a_reset_already_past_does_not_pause_and_a_far_one_is_capped() {
        let g = QuotaGate::new();
        let now = at("2026-10-20T10:00:00Z");
        assert!(!g.pause_at(at("2026-10-01T00:00:00Z"), "ingest", now));
        assert!(!g.is_paused_at(now));
        assert!(g.pause_at(at("2030-01-01T00:00:00Z"), "ingest", now));
        assert!(g.is_paused_at(at("2026-11-20T00:00:00Z")));
        assert!(
            !g.is_paused_at(at("2026-11-22T00:00:00Z")),
            "never longer than 32 days"
        );
    }

    #[test]
    fn drops_are_counted() {
        let g = QuotaGate::new();
        g.note_dropped();
        g.note_dropped();
        assert_eq!(g.dropped(), 2);
    }

    #[test]
    fn the_reset_time_comes_from_the_body_or_retry_after() {
        let now = at("2026-10-31T23:00:00Z");
        assert_eq!(
            reset_time(Some("2026-11-01T00:00:00.000Z"), Some(5), now),
            Some(at("2026-11-01T00:00:00Z"))
        );
        assert_eq!(
            reset_time(None, Some(3600), now),
            Some(at("2026-11-01T00:00:00Z"))
        );
        assert_eq!(
            reset_time(Some("not a date"), Some(60), now),
            Some(at("2026-10-31T23:01:00Z"))
        );
        assert_eq!(reset_time(None, None, now), None);
    }

    /// While paused, nothing reaches the spool: it does not grow, and every event
    /// is counted. After resuming, events are buffered again.
    #[test]
    fn a_paused_gate_keeps_events_out_of_the_spool() {
        let dir = std::env::temp_dir().join(format!(
            "vericto-quota-gate-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let disk = crate::telemetry::queue::DiskQueue::with_options(
            &dir,
            crate::telemetry::queue::DiskOptions::default(),
        )
        .unwrap();
        let gate = Arc::new(QuotaGate::new());
        let q = QuotaGatedQueue::new(Box::new(disk), Arc::clone(&gate));
        let ev = |id: &str| -> TelemetryEvent {
            serde_json::from_value(serde_json::json!({
                "event_id": id, "database_id": "db-1", "query_text": "SELECT 1",
                "dialect": "postgres", "status": "ALLOWED", "occurred_at": "2026-10-14T00:00:00Z"
            }))
            .unwrap()
        };
        q.push(ev("before"));
        assert!(q.flush(Duration::from_secs(10)));
        assert!(gate.pause(Utc::now() + chrono::Duration::hours(1), "ingest"));
        for i in 0..50 {
            q.push(ev(&format!("paused-{i}")));
        }
        assert!(q.flush(Duration::from_secs(10)));
        let s = q.stats();
        assert_eq!(s.spooled, 1, "the spool did not grow while paused");
        assert_eq!(s.enqueued, 1);
        assert_eq!(s.dropped_quota, 50);
        assert!(gate.resume("rules_sync"));
        q.push(ev("after"));
        assert!(q.flush(Duration::from_secs(10)));
        assert_eq!(q.stats().spooled, 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
