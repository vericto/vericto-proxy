//! Background reporter: periodically drains the event queue and POSTs batches
//! to the Vericto API. Delivery failures never propagate to the SQL path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::ControlPlaneConfig;
use crate::telemetry::queue::{EventQueue, QueueStats};

/// How often the reporter logs the queue's counters (only when something moved).
pub const STATS_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Reporter {
    cfg: ControlPlaneConfig,
    queue: Arc<dyn EventQueue>,
    client: reqwest::Client,
}

impl Reporter {
    pub fn new(cfg: ControlPlaneConfig, queue: Arc<dyn EventQueue>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(crate::config::same_origin_redirects())
            .build()
            .expect("failed to build telemetry HTTP client");
        Self { cfg, queue, client }
    }

    fn ingest_url(&self) -> String {
        format!("{}/api/v1/ingest/events", self.cfg.api_url)
    }

    /// Runs forever, flushing on the configured interval.
    pub async fn run(self) {
        let ingest_url = self.ingest_url();
        let mut ticker = tokio::time::interval(self.cfg.flush_interval);
        let mut last_stats = QueueStats::default();
        let mut last_stats_at = Instant::now();

        loop {
            ticker.tick().await;
            self.deliver_pending_to(&ingest_url).await;
            if last_stats_at.elapsed() >= STATS_LOG_EVERY {
                last_stats_at = Instant::now();
                let stats = self.queue.stats();
                if stats_moved(&last_stats, &stats) {
                    log_stats(&stats);
                }
                last_stats = stats;
            }
        }
    }

    /// Delivers everything buffered, in batches, until the queue is empty or a
    /// delivery fails. Returns how many events the API accepted. Also used once
    /// more at shutdown.
    pub async fn deliver_pending(&self) -> usize {
        self.deliver_pending_to(&self.ingest_url()).await
    }

    async fn deliver_pending_to(&self, ingest_url: &str) -> usize {
        let mut delivered = 0;
        loop {
            // The disk queue reads its spool here, off the async workers.
            let batch = {
                let queue = Arc::clone(&self.queue);
                let max = self.cfg.batch_size;
                match tokio::task::spawn_blocking(move || queue.drain_batch(max)).await {
                    Ok(batch) => batch,
                    Err(_) => return delivered,
                }
            };
            if batch.events.is_empty() {
                return delivered;
            }
            match self.deliver(ingest_url, &batch.events).await {
                Ok(()) => {
                    delivered += batch.events.len();
                    self.settle(batch, true).await;
                }
                Err(DeliveryError::Permanent { status }) => {
                    // The API refused this payload and always will: retrying
                    // re-sends the same bytes. `nack` re-buffers at the front
                    // of the queue, so retrying would park the batch at the
                    // head and block every event behind it until capacity
                    // churned past it — one wasted request per tick meanwhile.
                    // Dropping loses these events, which is why it is logged
                    // at error with the status that caused it.
                    tracing::error!(
                        status = status,
                        count = batch.events.len(),
                        "Telemetry batch rejected permanently; events dropped"
                    );
                    self.settle(batch, true).await;
                }
                Err(DeliveryError::Retryable { reason }) => {
                    tracing::warn!(error = %reason, count = batch.events.len(), "Telemetry delivery failed; will retry");
                    self.settle(batch, false).await;
                    return delivered; // back off until next tick
                }
            }
        }
    }

    /// `ack` (removes spool files) or `nack`, on the blocking pool.
    async fn settle(&self, batch: crate::telemetry::queue::Batch, ack: bool) {
        let queue = Arc::clone(&self.queue);
        let _ = tokio::task::spawn_blocking(move || {
            if ack {
                queue.ack(&batch)
            } else {
                queue.nack(batch)
            }
        })
        .await;
    }

    async fn deliver(
        &self,
        url: &str,
        events: &[crate::telemetry::TelemetryEvent],
    ) -> Result<(), DeliveryError> {
        let body = serde_json::json!({ "events": events });
        let res = self
            .client
            .post(url)
            .header("X-API-Key", &self.cfg.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| DeliveryError::Retryable {
                reason: e.to_string(),
            })?;

        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        if classify(status).is_permanent() {
            Err(DeliveryError::Permanent {
                status: status.as_u16(),
            })
        } else {
            Err(DeliveryError::Retryable {
                reason: format!("ingest returned HTTP {status}"),
            })
        }
    }
}

fn stats_moved(before: &QueueStats, now: &QueueStats) -> bool {
    now.enqueued != before.enqueued
        || now.dropped_queue_full != before.dropped_queue_full
        || now.evicted_oldest != before.evicted_oldest
        || now.write_failures != before.write_failures
        || now.queue_depth > 0
        || now.spooled > 0
}

fn log_stats(s: &QueueStats) {
    tracing::info!(
        queue_depth = s.queue_depth,
        spooled = s.spooled,
        enqueued = s.enqueued,
        dropped_queue_full = s.dropped_queue_full,
        evicted_oldest = s.evicted_oldest,
        write_failures = s.write_failures,
        batches_written = s.batches_written,
        last_batch_write_ms = s.last_batch_write_us as f64 / 1000.0,
        max_batch_write_ms = s.max_batch_write_us as f64 / 1000.0,
        "Telemetry pipeline stats"
    );
}

/// Why a batch was not delivered, and whether sending the same bytes again could
/// ever succeed.
enum DeliveryError {
    /// The API will refuse this payload no matter how often it is sent.
    Permanent { status: u16 },
    /// Transport error, or a server-side condition that may clear.
    Retryable { reason: String },
}

enum Disposition {
    Permanent,
    Retryable,
}

impl Disposition {
    fn is_permanent(&self) -> bool {
        matches!(self, Disposition::Permanent)
    }
}

/// Decide whether an HTTP status makes a batch permanently undeliverable.
///
/// Permanent covers the payload-shaped rejections: 400 when the ingest schema
/// refuses a field, 413 when the batch exceeds the API's body limit, 422. Those
/// are properties of the bytes, so a retry sends the same rejected bytes.
///
/// Everything else retries, including the auth codes. A 401/403 is an operator
/// misconfiguration — a rotated or mistyped API key — and it is fixable without
/// touching the proxy, so discarding telemetry over it would turn a recoverable
/// mistake into silent data loss. 429 and 408 are explicitly transient, and 5xx
/// is the server's problem, not the payload's.
fn classify(status: reqwest::StatusCode) -> Disposition {
    use reqwest::StatusCode;
    match status {
        StatusCode::BAD_REQUEST
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNPROCESSABLE_ENTITY => Disposition::Permanent,
        _ => Disposition::Retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    /// A stand-in for `/api/v1/ingest/events` that records every event id it is
    /// sent and fails the first `fail_first` requests with a 503.
    struct MockIngest {
        url: String,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
        _server: tokio::task::JoinHandle<()>,
    }

    async fn mock_ingest(fail_first: usize) -> MockIngest {
        use axum::{Json, Router, http::StatusCode as S, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let app = {
            let seen = seen.clone();
            Router::new().route(
                "/api/v1/ingest/events",
                post(move |Json(body): Json<serde_json::Value>| {
                    let seen = seen.clone();
                    let calls = calls.clone();
                    async move {
                        if calls.fetch_add(1, Ordering::SeqCst) < fail_first {
                            return S::SERVICE_UNAVAILABLE;
                        }
                        let mut seen = seen.lock().unwrap();
                        for ev in body["events"].as_array().unwrap() {
                            seen.push(ev["event_id"].as_str().unwrap().to_string());
                        }
                        S::OK
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockIngest {
            url,
            seen,
            _server: server,
        }
    }

    fn cfg(api_url: &str, spool: &std::path::Path) -> ControlPlaneConfig {
        ControlPlaneConfig {
            api_url: api_url.to_string(),
            api_key: "vk_test".into(),
            database_id: Some("db-1".into()),
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: None,
            buffer_mode: crate::config::BufferMode::Disk,
            disk_spool_path: spool.to_string_lossy().into_owned(),
            memory_capacity: 10_000,
            batch_size: 100,
            flush_interval: Duration::from_millis(50),
            spool: crate::config::SpoolTuning {
                flush_every: Duration::from_millis(10),
                ..crate::config::SpoolTuning::default()
            },
        }
    }

    fn event(id: String) -> crate::telemetry::TelemetryEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": id, "database_id": "db-1", "query_text": "SELECT 1",
            "dialect": "postgres", "status": "ALLOWED", "occurred_at": "2026-10-13T00:00:00Z"
        }))
        .unwrap()
    }

    async fn wait_for(mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// No regression in delivery through the asynchronous disk pipeline: every
    /// event pushed reaches the control plane, at least once, including across a
    /// failed delivery, and the spool is empty afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disk_mode_delivers_every_event_at_least_once() {
        let api = mock_ingest(2).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(&api.url, dir.path());
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        tokio::spawn(Reporter::new(cfg, queue.clone()).run());

        for i in 0..350 {
            queue.push(event(format!("d{i}")));
        }
        let seen = api.seen.clone();
        wait_for(|| {
            let seen = seen.lock().unwrap();
            (0..350).all(|i| seen.contains(&format!("d{i}")))
        })
        .await;
        wait_for(|| queue.stats().spooled == 0 && queue.stats().queue_depth == 0).await;
        assert_eq!(queue.stats().dropped_queue_full, 0);
    }

    /// Shutdown: what is still queued is written and then delivered within the
    /// deadline, in both modes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_flush_delivers_what_is_queued() {
        for mode in [
            crate::config::BufferMode::Disk,
            crate::config::BufferMode::Memory,
        ] {
            let api = mock_ingest(0).await;
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = cfg(&api.url, dir.path());
            cfg.buffer_mode = mode;
            cfg.spool.flush_every = Duration::from_secs(60); // only the flush writes
            let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
            let reporter = Reporter::new(cfg, queue.clone());
            for i in 0..120 {
                queue.push(event(format!("s{i}")));
            }
            let q = queue.clone();
            assert!(
                tokio::task::spawn_blocking(move || q.flush(Duration::from_secs(5)))
                    .await
                    .unwrap()
            );
            let delivered =
                tokio::time::timeout(Duration::from_secs(5), reporter.deliver_pending())
                    .await
                    .expect("delivery within the deadline");
            assert_eq!(delivered, 120, "{mode:?}");
            assert_eq!(api.seen.lock().unwrap().len(), 120, "{mode:?}");
            assert_eq!(queue.stats().spooled, 0, "{mode:?}");
        }
    }

    /// Payload-shaped rejections: the API refuses these bytes, so re-sending them
    /// cannot succeed. 400 is the ingest schema rejecting a field, 413 the body
    /// limit. These are the two that poisoned the queue.
    #[test]
    fn payload_rejections_are_permanent() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert!(
                classify(status).is_permanent(),
                "{status} should be permanent"
            );
        }
    }

    /// Auth failures stay retryable on purpose: a rotated or mistyped API key is
    /// fixable without redeploying the proxy, so dropping telemetry over it would
    /// turn a recoverable misconfiguration into silent data loss.
    #[test]
    fn auth_failures_are_retryable() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            assert!(
                !classify(status).is_permanent(),
                "{status} should be retryable"
            );
        }
    }

    #[test]
    fn throttling_and_server_errors_are_retryable() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(
                !classify(status).is_permanent(),
                "{status} should be retryable"
            );
        }
    }
}
