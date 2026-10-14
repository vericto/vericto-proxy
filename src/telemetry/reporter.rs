//! Background reporter: drains the event queue and POSTs batches to the Vericto
//! API. Delivery failures never propagate to the SQL path.
//!
//! ## Since 4.11.0
//!
//! Up to 4.10 the reporter was one loop: every `VERICTO_TELEMETRY_FLUSH_SECS` it
//! drained batches of 100 and sent them one at a time, each waiting for its
//! response. At ~700 ms per request that capped a proxy at ~140 events per second
//! whatever its traffic, and on staging the spool filled and evicted most events.
//! Now:
//!
//! - A batch is sent as soon as `batch_size` events (default 500) are pending, or
//!   when the oldest pending event has waited `flush_interval` (default 5 s),
//!   whichever comes first.
//! - Up to `max_in_flight` (default 4) requests are outstanding at once. The queue
//!   hands each batch events no other undelivered batch holds, and an event leaves
//!   the buffer only when the request that carried it got a 2xx, in whatever order
//!   the responses arrive.
//! - Bodies are gzip-compressed. An API that refuses a compressed body it would
//!   accept uncompressed (400/415 then 2xx) turns compression off for the process.
//! - A retryable failure (transport error, 5xx, 429, 401/403...) releases the batch
//!   for a later attempt and pauses new requests with exponential backoff; one that
//!   succeeds resets it. A 413 splits the batch in halves before anything is dropped.
//!
//! ## Since 4.12.0
//!
//! - A 429 with `code: "QUOTA_EXCEEDED"` and a reset time pauses telemetry until the
//!   quota resets or a rule sync says it is lifted (`telemetry::quota`): no request
//!   is sent or retried meanwhile, and the batch stays buffered. Any other 429 keeps
//!   the backoff above.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinSet;

use crate::config::ControlPlaneConfig;
use crate::telemetry::TelemetryEvent;
use crate::telemetry::queue::{Batch, EventQueue, QueueStats};
use crate::telemetry::quota::{QUOTA_EXCEEDED_CODE, QuotaGate};

/// How often the reporter logs the queue's counters (only when something moved).
pub const STATS_LOG_EVERY: Duration = Duration::from_secs(60);

/// How often the reporter looks at the buffer for a full or an aged batch. Reading
/// the buffer's size is an in-memory count, so this costs nothing measurable.
const POLL_EVERY: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct Reporter {
    cfg: ControlPlaneConfig,
    queue: Arc<dyn EventQueue>,
    client: reqwest::Client,
    shared: Arc<Shared>,
    /// Paused while the workspace is over its monthly quota (4.12.0).
    quota: Arc<QuotaGate>,
}

/// State shared by the reporter's delivery tasks.
struct Shared {
    /// Still compressing request bodies (see the module docs).
    gzip: AtomicBool,
    delivered: AtomicU64,
    requests: AtomicU64,
    retries: AtomicU64,
    dropped_permanent: AtomicU64,
    last_request_us: AtomicU64,
    max_request_us: AtomicU64,
    /// Unix milliseconds of the last request answered 2xx; 0 = none yet.
    last_delivery_ms: AtomicI64,
    /// Batches whose requests are outstanding.
    in_flight: AtomicUsize,
    /// The oldest event of each batch in flight, by flight token: a batch of the
    /// memory buffer has left the ring while it is out, and is still undelivered.
    in_flight_oldest: Mutex<Vec<(u64, SystemTime)>>,
    next_flight: AtomicU64,
}

/// One batch in flight, for the delivery-lag metric and the in-flight gauge.
/// Dropped with the delivery task, whether it finished, failed or panicked.
struct InFlight {
    shared: Arc<Shared>,
    token: u64,
}

impl InFlight {
    fn new(shared: &Arc<Shared>, oldest: Option<SystemTime>) -> Self {
        let token = shared.next_flight.fetch_add(1, Ordering::Relaxed);
        shared.in_flight.fetch_add(1, Ordering::Relaxed);
        if let Some(at) = oldest {
            shared.in_flight_oldest.lock().unwrap().push((token, at));
        }
        Self {
            shared: Arc::clone(shared),
            token,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.shared.in_flight.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut held) = self.shared.in_flight_oldest.lock() {
            held.retain(|(t, _)| *t != self.token);
        }
    }
}

/// Where delivery stands (since 4.12.0): for the metrics and the rule-sync
/// heartbeat. In-memory reads only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeliveryState {
    /// The last time the API answered 2xx to a telemetry request.
    pub last_delivery_at: Option<SystemTime>,
    /// Telemetry requests outstanding.
    pub in_flight: usize,
    /// The oldest event a batch in flight carries.
    pub oldest_in_flight: Option<SystemTime>,
}

/// The reporter's own totals since the process started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryCounters {
    pub delivered: u64,
    pub dropped_permanent: u64,
}

/// What became of a batch whose requests all completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Sent {
    /// Events the API answered 2xx for.
    delivered: usize,
    /// Events the API refused permanently (dropped, logged).
    dropped: usize,
}

impl Reporter {
    pub fn new(cfg: ControlPlaneConfig, queue: Arc<dyn EventQueue>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(crate::config::same_origin_redirects())
            .build()
            .expect("failed to build telemetry HTTP client");
        let shared = Arc::new(Shared {
            gzip: AtomicBool::new(cfg.delivery.gzip),
            delivered: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            dropped_permanent: AtomicU64::new(0),
            last_request_us: AtomicU64::new(0),
            max_request_us: AtomicU64::new(0),
            last_delivery_ms: AtomicI64::new(0),
            in_flight: AtomicUsize::new(0),
            in_flight_oldest: Mutex::new(Vec::new()),
            next_flight: AtomicU64::new(0),
        });
        Self {
            cfg,
            queue,
            client,
            shared,
            quota: Arc::new(QuotaGate::new()),
        }
    }

    /// Shares `gate` with the queue and the rule syncer, so a quota 429 here pauses
    /// all of them and a sync that lifts it resumes this reporter.
    pub fn with_quota_gate(mut self, gate: Arc<QuotaGate>) -> Self {
        self.quota = gate;
        self
    }

    /// The gate this reporter pauses on (for the heartbeat and the rule syncer).
    pub fn quota_gate(&self) -> Arc<QuotaGate> {
        Arc::clone(&self.quota)
    }

    fn ingest_url(&self) -> String {
        format!("{}/api/v1/ingest/events", self.cfg.api_url)
    }

    fn max_in_flight(&self) -> usize {
        self.cfg.delivery.max_in_flight.max(1)
    }

    /// Runs forever: sends full batches as they fill and partial ones as they age,
    /// with up to `max_in_flight` requests outstanding.
    pub async fn run(self) {
        let ingest_url: Arc<str> = self.ingest_url().into();
        let mut flights = Flights::default();
        let mut pending_since: Option<Instant> = None;
        let mut backoff = Backoff::new(self.cfg.delivery.retry_base, self.cfg.delivery.retry_max);
        let mut paused_until: Option<Instant> = None;
        let poll = POLL_EVERY.min(self.cfg.flush_interval);
        let mut last_stats = QueueStats::default();
        let mut last_stats_at = Instant::now();

        loop {
            if paused_until.is_some_and(|t| Instant::now() >= t) {
                paused_until = None;
            }
            // Over the monthly quota nothing is sent or retried; what is buffered
            // waits for the pause to end (telemetry::quota).
            let quota_paused = self.quota.is_paused();
            if quota_paused {
                pending_since = None;
            }
            if paused_until.is_none() && !quota_paused {
                while flights.len() < self.max_in_flight() {
                    let available = self.queue.available();
                    if available == 0 {
                        pending_since = None;
                        break;
                    }
                    let since = *pending_since.get_or_insert_with(Instant::now);
                    if available < self.cfg.batch_size && since.elapsed() < self.cfg.flush_interval
                    {
                        break; // neither a full batch nor an old enough one
                    }
                    let Some(batch) = self.drain().await else {
                        break;
                    };
                    // The rest waits for its own full batch or its own age.
                    pending_since = None;
                    flights.launch(self.clone(), Arc::clone(&ingest_url), batch);
                }
            }

            // Wake for a finished request, the end of a pause, or the next poll.
            let wake = paused_until
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(poll)
                .max(Duration::from_millis(1));
            tokio::select! {
                Some((batch, outcome)) = flights.next(), if !flights.is_empty() => {
                    match self.settle(batch, outcome).await {
                        Ok(()) => backoff.reset(),
                        Err(()) => {
                            let delay = backoff.next_delay();
                            tracing::warn!(retry_in_ms = delay.as_millis() as u64, "Telemetry delivery paused after a retryable failure");
                            paused_until = Some(Instant::now() + delay);
                        }
                    }
                }
                _ = tokio::time::sleep(wake) => {}
            }

            if last_stats_at.elapsed() >= STATS_LOG_EVERY {
                last_stats_at = Instant::now();
                let stats = self.queue.stats();
                if stats_moved(&last_stats, &stats) {
                    self.log_stats(&stats, flights.len());
                }
                last_stats = stats;
            }
        }
    }

    /// Delivers everything buffered, `max_in_flight` batches at a time, until the
    /// queue is empty or a delivery fails. Returns how many events the API
    /// accepted. Used once more at shutdown.
    pub async fn deliver_pending(&self) -> usize {
        let ingest_url: Arc<str> = self.ingest_url().into();
        let mut flights = Flights::default();
        let mut delivered = 0;
        let mut failed = false;
        loop {
            while !failed && !self.quota.is_paused() && flights.len() < self.max_in_flight() {
                let Some(batch) = self.drain().await else {
                    break;
                };
                flights.launch(self.clone(), Arc::clone(&ingest_url), batch);
            }
            let Some((batch, outcome)) = flights.next().await else {
                return delivered;
            };
            if let Ok(sent) = &outcome {
                delivered += sent.delivered;
            }
            if self.settle(batch, outcome).await.is_err() {
                failed = true; // let what is in flight finish, start nothing new
            }
        }
    }

    /// The next batch, read on the blocking pool (the disk queue reads its spool).
    async fn drain(&self) -> Option<Batch> {
        let queue = Arc::clone(&self.queue);
        let max = self.cfg.batch_size.max(1);
        match tokio::task::spawn_blocking(move || queue.drain_batch(max)).await {
            Ok(batch) if !batch.events.is_empty() => Some(batch),
            _ => None,
        }
    }

    /// Acks a batch whose requests completed (delivered or refused for good), or
    /// releases it for a retry. `Err` when the delivery should back off.
    async fn settle(&self, batch: Batch, outcome: Result<Sent, Failure>) -> Result<(), ()> {
        let count = batch.events.len();
        let queue = Arc::clone(&self.queue);
        match outcome {
            Ok(sent) => {
                self.shared
                    .delivered
                    .fetch_add(sent.delivered as u64, Ordering::Relaxed);
                if sent.delivered > 0 {
                    self.shared
                        .last_delivery_ms
                        .store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
                }
                let _ = tokio::task::spawn_blocking(move || queue.ack(&batch)).await;
                Ok(())
            }
            // Over the quota: the batch stays buffered for after the pause, which the
            // gate already entered (and logged once). Not a retry, not a backoff.
            Err(Failure::Quota) => {
                let _ = tokio::task::spawn_blocking(move || queue.nack(batch)).await;
                Ok(())
            }
            Err(Failure::Retry(reason)) => {
                self.shared.retries.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %reason, count, "Telemetry delivery failed; will retry");
                let _ = tokio::task::spawn_blocking(move || queue.nack(batch)).await;
                Err(())
            }
        }
    }

    /// Sends `events`, splitting on 413. `Err` (retry the whole batch) as soon as a
    /// part fails retryably; parts already delivered are sent again then, which the
    /// API deduplicates by event id.
    async fn deliver_events(&self, url: &str, events: &[TelemetryEvent]) -> Result<Sent, Failure> {
        match self.post(url, events).await {
            Ok(()) => Ok(Sent {
                delivered: events.len(),
                dropped: 0,
            }),
            Err(DeliveryError::Permanent { status: 413 }) if events.len() > 1 => {
                let (a, b) = events.split_at(events.len() / 2);
                let first = Box::pin(self.deliver_events(url, a)).await?;
                let second = Box::pin(self.deliver_events(url, b)).await?;
                Ok(Sent {
                    delivered: first.delivered + second.delivered,
                    dropped: first.dropped + second.dropped,
                })
            }
            Err(DeliveryError::Permanent { status }) => {
                // The API refused this payload and always will: retrying re-sends
                // the same bytes and would park the batch at the head of the queue,
                // blocking every event behind it. Dropping loses these events,
                // which is why it is logged at error with the status that caused it.
                tracing::error!(
                    status = status,
                    count = events.len(),
                    "Telemetry batch rejected permanently; events dropped"
                );
                self.shared
                    .dropped_permanent
                    .fetch_add(events.len() as u64, Ordering::Relaxed);
                Ok(Sent {
                    delivered: 0,
                    dropped: events.len(),
                })
            }
            Err(DeliveryError::Retryable { reason }) => Err(Failure::Retry(reason)),
            Err(DeliveryError::Quota { resets_at }) => {
                self.quota.pause(resets_at, "ingest");
                Err(Failure::Quota)
            }
        }
    }

    /// One POST. A compressed body refused with 400/415 is sent again uncompressed;
    /// if that is accepted, compression stays off for the rest of the process.
    async fn post(&self, url: &str, events: &[TelemetryEvent]) -> Result<(), DeliveryError> {
        let gzip = self.shared.gzip.load(Ordering::Relaxed);
        let first = self.send(url, events, gzip).await;
        match first {
            Err(DeliveryError::Permanent { status: 400 | 415 }) if gzip => {
                let plain = self.send(url, events, false).await;
                if plain.is_ok() && self.shared.gzip.swap(false, Ordering::Relaxed) {
                    tracing::warn!(
                        "The Vericto API refused a gzip-compressed telemetry body and accepted it uncompressed; sending uncompressed from now on"
                    );
                }
                plain
            }
            other => other,
        }
    }

    async fn send(
        &self,
        url: &str,
        events: &[TelemetryEvent],
        gzip: bool,
    ) -> Result<(), DeliveryError> {
        let body = encode_body(events, gzip).await?;
        let mut req = self
            .client
            .post(url)
            .header("X-API-Key", &self.cfg.api_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if gzip {
            req = req.header(reqwest::header::CONTENT_ENCODING, "gzip");
        }
        let started = Instant::now();
        let res = req.body(body).send().await;
        let us = started.elapsed().as_micros() as u64;
        self.shared.requests.fetch_add(1, Ordering::Relaxed);
        self.shared.last_request_us.store(us, Ordering::Relaxed);
        self.shared.max_request_us.fetch_max(us, Ordering::Relaxed);

        let res = res.map_err(|e| DeliveryError::Retryable {
            reason: e.to_string(),
        })?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if let Some(resets_at) = quota_reset_of(res).await {
                return Err(DeliveryError::Quota { resets_at });
            }
            return Err(DeliveryError::Retryable {
                reason: format!("ingest returned HTTP {status}"),
            });
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

    /// Events the API answered 2xx for, and events it refused permanently
    /// (dropped), since the process started. Reported in the rule-sync heartbeat
    /// (see `telemetry::heartbeat`).
    pub fn delivery_counters(&self) -> DeliveryCounters {
        DeliveryCounters {
            delivered: self.shared.delivered.load(Ordering::Relaxed),
            dropped_permanent: self.shared.dropped_permanent.load(Ordering::Relaxed),
        }
    }

    /// Where delivery stands now (since 4.12.0).
    pub fn delivery_state(&self) -> DeliveryState {
        let ms = self.shared.last_delivery_ms.load(Ordering::Relaxed);
        DeliveryState {
            last_delivery_at: (ms > 0)
                .then(|| SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)),
            in_flight: self.shared.in_flight.load(Ordering::Relaxed),
            oldest_in_flight: self
                .shared
                .in_flight_oldest
                .lock()
                .ok()
                .and_then(|held| held.iter().map(|(_, at)| *at).min()),
        }
    }

    fn log_stats(&self, s: &QueueStats, in_flight: usize) {
        let d = &self.shared;
        tracing::info!(
            queue_depth = s.queue_depth,
            spooled = s.spooled,
            spool_bytes = s.spool_bytes,
            enqueued = s.enqueued,
            dropped_queue_full = s.dropped_queue_full,
            evicted_oldest = s.evicted_oldest,
            write_failures = s.write_failures,
            batches_written = s.batches_written,
            last_batch_write_ms = s.last_batch_write_us as f64 / 1000.0,
            max_batch_write_ms = s.max_batch_write_us as f64 / 1000.0,
            delivered = d.delivered.load(Ordering::Relaxed),
            requests = d.requests.load(Ordering::Relaxed),
            retries = d.retries.load(Ordering::Relaxed),
            dropped_permanent = d.dropped_permanent.load(Ordering::Relaxed),
            dropped_quota = s.dropped_quota,
            quota_paused = self.quota.is_paused(),
            in_flight,
            last_request_ms = d.last_request_us.load(Ordering::Relaxed) as f64 / 1000.0,
            max_request_ms = d.max_request_us.load(Ordering::Relaxed) as f64 / 1000.0,
            gzip = d.gzip.load(Ordering::Relaxed),
            "Telemetry pipeline stats"
        );
    }
}

/// The batches in flight. Each batch stays here, not in its task, so that even a
/// task that panicked hands its batch back to be released rather than leaving its
/// events held for the life of the process.
#[derive(Default)]
struct Flights {
    tasks: JoinSet<Result<Sent, Failure>>,
    batches: HashMap<tokio::task::Id, Arc<Batch>>,
}

impl Flights {
    fn len(&self) -> usize {
        self.tasks.len()
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn launch(&mut self, reporter: Reporter, url: Arc<str>, batch: Batch) {
        let batch = Arc::new(batch);
        let held = Arc::clone(&batch);
        // Events leave in FIFO order, so the first is the batch's oldest.
        let oldest = held
            .events
            .first()
            .map(|e| crate::telemetry::queue::event_time(&e.occurred_at));
        let flight = InFlight::new(&reporter.shared, oldest);
        let handle = self.tasks.spawn(async move {
            let _flight = flight;
            reporter.deliver_events(&url, &held.events).await
        });
        self.batches.insert(handle.id(), batch);
    }

    /// The next finished batch and its outcome; `None` when nothing is in flight.
    async fn next(&mut self) -> Option<(Batch, Result<Sent, Failure>)> {
        loop {
            let (id, outcome) = match self.tasks.join_next_with_id().await? {
                Ok((id, outcome)) => (id, outcome),
                Err(e) => (
                    e.id(),
                    Err(Failure::Retry(format!("delivery task failed: {e}"))),
                ),
            };
            let Some(batch) = self.batches.remove(&id) else {
                continue;
            };
            // The task has ended, so this is the only reference left.
            match Arc::try_unwrap(batch) {
                Ok(batch) => return Some((batch, outcome)),
                Err(_) => {
                    tracing::error!("Telemetry batch still referenced after its delivery ended");
                    continue;
                }
            }
        }
    }
}

/// Exponential backoff between retryable failures: base, 2x base, ... up to max.
struct Backoff {
    base: Duration,
    max: Duration,
    failures: u32,
}

impl Backoff {
    fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max: max.max(base),
            failures: 0,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let factor = 1u32 << self.failures.min(16);
        self.failures = self.failures.saturating_add(1);
        self.base.saturating_mul(factor).min(self.max)
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

/// The request body, serialized (and compressed) on the blocking pool so a
/// 500-event batch never occupies a runtime thread the query path also uses.
async fn encode_body(events: &[TelemetryEvent], gzip: bool) -> Result<Vec<u8>, DeliveryError> {
    let json = serde_json::to_vec(&serde_json::json!({ "events": events })).map_err(|e| {
        DeliveryError::Retryable {
            reason: format!("serialize: {e}"),
        }
    })?;
    if !gzip {
        return Ok(json);
    }
    tokio::task::spawn_blocking(move || {
        let mut enc = flate2::write::GzEncoder::new(
            Vec::with_capacity(json.len() / 4),
            flate2::Compression::fast(),
        );
        enc.write_all(&json)?;
        enc.finish()
    })
    .await
    .map_err(|e| DeliveryError::Retryable {
        reason: format!("compress: {e}"),
    })?
    .map_err(|e| DeliveryError::Retryable {
        reason: format!("compress: {e}"),
    })
}

fn stats_moved(before: &QueueStats, now: &QueueStats) -> bool {
    now.enqueued != before.enqueued
        || now.dropped_queue_full != before.dropped_queue_full
        || now.evicted_oldest != before.evicted_oldest
        || now.write_failures != before.write_failures
        || now.queue_depth > 0
        || now.spooled > 0
}

/// Why a batch was not delivered, and whether sending the same bytes again could
/// ever succeed.
enum DeliveryError {
    /// The API will refuse this payload no matter how often it is sent.
    Permanent { status: u16 },
    /// Transport error, or a server-side condition that may clear.
    Retryable { reason: String },
    /// 429 QUOTA_EXCEEDED: refused until the monthly quota resets (4.12.0).
    Quota {
        resets_at: chrono::DateTime<chrono::Utc>,
    },
}

/// Why a batch's requests did not all succeed.
#[derive(Debug)]
enum Failure {
    /// Retry with backoff.
    Retry(String),
    /// Over the monthly quota: telemetry is paused (the gate is already entered).
    Quota,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Retry(reason) => f.write_str(reason),
            Failure::Quota => f.write_str("monthly quota exceeded"),
        }
    }
}

/// The quota reset a 429 announces: `QUOTA_EXCEEDED` in its body and a reset time
/// (`error.resets_at`, else `Retry-After`). `None` for any other 429, including a
/// quota 429 from an API before 4.12's, which says no reset time: those keep the
/// backoff and retries of 4.11.
async fn quota_reset_of(res: reqwest::Response) -> Option<chrono::DateTime<chrono::Utc>> {
    let retry_after = res
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    // The error body is small; a larger one is not the API's quota answer.
    let body = res.bytes().await.ok()?;
    if body.len() > 64 * 1024 {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let error = json.get("error")?;
    if error.get("code")?.as_str()? != QUOTA_EXCEEDED_CODE {
        return None;
    }
    crate::telemetry::quota::reset_time(
        error.get("resets_at").and_then(|v| v.as_str()),
        retry_after,
        chrono::Utc::now(),
    )
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
/// refuses a field, 413 when the batch exceeds the API's body limit, 415 when it
/// does not take the body's encoding, 422. Those are properties of the bytes, so a
/// retry sends the same rejected bytes. (A 413 is split and a 400/415 to a
/// compressed body is resent uncompressed before anything is dropped.)
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
        | StatusCode::UNSUPPORTED_MEDIA_TYPE
        | StatusCode::UNPROCESSABLE_ENTITY => Disposition::Permanent,
        _ => Disposition::Retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    /// How the stand-in for `/api/v1/ingest/events` answers one request.
    #[derive(Clone, Copy)]
    enum Answer {
        Ok,
        Status(u16),
        /// 429 with the API's quota body (`code`), and the reset time in the body
        /// (`resets_at`) and/or a `Retry-After` header.
        Quota {
            code: &'static str,
            resets_at: Option<&'static str>,
            retry_after: Option<u64>,
        },
    }

    type Rule = Arc<dyn Fn(usize, &Request) -> Answer + Send + Sync>;

    /// What the stand-in saw of a request.
    #[derive(Clone, Debug)]
    struct Request {
        gzip: bool,
        ids: Vec<String>,
    }

    /// A stand-in for `/api/v1/ingest/events`: decodes gzip bodies, records every
    /// request and the event ids of the accepted ones, answers by `rule`, and holds
    /// each request for `delay` (to have several in flight).
    struct MockIngest {
        url: String,
        /// Event ids of the requests answered 2xx, in order of acceptance.
        seen: Arc<Mutex<Vec<String>>>,
        requests: Arc<Mutex<Vec<Request>>>,
        max_concurrent: Arc<AtomicUsize>,
        _server: tokio::task::JoinHandle<()>,
    }

    async fn mock_with(rule: Rule, delay: Duration) -> MockIngest {
        use axum::response::IntoResponse;
        use axum::{Router, body::Bytes, http::HeaderMap, http::StatusCode as S, routing::post};
        let seen = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let app = {
            let (seen, requests, max_concurrent) =
                (seen.clone(), requests.clone(), max_concurrent.clone());
            Router::new().route(
                "/api/v1/ingest/events",
                post(move |headers: HeaderMap, body: Bytes| {
                    let (seen, requests, max_concurrent, current, calls, rule) = (
                        seen.clone(),
                        requests.clone(),
                        max_concurrent.clone(),
                        current.clone(),
                        calls.clone(),
                        rule.clone(),
                    );
                    async move {
                        let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                        max_concurrent.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(delay).await;
                        current.fetch_sub(1, Ordering::SeqCst);

                        let gzip = headers.get("content-encoding").is_some_and(|v| v == "gzip");
                        let raw = if gzip {
                            let mut out = Vec::new();
                            std::io::Read::read_to_end(
                                &mut flate2::read::GzDecoder::new(&body[..]),
                                &mut out,
                            )
                            .unwrap();
                            out
                        } else {
                            body.to_vec()
                        };
                        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                        let ids: Vec<String> = json["events"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|e| e["event_id"].as_str().unwrap().to_string())
                            .collect();
                        let req = Request { gzip, ids };
                        let n = calls.fetch_add(1, Ordering::SeqCst);
                        requests.lock().unwrap().push(req.clone());
                        match rule(n, &req) {
                            Answer::Ok => {
                                seen.lock().unwrap().extend(req.ids);
                                S::ACCEPTED.into_response()
                            }
                            Answer::Status(code) => S::from_u16(code).unwrap().into_response(),
                            Answer::Quota {
                                code,
                                resets_at,
                                retry_after,
                            } => {
                                let mut error =
                                    serde_json::json!({ "code": code, "message": "quota" });
                                if let Some(r) = resets_at {
                                    error["resets_at"] = r.into();
                                }
                                let mut res = (
                                    S::TOO_MANY_REQUESTS,
                                    axum::Json(serde_json::json!({ "error": error })),
                                )
                                    .into_response();
                                if let Some(secs) = retry_after {
                                    res.headers_mut()
                                        .insert("retry-after", secs.to_string().parse().unwrap());
                                }
                                res
                            }
                        }
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
            requests,
            max_concurrent,
            _server: server,
        }
    }

    /// Fails the first `fail_first` requests with a 503.
    async fn mock_ingest(fail_first: usize) -> MockIngest {
        mock_with(
            Arc::new(move |n, _| {
                if n < fail_first {
                    Answer::Status(503)
                } else {
                    Answer::Ok
                }
            }),
            Duration::ZERO,
        )
        .await
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
            delivery: crate::config::DeliveryTuning {
                retry_base: Duration::from_millis(20),
                retry_max: Duration::from_millis(200),
                ..crate::config::DeliveryTuning::default()
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

    fn all_seen(seen: &Mutex<Vec<String>>, prefix: &str, n: usize) -> bool {
        let seen = seen.lock().unwrap();
        (0..n).all(|i| seen.contains(&format!("{prefix}{i}")))
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
        wait_for(|| all_seen(&seen, "d", 350)).await;
        wait_for(|| queue.stats().spooled == 0 && queue.stats().queue_depth == 0).await;
        assert_eq!(queue.stats().dropped_queue_full, 0);
    }

    /// The delivery lag counts a memory batch while it is in flight (it has left
    /// the ring but is not delivered), and the last 2xx is recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delivery_state_tracks_requests_in_flight_and_the_last_2xx() {
        let api = mock_with(Arc::new(|_, _| Answer::Ok), Duration::from_millis(300)).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(&api.url, dir.path());
        cfg.buffer_mode = crate::config::BufferMode::Memory;
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        let reporter = Reporter::new(cfg, queue.clone());
        assert_eq!(reporter.delivery_state(), DeliveryState::default());
        tokio::spawn(reporter.clone().run());
        for i in 0..10 {
            queue.push(event(format!("m{i}")));
        }
        wait_for(|| reporter.delivery_state().in_flight > 0).await;
        assert!(reporter.delivery_state().oldest_in_flight.is_some());
        assert_eq!(queue.oldest_buffered_at(), None, "the batch left the ring");
        wait_for(|| reporter.delivery_state().last_delivery_at.is_some()).await;
        wait_for(|| reporter.delivery_state().in_flight == 0).await;
        assert_eq!(reporter.delivery_state().oldest_in_flight, None);
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

    /// The 4.11 pipeline: with a slow API, up to `max_in_flight` requests are
    /// outstanding at once (never more), every event is delivered exactly once
    /// (concurrent batches never share an event), and while a request is in flight
    /// its events are still on disk: nothing is acked before its 2xx.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batches_are_sent_concurrently_and_acked_only_after_their_2xx() {
        let api = mock_with(Arc::new(|_, _| Answer::Ok), Duration::from_millis(300)).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(&api.url, dir.path());
        cfg.batch_size = 50;
        cfg.flush_interval = Duration::from_secs(60); // only full batches go
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        for i in 0..1_000 {
            queue.push(event(format!("c{i}")));
        }
        let q = queue.clone();
        assert!(
            tokio::task::spawn_blocking(move || q.flush(Duration::from_secs(5)))
                .await
                .unwrap()
        );
        tokio::spawn(Reporter::new(cfg, queue.clone()).run());

        // The first round is in flight and none of it answered yet.
        let requests = api.requests.clone();
        let max_concurrent = api.max_concurrent.clone();
        wait_for(|| max_concurrent.load(Ordering::SeqCst) >= 4).await;
        assert!(requests.lock().unwrap().is_empty());
        assert_eq!(queue.stats().spooled, 1_000, "nothing acked before a 2xx");
        assert_eq!(
            queue.available(),
            1_000 - 4 * 50,
            "in-flight events are held"
        );

        let seen = api.seen.clone();
        wait_for(|| seen.lock().unwrap().len() >= 1_000).await;
        wait_for(|| queue.stats().spooled == 0).await;
        assert_eq!(api.max_concurrent.load(Ordering::SeqCst), 4);
        let seen = api.seen.lock().unwrap();
        let unique: std::collections::HashSet<&String> = seen.iter().collect();
        assert_eq!(seen.len(), 1_000, "no event sent twice");
        assert_eq!(unique.len(), 1_000);
        assert!(api.requests.lock().unwrap().iter().all(|r| r.gzip));
    }

    /// Acks out of order and a failure in the middle: requests fail at random (one
    /// in three, the first time each batch is tried). Every event still arrives, and
    /// the spool ends empty with no file left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failures_among_concurrent_batches_lose_nothing() {
        let tried = Arc::new(Mutex::new(std::collections::HashSet::<String>::new()));
        let rule: Rule = {
            let tried = tried.clone();
            Arc::new(move |n, req| {
                let first_try = tried.lock().unwrap().insert(req.ids[0].clone());
                if first_try && n % 3 == 1 {
                    Answer::Status(503)
                } else {
                    Answer::Ok
                }
            })
        };
        // Varying delays make the responses arrive out of order.
        let api = mock_with(rule, Duration::from_millis(30)).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(&api.url, dir.path());
        cfg.batch_size = 40;
        cfg.spool.segment_max = 100; // batches split segments and span two of them
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        tokio::spawn(Reporter::new(cfg, queue.clone()).run());
        for i in 0..1_000 {
            queue.push(event(format!("f{i}")));
        }
        let seen = api.seen.clone();
        wait_for(|| all_seen(&seen, "f", 1_000)).await;
        wait_for(|| queue.stats().spooled == 0 && queue.stats().queue_depth == 0).await;
        let files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .count();
        assert_eq!(files, 0, "every delivered segment is removed");
    }

    /// Whichever comes first: a full batch goes at once, a partial one only when
    /// its oldest event has waited the flush interval.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_batch_goes_at_once_and_a_partial_one_when_it_ages() {
        for mode in [
            crate::config::BufferMode::Memory,
            crate::config::BufferMode::Disk,
        ] {
            let api = mock_ingest(0).await;
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = cfg(&api.url, dir.path());
            cfg.buffer_mode = mode;
            cfg.batch_size = 20;
            cfg.flush_interval = Duration::from_millis(1_500);
            let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
            tokio::spawn(Reporter::new(cfg, queue.clone()).run());

            let started = Instant::now();
            for i in 0..20 {
                queue.push(event(format!("full{i}")));
            }
            let seen = api.seen.clone();
            wait_for(|| all_seen(&seen, "full", 20)).await;
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "{mode:?}: a full batch must not wait for the interval"
            );

            let started = Instant::now();
            for i in 0..5 {
                queue.push(event(format!("part{i}")));
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert!(
                !all_seen(&api.seen, "part", 5),
                "{mode:?}: a partial batch waits for its age"
            );
            wait_for(|| all_seen(&seen, "part", 5)).await;
            let waited = started.elapsed();
            assert!(
                waited >= Duration::from_millis(1_400) && waited < Duration::from_millis(3_000),
                "{mode:?}: partial batch sent after {waited:?}"
            );
            assert_eq!(api.requests.lock().unwrap().len(), 2, "{mode:?}");
        }
    }

    /// An API that does not take gzip (an older one: 415, or a JSON parser that
    /// reads the compressed bytes: 400) still gets every event, uncompressed, and the
    /// reporter stops compressing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_api_without_gzip_gets_the_events_uncompressed() {
        for refusal in [415u16, 400] {
            let api = mock_with(
                Arc::new(move |_, req| {
                    if req.gzip {
                        Answer::Status(refusal)
                    } else {
                        Answer::Ok
                    }
                }),
                Duration::ZERO,
            )
            .await;
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = cfg(&api.url, dir.path());
            cfg.batch_size = 10;
            let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
            tokio::spawn(Reporter::new(cfg, queue.clone()).run());
            for i in 0..50 {
                queue.push(event(format!("g{i}")));
            }
            let seen = api.seen.clone();
            wait_for(|| all_seen(&seen, "g", 50)).await;
            wait_for(|| queue.stats().spooled == 0).await;
            let requests = api.requests.lock().unwrap();
            let compressed = requests.iter().filter(|r| r.gzip).count();
            // Batches launched before the first refusal came back were compressed;
            // after it, none.
            assert!(
                compressed <= 4,
                "{refusal}: {compressed} compressed requests"
            );
            assert!(!requests.last().unwrap().gzip);
        }
    }

    /// A 413 splits the batch until the parts fit; nothing is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_over_the_body_limit_is_split_not_dropped() {
        let api = mock_with(
            Arc::new(|_, req| {
                if req.ids.len() > 7 {
                    Answer::Status(413)
                } else {
                    Answer::Ok
                }
            }),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(&api.url, dir.path());
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        tokio::spawn(Reporter::new(cfg, queue.clone()).run());
        for i in 0..100 {
            queue.push(event(format!("b{i}")));
        }
        let seen = api.seen.clone();
        wait_for(|| all_seen(&seen, "b", 100)).await;
        wait_for(|| queue.stats().spooled == 0).await;
        assert_eq!(api.seen.lock().unwrap().len(), 100);
    }

    /// A permanent refusal drops the batch (logged) instead of blocking the queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permanent_refusal_drops_the_batch_and_the_queue_moves_on() {
        let api = mock_with(
            Arc::new(|_, req| {
                if req.ids.iter().any(|id| id == "p3") {
                    Answer::Status(422)
                } else {
                    Answer::Ok
                }
            }),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(&api.url, dir.path());
        cfg.batch_size = 5;
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        for i in 0..20 {
            queue.push(event(format!("p{i}")));
        }
        let q = queue.clone();
        assert!(
            tokio::task::spawn_blocking(move || q.flush(Duration::from_secs(5)))
                .await
                .unwrap()
        );
        tokio::spawn(Reporter::new(cfg, queue.clone()).run());
        wait_for(|| queue.stats().spooled == 0).await;
        let seen = api.seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            15,
            "the batch holding p3 is dropped, the rest delivered"
        );
        assert!(!seen.contains(&"p3".to_string()));
    }

    /// Over the monthly quota (4.12.0): the first 429 QUOTA_EXCEEDED pauses
    /// telemetry. Nothing more is sent or retried, new events do not reach the
    /// spool (counted as dropped_quota), and what was buffered waits. When the
    /// pause is lifted (a rule sync says "ok"), the buffered events are delivered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_quota_429_pauses_telemetry_until_it_is_lifted() {
        let lifted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let api = {
            let lifted = lifted.clone();
            mock_with(
                Arc::new(move |_, _| {
                    if lifted.load(Ordering::SeqCst) {
                        Answer::Ok
                    } else {
                        Answer::Quota {
                            code: "QUOTA_EXCEEDED",
                            resets_at: Some("2099-01-01T00:00:00.000Z"),
                            retry_after: Some(3600),
                        }
                    }
                }),
                Duration::ZERO,
            )
            .await
        };
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(&api.url, dir.path());
        cfg.batch_size = 10;
        let gate = Arc::new(QuotaGate::new());
        let queue: Arc<dyn EventQueue> = Arc::new(crate::telemetry::quota::QuotaGatedQueue::new(
            crate::telemetry::new_queue(&cfg),
            gate.clone(),
        ));
        for i in 0..10 {
            queue.push(event(format!("q{i}")));
        }
        tokio::spawn(
            Reporter::new(cfg, queue.clone())
                .with_quota_gate(gate.clone())
                .run(),
        );
        wait_for(|| gate.is_paused()).await;
        let sent = api.requests.lock().unwrap().len();
        assert_eq!(sent, 1, "one request, then the pause");

        // While paused: no request, no retry, the spool does not grow.
        for i in 0..200 {
            queue.push(event(format!("x{i}")));
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            api.requests.lock().unwrap().len(),
            1,
            "nothing sent while paused"
        );
        let s = queue.stats();
        assert_eq!(s.spooled, 10, "the paused events never reached the spool");
        assert_eq!(s.dropped_quota, 200);
        assert!(api.seen.lock().unwrap().is_empty());

        // Lifted: the buffered batch goes out, and new events are recorded again.
        lifted.store(true, Ordering::SeqCst);
        assert!(gate.resume("rules_sync"));
        queue.push(event("after".to_string()));
        let seen = api.seen.clone();
        wait_for(|| {
            all_seen(&seen, "q", 10) && seen.lock().unwrap().contains(&"after".to_string())
        })
        .await;
        wait_for(|| queue.stats().spooled == 0).await;
    }

    /// Any other 429 keeps 4.11's backoff and retries: a rate limit, and a quota
    /// 429 from an API that does not say when the quota resets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn other_429s_are_retried_without_pausing() {
        for answer in [
            Answer::Status(429),
            Answer::Quota {
                code: "RATE_LIMIT_EXCEEDED",
                resets_at: Some("2099-01-01T00:00:00.000Z"),
                retry_after: Some(60),
            },
            Answer::Quota {
                code: "QUOTA_EXCEEDED",
                resets_at: None,
                retry_after: None,
            },
        ] {
            let api = mock_with(
                Arc::new(move |n, _| if n < 2 { answer } else { Answer::Ok }),
                Duration::ZERO,
            )
            .await;
            let dir = tempfile::tempdir().unwrap();
            let cfg = cfg(&api.url, dir.path());
            let gate = Arc::new(QuotaGate::new());
            let queue: Arc<dyn EventQueue> =
                Arc::new(crate::telemetry::quota::QuotaGatedQueue::new(
                    crate::telemetry::new_queue(&cfg),
                    gate.clone(),
                ));
            tokio::spawn(
                Reporter::new(cfg, queue.clone())
                    .with_quota_gate(gate.clone())
                    .run(),
            );
            for i in 0..5 {
                queue.push(event(format!("r{i}")));
            }
            let seen = api.seen.clone();
            wait_for(|| all_seen(&seen, "r", 5)).await;
            assert!(!gate.is_paused());
            assert_eq!(queue.stats().dropped_quota, 0);
            assert!(api.requests.lock().unwrap().len() >= 3, "retried");
        }
    }

    /// Shutdown while paused sends nothing; the spool keeps the events.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_while_paused_sends_nothing() {
        let api = mock_ingest(0).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(&api.url, dir.path());
        let gate = Arc::new(QuotaGate::new());
        let queue: Arc<dyn EventQueue> = Arc::from(crate::telemetry::new_queue(&cfg));
        for i in 0..5 {
            queue.push(event(format!("z{i}")));
        }
        let q = queue.clone();
        assert!(
            tokio::task::spawn_blocking(move || q.flush(Duration::from_secs(5)))
                .await
                .unwrap()
        );
        gate.pause(chrono::Utc::now() + chrono::Duration::hours(1), "ingest");
        let reporter = Reporter::new(cfg, queue.clone()).with_quota_gate(gate);
        assert_eq!(reporter.deliver_pending().await, 0);
        assert!(api.requests.lock().unwrap().is_empty());
        assert_eq!(queue.stats().spooled, 5);
    }

    #[test]
    fn backoff_doubles_up_to_its_maximum_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(10));
        let delays: Vec<u64> = (0..6).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 10, 10]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    /// Payload-shaped rejections: the API refuses these bytes, so re-sending them
    /// cannot succeed. 400 is the ingest schema rejecting a field, 413 the body
    /// limit. These are the two that poisoned the queue.
    #[test]
    fn payload_rejections_are_permanent() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
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
