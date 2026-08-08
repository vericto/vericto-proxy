//! Background reporter: periodically drains the event queue and POSTs batches
//! to the Vericto API. Delivery failures never propagate to the SQL path.

use std::sync::Arc;
use std::time::Duration;

use crate::config::ControlPlaneConfig;
use crate::telemetry::queue::EventQueue;

pub struct Reporter {
    cfg: ControlPlaneConfig,
    queue: Arc<dyn EventQueue>,
    client: reqwest::Client,
}

impl Reporter {
    pub fn new(cfg: ControlPlaneConfig, queue: Arc<dyn EventQueue>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build telemetry HTTP client");
        Self { cfg, queue, client }
    }

    /// Runs forever, flushing on the configured interval.
    pub async fn run(self) {
        let ingest_url = format!("{}/api/v1/ingest/events", self.cfg.api_url);
        let mut ticker = tokio::time::interval(self.cfg.flush_interval);

        loop {
            ticker.tick().await;
            // Drain and deliver everything currently buffered, in batches.
            loop {
                let batch = self.queue.drain_batch(self.cfg.batch_size);
                if batch.events.is_empty() {
                    break;
                }
                match self.deliver(&ingest_url, &batch.events).await {
                    Ok(()) => self.queue.ack(&batch),
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
                        self.queue.ack(&batch);
                    }
                    Err(DeliveryError::Retryable { reason }) => {
                        tracing::warn!(error = %reason, count = batch.events.len(), "Telemetry delivery failed; will retry");
                        self.queue.nack(batch);
                        break; // back off until next tick
                    }
                }
            }
        }
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
