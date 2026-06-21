//! Background reporter: periodically drains the event queue and POSTs batches
//! to the Vetro API. Delivery failures never propagate to the SQL path.

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
                    Err(e) => {
                        tracing::warn!(error = %e, count = batch.events.len(), "Telemetry delivery failed; will retry");
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
    ) -> Result<(), String> {
        let body = serde_json::json!({ "events": events });
        let res = self
            .client
            .post(url)
            .header("X-API-Key", &self.cfg.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("ingest returned HTTP {}", res.status()))
        }
    }
}
