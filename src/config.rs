//! Configuration for the control-plane link to the Vetro API.
//!
//! When the proxy runs in customer infrastructure (wire-protocol mode), it
//! reports evaluations to the Vetro API and pulls its ruleset from it, both
//! over HTTPS authenticated with a workspace API key.
//!
//! All settings are optional: if `VETRO_API_URL` / `VETRO_API_KEY` are unset,
//! the control-plane link is disabled (the proxy still evaluates with its local
//! default ruleset — useful for dev / air-gapped deployments).

use std::time::Duration;

/// Minimum allowed rules-sync polling interval.
/// Values below this are clamped to prevent excessive API load.
const RULES_SYNC_MIN_SECS: u64 = 30;

/// Where telemetry events are buffered before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMode {
    /// In-memory ring buffer (default). Lost on restart; zero disk footprint.
    Memory,
    /// On-disk spool. Survives restarts and long API outages.
    Disk,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub api_url: String,
    pub api_key: String,
    pub database_id: Option<String>,
    /// How often to poll GET /sync/rules.
    pub rules_sync_interval: Duration,
    /// Telemetry buffering strategy.
    pub buffer_mode: BufferMode,
    /// Spool directory when buffer_mode = Disk.
    pub disk_spool_path: String,
    /// Max events held in memory before the oldest are dropped.
    pub memory_capacity: usize,
    /// Max events flushed in one POST /ingest/events batch.
    pub batch_size: usize,
    /// How often the reporter flushes the buffer.
    pub flush_interval: Duration,
}

impl ControlPlaneConfig {
    /// Build from environment. Returns `None` when the link is not configured.
    pub fn from_env() -> Option<Self> {
        let api_url = std::env::var("VETRO_API_URL").ok()?;
        let api_key = std::env::var("VETRO_API_KEY").ok()?;
        if api_url.is_empty() || api_key.is_empty() {
            return None;
        }

        let rules_sync_interval = Duration::from_secs(
            // Minimum 30 seconds to avoid hammering the API.
            // Values below the minimum are silently clamped — a warning is logged
            // so operators can spot the misconfiguration without a hard failure.
            env_u64("VETRO_RULES_SYNC_INTERVAL_SECS")
                .map(|v| {
                    if v < RULES_SYNC_MIN_SECS {
                        tracing::warn!(
                            configured = v,
                            minimum = RULES_SYNC_MIN_SECS,
                            "VETRO_RULES_SYNC_INTERVAL_SECS is below the minimum — \
                             clamping to {} seconds",
                            RULES_SYNC_MIN_SECS
                        );
                        RULES_SYNC_MIN_SECS
                    } else {
                        v
                    }
                })
                .unwrap_or(300), // default: 5 min
        );

        let buffer_mode = match std::env::var("VETRO_TELEMETRY_BUFFER").as_deref() {
            Ok("disk") => BufferMode::Disk,
            _ => BufferMode::Memory,
        };

        let disk_spool_path = std::env::var("VETRO_TELEMETRY_DISK_PATH")
            .unwrap_or_else(|_| "/var/lib/vetro/spool".to_string());

        Some(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            api_key,
            database_id: std::env::var("VETRO_DATABASE_ID").ok(),
            rules_sync_interval,
            buffer_mode,
            disk_spool_path,
            memory_capacity: env_usize("VETRO_TELEMETRY_MEMORY_CAPACITY").unwrap_or(10_000),
            batch_size: env_usize("VETRO_TELEMETRY_BATCH_SIZE").unwrap_or(100),
            flush_interval: Duration::from_secs(env_u64("VETRO_TELEMETRY_FLUSH_SECS").unwrap_or(5)),
        })
    }
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}
