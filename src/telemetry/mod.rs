//! Outbound telemetry: buffers query evaluations and ships them to the Vetro
//! API in batches over HTTPS.
//!
//! Hard invariant: telemetry MUST NEVER block or fail the SQL data path. The
//! hot path only calls `EventQueue::push` (non-blocking, bounded). A background
//! `Reporter` task drains and delivers. If the API is down, events buffer (and
//! drop oldest when full) — the proxy keeps evaluating and blocking queries.

pub mod queue;
pub mod reporter;

use serde::{Deserialize, Serialize};

/// A single evaluation result reported to the API. Mirrors the API's ingest
/// schema (apps/api/src/routes/telemetry.ts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub database_id: String,
    pub query_text: String,
    pub dialect: String,
    /// "ALLOWED" | "BLOCKED" | "PARSE_ERROR"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_node_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    pub occurred_at: String,
}

pub use queue::{new_queue, EventQueue};
pub use reporter::Reporter;
