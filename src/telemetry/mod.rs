//! Outbound telemetry: buffers query evaluations and ships them to the Vericto
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
    /// "ALLOWED" | "BLOCKED" | "FLAGGED" | "MONITORED" | "PARSE_ERROR"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_node_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Resolved enforcement action: "block" | "flag" | "monitor".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_action: Option<String>,
    /// Parser error message for PARSE_ERROR events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    pub occurred_at: String,
}

/// Maximum `query_text` shipped per event, in bytes.
///
/// The API imposes two ceilings, and the proxy previously respected neither: the
/// ingest schema caps `query_text` at 65 536, and the HTTP body limit is 1 MiB
/// for the *whole batch*.
///
/// The batch limit is the binding one. At the default `batch_size` of 100, a
/// field at the schema's own 65 536 would produce a ~6.5 MiB body — six times
/// over. 8 KiB keeps a default batch near 800 KiB, leaving room for the rest of
/// each event and for JSON escaping (quotes and newlines in SQL expand).
///
/// Raising `VERICTO_TELEMETRY_BATCH_SIZE` much past 120 reopens that arithmetic.
/// The reporter's permanent-failure handling is the backstop for that case: an
/// oversized batch is dropped with a log instead of being retried forever.
pub const MAX_REPORTED_QUERY_BYTES: usize = 8 * 1024;

// The arithmetic above, enforced at compile time rather than discovered as a 413
// in production: a full batch at the default size must fit the API's body limit.
// Left side is `VERICTO_TELEMETRY_BATCH_SIZE`'s default from config.rs; right side
// is Fastify's default `bodyLimit`, which the API does not override.
const _: () = assert!(100 * MAX_REPORTED_QUERY_BYTES < 1024 * 1024);

/// Appended when the SQL was cut, so a reader can tell a truncated record from a
/// genuinely short query. Counts against [`MAX_REPORTED_QUERY_BYTES`].
const TRUNCATION_MARKER: &str = "… [truncated by vericto-proxy]";

/// Largest index `<= max` that lands on a UTF-8 character boundary.
///
/// Slicing a `String` mid-character panics, and SQL is not guaranteed ASCII —
/// identifiers, string literals and comments carry any UTF-8. `str::floor_char_
/// boundary` would do this but is still unstable.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut i = max;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Bound the SQL carried in a telemetry event to [`MAX_REPORTED_QUERY_BYTES`].
///
/// Applied when the event is built rather than when the batch is sent, so the
/// bound also covers what the queue holds: with `memory_capacity` at 10 000
/// events and no truncation, a single large query per event is enough to exhaust
/// memory, and the disk spool writes each event to a file.
pub fn truncate_reported_query(sql: &str) -> String {
    if sql.len() <= MAX_REPORTED_QUERY_BYTES {
        return sql.to_string();
    }
    let budget = MAX_REPORTED_QUERY_BYTES - TRUNCATION_MARKER.len();
    let cut = floor_char_boundary(sql, budget);
    let mut out = String::with_capacity(cut + TRUNCATION_MARKER.len());
    out.push_str(&sql[..cut]);
    out.push_str(TRUNCATION_MARKER);
    out
}

pub use queue::{EventQueue, new_queue};
pub use reporter::Reporter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_query_is_reported_verbatim() {
        let sql = "DELETE FROM users WHERE id = 1";
        assert_eq!(truncate_reported_query(sql), sql);
    }

    #[test]
    fn query_exactly_at_the_limit_is_not_truncated() {
        let sql = "a".repeat(MAX_REPORTED_QUERY_BYTES);
        let out = truncate_reported_query(&sql);
        assert_eq!(out.len(), MAX_REPORTED_QUERY_BYTES);
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn oversized_query_is_cut_within_the_limit_and_marked() {
        let sql = "a".repeat(MAX_REPORTED_QUERY_BYTES * 4);
        let out = truncate_reported_query(&sql);
        // The marker counts against the budget: the whole field must still fit,
        // because the point of the cut is to satisfy the API's ceilings.
        assert!(
            out.len() <= MAX_REPORTED_QUERY_BYTES,
            "truncated field is {} bytes, over the {MAX_REPORTED_QUERY_BYTES} limit",
            out.len()
        );
        assert!(out.ends_with(TRUNCATION_MARKER));
        assert!(out.starts_with("aaa"));
    }

    /// Slicing a multibyte string by byte offset panics unless the index lands on
    /// a character boundary. SQL carries arbitrary UTF-8 in identifiers, literals
    /// and comments, so this is the case a naive `&sql[..limit]` would crash on.
    #[test]
    fn multibyte_query_is_cut_on_a_character_boundary() {
        // 3 bytes per character, so no multiple of the character width lines up
        // with the byte budget.
        let sql = "数".repeat(MAX_REPORTED_QUERY_BYTES);
        let out = truncate_reported_query(&sql);
        assert!(out.len() <= MAX_REPORTED_QUERY_BYTES);
        assert!(out.ends_with(TRUNCATION_MARKER));
        // Round-tripping proves the cut did not split a character.
        assert_eq!(
            String::from_utf8(out.clone().into_bytes()).unwrap().len(),
            out.len()
        );
        let body = out.strip_suffix(TRUNCATION_MARKER).unwrap();
        assert!(body.chars().all(|c| c == '数'));
    }

    #[test]
    fn astral_plane_query_is_cut_on_a_character_boundary() {
        // 4 bytes per character — the widest UTF-8 encoding.
        let sql = "🙂".repeat(MAX_REPORTED_QUERY_BYTES);
        let out = truncate_reported_query(&sql);
        assert!(out.len() <= MAX_REPORTED_QUERY_BYTES);
        let body = out.strip_suffix(TRUNCATION_MARKER).unwrap();
        assert!(body.chars().all(|c| c == '🙂'));
    }
}
