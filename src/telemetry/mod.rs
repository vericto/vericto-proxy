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
    ///
    /// On the wire this is `parse_error_message`, the name `/ingest/events` reads.
    /// It used to go out as `parse_error`, which the API's schema does not know and
    /// silently dropped, so no parser message ever reached the dashboard. `alias`
    /// keeps spool files written before the rename readable (`BufferMode::Disk`
    /// reads its own output back). Bounded by [`truncate_reported_parse_error`].
    #[serde(
        rename = "parse_error_message",
        alias = "parse_error",
        skip_serializing_if = "Option::is_none"
    )]
    pub parse_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    pub occurred_at: String,
    /// Every rule the query violated, not only the reported winner.
    ///
    /// The engine already computes the full set and orders it exactly as the
    /// winner is chosen (severity descending, then rule code ascending), so
    /// `violations[0]` IS the rule named in `rule_code` above. The proxy used to
    /// drop everything past that first entry, which made the audit trail record
    /// one rule for a query that broke several: measured on a live stack, a
    /// `SELECT * FROM t` violates both VERICTO-050 (no LIMIT) and VERICTO-051
    /// (star without WHERE) and only VERICTO-050 reached the database.
    ///
    /// Empty when no rule matched, and omitted from the payload in that case so
    /// an ALLOWED event stays exactly as small as it was.
    ///
    /// `default` is load-bearing: without it this type does not round-trip through its
    /// own serializer, so keep both attributes together. `skip_serializing_if` omits the key
    /// for an event with no violations, and a `Vec` field with no default makes
    /// deserialization fail with "missing field `violations`" when the key is
    /// absent. That only matters in `BufferMode::Disk`, which is the one path that
    /// reads its own output back: `DiskQueue::drain_batch` deserializes every
    /// spool file, so an ALLOWED event written to disk could never be read again.
    ///
    /// Observed on staging, where the impact reached beyond those events. The
    /// spool is drained oldest-first, and a file that fails to parse is skipped
    /// WITHOUT being removed, so the first unreadable event parks at the head of
    /// the queue forever: every later tick re-reads the same files, gets an empty
    /// batch, and stops. 536 events accumulated behind 283 unreadable ones, the
    /// oldest from nine hours earlier, with no error logged anywhere — telemetry
    /// looked simply idle. Restarting did not help, because the file is on EFS and
    /// outlives the task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<ReportedViolationPayload>,
    /// The SQL the proxy sent to the database INSTEAD of `query_text`, when a
    /// `mask` tag applied (Sensitive Column Protection). The audit keeps both:
    /// the original says what the agent asked for, this says what ran. Sanitized
    /// like `query_text` in sanitized mode, and bounded together with it (see
    /// [`truncate_reported_pair`]). Omitted when nothing was rewritten.
    ///
    /// `default` for the same reason as `violations`: the disk spool reads its
    /// own output back, and an event written without the key must still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewritten_query: Option<String>,
    /// The tagged columns the query read, as the engine identifies them (the
    /// tag's names, not the query's spelling). Omitted when none was read, so an
    /// event from a database without tags is exactly what it was before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_columns: Vec<SensitiveColumnPayload>,
    /// The database user of the session that issued the query (Postgres
    /// StartupMessage `user`, MySQL HandshakeResponse username): the identity
    /// agent-access allowlists are selected by. A user name, not query data, so
    /// it is sent in sanitized mode too. Omitted when it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_user: Option<String>,
    /// `"observe"` | `"enforce"`: the mode of the session user's agent-access
    /// policy when one applied. Omitted when the user has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy_mode: Option<String>,
    /// What the session user's allowlist denied (VERICTO-087), as the engine
    /// lists it (engine contract §3.2). Names only. Omitted when nothing was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_denied: Vec<AccessDeniedPayload>,
}

/// One reference an agent-access allowlist denied, shaped for the ingest schema:
/// `{schema, table, column, needed}`; `schema` / `column` null when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDeniedPayload {
    pub schema: Option<String>,
    pub table: String,
    pub column: Option<String>,
    /// "read" | "write" | "ddl".
    pub needed: String,
}

impl AccessDeniedPayload {
    /// The engine's reference with every name cut to [`MAX_REPORTED_NAME_BYTES`].
    pub fn from_denied(d: &vericto_engine::DeniedRef) -> Self {
        Self {
            schema: d.schema.as_deref().map(truncate_reported_name),
            table: truncate_reported_name(&d.table),
            column: d.column.as_deref().map(truncate_reported_name),
            needed: d.needed.as_str().to_string(),
        }
    }
}

/// Largest number of denied references reported per event: the ingest schema's
/// bound (`.max(64)`), which would otherwise reject the whole batch. The engine
/// sorts the list; the decision never depends on it.
pub const MAX_REPORTED_ACCESS_DENIED: usize = 64;

/// Longest name (schema, table, column) reported in `access_denied`, in bytes:
/// the ingest schema's `.max(63)`. MySQL names may be 64 characters, and a name
/// can be whatever the query wrote, so it is cut here rather than letting one
/// long name reject the batch. Bytes bound the schema's UTF-16 length from above.
pub const MAX_REPORTED_NAME_BYTES: usize = 63;

/// A name cut to [`MAX_REPORTED_NAME_BYTES`] on a character boundary.
pub fn truncate_reported_name(name: &str) -> String {
    name[..floor_char_boundary(name, MAX_REPORTED_NAME_BYTES)].to_string()
}

/// Longest `ast_node_path` reported (flat and per violation), in bytes: the
/// ingest schema's `.max(512)`. A VERICTO-087 path names what the query
/// referenced and a parse-error path carries the parser message, so either can
/// be longer; one over the cap would reject the whole batch.
pub const MAX_REPORTED_AST_PATH_BYTES: usize = 512;

/// Bound an `ast_node_path` to [`MAX_REPORTED_AST_PATH_BYTES`], marking the cut.
pub fn truncate_reported_ast_path(path: &str) -> String {
    truncate_to(path, MAX_REPORTED_AST_PATH_BYTES)
}

/// One tagged column a query read, shaped for the ingest schema:
/// `{schema, table, column, policy}`, `schema` null when the tag has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveColumnPayload {
    pub schema: Option<String>,
    pub table: String,
    pub column: String,
    /// "block" | "flag" | "mask": the tag's policy.
    pub policy: String,
}

/// Largest number of touched columns reported per event: the ingest schema's
/// own bound (`.max(64)`). One over it fails validation and the API rejects the
/// whole batch, so the list is cut here. The engine sorts it by name; a query
/// reading 64 tagged columns at once is not expected, and the decision never
/// depends on this list.
pub const MAX_REPORTED_SENSITIVE_COLUMNS: usize = 64;

/// Maximum `suggested_safe_query` shipped per violation, in bytes: the ingest
/// schema's cap (2048). A VERICTO-085 suggestion can be a whole rewritten
/// statement, so it is cut here rather than letting it reject the batch.
pub const MAX_REPORTED_SUGGESTION_BYTES: usize = 2048;

/// One violated rule, shaped for the API's ingest schema.
///
/// A local mirror of the engine's `ReportedViolation` rather than a re-export:
/// the engine type is not `Serialize`, and this is a wire contract with the API
/// that must not silently change when the engine adds a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedViolationPayload {
    pub rule_code: String,
    pub severity: String,
    /// This violation's OWN resolved action, not the event's. A per-class cap can
    /// leave a lower-severity violation resolving to a stronger action than the
    /// winner, so it cannot be derived from the event.
    pub enforcement_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_node_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_safe_query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_rows_affected: Option<i64>,
}

// `rule_id` is deliberately absent from the payload above.
//
// The API's ingest schema types it as `z.string().uuid()`. Inside this proxy a
// rule's identity IS its code — `rules_sync` stores `rule_id: code.to_string()`
// because that is what the control plane's sync endpoint keys the ruleset by — so
// sending it would put a non-UUID in a UUID field. Zod parses the whole request
// body at once, so that single field would fail validation and reject the ENTIRE
// batch with a 400, losing every event in it, not just this violation.
//
// The API resolves the code to its UUID server-side on ingest, which is the only
// side that has the catalogue. Do not add `rule_id` here without changing that
// schema first.

/// Largest number of violations reported per event.
///
/// ## Why a cap at all
///
/// The binding constraint is the API's 1 MiB HTTP body limit for the whole
/// batch, the same one [`MAX_REPORTED_QUERY_BYTES`] is sized against. At the
/// default `batch_size` of 100 the query text alone already accounts for
/// ~800 KiB, leaving roughly 2.2 KiB per event for every other field. A
/// serialized violation runs ~150–250 bytes, so 8 fits that headroom with room
/// for JSON escaping and the event's own fields.
///
/// ## Why truncating is safe
///
/// The engine's ordering means the entries kept are the most severe ones and the
/// winner — the rule that actually decided the query's fate — is always first.
/// Dropping the tail loses the least consequential findings, never the decision.
/// The catalogue is 28 standard rules plus a per-workspace handful, and a real
/// statement violates a small number of them, so this bound is not expected to
/// engage in practice; it exists so a pathological query cannot make one event
/// unboundedly large.
pub const MAX_REPORTED_VIOLATIONS: usize = 8;

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

/// Bound the original and the rewritten SQL of a masked query together, to
/// [`MAX_REPORTED_QUERY_BYTES`] for the pair.
///
/// Not each to its own limit: that would double what a masked event costs, and
/// the per-event budget is what keeps a default batch under the API's 1 MiB body
/// limit (see [`MAX_REPORTED_QUERY_BYTES`] and the compile-time check under it).
/// When both do not fit, a text shorter than half the budget is kept whole and
/// the other gets the rest; otherwise each gets half.
pub fn truncate_reported_pair(original: &str, rewritten: &str) -> (String, String) {
    if original.len() + rewritten.len() <= MAX_REPORTED_QUERY_BYTES {
        return (original.to_string(), rewritten.to_string());
    }
    let half = MAX_REPORTED_QUERY_BYTES / 2;
    let (o_budget, r_budget) = if original.len() <= half {
        (original.len(), MAX_REPORTED_QUERY_BYTES - original.len())
    } else if rewritten.len() <= half {
        (MAX_REPORTED_QUERY_BYTES - rewritten.len(), rewritten.len())
    } else {
        (half, MAX_REPORTED_QUERY_BYTES - half)
    };
    (
        truncate_to(original, o_budget),
        truncate_to(rewritten, r_budget),
    )
}

/// `s` cut to at most `max` bytes on a character boundary, marked when cut.
fn truncate_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = floor_char_boundary(s, max.saturating_sub(TRUNCATION_MARKER.len()));
    format!("{}{TRUNCATION_MARKER}", &s[..cut])
}

/// Bound a violation's suggestion to [`MAX_REPORTED_SUGGESTION_BYTES`].
pub fn truncate_reported_suggestion(s: &str) -> String {
    truncate_to(s, MAX_REPORTED_SUGGESTION_BYTES)
}

/// Maximum `parse_error_message` shipped per event, in bytes: the ingest schema's
/// own cap (2048). A longer value fails validation and the API rejects the whole
/// batch, so it is cut here. Bytes bound the schema's UTF-16 length from above.
pub const MAX_REPORTED_PARSE_ERROR_BYTES: usize = 2048;

/// Bound a parser message to [`MAX_REPORTED_PARSE_ERROR_BYTES`], marking the cut.
pub fn truncate_reported_parse_error(msg: &str) -> String {
    if msg.len() <= MAX_REPORTED_PARSE_ERROR_BYTES {
        return msg.to_string();
    }
    let cut = floor_char_boundary(
        msg,
        MAX_REPORTED_PARSE_ERROR_BYTES - TRUNCATION_MARKER.len(),
    );
    format!("{}{TRUNCATION_MARKER}", &msg[..cut])
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

    fn parse_error_event(msg: &str) -> TelemetryEvent {
        TelemetryEvent {
            event_id: "e-1".to_string(),
            database_id: "db-1".to_string(),
            query_text: "SELEC 1".to_string(),
            dialect: "postgres".to_string(),
            status: "PARSE_ERROR".to_string(),
            rule_code: Some("VERICTO-PARSE-ERROR".to_string()),
            ast_node_path: None,
            severity: Some("medium".to_string()),
            enforcement_action: Some("flag".to_string()),
            parse_error: Some(msg.to_string()),
            latency_ms: Some(0.1),
            client_ip: None,
            occurred_at: "2026-10-07T00:00:00Z".to_string(),
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            db_user: None,
            access_policy_mode: None,
            access_denied: Vec::new(),
        }
    }

    /// `/ingest/events` reads `parse_error_message`; any other key is dropped by
    /// its schema, which is how every parser message used to be lost.
    #[test]
    fn parser_message_goes_out_as_parse_error_message() {
        let json = serde_json::to_value(parse_error_event("syntax error")).unwrap();
        assert_eq!(json["parse_error_message"], "syntax error");
        assert!(json.get("parse_error").is_none());
    }

    /// A disk spool written by the previous build still carries `parse_error`.
    #[test]
    fn a_spooled_event_with_the_old_key_still_reads_back() {
        let mut json = serde_json::to_value(parse_error_event("old")).unwrap();
        let obj = json.as_object_mut().unwrap();
        let msg = obj.remove("parse_error_message").unwrap();
        obj.insert("parse_error".to_string(), msg);
        let ev: TelemetryEvent = serde_json::from_value(json).unwrap();
        assert_eq!(ev.parse_error.as_deref(), Some("old"));
    }

    #[test]
    fn a_short_pair_is_reported_verbatim() {
        let (o, r) = truncate_reported_pair("SELECT email FROM t", "SELECT 'x' AS email FROM t");
        assert_eq!(o, "SELECT email FROM t");
        assert_eq!(r, "SELECT 'x' AS email FROM t");
    }

    /// The pair shares one budget, so a masked event costs no more than any other.
    #[test]
    fn a_long_pair_fits_one_query_budget() {
        let long = "a".repeat(MAX_REPORTED_QUERY_BYTES);
        let (o, r) = truncate_reported_pair(&long, &long);
        assert!(o.len() + r.len() <= MAX_REPORTED_QUERY_BYTES);
        assert!(o.ends_with(TRUNCATION_MARKER) && r.ends_with(TRUNCATION_MARKER));

        // A short side is kept whole; the long one gets the rest.
        let (o, r) = truncate_reported_pair("SELECT 1", &long);
        assert_eq!(o, "SELECT 1");
        assert!(o.len() + r.len() <= MAX_REPORTED_QUERY_BYTES);
        let (o, r) = truncate_reported_pair(&"数".repeat(MAX_REPORTED_QUERY_BYTES), "SELECT 2");
        assert_eq!(r, "SELECT 2");
        assert!(o.len() + r.len() <= MAX_REPORTED_QUERY_BYTES);
    }

    #[test]
    fn a_suggestion_is_bounded_by_the_ingest_schema() {
        assert_eq!(truncate_reported_suggestion("LIMIT 100"), "LIMIT 100");
        let out = truncate_reported_suggestion(&"x".repeat(10_000));
        assert!(out.len() <= MAX_REPORTED_SUGGESTION_BYTES);
        assert!(out.ends_with(TRUNCATION_MARKER));
    }

    /// The masked-query fields are omitted when unused, and an event spooled
    /// before they existed still reads back.
    #[test]
    fn sensitive_fields_are_optional_both_ways() {
        let json = serde_json::to_value(parse_error_event("x")).unwrap();
        assert!(json.get("rewritten_query").is_none());
        assert!(json.get("sensitive_columns").is_none());
        let ev: TelemetryEvent = serde_json::from_value(json).unwrap();
        assert!(ev.rewritten_query.is_none() && ev.sensitive_columns.is_empty());
    }

    #[test]
    fn a_touched_column_has_the_ingest_shape() {
        let mut ev = parse_error_event("x");
        ev.sensitive_columns.push(SensitiveColumnPayload {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy: "mask".into(),
        });
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            json["sensitive_columns"],
            serde_json::json!([{"schema": null, "table": "customers", "column": "email", "policy": "mask"}])
        );
    }

    #[test]
    fn parser_message_is_bounded_by_the_ingest_schema() {
        let short = "syntax error at or near \"SELEC\"";
        assert_eq!(truncate_reported_parse_error(short), short);
        let out = truncate_reported_parse_error(&"数".repeat(MAX_REPORTED_PARSE_ERROR_BYTES));
        assert!(out.len() <= MAX_REPORTED_PARSE_ERROR_BYTES);
        assert!(out.ends_with(TRUNCATION_MARKER));
    }
}
