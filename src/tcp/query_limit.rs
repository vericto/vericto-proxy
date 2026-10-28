// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Admission limit on the size of a query the proxy will evaluate.
//!
//! Evaluation cost grows linearly with input size, and it runs before the query
//! reaches the database, so an oversized statement turns into latency the client
//! pays. Measured on `pg_query` 6.2 with a wide `INSERT … VALUES` (the shape
//! `MAX_AST_DEPTH` does not bound, since it limits nesting depth and not
//! breadth):
//!
//! | size  | evaluate | + sanitize | total |
//! |-------|----------|------------|-------|
//! | 64 KB |    20 ms |     1.7 ms |  22 ms |
//! |  1 MB |   335 ms |      28 ms | 363 ms |
//! |  4 MB |  1313 ms |     122 ms | 1435 ms |
//! | 10 MB |  3440 ms |     382 ms | 3822 ms |
//!
//! The table works out to roughly 0.33 ms/KB on the machine it was taken on (an
//! earlier version of this comment said 0.35). The proxy path measured end to
//! end is lower: added p50 grows by about 0.23 ms/KB of SQL on PostgreSQL and
//! 0.18 ms/KB on MySQL (least-squares fit; benchmark session s3-412,
//! 2026-10-16: vericto-proxy 4.12.0, vericto-engine 3.9.0, Fargate ARM64 at
//! 0.25 vCPU, TLS on both legs, multi-row `INSERT` of 10 to 1,000 rows, 0.2 to
//! 48 KB, one connection at 10 statements/s). Evaluation alone over the same
//! statements, single thread, same session: 0.22 to 0.26 ms/KB on PostgreSQL
//! and 0.06 to 0.09 ms/KB on MySQL. The cost is CPU time, so it shrinks with a
//! larger vCPU share; BENCH-2026-11 (P-size) re-measures it at 0.5 and 1 vCPU.
//!
//! Postgres framing accepts up to 64 MiB, which at 0.23 to 0.33 ms/KB
//! extrapolates to about 15 to 22 s of evaluation for a single statement.
//!
//! The limit is a *guard*, checked before parsing, so a refused query costs
//! neither the evaluation parse nor the telemetry sanitize pass.

use crate::tcp::codec_mysql::MYSQL_MAX_PACKET_LEN;
use vericto_engine::Dialect;

/// Default ceiling: 10 MiB, about 3.8 s of evaluation at the rate in the table
/// above (about 2.4 s at the 0.23 ms/KB measured end to end).
///
/// Chosen to clear realistic large statements rather than to minimise latency.
/// The shapes that legitimately get big are batch inserts and long `IN` lists —
/// 100 000 UUIDs in an `IN` list is roughly 3.8 MB, a 5 000-row insert across 20
/// columns roughly 2 MB — so this leaves headroom over both. Rejecting a
/// customer's ETL is a worse outcome than evaluating it slowly, which is why the
/// default errs high and the knob exists.
pub const DEFAULT_MAX_QUERY_BYTES: usize = 10 * 1024 * 1024;

/// Hard ceiling per wire protocol: the point past which the codec already
/// refuses the message, so configuring beyond it changes nothing.
///
/// Anchoring to the codec caps keeps this from being an arbitrary number, and it
/// differs per dialect — a single value would be meaningless on MySQL, whose
/// protocol caps a packet at 16 MiB and which this proxy does not reassemble
/// across packets.
pub fn dialect_cap(dialect: Dialect) -> usize {
    match dialect {
        // `codec::MAX_MESSAGE_LEN`, duplicated as a literal because that constant
        // is private to the Postgres codec.
        Dialect::Postgres => 64 * 1024 * 1024,
        Dialect::Mysql => MYSQL_MAX_PACKET_LEN,
        // Not served over the wire by this proxy; use the stricter cap so a
        // future protocol cannot silently inherit the most permissive one.
        _ => MYSQL_MAX_PACKET_LEN,
    }
}

/// Read `VERICTO_MAX_QUERY_BYTES`, falling back to [`DEFAULT_MAX_QUERY_BYTES`].
///
/// An unparseable or zero value falls back rather than failing startup, matching
/// how `VERICTO_HEALTHZ_PORT` treats bad input — but it warns, because silently
/// ignoring a limit an operator meant to set is how a deployment ends up running
/// something other than what its config says.
pub fn configured_max_query_bytes() -> usize {
    max_query_bytes_from(std::env::var("VERICTO_MAX_QUERY_BYTES").ok().as_deref())
}

/// [`configured_max_query_bytes`] for the raw value of the variable (`None` when
/// it is unset), so the parsing is testable without touching the environment.
fn max_query_bytes_from(raw: Option<&str>) -> usize {
    match raw {
        None => DEFAULT_MAX_QUERY_BYTES,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(v) if v > 0 => v,
            _ => {
                tracing::warn!(
                    value = %raw,
                    default = DEFAULT_MAX_QUERY_BYTES,
                    "VERICTO_MAX_QUERY_BYTES is not a positive integer; using the default"
                );
                DEFAULT_MAX_QUERY_BYTES
            }
        },
    }
}

/// Clamp the configured limit to what the dialect's framing can deliver, warning
/// when the configured value is unreachable so the operator is not left believing
/// a larger limit is in force.
pub fn effective_max_query_bytes(configured: usize, dialect: Dialect) -> usize {
    let cap = dialect_cap(dialect);
    if configured > cap {
        tracing::warn!(
            configured,
            cap,
            dialect = ?dialect,
            "VERICTO_MAX_QUERY_BYTES exceeds what this wire protocol can deliver; clamped to the cap"
        );
        cap
    } else {
        configured
    }
}

/// Default of `VERICTO_INLINE_EVAL_MAX_BYTES` (since 4.19.0): statements up to
/// this size are evaluated on the session's own task rather than on the blocking
/// pool.
///
/// The pool costs two thread hand-offs per statement (a futex wake to the pool
/// thread, an eventfd write and an epoll wake back to the worker), about 4 of the
/// 10 system calls a PostgreSQL statement costs the proxy, plus two context
/// switches. Below this size the evaluation is shorter than that: measured at
/// 0.1 to 0.25 µs per byte, 1 KiB is about 120 to 200 µs at the worst, and the
/// statements of OLTP traffic (50 to 500 bytes) take 10 to 80 µs. Above it the
/// pool keeps one large statement from stalling the other connections a worker
/// serves, as before.
pub const DEFAULT_INLINE_EVAL_MAX_BYTES: usize = 1024;

/// Read `VERICTO_INLINE_EVAL_MAX_BYTES`, falling back to
/// [`DEFAULT_INLINE_EVAL_MAX_BYTES`]. `0` evaluates every statement on the
/// blocking pool (the behaviour up to 4.18.0).
pub fn configured_inline_eval_max_bytes() -> usize {
    inline_eval_max_bytes_from(
        std::env::var("VERICTO_INLINE_EVAL_MAX_BYTES")
            .ok()
            .as_deref(),
    )
}

/// [`configured_inline_eval_max_bytes`] for the raw value of the variable.
fn inline_eval_max_bytes_from(raw: Option<&str>) -> usize {
    match raw {
        None => DEFAULT_INLINE_EVAL_MAX_BYTES,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    default = DEFAULT_INLINE_EVAL_MAX_BYTES,
                    "VERICTO_INLINE_EVAL_MAX_BYTES is not a non-negative integer; using the default"
                );
                DEFAULT_INLINE_EVAL_MAX_BYTES
            }
        },
    }
}

/// Rule code reported when a query is refused for its size.
///
/// Not a rule violation: there is no AST to point at and no severity to resolve,
/// so it carries its own code rather than borrowing a `VERICTO-NNN` one, which
/// would land in findings grouped by rule and be classified by
/// `RuleClass::for_code` as if it were a data mutation.
pub const OVERSIZE_RULE_CODE: &str = "VERICTO-QUERY-TOO-LARGE";

/// Stand-in for the SQL of a refused query.
///
/// The statement is not reported: it is by definition larger than anything worth
/// shipping, and it was never parsed, so it cannot be sanitized — normalization
/// is what replaces literals, and skipping it is the point of refusing early.
/// Reporting the size keeps the record diagnosable without carrying customer data.
pub fn oversize_marker(bytes: usize) -> String {
    format!("<query of {bytes} bytes refused before evaluation; text not reported>")
}

/// How to dispose of a query that exceeds the limit.
///
/// Blocks unless the workspace is in `monitor_mode`. That exception is not a
/// convenience: the engine documents `monitor_mode` as forcing every blocking
/// action to a non-blocking one, and holds it under a property test asserting it
/// never *increases* blocking. A size rejection there would be the one thing that
/// blocks in a dry-run deployment, breaking the guarantee a workspace relies on
/// while it evaluates Vericto before enforcing.
pub fn oversized_decision(
    bytes: usize,
    limit: usize,
    monitor_mode: bool,
) -> crate::tcp::evaluator::TcpDecision {
    use crate::tcp::evaluator::{Observation, TcpDecision};
    use vericto_engine::Severity;
    use vericto_engine::rules::engine::EnforcementAction;

    let detail = format!("query is {bytes} bytes, over the {limit} byte limit");
    if monitor_mode {
        TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: OVERSIZE_RULE_CODE.to_string(),
                ast_node_path: String::new(),
                severity: Severity::High,
                action: EnforcementAction::Monitor,
                parse_error: Some(detail),
            }),
            // The size check runs BEFORE parsing, so no rule was ever evaluated
            // and there is nothing to enumerate. The oversize code itself travels
            // in `rule_code`, which the API persists on its own.
            violations: Vec::new(),
            // Never parsed, so never rewritten and no column analysed.
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    } else {
        TcpDecision::Block {
            rule_code: OVERSIZE_RULE_CODE.to_string(),
            ast_node_path: String::new(),
            suggested_safe_query: Some(
                "Split the statement into smaller batches, or raise VERICTO_MAX_QUERY_BYTES"
                    .to_string(),
            ),
            severity: Severity::High,
            // Same as above: rejected before parsing, so no evaluated rules.
            violations: Vec::new(),
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::evaluator::TcpDecision;
    use vericto_engine::rules::engine::EnforcementAction;

    /// Unset is the default; any non-negative integer is taken as is, 0
    /// included (every statement on the blocking pool); garbage is the default.
    #[test]
    fn inline_eval_threshold_parses_zero_and_falls_back_on_garbage() {
        assert_eq!(
            inline_eval_max_bytes_from(None),
            DEFAULT_INLINE_EVAL_MAX_BYTES
        );
        assert_eq!(inline_eval_max_bytes_from(Some(" 4096 ")), 4096);
        assert_eq!(inline_eval_max_bytes_from(Some("0")), 0);
        for bad in ["", "-1", "1k", "abc"] {
            assert_eq!(
                inline_eval_max_bytes_from(Some(bad)),
                DEFAULT_INLINE_EVAL_MAX_BYTES,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn postgres_and_mysql_have_different_caps() {
        // The reason a single hard cap would not do: MySQL's framing stops an
        // order of magnitude below Postgres'.
        assert!(dialect_cap(Dialect::Postgres) > dialect_cap(Dialect::Mysql));
        assert_eq!(dialect_cap(Dialect::Mysql), MYSQL_MAX_PACKET_LEN);
    }

    #[test]
    fn the_default_fits_under_every_cap() {
        for dialect in [
            Dialect::Postgres,
            Dialect::Mysql,
            Dialect::Oracle,
            Dialect::MsSql,
            Dialect::Snowflake,
            Dialect::Sqlite,
        ] {
            assert!(
                DEFAULT_MAX_QUERY_BYTES <= dialect_cap(dialect),
                "the default is unreachable on {dialect:?}"
            );
        }
    }

    #[test]
    fn a_configured_value_within_the_cap_is_used_as_is() {
        assert_eq!(
            effective_max_query_bytes(4 * 1024 * 1024, Dialect::Postgres),
            4 * 1024 * 1024
        );
    }

    /// The default disposition: refuse. Forwarding an unevaluated query would
    /// create a rule bypass that does not exist today — padding a statement past
    /// the limit would carry it to the database unexamined.
    #[test]
    fn an_oversized_query_blocks_when_enforcement_is_on() {
        let d = oversized_decision(20 * 1024 * 1024, 10 * 1024 * 1024, false);
        match d {
            TcpDecision::Block { rule_code, .. } => assert_eq!(rule_code, OVERSIZE_RULE_CODE),
            TcpDecision::Forward { .. } => panic!("must not forward when enforcement is on"),
        }
    }

    /// `monitor_mode` is documented as forcing every blocking action to a
    /// non-blocking one, and the engine holds that under a property test asserting
    /// it never increases blocking. A size rejection there would be the one thing
    /// that blocks in a dry-run deployment.
    #[test]
    fn an_oversized_query_never_blocks_in_monitor_mode() {
        let d = oversized_decision(20 * 1024 * 1024, 10 * 1024 * 1024, true);
        match d {
            TcpDecision::Forward { observation, .. } => {
                let obs = observation.expect("monitor_mode still records the event");
                assert_eq!(obs.rule_code, OVERSIZE_RULE_CODE);
                assert_eq!(obs.action, EnforcementAction::Monitor);
                // Carries the reason, so the record says why it was not analysed.
                assert!(obs.parse_error.is_some());
            }
            TcpDecision::Block { .. } => {
                panic!("monitor_mode must never block, including on size")
            }
        }
    }

    /// The refused statement was never parsed, so it cannot be sanitized — and it
    /// is by definition too large to ship. The marker has to stay diagnostic
    /// without carrying customer SQL.
    #[test]
    fn the_marker_reports_the_size_without_the_statement() {
        let marker = oversize_marker(12_345);
        assert!(marker.contains("12345"));
        assert!(!marker.to_ascii_uppercase().contains("SELECT"));
        assert!(!marker.to_ascii_uppercase().contains("INSERT"));
    }

    /// Unset, unparseable, zero or negative values fall back to the default
    /// instead of failing startup; a positive value, padded or not, is used.
    #[test]
    fn the_configured_limit_falls_back_to_the_default_on_bad_input() {
        assert_eq!(max_query_bytes_from(None), DEFAULT_MAX_QUERY_BYTES);
        assert_eq!(max_query_bytes_from(Some("65536")), 65_536);
        assert_eq!(max_query_bytes_from(Some(" 1024 \n")), 1024);
        for bad in ["", "0", "-1", "10MB", "1e6"] {
            assert_eq!(
                max_query_bytes_from(Some(bad)),
                DEFAULT_MAX_QUERY_BYTES,
                "{bad:?} must fall back"
            );
        }
    }

    #[test]
    fn a_dialect_the_proxy_does_not_serve_gets_the_strictest_cap() {
        assert_eq!(dialect_cap(Dialect::Snowflake), MYSQL_MAX_PACKET_LEN);
        assert_eq!(dialect_cap(Dialect::Postgres), 64 * 1024 * 1024);
    }

    #[test]
    fn a_configured_value_over_the_cap_is_clamped() {
        // 32 MiB is reachable on Postgres but not on MySQL, so the same
        // configuration resolves differently per protocol.
        let configured = 32 * 1024 * 1024;
        assert_eq!(
            effective_max_query_bytes(configured, Dialect::Postgres),
            configured
        );
        assert_eq!(
            effective_max_query_bytes(configured, Dialect::Mysql),
            MYSQL_MAX_PACKET_LEN
        );
    }
}
