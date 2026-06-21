//! Bridge between the TCP proxy and the AST evaluation engine (in-process).
//!
//! The TCP proxy calls the existing parser and `RuleEngine` directly, without
//! going through HTTP. This keeps latency minimal on the critical path.

use crate::parser::{parser_for, Dialect};
use crate::rules::engine::{Decision, Rule, RuleEngine, RuleType, Severity};

/// Result of evaluating a query on the TCP path.
pub enum TcpDecision {
    Allow,
    Block {
        rule_code: String,
        ast_node_path: String,
        suggested_safe_query: Option<String>,
    },
}

/// Evaluates a SQL query against the given ruleset.
///
/// A query that does not parse is blocked (fail-closed) — same as the HTTP
/// endpoint, nothing potentially destructive is let through.
pub fn evaluate(sql: &str, dialect: Dialect, rules: &[Rule]) -> TcpDecision {
    let parser = parser_for(dialect);
    let parsed = match parser.parse(sql) {
        Ok(p) => p,
        Err(_) => {
            return TcpDecision::Block {
                rule_code: "VETRO-PARSE-ERROR".to_string(),
                ast_node_path: "PARSE_ERROR".to_string(),
                suggested_safe_query: None,
            };
        }
    };

    let outcome = RuleEngine::evaluate(&parsed, rules);
    match outcome.decision {
        Decision::Allowed => TcpDecision::Allow,
        Decision::Blocked => TcpDecision::Block {
            rule_code: outcome.rule_code.unwrap_or_else(|| "VETRO".to_string()),
            ast_node_path: outcome.ast_node_path.unwrap_or_default(),
            suggested_safe_query: outcome.suggested_safe_query,
        },
    }
}

/// Default ruleset: the CRITICAL rules always active.
///
/// In production this ruleset would be resolved per workspace (querying the
/// API or database based on the `database` from the StartupMessage). For
/// single-tenant / dev mode the CRITICAL built-ins are the safe minimum.
pub fn default_ruleset() -> Vec<Rule> {
    // (code, severity)
    let rules: &[(&str, Severity)] = &[
        // CRITICAL
        ("VETRO-001", Severity::Critical), // DELETE without WHERE
        ("VETRO-003", Severity::Critical), // DELETE with always-true WHERE
        ("VETRO-010", Severity::Critical), // DROP TABLE / DATABASE
        ("VETRO-011", Severity::Critical), // TRUNCATE TABLE
        ("VETRO-012", Severity::Critical), // DROP SCHEMA
        ("VETRO-030", Severity::Critical), // UPDATE without WHERE (primary tables)
        ("VETRO-042", Severity::Critical), // UPDATE without WHERE
        // HIGH
        ("VETRO-002", Severity::High),     // DELETE with LIMIT 0 (MySQL)
        ("VETRO-013", Severity::High),     // DROP INDEX without IF EXISTS
        ("VETRO-015", Severity::High),     // ALTER TABLE DROP COLUMN
        ("VETRO-016", Severity::High),     // ALTER TABLE RENAME
        ("VETRO-031", Severity::High),     // UPDATE in CTE without WHERE
        ("VETRO-033", Severity::High),     // DELETE in subquery without WHERE
        ("VETRO-040", Severity::High),     // INSERT INTO … SELECT without filter
        ("VETRO-070", Severity::High),     // SLEEP() / PG_SLEEP()
        // MEDIUM
        ("VETRO-050", Severity::Medium),   // SELECT without LIMIT
        ("VETRO-051", Severity::Medium),   // SELECT * without WHERE
        ("VETRO-060", Severity::Medium),   // INSERT without explicit columns
        ("VETRO-061", Severity::Medium),   // INSERT batch > 10k rows
        // SQL injection
        ("VETRO-090", Severity::Critical), // OR tautology in WHERE (SQL injection)
    ];

    rules
        .iter()
        .map(|(code, severity)| Rule {
            rule_id: code.to_string(),
            code: code.to_string(),
            severity: *severity,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        })
        .collect()
}
