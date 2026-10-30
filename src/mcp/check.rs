// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `check_sql` in Proxy mode (design "MCP execution modes" §6.1, Q4):
//! evaluated locally by the same evaluator `execute_sql` uses, under the
//! same snapshot and identity; it spends no CI-check allowance, and each
//! statement is recorded as an event with `execution_status: dry_run`. Input
//! and output follow the hosted tool (vericto-fmw `mcp-tools/runtime.ts`,
//! `compactCheckResult`), with the hints of §6.7: where execute_sql exists,
//! `run_as_written` and `run_approved_query` point to it.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::mcp::execute::verdict;
use crate::mcp::next_steps::{self, VerdictContext};
use crate::mcp::runtime::{Caller, Runtime};
use crate::mcp::tools::ToolOutput;
use crate::tcp::protocol::QueryKind;

/// Most statements one call evaluates (the hosted tool's `queries` bound).
const MAX_STATEMENTS: usize = 500;

fn input_error(message: &str) -> ToolOutput {
    ToolOutput {
        text: format!("{message}\nNext: fix the arguments and call check_sql again."),
        structured: json!({
            "error": { "code": "INVALID_INPUT", "message": message },
            "next_action": "fix_and_recheck",
            "next_steps": [{
                "action": "fix_and_recheck", "lines": [], "rule_code": null, "tool": "check_sql",
                "message": "fix the arguments and call check_sql again."
            }],
        }),
        is_error: true,
    }
}

/// Splits a script into statements with the line each starts on: the
/// scanner's tokens (strings, quoted identifiers, dollar quotes and comments
/// are single tokens), cut at `;`. `whole_script` when the scanner cannot
/// read it or the parser says one statement spans what the scanner split
/// (a procedural body), as the hosted tool does.
pub fn split_script(sql: &str) -> (Vec<(u32, String)>, &'static str) {
    let line_of =
        |offset: usize| -> u32 { sql[..offset.min(sql.len())].matches('\n').count() as u32 + 1 };
    let whole = || {
        let first = sql.len() - sql.trim_start().len();
        (vec![(line_of(first), sql.to_string())], "whole_script")
    };
    let Ok(scan) = pg_query::scan(sql) else {
        return whole();
    };
    use pg_query::protobuf::Token;
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut end = 0usize;
    for t in &scan.tokens {
        let (s, e) = (t.start as usize, t.end as usize);
        match Token::try_from(t.token) {
            Ok(Token::Ascii59) => {
                if let Some(b) = start.take() {
                    out.push((line_of(b), sql[b..end].to_string()));
                }
            }
            Ok(Token::SqlComment | Token::CComment) => {}
            _ => {
                start.get_or_insert(s);
                end = e;
            }
        }
    }
    if let Some(b) = start {
        out.push((line_of(b), sql[b..end].to_string()));
    }
    // A function body or DO block holds `;` inside one statement: the parser
    // counts fewer statements than the scanner split.
    if let Ok(parts) = pg_query::split_with_parser(sql)
        && parts.iter().filter(|p| !p.trim().is_empty()).count() != out.len()
    {
        return whole();
    }
    (out, "statements")
}

/// `check_sql`.
pub fn check_sql(rt: &Arc<Runtime>, caller: &Caller, args: &Value) -> ToolOutput {
    let dialect = args
        .get("dialect")
        .and_then(Value::as_str)
        .unwrap_or("postgres");
    if dialect != "postgres" {
        return input_error(&format!(
            "this server checks PostgreSQL only (its database is PostgreSQL), not {dialect}"
        ));
    }
    let (statements, evaluated_as) = match (args.get("sql"), args.get("queries")) {
        (Some(Value::String(sql)), None) => {
            let (s, how) = split_script(sql);
            if s.is_empty() {
                return input_error(
                    "The script has no SQL statements (only whitespace or comments).",
                );
            }
            (s, how)
        }
        (None, Some(Value::Array(qs))) if !qs.is_empty() => {
            let mut out = Vec::with_capacity(qs.len());
            for (i, q) in qs.iter().enumerate() {
                let Some(sql) = q
                    .get("sql")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                else {
                    return input_error(&format!("queries[{i}].sql must be a non-empty string"));
                };
                let line = q
                    .get("line")
                    .and_then(Value::as_u64)
                    .map_or(i as u32 + 1, |l| l as u32);
                out.push((line, sql.to_string()));
            }
            (out, "queries")
        }
        _ => {
            return input_error(
                "Pass exactly one of `sql` (a whole script) or `queries` (pre-split statements).",
            );
        }
    };
    if statements.len() > MAX_STATEMENTS {
        return input_error(&format!("at most {MAX_STATEMENTS} statements per call"));
    }
    if statements.iter().any(|(_, s)| s.contains('\0')) {
        return input_error("the SQL contains a NUL byte (\\u0000), which is refused");
    }
    let ticket = args.get("ticket").and_then(Value::as_str);
    let ruleset_version = rt.ruleset_version();
    let all_lines: Vec<u32> = statements.iter().map(|(l, _)| *l).collect();

    // The kill switch: every statement carries the same instruction to stop.
    if let Some(block) = rt.kill_switch_block(caller) {
        let steps = vec![next_steps::kill_switch_step(
            &block.block_id,
            all_lines.clone(),
        )];
        let structured = json!({
            "passed": false,
            "summary": { "total": statements.len(), "blocked": statements.len(), "flagged": 0, "monitored": 0, "allowed": 0, "parse_errors": 0 },
            "findings": [],
            "dialect": "postgres",
            "evaluated_as": evaluated_as,
            "ruleset_version": ruleset_version,
            "ci_checks_remaining": null,
            "next_action": "stop",
            "next_steps": steps,
            "kill_switch": { "block_id": block.block_id, "message": block.message },
        });
        let text = [format!("BLOCKED: {}", block.message)]
            .into_iter()
            .chain(next_steps::next_steps_text(&steps, true))
            .collect::<Vec<_>>()
            .join("\n");
        return ToolOutput {
            text,
            structured,
            is_error: false,
        };
    }

    let access = rt.access();
    let ctx = VerdictContext {
        access: &access,
        dialect: "postgres",
        ruleset_version: Some(&ruleset_version),
        execute_available: true,
    };
    let policy = rt.policy_for_db_user();
    let (mut blocked, mut flagged, mut monitored, mut allowed, mut parse_errors) = (0, 0, 0, 0, 0);
    let mut per_statement = Vec::new();
    let mut findings = Vec::new();
    let mut verbose_rows = Vec::new();
    for (line, sql) in &statements {
        let e = rt.evaluate(sql, QueryKind::Simple, caller, ticket, Arc::clone(&policy));
        let v = verdict(&e.decision);
        match v.json["status"].as_str().unwrap_or("") {
            "BLOCKED" => blocked += 1,
            "FLAGGED" => flagged += 1,
            "MONITORED" => monitored += 1,
            "PARSE_ERROR" => {
                parse_errors += 1;
                if v.facts.status == "BLOCKED" {
                    blocked += 1;
                }
            }
            _ => allowed += 1,
        }
        rt.emit(sql, &e.decision, e.eval_us, &e.identity, |ev| {
            rt.caller_fields(caller, ev);
            ev.event_kind = Some("check".into());
            ev.execution_status = Some("dry_run".into());
        });
        let step = next_steps::verdict_step(&v.facts, &ctx);
        let preview: String = sql.chars().take(120).collect();
        if v.json["status"] != "ALLOWED" {
            findings.push(json!({
                "line": line,
                "status": v.json["status"],
                "rule_code": v.facts.rule_code,
                "severity": v.facts.severity,
                "sql_preview": preview,
                "ast_node_path": v.json["ast_node_path"],
                "suggested_fix": v.facts.suggested_fix,
                "approved_query": v.facts.approved_query,
                "sensitive_columns": v.json["sensitive_columns"],
                "access_denied": v.json["access_denied"],
                "next_action": step.action,
            }));
        }
        verbose_rows.push(json!({ "line": line, "sql": sql, "verdict": v.json }));
        per_statement.push((*line, step));
    }
    let steps = next_steps::group_steps(per_statement);
    let total = statements.len();
    let unit = if evaluated_as == "queries" {
        if total == 1 { "query" } else { "queries" }
    } else if total == 1 {
        "statement"
    } else {
        "statements"
    };
    let mut lines = vec![if blocked > 0 {
        format!("BLOCKED: {blocked} of {total} {unit} must not ship as written.")
    } else if !findings.is_empty() {
        format!(
            "PASSED with findings: {} of {total} {unit} worth a look.",
            findings.len()
        )
    } else {
        format!("PASSED: all {total} {unit} allowed.")
    }];
    for f in &findings {
        let fix = match (f["approved_query"].as_str(), f["suggested_fix"].as_str()) {
            (Some(q), _) if f["status"] != "BLOCKED" => {
                format!(" The approved rewrite runs through execute_sql: {q}")
            }
            (_, Some(fix)) => format!(" Fix: {fix}"),
            _ => String::new(),
        };
        let rule = match (f["rule_code"].as_str(), f["severity"].as_str()) {
            (Some(r), Some(s)) => format!(" {r} ({s})"),
            (Some(r), None) => format!(" {r}"),
            _ => String::new(),
        };
        lines.push(format!(
            "- line {} {}{rule}: {}{fix}",
            f["line"],
            f["status"].as_str().unwrap_or(""),
            f["sql_preview"].as_str().unwrap_or("")
        ));
    }
    if evaluated_as == "whole_script" {
        lines.push("Note: the script has a procedural body, so it was evaluated as one unit and only its worst finding is shown.".to_string());
    }
    if parse_errors > 0 {
        lines.push(format!(
            "Note: {parse_errors} could not be parsed as postgres and were not evaluated."
        ));
    }
    let one_step_for_all = steps.len() == 1 && steps[0].lines.len() == all_lines.len();
    lines.extend(next_steps::next_steps_text(&steps, one_step_for_all));
    lines.push(format!(
        "Ruleset {ruleset_version} · checked locally, no CI checks spent"
    ));
    let mut structured = json!({
        "passed": blocked == 0,
        "summary": { "total": total, "blocked": blocked, "flagged": flagged, "monitored": monitored, "allowed": allowed, "parse_errors": parse_errors },
        "findings": findings,
        "dialect": "postgres",
        "evaluated_as": evaluated_as,
        "ruleset_version": ruleset_version,
        "ci_checks_remaining": null,
        "next_action": steps.first().map_or("run_as_written", |s| s.action),
        "next_steps": steps,
        "evaluated_locally": true,
    });
    if args.get("verbose").and_then(Value::as_bool) == Some(true) {
        structured["queries"] = Value::Array(verbose_rows);
    }
    ToolOutput {
        text: lines.join("\n"),
        structured,
        is_error: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_split_with_their_lines() {
        let (s, how) = split_script("SELECT 1;\n-- c\nSELECT ';';\n\n  DELETE FROM t");
        assert_eq!(how, "statements");
        assert_eq!(
            s,
            vec![
                (1, "SELECT 1".to_string()),
                (3, "SELECT ';'".to_string()),
                (5, "DELETE FROM t".to_string())
            ]
        );
        let (s, how) = split_script(
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$;",
        );
        assert_eq!(how, "statements");
        assert_eq!(s.len(), 1);
        let (s, how) = split_script("CREATE PROCEDURE p() BEGIN ATOMIC SELECT 1; SELECT 2; END;");
        assert_eq!(how, "whole_script");
        assert_eq!(s.len(), 1);
    }
}
