// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `describe_schema` (design "MCP execution modes" §6.6): tables, columns,
//! types, primary and foreign keys, from the fixed catalog queries of
//! `control.rs`, run like any statement (read-only transaction, ROLLBACK) and
//! recorded as one event of kind `catalog`. It never taints.
//!
//! Columns tagged `block` are listed with `"sensitive": "block"` and masked
//! ones with their mask, so the agent knows in advance what it will not see.
//! Under an enforced agent-access allowlist only what the database user may
//! read is listed: each table's columns are checked with the engine, as one
//! `SELECT` of them would be.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};
use vericto_engine::{AccessMode, Dialect, SensitivePolicy};

use crate::mcp::control;
use crate::mcp::execute::{self, Ran};
use crate::mcp::next_steps::{self, InvalidReason, Outcome, Step, Unavailable};
use crate::mcp::pg::RunOutcome;
use crate::mcp::runtime::{Caller, Runtime, mask_style_name};
use crate::mcp::tools::ToolOutput;
use crate::tcp::evaluator::TcpDecision;
use crate::tcp::protocol::QueryKind;

/// Most columns read from the catalog per call (the query's LIMIT minus one).
const MAX_CATALOG_ROWS: u32 = 5000;

fn text(cell: &Option<crate::mcp::pg::Cell>) -> Option<String> {
    cell.as_ref()
        .map(|c| String::from_utf8_lossy(&c.bytes).into_owned())
}

fn name_arg(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 63 && !s.contains('\0') => {
            Ok(Some(s.clone()))
        }
        Some(_) => Err(format!("{key} must be a name of 1 to 63 bytes")),
    }
}

fn answer(
    rt: &Runtime,
    text: String,
    mut s: serde_json::Map<String, Value>,
    step: Step,
    is_error: bool,
    event_id: Option<String>,
) -> ToolOutput {
    let step = step.with_lines(vec![1]);
    s.insert("next_action".into(), json!(step.action));
    s.insert("ruleset_version".into(), json!(rt.ruleset_version()));
    s.insert("taint".into(), rt.taint());
    s.insert("event_id".into(), json!(event_id));
    let lines = [text, format!("Next: {}", step.message)];
    s.insert("next_steps".into(), json!([step]));
    ToolOutput {
        text: lines.join("\n"),
        structured: Value::Object(s),
        is_error,
    }
}

/// The step of an outcome execute_sql shares (input, readiness, kill switch,
/// database errors), as the contract words it.
fn shared_step(rt: &Runtime, o: Outcome) -> Step {
    let access = rt.access();
    let ruleset = rt.ruleset_version();
    let v = next_steps::execute_verdict(
        &o,
        &next_steps::ExecuteContext {
            access: &access,
            dialect: "postgres",
            ruleset_version: Some(&ruleset),
        },
    );
    let s = v.next_steps.into_iter().next().expect("one step");
    Step::new(s.action, s.rule_code, s.tool, s.message)
}

fn error(rt: &Runtime, code: &str, message: &str, step: Step) -> ToolOutput {
    let mut s = serde_json::Map::new();
    s.insert("status".into(), json!("ERROR"));
    s.insert("error".into(), json!({ "code": code, "message": message }));
    answer(
        rt,
        format!("ERROR ({code}): {message}"),
        s,
        step,
        true,
        None,
    )
}

/// `describe_schema`.
pub async fn describe_schema(rt: &Arc<Runtime>, caller: &Caller, args: &Value) -> ToolOutput {
    let (schema, table) = match (name_arg(args, "schema"), name_arg(args, "table")) {
        (Ok(s), Ok(t)) => (s, t),
        (Err(e), _) | (_, Err(e)) => {
            let step = shared_step(
                rt,
                Outcome::InvalidInput(InvalidReason::Argument(e.clone())),
            );
            return error(rt, "INVALID_INPUT", &e, step);
        }
    };
    if rt.not_ready() {
        return error(
            rt,
            "NOT_READY",
            "no signed rules bundle is loaded yet (VERICTO_MCP_REQUIRE_CONTROL_PLANE)",
            shared_step(rt, Outcome::NotReady(2)),
        );
    }
    if let Some(block) = rt.kill_switch_block(caller) {
        return error(
            rt,
            "KILL_SWITCH",
            &block.message,
            shared_step(rt, Outcome::KillSwitch(block.block_id.clone())),
        );
    }
    // The catalog queries are control statements: evaluated like any
    // statement, with the workspace policy (an allowlist is applied to the
    // result below, not to the catalog's own tables).
    let mut base = (*rt.policy_for_db_user()).clone();
    let access = base.access_policy.take();
    let evaluated = rt.evaluate(
        control::CATALOG_COLUMNS,
        QueryKind::Prepared,
        caller,
        None,
        Arc::new(base),
    );
    if let TcpDecision::Block { rule_code, .. } = &evaluated.decision {
        return error(
            rt,
            "BLOCKED",
            &format!("the catalog query was blocked by {rule_code}"),
            Step::new(
                "stop",
                Some(rule_code.clone()),
                None,
                "the workspace's rules block reading the catalog; ask the user.".to_string(),
            ),
        );
    }
    let params = vec![schema.clone(), table.clone()];
    let limits = rt.limits();
    let timeout = limits.statement_timeout_ms;
    let columns = match execute::run_in_read_transaction(
        rt,
        Some(caller),
        control::CATALOG_COLUMNS,
        &params,
        MAX_CATALOG_ROWS,
        timeout,
        &limits,
    )
    .await
    {
        Ran::Done(o) => o,
        Ran::Unavailable {
            reason,
            sqlstate,
            message,
        } => {
            let retry_after_s = if reason == Unavailable::PoolBusy {
                1
            } else {
                5
            };
            let step = shared_step(
                rt,
                Outcome::Unavailable {
                    reason,
                    sqlstate,
                    retry_after_s,
                },
            );
            return error(rt, "DATABASE_UNAVAILABLE", &message, step);
        }
        Ran::Killed(b) => {
            return error(
                rt,
                "KILL_SWITCH",
                &b.message,
                shared_step(rt, Outcome::KillSwitch(b.block_id.clone())),
            );
        }
    };
    if let Some(e) = &columns.error {
        let agent = crate::mcp::errors::for_agent(e, rt.cfg.result_detail);
        return error(
            rt,
            "DATABASE_ERROR",
            &format!("{} {}", agent.sqlstate, agent.message),
            shared_step(rt, Outcome::DatabaseError(e.sqlstate.clone())),
        );
    }
    let keys = match execute::run_in_read_transaction(
        rt,
        Some(caller),
        control::CATALOG_KEYS,
        &params,
        MAX_CATALOG_ROWS,
        timeout,
        &limits,
    )
    .await
    {
        Ran::Done(o) if o.error.is_none() => Some(o),
        _ => None,
    };
    let (tables, truncated) = assemble(rt, &columns, keys.as_deref(), access.as_ref());
    let event_id = rt.emit(
        control::CATALOG_COLUMNS,
        &evaluated.decision,
        evaluated.eval_us,
        &evaluated.identity,
        |ev| {
            rt.caller_fields(caller, ev);
            ev.event_kind = Some("catalog".into());
            ev.execution_status = Some("executed".into());
            ev.tier = Some("read".into());
            ev.rows_returned = Some(tables.len() as u64);
            ev.execution_ms = Some(columns.db_time.as_secs_f64() * 1000.0);
        },
    );
    let table_count = tables.len();
    let summary = tables
        .iter()
        .take(50)
        .map(|t| {
            let cols: Vec<String> = t["columns"]
                .as_array()
                .map(|c| {
                    c.iter()
                        .map(|c| {
                            let mut s = format!(
                                "{} {}",
                                c["name"].as_str().unwrap_or(""),
                                c["type"].as_str().unwrap_or("")
                            );
                            if let Some(m) = c.get("masked").and_then(Value::as_str) {
                                s.push_str(&format!(" [masked:{m}]"));
                            }
                            if c.get("sensitive").and_then(Value::as_str) == Some("block") {
                                s.push_str(" [blocked]");
                            }
                            s
                        })
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "- {}.{} ({}): {}",
                t["schema"].as_str().unwrap_or(""),
                t["name"].as_str().unwrap_or(""),
                t["kind"].as_str().unwrap_or(""),
                cols.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let more = if table_count > 50 {
        format!(
            "\n… and {} more tables (structuredContent has them all)",
            table_count - 50
        )
    } else {
        String::new()
    };
    let text = format!(
        "{table_count} table(s) and view(s){}:\n{summary}{more}",
        if truncated {
            ", cut at 5000 columns"
        } else {
            ""
        }
    );
    let mut s = serde_json::Map::new();
    s.insert("status".into(), json!("OK"));
    s.insert("database".into(), json!(rt.database_name()));
    s.insert("tables".into(), Value::Array(tables));
    s.insert("truncated".into(), json!(truncated));
    let step = if table_count == 0 {
        Step::new(
            "mention_to_user",
            None,
            None,
            "no table is visible to this server's database role; ask the user which schema to use or to grant the role SELECT.".to_string(),
        )
    } else {
        Step::new(
            "run_as_written",
            None,
            Some("execute_sql"),
            "call execute_sql with one read statement on these tables; masked columns come back masked, and columns marked block cannot be read.".to_string(),
        )
    };
    answer(rt, text, s, step, false, event_id)
}

/// Tables from the catalog rows, filtered by the allowlist when it is enforced.
fn assemble(
    rt: &Runtime,
    columns: &RunOutcome,
    keys: Option<&RunOutcome>,
    access: Option<&vericto_engine::AccessPolicy>,
) -> (Vec<Value>, bool) {
    let policy = rt.shared.policy.load_full();
    let mut tables: BTreeMap<(String, String), (String, Vec<Value>)> = BTreeMap::new();
    for row in &columns.rows {
        let get = |i: usize| row.get(i).and_then(text);
        let (Some(schema), Some(name), Some(col)) = (get(0), get(1), get(3)) else {
            continue;
        };
        let kind = match get(2).as_deref() {
            Some("VIEW") => "view",
            Some("FOREIGN") => "foreign table",
            _ => "table",
        };
        let data_type = get(4).unwrap_or_default();
        let udt = get(5).unwrap_or_default();
        let ty = if data_type == "USER-DEFINED" || data_type == "ARRAY" {
            udt
        } else {
            data_type
        };
        let mut c = json!({
            "name": col,
            "type": ty,
            "nullable": get(6).as_deref() == Some("YES"),
        });
        if let Some(d) = get(7) {
            c["default"] = json!(d);
        }
        if let Some(tag) = policy.sensitive_columns.iter().find(|t| {
            t.column.eq_ignore_ascii_case(&col)
                && t.table.eq_ignore_ascii_case(&name)
                && t.schema
                    .as_deref()
                    .is_none_or(|s| s.eq_ignore_ascii_case(&schema))
        }) {
            match tag.policy {
                SensitivePolicy::Mask => c["masked"] = json!(mask_style_name(&tag.mask_style)),
                p => c["sensitive"] = json!(p.as_str()),
            }
        }
        tables
            .entry((schema, name))
            .or_insert_with(|| (kind.to_string(), Vec::new()))
            .1
            .push(c);
    }
    let truncated = columns.more_rows;

    // Keys.
    let mut pks: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
    let mut fks: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
    if let Some(k) = keys {
        for row in &k.rows {
            let get = |i: usize| row.get(i).and_then(text);
            let (Some(s), Some(t), Some(kind), Some(name), Some(def)) =
                (get(0), get(1), get(2), get(3), get(4))
            else {
                continue;
            };
            let entry = json!({ "name": name, "definition": def });
            if kind == "p" {
                pks.entry((s, t)).or_default().push(entry);
            } else {
                fks.entry((s, t)).or_default().push(entry);
            }
        }
    }

    let enforced = access.filter(|a| a.mode == AccessMode::Enforce && !policy.monitor_mode);
    let mut out = Vec::with_capacity(tables.len());
    for ((schema, name), (kind, mut cols)) in tables {
        if let Some(a) = enforced {
            match readable(rt, a, &schema, &name, &cols) {
                Readable::None => continue,
                Readable::Some(denied) => cols.retain(|c| {
                    !denied.iter().any(|d| {
                        c["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case(d))
                    })
                }),
                Readable::All => {}
            }
            if cols.is_empty() {
                continue;
            }
        }
        let key = (schema.clone(), name.clone());
        out.push(json!({
            "schema": schema,
            "name": name,
            "kind": kind,
            "columns": cols,
            "primary_key": pks.get(&key).and_then(|v| v.first()).map(|p| p["definition"].clone()),
            "foreign_keys": fks.get(&key).cloned().unwrap_or_default(),
        }));
    }
    (out, truncated)
}

enum Readable {
    All,
    None,
    /// These columns are denied.
    Some(Vec<String>),
}

/// What of a table the allowlist lets the database user read: the engine's
/// verdict on one `SELECT` of its columns.
fn readable(
    rt: &Runtime,
    access: &vericto_engine::AccessPolicy,
    schema: &str,
    table: &str,
    cols: &[Value],
) -> Readable {
    let names: Vec<&str> = cols.iter().filter_map(|c| c["name"].as_str()).collect();
    if names.is_empty() {
        return Readable::None;
    }
    let probe = control::access_probe(schema, table, &names);
    let policy = vericto_engine::EnforcementPolicy {
        access_policy: Some(access.clone()),
        ..(*rt.shared.policy.load_full()).clone()
    };
    let rules = rt.shared.ruleset.load_full();
    let outcome = vericto_engine::evaluate(&probe, Dialect::Postgres, &rules, &policy);
    if outcome.access_denied.is_empty() {
        return Readable::All;
    }
    if outcome
        .access_denied
        .iter()
        .any(|d| d.column.as_deref().is_none_or(|c| c == "*"))
    {
        return Readable::None;
    }
    Readable::Some(
        outcome
            .access_denied
            .iter()
            .filter_map(|d| d.column.clone())
            .collect(),
    )
}
