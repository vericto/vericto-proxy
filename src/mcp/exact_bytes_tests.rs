// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The exact-text guarantee against a byte-recording Postgres (design §7.6):
//! for each call, the `Parse` text the database received is the text the
//! evaluator evaluated (or its rewrite), no other SQL than the control
//! statements of `control.rs` was sent, and a refused statement sent nothing
//! at all. Then the smuggling corpus (multi-statement, NUL, comments, quoting,
//! encodings) and the answers of every outcome.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::mcp::control;
use crate::mcp::execute::{self, execute_sql};
use crate::mcp::fake_pg::{self, Answer, Auth, FakePg, Opts, Seen};
use crate::mcp::runtime::{Runtime, Shared};
use crate::tcp::evaluator::TcpDecision;

async fn setup(
    shared: Shared,
) -> (
    FakePg,
    Arc<Runtime>,
    Arc<crate::telemetry::queue::MemoryQueue>,
) {
    let fake = FakePg::start(Auth::Trust).await;
    let (rt, q) = fake_pg::runtime(
        &fake_pg::url(&fake),
        shared,
        Opts {
            telemetry: true,
            ..Default::default()
        },
    );
    (fake, rt, q)
}

async fn call(rt: &Arc<Runtime>, args: Value) -> crate::mcp::tools::ToolOutput {
    let caller = fake_pg::caller(rt);
    execute_sql(rt, &caller, &args).await
}

/// Every statement the fake received is either a control statement or the
/// one expected Parse text, which arrives exactly once.
fn assert_only(fake: &FakePg, expected_parse: Option<&str>) {
    let parses = fake.parses();
    match expected_parse {
        Some(text) => {
            assert_eq!(parses.len(), 1, "exactly one Parse: {:?}", fake.seen());
            assert_eq!(
                parses[0],
                text.as_bytes(),
                "the Parse text is the evaluated text"
            );
        }
        None => assert!(parses.is_empty(), "nothing parsed: {:?}", fake.seen()),
    }
    for q in fake.queries() {
        assert!(
            control::is_control(&q),
            "a non-control simple query was sent: {q}"
        );
    }
    for s in fake.seen() {
        if let Seen::Parse {
            name, param_types, ..
        } = s
        {
            assert_eq!(name, "", "only the unnamed statement is used");
            assert_eq!(param_types, 0, "parameter types are left to the server");
        }
    }
}

/// What the evaluator decides for `sql` under the runtime's snapshot, as an
/// independent check of the bytes sent.
fn evaluated_text(rt: &Arc<Runtime>, sql: &str) -> Option<String> {
    let (rt, sql) = (Arc::clone(rt), sql.to_string());
    crate::mcp::stack::on_big_stack_sync(move || {
        let caller = fake_pg::caller(&rt);
        let e = rt.evaluate(
            &sql,
            crate::tcp::protocol::QueryKind::Prepared,
            &caller,
            None,
            rt.policy_for_db_user(),
        );
        match e.decision {
            TcpDecision::Forward {
                rewritten_query, ..
            } => Some(rewritten_query.unwrap_or_else(|| sql.clone())),
            TcpDecision::Block { .. } => None,
        }
    })
    .unwrap()
}

#[tokio::test]
async fn a_read_sends_exactly_its_bytes_inside_a_read_only_transaction() {
    let (fake, rt, q) = setup(Shared::built_in()).await;
    let sql = "SELECT id, status FROM orders WHERE id = $1 /* keep this comment */ LIMIT 5;";
    fake.answer(
        sql,
        Answer::rows(
            &[("id", 20), ("status", 25)],
            vec![vec![Some("7"), Some("paid")]],
        ),
    );
    let out = call(&rt, json!({ "sql": sql, "params": [7] })).await;
    assert!(!out.is_error, "{}", out.text);
    assert_only(&fake, Some(sql));
    let s = &out.structured;
    assert_eq!(s["status"], "EXECUTED");
    assert_eq!(s["executed_sql"], sql);
    assert_eq!(s["rewritten"], false);
    assert_eq!(s["rows"], json!([["7", "paid"]]));
    assert_eq!(s["columns"][0]["type"], "int8");
    assert_eq!(
        s["statement_sha256"],
        crate::mcp::identity::sha256_hex(sql.as_bytes())
    );
    // BEGIN … READ ONLY before, ROLLBACK after, nothing else.
    let queries = fake.queries();
    assert_eq!(queries.len(), 2, "{queries:?}");
    assert!(queries[0].starts_with(control::BEGIN_READ_ONLY));
    assert_eq!(queries[1], control::ROLLBACK);
    // Parameters only through Bind, as text.
    let binds: Vec<_> = fake
        .seen()
        .into_iter()
        .filter_map(|s| match s {
            Seen::Bind { params } => Some(params),
            _ => None,
        })
        .collect();
    assert_eq!(binds, vec![vec![Some(b"7".to_vec())]]);
    // Execute asks for one row more than it returns.
    assert!(fake.seen().contains(&Seen::Execute { max_rows: 201 }));
    // One event, source mcp_proxy, counts and the hash only.
    let ev = fake_pg::events(&q);
    assert_eq!(ev.len(), 1);
    let e = &ev[0];
    assert_eq!(e.source.as_deref(), Some("mcp_proxy"));
    assert_eq!(e.execution_status.as_deref(), Some("executed"));
    assert_eq!(e.tier.as_deref(), Some("read"));
    assert_eq!(e.rows_returned, Some(1));
    assert_eq!(e.truncated, Some(false));
    assert_eq!(
        e.statement_sha256.as_deref(),
        Some(s["statement_sha256"].as_str().unwrap())
    );
    assert_eq!(e.mcp_client_name.as_deref(), Some("test-client"));
    let wire = serde_json::to_string(e).unwrap();
    assert!(
        !wire.contains("paid"),
        "no result value in an event: {wire}"
    );
}

#[tokio::test]
async fn a_masked_read_sends_the_evaluators_rewrite_never_the_original() {
    let (fake, rt, _) = setup(fake_pg::shared_with_mask()).await;
    let sql = "SELECT id, email FROM users WHERE id = $1";
    let rewrite = evaluated_text(&rt, sql).expect("the mask forwards a rewrite");
    assert_ne!(rewrite, sql, "the mask rewrites the projection");
    fake.answer(
        &rewrite,
        Answer::rows(
            &[("id", 23), ("email", 25)],
            vec![vec![Some("1"), Some("j***@example.com")]],
        ),
    );
    let out = call(&rt, json!({ "sql": sql, "params": ["1"] })).await;
    assert!(!out.is_error, "{}", out.text);
    assert_only(&fake, Some(&rewrite));
    let s = &out.structured;
    assert_eq!(s["rewritten"], true);
    assert_eq!(s["executed_sql"], rewrite.as_str());
    assert_eq!(s["columns"][1]["masked"], "email");
    assert_eq!(s["next_action"], "mention_to_user");
    assert!(
        s["next_steps"][0]["message"]
            .as_str()
            .unwrap()
            .contains("public.users.email masked"),
        "{}",
        s["next_steps"]
    );
}

#[tokio::test]
async fn refused_statements_send_nothing() {
    let (fake, rt, q) = setup(Shared::built_in()).await;
    for (args, code, execution_status) in [
        (json!({ "sql": "DELETE FROM users" }), "BLOCKED", "blocked"),
        (json!({ "sql": "DROP TABLE users" }), "BLOCKED", "blocked"),
        (
            json!({ "sql": "DELETE FROM users WHERE id = 1" }),
            "TIER_NOT_ENABLED",
            "tier_refused",
        ),
        (
            json!({ "sql": "UPDATE users SET a = 1 WHERE id = 1", "tier": "write" }),
            "TIER_NOT_ENABLED",
            "tier_refused",
        ),
        (
            json!({ "sql": "UPDATE users SET a = 1 WHERE id = 1" }),
            "TIER_NOT_ENABLED",
            "tier_refused",
        ),
        (
            json!({ "sql": "UPDATE users SET a = 1 WHERE id = 1", "tier": "read" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT 1; DELETE FROM users" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT 1\u{0}; DROP TABLE users" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (json!({ "sql": "SELECT $1" }), "INVALID_INPUT", "invalid"),
        (
            json!({ "sql": "SET search_path = evil" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT pg_terminate_backend(1)" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT * FROM t FOR UPDATE" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (json!({ "sql": "SELEC 1" }), "BLOCKED", "blocked"),
        (json!({ "sql": "   " }), "INVALID_INPUT", "invalid"),
        (
            json!({ "sql": "-- only a comment" }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT 1", "max_rows": 0 }),
            "INVALID_INPUT",
            "invalid",
        ),
        (
            json!({ "sql": "SELECT 1", "approval_id": "a1" }),
            "INVALID_INPUT",
            "invalid",
        ),
    ] {
        fake.clear();
        let out = call(&rt, args.clone()).await;
        assert!(out.is_error, "{args}: {}", out.text);
        assert_eq!(
            out.structured["error"]["code"], code,
            "{args}: {}",
            out.structured
        );
        assert_only(&fake, None);
        assert!(
            fake.queries().is_empty(),
            "{args}: no control statement either"
        );
        let ev = fake_pg::events(&q);
        assert_eq!(ev.len(), 1, "{args}: one event per call");
        assert_eq!(
            ev[0].execution_status.as_deref(),
            Some(execution_status),
            "{args}"
        );
        if execution_status == "invalid" && code == "INVALID_INPUT" && ev[0].status == "INVALID" {
            assert_eq!(
                ev[0].query_text, "",
                "{args}: invalid input is reported by its hash only"
            );
            assert!(ev[0].statement_sha256.is_some());
        }
    }
    assert_eq!(fake.connections(), 0, "no connection was even opened");
}

#[tokio::test]
async fn the_smuggling_corpus_never_reaches_the_database_as_anything_but_one_evaluated_statement() {
    let (fake, rt, _) = setup(fake_pg::shared_with_mask()).await;
    let long = format!("SELECT {}", "1 + ".repeat(5000) + "1");
    let corpus: Vec<String> = vec![
        "SELECT 1; DELETE FROM users".into(),
        "SELECT 1;DELETE FROM users;".into(),
        "SELECT ';' ; DROP TABLE users".into(),
        "SELECT $$;$$; DROP TABLE users".into(),
        "SELECT $tag$ ; DROP TABLE users; $tag$".into(),
        "SELECT 1 /* ; */; DROP TABLE users".into(),
        "SELECT 1 /* nested /* ; */ still */; DROP TABLE users".into(),
        "SELECT 1 -- ;\n; DROP TABLE users".into(),
        "SELECT 1 -- \n DROP TABLE users".into(),
        "SELECT 'a\\'; DROP TABLE users; --'".into(),
        "SELECT E'\\'; DROP TABLE users; --'".into(),
        "SELECT E'a\\\\'; DROP TABLE users; --'".into(),
        "SELECT \"; DROP TABLE users; --\" FROM t".into(),
        "SELECT 1；DROP TABLE users".into(),
        "SELECT U&'\\0000'".into(),
        "SELECT U&'d\\0061t\\+000061'".into(),
        "SELECT 1\u{0}".into(),
        "SELECT 1\u{0}; DROP TABLE users".into(),
        "SELECT email FROM users\u{0}".into(),
        "SELECT email FROM users".into(),
        "SELECT email FROM users; SELECT 1".into(),
        "SELECT /*; DELETE FROM users */ email FROM users".into(),
        "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d".into(),
        "SELECT * FROM users WHERE id = $0".into(),
        "SELECT * FROM users WHERE id = $2".into(),
        "BEGIN; SELECT 1".into(),
        "COMMIT".into(),
        "ROLLBACK".into(),
        "SELECT 1 \\g".into(),
        "\\! rm -rf /".into(),
        "SELECT ﻿1".into(),
        "SELECT 'Ω≈ç√∫'".into(),
        "SELECT 1\r\n;\r\nDROP TABLE users".into(),
        long,
    ];
    for sql in &corpus {
        fake.clear();
        let out = call(&rt, json!({ "sql": sql })).await;
        let parses = fake.parses();
        match parses.len() {
            0 => {}
            1 => {
                // It ran: it must be one statement, a read, and the bytes sent
                // are the evaluator's (the input or its mask rewrite).
                assert!(
                    !sql.contains('\0'),
                    "{sql:?} reached the database with a NUL"
                );
                let expected =
                    evaluated_text(&rt, sql).expect("ran, so the evaluator forwarded it");
                assert_eq!(parses[0], expected.as_bytes(), "{sql:?}");
                let owned = sql.clone();
                let count = crate::mcp::stack::on_big_stack_sync(move || {
                    crate::mcp::classify::statement_count(&owned)
                })
                .unwrap();
                assert_eq!(count, 1, "{sql:?}");
                assert_eq!(
                    out.structured["status"], "EXECUTED",
                    "{sql:?}: {}",
                    out.text
                );
            }
            n => panic!("{sql:?} produced {n} Parse messages"),
        }
        for q in fake.queries() {
            assert!(control::is_control(&q), "{sql:?}: non-control query {q}");
        }
        if parses.is_empty() {
            assert!(
                out.is_error,
                "{sql:?}: not run, so the answer is an error: {}",
                out.text
            );
        }
    }
}

#[tokio::test]
async fn rows_are_capped_and_the_cut_is_said_three_times() {
    let (fake, rt, q) = setup(Shared::built_in()).await;
    let sql = "SELECT id FROM orders ORDER BY id";
    let rows: Vec<Vec<Option<String>>> = (0..300).map(|i| vec![Some(i.to_string())]).collect();
    fake.answer(
        sql,
        Answer {
            columns: vec![("id".into(), 20)],
            rows,
            ..Default::default()
        },
    );
    let out = call(&rt, json!({ "sql": sql, "max_rows": 50 })).await;
    let s = &out.structured;
    assert_eq!(s["row_count"], 50);
    assert_eq!(s["truncated"], true);
    assert_eq!(
        s["truncation"],
        json!({ "reason": "max_rows", "limit": 50 })
    );
    // FLAGGED (no LIMIT) and cut: mention the finding, then refine.
    let actions: Vec<&str> = s["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|st| st["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"refine_query"), "{actions:?}");
    assert!(out.text.contains("more exist"), "{}", out.text);
    assert!(fake.seen().contains(&Seen::Execute { max_rows: 51 }));
    let ev = fake_pg::events(&q);
    assert_eq!(ev[0].truncated, Some(true));
    assert_eq!(ev[0].rows_returned, Some(50));
}

#[tokio::test]
async fn large_values_are_cut_and_the_byte_cap_holds() {
    let (fake, rt, _) = setup(Shared::built_in()).await;
    let sql = "SELECT body FROM docs";
    let big = "x".repeat(20_000);
    fake.answer(
        sql,
        Answer {
            columns: vec![("body".into(), 25)],
            rows: (0..100).map(|_| vec![Some(big.clone())]).collect(),
            ..Default::default()
        },
    );
    let out = call(&rt, json!({ "sql": sql })).await;
    let s = &out.structured;
    assert!(s["cells_truncated"].as_u64().unwrap() > 0);
    assert!(s["rows"][0][0].as_str().unwrap().contains("…[truncated "));
    let bytes = serde_json::to_string(&s["rows"]).unwrap().len();
    assert!(bytes <= 256 * 1024 + 64, "rows are {bytes} bytes");
    assert_eq!(s["truncation"]["reason"], "max_bytes");
}

#[tokio::test]
async fn database_errors_reach_the_agent_without_values() {
    let (fake, rt, q) = setup(Shared::built_in()).await;
    let sql = "SELECT 1 FROM people WHERE CAST(ssn AS int) = 0";
    fake.answer(
        sql,
        Answer::error(
            "22P02",
            "invalid input syntax for type integer: \"123-45-6789\"",
        ),
    );
    let out = call(&rt, json!({ "sql": sql })).await;
    let s = &out.structured;
    assert_eq!(s["status"], "ERROR");
    assert_eq!(s["error"]["code"], "DATABASE_ERROR");
    assert_eq!(s["error"]["sqlstate"], "22P02");
    let text = serde_json::to_string(s).unwrap() + &out.text;
    assert!(!text.contains("123-45-6789"), "{text}");
    assert!(
        !text.contains("a detail with a value"),
        "DETAIL is dropped: {text}"
    );
    assert_eq!(s["next_action"], "fix_sql_error");
    let ev = fake_pg::events(&q);
    assert_eq!(ev[0].sqlstate.as_deref(), Some("22P02"));
    assert_eq!(ev[0].execution_status.as_deref(), Some("db_error"));
    // The transaction was rolled back and the connection reused.
    assert_eq!(
        fake.queries().last().map(String::as_str),
        Some(control::ROLLBACK)
    );
    fake.clear();
    let ok = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert!(!ok.is_error);
    assert_eq!(
        fake.connections(),
        1,
        "one pooled connection served both calls"
    );
}

#[tokio::test]
async fn a_statement_timeout_is_timeout_and_never_retried_unchanged() {
    let (fake, rt, q) = setup(Shared::built_in()).await;
    let sql = "SELECT count(*) FROM events WHERE kind = 'x'";
    fake.answer(
        sql,
        Answer::error("57014", "canceling statement due to statement timeout"),
    );
    let out = call(&rt, json!({ "sql": sql, "timeout_ms": 2500 })).await;
    assert_eq!(out.structured["error"]["code"], "TIMEOUT");
    assert_eq!(out.structured["next_action"], "refine_query");
    assert!(
        out.structured["next_steps"][0]["message"]
            .as_str()
            .unwrap()
            .contains("2.5 s")
    );
    assert!(fake.queries()[0].contains("statement_timeout = 2500"));
    assert_eq!(
        fake_pg::events(&q)[0].execution_status.as_deref(),
        Some("timeout")
    );
}

#[tokio::test]
async fn the_kill_switch_refuses_before_anything_is_evaluated_or_sent() {
    let shared = Shared::built_in();
    shared.kill_switch.store(
        crate::tcp::kill_switch::KillSwitch::from_sync(Some(json!({
            "db_users": { "agent_ro": { "block_id": "blk-1", "message": "Vericto blocked this query [VERICTO-105]: stopped." } }
        })))
        .map(Arc::new),
    );
    let (fake, rt, q) = setup(shared).await;
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["error"]["code"], "KILL_SWITCH");
    assert_eq!(out.structured["next_action"], "stop");
    assert_only(&fake, None);
    let ev = fake_pg::events(&q);
    assert_eq!(ev[0].kill_switch_id.as_deref(), Some("blk-1"));
    // The bundle's own block of this server's key stops it as well.
    let shared = Shared::built_in();
    shared.watch.record_for_tests(
        "v2",
        Some(json!({ "self": { "key_id": "k-proxy", "sql_read": true, "kill_switch": { "block_id": "blk-2", "message": "stopped" } } })),
    );
    let (fake, rt, _) = setup(shared).await;
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["error"]["block_id"], "blk-2");
    assert_only(&fake, None);
}

#[tokio::test]
async fn nothing_runs_before_a_signed_bundle_when_one_is_required() {
    let fake = FakePg::start(Auth::Trust).await;
    let (rt, q) = fake_pg::runtime(
        &fake_pg::url(&fake),
        Shared::built_in(),
        Opts {
            require_control_plane: true,
            telemetry: true,
            ..Default::default()
        },
    );
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["error"]["code"], "NOT_READY");
    assert_eq!(out.structured["next_action"], "retry_later");
    assert_only(&fake, None);
    assert_eq!(
        fake_pg::events(&q)[0].execution_status.as_deref(),
        Some("blocked")
    );
    rt.shared.watch.record_for_tests("v1", None);
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    assert_eq!(out.structured["ruleset_version"], "v1");
}

#[tokio::test]
async fn the_read_tier_follows_the_bundle_and_its_limits_only_lower() {
    let shared = Shared::built_in();
    shared.watch.record_for_tests(
        "v3",
        Some(json!({
            "tiers": { "read": "off", "write": "off", "delete": "off", "ddl": "off" },
            "self": { "key_id": "k", "sql_read": false, "kill_switch": null },
            "limits": { "max_rows": 10, "max_rows_cap": 5000, "max_result_bytes": 999999999 }
        })),
    );
    let (fake, rt, _) = setup(shared).await;
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["error"]["code"], "TIER_NOT_ENABLED");
    assert_eq!(out.structured["error"]["layer"], "scope");
    assert!(
        out.structured["next_steps"][0]["message"]
            .as_str()
            .unwrap()
            .contains("sql:read")
    );
    assert_only(&fake, None);
    let l = rt.limits();
    assert_eq!(l.max_rows, 10, "lowered by the control plane");
    assert_eq!(l.max_rows_cap, 1000, "never raised by it");
    assert_eq!(l.max_result_bytes, 256 * 1024);
}

#[tokio::test]
async fn md5_and_cleartext_without_tls_are_refused_off_loopback_rules() {
    // MD5 is refused unless allowed.
    let fake = FakePg::start(Auth::Md5).await;
    let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), Shared::built_in(), Opts::default());
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["error"]["code"], "DATABASE_UNAVAILABLE");
    assert_eq!(out.structured["next_action"], "stop", "{}", out.structured);
    assert!(
        !fake
            .all_seen()
            .iter()
            .any(|s| matches!(s, Seen::Password(_))),
        "no MD5 hash was sent"
    );
    let (rt, _) = fake_pg::runtime(
        &fake_pg::url(&fake),
        Shared::built_in(),
        Opts {
            extra: vec![("VERICTO_MCP_ALLOW_MD5", "true".into())],
            ..Default::default()
        },
    );
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    // A cleartext password goes only to loopback (or over TLS).
    let fake = FakePg::start(Auth::Cleartext).await;
    let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), Shared::built_in(), Opts::default());
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    assert_eq!(
        out.structured["status"], "EXECUTED",
        "loopback: {}",
        out.text
    );
    assert!(fake.all_seen().contains(&Seen::Password(b"pw\0".to_vec())));
}

#[tokio::test]
async fn an_unreachable_database_is_retry_later_and_names_no_host() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let (rt, q) = fake_pg::runtime(
        &format!("postgres://agent_ro:hunter2@127.0.0.1:{port}/shop"),
        Shared::built_in(),
        Opts {
            telemetry: true,
            ..Default::default()
        },
    );
    let out = call(&rt, json!({ "sql": "SELECT 1" })).await;
    let s = &out.structured;
    assert_eq!(s["error"]["code"], "DATABASE_UNAVAILABLE");
    assert_eq!(s["next_action"], "retry_later");
    let text = serde_json::to_string(s).unwrap() + &out.text;
    assert!(
        !text.contains("hunter2") && !text.contains(&port.to_string()),
        "{text}"
    );
    assert_eq!(
        fake_pg::events(&q)[0].execution_status.as_deref(),
        Some("db_error")
    );
}

#[tokio::test]
async fn every_answer_carries_every_field_of_the_output_schema() {
    let (fake, rt, _) = setup(Shared::built_in()).await;
    fake.answer(
        "SELECT * FROM userz",
        Answer::error("42P01", "relation \"userz\" does not exist"),
    );
    for args in [
        json!({ "sql": "SELECT 1" }),
        json!({ "sql": "DROP TABLE users" }),
        json!({ "sql": "SELECT * FROM userz" }),
        json!({ "sql": "SELECT 1; SELECT 2" }),
        json!({ "sql": "DELETE FROM users WHERE id = 1" }),
    ] {
        let out = call(&rt, args.clone()).await;
        for k in crate::mcp::tools::EXECUTE_SQL_REQUIRED {
            assert!(
                out.structured.get(*k).is_some(),
                "{args}: missing {k}: {}",
                out.structured
            );
        }
        assert_eq!(
            out.is_error,
            matches!(out.structured["status"].as_str(), Some("BLOCKED" | "ERROR"))
        );
        assert!(out.text.contains("Next: "), "{}", out.text);
    }
}

#[test]
fn input_is_parsed_as_the_contract_says() {
    let limits = crate::mcp::config::Limits::default();
    let doc: Value = serde_json::from_str(include_str!(
        "../../tests/mcp-contract/execute-sql-input.json"
    ))
    .unwrap();
    for valid in doc["valid"].as_array().unwrap() {
        assert!(
            execute::parse_input(valid, &limits, 1 << 20).is_ok(),
            "{valid}"
        );
    }
    for case in doc["invalid"].as_array().unwrap() {
        assert!(
            execute::parse_input(&case["input"], &limits, 1 << 20).is_err(),
            "{}: {}",
            case["why"],
            case["input"]
        );
    }
}
