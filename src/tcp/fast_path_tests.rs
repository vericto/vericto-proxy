// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The trivial-statement fast path (`fast_path`, 4.19.0) never answers a
//! statement differently from the full evaluation.
//!
//! Every entry and many near misses (comments, a second statement after `;`,
//! other whitespace, case, Unicode look-alikes, `SET ROLE`, `SET SESSION
//! AUTHORIZATION`, `BEGIN; DROP …`) go through two real sessions, one with the
//! fast path and one without, each statement twice (the second time is the one
//! the fast path may answer), under every policy configuration that can bear on
//! them: the built-in rules, monitor mode, parse errors blocked, sensitive
//! columns, an enforced agent-access allowlist, a custom rule that blocks every
//! SELECT; raw and sanitized telemetry; PostgreSQL simple query and Parse, MySQL
//! COM_QUERY and COM_STMT_PREPARE. What reaches the database, what the client
//! gets back, and every telemetry event but its id, time and latency, must be
//! the same.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use vericto_engine::{
    AccessPolicyMap, EnforcementPolicy, ParseErrorAction, Rule, RuleType, Severity,
};

use super::sensitive_tests::{
    Wire, config_with, events, my_cmd, pg_parse, pg_query, pg_sync, read_my, read_pg, wire_as,
};
use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE};
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::telemetry::queue::MemoryQueue;

const USER: &str = "app_user";

/// Every entry, in the forms that are entries, and the near misses.
fn statements() -> Vec<String> {
    let mut all: Vec<String> = crate::tcp::fast_path::ENTRIES
        .iter()
        .flat_map(|e| {
            [
                e.to_string(),
                e.to_lowercase(),
                format!("  {e}  "),
                format!("{e};"),
                format!("{e} ;"),
                format!("\t{e};\n"),
            ]
        })
        .collect();
    for near in [
        "BEGIN;;",
        "BEGIN; DROP TABLE users",
        "BEGIN; DELETE FROM users",
        "COMMIT; DROP TABLE users",
        "SELECT 1; DELETE FROM users",
        "BEGIN -- comment",
        "/* comment */ BEGIN",
        "BEGIN /* comment */",
        "SELECT 1 -- comment",
        "SELECT/**/1",
        "BEGIN\u{00a0}",
        "BEGIN\u{200b}",
        "\u{feff}BEGIN",
        "B\u{0130}GIN",
        "\u{0392}EGIN",
        "SELEC\u{0422} 1",
        "SELECT  1",
        "SELECT 01",
        "SELECT 1 FROM users",
        "SELECT 1, password FROM users",
        "SET ROLE admin",
        "SET SESSION AUTHORIZATION admin",
        "SET search_path TO evil",
        "SET autocommit = 1",
        "SET NAMES latin1",
        "START TRANSACTION READ ONLY",
        "ROLLBACK TO SAVEPOINT a",
        "BEGIN ISOLATION LEVEL SERIALIZABLE",
        "DELETE FROM users",
        "SELECT * FROM users",
    ] {
        all.push(near.to_string());
    }
    all
}

/// The configurations: (name, policy, rules, allowlist for USER).
fn configurations() -> Vec<(&'static str, EnforcementPolicy, Vec<Rule>, AccessPolicyMap)> {
    let builtin = crate::tcp::evaluator::default_ruleset;
    let mut block_select = builtin();
    block_select.push(Rule {
        rule_id: "custom-no-select".into(),
        code: "CUSTOM-SELECT".into(),
        severity: Severity::High,
        default_action: vericto_engine::EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some("rule: no-select\nnode_type: SelectStmt\n".into()),
    });
    let allowlist: AccessPolicyMap = serde_json::from_value(serde_json::json!({
        USER: { "mode": "enforce", "ddl": "deny", "entries": [
            { "table": "orders", "columns": "*", "access": "read" }
        ]}
    }))
    .unwrap();
    let tags = serde_json::from_value(serde_json::json!([
        { "schema": null, "table": "users", "column": "password", "policy": "block" }
    ]))
    .unwrap();
    vec![
        (
            "built-in",
            EnforcementPolicy::default(),
            builtin(),
            Default::default(),
        ),
        (
            "monitor mode",
            EnforcementPolicy {
                monitor_mode: true,
                ..Default::default()
            },
            builtin(),
            Default::default(),
        ),
        (
            "parse errors blocked",
            EnforcementPolicy {
                parse_error: ParseErrorAction::Block,
                ..Default::default()
            },
            builtin(),
            Default::default(),
        ),
        (
            "sensitive columns",
            EnforcementPolicy {
                sensitive_columns: tags,
                ..Default::default()
            },
            builtin(),
            Default::default(),
        ),
        (
            "allowlist",
            EnforcementPolicy::default(),
            builtin(),
            allowlist,
        ),
        (
            "custom rule on SELECT",
            EnforcementPolicy::default(),
            block_select,
            Default::default(),
        ),
    ]
}

fn session(
    mysql: bool,
    fast: bool,
    mode: TelemetryQueryMode,
    policy: &EnforcementPolicy,
    rules: &[Rule],
    access: &AccessPolicyMap,
) -> (Wire, Arc<PgProxyConfig>) {
    let (cfg, queue) = config_with(
        ("unused", 0),
        policy.clone(),
        mode,
        rules.to_vec(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let mut cfg = Arc::into_inner(cfg).expect("unshared config");
    cfg.trivial_fast_path = fast;
    cfg.agent_access.store(Arc::new(access.clone()));
    let cfg = Arc::new(cfg);
    let proto: Box<dyn WireProtocol> = if mysql {
        Box::new(MysqlProtocol)
    } else {
        Box::new(PostgresProtocol)
    };
    (wire_as(proto, Arc::clone(&cfg), queue, Some(USER)), cfg)
}

/// How a statement is sent: PostgreSQL simple query or Parse + Sync, MySQL
/// COM_QUERY or COM_STMT_PREPARE.
#[derive(Clone, Copy, Debug)]
enum Way {
    PgQuery,
    PgParse,
    MyQuery,
    MyPrepare,
}

/// Sends `sql`; what reached the database or what the client got back.
async fn exchange(w: &mut Wire, way: Way, sql: &str) -> String {
    match way {
        Way::MyQuery | Way::MyPrepare => {
            let cmd = if matches!(way, Way::MyQuery) {
                COM_QUERY
            } else {
                COM_STMT_PREPARE
            };
            w.client.write_all(&my_cmd(cmd, sql)).await.unwrap();
            tokio::select! {
                p = read_my(&mut w.db) => format!("db {:?}", p.encode()),
                p = read_my(&mut w.client) => format!("client {:?}", p.encode()),
            }
        }
        Way::PgQuery | Way::PgParse => {
            let extended = matches!(way, Way::PgParse);
            let bytes = if extended {
                [pg_parse("", sql, &[]), pg_sync()].concat()
            } else {
                pg_query(sql)
            };
            w.client.write_all(&bytes).await.unwrap();
            tokio::select! {
                m = read_pg(&mut w.db) => {
                    let mut seen = format!("db {:?}", m.encode());
                    if extended {
                        seen.push_str(&format!(" {:?}", read_pg(&mut w.db).await.encode()));
                    }
                    seen
                }
                m = read_pg(&mut w.client) => {
                    let mut seen = format!("client {:?}", m.encode());
                    if m.tag == b'E' {
                        seen.push_str(&format!(" {:?}", read_pg(&mut w.client).await.encode()));
                    }
                    seen
                }
            }
        }
    }
}

/// The events, without what differs between two runs of the same statements.
fn stable(queue: &MemoryQueue) -> Vec<serde_json::Value> {
    let mut all = Vec::new();
    loop {
        let batch = events(queue);
        if batch.is_empty() {
            break;
        }
        all.extend(batch);
    }
    for e in &mut all {
        let o = e.as_object_mut().unwrap();
        for k in ["event_id", "occurred_at", "latency_ms"] {
            o.remove(k);
        }
    }
    all
}

#[tokio::test]
async fn the_fast_path_answers_every_statement_as_the_full_evaluation_does() {
    let statements = statements();
    for way in [Way::PgQuery, Way::PgParse, Way::MyQuery, Way::MyPrepare] {
        let mysql = matches!(way, Way::MyQuery | Way::MyPrepare);
        for ((name, policy, rules, access), mode) in configurations().into_iter().flat_map(|c| {
            [
                (c.clone(), TelemetryQueryMode::Raw),
                (c, TelemetryQueryMode::Sanitized),
            ]
        }) {
            let (mut fast, _) = session(mysql, true, mode, &policy, &rules, &access);
            let (mut full, _) = session(mysql, false, mode, &policy, &rules, &access);
            let (mut fast_events, mut full_events) = (Vec::new(), Vec::new());
            for sql in &statements {
                for round in 0..2 {
                    let a = exchange(&mut fast, way, sql).await;
                    let b = exchange(&mut full, way, sql).await;
                    assert_eq!(a, b, "{name}, {mode:?}, {way:?}, {sql:?}, round {round}");
                }
                // Drained as the session goes: the test queue holds 100 events.
                fast_events.extend(stable(&fast.queue));
                full_events.extend(stable(&full.queue));
            }
            assert_eq!(
                fast_events.len(),
                statements.len() * 2,
                "{name}, mysql={mysql}"
            );
            assert_eq!(fast_events, full_events, "{name}, mysql={mysql}: telemetry");
        }
    }
}

/// A sync that changes what a remembered statement deserves applies from the
/// session's next statement: `SELECT 1` is forwarded, blocked once a rule
/// against SELECT arrives, and forwarded again when it goes.
#[tokio::test]
async fn a_new_ruleset_or_policy_is_never_answered_from_the_old_one() {
    let configs = configurations();
    let (_, _, block_select, _) = configs
        .iter()
        .find(|c| c.0 == "custom rule on SELECT")
        .unwrap();
    for way in [Way::PgQuery, Way::PgParse, Way::MyQuery, Way::MyPrepare] {
        let mysql = matches!(way, Way::MyQuery | Way::MyPrepare);
        let (mut w, cfg) = session(
            mysql,
            true,
            TelemetryQueryMode::Raw,
            &EnforcementPolicy::default(),
            &crate::tcp::evaluator::default_ruleset(),
            &Default::default(),
        );
        let forwarded = |s: &str| s.starts_with("db ");
        for _ in 0..2 {
            assert!(forwarded(&exchange(&mut w, way, "SELECT 1").await));
        }
        cfg.ruleset.store(Arc::new(block_select.clone()));
        for _ in 0..2 {
            let seen = exchange(&mut w, way, "SELECT 1").await;
            assert!(!forwarded(&seen), "blocked under the new ruleset: {seen}");
        }
        cfg.ruleset
            .store(Arc::new(crate::tcp::evaluator::default_ruleset()));
        assert!(forwarded(&exchange(&mut w, way, "SELECT 1").await));

        // The policy too: monitor mode, then back.
        cfg.ruleset.store(Arc::new(block_select.clone()));
        cfg.policy.store(Arc::new(EnforcementPolicy {
            monitor_mode: true,
            ..Default::default()
        }));
        assert!(
            forwarded(&exchange(&mut w, way, "SELECT 1").await),
            "monitor mode forwards"
        );
        cfg.policy.store(Arc::new(EnforcementPolicy::default()));
        assert!(!forwarded(&exchange(&mut w, way, "SELECT 1").await));
    }
}
