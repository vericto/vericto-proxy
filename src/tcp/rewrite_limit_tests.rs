// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `rewrite_limit` on the wire (4.17.0, engine 4.5.0): a business policy that
//! bounds the reads of a principal. Under `VERICTO_POLICY_RULES=enforce` the
//! proxy forwards the bounded statement (the engine's `rewritten_query`) in
//! place of the client's, on Postgres (simple query and Parse) and MySQL
//! (COM_QUERY and COM_STMT_PREPARE); `off` and `observe` forward the client's
//! statement byte for byte. The in-memory half checks what reaches the
//! database and what the event says; the real-database half (skipped without
//! `VERICTO_TEST_PG_URL` / `VERICTO_TEST_MYSQL_URL`) checks the rows the
//! client gets back.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::AsyncWriteExt;
use vericto_engine::{EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity};

use super::sensitive_tests::{
    Wire, config_with, connect, cstr, events, my_cmd, my_sql, mysql_url, pg_error, pg_parse,
    pg_query, pg_url, read_my, read_pg, spawn_mysql_proxy, split_parse, via_proxy, wire_start,
};
use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE};
use crate::tcp::policy_rules::{PolicyRulesMode, PolicyRulesRuntime, bundle_from_sync};
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::tcp::session::SessionStart;
use crate::telemetry::queue::MemoryQueue;

const BOT: &str = "support_bot";
const CAP: u64 = 100;
const CODE: &str = "POL-CAP";

/// The LIMIT cap template's rewrite mode: agents read at most [`CAP`] rows.
fn cap_rule() -> Rule {
    Rule {
        rule_id: "r-cap".into(),
        code: CODE.into(),
        severity: Severity::Low,
        default_action: EnforcementAction::Monitor,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(format!(
            "rule: cap-agent-reads\n\
             applies_to: {{ principal_types: [agent] }}\n\
             action: {{ rewrite_limit: {CAP} }}\n\
             message: agent reads are capped\n"
        )),
    }
}

fn rules() -> Vec<Rule> {
    let mut r = crate::tcp::evaluator::default_ruleset();
    r.push(cap_rule());
    r
}

/// `agent_user` is an agent; every other user is unknown (and not capped).
fn principals(agent_user: &str) -> serde_json::Value {
    serde_json::json!({ "version": "p1", "entries": [
        { "id": "agent-bot", "type": "agent", "identify": { "db_user": agent_user } }
    ]})
}

fn proxy_config(
    mode: PolicyRulesMode,
    upstream: (&str, u16),
    policy: EnforcementPolicy,
    telemetry: TelemetryQueryMode,
    agent_user: &str,
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let (cfg, queue) = config_with(
        upstream,
        policy,
        telemetry,
        rules(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let mut cfg = Arc::into_inner(cfg).expect("unshared config");
    let bundle = if mode.is_on() {
        let b = bundle_from_sync(
            mode,
            cfg.ruleset.load_full(),
            Some(principals(agent_user)),
            "v-test",
        );
        assert!(b.policies.errors().is_empty(), "{:?}", b.policies.errors());
        b
    } else {
        Default::default()
    };
    cfg.policy_rules = PolicyRulesRuntime {
        mode,
        bundle: Arc::new(ArcSwap::from_pointee(bundle)),
        listener: "0.0.0.0:5433".into(),
        database_id: Some("00000000-0000-0000-0000-000000000001".into()),
    };
    (Arc::new(cfg), queue)
}

fn session_with(
    proto: Box<dyn WireProtocol>,
    mode: PolicyRulesMode,
    user: &str,
    policy: EnforcementPolicy,
    telemetry: TelemetryQueryMode,
) -> Wire {
    let (cfg, queue) = proxy_config(mode, ("unused", 0), policy, telemetry, BOT);
    wire_start(
        proto,
        cfg,
        queue,
        SessionStart {
            user: Some(user.into()),
            ..Default::default()
        },
    )
}

fn pg(mode: PolicyRulesMode) -> Wire {
    session_with(
        Box::new(PostgresProtocol),
        mode,
        BOT,
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
    )
}

fn my(mode: PolicyRulesMode) -> Wire {
    session_with(
        Box::new(MysqlProtocol),
        mode,
        BOT,
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
    )
}

/// The simple query `sql` as the database received it.
async fn pg_sent(w: &mut Wire, sql: &str) -> String {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'Q', "{sql}");
    cstr(&m.body)
}

/// The SQL of the COM_QUERY / COM_STMT_PREPARE `cmd` as the database received it.
async fn my_sent(w: &mut Wire, cmd: u8, sql: &str) -> String {
    w.client.write_all(&my_cmd(cmd, sql)).await.unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(p.payload[0], cmd, "{sql}: same command");
    assert_eq!(p.seq, 0, "{sql}: the sequence id is kept");
    my_sql(&p)
}

const UNBOUNDED: &str = "SELECT id, status FROM orders WHERE status = 'open'";

// ── Postgres ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pg_enforce_forwards_the_bounded_select_and_reports_it() {
    let mut w = pg(PolicyRulesMode::Enforce);
    let bounded = format!("{UNBOUNDED} LIMIT {CAP}");
    assert_eq!(pg_sent(&mut w, UNBOUNDED).await, bounded);

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    let e = &ev[0];
    assert_ne!(e["status"], "BLOCKED", "{e}");
    assert_eq!(e["query_text"], UNBOUNDED, "the original is reported");
    assert_eq!(e["rewritten_query"], bounded.as_str());
    let finding = e["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["rule_code"] == CODE)
        .unwrap_or_else(|| panic!("the policy's finding: {e}"));
    assert_eq!(finding["enforcement_action"], "monitor");
    assert!(
        finding
            .get("suggested_safe_query")
            .is_none_or(|s| s.is_null()),
        "the bounded text travels once, in rewritten_query: {finding}"
    );
    // VERICTO-050 still reports the client's statement as unbounded.
    assert!(
        e["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["rule_code"] == "VERICTO-050"),
        "{e}"
    );
}

#[tokio::test]
async fn pg_enforce_lowers_a_larger_limit_and_keeps_a_smaller_one() {
    let mut w = pg(PolicyRulesMode::Enforce);
    assert_eq!(
        pg_sent(
            &mut w,
            "SELECT id FROM orders ORDER BY id LIMIT 5000 OFFSET 20"
        )
        .await,
        format!("SELECT id FROM orders ORDER BY id LIMIT {CAP} OFFSET 20")
    );
    let small = "SELECT id FROM orders ORDER BY id LIMIT 10";
    assert_eq!(pg_sent(&mut w, small).await, small, "byte for byte");
    let ev = events(&w.queue);
    assert!(ev[1].get("rewritten_query").is_none(), "{}", ev[1]);
}

/// Statements a LIMIT does not apply to reach the database as they came.
#[tokio::test]
async fn pg_enforce_leaves_what_is_not_a_bounded_read_untouched() {
    let mut w = pg(PolicyRulesMode::Enforce);
    for sql in [
        "UPDATE orders SET status = 'done' WHERE id = 1",
        "INSERT INTO orders (id, status) VALUES (1, 'open')",
        "DELETE FROM orders WHERE id = 1",
        "SELECT count(*) FROM orders",
        "SELECT 1",
        "SET search_path = public",
    ] {
        assert_eq!(pg_sent(&mut w, sql).await, sql, "{sql}");
    }
    assert!(
        events(&w.queue)
            .iter()
            .all(|e| e.get("rewritten_query").is_none())
    );
}

/// Parse (extended protocol): the same statement name and parameter types, the
/// bounded text; a `LIMIT $n` keeps its parameter (`LEAST($n::bigint, cap)`).
#[tokio::test]
async fn pg_enforce_bounds_a_parse_and_keeps_its_name_types_and_parameters() {
    let mut w = pg(PolicyRulesMode::Enforce);
    for (sql, types, want) in [
        (
            "SELECT id FROM orders WHERE id > $1",
            vec![23],
            format!("SELECT id FROM orders WHERE id > $1 LIMIT {CAP}"),
        ),
        (
            "SELECT id FROM orders WHERE id > $1 ORDER BY id LIMIT $2",
            vec![23, 20],
            format!(
                "SELECT id FROM orders WHERE id > $1 ORDER BY id LIMIT LEAST($2::bigint, {CAP})"
            ),
        ),
    ] {
        w.client
            .write_all(&pg_parse("s1", sql, &types))
            .await
            .unwrap();
        let m = read_pg(&mut w.db).await;
        assert_eq!(m.tag, b'P');
        let (name, query, sent_types) = split_parse(&m.body);
        assert_eq!(name, "s1");
        assert_eq!(sent_types, types);
        assert_eq!(query, want, "{sql}");
    }
    // A Parse with a small enough literal LIMIT is forwarded byte for byte.
    let small = pg_parse("s2", "SELECT id FROM orders WHERE id > $1 LIMIT 5", &[23]);
    w.client.write_all(&small).await.unwrap();
    assert_eq!(read_pg(&mut w.db).await.encode(), small);
}

/// Only the principal the policy names is bounded.
#[tokio::test]
async fn pg_enforce_leaves_other_principals_unbounded() {
    let mut w = session_with(
        Box::new(PostgresProtocol),
        PolicyRulesMode::Enforce,
        "reporting_user",
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
    );
    assert_eq!(pg_sent(&mut w, UNBOUNDED).await, UNBOUNDED);
}

/// `off` is 4.16.2: the policy is not evaluated and nothing is rewritten.
/// `observe` reports the would-be rewrite and forwards the original.
#[tokio::test]
async fn pg_off_and_observe_forward_the_original() {
    let mut w = pg(PolicyRulesMode::Off);
    assert_eq!(pg_sent(&mut w, UNBOUNDED).await, UNBOUNDED);
    let ev = events(&w.queue);
    assert!(ev[0].get("rewritten_query").is_none());
    assert!(
        ev[0]["violations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["rule_code"] != CODE),
        "{}",
        ev[0]
    );

    let mut w = pg(PolicyRulesMode::Observe);
    assert_eq!(pg_sent(&mut w, UNBOUNDED).await, UNBOUNDED);
    let ev = events(&w.queue);
    assert!(ev[0].get("rewritten_query").is_none());
    let finding = ev[0]["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["rule_code"] == CODE)
        .cloned()
        .unwrap_or_else(|| panic!("observe reports the policy: {}", ev[0]));
    assert_eq!(
        finding["suggested_safe_query"],
        format!("{UNBOUNDED} LIMIT {CAP}"),
        "the would-be rewrite"
    );
}

/// The workspace's dry-run never changes what runs.
#[tokio::test]
async fn pg_enforce_under_monitor_mode_forwards_the_original() {
    let mut w = session_with(
        Box::new(PostgresProtocol),
        PolicyRulesMode::Enforce,
        BOT,
        EnforcementPolicy {
            monitor_mode: true,
            ..EnforcementPolicy::default()
        },
        TelemetryQueryMode::Raw,
    );
    assert_eq!(pg_sent(&mut w, UNBOUNDED).await, UNBOUNDED);
}

/// Sanitized telemetry: no literal of the client's statement leaves, neither in
/// the rewritten query nor in a would-be rewrite reported as a suggestion.
#[tokio::test]
async fn sanitized_telemetry_sanitizes_the_bounded_text() {
    for mode in [PolicyRulesMode::Enforce, PolicyRulesMode::Observe] {
        let mut w = session_with(
            Box::new(PostgresProtocol),
            mode,
            BOT,
            EnforcementPolicy::default(),
            TelemetryQueryMode::Sanitized,
        );
        pg_sent(&mut w, UNBOUNDED).await;
        let ev = events(&w.queue);
        let json = ev[0].to_string();
        assert!(!json.contains("'open'"), "{mode:?}: {json}");
        if mode == PolicyRulesMode::Enforce {
            let r = ev[0]["rewritten_query"].as_str().expect("rewritten_query");
            assert!(r.contains("LIMIT"), "{r}");
        }
    }
}

// ── MySQL ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mysql_enforce_bounds_com_query_and_com_stmt_prepare() {
    let mut w = my(PolicyRulesMode::Enforce);
    let got = my_sent(&mut w, COM_QUERY, UNBOUNDED).await;
    assert_eq!(got, format!("{UNBOUNDED} LIMIT {CAP}"));
    let got = my_sent(
        &mut w,
        COM_QUERY,
        "SELECT id FROM orders ORDER BY id LIMIT 20, 5000",
    )
    .await;
    assert_eq!(
        got,
        format!("SELECT id FROM orders ORDER BY id LIMIT 20, {CAP}")
    );
    let small = "SELECT id FROM orders ORDER BY id LIMIT 10";
    assert_eq!(my_sent(&mut w, COM_QUERY, small).await, small);

    let got = my_sent(
        &mut w,
        COM_STMT_PREPARE,
        "SELECT id FROM orders WHERE id > ?",
    )
    .await;
    assert_eq!(
        got,
        format!("SELECT id FROM orders WHERE id > ? LIMIT {CAP}")
    );

    let ev = events(&w.queue);
    assert_eq!(ev[0]["rewritten_query"], format!("{UNBOUNDED} LIMIT {CAP}"));
    assert!(ev[2].get("rewritten_query").is_none());
}

/// A MySQL `LIMIT ?` is only known at execution: UNKNOWN, `on_unknown` (default
/// `flag`) decides, and the statement is forwarded as it came.
#[tokio::test]
async fn mysql_a_limit_placeholder_is_forwarded_and_flagged() {
    let mut w = my(PolicyRulesMode::Enforce);
    let sql = "SELECT id FROM orders ORDER BY id LIMIT ?";
    assert_eq!(my_sent(&mut w, COM_STMT_PREPARE, sql).await, sql);
    let ev = events(&w.queue);
    assert!(ev[0].get("rewritten_query").is_none());
    assert!(
        ev[0]["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["rule_code"] == CODE && v["enforcement_action"] == "flag"),
        "{}",
        ev[0]
    );
}

#[tokio::test]
async fn mysql_enforce_leaves_writes_untouched_and_off_observe_forward_the_original() {
    let mut w = my(PolicyRulesMode::Enforce);
    for sql in [
        "UPDATE orders SET status = 'done' WHERE id = 1",
        "INSERT INTO orders (id, status) VALUES (1, 'open')",
        "SELECT COUNT(*) FROM orders",
    ] {
        assert_eq!(my_sent(&mut w, COM_QUERY, sql).await, sql);
    }
    for mode in [PolicyRulesMode::Off, PolicyRulesMode::Observe] {
        let mut w = my(mode);
        assert_eq!(
            my_sent(&mut w, COM_QUERY, UNBOUNDED).await,
            UNBOUNDED,
            "{mode:?}"
        );
        assert_eq!(
            my_sent(
                &mut w,
                COM_STMT_PREPARE,
                "SELECT id FROM orders WHERE id > ?"
            )
            .await,
            "SELECT id FROM orders WHERE id > ?",
            "{mode:?}"
        );
    }
}

/// A rewrite that cannot be applied safely blocks (engine: failure blocks),
/// with the policy's code: never the unbounded original.
#[tokio::test]
async fn a_rewrite_that_cannot_be_applied_blocks() {
    let mut w = pg(PolicyRulesMode::Enforce);
    let sql = "SELECT id FROM orders ORDER BY id FETCH FIRST 5000 ROWS WITH TIES";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    let (state, msg) = pg_error(&e.body);
    assert_eq!(state, "42501", "{msg}");
    assert!(msg.contains(CODE), "{msg}");

    let mut w = my(PolicyRulesMode::Enforce);
    w.client
        .write_all(&my_cmd(COM_QUERY, "SELECT id FROM orders"))
        .await
        .unwrap();
    // Sanity: the MySQL session is bounding (not blocking) the plain case.
    let p = read_my(&mut w.db).await;
    assert!(my_sql(&p).ends_with(&format!("LIMIT {CAP}")));
}

// ── Real Postgres ────────────────────────────────────────────────────────────

const ROWS: i64 = 250;

/// Runs `body` against a fresh database with `orders` (ids 1 to [`ROWS`]),
/// reached through a proxy in `enforce` whose policy bounds the admin user's
/// reads to [`CAP`] rows. The database is dropped afterwards.
async fn with_pg_orders<F, Fut>(body: F)
where
    F: FnOnce(tokio_postgres::Config) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let Some(admin_url) = pg_url() else {
        eprintln!("VERICTO_TEST_PG_URL not set: skipping the real-Postgres test");
        return;
    };
    let cfg: tokio_postgres::Config = admin_url.parse().expect("VERICTO_TEST_PG_URL");
    let host = match &cfg.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(h) => h.clone(),
        #[allow(unreachable_patterns)]
        _ => panic!("VERICTO_TEST_PG_URL must use a TCP host"),
    };
    let port = cfg.get_ports().first().copied().unwrap_or(5432);
    let user = cfg.get_user().unwrap_or("postgres").to_string();
    let db = format!(
        "vericto_proxy_limit_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let admin = connect(&cfg).await;
    admin
        .batch_execute(&format!("CREATE DATABASE {db}"))
        .await
        .unwrap();

    let result = tokio::spawn({
        let mut direct = cfg.clone();
        direct.dbname(&db);
        let db_name = db.clone();
        async move {
            let seed = connect(&direct).await;
            seed.batch_execute(&format!(
                "CREATE TABLE orders (id int PRIMARY KEY, status text);
                 INSERT INTO orders SELECT g, 'open' FROM generate_series(1, {ROWS}) g;"
            ))
            .await
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = listener.local_addr().unwrap().port();
            let (pcfg, _queue) = proxy_config(
                PolicyRulesMode::Enforce,
                (&host, port),
                EnforcementPolicy::default(),
                TelemetryQueryMode::Raw,
                &user,
            );
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    tokio::spawn(crate::tcp::postgres::handle_connection(sock, pcfg.clone()));
                }
            });
            let mut via = tokio_postgres::Config::new();
            via.host("127.0.0.1")
                .port(proxy_port)
                .dbname(&db_name)
                .user(&user);
            if let Some(pw) = direct.get_password() {
                via.password(pw);
            }
            body(via).await;
        }
    })
    .await;

    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .await
        .unwrap();
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

fn simple_rows(msgs: &[tokio_postgres::SimpleQueryMessage]) -> usize {
    msgs.iter()
        .filter(|m| matches!(m, tokio_postgres::SimpleQueryMessage::Row(_)))
        .count()
}

#[tokio::test]
async fn real_pg_reads_are_bounded_on_simple_and_extended_protocol() {
    with_pg_orders(|via| async move {
        let c = connect(&via).await;
        let cap = CAP as usize;
        // Simple query.
        let m = c.simple_query("SELECT id FROM orders").await.unwrap();
        assert_eq!(simple_rows(&m), cap);
        let m = c
            .simple_query("SELECT id FROM orders ORDER BY id LIMIT 1000")
            .await
            .unwrap();
        assert_eq!(simple_rows(&m), cap);
        let m = c
            .simple_query("SELECT id FROM orders ORDER BY id LIMIT 7")
            .await
            .unwrap();
        assert_eq!(simple_rows(&m), 7);
        // Extended protocol: unnamed statement, inferred parameter types.
        let rows = c
            .query("SELECT id FROM orders WHERE id > $1 ORDER BY id", &[&0i32])
            .await
            .unwrap();
        assert_eq!(rows.len(), cap);
        assert_eq!(rows[0].get::<_, i32>(0), 1, "the first rows, in order");
        // LIMIT $1 keeps its parameter and its inferred type (bigint).
        let rows = c
            .query("SELECT id FROM orders ORDER BY id LIMIT $1", &[&1000i64])
            .await
            .unwrap();
        assert_eq!(rows.len(), cap);
        let rows = c
            .query("SELECT id FROM orders ORDER BY id LIMIT $1", &[&3i64])
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        // Named statement with an explicit type, executed twice.
        let stmt = c
            .prepare_typed(
                "SELECT id FROM orders WHERE id >= $1",
                &[tokio_postgres::types::Type::INT4],
            )
            .await
            .unwrap();
        assert_eq!(c.query(&stmt, &[&1i32]).await.unwrap().len(), cap);
        assert_eq!(c.query(&stmt, &[&200i32]).await.unwrap().len(), 51);
        // Writes are untouched, and an aggregate counts every row.
        assert_eq!(
            c.execute(
                "UPDATE orders SET status = 'done' WHERE id <= $1",
                &[&150i32]
            )
            .await
            .unwrap(),
            150
        );
        let n: i64 = c
            .query_one("SELECT count(*) FROM orders", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, ROWS);
    })
    .await;
}

// ── Real MySQL ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn real_mysql_reads_are_bounded_on_text_and_prepared_statements() {
    use mysql_async::prelude::Queryable;
    let Some(url) = mysql_url() else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
        return;
    };
    let admin = mysql_async::Opts::from_url(&url).expect("VERICTO_TEST_MYSQL_URL");
    let user = admin.user().unwrap_or("root").to_string();
    let upstream = (admin.ip_or_hostname().to_string(), admin.tcp_port());
    // Seeding and cleanup through a proxy with no rules and no policies.
    let (plain, _) = config_with(
        (&upstream.0, upstream.1),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        Vec::new(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let (capped, _) = proxy_config(
        PolicyRulesMode::Enforce,
        (&upstream.0, upstream.1),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        &user,
    );
    let plain_port = spawn_mysql_proxy(plain).await;
    let capped_port = spawn_mysql_proxy(capped).await;
    let db = format!(
        "vericto_proxy_limit_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let mut conn = mysql_async::Conn::new(via_proxy(&admin, plain_port, None, false))
        .await
        .expect("connect (admin, policies off)");
    conn.query_drop(format!("CREATE DATABASE {db}"))
        .await
        .unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {db}.orders (id INT PRIMARY KEY, status VARCHAR(10))"
    ))
    .await
    .unwrap();
    conn.query_drop(format!(
        "INSERT INTO {db}.orders (id, status) WITH RECURSIVE s(n) AS \
         (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < {ROWS}) SELECT n, 'open' FROM s"
    ))
    .await
    .unwrap();

    let result = tokio::spawn({
        let opts = via_proxy(&admin, capped_port, Some(&db), false);
        async move {
            let cap = CAP as usize;
            let mut c = mysql_async::Conn::new(opts).await.unwrap();
            // COM_QUERY.
            let ids: Vec<i64> = c.query("SELECT id FROM orders").await.unwrap();
            assert_eq!(ids.len(), cap);
            let ids: Vec<i64> = c
                .query("SELECT id FROM orders ORDER BY id LIMIT 10, 1000")
                .await
                .unwrap();
            assert_eq!(ids.len(), cap);
            assert_eq!(ids[0], 11, "OFFSET kept");
            let ids: Vec<i64> = c
                .query("SELECT id FROM orders ORDER BY id LIMIT 7")
                .await
                .unwrap();
            assert_eq!(ids.len(), 7);
            // COM_STMT_PREPARE + COM_STMT_EXECUTE, twice.
            let stmt = c
                .prep("SELECT id FROM orders WHERE id >= ? ORDER BY id")
                .await
                .unwrap();
            let ids: Vec<i64> = c.exec(&stmt, (1,)).await.unwrap();
            assert_eq!(ids.len(), cap);
            let ids: Vec<i64> = c.exec(&stmt, (200,)).await.unwrap();
            assert_eq!(ids.len(), 51);
            // Writes are untouched; an aggregate counts every row.
            c.exec_drop("UPDATE orders SET status = 'done' WHERE id <= ?", (150,))
                .await
                .unwrap();
            assert_eq!(c.affected_rows(), 150);
            let n: Option<i64> = c.query_first("SELECT COUNT(*) FROM orders").await.unwrap();
            assert_eq!(n, Some(ROWS));
            c.disconnect().await.unwrap();
        }
    })
    .await;

    conn.query_drop(format!("DROP DATABASE IF EXISTS {db}"))
        .await
        .unwrap();
    conn.disconnect().await.unwrap();
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}
