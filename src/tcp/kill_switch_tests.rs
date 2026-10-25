// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The kill switch (VERICTO-105) on the wire, both protocols: in memory (the
//! real interception loop between in-memory client and database) and against a
//! real Postgres / MySQL (`VERICTO_TEST_PG_URL` / `VERICTO_TEST_MYSQL_URL`, as in
//! `sensitive_tests`), where a real driver prepares a statement before the block
//! and executes it after.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use vericto_engine::{AccessPolicyMap, EnforcementPolicy};

use super::sensitive_tests::{
    Wire, config_with, events, first_query_reaching_db, my_cmd, my_err, my_first_query_reaching_db,
    pg_error, pg_parse, pg_query, pg_sync, read_my, read_pg, wire_as,
};
use crate::tcp::codec::PgMessage;
use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE, MySqlPacket};
use crate::tcp::kill_switch::KillSwitch;
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::telemetry::queue::MemoryQueue;

const AGENT: &str = "support_agent";

/// The control plane's text (agent-blocks.ts `killSwitchMessage`).
fn message(id: &str, whom: &str) -> String {
    format!(
        "Vericto blocked this query [VERICTO-105]: the kill switch blocks every statement of {whom}, \
         set by Ann <ann@example.com> at 2026-10-24T21:09:02.508Z (block {id}). Do not retry and \
         do not work around it: stop and ask a person, who must review the incident and lift the block."
    )
}

fn user_block(user: &str, id: &str) -> Arc<KillSwitch> {
    Arc::new(
        KillSwitch::from_sync(Some(serde_json::json!({
            "db_users": { user: { "block_id": id, "target_type": "db_user", "message": message(id, "this agent") } }
        })))
        .unwrap(),
    )
}

fn workspace_block(id: &str) -> Arc<KillSwitch> {
    Arc::new(
        KillSwitch::from_sync(Some(serde_json::json!({
            "workspace": { "block_id": id, "target_type": "workspace",
                           "message": message(id, "every agent of this workspace") }
        })))
        .unwrap(),
    )
}

fn proxy(policy: EnforcementPolicy) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    config_with(
        ("unused", 0),
        policy,
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    )
}

fn session(proto: Box<dyn WireProtocol>, user: &str) -> (Wire, Arc<PgProxyConfig>) {
    let (cfg, queue) = proxy(EnforcementPolicy::default());
    (wire_as(proto, cfg.clone(), queue, Some(user)), cfg)
}

/// A simple query refused by the kill switch: 42501 with the block's message
/// verbatim, then ReadyForQuery.
async fn pg_expect_105(w: &mut Wire, sql: &str, expected: &str) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E', "{sql} must be refused");
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert_eq!(msg, expected);
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
}

async fn pg_expect_forwarded(w: &mut Wire, sql: &str) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'Q');
    assert_eq!(super::sensitive_tests::cstr(&m.body), sql);
}

fn assert_105_event(ev: &serde_json::Value, block_id: &str, target: &str) {
    assert_eq!(ev["status"], "BLOCKED", "{ev}");
    assert_eq!(ev["rule_code"], "VERICTO-105");
    assert_eq!(ev["severity"], "critical");
    assert_eq!(ev["enforcement_action"], "block");
    assert_eq!(ev["ast_node_path"], format!("KillSwitch > {target}"));
    assert_eq!(ev["kill_switch_id"], block_id);
    let v = ev["violations"].as_array().unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["rule_code"], "VERICTO-105");
    assert_eq!(v[0]["enforcement_action"], "block");
}

// ── Postgres, in memory ──────────────────────────────────────────────────────

/// Statements that read no table are refused too: the whole agent is blocked.
#[tokio::test]
async fn pg_every_statement_of_a_blocked_user_is_refused_with_the_message() {
    let (mut w, cfg) = session(Box::new(PostgresProtocol), AGENT);
    cfg.kill_switch.store(Some(user_block(AGENT, "b-1")));
    let text = message("b-1", "this agent");
    for sql in [
        "SELECT 1",
        "BEGIN",
        "SET statement_timeout = 0",
        "SET vericto.ticket = 'INC-1'",
        "SELECT * FROM orders",
        "DELETE FROM orders",
        "not even sql",
    ] {
        pg_expect_105(&mut w, sql, &text).await;
    }
    let ev = events(&w.queue);
    assert_eq!(ev.len(), 7);
    for e in &ev {
        assert_105_event(e, "b-1", "db_user");
        assert_eq!(e["db_user"], AGENT);
    }
    assert_eq!(ev[0]["query_text"], "SELECT 1");

    // Lifted (the next sync carries no field): the session runs again, and
    // nothing refused before ever reached the database.
    cfg.kill_switch.store(None);
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
}

#[tokio::test]
async fn pg_extended_parse_is_refused_until_sync() {
    let (mut w, cfg) = session(Box::new(PostgresProtocol), AGENT);
    cfg.kill_switch.store(Some(user_block(AGENT, "b-2")));
    let mut seq = pg_parse("", "SELECT $1::int", &[]);
    seq.extend(
        PgMessage {
            tag: b'B',
            body: vec![0, 0, 0, 0, 0, 0, 0, 0],
        }
        .encode(),
    );
    seq.extend(
        PgMessage {
            tag: b'E',
            body: vec![0, 0, 0, 0, 0],
        }
        .encode(),
    );
    seq.extend(pg_sync());
    w.client.write_all(&seq).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert_eq!(pg_error(&e.body).1, message("b-2", "this agent"));
    // Bind and Execute were swallowed with the aborted sequence; Sync answers.
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    assert_105_event(&ev[0], "b-2", "db_user");
    cfg.kill_switch.store(None);
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
}

/// A Bind of a statement prepared before the block is refused on its own.
#[tokio::test]
async fn pg_bind_of_an_earlier_statement_is_refused() {
    let (mut w, cfg) = session(Box::new(PostgresProtocol), AGENT);
    cfg.kill_switch.store(Some(user_block(AGENT, "b-3")));
    let mut seq = PgMessage {
        tag: b'B',
        body: b"\0s1\0\0\0\0\0\0\0".to_vec(),
    }
    .encode();
    seq.extend(pg_sync());
    w.client.write_all(&seq).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(pg_error(&e.body).1, message("b-3", "this agent"));
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    assert_eq!(
        events(&w.queue)[0]["query_text"],
        "Bind (prepared statement)"
    );
}

/// Another user of the same proxy is not affected; the user's own block wins
/// over the workspace switch, which stops every other user.
#[tokio::test]
async fn only_the_blocked_user_and_user_blocks_win_over_the_workspace_switch() {
    let (cfg, queue) = proxy(EnforcementPolicy::default());
    let mut agent = wire_as(
        Box::new(PostgresProtocol),
        cfg.clone(),
        queue.clone(),
        Some(AGENT),
    );
    let mut app = wire_as(Box::new(PostgresProtocol), cfg.clone(), queue, Some("app"));
    cfg.kill_switch.store(Some(user_block(AGENT, "u-1")));
    pg_expect_105(&mut agent, "SELECT 1", &message("u-1", "this agent")).await;
    pg_expect_forwarded(&mut app, "SELECT 1").await;

    let both = KillSwitch::from_sync(Some(serde_json::json!({
        "workspace": { "block_id": "w-1", "target_type": "workspace",
                       "message": message("w-1", "every agent of this workspace") },
        "db_users": { AGENT: { "block_id": "u-1", "target_type": "principal",
                               "message": message("u-1", "this agent") } }
    })))
    .unwrap();
    cfg.kill_switch.store(Some(Arc::new(both)));
    pg_expect_105(&mut agent, "SELECT 1", &message("u-1", "this agent")).await;
    pg_expect_105(
        &mut app,
        "SELECT 1",
        &message("w-1", "every agent of this workspace"),
    )
    .await;

    cfg.kill_switch.store(Some(workspace_block("w-2")));
    pg_expect_105(
        &mut agent,
        "BEGIN",
        &message("w-2", "every agent of this workspace"),
    )
    .await;
    // One queue for both sessions: `app`'s forwarded statement is in it too.
    let ev: Vec<_> = events(&agent.queue)
        .into_iter()
        .filter(|e| e["rule_code"] == "VERICTO-105")
        .collect();
    assert_eq!(ev.len(), 4);
    assert_105_event(&ev[0], "u-1", "db_user");
    assert_105_event(&ev[1], "u-1", "principal");
    assert_105_event(&ev[2], "w-1", "workspace");
    assert_105_event(&ev[3], "w-2", "workspace");
}

/// Monitor mode (and an observe window) turns rule blocks into flags; the kill
/// switch still refuses, as on the API paths.
#[tokio::test]
async fn monitor_mode_does_not_lift_the_kill_switch() {
    let (cfg, queue) = proxy(EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    });
    let mut w = wire_as(Box::new(PostgresProtocol), cfg.clone(), queue, Some(AGENT));
    // Without a block, monitor mode forwards even a DELETE without WHERE.
    pg_expect_forwarded(&mut w, "DELETE FROM orders").await;
    cfg.kill_switch.store(Some(user_block(AGENT, "m-1")));
    pg_expect_105(&mut w, "SELECT 1", &message("m-1", "this agent")).await;
}

/// What a 4.17.x proxy does, and what this one does with a control plane that
/// sends no `kill_switch`: the deny-all allowlist refuses table reads with
/// VERICTO-087 and lets statements that read no table through.
#[tokio::test]
async fn without_the_field_the_deny_all_allowlist_behaves_as_before() {
    let (mut w, cfg) = session(Box::new(PostgresProtocol), AGENT);
    let deny: AccessPolicyMap = serde_json::from_value(serde_json::json!({
        AGENT: { "mode": "enforce", "ddl": "deny", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));
    w.client
        .write_all(&pg_query("SELECT * FROM orders"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert!(msg.contains("[VERICTO-087]"), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    pg_expect_forwarded(&mut w, "SELECT 1").await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["rule_code"], "VERICTO-087");
    assert!(ev[0].get("kill_switch_id").is_none(), "{}", ev[0]);
    assert!(ev[1].get("kill_switch_id").is_none());
}

// ── MySQL, in memory ─────────────────────────────────────────────────────────

fn my_packet(payload: Vec<u8>) -> Vec<u8> {
    MySqlPacket { seq: 0, payload }.encode()
}

async fn my_expect_105(w: &mut Wire, packet: Vec<u8>, expected: &str) {
    w.client.write_all(&packet).await.unwrap();
    let p = read_my(&mut w.client).await;
    assert_eq!(p.seq, 1, "the reply to a command is seq 1");
    let (code, msg) = my_err(&p);
    assert_eq!(code, 1142);
    assert_eq!(msg, expected);
}

#[tokio::test]
async fn mysql_every_statement_of_a_blocked_user_is_refused() {
    let (mut w, cfg) = session(Box::new(MysqlProtocol), AGENT);
    cfg.kill_switch.store(Some(user_block(AGENT, "my-1")));
    let text = message("my-1", "this agent");
    my_expect_105(&mut w, my_cmd(COM_QUERY, "SELECT 1"), &text).await;
    my_expect_105(&mut w, my_cmd(COM_QUERY, "BEGIN"), &text).await;
    my_expect_105(&mut w, my_cmd(COM_QUERY, "SET autocommit = 1"), &text).await;
    my_expect_105(&mut w, my_cmd(COM_STMT_PREPARE, "SELECT ?"), &text).await;
    // COM_STMT_EXECUTE of statement 1, prepared before the block.
    my_expect_105(
        &mut w,
        my_packet(vec![0x17, 1, 0, 0, 0, 0, 1, 0, 0, 0]),
        &text,
    )
    .await;
    // COM_INIT_DB, COM_FIELD_LIST, COM_CHANGE_USER: no way out of the block.
    my_expect_105(&mut w, my_packet(b"\x02other_db".to_vec()), &text).await;
    my_expect_105(&mut w, my_packet(b"\x04orders\0".to_vec()), &text).await;
    my_expect_105(&mut w, my_packet(b"\x11root\0\0".to_vec()), &text).await;
    // Plumbing passes: COM_PING reaches the server.
    w.client.write_all(&my_packet(vec![0x0e])).await.unwrap();
    assert_eq!(read_my(&mut w.db).await.payload, vec![0x0e]);

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 8);
    for e in &ev {
        assert_105_event(e, "my-1", "db_user");
    }
    assert_eq!(ev[4]["query_text"], "COM_STMT_EXECUTE (prepared statement)");

    cfg.kill_switch.store(None);
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
}

#[tokio::test]
async fn mysql_open_session_is_refused_from_the_next_sync_and_released_after() {
    let (mut w, cfg) = session(Box::new(MysqlProtocol), AGENT);
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
    cfg.kill_switch.store(Some(workspace_block("w-9")));
    my_expect_105(
        &mut w,
        my_cmd(COM_QUERY, "SELECT 1"),
        &message("w-9", "every agent of this workspace"),
    )
    .await;
    cfg.kill_switch.store(None);
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
}

// ── Real Postgres ────────────────────────────────────────────────────────────

use super::sensitive_tests::{connect, mysql_url, pg_url, spawn_mysql_proxy, via_proxy};

fn pg_refused(e: tokio_postgres::Error, expected: &str) {
    assert_eq!(
        e.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "{e:?}"
    );
    assert_eq!(e.as_db_error().unwrap().message(), expected);
}

/// A real driver through the proxy (the ordered response coordinator, the
/// extended protocol): a statement prepared before the block is refused at its
/// next execution, every new one too, the connection stays usable, and the
/// lift brings it all back.
#[tokio::test]
async fn real_pg_open_session_refused_at_the_next_sync_and_restored_by_the_lift() {
    let Some(url) = pg_url() else {
        eprintln!("VERICTO_TEST_PG_URL not set: skipping the real-Postgres test");
        return;
    };
    let direct: tokio_postgres::Config = url.parse().expect("VERICTO_TEST_PG_URL");
    let host = match &direct.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(h) => h.clone(),
        #[allow(unreachable_patterns)]
        _ => panic!("VERICTO_TEST_PG_URL must use a TCP host"),
    };
    let port = direct.get_ports().first().copied().unwrap_or(5432);
    let user = direct.get_user().unwrap_or("postgres").to_string();
    let (cfg, queue) = config_with(
        (&host, port),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let pcfg = cfg.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(crate::tcp::postgres::handle_connection(sock, pcfg.clone()));
        }
    });
    let mut via = tokio_postgres::Config::new();
    via.host("127.0.0.1")
        .port(proxy_port)
        .user(&user)
        .dbname(direct.get_dbname().unwrap_or("postgres"));
    if let Some(pw) = direct.get_password() {
        via.password(pw);
    }
    let client = connect(&via).await;
    let stmt = client.prepare("SELECT $1::int").await.unwrap();
    let row = client.query_one(&stmt, &[&7i32]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 7);

    // The sync that carries the block.
    cfg.kill_switch.store(Some(user_block(&user, "rp-1")));
    let text = message("rp-1", "this agent");
    pg_refused(client.simple_query("SELECT 1").await.unwrap_err(), &text);
    pg_refused(client.batch_execute("BEGIN").await.unwrap_err(), &text);
    pg_refused(client.query_one(&stmt, &[&8i32]).await.unwrap_err(), &text);
    pg_refused(client.query("SELECT 2", &[]).await.unwrap_err(), &text);
    // Monitor mode does not lift it.
    cfg.policy.store(Arc::new(EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    }));
    pg_refused(client.simple_query("SELECT 3").await.unwrap_err(), &text);

    // The lift: the same connection and the same prepared statement run again.
    cfg.kill_switch.store(None);
    let row = client.query_one(&stmt, &[&9i32]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 9);
    let rows = client.simple_query("SELECT 1").await.unwrap();
    assert!(!rows.is_empty());
    let ev = events(&queue);
    let refused: Vec<_> = ev
        .iter()
        .filter(|e| e["rule_code"] == "VERICTO-105")
        .collect();
    // One per statement: the Bind and Execute of one execution are one refusal.
    assert_eq!(refused.len(), 5, "{ev:?}");
    for e in refused {
        assert_105_event(e, "rp-1", "db_user");
        assert_eq!(e["db_user"], user.as_str());
    }
}

// ── Real MySQL ───────────────────────────────────────────────────────────────

use mysql_async::prelude::Queryable;

fn my_refused(e: mysql_async::Error, expected: &str) {
    match e {
        mysql_async::Error::Server(s) => {
            assert_eq!(s.code, 1142, "{}", s.message);
            assert_eq!(s.message, expected);
        }
        other => panic!("expected a server error, got {other:?}"),
    }
}

#[tokio::test]
async fn real_mysql_open_session_refused_at_the_next_sync_and_restored_by_the_lift() {
    let Some(url) = mysql_url() else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
        return;
    };
    let admin = mysql_async::Opts::from_url(&url).expect("VERICTO_TEST_MYSQL_URL");
    let user = admin.user().unwrap_or("root").to_string();
    let (cfg, queue) = config_with(
        (admin.ip_or_hostname(), admin.tcp_port()),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let port = spawn_mysql_proxy(cfg.clone()).await;
    let mut conn = mysql_async::Conn::new(via_proxy(&admin, port, None, false))
        .await
        .expect("connect through the proxy");
    let stmt = conn.prep("SELECT ?").await.unwrap();
    let v: Option<i64> = conn.exec_first(&stmt, (7,)).await.unwrap();
    assert_eq!(v, Some(7));

    cfg.kill_switch.store(Some(user_block(&user, "rm-1")));
    let text = message("rm-1", "this agent");
    my_refused(conn.query_drop("SELECT 1").await.unwrap_err(), &text);
    my_refused(conn.query_drop("BEGIN").await.unwrap_err(), &text);
    my_refused(conn.exec_drop(&stmt, (8,)).await.unwrap_err(), &text);
    my_refused(conn.prep("SELECT 2").await.unwrap_err(), &text);

    cfg.kill_switch.store(None);
    let v: Option<i64> = conn.exec_first(&stmt, (9,)).await.unwrap();
    assert_eq!(v, Some(9));
    let one: Option<i64> = conn.query_first("SELECT 1").await.unwrap();
    assert_eq!(one, Some(1));
    conn.disconnect().await.unwrap();

    let ev = events(&queue);
    let refused: Vec<_> = ev
        .iter()
        .filter(|e| e["rule_code"] == "VERICTO-105")
        .collect();
    assert_eq!(refused.len(), 4, "{ev:?}");
    for e in refused {
        assert_105_event(e, "rm-1", "db_user");
    }
}
