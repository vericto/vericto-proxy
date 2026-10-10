//! Agent access allowlists (VERICTO-087) on the wire.
//!
//! The identity is the database user of the session (Postgres StartupMessage
//! `user`, MySQL HandshakeResponse username); `/sync/rules` carries one policy per
//! user (`agent_access`). Same layers as `sensitive_tests`:
//!
//! * **In-memory** (always run): the real interception loop between an
//!   in-memory client and an in-memory database, for both wire protocols, with
//!   the session user given to the loop as the session entrypoints give it.
//! * **Real Postgres / MySQL** (`VERICTO_TEST_PG_URL` / `VERICTO_TEST_MYSQL_URL`,
//!   as in `sensitive_tests`): a real driver authenticates through the proxy as a
//!   role the test creates. Each test creates its own database and roles and
//!   drops them afterwards, also on failure.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use vericto_engine::{AccessPolicyMap, EnforcementPolicy};

use super::sensitive_tests::{
    Wire, config_with, events, first_query_reaching_db, my_cmd, my_err, my_first_query_reaching_db,
    my_sql, pg_error, pg_parse, pg_query, pg_sync, read_my, read_pg, timeout, wire_as, wire_start,
};
use crate::tcp::codec::PgMessage;
use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE, MySqlPacket};
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::tcp::session::{CurrentDatabase, SessionStart, startup_settings_block};
use crate::telemetry::queue::MemoryQueue;

const AGENT: &str = "support_agent";
const BOT: &str = "reporting_bot";

/// The allowlists every in-memory test uses: `support_agent` enforced,
/// `reporting_bot` observed, nobody else restricted.
fn policies_json(agent: &str, bot: &str) -> serde_json::Value {
    serde_json::json!({
        agent: { "mode": "enforce", "ddl": "deny", "entries": [
            { "table": "orders", "columns": "*", "access": "read" },
            { "table": "customers", "columns": ["id", "name", "email"], "access": "read" },
            { "table": "tickets", "columns": ["id", "status"], "access": "read_write" }
        ]},
        bot: { "mode": "observe", "entries": [
            { "table": "orders", "columns": "*", "access": "read" }
        ]}
    })
}

fn policies() -> AccessPolicyMap {
    serde_json::from_value(policies_json(AGENT, BOT)).expect("policies deserialize")
}

fn proxy(
    policy: EnforcementPolicy,
    mode: TelemetryQueryMode,
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let (cfg, queue) = config_with(
        ("unused", 0),
        policy,
        mode,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    cfg.agent_access.store(Arc::new(policies()));
    (cfg, queue)
}

/// A session as `user` on a proxy with [`policies`].
fn session(proto: Box<dyn WireProtocol>, user: &str) -> Wire {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    wire_as(proto, cfg, queue, Some(user))
}

/// Sends `sql` as a simple query and expects the 42501 block of VERICTO-087,
/// followed by ReadyForQuery. Returns the message.
async fn pg_expect_087(w: &mut Wire, sql: &str) -> String {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E', "{sql} must be blocked");
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501", "{msg}");
    assert!(msg.contains("VERICTO-087"), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    msg
}

/// Sends `sql` as a simple query and expects it to reach the database unchanged.
async fn pg_expect_forwarded(w: &mut Wire, sql: &str) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'Q');
    assert_eq!(super::sensitive_tests::cstr(&m.body), sql);
}

async fn my_expect_087(w: &mut Wire, cmd: u8, sql: &str) -> String {
    w.client.write_all(&my_cmd(cmd, sql)).await.unwrap();
    let p = read_my(&mut w.client).await;
    assert_eq!(p.seq, 1, "the reply to a command is seq 1");
    let (code, msg) = my_err(&p);
    assert_eq!(code, 1142, "{msg}");
    assert!(msg.contains("VERICTO-087"), "{msg}");
    msg
}

async fn my_expect_forwarded(w: &mut Wire, cmd: u8, sql: &str) {
    w.client.write_all(&my_cmd(cmd, sql)).await.unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(p.payload[0], cmd);
    assert_eq!(my_sql(&p), sql);
}

// ── Postgres, in memory ──────────────────────────────────────────────────────

#[tokio::test]
async fn pg_allowed_read_is_forwarded_and_reports_the_identity() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    let sql = "SELECT o.id, o.total, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = 7 LIMIT 5";
    // `o.customer_id`: orders grants every column; `c.id`, `c.name` are granted.
    pg_expect_forwarded(&mut w, sql).await;

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["db_user"], AGENT);
    assert_eq!(ev[0]["access_policy_mode"], "enforce");
    assert!(ev[0].get("access_denied").is_none());
}

#[tokio::test]
async fn pg_denied_read_is_blocked_with_42501_on_simple_and_extended() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    // A column not in the list, in a predicate only: predicates count.
    let msg = pg_expect_087(&mut w, "SELECT id FROM customers WHERE ssn = '123' LIMIT 1").await;
    assert!(msg.contains("customers.ssn (read)"), "{msg}");
    // A table not in the allowlist at all.
    pg_expect_087(&mut w, "SELECT id FROM invoices LIMIT 1").await;
    // Catalogue reads are denied unless listed.
    pg_expect_087(&mut w, "SELECT relname FROM pg_class LIMIT 1").await;

    // Extended: ErrorResponse, the sequence is swallowed until Sync.
    w.client
        .write_all(&pg_parse(
            "s1",
            "SELECT ssn FROM customers WHERE id = $1",
            &[23],
        ))
        .await
        .unwrap();
    w.client.write_all(&pg_sync()).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert!(msg.contains("VERICTO-087"), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');

    // Nothing above reached the database.
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    let first = &ev[0];
    assert_eq!(first["status"], "BLOCKED");
    assert_eq!(first["rule_code"], "VERICTO-087");
    assert_eq!(first["db_user"], AGENT);
    assert_eq!(
        first["access_denied"],
        serde_json::json!([{ "schema": null, "table": "customers", "column": "ssn", "needed": "read" }])
    );
    assert_eq!(ev[2]["access_denied"][0]["schema"], "pg_catalog");
}

#[tokio::test]
async fn pg_denied_write_is_blocked_and_a_granted_write_passes() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    // orders is granted `read` only.
    let msg = pg_expect_087(&mut w, "UPDATE orders SET total = 0 WHERE id = 1").await;
    // A table granted `read` only: the table itself is named (contract §3.1).
    assert!(msg.contains("AccessPolicy > orders (write)"), "{msg}");
    // DELETE is a table-level write (engine 3.8.1): it needs a `read_write`
    // entry for the table, whatever its column list, and is reported as the
    // table, column null.
    let msg = pg_expect_087(&mut w, "DELETE FROM orders WHERE id = 1").await;
    assert!(msg.contains("AccessPolicy > orders (write)"), "{msg}");
    pg_expect_087(&mut w, "CREATE TABLE x (id int)").await; // DDL
    // tickets.status is granted `read_write`: its UPDATE and a DELETE of tickets.
    pg_expect_forwarded(&mut w, "UPDATE tickets SET status = 'closed' WHERE id = 1").await;
    pg_expect_forwarded(&mut w, "DELETE FROM tickets WHERE id = 1").await;

    let ev = events(&w.queue);
    assert_eq!(ev[0]["access_denied"][0]["needed"], "write");
    assert_eq!(
        ev[1]["access_denied"],
        serde_json::json!([{"schema": null, "table": "orders", "column": null, "needed": "write"}])
    );
    assert_eq!(ev[2]["access_denied"][0]["needed"], "ddl");
}

/// A row lock stalls every other writer of those rows: `FOR UPDATE` / `FOR
/// SHARE` need write on each locked table (engine 3.8.1), on both protocols.
#[tokio::test]
async fn row_locks_need_write() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    let msg = pg_expect_087(&mut w, "SELECT id FROM orders WHERE id = 1 FOR UPDATE").await;
    assert!(msg.contains("AccessPolicy > orders (write)"), "{msg}");
    pg_expect_087(&mut w, "SELECT id FROM orders FOR SHARE").await;
    pg_expect_forwarded(
        &mut w,
        "SELECT id, status FROM tickets WHERE id = 1 FOR UPDATE",
    )
    .await;

    let mut m = session(Box::new(MysqlProtocol), AGENT);
    let msg = my_expect_087(&mut m, COM_QUERY, "SELECT id FROM orders FOR UPDATE").await;
    assert!(msg.contains("AccessPolicy > orders (write)"), "{msg}");
    my_expect_forwarded(&mut m, COM_QUERY, "SELECT id FROM tickets FOR UPDATE").await;
}

#[tokio::test]
async fn pg_observe_mode_forwards_and_flags() {
    let mut w = session(Box::new(PostgresProtocol), BOT);
    let sql = "SELECT id, ssn FROM customers LIMIT 1";
    pg_expect_forwarded(&mut w, sql).await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "FLAGGED");
    assert_eq!(ev[0]["rule_code"], "VERICTO-087");
    assert_eq!(ev[0]["enforcement_action"], "flag");
    assert_eq!(ev[0]["access_policy_mode"], "observe");
    assert_eq!(ev[0]["db_user"], BOT);
    // The bot is granted orders only: the table itself is the denial.
    assert_eq!(
        ev[0]["access_denied"],
        serde_json::json!([{ "schema": null, "table": "customers", "column": null, "needed": "read" }])
    );
}

#[tokio::test]
async fn two_sessions_on_one_proxy_get_their_own_users_policy() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let mut agent = wire_as(
        Box::new(PostgresProtocol),
        cfg.clone(),
        queue.clone(),
        Some(AGENT),
    );
    let mut app = wire_as(
        Box::new(PostgresProtocol),
        cfg.clone(),
        queue.clone(),
        Some("app"),
    );
    let mut unknown = wire_as(Box::new(PostgresProtocol), cfg, queue.clone(), None);

    let sql = "SELECT ssn FROM customers LIMIT 1";
    pg_expect_087(&mut agent, sql).await;
    // `app` has no policy and there is no "*": exactly as before.
    pg_expect_forwarded(&mut app, sql).await;
    // A session whose user could not be read gets nothing while any user has
    // a policy: it might be that user.
    pg_expect_087(&mut unknown, "SELECT id FROM orders LIMIT 1").await;

    let ev = events(&queue);
    let app_ev = ev.iter().find(|e| e["db_user"] == "app").unwrap();
    assert_eq!(app_ev["status"], "ALLOWED");
    assert!(app_ev.get("access_policy_mode").is_none());
}

#[tokio::test]
async fn the_star_default_applies_to_every_user_not_listed() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let mut map = policies();
    map.0.insert(
        "*".into(),
        serde_json::from_value(serde_json::json!({
            "entries": [{ "table": "status", "columns": "*" }]
        }))
        .unwrap(),
    );
    cfg.agent_access.store(Arc::new(map));
    let mut other = wire_as(
        Box::new(PostgresProtocol),
        cfg.clone(),
        queue.clone(),
        Some("anyone"),
    );
    let mut agent = wire_as(Box::new(PostgresProtocol), cfg, queue.clone(), Some(AGENT));

    pg_expect_forwarded(&mut other, "SELECT id, state FROM status LIMIT 1").await;
    pg_expect_087(&mut other, "SELECT id FROM orders LIMIT 1").await;
    // The exact key wins over "*".
    pg_expect_forwarded(&mut agent, "SELECT id FROM orders LIMIT 1").await;
    pg_expect_087(&mut agent, "SELECT id, state FROM status LIMIT 1").await;
    // "*" has no mode: enforce (fail-safe).
    let ev = events(&queue);
    assert_eq!(ev[0]["access_policy_mode"], "enforce");
}

/// The policy is resolved per statement, from the live sync state: a sync that
/// adds, changes or removes it applies to an open session on its next statement.
#[tokio::test]
async fn a_rules_sync_applies_to_open_sessions_on_their_next_statement() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    cfg.agent_access.store(Arc::new(AccessPolicyMap::default()));
    let mut w = wire_as(Box::new(PostgresProtocol), cfg.clone(), queue, Some(AGENT));
    let sql = "SELECT ssn FROM customers LIMIT 1";

    pg_expect_forwarded(&mut w, sql).await; // no policy yet
    cfg.agent_access.store(Arc::new(policies())); // sync: enforce
    pg_expect_087(&mut w, sql).await;
    let mut observe = policies();
    observe.0.get_mut(AGENT).unwrap().mode = vericto_engine::AccessMode::Observe;
    cfg.agent_access.store(Arc::new(observe)); // sync: observe
    pg_expect_forwarded(&mut w, sql).await;
    cfg.agent_access.store(Arc::new(AccessPolicyMap::default())); // sync: removed
    pg_expect_forwarded(&mut w, sql).await;
}

/// The identity is the startup user, never something the client changes later:
/// under a policy the SQL that would change it is denied by the engine.
#[tokio::test]
async fn set_role_and_session_authorization_are_denied_under_a_policy() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    for sql in [
        "SET ROLE postgres",
        "SET SESSION AUTHORIZATION postgres",
        "SET search_path = admin, public",
        "SELECT set_config('role', 'postgres', false)",
        "RESET ROLE",
    ] {
        pg_expect_087(&mut w, sql).await;
    }
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
    // Without a policy, unchanged.
    let mut app = session(Box::new(PostgresProtocol), "app");
    pg_expect_forwarded(&mut app, "SET ROLE postgres").await;
}

fn pg_function_call() -> Vec<u8> {
    // FunctionCall: function OID, 0 argument format codes, 0 arguments, text result.
    let mut body = 2078i32.to_be_bytes().to_vec(); // set_config
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes());
    PgMessage { tag: b'F', body }.encode()
}

/// A FunctionCall message calls a function by OID with no SQL to analyse
/// (`set_config('role', …)` through it would change the identity).
#[tokio::test]
async fn pg_function_call_is_refused_under_a_policy() {
    let mut w = session(Box::new(PostgresProtocol), AGENT);
    w.client.write_all(&pg_function_call()).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert!(msg.contains("AccessPolicy > FunctionCall (ddl)"), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let mut app = session(Box::new(PostgresProtocol), "app");
    app.client.write_all(&pg_function_call()).await.unwrap();
    assert_eq!(read_pg(&mut app.db).await.tag, b'F');
}

/// Allowed and tagged `mask`: the allowlist does not lift the mask (precedence
/// step 3), the rewritten SQL is what runs.
#[tokio::test]
async fn an_allowed_but_masked_column_is_forwarded_masked() {
    let tags = serde_json::from_value(serde_json::json!([
        { "table": "customers", "column": "email", "policy": "mask", "mask_style": "email" }
    ]))
    .unwrap();
    let (cfg, queue) = proxy(
        EnforcementPolicy {
            sensitive_columns: tags,
            ..EnforcementPolicy::default()
        },
        TelemetryQueryMode::Raw,
    );
    let mut w = wire_as(Box::new(PostgresProtocol), cfg, queue, Some(AGENT));
    let sql = "SELECT id, email FROM customers WHERE id = 7 LIMIT 5";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    let forwarded = super::sensitive_tests::cstr(&m.body);
    assert_ne!(forwarded, sql);
    assert!(forwarded.contains("regexp_replace"), "{forwarded}");
    let ev = events(&w.queue);
    assert_eq!(ev[0]["rule_code"], "VERICTO-085");
    assert_eq!(ev[0]["status"], "FLAGGED");
    assert!(ev[0].get("access_denied").is_none());
    // Masked but NOT allowed: the allowlist blocks (step 2).
    pg_expect_087(&mut w, "SELECT id, email, ssn FROM customers LIMIT 5").await;
}

/// Sanitized telemetry: identifiers are reported, literal values never.
#[tokio::test]
async fn pg_sanitized_mode_reports_names_not_values() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Sanitized);
    let mut w = wire_as(Box::new(PostgresProtocol), cfg, queue, Some(AGENT));
    pg_expect_087(
        &mut w,
        "SELECT id FROM customers WHERE ssn = '123-45-6789' LIMIT 1",
    )
    .await;
    let ev = events(&w.queue);
    let body = serde_json::to_string(&ev[0]).unwrap();
    assert!(!body.contains("123-45-6789"), "{body}");
    assert_eq!(ev[0]["access_denied"][0]["column"], "ssn");
    assert_eq!(ev[0]["db_user"], AGENT);
}

// ── MySQL, in memory ─────────────────────────────────────────────────────────

#[tokio::test]
async fn mysql_allowed_read_denied_read_and_denied_write() {
    let mut w = session(Box::new(MysqlProtocol), AGENT);
    my_expect_forwarded(
        &mut w,
        COM_QUERY,
        "SELECT id, name FROM customers WHERE id = 7 LIMIT 5",
    )
    .await;
    let msg = my_expect_087(&mut w, COM_QUERY, "SELECT id, ssn FROM customers LIMIT 5").await;
    assert!(msg.contains("customers.ssn (read)"), "{msg}");
    my_expect_087(
        &mut w,
        COM_QUERY,
        "UPDATE orders SET total = 0 WHERE id = 1",
    )
    .await;
    // Prepared: blocked at COM_STMT_PREPARE.
    my_expect_087(
        &mut w,
        COM_STMT_PREPARE,
        "SELECT ssn FROM customers WHERE id = ?",
    )
    .await;
    my_expect_087(&mut w, COM_QUERY, "SHOW TABLES").await; // catalogue
    my_expect_forwarded(
        &mut w,
        COM_STMT_PREPARE,
        "UPDATE tickets SET status = ? WHERE id = ?",
    )
    .await;
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["db_user"], AGENT);
    assert_eq!(ev[1]["status"], "BLOCKED");
    assert_eq!(ev[1]["rule_code"], "VERICTO-087");
    assert_eq!(ev[2]["access_denied"][0]["needed"], "write");
}

#[tokio::test]
async fn mysql_observe_mode_forwards_and_flags() {
    let mut w = session(Box::new(MysqlProtocol), BOT);
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id, ssn FROM customers LIMIT 1").await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "FLAGGED");
    assert_eq!(ev[0]["rule_code"], "VERICTO-087");
    assert_eq!(ev[0]["access_policy_mode"], "observe");
}

/// Rails' mysql2 connection setup runs under an enforced allowlist; a session
/// setting that changes integrity checks does not.
#[tokio::test]
async fn mysql_rails_connection_setup_passes_and_foreign_key_checks_is_refused() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let one_table: AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "rails_app": { "mode": "enforce", "entries": [
            { "table": "orders", "columns": "*", "access": "read_write" }
        ]}
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(one_table));
    let mut w = wire_as(Box::new(MysqlProtocol), cfg, queue, Some("rails_app"));
    for sql in [
        "SET NAMES utf8mb4",
        "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
        "SELECT id FROM orders LIMIT 1",
    ] {
        my_expect_forwarded(&mut w, COM_QUERY, sql).await;
    }
    let msg = my_expect_087(&mut w, COM_QUERY, "SET foreign_key_checks = 0").await;
    assert!(msg.contains("SET foreign_key_checks (ddl)"), "{msg}");
}

fn my_packet(payload: Vec<u8>) -> Vec<u8> {
    MySqlPacket { seq: 0, payload }.encode()
}

/// The protocol commands that change the user or where names resolve, outside
/// SQL: refused under a policy like the SQL they stand for.
#[tokio::test]
async fn mysql_init_db_and_change_user_are_refused_under_a_policy() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let mut agent = wire_as(
        Box::new(MysqlProtocol),
        cfg.clone(),
        queue.clone(),
        Some(AGENT),
    );

    // COM_INIT_DB is `USE`: it moves where unqualified names resolve.
    agent
        .client
        .write_all(&my_packet(b"\x02other_db".to_vec()))
        .await
        .unwrap();
    let (code, msg) = my_err(&read_my(&mut agent.client).await);
    assert_eq!(code, 1142);
    assert!(msg.contains("AccessPolicy > COM_INIT_DB (ddl)"), "{msg}");
    // COM_FIELD_LIST is `SHOW COLUMNS`.
    agent
        .client
        .write_all(&my_packet(b"\x04customers\0".to_vec()))
        .await
        .unwrap();
    assert_eq!(my_err(&read_my(&mut agent.client).await).0, 1142);
    // COM_CHANGE_USER away from a user with a policy.
    agent
        .client
        .write_all(&my_packet(b"\x11root\0\0".to_vec()))
        .await
        .unwrap();
    let (code, msg) = my_err(&read_my(&mut agent.client).await);
    assert_eq!(code, 1142);
    assert!(msg.contains("COM_CHANGE_USER"), "{msg}");
    // The session is still the agent: still restricted.
    my_expect_087(&mut agent, COM_QUERY, "SELECT ssn FROM customers LIMIT 1").await;
    assert_eq!(my_first_query_reaching_db(&mut agent).await, "SELECT 1");

    // From a user without a policy INTO one with a policy: refused too.
    let mut app = wire_as(
        Box::new(MysqlProtocol),
        cfg.clone(),
        queue.clone(),
        Some("app"),
    );
    let into_agent = format!("\x11{AGENT}\0\0").into_bytes();
    app.client.write_all(&my_packet(into_agent)).await.unwrap();
    assert_eq!(my_err(&read_my(&mut app.client).await).0, 1142);
    // Ping and COM_INIT_DB pass for a user without a policy, as before.
    app.client.write_all(&my_packet(vec![0x0e])).await.unwrap();
    assert_eq!(read_my(&mut app.db).await.payload, vec![0x0e]);
    app.client
        .write_all(&my_packet(b"\x02other_db".to_vec()))
        .await
        .unwrap();
    assert_eq!(read_my(&mut app.db).await.payload, b"\x02other_db".to_vec());
    // Between two users without a policy: forwarded.
    app.client
        .write_all(&my_packet(b"\x11app2\0\0".to_vec()))
        .await
        .unwrap();
    assert_eq!(read_my(&mut app.db).await.payload[0], 0x11);

    let ev = events(&queue);
    let change = ev
        .iter()
        .find(|e| e["query_text"] == "COM_CHANGE_USER")
        .unwrap();
    assert_eq!(change["status"], "BLOCKED");
    assert_eq!(change["access_denied"][0]["table"], "COM_CHANGE_USER");
}

/// On MySQL `"x"` is a string unless ANSI_QUOTES is on, and the engine also
/// reads it as a possible column `x`. In sanitized mode such a name must not
/// carry the literal out.
#[tokio::test]
async fn mysql_sanitized_mode_never_reports_a_double_quoted_literal() {
    let sql = r#"SELECT id FROM customers WHERE name = "Alice Smith" LIMIT 1"#;
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Sanitized);
    let mut w = wire_as(Box::new(MysqlProtocol), cfg, queue, Some(AGENT));
    my_expect_087(&mut w, COM_QUERY, sql).await;
    let ev = events(&w.queue);
    let body = serde_json::to_string(&ev[0]).unwrap();
    assert!(!body.contains("Alice"), "{body}");
    assert_eq!(ev[0]["rule_code"], "VERICTO-087");
    assert_eq!(ev[0]["access_denied"][0]["table"], "customers");
    assert_eq!(ev[0]["access_denied"][0]["column"], "?");

    // Raw mode reports it as the engine names it (proves the case is real).
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let mut w = wire_as(Box::new(MysqlProtocol), cfg, queue, Some(AGENT));
    my_expect_087(&mut w, COM_QUERY, sql).await;
    let body = serde_json::to_string(&events(&w.queue)[0]).unwrap();
    assert!(body.contains("Alice Smith"), "{body}");
}

/// The fields fmw's ingest schema bounds are bounded here, so one long name
/// cannot make the API reject the whole batch.
#[tokio::test]
async fn reported_names_and_paths_fit_the_ingest_schema() {
    let long = "c".repeat(200);
    let mut w = session(Box::new(MysqlProtocol), AGENT);
    my_expect_087(
        &mut w,
        COM_QUERY,
        &format!("SELECT `{long}` FROM customers LIMIT 1"),
    )
    .await;
    let ev = events(&w.queue);
    let column = ev[0]["access_denied"][0]["column"].as_str().unwrap();
    assert_eq!(column.len(), crate::telemetry::MAX_REPORTED_NAME_BYTES);
    assert!(ev[0]["ast_node_path"].as_str().unwrap().len() <= 512);
    assert!(
        ev[0]["violations"][0]["ast_node_path"]
            .as_str()
            .unwrap()
            .len()
            <= 512
    );
}

/// No user has a policy: nothing changes, not even the event's size beyond the
/// session's user name.
#[tokio::test]
async fn without_agent_access_every_session_is_unrestricted() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    cfg.agent_access.store(Arc::new(AccessPolicyMap::default()));
    cfg.ruleset.store(Arc::new(Vec::new()));
    let mut w = wire_as(Box::new(PostgresProtocol), cfg, queue, Some(AGENT));
    pg_expect_forwarded(&mut w, "SELECT ssn FROM customers").await;
    w.client.write_all(&pg_function_call()).await.unwrap();
    assert_eq!(read_pg(&mut w.db).await.tag, b'F');
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["db_user"], AGENT);
    assert!(ev[0].get("access_policy_mode").is_none());
    assert!(ev[0].get("access_denied").is_none());
}

// ── Real Postgres ────────────────────────────────────────────────────────────

use super::sensitive_tests::{connect, mysql_client_tls, mysql_url, pg_url, spawn_mysql_proxy};

/// A random suffix for the database and the roles a real-database test creates.
fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_string()
}

/// The proxy every real-database test fronts the database with: the default
/// rules, an `email` mask tag, and [`policies_json`] for the test's own agent
/// and bot roles.
fn real_proxy_config(
    upstream: (&str, u16),
    agent: &str,
    bot: &str,
    tls: crate::tcp::upstream::UpstreamTlsMode,
) -> Arc<PgProxyConfig> {
    let tags = serde_json::from_value(serde_json::json!([
        { "table": "customers", "column": "email", "policy": "mask", "mask_style": "email" }
    ]))
    .unwrap();
    let (cfg, _queue) = config_with(
        upstream,
        EnforcementPolicy {
            sensitive_columns: tags,
            ..EnforcementPolicy::default()
        },
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        tls,
    );
    cfg.agent_access.store(Arc::new(
        serde_json::from_value(policies_json(agent, bot)).unwrap(),
    ));
    cfg
}

/// Connection settings to the proxy, as the database's admin and as the agent.
struct RealPg {
    admin: tokio_postgres::Config,
    agent: tokio_postgres::Config,
    admin_user: String,
    agent_user: String,
}

/// Runs `body` against a fresh database with `customers`, `orders` and
/// `tickets`, a LOGIN role for the agent (granted everything on them, so only
/// the proxy restricts it) and a proxy with [`real_proxy_config`]. The database
/// and the role are dropped afterwards, also when `body` panics.
async fn with_real_pg_agent<F, Fut>(body: F)
where
    F: FnOnce(RealPg) -> Fut + Send + 'static,
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
    let id = suffix();
    let db = format!("vericto_proxy_access_{id}");
    let agent = format!("vericto_agent_{id}");
    let bot = format!("vericto_bot_{id}");

    let admin = connect(&cfg).await;
    // One statement per call: CREATE/DROP DATABASE cannot run in the implicit
    // transaction of a multi-statement query.
    for sql in [
        format!("CREATE DATABASE {db}"),
        format!("CREATE ROLE {agent} LOGIN PASSWORD 'agent-pw'"),
    ] {
        admin.batch_execute(&sql).await.unwrap();
    }

    let result = tokio::spawn({
        let mut direct = cfg.clone();
        direct.dbname(&db);
        let (db, agent) = (db.clone(), agent.clone());
        async move {
            let seed = connect(&direct).await;
            seed.batch_execute(&format!(
                "CREATE TABLE customers (id int PRIMARY KEY, name text, email text, ssn text);
                 CREATE TABLE orders (id int PRIMARY KEY, customer_id int, total int);
                 CREATE TABLE tickets (id int PRIMARY KEY, status text, note text);
                 INSERT INTO customers VALUES (1, 'Ann', 'ann@x.io', '123-45-6789'),
                                              (2, 'Bob', 'bob@y.io', '987-65-4321');
                 INSERT INTO orders VALUES (10, 1, 500), (11, 2, 700);
                 INSERT INTO tickets VALUES (100, 'open', 'n1');
                 GRANT ALL ON ALL TABLES IN SCHEMA public TO {agent};"
            ))
            .await
            .unwrap();

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = listener.local_addr().unwrap().port();
            let pcfg = real_proxy_config(
                (&host, port),
                &agent,
                &bot,
                crate::tcp::upstream::UpstreamTlsMode::Disable,
            );
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    tokio::spawn(crate::tcp::postgres::handle_connection(sock, pcfg.clone()));
                }
            });
            let via = |user: &str, password: Option<&[u8]>| {
                let mut c = tokio_postgres::Config::new();
                c.host("127.0.0.1").port(proxy_port).dbname(&db).user(user);
                if let Some(pw) = password {
                    c.password(pw);
                }
                c
            };
            let admin_user = direct.get_user().unwrap_or("postgres").to_string();
            body(RealPg {
                admin: via(&admin_user, direct.get_password()),
                agent: via(&agent, Some(b"agent-pw")),
                admin_user,
                agent_user: agent,
            })
            .await;
        }
    })
    .await;

    for sql in [
        format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS {agent}"),
    ] {
        admin.batch_execute(&sql).await.unwrap();
    }
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

fn pg_denied(e: tokio_postgres::Error) -> String {
    assert_eq!(
        e.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "{e:?}"
    );
    let msg = e.as_db_error().unwrap().message().to_string();
    assert!(msg.contains("VERICTO-087"), "{msg}");
    msg
}

#[tokio::test]
async fn real_pg_a_user_with_a_policy_is_restricted_and_one_without_is_not() {
    with_real_pg_agent(|pg| async move {
        let agent = connect(&pg.agent).await;
        // Allowed read (simple and extended).
        let rows = agent
            .query(
                "SELECT id, name FROM customers WHERE id >= $1 ORDER BY id LIMIT 10",
                &[&1i32],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<_, String>(1), "Ann");
        // Denied read, simple and extended; the connection stays usable.
        pg_denied(
            agent
                .simple_query("SELECT ssn FROM customers LIMIT 1")
                .await
                .unwrap_err(),
        );
        pg_denied(
            agent
                .query("SELECT id FROM customers WHERE ssn = $1", &[&"123-45-6789"])
                .await
                .unwrap_err(),
        );
        // Denied write (orders is read-only for the agent); a granted write runs.
        pg_denied(
            agent
                .execute("UPDATE orders SET total = 0 WHERE id = $1", &[&10i32])
                .await
                .unwrap_err(),
        );
        let n = agent
            .execute(
                "UPDATE tickets SET status = 'closed' WHERE id = $1",
                &[&100i32],
            )
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Allowed but masked: the masked value comes back.
        let row = agent
            .query_one("SELECT email FROM customers WHERE id = $1", &[&1i32])
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "a***@x.io");
        // The identity cannot be changed from SQL.
        let msg = pg_denied(
            agent
                .simple_query(&format!("SET ROLE {}", pg.admin_user))
                .await
                .unwrap_err(),
        );
        assert!(msg.contains("SET ROLE (ddl)"), "{msg}");
        pg_denied(
            agent
                .simple_query(&format!("SET SESSION AUTHORIZATION {}", pg.admin_user))
                .await
                .unwrap_err(),
        );
        let who = agent
            .query_one("SELECT current_user::text", &[])
            .await
            .unwrap();
        assert_eq!(who.get::<_, String>(0), pg.agent_user);

        // The admin has no policy: the same proxy does not restrict it.
        let admin = connect(&pg.admin).await;
        let row = admin
            .query_one("SELECT ssn FROM customers WHERE id = $1", &[&1i32])
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "123-45-6789");
        let total = admin
            .query_one("SELECT total FROM orders WHERE id = $1", &[&10i32])
            .await
            .unwrap();
        assert_eq!(total.get::<_, i32>(0), 500, "the denied UPDATE never ran");
    })
    .await;
}

// ── Real MySQL ───────────────────────────────────────────────────────────────

use mysql_async::prelude::Queryable;

struct RealMy {
    admin: mysql_async::Opts,
    agent: mysql_async::Opts,
}

/// [`with_real_pg_agent`] for MySQL: a fresh database, a native-password user
/// for the agent granted everything on it, a proxy with [`real_proxy_config`]
/// (TLS on both hops when `VERICTO_TEST_MYSQL_SSLMODE=require`, as in
/// `sensitive_tests`). Seeding and cleanup go through a proxy with no policy.
async fn with_real_mysql_agent<F, Fut>(body: F)
where
    F: FnOnce(RealMy) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = mysql_url() else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
        return;
    };
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let admin = mysql_async::Opts::from_url(&url).expect("VERICTO_TEST_MYSQL_URL");
    let upstream = (admin.ip_or_hostname().to_string(), admin.tcp_port());
    let tls = crate::tcp::upstream::UpstreamTlsMode::from_env_str(
        &std::env::var("VERICTO_TEST_MYSQL_SSLMODE").unwrap_or_default(),
    );
    let id = suffix();
    let db = format!("vericto_proxy_access_{id}");
    let agent = format!("vericto_agent_{id}");
    let (plain, _) = config_with(
        (&upstream.0, upstream.1),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        Vec::new(),
        tls,
    );
    let restricted = real_proxy_config((&upstream.0, upstream.1), &agent, "unused_bot", tls);
    let acceptor = mysql_client_tls(tls);
    let client_tls = acceptor.is_some();
    let with_tls = |cfg: Arc<PgProxyConfig>| {
        let mut cfg = Arc::into_inner(cfg).expect("unshared config");
        cfg.client_tls_acceptor = acceptor.clone();
        Arc::new(cfg)
    };
    let admin_port = spawn_mysql_proxy(with_tls(plain)).await;
    let proxy_port = spawn_mysql_proxy(with_tls(restricted)).await;
    let opts = |port: u16, user: Option<String>, pass: Option<String>, db: Option<&str>| {
        mysql_async::Opts::from(
            mysql_async::OptsBuilder::default()
                .ip_or_hostname("127.0.0.1")
                .tcp_port(port)
                .user(user)
                .pass(pass)
                .db_name(db)
                .prefer_socket(false)
                .ssl_opts(client_tls.then(|| {
                    mysql_async::SslOpts::default().with_danger_accept_invalid_certs(true)
                })),
        )
    };
    let admin_user = admin.user().map(str::to_string);
    let admin_pass = admin.pass().map(str::to_string);

    let mut conn = mysql_async::Conn::new(opts(
        admin_port,
        admin_user.clone(),
        admin_pass.clone(),
        None,
    ))
    .await
    .expect("connect (admin, through a proxy without policies)");
    let seed = [
        format!("CREATE DATABASE {db}"),
        format!("CREATE USER '{agent}'@'%' IDENTIFIED WITH mysql_native_password BY 'agent-pw'"),
        format!("GRANT ALL ON {db}.* TO '{agent}'@'%'"),
        format!(
            "CREATE TABLE {db}.customers (id INT PRIMARY KEY, name VARCHAR(40), email VARCHAR(80), ssn VARCHAR(11))"
        ),
        format!("CREATE TABLE {db}.orders (id INT PRIMARY KEY, customer_id INT, total INT)"),
        format!(
            "CREATE TABLE {db}.tickets (id INT PRIMARY KEY, status VARCHAR(20), note VARCHAR(20))"
        ),
        format!(
            "INSERT INTO {db}.customers VALUES (1, 'Ann', 'ann@x.io', '123-45-6789'), (2, 'Bob', 'bob@y.io', '987-65-4321')"
        ),
        format!("INSERT INTO {db}.orders VALUES (10, 1, 500), (11, 2, 700)"),
        format!("INSERT INTO {db}.tickets VALUES (100, 'open', 'n1')"),
    ];
    let mut seeded = Ok(());
    for sql in seed {
        if let Err(e) = conn.query_drop(sql).await {
            seeded = Err(e);
            break;
        }
    }
    let result: Result<(), Box<dyn std::any::Any + Send>> = match seeded {
        Ok(()) => tokio::spawn(body(RealMy {
            admin: opts(proxy_port, admin_user, admin_pass, Some(&db)),
            agent: opts(
                proxy_port,
                Some(agent.clone()),
                Some("agent-pw".into()),
                Some(&db),
            ),
        }))
        .await
        .map_err(|e| e.into_panic()),
        Err(e) => Err(Box::new(format!("seeding failed: {e}"))),
    };

    conn.query_drop(format!("DROP DATABASE IF EXISTS {db}"))
        .await
        .unwrap();
    conn.query_drop(format!("DROP USER IF EXISTS '{agent}'@'%'"))
        .await
        .unwrap();
    conn.disconnect().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn my_denied(e: mysql_async::Error) -> String {
    match e {
        mysql_async::Error::Server(s) => {
            assert_eq!(s.code, 1142, "{}", s.message);
            assert!(s.message.contains("VERICTO-087"), "{}", s.message);
            s.message
        }
        other => panic!("expected a server error, got {other}"),
    }
}

#[tokio::test]
async fn real_mysql_a_user_with_a_policy_is_restricted_and_one_without_is_not() {
    with_real_mysql_agent(|my| async move {
        let mut agent = mysql_async::Conn::new(my.agent)
            .await
            .expect("agent connects");
        // Rails-style connection setup runs under the enforced policy.
        agent.query_drop("SET NAMES utf8mb4").await.unwrap();
        agent
            .query_drop(
                "SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), \
                 ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, \
                 @@SESSION.wait_timeout = 2147483",
            )
            .await
            .unwrap();
        my_denied(
            agent
                .query_drop("SET foreign_key_checks = 0")
                .await
                .unwrap_err(),
        );
        // Allowed read, text and prepared.
        let names: Vec<String> = agent
            .query("SELECT name FROM customers ORDER BY id LIMIT 10")
            .await
            .unwrap();
        assert_eq!(names, vec!["Ann".to_string(), "Bob".to_string()]);
        let name: Option<String> = agent
            .exec_first("SELECT name FROM customers WHERE id = ?", (2,))
            .await
            .unwrap();
        assert_eq!(name.as_deref(), Some("Bob"));
        // Denied read, text and prepared; denied write; `USE` is denied.
        my_denied(
            agent
                .query_drop("SELECT ssn FROM customers LIMIT 1")
                .await
                .unwrap_err(),
        );
        my_denied(
            agent
                .exec_drop("SELECT id FROM customers WHERE ssn = ?", ("123-45-6789",))
                .await
                .unwrap_err(),
        );
        my_denied(
            agent
                .exec_drop("UPDATE orders SET total = 0 WHERE id = ?", (10,))
                .await
                .unwrap_err(),
        );
        my_denied(agent.query_drop("USE mysql").await.unwrap_err());
        // A granted write runs.
        agent
            .exec_drop(
                "UPDATE tickets SET status = ? WHERE id = ?",
                ("closed", 100),
            )
            .await
            .unwrap();
        assert_eq!(agent.affected_rows(), 1);
        // Allowed but masked.
        let email: Option<String> = agent
            .exec_first("SELECT email FROM customers WHERE id = ?", (1,))
            .await
            .unwrap();
        assert_eq!(email.as_deref(), Some("a***@x.io"));
        agent.disconnect().await.unwrap();

        // The admin has no policy: the same proxy does not restrict it.
        let mut admin = mysql_async::Conn::new(my.admin).await.unwrap();
        let ssn: Option<String> = admin
            .exec_first("SELECT ssn FROM customers WHERE id = ?", (1,))
            .await
            .unwrap();
        assert_eq!(ssn.as_deref(), Some("123-45-6789"));
        let total: Option<i64> = admin
            .exec_first("SELECT total FROM orders WHERE id = ?", (10,))
            .await
            .unwrap();
        assert_eq!(total, Some(500), "the denied UPDATE never ran");
        admin.disconnect().await.unwrap();
    })
    .await;
}

// ── The ingest contract ──────────────────────────────────────────────────────

/// The shape vericto-fmw's `/ingest/events` validator (`eventSchema` in
/// `backend/src/routes/telemetry.ts`) requires of the agent-access fields and
/// the fields they lengthen. One event out of it rejects the whole batch.
fn assert_ingest_shape(e: &serde_json::Value) {
    let obj = e.as_object().expect("an event is an object");
    let opt_str = |k: &str, max: usize| {
        if let Some(v) = obj.get(k).filter(|v| !v.is_null()) {
            let s = v.as_str().unwrap_or_else(|| panic!("{k} is a string: {e}"));
            assert!(s.encode_utf16().count() <= max, "{k} over {max}: {e}");
        }
    };
    // db_user: any string (one that is not a user name is stored as NULL);
    // the proxy sends the session user as is.
    if let Some(v) = obj.get("db_user").filter(|v| !v.is_null()) {
        assert!(v.is_string(), "db_user is a string: {e}");
    }
    if let Some(v) = obj.get("access_policy_mode").filter(|v| !v.is_null()) {
        assert!(
            v == "observe" || v == "enforce",
            "access_policy_mode is observe | enforce: {e}"
        );
    }
    if let Some(v) = obj.get("access_denied").filter(|v| !v.is_null()) {
        let list = v.as_array().expect("access_denied is an array");
        assert!(list.len() <= 64, "access_denied over 64: {e}");
        for d in list {
            let d = d.as_object().expect("a denied reference is an object");
            for k in d.keys() {
                assert!(
                    ["schema", "table", "column", "needed"].contains(&k.as_str()),
                    "unexpected key {k}: {e}"
                );
            }
            let name = |k: &str, required: bool| match d.get(k) {
                Some(serde_json::Value::String(s)) => {
                    assert!(s.encode_utf16().count() <= 63, "{k} over 63: {e}")
                }
                Some(serde_json::Value::Null) | None => assert!(!required, "{k} required: {e}"),
                Some(other) => panic!("{k} is a string or null, got {other}"),
            };
            name("schema", false);
            name("table", true);
            name("column", false);
            let needed = d["needed"].as_str().expect("needed is a string");
            assert!(["read", "write", "ddl"].contains(&needed), "{e}");
        }
    }
    opt_str("rule_code", 40);
    opt_str("ast_node_path", 512);
    opt_str("severity", 20);
    opt_str("enforcement_action", 10);
    if let Some(vs) = obj.get("violations") {
        let vs = vs.as_array().expect("violations is an array");
        assert!(vs.len() <= 64);
        for v in vs {
            let p = v["ast_node_path"].as_str().unwrap_or("");
            assert!(
                p.encode_utf16().count() <= 512,
                "violation path over 512: {e}"
            );
            assert!(v.get("rule_id").is_none(), "rule_id is never sent: {e}");
        }
    }
}

/// Every kind of agent-access event the proxy emits fits the ingest schema. With
/// `VERICTO_INGEST_FIXTURE=<path>` the batch is also written there, to be parsed
/// by fmw's own validator.
#[tokio::test]
async fn agent_access_events_fit_the_ingest_schema() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let (scfg, squeue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Sanitized);
    let long = "c".repeat(200);
    {
        let mut pg = wire_as(
            Box::new(PostgresProtocol),
            cfg.clone(),
            queue.clone(),
            Some(AGENT),
        );
        pg_expect_forwarded(&mut pg, "SELECT id FROM orders LIMIT 1").await;
        pg_expect_087(&mut pg, "SELECT ssn FROM customers LIMIT 1").await;
        pg_expect_087(&mut pg, "UPDATE orders SET total = 0 WHERE id = 1").await;
        pg_expect_087(&mut pg, "SET ROLE postgres").await;
        pg_expect_087(
            &mut pg,
            &format!("SELECT \"{long}\" FROM customers LIMIT 1"),
        )
        .await;
        pg.client.write_all(&pg_function_call()).await.unwrap();
        read_pg(&mut pg.client).await;
        let mut bot = wire_as(
            Box::new(PostgresProtocol),
            cfg.clone(),
            queue.clone(),
            Some(BOT),
        );
        pg_expect_forwarded(&mut bot, "SELECT id, ssn FROM customers LIMIT 1").await;
        let mut app = wire_as(
            Box::new(PostgresProtocol),
            cfg.clone(),
            queue.clone(),
            Some("app"),
        );
        pg_expect_forwarded(&mut app, "SELECT 1").await;
        let mut my = wire_as(
            Box::new(MysqlProtocol),
            cfg.clone(),
            queue.clone(),
            Some(AGENT),
        );
        my_expect_087(
            &mut my,
            COM_STMT_PREPARE,
            "SELECT ssn FROM customers WHERE id = ?",
        )
        .await;
        my.client
            .write_all(&my_packet(b"\x11root\0\0".to_vec()))
            .await
            .unwrap();
        read_my(&mut my.client).await;
        let mut smy = wire_as(Box::new(MysqlProtocol), scfg, squeue.clone(), Some(AGENT));
        my_expect_087(
            &mut smy,
            COM_QUERY,
            r#"SELECT id FROM customers WHERE name = "Alice Smith" LIMIT 1"#,
        )
        .await;
    }
    let mut all = events(&queue);
    all.extend(events(&squeue));
    assert_eq!(all.len(), 11);
    for e in &all {
        assert_ingest_shape(e);
    }
    assert!(all.iter().all(|e| e.get("db_user").is_some()));
    if let Ok(path) = std::env::var("VERICTO_INGEST_FIXTURE") {
        let batch = serde_json::json!({ "source": "tcp", "events": all });
        std::fs::write(path, serde_json::to_vec_pretty(&batch).unwrap()).unwrap();
    }
}

// ── Default schema and current database (engine 3.8.1) ──────────────────────

/// A proxy whose agent-access map is `map` (the `/sync/rules` shape).
fn proxy_with(map: serde_json::Value) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    cfg.agent_access
        .store(Arc::new(serde_json::from_value(map).expect("policies")));
    (cfg, queue)
}

/// A MySQL session as `user` whose HandshakeResponse named `database`.
fn mysql_session(
    cfg: &Arc<PgProxyConfig>,
    queue: &Arc<MemoryQueue>,
    user: &str,
    database: CurrentDatabase,
) -> Wire {
    wire_start(
        Box::new(MysqlProtocol),
        cfg.clone(),
        queue.clone(),
        SessionStart {
            user: Some(user.into()),
            database,
            client_caps: crate::tcp::codec_mysql::CLIENT_PROTOCOL_41
                | crate::tcp::codec_mysql::CLIENT_SECURE_CONNECTION,
        },
    )
}

/// The `access_denied` of the last event for `sql`.
fn denied_for(queue: &MemoryQueue, sql: &str) -> serde_json::Value {
    let ev = events(queue);
    let e = ev
        .iter()
        .rev()
        .find(|e| e["query_text"] == sql)
        .unwrap_or_else(|| panic!("no event for {sql}"));
    e.get("access_denied")
        .cloned()
        .unwrap_or(serde_json::json!([]))
}

fn orders_only(mode: &str, default_schema: Option<&str>) -> serde_json::Value {
    let mut p = serde_json::json!({ "mode": mode, "ddl": "deny", "entries": [
        { "schema": null, "table": "orders", "columns": "*", "access": "read" }
    ]});
    if let Some(d) = default_schema {
        p["default_schema"] = d.into();
    }
    p
}

/// MySQL: the policy's `default_schema` (the dashboard's setting) applies while
/// the session names no database; the database named in the handshake wins over
/// it; a database the proxy could not read leaves no default schema at all.
#[tokio::test]
async fn mysql_handshake_database_wins_over_the_policy_default_schema() {
    let (cfg, queue) =
        proxy_with(serde_json::json!({ AGENT: orders_only("enforce", Some("shop")) }));

    let mut w = mysql_session(&cfg, &queue, AGENT, CurrentDatabase::FromPolicy);
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM orders").await;
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM `shop`.`orders`").await;
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;

    let mut w = mysql_session(&cfg, &queue, AGENT, CurrentDatabase::Named("other".into()));
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM orders").await;
    let msg = my_expect_087(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
    assert!(msg.contains("shop.orders"), "{msg}");
    // MySQL database names compare exactly.
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM Other.orders").await;

    let mut w = mysql_session(&cfg, &queue, AGENT, CurrentDatabase::Unknown);
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM orders").await;
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
}

/// COM_INIT_DB is `USE <db>`: refused like `USE` under an enforced policy (the
/// current database does not move), and when forwarded (observe, or no policy)
/// it moves the current database the next statements are evaluated against,
/// exactly as a forwarded SQL `USE` does.
#[tokio::test]
async fn init_db_and_use_move_the_current_database() {
    let (cfg, queue) = proxy_with(serde_json::json!({
        AGENT: orders_only("enforce", None),
        BOT: orders_only("observe", None),
    }));

    // Enforced: COM_INIT_DB and USE are refused; still `shop`.
    let mut w = mysql_session(&cfg, &queue, AGENT, CurrentDatabase::Named("shop".into()));
    w.client
        .write_all(&my_packet(b"\x02other".to_vec()))
        .await
        .unwrap();
    let (code, msg) = my_err(&read_my(&mut w.client).await);
    assert_eq!(code, 1142);
    assert!(msg.contains("AccessPolicy > COM_INIT_DB (ddl)"), "{msg}");
    let msg = my_expect_087(&mut w, COM_QUERY, "USE other").await;
    assert!(msg.contains("USE (ddl)"), "{msg}");
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;

    // Observed: both are forwarded (and flagged) and move the database.
    let mut w = mysql_session(&cfg, &queue, BOT, CurrentDatabase::Named("shop".into()));
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
    assert_eq!(
        denied_for(&queue, "SELECT id FROM shop.orders"),
        serde_json::json!([])
    );
    w.client
        .write_all(&my_packet(b"\x02other".to_vec()))
        .await
        .unwrap();
    assert_eq!(read_my(&mut w.db).await.payload, b"\x02other".to_vec());
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
    assert_eq!(
        denied_for(&queue, "SELECT id FROM shop.orders")[0]["schema"],
        "shop"
    );
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;
    assert_eq!(
        denied_for(&queue, "SELECT id FROM other.orders"),
        serde_json::json!([])
    );
    my_expect_forwarded(&mut w, COM_QUERY, "USE `shop`").await;
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
    assert_eq!(
        denied_for(&queue, "SELECT id FROM shop.orders"),
        serde_json::json!([])
    );

    // No policy yet: COM_INIT_DB passes and is tracked, so a policy synced later
    // applies to the database the session is really in.
    let mut w = mysql_session(&cfg, &queue, "app", CurrentDatabase::Named("shop".into()));
    w.client
        .write_all(&my_packet(b"\x02other".to_vec()))
        .await
        .unwrap();
    assert_eq!(read_my(&mut w.db).await.payload, b"\x02other".to_vec());
    let synced = proxy_with(serde_json::json!({ "app": orders_only("enforce", Some("shop")) })).0;
    cfg.agent_access.store(synced.agent_access.load_full());
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
}

/// COM_CHANGE_USER between two users without a policy also changes the
/// database (the packet's schema field).
#[tokio::test]
async fn change_user_moves_the_current_database() {
    let (cfg, queue) = proxy_with(serde_json::json!({ "app2": orders_only("observe", None) }));
    let mut w = mysql_session(&cfg, &queue, "app", CurrentDatabase::Named("shop".into()));
    // user\0, 1-byte auth length + auth, database\0, charset.
    w.client
        .write_all(&my_packet(b"\x11app3\0\x02xyother\0\x21\x00".to_vec()))
        .await
        .unwrap();
    assert_eq!(read_my(&mut w.db).await.payload[0], 0x11);
    // The session is app3 in `other`; give app3 a policy and check where it is.
    let synced = proxy_with(serde_json::json!({ "app3": orders_only("enforce", None) })).0;
    cfg.agent_access.store(synced.agent_access.load_full());
    my_expect_forwarded(&mut w, COM_QUERY, "SELECT id FROM other.orders").await;
    my_expect_087(&mut w, COM_QUERY, "SELECT id FROM shop.orders").await;
}

/// Postgres: the policy's `default_schema` replaces `public`; names fmw sends
/// double-quoted are case-sensitive, unquoted ones fold to lower case.
#[tokio::test]
async fn pg_policy_default_schema_and_quoted_names() {
    let (cfg, queue) = proxy_with(serde_json::json!({ AGENT: {
        "mode": "enforce", "ddl": "deny", "default_schema": "app", "entries": [
            { "schema": null, "table": "orders", "columns": "*", "access": "read" },
            { "schema": null, "table": "\"Customers\"", "columns": ["id", "\"Email\""], "access": "read" }
        ]
    }}));
    let mut w = wire_as(Box::new(PostgresProtocol), cfg, queue, Some(AGENT));
    pg_expect_forwarded(&mut w, "SELECT id FROM orders").await;
    pg_expect_forwarded(&mut w, "SELECT id FROM app.orders").await;
    pg_expect_087(&mut w, "SELECT id FROM public.orders").await;
    pg_expect_forwarded(&mut w, "SELECT id, \"Email\" FROM \"Customers\"").await;
    pg_expect_087(&mut w, "SELECT id FROM customers").await;
    pg_expect_087(&mut w, "SELECT email FROM \"Customers\"").await;
}

/// Without `default_schema` the Postgres default stays `public`, as before.
#[tokio::test]
async fn pg_without_default_schema_keeps_public() {
    let (cfg, queue) = proxy_with(serde_json::json!({ AGENT: orders_only("enforce", None) }));
    let mut w = wire_as(Box::new(PostgresProtocol), cfg, queue, Some(AGENT));
    pg_expect_forwarded(&mut w, "SELECT id FROM public.orders").await;
    pg_expect_087(&mut w, "SELECT id FROM app.orders").await;
}

/// `search_path` (and the identity settings) in the StartupMessage are the
/// `SET` the engine denies: refused under an enforced allowlist, flagged under
/// observe, untouched without a policy.
#[test]
fn startup_settings_are_evaluated_as_their_set() {
    let (cfg, queue) = proxy(EnforcementPolicy::default(), TelemetryQueryMode::Raw);
    let path = vec![("search_path".to_string(), "secret, public".to_string())];
    let msg = startup_settings_block(&cfg, Some(AGENT), &path).expect("refused");
    assert!(msg.contains("VERICTO-087"), "{msg}");
    assert!(msg.contains("SET search_path (ddl)"), "{msg}");
    assert!(msg.contains("StartupMessage search_path"), "{msg}");
    let role = vec![("role".to_string(), "admin".to_string())];
    let msg = startup_settings_block(&cfg, Some(AGENT), &role).expect("refused");
    assert!(msg.contains("SET ROLE"), "{msg}");
    // Observe: reported, not refused. A quote in the value stays in the literal.
    let odd = vec![("search_path".to_string(), "x', y".to_string())];
    assert_eq!(startup_settings_block(&cfg, Some(BOT), &odd), None);
    // No policy for this user (and no tags): nothing evaluated.
    assert_eq!(startup_settings_block(&cfg, Some("app"), &path), None);
    let ev = events(&queue);
    assert_eq!(ev.len(), 3, "{ev:?}");
    assert_eq!(ev[2]["status"], "FLAGGED");
    assert_eq!(ev[2]["query_text"], "SET search_path = 'x'', y'");
}

/// End to end: a StartupMessage with `options=-c search_path=…` from an agent
/// gets 42501 and never reaches the database.
#[tokio::test]
async fn startup_search_path_is_refused_before_the_database() {
    use tokio::io::AsyncReadExt;
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let (cfg, _queue) = config_with(
        ("127.0.0.1", port),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    cfg.agent_access.store(Arc::new(policies()));
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (s, _) = proxy.accept().await.unwrap();
        crate::tcp::postgres::handle_connection(s, cfg).await;
    });

    let mut body = 196608i32.to_be_bytes().to_vec();
    for (k, v) in [
        ("user", AGENT),
        ("database", "shop"),
        ("options", "-c search_path=secret"),
    ] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut startup = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend_from_slice(&body);
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client.write_all(&startup).await.unwrap();
    let e = read_pg(&mut client).await;
    assert_eq!(e.tag, b'E');
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert!(msg.contains("SET search_path"), "{msg}");
    let mut rest = Vec::new();
    timeout(client.read_to_end(&mut rest)).await.unwrap();
    assert!(
        rest.is_empty(),
        "the connection is closed after the refusal"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "nothing reached the database"
    );
    task.await.unwrap();
}
