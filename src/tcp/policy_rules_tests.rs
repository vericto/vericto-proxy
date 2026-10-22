// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Business policy rules on the wire (4.15.0, `VERICTO_POLICY_RULES`).
//!
//! Same in-memory layer as `sensitive_tests` (the real interception loop between
//! an in-memory client and an in-memory database), plus real sockets for the
//! Postgres StartupMessage. Covered: what `off` leaves exactly as 4.14.3, the
//! startup capture (`application_name`, `-c vericto.*`, MySQL connect
//! attributes), `SET vericto.*` consumed and set once, principal resolution
//! (strongest signal, narrowing, ambiguity) and the observe / enforce verdicts.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vericto_engine::{EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity};

use super::sensitive_tests::{
    Wire, config_with, cstr, events, first_query_reaching_db, my_cmd, my_err,
    my_first_query_reaching_db, my_sql, pg_error, pg_parse, pg_query, pg_sync, read_my, read_pg,
    timeout, wire_start,
};
use crate::tcp::codec_mysql::{COM_QUERY, MySqlPacket};
use crate::tcp::policy_rules::{
    PolicyRulesMode, PolicyRulesRuntime, SESSION_CONTEXT_RULE_CODE, SessionDeclared,
    bundle_from_sync,
};
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::tcp::session::SessionStart;
use crate::telemetry::queue::MemoryQueue;

const BOT: &str = "support_bot";
/// Over the policy's cap: blocked for an agent under enforce.
const BIG_REFUND: &str = "INSERT INTO refunds (order_id, amount) VALUES (1, 950)";
const SMALL_REFUND: &str = "INSERT INTO refunds (order_id, amount) VALUES (1, 150)";
/// Blocked by the built-in ruleset, policies or not.
const DANGEROUS: &str = "DELETE FROM users";

/// The keys a 4.14.3 event could carry. With the flag off nothing else appears.
const KEYS_4_14_3: &[&str] = &[
    "event_id",
    "database_id",
    "query_text",
    "dialect",
    "status",
    "rule_code",
    "ast_node_path",
    "severity",
    "enforcement_action",
    "parse_error_message",
    "latency_ms",
    "client_ip",
    "occurred_at",
    "violations",
    "rewritten_query",
    "sensitive_columns",
    "db_user",
    "access_policy_mode",
    "access_denied",
];

fn refund_cap() -> Rule {
    Rule {
        rule_id: "r-refunds".into(),
        code: "POL-014".into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(
            r#"
rule: refund-cap
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent] }
deny_if: stmt.values("public.refunds.amount").exists(v, double(v) > 200.0)
action: block
"#
            .into(),
        ),
    }
}

fn rules() -> Vec<Rule> {
    let mut r = crate::tcp::evaluator::default_ruleset();
    r.push(refund_cap());
    r
}

fn principals() -> serde_json::Value {
    serde_json::json!({ "version": "p1", "entries": [
        { "id": "agent-support-bot", "type": "agent", "owner": "ana@acme.com",
          "identify": { "db_user": BOT } },
        { "id": "metabase", "type": "tool",
          "identify": { "db_user": "metabase_ro" },
          "narrow": { "application_name": "Metabase*" } },
        { "id": "agent-by-app", "type": "agent",
          "identify": { "application_name": "refund-agent*" } },
        { "id": "shared-a", "type": "agent", "identify": { "db_user": "shared" } },
        { "id": "shared-b", "type": "service", "identify": { "db_user_pattern": "sha*" } }
    ]})
}

/// A proxy with [`rules`] in `mode`, its bundle compiled as a sync would.
fn proxy(mode: PolicyRulesMode) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    proxy_to(mode, ("unused", 0))
}

fn proxy_to(
    mode: PolicyRulesMode,
    upstream: (&str, u16),
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let (cfg, queue) = config_with(
        upstream,
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        rules(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let mut cfg = Arc::into_inner(cfg).expect("unshared config");
    let bundle = if mode.is_on() {
        bundle_from_sync(mode, cfg.ruleset.load_full(), Some(principals()), "v-test")
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

fn session(
    proto: Box<dyn WireProtocol>,
    mode: PolicyRulesMode,
    user: &str,
    declared: SessionDeclared,
) -> Wire {
    let (cfg, queue) = proxy(mode);
    wire_start(
        proto,
        cfg,
        queue,
        SessionStart {
            user: Some(user.into()),
            declared,
            ..Default::default()
        },
    )
}

fn pg(mode: PolicyRulesMode, user: &str) -> Wire {
    session(Box::new(PostgresProtocol), mode, user, Default::default())
}

async fn pg_forwarded(w: &mut Wire, sql: &str) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.encode(), pg_query(sql), "{sql} forwarded byte for byte");
}

/// Expects a 42501 block naming `code`, then ReadyForQuery. Returns the message.
async fn pg_blocked(w: &mut Wire, sql: &str, code: &str) -> String {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E', "{sql} must be blocked");
    let (state, msg) = pg_error(&e.body);
    assert_eq!(state, "42501", "{msg}");
    assert!(msg.contains(code), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    msg
}

/// Expects the proxy's own answer to a consumed SET: CommandComplete + RFQ.
async fn pg_set_ok(w: &mut Wire, sql: &str) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let c = read_pg(&mut w.client).await;
    assert_eq!((c.tag, cstr(&c.body).as_str()), (b'C', "SET"), "{sql}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
}

// ── Off: exactly 4.14.3 ──────────────────────────────────────────────────────

/// With the flag off the policy rule is not evaluated as a policy, `SET
/// vericto.*` reaches the database like any SET, and events carry only the
/// fields 4.14.3 sent.
#[tokio::test]
async fn off_forwards_set_vericto_evaluates_without_policies_and_adds_no_fields() {
    let mut w = pg(PolicyRulesMode::Off, BOT);
    pg_forwarded(&mut w, "SET vericto.ticket = 'OPS-1'").await;
    pg_forwarded(&mut w, "SET vericto.ticket = 'OPS-2'").await;
    pg_forwarded(&mut w, BIG_REFUND).await;
    pg_blocked(&mut w, DANGEROUS, "VERICTO-").await;

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 4);
    for e in &ev {
        for key in e.as_object().unwrap().keys() {
            assert!(
                KEYS_4_14_3.contains(&key.as_str()),
                "new key {key} with the flag off"
            );
        }
    }
    assert_eq!(ev[2]["status"], "ALLOWED", "no policy verdict when off");
}

/// Same on MySQL.
#[tokio::test]
async fn off_mysql_forwards_set_vericto() {
    let mut w = session(
        Box::new(MysqlProtocol),
        PolicyRulesMode::Off,
        BOT,
        Default::default(),
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, "SET vericto.ticket = 'OPS-1'"))
        .await
        .unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(my_sql(&p), "SET vericto.ticket = 'OPS-1'");
}

// ── Enforce and observe ──────────────────────────────────────────────────────

#[tokio::test]
async fn enforce_blocks_what_the_policy_denies_for_the_identified_agent() {
    let mut w = pg(PolicyRulesMode::Enforce, BOT);
    pg_forwarded(&mut w, SMALL_REFUND).await;
    let msg = pg_blocked(&mut w, BIG_REFUND, "POL-014").await;
    assert!(msg.starts_with("Vericto blocked this query"), "{msg}");
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    assert_eq!(ev[1]["status"], "BLOCKED");
    assert_eq!(ev[1]["rule_code"], "POL-014");
    for e in &ev {
        assert_eq!(e["principal_id"], "agent-support-bot");
        assert_eq!(e["principal_type"], "agent");
        assert_eq!(e["principal_trust"], "medium");
        assert_eq!(e["principal_via"], "db_user");
        assert_eq!(e["policy_bundle_version"], "v-test");
        assert!(e.get("client_ip").is_none(), "no client address, ever");
        assert!(e.get("ticket_id").is_none() && e.get("session_tenant").is_none());
    }
}

/// Observe: the policy's block becomes a flag (forwarded, FLAGGED, the policy
/// violation at `flag`); a block of the built-in rules stays a block.
#[tokio::test]
async fn observe_flags_policy_blocks_and_keeps_every_other_verdict() {
    let mut w = pg(PolicyRulesMode::Observe, BOT);
    pg_forwarded(&mut w, BIG_REFUND).await;
    pg_forwarded(&mut w, SMALL_REFUND).await;
    pg_blocked(&mut w, DANGEROUS, "VERICTO-").await;

    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "FLAGGED", "{}", ev[0]);
    assert_eq!(ev[0]["rule_code"], "POL-014");
    assert_eq!(ev[0]["enforcement_action"], "flag");
    let v = ev[0]["violations"].as_array().unwrap();
    assert!(
        v.iter()
            .any(|v| v["rule_code"] == "POL-014" && v["enforcement_action"] == "flag"),
        "{v:?}"
    );
    assert_eq!(ev[1]["status"], "ALLOWED");
    assert_eq!(ev[2]["status"], "BLOCKED");
    assert_ne!(ev[2]["rule_code"], "POL-014");
}

/// A user no principal matches is `unknown` and `weak`: an agents-only policy
/// does not apply to it.
#[tokio::test]
async fn an_unmatched_session_is_unknown_and_weak() {
    let mut w = pg(PolicyRulesMode::Enforce, "someone_else");
    pg_forwarded(&mut w, BIG_REFUND).await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["principal_id"], "someone_else");
    assert_eq!(ev[0]["principal_type"], "unknown");
    assert_eq!(ev[0]["principal_trust"], "weak");
    assert!(ev[0].get("principal_via").is_none());
}

/// Two principals match `shared` at the same trust (an exact user and a
/// pattern): ambiguous, so unknown and weak, and the agent policy does not
/// treat it as either.
#[tokio::test]
async fn an_ambiguous_session_fails_closed_to_unknown_and_weak() {
    let mut w = pg(PolicyRulesMode::Enforce, "shared");
    pg_forwarded(&mut w, BIG_REFUND).await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["principal_id"], "shared");
    assert_eq!(ev[0]["principal_type"], "unknown");
    assert_eq!(ev[0]["principal_trust"], "weak");
}

/// The strongest signal wins and narrowing must hold: `metabase_ro` from
/// Metabase is the `metabase` tool (medium); from another client it matches
/// nothing; an unknown user whose application_name names the refund agent is
/// that agent with weak trust, and the agent policy applies to it.
#[tokio::test]
async fn strongest_signal_and_narrowing_on_the_wire() {
    let declared = |app: &str| SessionDeclared {
        application_name: Some(app.into()),
        ..Default::default()
    };
    let mut w = session(
        Box::new(PostgresProtocol),
        PolicyRulesMode::Enforce,
        "metabase_ro",
        declared("Metabase v0.50"),
    );
    pg_forwarded(&mut w, "SELECT 1").await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["principal_id"], "metabase");
    assert_eq!(ev[0]["principal_trust"], "medium");
    assert_eq!(ev[0]["application_name"], "Metabase v0.50");

    let mut w = session(
        Box::new(PostgresProtocol),
        PolicyRulesMode::Enforce,
        "metabase_ro",
        declared("psql"),
    );
    pg_forwarded(&mut w, "SELECT 1").await;
    assert_eq!(events(&w.queue)[0]["principal_type"], "unknown");

    let mut w = session(
        Box::new(PostgresProtocol),
        PolicyRulesMode::Enforce,
        "nobody",
        declared("refund-agent 2.1"),
    );
    pg_blocked(&mut w, BIG_REFUND, "POL-014").await;
    let ev = events(&w.queue);
    assert_eq!(ev[0]["principal_id"], "agent-by-app");
    assert_eq!(ev[0]["principal_trust"], "weak");
    assert_eq!(ev[0]["principal_via"], "application_name");
}

// ── SET vericto.* ────────────────────────────────────────────────────────────

/// Consumed (answered by the proxy, never forwarded), set once, and carried on
/// every later event.
#[tokio::test]
async fn pg_set_vericto_is_consumed_set_once_and_never_forwarded() {
    let mut w = pg(PolicyRulesMode::Enforce, BOT);
    pg_set_ok(&mut w, "SET vericto.ticket = 'OPS-123'").await;
    pg_set_ok(&mut w, "set session vericto.tenant to acme_eu;").await;
    pg_blocked(
        &mut w,
        "SET vericto.ticket = 'OPS-999'",
        SESSION_CONTEXT_RULE_CODE,
    )
    .await;
    pg_blocked(&mut w, "RESET vericto.ticket", SESSION_CONTEXT_RULE_CODE).await;
    pg_blocked(
        &mut w,
        "SELECT set_config('vericto.tenant', 'other', false)",
        SESSION_CONTEXT_RULE_CODE,
    )
    .await;
    pg_blocked(
        &mut w,
        "SET vericto.role = 'admin'",
        SESSION_CONTEXT_RULE_CODE,
    )
    .await;
    // None of the above reached the database: the first thing it sees is this.
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    let last = ev.last().unwrap();
    assert_eq!(last["query_text"], "SELECT 1");
    assert_eq!(last["ticket_id"], "OPS-123");
    assert_eq!(last["session_tenant"], "acme_eu");
    // The four refusals are reported as blocks of the session context.
    let blocked: Vec<_> = ev
        .iter()
        .filter(|e| e["rule_code"] == SESSION_CONTEXT_RULE_CODE)
        .collect();
    assert_eq!(blocked.len(), 4);
    assert!(blocked.iter().all(|e| e["status"] == "BLOCKED"));
}

/// A prepared `SET vericto.*` is refused (the proxy would have to answer the
/// whole extended sequence), and the sequence is swallowed until Sync.
#[tokio::test]
async fn pg_prepared_set_vericto_is_refused_until_sync() {
    let mut w = pg(PolicyRulesMode::Observe, BOT);
    w.client
        .write_all(&pg_parse("", "SET vericto.ticket = 'OPS-1'", &[]))
        .await
        .unwrap();
    w.client.write_all(&pg_sync()).await.unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert!(pg_error(&e.body).1.contains(SESSION_CONTEXT_RULE_CODE));
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
}

#[tokio::test]
async fn mysql_set_vericto_is_consumed_and_set_once() {
    let mut w = session(
        Box::new(MysqlProtocol),
        PolicyRulesMode::Enforce,
        BOT,
        Default::default(),
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, "SET vericto.ticket = 'OPS-7'"))
        .await
        .unwrap();
    let ok = read_my(&mut w.client).await;
    assert_eq!((ok.seq, ok.payload[0]), (1, 0x00), "an OK_Packet, seq 1");
    w.client
        .write_all(&my_cmd(COM_QUERY, "SET vericto.ticket = 'OPS-8'"))
        .await
        .unwrap();
    let err = read_my(&mut w.client).await;
    let (code, msg) = my_err(&err);
    assert_eq!(code, 1142);
    assert!(msg.contains(SESSION_CONTEXT_RULE_CODE), "{msg}");
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
    let ev = events(&w.queue);
    assert_eq!(ev.last().unwrap()["ticket_id"], "OPS-7");
}

// ── Startup capture ──────────────────────────────────────────────────────────

/// A HandshakeResponse41 (mysql_native_password, no database) with these
/// connect attributes.
fn handshake_response(attrs: &[(&str, &str)]) -> Vec<u8> {
    use crate::tcp::codec_mysql::{
        CLIENT_CONNECT_ATTRS, CLIENT_PLUGIN_AUTH, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
    };
    let caps =
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS;
    let mut p = caps.to_le_bytes().to_vec();
    p.extend_from_slice(&16_777_216u32.to_le_bytes());
    p.push(45);
    p.extend_from_slice(&[0u8; 23]);
    p.extend_from_slice(b"support_bot\0");
    p.push(20);
    p.extend_from_slice(&[7u8; 20]);
    p.extend_from_slice(b"mysql_native_password\0");
    let mut block = Vec::new();
    for (k, v) in attrs {
        block.push(k.len() as u8);
        block.extend_from_slice(k.as_bytes());
        block.push(v.len() as u8);
        block.extend_from_slice(v.as_bytes());
    }
    p.push(block.len() as u8);
    p.extend_from_slice(&block);
    p
}

/// MySQL: `program_name` is the application name; `vericto.*` attributes are
/// the session context, taken out of the response the server gets; the rest
/// is kept as it was. A bad one refuses the connection.
#[test]
fn mysql_connect_attributes_give_program_name_and_the_context() {
    let resp = handshake_response(&[
        ("_os", "Linux"),
        ("program_name", "refund-agent 2.1"),
        ("vericto.ticket", "OPS-5"),
        ("vericto.tenant", "acme"),
    ]);
    let (stripped, declared) = crate::tcp::session::mysql_handshake_context(&resp).unwrap();
    assert_eq!(
        declared.application_name.as_deref(),
        Some("refund-agent 2.1")
    );
    assert_eq!(declared.ticket.as_deref(), Some("OPS-5"));
    assert_eq!(declared.tenant.as_deref(), Some("acme"));
    let stripped = stripped.expect("rewritten without the vericto attributes");
    assert_eq!(
        stripped,
        handshake_response(&[("_os", "Linux"), ("program_name", "refund-agent 2.1")])
    );
    assert_eq!(
        crate::tcp::codec_mysql::read_handshake_username(&stripped).as_deref(),
        Some("support_bot")
    );

    // Nothing to take out: forwarded unchanged.
    let plain = handshake_response(&[("program_name", "mysql")]);
    let (none, declared) = crate::tcp::session::mysql_handshake_context(&plain).unwrap();
    assert!(none.is_none());
    assert_eq!(declared.application_name.as_deref(), Some("mysql"));

    let bad = handshake_response(&[("vericto.role", "admin")]);
    assert!(crate::tcp::session::mysql_handshake_context(&bad).is_err());
}

/// A session that declared its `program_name` reports it, and resolves its
/// principal with it.
#[tokio::test]
async fn mysql_program_name_identifies_and_is_reported() {
    let declared = SessionDeclared {
        application_name: Some("refund-agent 2.1".into()),
        ..Default::default()
    };
    let mut w = session(
        Box::new(MysqlProtocol),
        PolicyRulesMode::Enforce,
        "nobody",
        declared,
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, BIG_REFUND))
        .await
        .unwrap();
    let err = read_my(&mut w.client).await;
    assert!(my_err(&err).1.contains("POL-014"));
    let ev = events(&w.queue);
    assert_eq!(ev[0]["application_name"], "refund-agent 2.1");
    assert_eq!(ev[0]["principal_id"], "agent-by-app");
}

fn startup(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut body = 196_608i32.to_be_bytes().to_vec();
    for (k, v) in pairs {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut raw = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    raw.extend_from_slice(&body);
    raw
}

/// A real Postgres session through `handle_connection`: returns the
/// StartupMessage the database received and the queue. With `query`, the
/// client sends it after startup and the database's copy is returned too.
async fn through_the_proxy(
    mode: PolicyRulesMode,
    startup_msg: Vec<u8>,
    query: Option<&str>,
) -> (Option<Vec<u8>>, Option<String>, Vec<u8>, Arc<MemoryQueue>) {
    let db = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_addr = db.local_addr().unwrap();
    let expect_query = query.is_some();
    let db_task = tokio::spawn(async move {
        let Ok(Ok((mut sock, _))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), db.accept()).await
        else {
            return (None, None);
        };
        let mut len = [0u8; 4];
        sock.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
        sock.read_exact(&mut body).await.unwrap();
        let mut startup = len.to_vec();
        startup.extend_from_slice(&body);
        let q = if expect_query {
            let m = read_pg(&mut sock).await;
            Some(cstr(&m.body))
        } else {
            None
        };
        (Some(startup), q)
    });
    let (cfg, queue) = proxy_to(mode, ("127.0.0.1", db_addr.port()));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (client, _) = proxy.accept().await.unwrap();
        crate::tcp::postgres::handle_connection(client, cfg).await;
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&startup_msg).await.unwrap();
    if let Some(q) = query {
        client.write_all(&pg_query(q)).await.unwrap();
    }
    let (startup, q) = timeout(db_task).await.unwrap();
    // What the client got back (an ErrorResponse when refused).
    let mut reply = Vec::new();
    if startup.is_none() {
        let _ = timeout(client.read_to_end(&mut reply)).await;
    }
    drop(client);
    server.abort();
    (startup, q, reply, queue)
}

/// On: `-c vericto.ticket=…` and a `vericto.tenant` parameter are taken out of
/// the StartupMessage before it reaches the database; the rest arrives as
/// sent; the session reports the ticket, tenant and application_name.
#[tokio::test]
async fn pg_startup_vericto_settings_are_consumed_and_application_name_captured() {
    let sent = startup(&[
        ("user", BOT),
        ("database", "app"),
        ("options", "-c vericto.ticket=OPS-9 -c statement_timeout=5s"),
        ("application_name", "psql"),
        ("vericto.tenant", "acme"),
    ]);
    let (got, q, _, queue) =
        through_the_proxy(PolicyRulesMode::Enforce, sent, Some("SELECT 1")).await;
    assert_eq!(
        got.unwrap(),
        startup(&[
            ("user", BOT),
            ("database", "app"),
            ("options", "-c statement_timeout=5s"),
            ("application_name", "psql"),
        ])
    );
    assert_eq!(q.as_deref(), Some("SELECT 1"));
    let ev = events(&queue);
    assert_eq!(ev[0]["ticket_id"], "OPS-9");
    assert_eq!(ev[0]["session_tenant"], "acme");
    assert_eq!(ev[0]["application_name"], "psql");
    assert_eq!(ev[0]["principal_id"], "agent-support-bot");
}

/// Off: the StartupMessage reaches the database byte for byte, `vericto.*`
/// included, as in 4.14.3.
#[tokio::test]
async fn pg_startup_is_forwarded_unchanged_when_off() {
    let sent = startup(&[
        ("user", BOT),
        ("options", "-c vericto.ticket=OPS-9"),
        ("application_name", "psql"),
    ]);
    let (got, _, _, queue) =
        through_the_proxy(PolicyRulesMode::Off, sent.clone(), Some("SELECT 1")).await;
    assert_eq!(got.unwrap(), sent);
    let ev = events(&queue);
    assert!(ev[0].get("ticket_id").is_none() && ev[0].get("application_name").is_none());
}

/// A startup `vericto.*` setting the proxy cannot accept refuses the
/// connection before it reaches the database.
#[tokio::test]
async fn pg_startup_with_a_bad_vericto_setting_is_refused_before_the_database() {
    let sent = startup(&[("user", BOT), ("options", "-c vericto.role=admin")]);
    let (got, _, reply, _) = through_the_proxy(PolicyRulesMode::Observe, sent, None).await;
    assert!(got.is_none(), "nothing reached the database");
    assert_eq!(reply.first(), Some(&b'E'), "an ErrorResponse");
    let msg = String::from_utf8_lossy(&reply);
    assert!(msg.contains(SESSION_CONTEXT_RULE_CODE), "{msg}");
}

/// The packet the proxy answers a consumed MySQL SET with parses as an OK.
#[test]
fn the_mysql_set_ok_is_an_ok_packet() {
    let bytes = MysqlProtocol.build_set_ok(0, &crate::tcp::tx_state::ServerTxState::new());
    assert_eq!(&bytes[..4], &[7, 0, 0, 1]);
    let p = MySqlPacket {
        seq: bytes[3],
        payload: bytes[4..].to_vec(),
    };
    assert_eq!(p.payload[0], 0x00);
}

// ── The real transaction state in the proxy's own replies ────────────────────
//
// A session with the relay running, as in production: what the test writes on
// the database side reaches the client through the relay, which follows the
// transaction state the server reports.

use crate::tcp::tx_state::{
    CLIENT_DEPRECATE_EOF, MYSQL_STATUS_AUTOCOMMIT, MYSQL_STATUS_IN_TRANS, ServerTxState,
};

struct Relayed {
    client: tokio::io::DuplexStream,
    db: tokio::io::DuplexStream,
    _tasks: (
        tokio::task::JoinHandle<std::io::Result<()>>,
        tokio::task::JoinHandle<()>,
    ),
}

fn relayed(mysql: bool) -> Relayed {
    use crate::tcp::client_tls::{ClientRead, ClientWrite};
    use tokio::sync::Mutex;
    let (cfg, _queue) = proxy(PolicyRulesMode::Enforce);
    let (client, proxy_client_side) = tokio::io::duplex(1 << 20);
    let (proxy_db_side, db) = tokio::io::duplex(1 << 20);
    let (cr, cw) = tokio::io::split(proxy_client_side);
    let (dr, dw) = tokio::io::split(proxy_db_side);
    let mut client_read: ClientRead = Box::new(cr);
    let client_write: Arc<Mutex<ClientWrite>> = Arc::new(Mutex::new(Box::new(cw)));
    let server_read: crate::tcp::upstream::UpstreamRead = Box::new(dr);
    let mut server_write: crate::tcp::upstream::UpstreamWrite = Box::new(dw);
    let tx = Arc::new(ServerTxState::new());
    let caps = CLIENT_DEPRECATE_EOF;
    let relay = if mysql {
        tokio::spawn(crate::tcp::session::relay_upstream_to_client(
            server_read,
            client_write.clone(),
            Some((crate::tcp::tx_state::MySqlTxTracker::new(caps), tx.clone())),
        ))
    } else {
        tokio::spawn(crate::tcp::postgres::relay_server_to_client(
            server_read,
            client_write.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Some(tx.clone()),
        ))
    };
    let start = SessionStart {
        user: Some(BOT.into()),
        client_caps: if mysql { caps } else { 0 },
        tx_state: Some(tx),
        ..Default::default()
    };
    let session = tokio::spawn(async move {
        let proto: Box<dyn WireProtocol> = if mysql {
            Box::new(MysqlProtocol)
        } else {
            Box::new(PostgresProtocol)
        };
        crate::tcp::session::intercept_client_to_server(
            proto.as_ref(),
            &mut client_read,
            &mut server_write,
            &client_write,
            &cfg,
            start,
        )
        .await
    });
    Relayed {
        client,
        db,
        _tasks: (session, relay),
    }
}

fn pg_msg(tag: u8, body: &[u8]) -> Vec<u8> {
    crate::tcp::codec::PgMessage {
        tag,
        body: body.to_vec(),
    }
    .encode()
}

/// The client sends `sql`, the database answers `tag` and ReadyForQuery `status`.
async fn pg_server_round(w: &mut Relayed, sql: &str, tag: &str, status: u8) {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.encode(), pg_query(sql), "{sql} reaches the database");
    let mut reply = if tag == "ERROR" {
        crate::tcp::codec::build_error_response("22012", "division by zero")
    } else {
        pg_msg(b'C', format!("{tag}\0").as_bytes())
    };
    reply.extend(pg_msg(b'Z', &[status]));
    w.db.write_all(&reply).await.unwrap();
    let first = read_pg(&mut w.client).await;
    assert_eq!(first.tag, if tag == "ERROR" { b'E' } else { b'C' });
    let z = read_pg(&mut w.client).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &[status][..]));
}

/// The proxy's own answer to a consumed SET, with its ReadyForQuery status.
async fn pg_set_status(w: &mut Relayed, sql: &str) -> u8 {
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let c = read_pg(&mut w.client).await;
    assert_eq!((c.tag, cstr(&c.body).as_str()), (b'C', "SET"), "{sql}");
    let z = read_pg(&mut w.client).await;
    assert_eq!(z.tag, b'Z');
    z.body[0]
}

#[tokio::test]
async fn pg_consumed_set_reports_idle_outside_a_transaction() {
    let mut w = relayed(false);
    assert_eq!(
        pg_set_status(&mut w, "SET vericto.ticket = 'OPS-1'").await,
        b'I'
    );
    pg_server_round(&mut w, "SELECT 1", "SELECT 1", b'I').await;
    assert_eq!(
        pg_set_status(&mut w, "SET vericto.tenant = 't1'").await,
        b'I'
    );
}

#[tokio::test]
async fn pg_consumed_set_inside_begin_reports_in_transaction() {
    let mut w = relayed(false);
    pg_server_round(&mut w, "BEGIN", "BEGIN", b'T').await;
    assert_eq!(
        pg_set_status(&mut w, "SET vericto.ticket = 'OPS-1'").await,
        b'T'
    );
    pg_server_round(&mut w, "COMMIT", "COMMIT", b'I').await;
    assert_eq!(
        pg_set_status(&mut w, "SET vericto.tenant = 't1'").await,
        b'I'
    );
}

/// In a failed transaction block the server refuses everything with 25P02: so
/// does the proxy for a `SET vericto.*`, which is not taken (set once still
/// accepts the value after the ROLLBACK).
#[tokio::test]
async fn pg_set_in_a_failed_transaction_is_25p02_and_not_consumed() {
    let mut w = relayed(false);
    pg_server_round(&mut w, "BEGIN", "BEGIN", b'T').await;
    pg_server_round(&mut w, "SELECT 1/0", "ERROR", b'E').await;
    w.client
        .write_all(&pg_query("SET vericto.ticket = 'OPS-1'"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert_eq!(pg_error(&e.body).0, "25P02");
    let z = read_pg(&mut w.client).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"E"[..]));
    pg_server_round(&mut w, "ROLLBACK", "ROLLBACK", b'I').await;
    assert_eq!(
        pg_set_status(&mut w, "SET vericto.ticket = 'OPS-2'").await,
        b'I'
    );
    // Set once: the value now is OPS-2, so a second SET is refused.
    w.client
        .write_all(&pg_query("SET vericto.ticket = 'OPS-3'"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(pg_error(&e.body).0, "42501");
    let z = read_pg(&mut w.client).await;
    assert_eq!(z.body, b"I");
}

/// Parse/Bind/Execute/Sync of a `SET vericto.*`: refused, swallowed until
/// Sync, and the Sync's ReadyForQuery carries the server's state (25P02 first
/// in a failed transaction block, as the server would answer the Parse).
#[tokio::test]
async fn pg_extended_set_reports_the_real_state_at_sync() {
    let mut w = relayed(false);
    pg_server_round(&mut w, "BEGIN", "BEGIN", b'T').await;
    let extended = |sql: &str| {
        let mut b = pg_parse("", sql, &[]);
        b.extend(pg_msg(b'B', b"\0\0\0\0\0\0\0\0"));
        b.extend(pg_msg(b'E', b"\0\0\0\0\0"));
        b.extend(pg_sync());
        b
    };
    w.client
        .write_all(&extended("SET vericto.ticket = 'OPS-1'"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert!(pg_error(&e.body).1.contains(SESSION_CONTEXT_RULE_CODE));
    let z = read_pg(&mut w.client).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"T"[..]));

    pg_server_round(&mut w, "SELECT 1/0", "ERROR", b'E').await;
    w.client
        .write_all(&extended("SET vericto.ticket = 'OPS-1'"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(pg_error(&e.body).0, "25P02");
    let z = read_pg(&mut w.client).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"E"[..]));
}

fn my_ok(seq: u8, flags: u16) -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00];
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&[0, 0]);
    MySqlPacket { seq, payload }.encode()
}

/// The client sends `sql`; the database answers an OK with `flags`.
async fn my_server_round(w: &mut Relayed, sql: &str, reply: Vec<u8>) {
    w.client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();
    let m = read_my(&mut w.db).await;
    assert_eq!(my_sql(&m), sql, "{sql} reaches the database");
    w.db.write_all(&reply).await.unwrap();
    let back = read_my(&mut w.client).await;
    assert_eq!(back.encode(), reply);
}

async fn my_set_flags(w: &mut Relayed, sql: &str) -> u16 {
    w.client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();
    let ok = read_my(&mut w.client).await;
    assert_eq!((ok.seq, ok.payload[0]), (1, 0x00), "{sql}: an OK_Packet");
    u16::from_le_bytes([ok.payload[3], ok.payload[4]])
}

#[tokio::test]
async fn mysql_consumed_set_reports_the_flags_with_autocommit_on() {
    let mut w = relayed(true);
    assert_eq!(
        my_set_flags(&mut w, "SET vericto.ticket = 'OPS-1'").await,
        MYSQL_STATUS_AUTOCOMMIT
    );
    my_server_round(
        &mut w,
        "BEGIN",
        my_ok(1, MYSQL_STATUS_AUTOCOMMIT | MYSQL_STATUS_IN_TRANS),
    )
    .await;
    assert_eq!(
        my_set_flags(&mut w, "SET vericto.tenant = 't1'").await,
        MYSQL_STATUS_AUTOCOMMIT | MYSQL_STATUS_IN_TRANS
    );
}

/// Autocommit off: no autocommit flag, and IN_TRANS once a statement opened
/// the transaction. An error leaves it open (MySQL has no failed-transaction
/// state, so no 25P02 equivalent): the flags stay the last OK's.
#[tokio::test]
async fn mysql_consumed_set_reports_the_flags_with_autocommit_off() {
    let mut w = relayed(true);
    my_server_round(&mut w, "SET autocommit = 0", my_ok(1, 0)).await;
    assert_eq!(
        my_set_flags(&mut w, "SET vericto.ticket = 'OPS-1'").await,
        0
    );
    my_server_round(
        &mut w,
        "UPDATE orders SET status = 'x' WHERE id = 1",
        my_ok(1, MYSQL_STATUS_IN_TRANS),
    )
    .await;
    let err = crate::tcp::codec_mysql::build_err_packet(1, 1146, "42S02", "no such table");
    my_server_round(&mut w, "SELECT * FROM missing WHERE id = 1 LIMIT 1", err).await;
    assert_eq!(
        my_set_flags(&mut w, "SET vericto.tenant = 't1'").await,
        MYSQL_STATUS_IN_TRANS
    );
}

/// A result set reaches the client unchanged, and its terminator's flags count.
#[tokio::test]
async fn mysql_flags_follow_a_result_set_terminator() {
    let mut w = relayed(true);
    w.client
        .write_all(&my_cmd(
            COM_QUERY,
            "SELECT id FROM orders WHERE id = 1 LIMIT 1",
        ))
        .await
        .unwrap();
    read_my(&mut w.db).await;
    let mut set = MySqlPacket {
        seq: 1,
        payload: vec![1],
    }
    .encode();
    set.extend(
        MySqlPacket {
            seq: 2,
            payload:
                b"\x03def\x00\x00\x00\x02id\x00\x0c\x3f\x00\x0b\x00\x00\x00\x03\x00\x00\x00\x00\x00"
                    .to_vec(),
        }
        .encode(),
    );
    set.extend(
        MySqlPacket {
            seq: 3,
            payload: vec![0x01, b'1'],
        }
        .encode(),
    );
    let mut term = vec![0xfe, 0x00, 0x00];
    term.extend_from_slice(&(MYSQL_STATUS_IN_TRANS).to_le_bytes());
    term.extend_from_slice(&[0, 0]);
    set.extend(
        MySqlPacket {
            seq: 4,
            payload: term,
        }
        .encode(),
    );
    w.db.write_all(&set).await.unwrap();
    for _ in 0..4 {
        read_my(&mut w.client).await;
    }
    assert_eq!(
        my_set_flags(&mut w, "SET vericto.ticket = 'OPS-1'").await,
        MYSQL_STATUS_IN_TRANS
    );
}
