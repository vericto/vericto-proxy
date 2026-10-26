// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The interception loop's everyday paths and their failure modes, on both wire
//! protocols: a query in, a decision, and what reaches the database.
//!
//! Same in-memory layer as `sensitive_tests`: the real
//! `session::intercept_client_to_server` between an in-memory client and an
//! in-memory database, with the built-in ruleset. Every read is bounded, so a
//! wrong turn shows up as a timeout instead of a hung suite.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vericto_engine::EnforcementPolicy;

use super::sensitive_tests::{
    Wire, config_with, cstr, events, first_query_reaching_db, my_cmd, my_err,
    my_first_query_reaching_db, my_sql, pg_error, pg_parse, pg_query, pg_sync, read_my, read_pg,
    split_parse, timeout, wire_with,
};
use crate::tcp::codec::PgMessage;
use crate::tcp::codec_mysql::{COM_QUERY, COM_QUIT, COM_STMT_PREPARE, VERICTO_BLOCK_ERR_CODE};
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::query_limit::OVERSIZE_RULE_CODE;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::telemetry::queue::MemoryQueue;

/// A statement the built-in ruleset blocks: a DELETE without WHERE.
const DANGEROUS: &str = "DELETE FROM users";
/// A statement it allows.
const SAFE: &str = "SELECT id, name FROM users WHERE id = 1 LIMIT 1";

fn proxy_config(
    policy: EnforcementPolicy,
    max_query_bytes: Option<usize>,
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let (cfg, queue) = config_with(
        ("unused", 0),
        policy,
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let cfg = match max_query_bytes {
        Some(limit) => {
            let mut cfg = Arc::into_inner(cfg).expect("unshared config");
            cfg.max_query_bytes = limit;
            Arc::new(cfg)
        }
        None => cfg,
    };
    (cfg, queue)
}

fn session(proto: Box<dyn WireProtocol>) -> Wire {
    let (cfg, queue) = proxy_config(EnforcementPolicy::default(), None);
    wire_with(proto, cfg, queue)
}

fn session_limited(proto: Box<dyn WireProtocol>, limit: usize, monitor_mode: bool) -> Wire {
    let policy = EnforcementPolicy {
        monitor_mode,
        ..EnforcementPolicy::default()
    };
    let (cfg, queue) = proxy_config(policy, Some(limit));
    wire_with(proto, cfg, queue)
}

fn pg_msg(tag: u8, body: &[u8]) -> Vec<u8> {
    PgMessage {
        tag,
        body: body.to_vec(),
    }
    .encode()
}

/// Bind of the unnamed portal to `statement`, no parameters, text results.
fn pg_bind(statement: &str) -> Vec<u8> {
    let mut body = vec![0]; // unnamed portal
    body.extend_from_slice(statement.as_bytes());
    body.push(0);
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no formats, no params, no result formats
    pg_msg(b'B', &body)
}

fn pg_execute() -> Vec<u8> {
    pg_msg(b'E', &[0, 0, 0, 0, 0])
}

/// Reads until the database side is closed by the proxy; returns what arrived.
async fn db_until_closed(w: &mut Wire) -> Vec<u8> {
    let mut rest = Vec::new();
    timeout(w.db.read_to_end(&mut rest)).await.unwrap();
    rest
}

/// Asserts an ErrorResponse (42501) naming `code`, followed by ReadyForQuery.
async fn pg_expect_block(w: &mut Wire, code: &str) -> String {
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E', "an ErrorResponse");
    let (sqlstate, msg) = pg_error(&e.body);
    assert_eq!(sqlstate, "42501", "{msg}");
    assert!(msg.contains(code), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z', "then ReadyForQuery");
    msg
}

// ── Postgres: the daily path ─────────────────────────────────────────────────

/// Simple protocol: an allowed query reaches the database byte for byte; a
/// dangerous one is answered by the proxy (42501 + ReadyForQuery), never reaches
/// it, and both are reported.
#[tokio::test]
async fn pg_simple_query_is_forwarded_when_allowed_and_blocked_when_dangerous() {
    let mut w = session(Box::new(PostgresProtocol));

    w.client.write_all(&pg_query(SAFE)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.encode(), pg_query(SAFE), "forwarded unchanged");

    w.client.write_all(&pg_query(DANGEROUS)).await.unwrap();
    let msg = pg_expect_block(&mut w, "VERICTO-").await;
    assert!(msg.starts_with("Vericto blocked this query"), "{msg}");
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 3);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["query_text"], SAFE);
    assert_eq!(ev[1]["status"], "BLOCKED");
    assert!(
        ev[1]["rule_code"]
            .as_str()
            .is_some_and(|c| c.starts_with("VERICTO-")),
        "{}",
        ev[1]
    );
}

/// Extended protocol: an allowed Parse/Bind/Execute/Sync passes in order; after
/// a blocked Parse, the Bind/Execute that follow are swallowed (never reach the
/// database) and the Sync is answered with ReadyForQuery by the proxy, after
/// which the session works normally.
#[tokio::test]
async fn pg_extended_block_swallows_the_sequence_until_sync() {
    let mut w = session(Box::new(PostgresProtocol));

    let allowed = [
        pg_parse("ok", SAFE, &[]),
        pg_bind("ok"),
        pg_execute(),
        pg_sync(),
    ];
    for m in &allowed {
        w.client.write_all(m).await.unwrap();
    }
    let parse = read_pg(&mut w.db).await;
    assert_eq!(parse.tag, b'P');
    assert_eq!(split_parse(&parse.body).1, SAFE);
    for tag in [b'B', b'E', b'S'] {
        assert_eq!(read_pg(&mut w.db).await.tag, tag, "relayed in order");
    }

    for m in [
        pg_parse("bad", DANGEROUS, &[]),
        pg_bind("bad"),
        pg_msg(b'D', b"Pbad\0"),
        pg_execute(),
        pg_sync(),
    ] {
        w.client.write_all(&m).await.unwrap();
    }
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert!(pg_error(&e.body).1.contains("VERICTO-"));
    assert_eq!(
        read_pg(&mut w.client).await.tag,
        b'Z',
        "Sync answered by the proxy"
    );

    // None of the blocked sequence reached the database.
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
    let ev = events(&w.queue);
    assert_eq!(ev[1]["status"], "BLOCKED");
}

/// Terminate is forwarded so the database closes its backend, and the loop ends
/// (the proxy closes its side of the upstream).
#[tokio::test]
async fn pg_terminate_is_forwarded_and_ends_the_session() {
    let mut w = session(Box::new(PostgresProtocol));
    w.client.write_all(&pg_msg(b'X', &[])).await.unwrap();
    assert_eq!(read_pg(&mut w.db).await.tag, b'X');
    assert!(db_until_closed(&mut w).await.is_empty());
}

/// A client that disconnects ends the session; nothing is sent upstream.
#[tokio::test]
async fn pg_client_disconnect_closes_the_upstream() {
    let Wire { client, mut db, .. } = session(Box::new(PostgresProtocol));
    drop(client);
    let mut rest = Vec::new();
    timeout(db.read_to_end(&mut rest)).await.unwrap();
    assert!(rest.is_empty());
}

/// A frame with an impossible length (below the 4 bytes of the length itself,
/// or above the 64 MiB the codec accepts) ends the session: nothing of it is
/// forwarded and the proxy does not try to resynchronise on garbage.
#[tokio::test]
async fn pg_malformed_frames_end_the_session_without_forwarding() {
    for len in [2i32, -1, 64 * 1024 * 1024 + 1] {
        let mut w = session(Box::new(PostgresProtocol));
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(b"DELETE FROM users\0");
        w.client.write_all(&frame).await.unwrap();
        assert!(
            db_until_closed(&mut w).await.is_empty(),
            "length {len}: nothing reaches the database"
        );
        assert!(events(&w.queue).is_empty());
    }
}

/// A Query whose SQL is not NUL-terminated cannot be read, so it is not
/// evaluated as SQL; it is passed through untouched and the database rejects it.
#[tokio::test]
async fn pg_unreadable_query_is_passed_through_without_evaluation() {
    let mut w = session(Box::new(PostgresProtocol));
    let raw = pg_msg(b'Q', b"DELETE FROM users");
    w.client.write_all(&raw).await.unwrap();
    assert_eq!(read_pg(&mut w.db).await.encode(), raw);
    assert!(events(&w.queue).is_empty(), "nothing evaluated");
}

/// An empty query is valid Postgres (EmptyQueryResponse): forwarded, not blocked.
#[tokio::test]
async fn pg_empty_query_is_forwarded() {
    let mut w = session(Box::new(PostgresProtocol));
    w.client.write_all(&pg_query("")).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'Q');
    assert_eq!(cstr(&m.body), "");
}

// ── Postgres: the size limit ─────────────────────────────────────────────────

/// At the limit a statement is evaluated as usual; one byte over, it is refused
/// before any parse, with its own code, and the event carries its size, not its
/// text.
#[tokio::test]
async fn pg_query_size_limit_is_inclusive_and_refuses_one_byte_over() {
    let at_limit = SAFE;
    let mut w = session_limited(Box::new(PostgresProtocol), at_limit.len(), false);

    w.client.write_all(&pg_query(at_limit)).await.unwrap();
    assert_eq!(cstr(&read_pg(&mut w.db).await.body), at_limit);

    let over = format!("{at_limit} ");
    w.client.write_all(&pg_query(&over)).await.unwrap();
    let msg = pg_expect_block(&mut w, OVERSIZE_RULE_CODE).await;
    assert!(msg.contains("VERICTO_MAX_QUERY_BYTES"), "{msg}");
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    assert_eq!(ev[1]["status"], "BLOCKED");
    assert_eq!(ev[1]["rule_code"], OVERSIZE_RULE_CODE);
    let text = ev[1]["query_text"].as_str().unwrap();
    assert!(text.contains(&over.len().to_string()), "{text}");
    assert!(
        !text.contains("users"),
        "the statement is not reported: {text}"
    );
}

/// An oversized Parse is refused like any blocked Parse: the rest of the
/// sequence is swallowed until Sync.
#[tokio::test]
async fn pg_oversized_parse_swallows_the_sequence_until_sync() {
    let mut w = session_limited(Box::new(PostgresProtocol), 16, false);
    for m in [
        pg_parse("big", SAFE, &[]),
        pg_bind("big"),
        pg_execute(),
        pg_sync(),
    ] {
        w.client.write_all(&m).await.unwrap();
    }
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert!(pg_error(&e.body).1.contains(OVERSIZE_RULE_CODE));
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
}

/// monitor_mode never blocks, also on size: the oversized statement is
/// forwarded unevaluated and recorded as monitored.
#[tokio::test]
async fn pg_oversized_query_in_monitor_mode_is_forwarded_unevaluated() {
    let mut w = session_limited(Box::new(PostgresProtocol), 8, true);
    w.client.write_all(&pg_query(DANGEROUS)).await.unwrap();
    assert_eq!(cstr(&read_pg(&mut w.db).await.body), DANGEROUS);
    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    assert_ne!(ev[0]["status"], "BLOCKED");
    assert_eq!(ev[0]["rule_code"], OVERSIZE_RULE_CODE);
}

// ── MySQL: the daily path ────────────────────────────────────────────────────

/// COM_QUERY: allowed SQL reaches the database; dangerous SQL gets an ERR_Packet
/// numbered as the reply to the command (seq 1) and never reaches it. The same
/// statement through COM_STMT_PREPARE is blocked too.
#[tokio::test]
async fn mysql_com_query_and_prepare_are_forwarded_or_blocked() {
    let mut w = session(Box::new(MysqlProtocol));

    w.client.write_all(&my_cmd(COM_QUERY, SAFE)).await.unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(p.payload[0], COM_QUERY);
    assert_eq!(my_sql(&p), SAFE);

    for cmd in [COM_QUERY, COM_STMT_PREPARE] {
        w.client.write_all(&my_cmd(cmd, DANGEROUS)).await.unwrap();
        let err = read_my(&mut w.client).await;
        assert_eq!(err.seq, 1, "the reply to a command is seq 1");
        let (code, msg) = my_err(&err);
        assert_eq!(code, VERICTO_BLOCK_ERR_CODE, "{msg}");
        assert!(msg.contains("VERICTO-"), "{msg}");
    }
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");

    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "ALLOWED");
    assert_eq!(ev[0]["dialect"], "mysql");
    assert_eq!(ev[1]["status"], "BLOCKED");
    assert_eq!(ev[2]["status"], "BLOCKED");
}

/// COM_QUIT is forwarded and ends the session.
#[tokio::test]
async fn mysql_quit_is_forwarded_and_ends_the_session() {
    let mut w = session(Box::new(MysqlProtocol));
    w.client.write_all(&[1, 0, 0, 0, COM_QUIT]).await.unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(p.payload, vec![COM_QUIT]);
    assert!(db_until_closed(&mut w).await.is_empty());
}

/// A `USE` that is allowed moves the session's database and is forwarded.
#[tokio::test]
async fn mysql_use_is_forwarded() {
    let mut w = session(Box::new(MysqlProtocol));
    for sql in ["USE shop", "USE `odd``name`"] {
        w.client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();
        assert_eq!(my_sql(&read_my(&mut w.db).await), sql);
    }
}

/// An oversized COM_QUERY is refused with an ERR_Packet and never reaches the
/// database; at the limit it is evaluated as usual.
#[tokio::test]
async fn mysql_query_size_limit_refuses_one_byte_over() {
    let mut w = session_limited(Box::new(MysqlProtocol), SAFE.len(), false);
    w.client.write_all(&my_cmd(COM_QUERY, SAFE)).await.unwrap();
    assert_eq!(my_sql(&read_my(&mut w.db).await), SAFE);

    let over = format!("{SAFE} ");
    w.client.write_all(&my_cmd(COM_QUERY, &over)).await.unwrap();
    let err = read_my(&mut w.client).await;
    assert_eq!(err.seq, 1);
    let (code, msg) = my_err(&err);
    assert_eq!(code, VERICTO_BLOCK_ERR_CODE);
    assert!(msg.contains(OVERSIZE_RULE_CODE), "{msg}");
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
}

// ── Where a statement is evaluated (4.19.0) ──────────────────────────────────

/// Up to the threshold the evaluation runs on the calling thread; above it, and
/// for every statement with the threshold at 0, on the blocking pool.
#[tokio::test]
async fn run_evaluation_is_inline_up_to_the_threshold_and_on_the_pool_above() {
    use crate::tcp::session::run_evaluation;
    let here = std::thread::current().id();
    let on = |max: usize, len: usize| async move {
        run_evaluation(max, len, || std::thread::current().id())
            .await
            .expect("evaluation")
    };
    assert_eq!(on(1024, 0).await, here);
    assert_eq!(on(1024, 1024).await, here, "at the threshold: inline");
    assert_ne!(on(1024, 1025).await, here, "one byte over: the pool");
    assert_ne!(on(0, 0).await, here, "0: always the pool");
    assert_ne!(on(0, 10).await, here);
}

/// The same statements, evaluated inline or on the pool, give the same verdicts,
/// the same bytes to the database and to the client, and the same events.
#[tokio::test]
async fn inline_and_pool_evaluation_give_the_same_outcome() {
    fn stable(mut events: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        for e in &mut events {
            let o = e.as_object_mut().unwrap();
            for k in ["event_id", "occurred_at", "latency_ms"] {
                o.remove(k);
            }
        }
        events
    }
    async fn run(inline_eval_max_bytes: usize) -> (Vec<Vec<u8>>, Vec<serde_json::Value>) {
        let (cfg, queue) = proxy_config(EnforcementPolicy::default(), None);
        let mut cfg = Arc::into_inner(cfg).expect("unshared config");
        cfg.inline_eval_max_bytes = inline_eval_max_bytes;
        let mut w = wire_with(Box::new(PostgresProtocol), Arc::new(cfg), queue);
        let mut seen = Vec::new();
        for sql in [SAFE, DANGEROUS, "BEGIN", "SELECT * FROM users", SAFE] {
            w.client.write_all(&pg_query(sql)).await.unwrap();
            if sql == DANGEROUS {
                pg_expect_block(&mut w, "VERICTO-").await;
                seen.push(b"blocked".to_vec());
            } else {
                seen.push(read_pg(&mut w.db).await.encode());
            }
        }
        (seen, stable(events(&w.queue)))
    }
    let inline = run(crate::tcp::query_limit::DEFAULT_INLINE_EVAL_MAX_BYTES).await;
    let pool = run(0).await;
    assert_eq!(inline.0, pool.0);
    assert_eq!(inline.1, pool.1);
    assert_eq!(inline.1.len(), 5, "one event per statement");
}
