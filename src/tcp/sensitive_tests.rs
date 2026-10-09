//! Sensitive Column Protection (VERICTO-085) on the wire.
//!
//! Two layers:
//!
//! * **In-memory** (always run): the real interception loop
//!   (`session::intercept_client_to_server`) between an in-memory client and an
//!   in-memory "database", for both wire protocols. They prove what reaches the
//!   database for each policy, byte for byte: the rewritten SQL on a mask, the
//!   original on a flag, nothing on a block.
//! * **Real Postgres** (run when `VERICTO_TEST_PG_URL` is set, e.g.
//!   `postgres://postgres:postgres@127.0.0.1:54322/postgres`): a real driver
//!   (`tokio-postgres`) talks to the proxy, which fronts a real Postgres, over
//!   the simple and the extended protocol, and must receive masked values. Each
//!   test creates its own database and drops it afterwards, also on failure.
//! * **Real MySQL** (run when `VERICTO_TEST_MYSQL_URL` is set, e.g.
//!   `mysql://root:mysql@127.0.0.1:33061`): a real driver (`mysql_async`) talks to
//!   the proxy over COM_QUERY and prepared statements (COM_STMT_PREPARE /
//!   COM_STMT_EXECUTE with bound parameters). Same own-database rule. For an
//!   upstream that requires TLS, MySQL needs TLS on both hops (see the README):
//!   set `VERICTO_TEST_MYSQL_SSLMODE=require` and the proxy's certificate and key
//!   in `VERICTO_TEST_MYSQL_TLS_CERT` / `VERICTO_TEST_MYSQL_TLS_KEY`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;
use vericto_engine::{EnforcementPolicy, SensitiveColumn};

use crate::tcp::client_tls::{ClientRead, ClientWrite};
use crate::tcp::codec::PgMessage;
use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE, MySqlPacket};
use crate::tcp::postgres::{PgProxyConfig, TelemetrySink};
use crate::tcp::protocol::WireProtocol;
use crate::tcp::protocol::mysql::MysqlProtocol;
use crate::tcp::protocol::postgres::PostgresProtocol;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::telemetry::EventQueue;
use crate::telemetry::queue::MemoryQueue;

/// The tags every test uses. One column per policy, plus two mask styles.
fn tags() -> Vec<SensitiveColumn> {
    serde_json::from_value(serde_json::json!([
        { "schema": null, "table": "customers", "column": "email", "policy": "mask", "mask_style": "email" },
        { "schema": null, "table": "customers", "column": "card", "policy": "mask", "mask_style": "last4" },
        { "schema": null, "table": "customers", "column": "ssn", "policy": "block" },
        { "schema": null, "table": "customers", "column": "phone", "policy": "flag" }
    ]))
    .expect("tags deserialize")
}

fn policy_with_tags() -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: tags(),
        ..EnforcementPolicy::default()
    }
}

fn config(
    upstream: (&str, u16),
    policy: EnforcementPolicy,
    mode: TelemetryQueryMode,
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    config_with(
        upstream,
        policy,
        mode,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    )
}

fn config_with(
    upstream: (&str, u16),
    policy: EnforcementPolicy,
    mode: TelemetryQueryMode,
    rules: Vec<vericto_engine::Rule>,
    upstream_tls: crate::tcp::upstream::UpstreamTlsMode,
) -> (Arc<PgProxyConfig>, Arc<MemoryQueue>) {
    let queue = Arc::new(MemoryQueue::new(100));
    let cfg = Arc::new(PgProxyConfig {
        upstream_host: upstream.0.to_string(),
        upstream_port: upstream.1,
        upstream_tls,
        upstream_ca_path: None,
        upstream_client_cert: None,
        upstream_client_key: None,
        client_tls_acceptor: None,
        ruleset: Arc::new(ArcSwap::from_pointee(rules)),
        policy: Arc::new(ArcSwap::from_pointee(policy)),
        telemetry_mode: Arc::new(ArcSwap::from_pointee(mode)),
        telemetry: Some(TelemetrySink {
            queue: queue.clone() as Arc<dyn EventQueue>,
            database_id: "00000000-0000-0000-0000-000000000001".to_string(),
        }),
        max_query_bytes: crate::tcp::query_limit::DEFAULT_MAX_QUERY_BYTES,
    });
    (cfg, queue)
}

/// The interception loop between an in-memory client and an in-memory database.
struct Wire {
    /// What the client application writes to / reads from.
    client: DuplexStream,
    /// What the proxy forwarded to the database.
    db: DuplexStream,
    queue: Arc<MemoryQueue>,
    _task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn wire(proto: Box<dyn WireProtocol>, policy: EnforcementPolicy, mode: TelemetryQueryMode) -> Wire {
    let (client, proxy_client_side) = tokio::io::duplex(1 << 20);
    let (proxy_db_side, db) = tokio::io::duplex(1 << 20);
    let (cfg, queue) = config(("unused", 0), policy, mode);
    let (cr, cw) = tokio::io::split(proxy_client_side);
    let mut client_read: ClientRead = Box::new(cr);
    let client_write: Arc<Mutex<ClientWrite>> = Arc::new(Mutex::new(Box::new(cw)));
    let mut server_write: crate::tcp::upstream::UpstreamWrite = Box::new(proxy_db_side);
    let task = tokio::spawn(async move {
        crate::tcp::session::intercept_client_to_server(
            proto.as_ref(),
            &mut client_read,
            &mut server_write,
            &client_write,
            &cfg,
        )
        .await
    });
    Wire {
        client,
        db,
        queue,
        _task: task,
    }
}

async fn timeout<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), f)
        .await
        .expect("timed out")
}

// ── Postgres framing helpers ─────────────────────────────────────────────────

fn pg_query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    PgMessage { tag: b'Q', body }.encode()
}

fn pg_parse(name: &str, sql: &str, types: &[i32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    body.extend_from_slice(&(types.len() as i16).to_be_bytes());
    for t in types {
        body.extend_from_slice(&t.to_be_bytes());
    }
    PgMessage { tag: b'P', body }.encode()
}

fn pg_sync() -> Vec<u8> {
    PgMessage {
        tag: b'S',
        body: Vec::new(),
    }
    .encode()
}

async fn read_pg(s: &mut DuplexStream) -> PgMessage {
    let mut tag = [0u8; 1];
    timeout(s.read_exact(&mut tag)).await.unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
    s.read_exact(&mut body).await.unwrap();
    PgMessage { tag: tag[0], body }
}

/// (statement name, query, parameter type OIDs) of a Parse body.
fn split_parse(body: &[u8]) -> (String, String, Vec<i32>) {
    let n = body.iter().position(|&b| b == 0).unwrap();
    let name = String::from_utf8(body[..n].to_vec()).unwrap();
    let rest = &body[n + 1..];
    let q = rest.iter().position(|&b| b == 0).unwrap();
    let query = String::from_utf8(rest[..q].to_vec()).unwrap();
    let rest = &rest[q + 1..];
    let count = i16::from_be_bytes([rest[0], rest[1]]) as usize;
    let types = (0..count)
        .map(|i| {
            let o = 2 + i * 4;
            i32::from_be_bytes([rest[o], rest[o + 1], rest[o + 2], rest[o + 3]])
        })
        .collect();
    assert_eq!(rest.len(), 2 + count * 4, "nothing after the types");
    (name, query, types)
}

fn cstr(body: &[u8]) -> String {
    let n = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    String::from_utf8(body[..n].to_vec()).unwrap()
}

/// SQLSTATE and message of an ErrorResponse body.
fn pg_error(body: &[u8]) -> (String, String) {
    let (mut code, mut msg) = (String::new(), String::new());
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field = body[i];
        let v = cstr(&body[i + 1..]);
        i += 1 + v.len() + 1;
        match field {
            b'C' => code = v,
            b'M' => msg = v,
            _ => {}
        }
    }
    (code, msg)
}

/// Sends a probe the proxy always forwards and returns the first SQL the
/// database received: proves whether an earlier statement reached it.
async fn first_query_reaching_db(w: &mut Wire) -> String {
    w.client.write_all(&pg_query("SELECT 1")).await.unwrap();
    let m = read_pg(&mut w.db).await;
    match m.tag {
        b'Q' => cstr(&m.body),
        b'P' => split_parse(&m.body).1,
        t => panic!("unexpected message {}", t as char),
    }
}

fn events(q: &MemoryQueue) -> Vec<serde_json::Value> {
    q.drain_batch(100)
        .events
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

// ── Postgres, in memory ──────────────────────────────────────────────────────

#[tokio::test]
async fn pg_simple_query_mask_forwards_the_rewritten_sql() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT id, email FROM customers WHERE id = 7 LIMIT 5";
    w.client.write_all(&pg_query(sql)).await.unwrap();

    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'Q');
    let forwarded = cstr(&m.body);
    assert_ne!(forwarded, sql, "the original must never be forwarded");
    assert!(forwarded.contains("regexp_replace"), "got {forwarded}");
    assert!(forwarded.contains("AS email"), "got {forwarded}");

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    let e = &ev[0];
    assert_eq!(
        e["query_text"], sql,
        "the original is reported as query_text"
    );
    assert_eq!(e["rewritten_query"], forwarded.as_str());
    assert_eq!(e["rule_code"], "VERICTO-085");
    assert_eq!(e["status"], "FLAGGED");
    assert_eq!(
        e["sensitive_columns"],
        serde_json::json!([{ "schema": null, "table": "customers", "column": "email", "policy": "mask" }])
    );
}

#[tokio::test]
async fn pg_parse_mask_keeps_the_statement_name_and_parameter_types() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT id, card FROM customers WHERE id = $1 LIMIT 5";
    w.client
        .write_all(&pg_parse("stmt_7", sql, &[23]))
        .await
        .unwrap();

    let m = read_pg(&mut w.db).await;
    assert_eq!(m.tag, b'P');
    let (name, query, types) = split_parse(&m.body);
    assert_eq!(name, "stmt_7");
    assert_eq!(types, vec![23]);
    assert_ne!(query, sql);
    assert!(query.contains("$1"), "placeholders survive: {query}");
    assert!(query.contains("'****'"), "last4 mask: {query}");
}

#[tokio::test]
async fn pg_block_tag_blocks_simple_and_extended() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    // Simple: ErrorResponse + ReadyForQuery, nothing upstream.
    w.client
        .write_all(&pg_query("SELECT ssn FROM customers LIMIT 1"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    let (code, msg) = pg_error(&e.body);
    assert_eq!(code, "42501");
    assert!(msg.contains("VERICTO-085"), "{msg}");
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');

    // Extended: ErrorResponse, then the sequence is swallowed until Sync.
    w.client
        .write_all(&pg_parse(
            "",
            "SELECT ssn FROM customers WHERE id = $1",
            &[],
        ))
        .await
        .unwrap();
    w.client.write_all(&pg_sync()).await.unwrap();
    assert_eq!(read_pg(&mut w.client).await.tag, b'E');
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');

    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "BLOCKED");
    assert_eq!(ev[0]["sensitive_columns"][0]["column"], "ssn");
    assert!(ev[0].get("rewritten_query").is_none());
}

#[tokio::test]
async fn pg_flag_tag_forwards_the_original_and_reports_it() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT phone FROM customers LIMIT 1";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(cstr(&m.body), sql);

    let parse = "SELECT phone FROM customers WHERE id = $1 LIMIT 1";
    w.client
        .write_all(&pg_parse("p", parse, &[23]))
        .await
        .unwrap();
    let m = read_pg(&mut w.db).await;
    assert_eq!(split_parse(&m.body), ("p".into(), parse.into(), vec![23]));

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 2);
    for e in &ev {
        assert_eq!(e["status"], "FLAGGED");
        assert_eq!(e["rule_code"], "VERICTO-085");
        assert_eq!(e["sensitive_columns"][0]["policy"], "flag");
        assert!(e.get("rewritten_query").is_none());
    }
}

/// A mask that drops a `$n` (a computed expression over a parameter is masked
/// whole) cannot be bound: blocked with a clear message rather than forwarded
/// as a statement the client's Bind no longer fits.
#[tokio::test]
async fn pg_parse_with_a_masked_parameter_keeps_it() {
    // Engine 3.6.1 keeps every `$n` of a masked expression (3.6.0 dropped them,
    // and this Parse was blocked by the parameter check). The Parse now reaches
    // the database rewritten, with the same parameters for the client to bind.
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    w.client
        .write_all(&pg_parse(
            "",
            "SELECT substring(card, $1, 4) FROM customers LIMIT 1",
            &[],
        ))
        .await
        .unwrap();
    let p = timeout(read_pg(&mut w.db)).await;
    assert_eq!(p.tag, b'P');
    // Parse body: statement name (here empty), then the query, both NUL-terminated.
    let forwarded = cstr(&p.body[1..]);
    assert!(
        forwarded.contains("[redacted]") && forwarded.contains("$1"),
        "{forwarded}"
    );
    assert!(
        !forwarded.contains("substring(card, $1, 4) AS"),
        "{forwarded}"
    );
}

#[tokio::test]
async fn sanitized_mode_sanitizes_the_rewritten_query_too() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Sanitized,
    );
    let sql = "SELECT email FROM customers WHERE name = 'Alice Secret' LIMIT 5";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    let forwarded = cstr(&read_pg(&mut w.db).await.body);
    assert!(
        forwarded.contains("Alice Secret"),
        "the database gets the real query"
    );

    let ev = events(&w.queue);
    let reported = ev[0]["rewritten_query"].as_str().expect("rewritten_query");
    assert!(!reported.contains("Alice Secret"), "{reported}");
    assert!(reported.contains("regexp_replace"), "{reported}");
    assert!(!ev[0]["query_text"].as_str().unwrap().contains("Alice"));
    // The VERICTO-085 violation does not carry the unsanitized rewrite either.
    let body = serde_json::to_string(&ev[0]).unwrap();
    assert!(!body.contains("Alice Secret"), "{body}");
}

/// A parse error with a block or mask tag configured blocks, whatever the
/// workspace's parse_error policy says.
#[tokio::test]
async fn pg_parse_error_with_a_block_tag_blocks() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    w.client
        .write_all(&pg_query("SELEC email FROM customers"))
        .await
        .unwrap();
    let e = read_pg(&mut w.client).await;
    assert_eq!(e.tag, b'E');
    assert!(pg_error(&e.body).1.contains("VERICTO-PARSE-ERROR"));
    assert_eq!(read_pg(&mut w.client).await.tag, b'Z');
    assert_eq!(first_query_reaching_db(&mut w).await, "SELECT 1");
}

/// Without tags nothing changes: the same SELECT reaches the database as sent.
#[tokio::test]
async fn pg_without_tags_forwards_unchanged() {
    let mut w = wire(
        Box::new(PostgresProtocol),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT id, email FROM customers WHERE id = 7 LIMIT 5";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    assert_eq!(cstr(&read_pg(&mut w.db).await.body), sql);
    let ev = events(&w.queue);
    assert!(ev[0].get("sensitive_columns").is_none());
    assert!(ev[0].get("rewritten_query").is_none());
}

/// monitor_mode never changes what runs: the original is forwarded, and the
/// would-be rewrite is only reported.
#[tokio::test]
async fn pg_monitor_mode_forwards_the_original() {
    let mut policy = policy_with_tags();
    policy.monitor_mode = true;
    let mut w = wire(Box::new(PostgresProtocol), policy, TelemetryQueryMode::Raw);
    let sql = "SELECT email FROM customers LIMIT 5";
    w.client.write_all(&pg_query(sql)).await.unwrap();
    assert_eq!(cstr(&read_pg(&mut w.db).await.body), sql);
    let ev = events(&w.queue);
    assert!(ev[0].get("rewritten_query").is_none());
    assert_eq!(ev[0]["sensitive_columns"][0]["policy"], "mask");
}

// ── MySQL, in memory ─────────────────────────────────────────────────────────

fn my_cmd(cmd: u8, sql: &str) -> Vec<u8> {
    let mut payload = vec![cmd];
    payload.extend_from_slice(sql.as_bytes());
    MySqlPacket { seq: 0, payload }.encode()
}

async fn read_my(s: &mut DuplexStream) -> MySqlPacket {
    let mut h = [0u8; 4];
    timeout(s.read_exact(&mut h)).await.unwrap();
    let len = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await.unwrap();
    MySqlPacket { seq: h[3], payload }
}

/// ERR_Packet error code and message.
fn my_err(p: &MySqlPacket) -> (u16, String) {
    assert_eq!(p.payload[0], 0xFF, "expected an ERR_Packet");
    let code = u16::from_le_bytes([p.payload[1], p.payload[2]]);
    (code, String::from_utf8_lossy(&p.payload[9..]).into_owned())
}

async fn my_first_query_reaching_db(w: &mut Wire) -> String {
    w.client
        .write_all(&my_cmd(COM_QUERY, "SELECT 1"))
        .await
        .unwrap();
    let p = read_my(&mut w.db).await;
    String::from_utf8_lossy(&p.payload[1..]).into_owned()
}

const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;

/// SQL of a COM_QUERY / COM_STMT_PREPARE as the database received it.
fn my_sql(p: &MySqlPacket) -> String {
    p.extract_sql().expect("a SQL command")
}

#[tokio::test]
async fn mysql_com_query_mask_forwards_the_rewritten_sql() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT id, email, card FROM customers WHERE id = 7 LIMIT 5";
    w.client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();

    let p = read_my(&mut w.db).await;
    assert_eq!(p.seq, 0, "the sequence id is kept");
    assert_eq!(p.payload[0], COM_QUERY, "still a COM_QUERY");
    let forwarded = my_sql(&p);
    assert_ne!(forwarded, sql, "the original must never be forwarded");
    assert!(forwarded.contains("'****'"), "last4 mask: {forwarded}");
    assert!(
        forwarded.contains("AS `email`") || forwarded.contains("AS email"),
        "{forwarded}"
    );

    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1);
    let e = &ev[0];
    assert_eq!(
        e["query_text"], sql,
        "the original is reported as query_text"
    );
    assert_eq!(e["rewritten_query"], forwarded.as_str());
    assert_eq!(e["dialect"], "mysql");
    assert_eq!(e["rule_code"], "VERICTO-085");
    assert_eq!(e["status"], "FLAGGED");
    assert_eq!(e["sensitive_columns"].as_array().unwrap().len(), 2);
}

/// MySQL 8.0.23+ clients prefix COM_QUERY with query attributes; the rewrite
/// keeps that prefix, which the server parses before the SQL.
#[tokio::test]
async fn mysql_com_query_mask_keeps_the_query_attributes_prefix() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT email FROM customers LIMIT 5";
    let mut payload = vec![COM_QUERY, 0x00, 0x01];
    payload.extend_from_slice(sql.as_bytes());
    w.client
        .write_all(&MySqlPacket { seq: 0, payload }.encode())
        .await
        .unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(&p.payload[..3], &[COM_QUERY, 0x00, 0x01]);
    let forwarded = my_sql(&p);
    assert_ne!(forwarded, sql);
    assert!(forwarded.starts_with("SELECT"), "{forwarded}");
}

/// A prepared statement: COM_STMT_PREPARE carries the rewrite with the same
/// `?` parameters; COM_STMT_SEND_LONG_DATA and COM_STMT_EXECUTE, which only
/// carry the server's statement id and the bound values, pass through byte for
/// byte. The proxy keeps no statement map: the id the client executes is the
/// one the server assigned to the rewritten statement.
#[tokio::test]
async fn mysql_prepare_mask_forwards_the_rewrite_and_execute_passes_through() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    let sql = "SELECT id, card FROM customers WHERE id = ? AND name = ? LIMIT 5";
    w.client
        .write_all(&my_cmd(COM_STMT_PREPARE, sql))
        .await
        .unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(p.payload[0], COM_STMT_PREPARE);
    let forwarded = my_sql(&p);
    assert_ne!(forwarded, sql);
    assert!(forwarded.contains("'****'"), "{forwarded}");
    assert_eq!(
        forwarded.matches('?').count(),
        2,
        "both parameters survive: {forwarded}"
    );

    // stmt_id 1, a long-data chunk for parameter 1, then the execute.
    let long_data = MySqlPacket {
        seq: 0,
        payload: [&[COM_STMT_SEND_LONG_DATA, 1, 0, 0, 0, 1, 0][..], b"Ann"].concat(),
    };
    let execute = MySqlPacket {
        seq: 0,
        payload: vec![
            COM_STMT_EXECUTE,
            1,
            0,
            0,
            0, // stmt_id
            0,
            1,
            0,
            0,
            0, // flags, iteration_count
            0, // null bitmap
            1,
            3,
            0,
            0xfe,
            0, // new_params_bound, types (LONG, STRING)
            7,
            0,
            0,
            0, // id = 7 (name was sent as long data)
        ],
    };
    for pkt in [&long_data, &execute] {
        w.client.write_all(&pkt.encode()).await.unwrap();
        assert_eq!(&read_my(&mut w.db).await, pkt, "forwarded unchanged");
    }
    let ev = events(&w.queue);
    assert_eq!(ev.len(), 1, "only the prepare is evaluated");
    assert_eq!(ev[0]["rewritten_query"], forwarded.as_str());
}

/// A mask the engine cannot rewrite (`*` over a masked column) still blocks
/// with ERROR 1142, on COM_QUERY and COM_STMT_PREPARE: nothing reaches the
/// database.
#[tokio::test]
async fn mysql_mask_without_a_rewrite_is_blocked_with_err_1142() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    for cmd in [COM_QUERY, COM_STMT_PREPARE] {
        w.client
            .write_all(&my_cmd(cmd, "SELECT * FROM customers LIMIT 1"))
            .await
            .unwrap();
        let reply = read_my(&mut w.client).await;
        assert_eq!(reply.seq, 1);
        let (code, msg) = my_err(&reply);
        assert_eq!(code, 1142);
        assert!(
            msg.contains("VERICTO-085") && msg.contains("list the columns"),
            "{msg}"
        );
    }
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "BLOCKED");
    assert!(ev[0].get("rewritten_query").is_none());
}

/// monitor_mode never changes what runs: the original is forwarded on both
/// commands, and the would-be rewrite is only reported.
#[tokio::test]
async fn mysql_monitor_mode_forwards_the_original() {
    let mut policy = policy_with_tags();
    policy.monitor_mode = true;
    let mut w = wire(Box::new(MysqlProtocol), policy, TelemetryQueryMode::Raw);
    for cmd in [COM_QUERY, COM_STMT_PREPARE] {
        let sql = "SELECT email FROM customers WHERE id = 1 LIMIT 5";
        w.client.write_all(&my_cmd(cmd, sql)).await.unwrap();
        assert_eq!(my_sql(&read_my(&mut w.db).await), sql);
    }
    for e in events(&w.queue) {
        assert!(e.get("rewritten_query").is_none());
        assert_eq!(e["sensitive_columns"][0]["policy"], "mask");
    }
}

/// Sanitized telemetry covers the MySQL rewrite too: its literals never leave.
#[tokio::test]
async fn mysql_sanitized_mode_sanitizes_the_rewritten_query_too() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Sanitized,
    );
    let sql = "SELECT email FROM customers WHERE name = 'Alice Secret' LIMIT 5";
    w.client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();
    let forwarded = my_sql(&read_my(&mut w.db).await);
    assert!(
        forwarded.contains("Alice Secret"),
        "the database gets the real query"
    );

    let ev = events(&w.queue);
    let body = serde_json::to_string(&ev[0]).unwrap();
    assert!(!body.contains("Alice Secret"), "{body}");
    let reported = ev[0]["rewritten_query"].as_str().expect("rewritten_query");
    assert_ne!(reported, forwarded);
}

#[tokio::test]
async fn mysql_block_and_flag_tags() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, "SELECT ssn FROM customers LIMIT 1"))
        .await
        .unwrap();
    assert_eq!(my_err(&read_my(&mut w.client).await).0, 1142);

    let flagged = "SELECT phone FROM customers LIMIT 1";
    w.client
        .write_all(&my_cmd(COM_QUERY, flagged))
        .await
        .unwrap();
    let p = read_my(&mut w.db).await;
    assert_eq!(&p.payload[1..], flagged.as_bytes(), "flag forwards as sent");

    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "BLOCKED");
    assert_eq!(ev[1]["status"], "FLAGGED");
    assert_eq!(ev[1]["sensitive_columns"][0]["policy"], "flag");
}

#[tokio::test]
async fn mysql_parse_error_with_a_block_tag_blocks() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, "HANDLER customers READ FIRST"))
        .await
        .unwrap();
    let (code, msg) = my_err(&read_my(&mut w.client).await);
    assert_eq!(code, 1142);
    assert!(msg.contains("VERICTO-PARSE-ERROR"), "{msg}");
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
}

// ── VERICTO-086: text MySQL and the engine would read differently ────────────

/// A statement inside an executable comment that is never closed: what MySQL
/// runs depends on how it ends the comment, so the engine cannot vouch for it.
const DIVERGENT: &str = "/*!50000 SELECT id FROM accounts";

/// VERICTO-086 blocks with no tags at all, on COM_QUERY and COM_STMT_PREPARE,
/// as a native ERROR 1142 naming the rule; nothing reaches the database, and the
/// event is a BLOCKED one with the original text (raw mode).
#[tokio::test]
async fn mysql_text_divergence_is_blocked_with_err_1142() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
    );
    for cmd in [COM_QUERY, COM_STMT_PREPARE] {
        w.client.write_all(&my_cmd(cmd, DIVERGENT)).await.unwrap();
        let reply = read_my(&mut w.client).await;
        assert_eq!(reply.seq, 1);
        let (code, msg) = my_err(&reply);
        assert_eq!(code, 1142);
        assert!(msg.contains("[VERICTO-086]"), "{msg}");
    }
    assert_eq!(my_first_query_reaching_db(&mut w).await, "SELECT 1");
    let ev = events(&w.queue);
    for e in &ev[..2] {
        assert_eq!(e["status"], "BLOCKED");
        assert_eq!(e["rule_code"], "VERICTO-086");
        assert_eq!(e["enforcement_action"], "block");
        assert_eq!(e["violations"][0]["rule_code"], "VERICTO-086");
        assert_eq!(e["query_text"], DIVERGENT);
        assert!(e.get("parse_error").is_none(), "not a parse error");
    }
}

/// In sanitized mode the text does not tokenize, so it is redacted; the
/// rule's message carries no query text either.
#[tokio::test]
async fn mysql_text_divergence_in_sanitized_mode_leaks_nothing() {
    let mut w = wire(
        Box::new(MysqlProtocol),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Sanitized,
    );
    w.client
        .write_all(&my_cmd(COM_QUERY, DIVERGENT))
        .await
        .unwrap();
    assert_eq!(my_err(&read_my(&mut w.client).await).0, 1142);
    let ev = events(&w.queue);
    assert_eq!(ev[0]["rule_code"], "VERICTO-086");
    assert_eq!(ev[0]["query_text"], "<unparseable query redacted>");
    let body = serde_json::to_string(&ev[0]).unwrap();
    assert!(!body.contains("accounts"), "{body}");
}

/// monitor_mode never blocks: forwarded as sent, reported as FLAGGED.
#[tokio::test]
async fn mysql_text_divergence_under_monitor_mode_is_flagged() {
    let policy = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let mut w = wire(Box::new(MysqlProtocol), policy, TelemetryQueryMode::Raw);
    w.client
        .write_all(&my_cmd(COM_QUERY, DIVERGENT))
        .await
        .unwrap();
    assert_eq!(my_sql(&read_my(&mut w.db).await), DIVERGENT);
    let ev = events(&w.queue);
    assert_eq!(ev[0]["status"], "FLAGGED");
    assert_eq!(ev[0]["rule_code"], "VERICTO-086");
}

/// The engine raises VERICTO-086 on MySQL text only, but a block is rendered
/// per protocol from its rule code: on Postgres it is the native
/// ErrorResponse 42501 (+ ReadyForQuery) naming the rule.
#[test]
fn a_vericto_086_block_on_postgres_is_42501() {
    let block = PostgresProtocol.build_block_response(&crate::tcp::protocol::BlockContext {
        rule_code: "VERICTO-086",
        ast_node_path: "LexicalDivergence > MySQL may read this text differently (…)",
        suggested_safe_query: None,
        kind: crate::tcp::protocol::QueryKind::Simple,
        client_seq: 0,
    });
    assert_eq!(block.bytes[0], b'E');
    let len = i32::from_be_bytes(block.bytes[1..5].try_into().unwrap()) as usize;
    let (code, msg) = pg_error(&block.bytes[5..1 + len]);
    assert_eq!(code, "42501");
    assert!(msg.contains("[VERICTO-086]"), "{msg}");
    assert_eq!(block.bytes[1 + len], b'Z');
}

// ── Real Postgres ────────────────────────────────────────────────────────────

/// URL of an admin connection (`postgres://user:pass@host:port/db`), or None to skip.
fn pg_url() -> Option<String> {
    std::env::var("VERICTO_TEST_PG_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn connect(cfg: &tokio_postgres::Config) -> tokio_postgres::Client {
    let (client, conn) = cfg.connect(tokio_postgres::NoTls).await.expect("connect");
    tokio::spawn(conn);
    client
}

/// Runs `body` against a fresh database seeded with `customers`, reached
/// through a proxy with [`tags`]. The database is dropped afterwards, also
/// when `body` panics.
async fn with_real_pg<F, Fut>(body: F)
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
    let db = format!(
        "vericto_proxy_pii_{}",
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
        let host = host.clone();
        let db_name = db.clone();
        async move {
            // Seed directly, not through the proxy.
            let (seed, conn) = direct.connect(tokio_postgres::NoTls).await.unwrap();
            tokio::spawn(conn);
            seed.batch_execute(
                "CREATE TABLE customers (id int PRIMARY KEY, name text, email text, card text, ssn text, phone text);
                 INSERT INTO customers VALUES
                   (1, 'Ann',  'ann@x.io',   '4111111111114242', '123-45-6789', '555-0101'),
                   (2, 'Bob',  'plainvalue', '5500000000000004', '987-65-4321', '555-0102'),
                   (3, 'Cleo', NULL,         NULL,               NULL,          NULL);",
            )
            .await
            .unwrap();

            // The proxy, fronting that database.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = listener.local_addr().unwrap().port();
            let (pcfg, _queue) = config((&host, port), policy_with_tags(), TelemetryQueryMode::Raw);
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    tokio::spawn(crate::tcp::postgres::handle_connection(sock, pcfg.clone()));
                }
            });
            // A fresh Config: `host()`/`port()` on a parsed one ADD a host, and
            // the driver would try the database's own address first.
            let mut via = tokio_postgres::Config::new();
            via.host("127.0.0.1")
                .port(proxy_port)
                .dbname(&db_name)
                .user(direct.get_user().unwrap_or("postgres"));
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

fn texts(rows: &[tokio_postgres::Row], col: usize) -> Vec<Option<String>> {
    rows.iter()
        .map(|r| r.get::<_, Option<String>>(col))
        .collect()
}

#[tokio::test]
async fn real_pg_simple_query_returns_masked_values() {
    with_real_pg(|via| async move {
        let c = connect(&via).await;
        let msgs = c
            .simple_query("SELECT id, email, card FROM customers ORDER BY id LIMIT 10")
            .await
            .unwrap();
        let rows: Vec<(String, Option<String>, Option<String>)> = msgs
            .iter()
            .filter_map(|m| match m {
                tokio_postgres::SimpleQueryMessage::Row(r) => Some((
                    r.get(0).unwrap().to_string(),
                    r.get(1).map(str::to_string),
                    r.get(2).map(str::to_string),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "1".into(),
                    Some("a***@x.io".into()),
                    Some("****4242".into())
                ),
                ("2".into(), Some("p***".into()), Some("****0004".into())),
                ("3".into(), None, None),
            ]
        );
    })
    .await;
}

#[tokio::test]
async fn real_pg_extended_query_returns_masked_values() {
    with_real_pg(|via| async move {
        let c = connect(&via).await;
        // Unnamed statement with an inferred parameter type.
        let rows = c
            .query(
                "SELECT email, card, name FROM customers WHERE id >= $1 ORDER BY id LIMIT 10",
                &[&1i32],
            )
            .await
            .unwrap();
        assert_eq!(
            texts(&rows, 0),
            vec![Some("a***@x.io".into()), Some("p***".into()), None]
        );
        assert_eq!(
            texts(&rows, 1),
            vec![Some("****4242".into()), Some("****0004".into()), None]
        );
        assert_eq!(
            texts(&rows, 2),
            vec![Some("Ann".into()), Some("Bob".into()), Some("Cleo".into())]
        );
        // The masked column keeps its name.
        assert_eq!(rows[0].columns()[0].name(), "email");

        // Named statement with an explicit parameter type, executed twice.
        let stmt = c
            .prepare_typed(
                "SELECT card FROM customers WHERE id = $1",
                &[tokio_postgres::types::Type::INT4],
            )
            .await
            .unwrap();
        for (id, want) in [(1i32, "****4242"), (2, "****0004")] {
            let row = c.query_one(&stmt, &[&id]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), want);
        }
    })
    .await;
}

#[tokio::test]
async fn real_pg_block_and_flag() {
    with_real_pg(|via| async move {
        let c = connect(&via).await;
        let err = c
            .simple_query("SELECT ssn FROM customers LIMIT 1")
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
        );
        let err = c
            .query("SELECT ssn FROM customers WHERE id = $1", &[&1i32])
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
        );
        // The connection is still usable, and flag returns the value in clear.
        let row = c
            .query_one("SELECT phone FROM customers WHERE id = $1", &[&1i32])
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "555-0101");
    })
    .await;
}

// ── Real MySQL ───────────────────────────────────────────────────────────────

use mysql_async::prelude::Queryable;

/// URL of an admin connection (`mysql://user:pass@host:port`), or None to skip.
fn mysql_url() -> Option<String> {
    std::env::var("VERICTO_TEST_MYSQL_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A proxy fronting `upstream` on an ephemeral port; returns that port.
async fn spawn_mysql_proxy(cfg: Arc<PgProxyConfig>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(crate::tcp::session::handle_mysql_connection(
                sock,
                cfg.clone(),
            ));
        }
    });
    port
}

/// Driver options for a connection to the proxy on `port`. `prefer_socket` off:
/// otherwise the driver reconnects to the server's own unix socket and bypasses
/// the proxy.
fn via_proxy(
    admin: &mysql_async::Opts,
    port: u16,
    db: Option<&str>,
    tls: bool,
) -> mysql_async::Opts {
    mysql_async::OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .user(admin.user())
        .pass(admin.pass())
        .db_name(db)
        .prefer_socket(false)
        // The proxy's test certificate is not issued for 127.0.0.1.
        .ssl_opts(
            tls.then(|| mysql_async::SslOpts::default().with_danger_accept_invalid_certs(true)),
        )
        .into()
}

/// The proxy's client-side TLS acceptor when the upstream hop is TLS (MySQL
/// needs both hops or neither).
fn mysql_client_tls(
    tls: crate::tcp::upstream::UpstreamTlsMode,
) -> Option<tokio_rustls::TlsAcceptor> {
    if tls == crate::tcp::upstream::UpstreamTlsMode::Disable {
        return None;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is required with TLS"));
    Some(
        crate::tcp::client_tls::build_acceptor(
            &var("VERICTO_TEST_MYSQL_TLS_CERT"),
            &var("VERICTO_TEST_MYSQL_TLS_KEY"),
        )
        .expect("proxy certificate"),
    )
}

/// Runs `body` against a fresh database seeded with `customers`, reached
/// through a proxy with [`tags`] and the default rules. Seeding and cleanup go
/// through a second proxy with no tags and no rules (the upstream may require
/// TLS, which the test driver does not speak). The database is dropped
/// afterwards, also when `body` panics.
async fn with_real_mysql<F, Fut>(body: F)
where
    F: FnOnce(mysql_async::Opts) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = mysql_url() else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
        return;
    };
    // The upstream TLS hop needs a process-level provider (main.rs installs it).
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let admin = mysql_async::Opts::from_url(&url).expect("VERICTO_TEST_MYSQL_URL");
    let upstream = (admin.ip_or_hostname().to_string(), admin.tcp_port());
    let tls = crate::tcp::upstream::UpstreamTlsMode::from_env_str(
        &std::env::var("VERICTO_TEST_MYSQL_SSLMODE").unwrap_or_default(),
    );
    let (plain, _) = config_with(
        (&upstream.0, upstream.1),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        Vec::new(),
        tls,
    );
    let (tagged, _) = config_with(
        (&upstream.0, upstream.1),
        policy_with_tags(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        tls,
    );
    let acceptor = mysql_client_tls(tls);
    let client_tls = acceptor.is_some();
    let with_tls = |cfg: Arc<PgProxyConfig>| {
        let mut cfg = Arc::into_inner(cfg).expect("unshared config");
        cfg.client_tls_acceptor = acceptor.clone();
        Arc::new(cfg)
    };
    let admin_port = spawn_mysql_proxy(with_tls(plain)).await;
    let tagged_port = spawn_mysql_proxy(with_tls(tagged)).await;
    let db = format!(
        "vericto_proxy_pii_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    let mut conn = mysql_async::Conn::new(via_proxy(&admin, admin_port, None, client_tls))
        .await
        .expect("connect (admin, through an untagged proxy)");
    conn.query_drop(format!("CREATE DATABASE {db}"))
        .await
        .unwrap();
    let seed = [
        format!(
            "CREATE TABLE {db}.customers (id INT PRIMARY KEY, name VARCHAR(40), \
             email VARCHAR(80), card VARCHAR(20), ssn VARCHAR(11), phone VARCHAR(20))"
        ),
        format!(
            "INSERT INTO {db}.customers (id, name, email, card, ssn, phone) VALUES \
               (1, 'Ann',  'ann@example.io', '4111111111114242', '123-45-6789', '555-0101'), \
               (2, 'Bob',  'plainvalue',     '5500000000000004', '987-65-4321', '555-0102'), \
               (3, 'Cleo', NULL,             NULL,               NULL,          NULL)"
        ),
    ];
    let mut seeded = Ok(());
    for sql in seed {
        if let Err(e) = conn.query_drop(sql).await {
            seeded = Err(e);
            break;
        }
    }

    let result: Result<(), Box<dyn std::any::Any + Send>> = match seeded {
        Ok(()) => tokio::spawn(body(via_proxy(&admin, tagged_port, Some(&db), client_tls)))
            .await
            .map_err(|e| e.into_panic()),
        Err(e) => Err(Box::new(format!("seeding failed: {e}"))),
    };

    conn.query_drop(format!("DROP DATABASE IF EXISTS {db}"))
        .await
        .unwrap();
    conn.disconnect().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

type MaskedRow = (i64, Option<String>, Option<String>);

const EXPECTED_MASKED: [(i64, Option<&str>, Option<&str>); 3] = [
    (1, Some("a***@example.io"), Some("****4242")),
    (2, Some("p***"), Some("****0004")),
    (3, None, None),
];

fn expected_masked() -> Vec<MaskedRow> {
    EXPECTED_MASKED
        .iter()
        .map(|(i, e, c)| (*i, e.map(str::to_string), c.map(str::to_string)))
        .collect()
}

/// COM_QUERY (the text protocol).
#[tokio::test]
async fn real_mysql_text_query_returns_masked_values() {
    with_real_mysql(|opts| async move {
        let mut c = mysql_async::Conn::new(opts).await.unwrap();
        let rows: Vec<MaskedRow> = c
            .query("SELECT id, email, card FROM customers ORDER BY id LIMIT 10")
            .await
            .unwrap();
        assert_eq!(rows, expected_masked());
        c.disconnect().await.unwrap();
    })
    .await;
}

/// COM_STMT_PREPARE + COM_STMT_EXECUTE with a bound parameter (the binary
/// protocol), and a prepared statement executed twice.
#[tokio::test]
async fn real_mysql_prepared_statement_returns_masked_values() {
    with_real_mysql(|opts| async move {
        let mut c = mysql_async::Conn::new(opts).await.unwrap();
        let rows: Vec<MaskedRow> = c
            .exec(
                "SELECT id, email, card FROM customers WHERE id >= ? ORDER BY id LIMIT 10",
                (1,),
            )
            .await
            .unwrap();
        assert_eq!(rows, expected_masked());

        let stmt = c
            .prep("SELECT card, name FROM customers WHERE id = ?")
            .await
            .unwrap();
        assert_eq!(stmt.num_params(), 1, "the server's parameter count");
        assert_eq!(
            stmt.columns()[0].name_str(),
            "card",
            "the masked column keeps its name"
        );
        for (id, want) in [(1, "****4242"), (2, "****0004")] {
            let row: Option<(String, String)> = c.exec_first(&stmt, (id,)).await.unwrap();
            assert_eq!(row.unwrap().0, want);
        }
        c.disconnect().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn real_mysql_block_and_flag() {
    with_real_mysql(|opts| async move {
        let mut c = mysql_async::Conn::new(opts).await.unwrap();
        let code = |e: mysql_async::Error| match e {
            mysql_async::Error::Server(s) => (s.code, s.message),
            other => panic!("expected a server error, got {other}"),
        };
        for sql in [
            "SELECT ssn FROM customers LIMIT 1",
            "SELECT * FROM customers LIMIT 1",
        ] {
            let (n, msg) = code(c.query_drop(sql).await.unwrap_err());
            assert_eq!(n, 1142, "{msg}");
            assert!(msg.contains("VERICTO-085"), "{msg}");
            let (n, _) = code(
                c.exec_drop(format!("{sql} OFFSET ?").as_str(), (0,))
                    .await
                    .unwrap_err(),
            );
            assert_eq!(n, 1142);
        }
        // The connection is still usable, and flag returns the value in clear.
        let phone: Option<String> = c
            .exec_first("SELECT phone FROM customers WHERE id = ?", (1,))
            .await
            .unwrap();
        assert_eq!(phone.as_deref(), Some("555-0101"));
        c.disconnect().await.unwrap();
    })
    .await;
}
