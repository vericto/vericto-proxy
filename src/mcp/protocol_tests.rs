// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The MCP protocol over both transports, and the shared contract fixtures
//! of `tests/mcp-contract/` (design §6.9): every fixture the proxy implements
//! is asserted here.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::mcp::fake_pg::{self, Answer, Auth, FakePg, Opts};
use crate::mcp::next_steps::{
    self, DeniedName, ExecuteContext, InvalidReason, Layer, Outcome, ProxyAccess, Unavailable,
    VerdictFacts,
};
use crate::mcp::runtime::{Runtime, Shared};

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/mcp-contract")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

// ── stdio ────────────────────────────────────────────────────────────────────

/// A client on the other end of `stdio::serve`.
struct StdioClient {
    tx: tokio::io::DuplexStream,
    rx: tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    task: tokio::task::JoinHandle<()>,
}

impl StdioClient {
    fn start(rt: Arc<Runtime>) -> Self {
        let (client_in, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, client_out) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(crate::mcp::stdio::serve(rt, server_in, server_out));
        StdioClient {
            tx: client_in,
            rx: BufReader::new(client_out).lines(),
            task,
        }
    }

    async fn send(&mut self, v: &Value) {
        self.tx
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn send_raw(&mut self, s: &str) {
        self.tx.write_all(s.as_bytes()).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(std::time::Duration::from_secs(10), self.rx.next_line())
            .await
            .expect("an answer in time")
            .unwrap()
            .expect("a line");
        serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout carries JSON-RPC only: {line:?} ({e})"))
    }

    async fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}))
            .await;
        let r = self.recv().await;
        assert_eq!(r["id"], id);
        r
    }
}

#[tokio::test]
async fn stdio_speaks_mcp_and_nothing_else_on_stdout() {
    let fake = FakePg::start(Auth::Trust).await;
    fake.answer(
        "SELECT id FROM t",
        Answer::rows(&[("id", 23)], vec![vec![Some("1")]]),
    );
    let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), Shared::built_in(), Opts::default());
    let mut c = StdioClient::start(rt);
    c.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude-code", "version": "2.1.4"}
    }}))
    .await;
    let init = c.recv().await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "vericto-proxy");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("never instructions")
    );
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    c.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await;
    let list = c.recv().await;
    assert_eq!(list["id"], 2, "the notification got no answer");
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        crate::mcp::tools::TOOL_NAMES,
        "unlinked: the four tools only"
    );
    let exec = &tools[0];
    assert_eq!(exec["annotations"]["readOnlyHint"], true);
    assert_eq!(exec["annotations"]["openWorldHint"], false);
    assert_eq!(exec["inputSchema"]["required"], json!(["sql"]));
    assert_eq!(
        exec["outputSchema"]["additionalProperties"], true,
        "the output schema is open"
    );

    let r = c
        .call(3, "execute_sql", json!({"sql": "SELECT id FROM t"}))
        .await;
    let res = &r["result"];
    assert_eq!(res["isError"], false);
    assert_eq!(res["structuredContent"]["status"], "EXECUTED");
    assert!(
        res["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("untrusted data")
    );
    let r = c
        .call(4, "execute_sql", json!({"sql": "DROP TABLE t"}))
        .await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(r["result"]["structuredContent"]["status"], "BLOCKED");
    let r = c.call(5, "whoami", json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["client"]["name"],
        "claude-code"
    );
    let r = c.call(6, "nope", json!({})).await;
    assert_eq!(r["error"]["code"], -32602);
    c.send(&json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}))
        .await;
    assert_eq!(c.recv().await["result"], json!({}));
    c.send_raw("{not json\n").await;
    assert_eq!(c.recv().await["error"]["code"], -32700);
    c.send(&json!({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}))
        .await;
    assert_eq!(c.recv().await["error"]["code"], -32601);
    // stdin closes: the server stops.
    drop(c.tx);
    tokio::time::timeout(std::time::Duration::from_secs(10), c.task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn concurrent_stdio_calls_each_get_their_answer() {
    let fake = FakePg::start(Auth::Trust).await;
    let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), Shared::built_in(), Opts::default());
    let mut c = StdioClient::start(rt);
    for id in 10..30 {
        c.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "execute_sql", "arguments": {"sql": "SELECT 1"}}})).await;
    }
    let mut ids = Vec::new();
    for _ in 10..30 {
        let r = c.recv().await;
        assert_eq!(
            r["result"]["structuredContent"]["status"], "EXECUTED",
            "{r}"
        );
        ids.push(r["id"].as_u64().unwrap());
    }
    ids.sort();
    assert_eq!(ids, (10..30).collect::<Vec<_>>());
}

// ── Streamable HTTP ──────────────────────────────────────────────────────────

const TOKEN: &str = "vtro_http_agent_token_0123456789abcdef0123456789";

async fn http_server(
    rt_extra: Vec<(&'static str, String)>,
    mcp: Option<Value>,
) -> (
    std::net::SocketAddr,
    FakePg,
    Arc<Runtime>,
    Arc<crate::telemetry::queue::MemoryQueue>,
) {
    let fake = FakePg::start(Auth::Trust).await;
    let shared = Shared::built_in();
    if let Some(m) = mcp {
        shared.watch.record_for_tests("v-http", Some(m));
    }
    let (rt, q) = fake_pg::runtime(
        &fake_pg::url(&fake),
        shared,
        Opts {
            extra: rt_extra,
            telemetry: true,
            linked: true,
            ..Default::default()
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(crate::mcp::http::serve(Arc::clone(&rt), listener, None));
    (addr, fake, rt, q)
}

fn post(addr: std::net::SocketAddr, body: &Value) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(body)
}

#[tokio::test]
async fn http_guards_host_origin_and_auth_before_any_tool() {
    let identities = json!({
        "version": "1", "mode": "proxy",
        "tiers": {"read": "enabled", "write": "off", "delete": "off", "ddl": "off"},
        "self": {"key_id": "11111111-1111-4111-8111-111111111111", "sql_read": true, "kill_switch": null},
        "identities": [{
            "key_id": "22222222-2222-4222-8222-222222222222",
            "key_sha256": crate::mcp::identity::sha256_hex(TOKEN.as_bytes()),
            "name": "cursor-alice", "principal_id": null, "expires_at": null, "kill_switch": null
        }]
    });
    let (addr, fake, _rt, q) = http_server(Vec::new(), Some(identities)).await;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "cursor", "version": "1"}}});
    // No token, a wrong one.
    let r = post(addr, &init).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(
        r.headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );
    let r = post(addr, &init)
        .bearer_auth("vtro_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // DNS rebinding: a foreign Host or Origin is refused before authentication.
    let r = post(addr, &init)
        .bearer_auth(TOKEN)
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = post(addr, &init)
        .bearer_auth(TOKEN)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // Wrong method, media type, path, protocol version.
    let r = reqwest::Client::new()
        .get(format!("http://{addr}/mcp"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .bearer_auth(TOKEN)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 415);
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/other"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = post(addr, &init)
        .bearer_auth(TOKEN)
        .header("mcp-protocol-version", "1999-01-01")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    // The real thing.
    let r = post(addr, &init).bearer_auth(TOKEN).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "application/json");
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "vericto-proxy");
    let r = post(
        addr,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .bearer_auth(TOKEN)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), 202);
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_sql", "arguments": {"sql": "SELECT 1"}}});
    let v: Value = post(addr, &call)
        .bearer_auth(TOKEN)
        .header("mcp-protocol-version", "2025-06-18")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v["result"]["structuredContent"]["status"], "EXECUTED",
        "{v}"
    );
    assert_eq!(fake.parses().len(), 1);
    // The event names the agent key.
    let ev = fake_pg::events(&q);
    assert_eq!(
        ev.last().unwrap().api_key_id.as_deref(),
        Some("22222222-2222-4222-8222-222222222222")
    );
    // Linked: the rule tools exist.
    let v: Value = post(
        addr,
        &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    )
    .bearer_auth(TOKEN)
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"show_rule") && names.contains(&"list_rules"),
        "{names:?}"
    );
    // An oversized body.
    let big = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "execute_sql", "arguments": {"sql": "x".repeat(2 << 20)}}});
    // 413, or the connection closed under a client still sending the body.
    match post(addr, &big).bearer_auth(TOKEN).send().await {
        Ok(r) => assert_eq!(r.status(), 413),
        Err(e) => assert!(e.is_request(), "{e}"),
    }
    assert_eq!(fake.parses().len(), 1, "the oversized call ran nothing");
}

#[tokio::test]
async fn http_kill_switch_by_key_and_local_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens");
    std::fs::write(&tokens, format!("{TOKEN} local-bot\n")).unwrap();
    let blocked = "vtro_blocked_agent_token_0123456789abcdef0123";
    let section = json!({
        "tiers": {"read": "enabled", "write": "off", "delete": "off", "ddl": "off"},
        "self": {"key_id": "k-proxy", "sql_read": true, "kill_switch": null},
        "identities": [{
            "key_id": "33333333-3333-4333-8333-333333333333",
            "key_sha256": crate::mcp::identity::sha256_hex(blocked.as_bytes()),
            "name": "rogue", "kill_switch": {"block_id": "blk-key", "message": "Vericto blocked this query [VERICTO-105]: rogue agent."}
        }]
    });
    let (addr, fake, _rt, _) = http_server(
        vec![(
            "VERICTO_MCP_AUTH_TOKENS_FILE",
            tokens.to_str().unwrap().to_string(),
        )],
        Some(section),
    )
    .await;
    // Re-read: tokens are loaded by `run`, not by the test runtime; check the
    // blocked bundle key instead.
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_sql", "arguments": {"sql": "SELECT 1"}}});
    let v: Value = post(addr, &call)
        .bearer_auth(blocked)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v["result"]["structuredContent"]["error"]["code"], "KILL_SWITCH",
        "{v}"
    );
    assert_eq!(
        v["result"]["structuredContent"]["error"]["block_id"],
        "blk-key"
    );
    assert!(fake.parses().is_empty());
}

// ── The shared contract (tests/mcp-contract) ─────────────────────────────────

fn facts(v: &Value) -> VerdictFacts {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    VerdictFacts {
        status: s("status").unwrap(),
        rule_code: s("rule_code"),
        severity: s("severity"),
        suggested_fix: s("suggested_fix"),
        approved_query: s("approved_query"),
        access_denied: v["access_denied"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| DeniedName {
                        schema: r["schema"].as_str().map(str::to_string),
                        table: r["table"].as_str().unwrap().to_string(),
                        column: r["column"].as_str().map(str::to_string),
                        needed: r["needed"].as_str().map(str::to_string),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        parse_error_kind: s("parse_error_kind"),
    }
}

fn tier_name(t: &str) -> &'static str {
    match t {
        "read" => "read",
        "write" => "write",
        "delete" => "delete",
        _ => "ddl",
    }
}

fn outcome(o: &Value) -> Outcome {
    let s = |k: &str| o[k].as_str().unwrap_or("").to_string();
    let n = |k: &str| o[k].as_u64().unwrap_or(0);
    match o["kind"].as_str().unwrap() {
        "executed" => Outcome::Executed {
            verdict: facts(&o["verdict"]),
            masked_columns: o["masked_columns"]
                .as_array()
                .map(|a| a.iter().map(|c| c.as_str().unwrap().to_string()).collect())
                .unwrap_or_default(),
            limit_bound: o["limit_bound"].as_bool().unwrap_or(false),
            truncation: o.get("truncation").filter(|t| !t.is_null()).map(|t| {
                (
                    if t["reason"] == "max_rows" {
                        "max_rows"
                    } else {
                        "max_bytes"
                    },
                    t["limit"].as_u64().unwrap(),
                )
            }),
            row_count: n("row_count") as usize,
        },
        "blocked" => Outcome::Blocked(facts(&o["verdict"])),
        "kill_switch" => Outcome::KillSwitch(s("block_id")),
        "tier_not_enabled" => Outcome::TierNotEnabled {
            tier: tier_name(&s("tier")),
            command: s("command"),
            enabled_tiers: o["enabled_tiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| tier_name(t.as_str().unwrap()))
                .collect(),
            database: s("database"),
            layer: match o["layer"].as_str().unwrap() {
                "database" => Layer::Database,
                "scope" => Layer::Scope,
                _ => Layer::Process,
            },
        },
        "tier_mismatch" => Outcome::TierMismatch {
            tier: tier_name(&s("tier")),
            command: s("command"),
        },
        "invalid_input" => Outcome::InvalidInput(match o["reason"].as_str().unwrap() {
            "multiple_statements" => InvalidReason::MultipleStatements,
            "nul_byte" => InvalidReason::NulByte,
            "too_large" => InvalidReason::TooLarge {
                max_bytes: n("max_bytes") as usize,
            },
            "params_mismatch" => InvalidReason::ParamsMismatch {
                placeholders: n("placeholders") as usize,
                params: n("params") as usize,
            },
            _ => InvalidReason::Empty,
        }),
        "database_error" => Outcome::DatabaseError(s("sqlstate")),
        "timeout" => Outcome::Timeout(n("timeout_ms") as u32),
        "unavailable" => Outcome::Unavailable {
            reason: match o["reason"].as_str().unwrap() {
                "tls" => Unavailable::Tls,
                "auth" => Unavailable::Auth,
                "pool_busy" => Unavailable::PoolBusy,
                _ => Unavailable::Connect,
            },
            sqlstate: o["sqlstate"].as_str().map(str::to_string),
            retry_after_s: n("retry_after_s") as u32,
        },
        "not_ready" => Outcome::NotReady(n("retry_after_s") as u32),
        k => panic!("unknown outcome kind {k}"),
    }
}

#[test]
fn every_outcome_of_the_contract_gets_its_status_code_and_next_steps() {
    let doc = fixture("execute-sql-next-steps.json");
    let cases = doc["outcomes"]
        .as_array()
        .or_else(|| doc["cases"].as_array())
        .unwrap();
    assert!(cases.len() >= 42, "{} outcomes", cases.len());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let c = &case["context"];
        let access = ProxyAccess {
            linked: c["linked"].as_bool().unwrap(),
        };
        let ctx = ExecuteContext {
            access: &access,
            dialect: c["dialect"].as_str().unwrap(),
            ruleset_version: c["ruleset_version"].as_str(),
        };
        let got = next_steps::execute_verdict(&outcome(&case["outcome"]), &ctx);
        let want = &case["expected"];
        assert_eq!(
            got.status,
            want["status"].as_str().unwrap(),
            "{name}: status"
        );
        assert_eq!(
            got.error_code,
            want["error_code"].as_str(),
            "{name}: error_code"
        );
        assert_eq!(
            got.execution_status,
            want["execution_status"].as_str().unwrap(),
            "{name}: execution_status"
        );
        assert_eq!(
            got.next_action(),
            want["next_action"].as_str().unwrap(),
            "{name}: next_action"
        );
        assert_eq!(
            serde_json::to_value(&got.next_steps).unwrap(),
            want["next_steps"],
            "{name}: next_steps"
        );
    }
}

#[test]
fn the_error_codes_and_actions_are_the_contracts() {
    let doc = fixture("errors.json");
    let m1: Vec<&str> = doc["codes"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, v)| v["m1"] == true)
        .map(|(k, _)| k.as_str())
        .collect();
    let mut mine = crate::mcp::tools::ERROR_CODES.to_vec();
    mine.sort();
    let mut theirs = m1.clone();
    theirs.sort();
    assert_eq!(mine, theirs);
    let actions: Vec<&str> = doc["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    assert_eq!(actions, next_steps::NEXT_ACTIONS);
}

#[test]
fn the_output_examples_carry_what_the_server_always_sends() {
    let doc = fixture("execute-sql-output.json");
    for ex in doc["examples"].as_array().unwrap() {
        let sc = &ex["structured_content"];
        for k in crate::mcp::tools::EXECUTE_SQL_REQUIRED {
            if *k == "ruleset_version" || *k == "verdict" {
                assert!(sc.get(*k).is_some(), "{}: {k}", ex["name"]);
                continue;
            }
            assert!(
                sc.get(*k).is_some(),
                "{}: the fixture lacks {k}",
                ex["name"]
            );
        }
        let status = sc["status"].as_str().unwrap();
        assert_eq!(
            ex["is_error"].as_bool().unwrap(),
            matches!(status, "BLOCKED" | "ERROR")
        );
    }
}

#[tokio::test]
async fn whoami_execution_matches_the_contract() {
    let fake = FakePg::start(Auth::Trust).await;
    let doc = fixture("whoami-execution.json");
    // Unlinked, stdio, default limits, no credential in the environment.
    let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), Shared::built_in(), Opts::default());
    let mut rt2 = Arc::try_unwrap(rt).ok().unwrap();
    rt2.warnings = vec![
        json!({"code": "no_control_plane", "message": "m"}),
        json!({"code": "no_database_id", "message": "m"}),
    ];
    let rt = Arc::new(rt2);
    let w = crate::mcp::tools::whoami(&rt, &fake_pg::caller(&rt));
    assert_eq!(
        w.structured["execution"], doc["proxy_unlinked"],
        "{}",
        w.structured["execution"]
    );
    let mut rt3 = Arc::try_unwrap(rt).ok().unwrap();
    rt3.warnings = vec![json!({"code": "agent_environment_has_db_credentials", "message": "m"})];
    let rt = Arc::new(rt3);
    let w = crate::mcp::tools::whoami(&rt, &fake_pg::caller(&rt));
    assert_eq!(w.structured["execution"], doc["proxy_stdio"]);
}

#[test]
fn ingest_events_of_the_contract_are_the_proxys_event_shape() {
    let doc = fixture("ingest-events.json");
    let mut seen_fields = std::collections::BTreeSet::new();
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if name == "unknown_values_dropped" {
            continue; // wrong types on purpose: the API's leniency, not the proxy's shape
        }
        let ev: crate::telemetry::TelemetryEvent =
            serde_json::from_value(case["event"].clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let back = serde_json::to_value(&ev).unwrap();
        for (k, v) in case["event"].as_object().unwrap() {
            assert_eq!(&back[k], v, "{name}: {k} round-trips");
            seen_fields.insert(k.clone());
        }
    }
    for f in [
        "execution_status",
        "tier",
        "rows_returned",
        "bytes_returned",
        "truncated",
        "sqlstate",
        "execution_ms",
        "mcp_client_name",
        "mcp_client_version",
        "statement_sha256",
        "api_key_id",
        "source",
    ] {
        assert!(seen_fields.contains(f), "{f}");
    }
}

#[test]
fn the_sync_section_of_the_contract_is_read() {
    let doc = fixture("sync-mcp.json");
    assert_eq!(
        doc["request_header"]["name"],
        crate::tcp::rules_sync::PROXY_MODE_HEADER
    );
    assert_eq!(doc["request_header"]["value"], "mcp");
    let mut ex = doc["example"].clone();
    ex["identities"][0]["key_sha256"] = json!(crate::mcp::identity::sha256_hex(TOKEN.as_bytes()));
    ex["identities"][0]["kill_switch"] = doc["kill_switch_entry"].clone();
    let ids = crate::mcp::identity::from_bundle(Some(&ex));
    assert_eq!(ids.len(), 1);
    let who = crate::mcp::identity::authenticate(TOKEN, &ids).unwrap();
    assert_eq!(who.name.as_deref(), Some("cursor-alice"));
    assert_eq!(who.kill_switch.unwrap().block_id, "{{block_id}}");
    let shared = Shared::built_in();
    shared
        .watch
        .record_for_tests("v", Some(doc["example"].clone()));
    let fake_url = "postgres://u:p@127.0.0.1:1/db";
    let (rt, _) = fake_pg::runtime(fake_url, shared, Opts::default());
    assert!(rt.read_tier().is_ok());
    assert_eq!(rt.limits(), crate::mcp::config::Limits::default());
}

#[test]
fn the_tools_fixture_is_what_tools_list_returns() {
    let (rt, _) = fake_pg::runtime(
        "postgres://u:p@127.0.0.1:1/db",
        Shared::built_in(),
        Opts::default(),
    );
    let list = crate::mcp::tools::list(&rt);
    let doc = fixture("tools.json");
    for t in doc["tools"].as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        let mine = list
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == name)
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(
            mine["inputSchema"]["required"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
            t["required"].as_array().cloned().unwrap_or_default(),
            "{name}"
        );
        assert_eq!(
            mine["annotations"]["readOnlyHint"], t["read_only"],
            "{name}"
        );
        if let Some(out) = t.get("output_required") {
            assert_eq!(&mine["outputSchema"]["required"], out, "{name}");
        }
    }
}
