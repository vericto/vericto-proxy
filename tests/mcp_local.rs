// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `vericto-proxy mcp` with and without a control plane, as the binary runs:
//!
//! * no control plane configured: the local mode starts on the built-in
//!   ruleset and `execute_sql`, `describe_schema`, `check_sql` and `whoami`
//!   work (against a real PostgreSQL when `VERICTO_TEST_PG_URL` is set);
//! * a configured control plane that is unreachable, or whose bundle fails the
//!   signature check, keeps the server `NOT_READY` (never the built-in rules);
//!   a correctly signed bundle makes it ready (the control case);
//! * a partial control-plane configuration is a startup error;
//! * HTTP without a control plane needs bearer tokens.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};

/// A loopback port nothing listens on, for an address that must be
/// unreachable (the fake database URL, the unreachable control plane).
///
/// The port is released before the caller uses it, so another process could
/// bind it in between; that is acceptable here, where the test only needs
/// the connection to fail (and a stray listener would not speak the protocol
/// either). Never use it for a port the code under test must bind: let it
/// bind `127.0.0.1:0` and read the bound address instead (see
/// [`http_listen_addr`]).
fn unused_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn private_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"));
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    c
}

/// One `vericto-proxy mcp` over stdio.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    stderr: Option<std::thread::JoinHandle<String>>,
    next_id: u64,
    /// The HOME of the process, removed with the session.
    _home: Option<tempfile::TempDir>,
}

impl Session {
    fn start(mut cmd: Command) -> Session {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut err = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Some(std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        }));
        Session {
            child,
            stdin,
            lines,
            stderr,
            next_id: 1,
            _home: None,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no answer to {method}"));
            let v: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout must carry JSON-RPC only, got {line:?}: {e}"));
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    fn initialize(&mut self) -> Value {
        let r = self.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude-code", "version": "2.1"}}),
        );
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        r
    }

    /// `structuredContent` of a tool call.
    fn call(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        r["result"]["structuredContent"].clone()
    }

    /// Closes stdin, waits for the exit, returns stderr.
    fn finish(mut self) -> String {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                assert!(s.success(), "{s:?}");
                break;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the process did not exit when stdin closed");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.stderr.take().unwrap().join().unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── A real database, when VERICTO_TEST_PG_URL is set ─────────────────────────

struct RealDb {
    admin: tokio_postgres::Config,
    db: String,
    role: String,
    url: String,
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

async fn connect(cfg: &tokio_postgres::Config) -> tokio_postgres::Client {
    let (c, conn) = cfg.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    c
}

impl RealDb {
    fn create() -> Option<RealDb> {
        let admin_url = std::env::var("VERICTO_TEST_PG_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        let admin: tokio_postgres::Config = admin_url.parse().expect("VERICTO_TEST_PG_URL");
        let host = match &admin.get_hosts()[0] {
            tokio_postgres::config::Host::Tcp(h) => h.clone(),
            #[allow(unreachable_patterns)]
            _ => panic!("VERICTO_TEST_PG_URL must use a TCP host"),
        };
        let port = admin.get_ports().first().copied().unwrap_or(5432);
        let suffix = uuid_suffix();
        let db = format!("vericto_local_{suffix}");
        let role = format!("vericto_local_ro_{suffix}");
        let pw = format!("ro-secret-{suffix}");
        block_on(async {
            let c = connect(&admin).await;
            c.batch_execute(&format!("CREATE DATABASE {db}"))
                .await
                .unwrap();
            c.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{pw}'"))
                .await
                .unwrap();
            let mut direct = admin.clone();
            direct.dbname(&db);
            let seed = connect(&direct).await;
            seed.batch_execute(&format!(
                "SET password_encryption = 'scram-sha-256';
                 ALTER ROLE {role} PASSWORD '{pw}';
                 CREATE SCHEMA app;
                 CREATE TABLE app.users (id int8 PRIMARY KEY, email text NOT NULL, active bool NOT NULL DEFAULT true);
                 CREATE TABLE app.orders (id int8 PRIMARY KEY, user_id int8 REFERENCES app.users(id), total numeric(10,2));
                 INSERT INTO app.users VALUES (1, 'ann@example.com', true), (2, 'bob@example.com', false);
                 INSERT INTO app.orders VALUES (10, 1, 12.30), (11, 2, 4.50);
                 GRANT USAGE ON SCHEMA app TO {role};
                 GRANT SELECT ON ALL TABLES IN SCHEMA app TO {role};"
            ))
            .await
            .unwrap();
        });
        let url = format!("postgres://{role}:{pw}@{host}:{port}/{db}");
        Some(RealDb {
            admin,
            db,
            role,
            url,
        })
    }

    fn count_users(&self) -> i64 {
        let mut direct = self.admin.clone();
        direct.dbname(&self.db);
        block_on(async {
            let c = connect(&direct).await;
            c.query_one("SELECT count(*) FROM app.users", &[])
                .await
                .unwrap()
                .get(0)
        })
    }
}

impl Drop for RealDb {
    fn drop(&mut self) {
        let (admin, db, role) = (self.admin.clone(), self.db.clone(), self.role.clone());
        block_on(async move {
            let c = connect(&admin).await;
            let _ = c
                .batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
                .await;
            let _ = c
                .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                .await;
        });
    }
}

/// A suffix for database and role names, unique per call: the clock and the
/// pid separate processes, the counter separates calls within this one.
/// Lowercase hex and `_` only, so it is a valid unquoted Postgres identifier.
fn uuid_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{:x}_{:x}_{seq:x}", n & 0xffff_ffff, std::process::id())
}

// ── The local mode ────────────────────────────────────────────────────────────

#[test]
fn without_a_control_plane_the_local_mode_runs_on_the_built_in_rules() {
    let Some(db) = RealDb::create() else {
        eprintln!(
            "VERICTO_TEST_PG_URL is not set: the local-mode test against a real database is skipped"
        );
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let url_file = private_file(home.path(), "db.url", &db.url);
    let mut cmd = bin();
    cmd.args([
        "mcp",
        "--database-url-file",
        url_file.to_str().unwrap(),
        "--search-path",
        "app",
    ])
    .env("HOME", home.path());
    let mut s = Session::start(cmd);

    let init = s.initialize();
    let instructions = init["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("built-in ruleset"), "{instructions}");
    assert_eq!(
        instructions.matches("A Vericto account adds").count(),
        1,
        "{instructions}"
    );
    let tools: Vec<String> = s.request("tools/list", json!({}))["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        tools,
        ["execute_sql", "describe_schema", "check_sql", "whoami"]
    );

    // whoami: the local mode, as the contract names it.
    let who = s.call("whoami", json!({}));
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/mcp-contract/whoami-execution.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for (k, v) in fixture["proxy_unlinked_control_plane"].as_object().unwrap() {
        assert_eq!(&who["control_plane"][k], v, "control_plane.{k}: {who}");
    }
    assert_eq!(who["execution"]["mode"], "proxy");
    assert_eq!(
        who["execution"]["warnings"],
        json!(["no_control_plane"]),
        "{who}"
    );
    assert_eq!(
        who["execution"]["databases"][0]["tiers"],
        json!({"read": "enabled", "write": "off", "delete": "off", "ddl": "off"})
    );
    assert!(who["identity"].is_null(), "{who}");
    assert!(who["kill_switch"].is_null(), "{who}");
    assert!(
        who["ruleset_version"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );

    // describe_schema: the tables the role can read.
    let schema = s.call("describe_schema", json!({"schema": "app"}));
    assert!(schema.get("error").is_none_or(Value::is_null), "{schema}");
    let tables: Vec<&str> = schema["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        tables.contains(&"users") && tables.contains(&"orders"),
        "{schema}"
    );

    // execute_sql: a read runs, exactly as evaluated.
    let sql = "SELECT id, email FROM users WHERE active = $1 ORDER BY id";
    let r = s.call("execute_sql", json!({"sql": sql, "params": [true]}));
    assert_eq!(r["status"], "EXECUTED", "{r}");
    assert_eq!(r["executed_sql"], sql);
    // int8 is a string (exact), as documented.
    assert_eq!(r["rows"], json!([["1", "ann@example.com"]]));
    assert!(r["event_id"].is_null(), "nothing is reported: {r}");
    // The built-in rules block, and nothing above read runs.
    let r = s.call("execute_sql", json!({"sql": "DROP TABLE users"}));
    assert_eq!(r["status"], "BLOCKED", "{r}");
    let r = s.call("execute_sql", json!({"sql": "DELETE FROM users"}));
    assert_ne!(r["status"], "EXECUTED", "{r}");
    let r = s.call(
        "execute_sql",
        json!({"sql": "UPDATE users SET active = false WHERE id = 1"}),
    );
    assert_eq!(r["error"]["code"], "TIER_NOT_ENABLED", "{r}");

    // check_sql: evaluated locally on the same rules.
    let c = s.call(
        "check_sql",
        json!({"sql": "SELECT id FROM users WHERE id = 1;\nDELETE FROM users;"}),
    );
    assert_eq!(c["summary"]["total"], 2, "{c}");
    assert_eq!(c["passed"], false, "{c}");
    assert_eq!(c["ruleset_version"], who["ruleset_version"], "{c}");

    let err = s.finish();
    assert!(err.contains("Local mode"), "{err}");
    assert!(
        !err.contains("Control-plane link enabled"),
        "no link in the local mode: {err}"
    );
    assert!(!err.contains("ro-secret-"), "no credential is logged");
    assert_eq!(db.count_users(), 2, "nothing was written");
}

#[test]
fn operator_guard_reaches_both_mcp_tool_outcomes_before_database_io() {
    let home = tempfile::tempdir().unwrap();
    let url = format!(
        "postgres://u:p@127.0.0.1:{}/db?sslmode=disable",
        unused_port()
    );
    let url_file = private_file(home.path(), "db.url", &url);
    let mut cmd = bin();
    cmd.args(["mcp", "--database-url-file", url_file.to_str().unwrap()])
        .env("HOME", home.path())
        .env("VERICTO_MAX_BINARY_OPERATORS", "2");
    let mut s = Session::start(cmd);
    s.initialize();

    let sql = "SELECT 1+1+1+1";
    let checked = s.call("check_sql", json!({"sql": sql, "verbose": true}));
    assert_eq!(checked["summary"]["parse_errors"], 1, "{checked}");
    assert_eq!(
        checked["queries"][0]["verdict"]["status"], "PARSE_ERROR",
        "{checked}"
    );
    assert!(
        checked["queries"][0]["verdict"]["ast_node_path"]
            .as_str()
            .is_some_and(|p| p.contains("VERICTO_MAX_BINARY_OPERATORS")),
        "{checked}"
    );

    let executed = s.call("execute_sql", json!({"sql": sql}));
    assert_eq!(executed["status"], "BLOCKED", "{executed}");
    assert_eq!(executed["error"]["code"], "BLOCKED", "{executed}");
    assert_eq!(executed["verdict"]["status"], "PARSE_ERROR", "{executed}");
    assert!(
        executed["event_id"].is_null(),
        "local mode reports nothing: {executed}"
    );

    let err = s.finish();
    assert!(err.contains("Local mode"), "{err}");
}

// ── A configured control plane never falls back ──────────────────────────────

/// A stand-in control plane on loopback: `/api/v1/sync/rules` answers `body`
/// with `signature` (when set); everything else `{}`. Counts the syncs.
fn fake_control_plane(body: String, signature: Option<String>) -> (u16, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let syncs = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&syncs);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&req).to_string();
            let is_sync = head.starts_with("GET /api/v1/sync/rules");
            let (payload, extra) = if is_sync {
                seen.fetch_add(1, Ordering::SeqCst);
                let sig = signature
                    .as_ref()
                    .map(|s| format!("X-Vericto-Bundle-Signature: {s}\r\n"))
                    .unwrap_or_default();
                (body.clone(), format!("ETag: \"v-local-test\"\r\n{sig}"))
            } else {
                ("{}".to_string(), String::new())
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, syncs)
}

fn signer() -> ring::signature::Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn signature_header(key: &ring::signature::Ed25519KeyPair, key_id: &str, body: &str) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"vericto-sync-bundle/1\n");
    ctx.update(body.as_bytes());
    let digest = ctx.finish();
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let sig = key.sign(digest.as_ref());
    format!(
        "scheme=ed25519-sha256; key-id={key_id}; sha256={hex}; sig={}",
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
    )
}

fn linked_session(api_port: u16, trusted: &ring::signature::Ed25519KeyPair) -> Session {
    use ring::signature::KeyPair as _;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let url = std::env::var("VERICTO_TEST_PG_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("postgres://agent:pw@127.0.0.1:{}/shop", unused_port()));
    let url_file = private_file(&home, "db.url", &url);
    let keys = json!([{
        "key_id": "k-local-test",
        "public_key": base64::engine::general_purpose::STANDARD.encode(trusted.public_key().as_ref()),
    }])
    .to_string();
    let mut cmd = bin();
    cmd.args(["mcp", "--database-url-file", url_file.to_str().unwrap()])
        .env("HOME", &home)
        .env("VERICTO_API_URL", format!("http://127.0.0.1:{api_port}"))
        .env("VERICTO_API_KEY", "vtro_local_test_key_not_a_secret")
        .env(
            "VERICTO_DATABASE_ID",
            "00000000-0000-4000-8000-000000000001",
        )
        .env("VERICTO_BUNDLE_SIGNING_KEYS", keys)
        .env("VERICTO_RULES_CACHE_PATH", home.join("rules-cache.json"));
    let mut s = Session::start(cmd);
    s._home = Some(dir);
    s
}

const BUNDLE: &str = r#"{"version":"v-local-test","rules":[],"mcp":{"version":"1","mode":"proxy","tiers":{"read":"enabled","write":"off","delete":"off","ddl":"off"}},"mcp_write_tiers_allowed":false}"#;

fn assert_not_ready(s: &mut Session) {
    let r = s.call("execute_sql", json!({"sql": "SELECT 1"}));
    assert_eq!(r["error"]["code"], "NOT_READY", "{r}");
    let r = s.call("describe_schema", json!({}));
    assert_eq!(r["error"]["code"], "NOT_READY", "{r}");
    let who = s.call("whoami", json!({}));
    assert_eq!(who["control_plane"]["mode"], "linked", "{who}");
    assert_eq!(who["control_plane"]["ruleset"], "none", "{who}");
    assert!(
        !who["execution"]["warnings"]
            .as_array()
            .unwrap()
            .contains(&json!("no_control_plane")),
        "{who}"
    );
}

#[test]
fn a_configured_but_unreachable_control_plane_stays_not_ready() {
    let key = signer();
    // Nothing listens on the port.
    let mut s = linked_session(unused_port(), &key);
    let init = s.initialize();
    assert!(
        !init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("A Vericto account adds")
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_not_ready(&mut s);
    let err = s.finish();
    assert!(!err.contains("Local mode"), "{err}");
}

#[test]
fn a_bundle_that_fails_the_signature_check_stays_not_ready() {
    let trusted = signer();
    let other = signer();
    // Signed by a key the proxy does not trust, under the trusted key's id.
    let (port, syncs) = fake_control_plane(
        BUNDLE.to_string(),
        Some(signature_header(&other, "k-local-test", BUNDLE)),
    );
    let mut s = linked_session(port, &trusted);
    s.initialize();
    let deadline = Instant::now() + Duration::from_secs(20);
    while syncs.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the proxy never synced");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_not_ready(&mut s);
    // And an unsigned one.
    drop(s);
    let (port, syncs) = fake_control_plane(BUNDLE.to_string(), None);
    let mut s = linked_session(port, &trusted);
    s.initialize();
    let deadline = Instant::now() + Duration::from_secs(20);
    while syncs.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the proxy never synced");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_not_ready(&mut s);
}

#[test]
fn a_correctly_signed_bundle_makes_the_server_ready() {
    // The control case of the two above: the same harness, a good signature.
    let trusted = signer();
    let (port, _) = fake_control_plane(
        BUNDLE.to_string(),
        Some(signature_header(&trusted, "k-local-test", BUNDLE)),
    );
    let mut s = linked_session(port, &trusted);
    s.initialize();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let who = s.call("whoami", json!({}));
        if who["control_plane"]["ruleset"] == "signed_bundle" {
            assert_eq!(who["ruleset_version"], "v-local-test", "{who}");
            break;
        }
        assert!(Instant::now() < deadline, "never ready: {who}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let r = s.call("execute_sql", json!({"sql": "SELECT 1 AS one"}));
    assert_ne!(r["error"]["code"], "NOT_READY", "{r}");
}

// ── Startup errors ────────────────────────────────────────────────────────────

fn startup_error(args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = bin();
    cmd.arg("mcp").args(args);
    cmd.env("VERICTO_MCP_DATABASE_URL", "postgres://u:p@127.0.0.1:1/db");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    assert!(!out.status.success(), "{args:?} {env:?} must not start");
    assert!(out.stdout.is_empty(), "nothing on stdout");
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn a_partial_control_plane_is_a_startup_error() {
    let e = startup_error(
        &[],
        &[(
            "VERICTO_DATABASE_ID",
            "00000000-0000-4000-8000-000000000001",
        )],
    );
    assert!(
        e.contains("VERICTO_DATABASE_ID is set but VERICTO_API_KEY is not"),
        "{e}"
    );
    let e = startup_error(&["--database-id", "db-1"], &[]);
    assert!(e.contains("VERICTO_API_KEY is not"), "{e}");
    let e = startup_error(&[], &[("VERICTO_API_URL", "https://api.vericto.com")]);
    assert!(
        e.contains("VERICTO_API_URL is set but VERICTO_API_KEY is not"),
        "{e}"
    );
    let e = startup_error(
        &[],
        &[
            ("VERICTO_API_KEY", "vtro_local_test_key_not_a_secret"),
            ("VERICTO_API_URL", ""),
        ],
    );
    assert!(e.contains("VERICTO_API_URL is empty"), "{e}");
    let e = startup_error(&["--require-control-plane"], &[]);
    assert!(e.contains("VERICTO_MCP_REQUIRE_CONTROL_PLANE=true"), "{e}");
}

#[test]
fn http_without_a_control_plane_requires_a_bearer_token() {
    let e = startup_error(&["--transport", "http"], &[]);
    assert!(e.contains("VERICTO_MCP_AUTH_TOKENS_FILE"), "{e}");
    assert!(e.contains("never served unauthenticated"), "{e}");
    let dir = tempfile::tempdir().unwrap();
    let empty = private_file(dir.path(), "empty.tokens", "# no token yet\n");
    let e = startup_error(
        &[
            "--transport",
            "http",
            "--auth-tokens-file",
            empty.to_str().unwrap(),
        ],
        &[],
    );
    assert!(e.contains("VERICTO_MCP_AUTH_TOKENS_FILE"), "{e}");

    // With a tokens file it serves, and only to a holder of a token.
    let token = "local-mcp-token-0123456789abcdef-test";
    let tokens = private_file(dir.path(), "mcp.tokens", &format!("{token} laptop\n"));
    // The proxy binds port 0 itself and logs the address it got, so no port
    // is picked before the bind (no race with another process).
    let mut child = bin()
        .args([
            "mcp",
            "--transport",
            "http",
            "--listen",
            "127.0.0.1:0",
            "--auth-tokens-file",
            tokens.to_str().unwrap(),
        ])
        .env("VERICTO_MCP_DATABASE_URL", "postgres://u:p@127.0.0.1:1/db")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let addr = http_listen_addr(&mut child);
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}});
    let result = block_on(async {
        let client = reqwest::Client::new();
        let post = |auth: Option<&str>| {
            let mut r = client
                .post(format!("http://{addr}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .json(&init);
            if let Some(a) = auth {
                r = r.bearer_auth(a);
            }
            r.send()
        };
        // The address is logged after the bind: the listener is up.
        let anonymous = post(None).await.unwrap().status().as_u16();
        let with_token = post(Some(token)).await.unwrap();
        let status = with_token.status().as_u16();
        let body: Value = with_token.json().await.unwrap();
        (anonymous, status, body)
    });
    let _ = child.kill();
    let _ = child.wait();
    let (anonymous, status, body) = result;
    assert_eq!(anonymous, 401, "never served unauthenticated");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "vericto-proxy");
}

/// The address the HTTP listener of `child` bound, from its startup log line
/// (`MCP Streamable HTTP listening on /mcp`, JSON on stderr). The rest of
/// stderr keeps being drained so the child never blocks on a full pipe.
fn http_listen_addr(child: &mut Child) -> std::net::SocketAddr {
    let stderr = BufReader::new(child.stderr.take().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in stderr.lines() {
            let Ok(line) = line else { break };
            let Some(t) = tx.as_ref() else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if v["fields"]["message"] == "MCP Streamable HTTP listening on /mcp" {
                let _ = t.send(v["fields"]["listen"].as_str().unwrap_or("").to_string());
                tx = None;
            }
        }
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the HTTP listener never logged its address");
    let addr: std::net::SocketAddr = addr
        .parse()
        .unwrap_or_else(|e| panic!("listen={addr:?} is not an address: {e}"));
    assert!(addr.ip().is_loopback() && addr.port() != 0, "{addr}");
    addr
}
