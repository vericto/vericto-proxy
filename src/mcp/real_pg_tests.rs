// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `vericto-proxy mcp` against a real PostgreSQL (run when
//! `VERICTO_TEST_PG_URL` is set to an admin URL, e.g. Docker
//! `postgres:16`/`17`/`18`): SCRAM login of a dedicated read-only role,
//! reads and their types, masks, read-only enforced twice, timeouts, error
//! sanitization, the kill switch cancelling a running statement,
//! `describe_schema` and the local `check_sql`. Each test gets a fresh
//! database and role, dropped afterwards.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::mcp::fake_pg::{self, Opts};
use crate::mcp::runtime::{Runtime, Shared};

struct RealDb {
    admin: tokio_postgres::Config,
    db: String,
    role: String,
    url: String,
}

impl RealDb {
    async fn create() -> Option<RealDb> {
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
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let db = format!("vericto_mcp_{suffix}");
        let role = format!("vericto_mcp_ro_{suffix}");
        let c = connect(&admin).await;
        c.batch_execute(&format!("CREATE DATABASE {db}"))
            .await
            .unwrap();
        c.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'ro-secret-{suffix}'"
        ))
        .await
        .unwrap();
        let mut direct = admin.clone();
        direct.dbname(&db);
        let seed = connect(&direct).await;
        seed.batch_execute(&format!(
            "SET password_encryption = 'scram-sha-256';
             ALTER ROLE {role} PASSWORD 'ro-secret-{suffix}';
             CREATE SCHEMA app;
             CREATE TABLE app.users (id int8 PRIMARY KEY, email text, ssn text, active bool NOT NULL DEFAULT true);
             CREATE TABLE app.orders (
                id int8 PRIMARY KEY, user_id int8 REFERENCES app.users(id), total numeric(10,2),
                created_at timestamptz, tags text[], meta jsonb, blob bytea, ratio float8, n int4);
             CREATE TABLE app.audit_log (n int);
             INSERT INTO app.users VALUES (1, 'ann@example.com', '123-45-6789', true), (2, 'bob@example.com', '987-65-4321', false);
             INSERT INTO app.orders VALUES
               (10, 1, 12.30, '2026-10-30 12:00:00+00', ARRAY['a','b,c'], '{{\"k\": [1, 2]}}', '\\x00ff', 0.5, 7),
               (11, 2, NULL, NULL, NULL, NULL, NULL, 'NaN', NULL);
             INSERT INTO app.orders SELECT g, 1, g, now(), NULL, NULL, NULL, NULL, g FROM generate_series(100, 400) g;
             CREATE FUNCTION app.sneaky_write() RETURNS int LANGUAGE sql VOLATILE AS $$ INSERT INTO app.audit_log VALUES (1) RETURNING 1 $$;
             GRANT USAGE ON SCHEMA app TO {role};
             GRANT SELECT ON ALL TABLES IN SCHEMA app TO {role};
             GRANT INSERT ON app.audit_log TO {role};
             GRANT EXECUTE ON FUNCTION app.sneaky_write() TO {role};"
        ))
        .await
        .unwrap();
        let url = format!("postgres://{role}:ro-secret-{suffix}@{host}:{port}/{db}");
        Some(RealDb {
            admin,
            db,
            role,
            url,
        })
    }

    fn runtime(&self, shared: Shared) -> (Arc<Runtime>, Arc<crate::telemetry::queue::MemoryQueue>) {
        fake_pg::runtime(
            &self.url,
            shared,
            Opts {
                extra: vec![("VERICTO_MCP_SEARCH_PATH", "app".to_string())],
                telemetry: true,
                ..Default::default()
            },
        )
    }

    async fn audit_rows(&self) -> i64 {
        let mut direct = self.admin.clone();
        direct.dbname(&self.db);
        let c = connect(&direct).await;
        c.query_one("SELECT count(*) FROM app.audit_log", &[])
            .await
            .unwrap()
            .get(0)
    }

    async fn drop(self) {
        let c = connect(&self.admin).await;
        for stmt in [
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                self.db
            ),
            format!("DROP DATABASE IF EXISTS {}", self.db),
            format!("DROP ROLE IF EXISTS {}", self.role),
        ] {
            let _ = c.batch_execute(&stmt).await;
        }
    }
}

async fn connect(cfg: &tokio_postgres::Config) -> tokio_postgres::Client {
    let (client, conn) = cfg.connect(tokio_postgres::NoTls).await.expect("connect");
    tokio::spawn(conn);
    client
}

async fn run(rt: &Arc<Runtime>, tool: &str, args: Value) -> crate::mcp::tools::ToolOutput {
    let caller = fake_pg::caller(rt);
    crate::mcp::tools::call(rt, &caller, tool, &args)
        .await
        .unwrap()
}

macro_rules! real_db {
    () => {
        match RealDb::create().await {
            Some(db) => db,
            None => {
                eprintln!("VERICTO_TEST_PG_URL not set: skipping the real-Postgres test");
                return;
            }
        }
    };
}

#[tokio::test]
async fn real_mcp_reads_types_masks_and_schema() {
    let db = real_db!();
    let shared = Shared::built_in();
    let p = vericto_engine::EnforcementPolicy {
        sensitive_columns: vec![serde_json::from_value(json!({
        "schema": "app", "table": "users", "column": "email", "policy": "mask", "mask_style": "email"
    }))
    .unwrap()],
        ..Default::default()
    };
    shared.policy.store(Arc::new(p));
    let (rt, q) = db.runtime(shared);

    // SCRAM login, search_path pinned to app, types.
    let out = run(&rt, "execute_sql", json!({
        "sql": "SELECT id, total, created_at, tags, meta, blob, ratio, n, total IS NULL AS no_total FROM orders WHERE id IN ($1, $2) ORDER BY id",
        "params": [10, "11"]
    }))
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    let rows = &out.structured["rows"];
    assert_eq!(rows[0][0], "10", "int8 is a string");
    assert_eq!(rows[0][1], "12.30", "numeric is exact");
    assert_eq!(
        rows[0][2], "2026-10-30 12:00:00+00",
        "timestamptz in UTC, ISO"
    );
    assert_eq!(rows[0][3], json!(["a", "b,c"]));
    assert_eq!(rows[0][4], json!({"k": [1, 2]}));
    assert_eq!(rows[0][5], json!({"base64": "AP8=", "bytes": 2}));
    assert_eq!(rows[0][6], json!(0.5));
    assert_eq!(rows[0][7], json!(7));
    assert_eq!(rows[0][8], json!(false));
    assert_eq!(rows[1][6], "NaN");
    assert_eq!(rows[1][1], Value::Null);
    assert_eq!(out.structured["columns"][2]["type"], "timestamptz");

    // A masked column comes back masked; the executed text is the rewrite.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT id, email FROM users ORDER BY id LIMIT 10" }),
    )
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    assert_eq!(out.structured["rewritten"], true);
    let email = out.structured["rows"][0][1].as_str().unwrap();
    assert_ne!(email, "ann@example.com");
    assert!(!out.text.contains("ann@example.com"), "{}", out.text);
    assert_eq!(out.structured["columns"][1]["masked"], "email");

    // Truncation at max_rows.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT id FROM orders ORDER BY id LIMIT 1000", "max_rows": 25 }),
    )
    .await;
    assert_eq!(out.structured["row_count"], 25);
    assert_eq!(out.structured["truncation"]["reason"], "max_rows");

    // An error that would print a value is sanitized.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT 1 FROM users WHERE CAST(ssn AS int) = 0 LIMIT 1" }),
    )
    .await;
    assert_eq!(
        out.structured["error"]["code"], "DATABASE_ERROR",
        "{}",
        out.text
    );
    assert_eq!(out.structured["error"]["sqlstate"], "22P02");
    let all = serde_json::to_string(&out.structured).unwrap() + &out.text;
    assert!(!all.contains("123-45-6789"), "{all}");

    // An unknown table points to describe_schema.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT * FROM nope LIMIT 1" }),
    )
    .await;
    assert_eq!(out.structured["error"]["sqlstate"], "42P01");
    assert_eq!(out.structured["next_steps"][0]["tool"], "describe_schema");

    // describe_schema: tables, columns, keys, the mask marked.
    let out = run(&rt, "describe_schema", json!({ "schema": "app" })).await;
    assert!(!out.is_error, "{}", out.text);
    let tables = out.structured["tables"].as_array().unwrap();
    let users = tables.iter().find(|t| t["name"] == "users").unwrap();
    let email = users["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "email")
        .unwrap();
    assert_eq!(email["masked"], "email");
    assert!(
        users["primary_key"]
            .as_str()
            .unwrap()
            .contains("PRIMARY KEY")
    );
    let orders = tables.iter().find(|t| t["name"] == "orders").unwrap();
    assert!(
        orders["foreign_keys"][0]["definition"]
            .as_str()
            .unwrap()
            .contains("REFERENCES users(id)")
    );

    // check_sql, locally.
    let out = run(
        &rt,
        "check_sql",
        json!({ "sql": "SELECT 1;\nDELETE FROM users;\nSELECT email FROM users" }),
    )
    .await;
    assert_eq!(out.structured["summary"]["total"], 3);
    assert_eq!(out.structured["passed"], false);
    assert_eq!(out.structured["evaluated_locally"], true);

    // whoami.
    let out = run(&rt, "whoami", json!({})).await;
    assert_eq!(out.structured["execution"]["mode"], "proxy");

    // Events: every call one event, source mcp_proxy, no values.
    let ev = fake_pg::events(&q);
    assert!(ev.iter().all(|e| e.source.as_deref() == Some("mcp_proxy")));
    let wire = serde_json::to_string(&ev).unwrap();
    assert!(
        !wire.contains("ann@example.com") && !wire.contains("123-45-6789"),
        "{wire}"
    );
    assert!(
        ev.iter()
            .any(|e| e.execution_status.as_deref() == Some("dry_run"))
    );
    assert!(
        ev.iter()
            .any(|e| e.event_kind.as_deref() == Some("catalog"))
    );
    db.drop().await;
}

#[tokio::test]
async fn real_mcp_read_only_holds_twice_and_nothing_persists() {
    let db = real_db!();
    let (rt, _) = db.runtime(Shared::built_in());
    // The statement classes refuse a write before anything is sent…
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "INSERT INTO audit_log VALUES (1)" }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "TIER_NOT_ENABLED");
    // … and the READ ONLY transaction refuses a write a SELECT hides in a
    // function the denylist cannot know.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT sneaky_write()" }),
    )
    .await;
    assert_eq!(
        out.structured["error"]["code"], "DATABASE_ERROR",
        "{}",
        out.text
    );
    assert_eq!(out.structured["error"]["sqlstate"], "25006");
    assert_eq!(out.structured["next_action"], "fix_sql_error");
    // A side-effect built-in is refused by the class check.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT set_config('search_path', 'public', false)" }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "INVALID_INPUT");
    // Nothing was written, and the connection is clean for the next call.
    assert_eq!(db.audit_rows().await, 0);
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT current_setting('transaction_read_only') AS ro" }),
    )
    .await;
    assert_eq!(out.structured["rows"][0][0], "on", "{}", out.text);
    let out = run(&rt, "execute_sql", json!({ "sql": "SHOW search_path" })).await;
    assert_eq!(
        out.structured["rows"][0][0], "app",
        "the search path is the pinned one"
    );
    db.drop().await;
}

#[tokio::test]
async fn real_mcp_timeouts_and_the_kill_switch_cancel_the_statement() {
    let db = real_db!();
    let (rt, _) = db.runtime(Shared::built_in());
    let slow = "SELECT count(*) FROM generate_series(1, 2000000000) g WHERE g % 7 = 3";
    let started = std::time::Instant::now();
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": slow, "timeout_ms": 400 }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "TIMEOUT", "{}", out.text);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // A kill switch that lands while the statement runs cancels it.
    let rt2 = Arc::clone(&rt);
    let call = tokio::spawn(async move {
        run(
            &rt2,
            "execute_sql",
            json!({ "sql": slow, "timeout_ms": 30000 }),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    rt.shared.kill_switch.store(
        crate::tcp::kill_switch::KillSwitch::from_sync(Some(json!({
            "workspace": { "block_id": "blk-live", "message": "Vericto blocked this query [VERICTO-105]: stopped by an admin." }
        })))
        .map(Arc::new),
    );
    let started = std::time::Instant::now();
    let out = tokio::time::timeout(std::time::Duration::from_secs(10), call)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        out.structured["error"]["code"], "KILL_SWITCH",
        "{}",
        out.text
    );
    assert_eq!(out.structured["cancelled_by_kill_switch"], true);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    db.drop().await;
}

#[tokio::test]
async fn real_mcp_wrong_password_is_stop_and_names_nothing() {
    let db = real_db!();
    let bad = db.url.replace("ro-secret-", "wrong-");
    let (rt, _) = fake_pg::runtime(&bad, Shared::built_in(), Opts::default());
    let out = run(&rt, "execute_sql", json!({ "sql": "SELECT 1" })).await;
    assert_eq!(
        out.structured["error"]["code"], "DATABASE_UNAVAILABLE",
        "{}",
        out.text
    );
    assert_eq!(out.structured["next_action"], "stop");
    let all = serde_json::to_string(&out.structured).unwrap() + &out.text;
    assert!(!all.contains(&db.role) && !all.contains("wrong-"), "{all}");
    db.drop().await;
}

#[tokio::test]
async fn real_mcp_an_enforced_allowlist_filters_the_schema_and_refuses_the_rest() {
    let db = real_db!();
    let shared = Shared::built_in();
    let map: vericto_engine::AccessPolicyMap = serde_json::from_value(json!({
        db.role.clone(): {"mode": "enforce", "ddl": "deny", "entries": [
            {"schema": "app", "table": "users", "columns": ["id", "email"], "access": "read"}
        ]}
    }))
    .unwrap();
    shared.agent_access.store(Arc::new(map));
    let (rt, _) = db.runtime(shared);
    // describe_schema lists only what the allowlist lets this role read.
    let out = run(&rt, "describe_schema", json!({})).await;
    assert!(!out.is_error, "{}", out.text);
    let tables = out.structured["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 1, "{}", out.structured);
    let cols: Vec<&str> = tables[0]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(cols, ["id", "email"]);
    // An allowed read runs; a denied column is refused before anything is sent.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT id, email FROM users ORDER BY id LIMIT 5" }),
    )
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT ssn FROM users LIMIT 5" }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "BLOCKED", "{}", out.text);
    assert_eq!(out.structured["next_action"], "request_access");
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT * FROM orders LIMIT 5" }),
    )
    .await;
    assert_eq!(
        out.structured["next_action"], "request_access",
        "{}",
        out.text
    );
    db.drop().await;
}
