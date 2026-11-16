// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto-proxy mcp` against a real MySQL (run when `VERICTO_TEST_MYSQL_URL`
//! is set to an admin URL, e.g. Docker `mysql:8.4`): caching_sha2_password
//! login of a dedicated user over plaintext loopback (RSA key exchange),
//! reads and their types, `?` params, masks, truncation, read-only enforced
//! twice, the statement timeout and the kill switch, `describe_schema`, the
//! local `check_sql`, and the startup role check. Each test gets a fresh
//! database and user, dropped afterwards.

use std::sync::Arc;

use mysql_async::prelude::Queryable;
use serde_json::{Value, json};

use crate::mcp::fake_pg::{self, Opts};
use crate::mcp::runtime::{Runtime, Shared};

struct RealMy {
    admin: String,
    db: String,
    user: String,
    url: String,
}

async fn admin_conn(url: &str) -> mysql_async::Conn {
    let opts = mysql_async::Opts::from_url(url).expect("VERICTO_TEST_MYSQL_URL");
    mysql_async::Conn::new(opts).await.expect("admin connect")
}

impl RealMy {
    async fn create() -> Option<RealMy> {
        let admin = std::env::var("VERICTO_TEST_MYSQL_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        let parsed = mysql_async::Opts::from_url(&admin).expect("VERICTO_TEST_MYSQL_URL");
        let host = parsed.ip_or_hostname().to_string();
        let port = parsed.tcp_port();
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let db = format!("vericto_mcp_{suffix}");
        let user = format!("ro_{suffix}");
        let mut c = admin_conn(&admin).await;
        for stmt in [
            format!("CREATE DATABASE {db}"),
            format!("CREATE USER '{user}'@'%' IDENTIFIED BY 'ro-secret-{suffix}'"),
            "SET GLOBAL log_bin_trust_function_creators = 1".to_string(),
            format!(
                "CREATE TABLE {db}.users (id BIGINT PRIMARY KEY, email VARCHAR(100), ssn VARCHAR(20), active TINYINT(1) NOT NULL DEFAULT 1)"
            ),
            format!(
                "CREATE TABLE {db}.orders (id BIGINT PRIMARY KEY, user_id BIGINT, total DECIMAL(10,2), \
                 created_at DATETIME(6), meta JSON, blob_col VARBINARY(16), ratio DOUBLE, n INT UNSIGNED, \
                 day DATE, FOREIGN KEY (user_id) REFERENCES {db}.users(id))"
            ),
            format!("CREATE TABLE {db}.audit_log (n INT)"),
            format!(
                "INSERT INTO {db}.users VALUES (1, 'ann@example.com', '123-45-6789', 1), (2, 'bob@example.com', '987-65-4321', 0)"
            ),
            format!(
                "INSERT INTO {db}.orders VALUES \
                 (10, 1, 12.30, '2026-10-30 12:00:00.250000', '{{\"k\": [1, 2]}}', X'00FF', 0.5, 7, '2026-10-30'), \
                 (11, 2, NULL, NULL, NULL, NULL, NULL, NULL, NULL)"
            ),
            format!(
                "INSERT INTO {db}.orders (id, user_id, total, n) \
                 WITH RECURSIVE g(i) AS (SELECT 100 UNION ALL SELECT i + 1 FROM g WHERE i < 400) \
                 SELECT i, 1, i, i FROM g"
            ),
            format!(
                "CREATE FUNCTION {db}.sneaky_write() RETURNS INT MODIFIES SQL DATA \
                 BEGIN INSERT INTO {db}.audit_log VALUES (1); RETURN 1; END"
            ),
            format!("GRANT SELECT ON {db}.* TO '{user}'@'%'"),
            format!("GRANT INSERT ON {db}.audit_log TO '{user}'@'%'"),
            format!("GRANT EXECUTE ON FUNCTION {db}.sneaky_write TO '{user}'@'%'"),
        ] {
            c.query_drop(&stmt)
                .await
                .unwrap_or_else(|e| panic!("{stmt}: {e}"));
        }
        let _ = c.disconnect().await;
        let url = format!("mysql://{user}:ro-secret-{suffix}@{host}:{port}/{db}");
        Some(RealMy {
            admin,
            db,
            user,
            url,
        })
    }

    fn runtime(&self, shared: Shared) -> (Arc<Runtime>, Arc<crate::telemetry::queue::MemoryQueue>) {
        fake_pg::runtime(
            &self.url,
            shared,
            Opts {
                telemetry: true,
                ..Default::default()
            },
        )
    }

    async fn audit_rows(&self) -> i64 {
        let mut c = admin_conn(&self.admin).await;
        let n: Option<i64> = c
            .query_first(format!("SELECT COUNT(*) FROM {}.audit_log", self.db))
            .await
            .unwrap();
        let _ = c.disconnect().await;
        n.unwrap_or(-1)
    }

    async fn drop(self) {
        let mut c = admin_conn(&self.admin).await;
        for stmt in [
            format!("DROP DATABASE IF EXISTS {}", self.db),
            format!("DROP USER IF EXISTS '{}'@'%'", self.user),
        ] {
            let _ = c.query_drop(&stmt).await;
        }
        let _ = c.disconnect().await;
    }
}

async fn run(rt: &Arc<Runtime>, tool: &str, args: Value) -> crate::mcp::tools::ToolOutput {
    let caller = fake_pg::caller(rt);
    crate::mcp::tools::call(rt, &caller, tool, &args)
        .await
        .unwrap()
}

macro_rules! real_my {
    () => {
        match RealMy::create().await {
            Some(db) => db,
            None => {
                eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
                return;
            }
        }
    };
}

#[tokio::test]
async fn real_mysql_reads_types_masks_and_schema() {
    let db = real_my!();
    let shared = Shared::built_in();
    let p = vericto_engine::EnforcementPolicy {
        sensitive_columns: vec![
            serde_json::from_value(json!({
                "table": "users", "column": "email", "policy": "mask", "mask_style": "email"
            }))
            .unwrap(),
        ],
        ..Default::default()
    };
    shared.policy.store(Arc::new(p));
    let (rt, q) = db.runtime(shared);

    // caching_sha2 login over plaintext loopback; `?` params; types.
    let out = run(&rt, "execute_sql", json!({
        "sql": "SELECT id, total, created_at, meta, blob_col, ratio, n, day, total IS NULL AS no_total FROM orders WHERE id IN (?, ?) ORDER BY id",
        "params": [10, "11"]
    }))
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    let rows = &out.structured["rows"];
    assert_eq!(rows[0][0], "10", "bigint is a string");
    assert_eq!(rows[0][1], "12.30", "decimal is exact");
    assert_eq!(rows[0][2], "2026-10-30 12:00:00.250000", "datetime, ISO");
    assert_eq!(rows[0][3], json!({"k": [1, 2]}));
    assert_eq!(rows[0][4], json!({"base64": "AP8=", "bytes": 2}));
    assert_eq!(rows[0][5], json!(0.5));
    assert_eq!(rows[0][6], json!(7));
    assert_eq!(rows[0][7], "2026-10-30");
    // A comparison is a BIGINT in MySQL: exact, a string.
    assert_eq!(rows[0][8], "0");
    assert_eq!(rows[1][1], Value::Null);
    assert_eq!(out.structured["columns"][0]["type"], "bigint");
    assert_eq!(out.structured["columns"][4]["type"], "varbinary");
    assert_eq!(out.structured["columns"][6]["type"], "int unsigned");

    // A masked column comes back masked; the executed text is the rewrite.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT id, email FROM users ORDER BY id LIMIT 10" }),
    )
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    assert_eq!(out.structured["rewritten"], true, "{}", out.text);
    let email = out.structured["rows"][0][1].as_str().unwrap();
    assert_ne!(email, "ann@example.com");
    assert!(!out.text.contains("ann@example.com"), "{}", out.text);

    // Truncation at max_rows closes that connection; the next call works.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT id FROM orders ORDER BY id LIMIT 1000", "max_rows": 25 }),
    )
    .await;
    assert_eq!(out.structured["row_count"], 25, "{}", out.text);
    assert_eq!(out.structured["truncation"]["reason"], "max_rows");
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT COUNT(*) AS c FROM orders" }),
    )
    .await;
    assert_eq!(out.structured["rows"][0][0], "303", "{}", out.text);

    // An unknown table points to describe_schema.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT * FROM nope LIMIT 1" }),
    )
    .await;
    assert_eq!(out.structured["error"]["sqlstate"], "42S02", "{}", out.text);
    assert_eq!(out.structured["next_steps"][0]["tool"], "describe_schema");

    // Two statements are refused before anything is sent; so is an
    // executable comment.
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT 1; DELETE FROM audit_log" }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "INVALID_INPUT");
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT 1 /*!, (SELECT sneaky_write()) */" }),
    )
    .await;
    // The engine refuses it first (VERICTO-085); the class check would too.
    assert!(
        matches!(
            out.structured["error"]["code"].as_str(),
            Some("BLOCKED" | "INVALID_INPUT")
        ),
        "{}",
        out.text
    );

    // describe_schema: the URL's database, columns, keys, the mask marked.
    let out = run(&rt, "describe_schema", json!({})).await;
    assert!(!out.is_error, "{}", out.text);
    let tables = out.structured["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 3, "{}", out.structured);
    let users = tables.iter().find(|t| t["name"] == "users").unwrap();
    let email = users["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "email")
        .unwrap();
    assert_eq!(email["type"], "varchar(100)");
    assert_eq!(email["masked"], "email");
    assert_eq!(users["primary_key"], "PRIMARY KEY (id)");
    let orders = tables.iter().find(|t| t["name"] == "orders").unwrap();
    let fk = orders["foreign_keys"][0]["definition"].as_str().unwrap();
    assert!(fk.contains("FOREIGN KEY (user_id) REFERENCES"), "{fk}");
    assert!(fk.ends_with(".users(id)"), "{fk}");

    // check_sql, locally, in MySQL.
    let out = run(
        &rt,
        "check_sql",
        json!({ "sql": "SELECT 1;\nDELETE FROM users;\nSELECT email FROM users WHERE id = 1" }),
    )
    .await;
    assert_eq!(out.structured["summary"]["total"], 3, "{}", out.text);
    assert_eq!(out.structured["passed"], false);
    assert_eq!(out.structured["dialect"], "mysql");

    // whoami.
    let out = run(&rt, "whoami", json!({})).await;
    assert_eq!(out.structured["databases"][0]["dialect"], "mysql");
    assert_eq!(out.structured["databases"][0]["engine"], "mysql");

    // Events: every call one event, source mcp_proxy, no values.
    let ev = fake_pg::events(&q);
    assert!(ev.iter().all(|e| e.source.as_deref() == Some("mcp_proxy")));
    let wire = serde_json::to_string(&ev).unwrap();
    assert!(
        !wire.contains("ann@example.com") && !wire.contains("123-45-6789"),
        "{wire}"
    );
    db.drop().await;
}

#[tokio::test]
async fn real_mysql_read_only_holds_twice_and_nothing_persists() {
    let db = real_my!();
    let (rt, _) = db.runtime(Shared::built_in());
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "INSERT INTO audit_log VALUES (1)" }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "TIER_NOT_ENABLED");
    // The READ ONLY transaction refuses a write a SELECT hides in a function.
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
    assert_eq!(out.structured["error"]["sqlstate"], "25006", "{}", out.text);
    for sql in [
        "SET SESSION transaction_read_only = 0",
        "START TRANSACTION",
        "SELECT GET_LOCK('x', 1)",
        "SELECT * FROM users FOR UPDATE",
        "SELECT /*+ MAX_EXECUTION_TIME(0) */ 1",
        "SELECT * FROM users WHERE id = :id",
    ] {
        let out = run(&rt, "execute_sql", json!({ "sql": sql })).await;
        assert!(out.is_error, "{sql}: {}", out.text);
        assert_ne!(out.structured["status"], "EXECUTED", "{sql}");
    }
    assert_eq!(db.audit_rows().await, 0);
    // The session is the pinned one, and the connection is clean.
    // (`@@transaction_read_only` is the next transaction's default, not this
    // one's: the sneaky_write refusal above is the proof of READ ONLY.)
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": "SELECT @@max_execution_time AS t, @@session.sql_mode AS m, @@session.time_zone AS tz" }),
    )
    .await;
    assert_eq!(out.structured["status"], "EXECUTED", "{}", out.text);
    assert_eq!(out.structured["rows"][0][0], "15000", "{}", out.text);
    let mode = out.structured["rows"][0][1].as_str().unwrap();
    assert!(
        !mode.contains("ANSI_QUOTES") && !mode.contains("NO_BACKSLASH"),
        "{mode}"
    );
    assert_eq!(out.structured["rows"][0][2], "+00:00");
    db.drop().await;
}

#[tokio::test]
async fn real_mysql_timeouts_and_the_kill_switch_cancel_the_statement() {
    let db = real_my!();
    let (rt, _) = db.runtime(Shared::built_in());
    let slow = "SELECT COUNT(*) FROM information_schema.COLUMNS a, information_schema.COLUMNS b, information_schema.COLUMNS c WHERE a.ORDINAL_POSITION + b.ORDINAL_POSITION = c.ORDINAL_POSITION + 99999";
    let started = std::time::Instant::now();
    let out = run(
        &rt,
        "execute_sql",
        json!({ "sql": slow, "timeout_ms": 400 }),
    )
    .await;
    assert_eq!(out.structured["error"]["code"], "TIMEOUT", "{}", out.text);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
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
async fn real_mysql_the_role_check_sees_writes_and_a_wrong_password_names_nothing() {
    let db = real_my!();
    let (rt, _) = db.runtime(Shared::built_in());
    // This user has INSERT on audit_log: it can write.
    let c = crate::mcp::readonly::check_pool(&rt.pool).await;
    assert_eq!(c.can_write, Some(true), "{c:?}");
    assert!(c.reasons[0].contains("INSERT"), "{c:?}");
    // Revoke it: SELECT (and EXECUTE) only is read-only.
    let mut a = admin_conn(&db.admin).await;
    a.query_drop(format!(
        "REVOKE INSERT ON {}.audit_log FROM '{}'@'%'",
        db.db, db.user
    ))
    .await
    .unwrap();
    let _ = a.disconnect().await;
    let (rt, _) = db.runtime(Shared::built_in());
    let c = crate::mcp::readonly::check_pool(&rt.pool).await;
    assert!(c.read_only(), "{c:?}");
    // The admin can write.
    let (admin_rt, _) = fake_pg::runtime(&db.admin, Shared::built_in(), Opts::default());
    let c = crate::mcp::readonly::check_pool(&admin_rt.pool).await;
    assert_eq!(c.can_write, Some(true), "{c:?}");

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
    assert!(!all.contains(&db.user) && !all.contains("wrong-"), "{all}");
    db.drop().await;
}

#[tokio::test]
async fn real_mysql_an_enforced_allowlist_filters_the_schema_and_refuses_the_rest() {
    let db = real_my!();
    let shared = Shared::built_in();
    let map: vericto_engine::AccessPolicyMap = serde_json::from_value(json!({
        db.user.clone(): {"mode": "enforce", "ddl": "deny", "entries": [
            {"schema": db.db.clone(), "table": "users", "columns": ["id", "email"], "access": "read"}
        ]}
    }))
    .unwrap();
    shared.agent_access.store(Arc::new(map));
    let (rt, _) = db.runtime(shared);
    // Unqualified names are the URL's database, for the allowlist too.
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
    db.drop().await;
}
