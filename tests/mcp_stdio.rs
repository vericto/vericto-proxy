// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The `vericto-proxy mcp` binary over stdio, as an MCP client spawns it:
//! stdout carries JSON-RPC messages only (every log line goes to stderr), the
//! tools answer, a credential in the environment is warned about, and the
//! process exits when stdin closes. Against `VERICTO_TEST_PG_URL` when set,
//! otherwise against a closed port (the database answers are then
//! DATABASE_UNAVAILABLE, which is what this test checks for).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[test]
fn the_binary_speaks_mcp_on_stdout_and_logs_on_stderr() {
    let home = tempfile::tempdir().unwrap();
    let url_file = home.path().join("db.url");
    let url = std::env::var("VERICTO_TEST_PG_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("postgres://agent:pw@127.0.0.1:{}/shop", closed_port()));
    std::fs::write(&url_file, &url).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"))
        .args([
            "mcp",
            "--database-url-file",
            url_file.to_str().unwrap(),
            "--max-rows",
            "20",
        ])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env(
            "DATABASE_URL",
            "postgres://someone:else@db.example.com/prod",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = child.stderr.take().unwrap();
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut BufReader::new(stderr), &mut s).unwrap();
        s
    });
    let messages = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex","version":"0.50"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_sql","arguments":{"sql":"SELECT 1 AS one"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_sql","arguments":{"sql":"DROP TABLE users"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"check_sql","arguments":{"sql":"SELECT 1; DELETE FROM users"}}}"#,
    ];
    for m in messages {
        writeln!(stdin, "{m}").unwrap();
    }
    stdin.flush().unwrap();
    let mut answers = std::collections::BTreeMap::new();
    let mut lines = stdout.lines();
    let started = Instant::now();
    while answers.len() < 6 && started.elapsed() < Duration::from_secs(60) {
        let line = lines.next().expect("stdout open").unwrap();
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout must carry JSON-RPC only, got {line:?}: {e}"));
        assert_eq!(v["jsonrpc"], "2.0", "{line}");
        answers.insert(v["id"].as_u64().unwrap(), v);
    }
    assert_eq!(answers[&1]["result"]["serverInfo"]["name"], "vericto-proxy");
    let tools: Vec<&str> = answers[&2]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        ["execute_sql", "describe_schema", "check_sql", "whoami"]
    );
    let who = &answers[&3]["result"]["structuredContent"];
    assert_eq!(who["execution"]["mode"], "proxy");
    assert_eq!(
        who["execution"]["databases"][0]["limits"]["max_rows"], 20,
        "the flag applied"
    );
    let warnings = who["execution"]["warnings"].as_array().unwrap();
    assert!(
        warnings.contains(&serde_json::json!("agent_environment_has_db_credentials")),
        "{who}"
    );
    assert!(
        warnings.contains(&serde_json::json!("no_control_plane")),
        "{who}"
    );
    assert_eq!(who["client"]["name"], "codex");
    let exec = &answers[&4]["result"]["structuredContent"];
    if std::env::var("VERICTO_TEST_PG_URL").is_ok_and(|u| !u.is_empty()) {
        assert_eq!(exec["status"], "EXECUTED", "{exec}");
        assert_eq!(exec["rows"], serde_json::json!([[1]]));
    } else {
        assert_eq!(exec["error"]["code"], "DATABASE_UNAVAILABLE", "{exec}");
    }
    assert_eq!(
        answers[&5]["result"]["structuredContent"]["status"],
        "BLOCKED"
    );
    assert_eq!(
        answers[&6]["result"]["structuredContent"]["summary"]["total"],
        2
    );
    // stdin closes: the process exits by itself.
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "the process did not exit when stdin closed"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{status:?}");
    let err = err_thread.join().unwrap();
    assert!(
        err.contains("agent_environment_has_db_credentials"),
        "the warning is logged: {err}"
    );
    assert!(err.contains("vericto-proxy mcp starting"), "{err}");
    assert!(
        !err.contains("someone:else") && !err.contains(":pw@"),
        "no credential is logged: {err}"
    );
}

#[test]
fn a_bad_setting_fails_fast_with_its_name() {
    let out = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"))
        .args(["mcp", "--transport", "carrier-pigeon"])
        .env_clear()
        .env("VERICTO_MCP_DATABASE_URL", "postgres://u:p@127.0.0.1/db")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "nothing on stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("VERICTO_MCP_TRANSPORT"), "{err}");
    let out = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"))
        .args(["mcp", "--help"])
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "help goes to stderr in mcp mode");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--database-url-file"));
}
