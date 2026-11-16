// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto-proxy mcp credential set|test|delete` and `--database-url-keychain`
//! through the binary, as `vericto guard install --hard` calls them. The debug
//! binary reads the store from `VERICTO_MCP_TEST_KEYCHAIN_FILE` (never the
//! developer's keychain; release builds have no such switch). Against
//! `VERICTO_TEST_MYSQL_URL` (an admin URL) when set, the `test` action also
//! connects; otherwise it checks the unreachable-database path.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn cmd(store: &std::path::Path, home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"));
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("VERICTO_MCP_TEST_KEYCHAIN_FILE", store)
        .env("RUST_LOG", "warn");
    c
}

fn credential(
    store: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> Output {
    let mut c = cmd(store, home);
    c.arg("mcp")
        .arg("credential")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        let mut i = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            i.write_all(s.as_bytes()).unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|_| panic!("stdout: {}", String::from_utf8_lossy(&o.stdout)))
}

#[test]
fn set_test_and_delete_never_print_the_url() {
    let home = tempfile::tempdir().unwrap();
    let store = home.path().join("store.json");
    let url = format!(
        "mysql://agent:hunter2-secret@127.0.0.1:{}/shop",
        closed_port()
    );

    // The URL comes on stdin, never as an argument.
    let o = credential(&store, home.path(), &["set", "shop", &url], None);
    assert_eq!(o.status.code(), Some(1));
    let o = credential(
        &store,
        home.path(),
        &["set", "shop"],
        Some(&format!("{url}\n")),
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let j = json(&o);
    assert_eq!(j["entry"], "vericto-proxy/shop");
    assert_eq!(j["dialect"], "mysql");
    assert_eq!(j["replaced"], false);
    // An invalid URL is refused without echoing it.
    let o = credential(
        &store,
        home.path(),
        &["set", "bad"],
        Some("oracle://u:hunter2-secret@h/x"),
    );
    assert_eq!(o.status.code(), Some(1));

    // `test` against a closed port: unavailable, exit 4.
    let o = credential(&store, home.path(), &["test", "shop"], None);
    assert_eq!(
        o.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(json(&o)["error"], "unavailable");
    let o2 = credential(&store, home.path(), &["test", "nope"], None);
    assert_eq!(o2.status.code(), Some(2));

    for out in [&o, &o2] {
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!all.contains("hunter2"), "{all}");
    }

    // The server reads it with --database-url-keychain and says where from.
    let mut child = cmd(&store, home.path())
        .args(["mcp", "--database-url-keychain", "shop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"t","version":"1"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"whoami","arguments":{{}}}}}}"#
    )
    .unwrap();
    let mut whoami = None;
    for _ in 0..2 {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        if v["id"] == 2 {
            whoami = Some(v);
        }
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let w = whoami.expect("whoami answer");
    let s = &w["result"]["structuredContent"];
    assert_eq!(s["credential_source"], "keychain", "{w}");
    assert_eq!(s["databases"][0]["dialect"], "mysql");
    let all = format!("{w}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("hunter2"), "{all}");

    let o = credential(&store, home.path(), &["delete", "shop"], None);
    assert_eq!(o.status.code(), Some(0));
    let o = credential(&store, home.path(), &["delete", "shop"], None);
    assert_eq!(o.status.code(), Some(2));
}

/// Against a real MySQL: `test` connects, reports the role, and with
/// `--require-read-only` exits 3 for a user that can write.
#[test]
fn test_reports_the_role_of_a_real_mysql() {
    let Some(admin) = std::env::var("VERICTO_TEST_MYSQL_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let store = home.path().join("store.json");
    let o = credential(&store, home.path(), &["set", "admin"], Some(&admin));
    assert_eq!(o.status.code(), Some(0));
    let o = credential(&store, home.path(), &["test", "admin"], None);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let j = json(&o);
    assert_eq!(j["engine"], "mysql");
    assert_eq!(j["database_role"]["read_only"], false, "{j}");
    let o = credential(
        &store,
        home.path(),
        &["test", "admin", "--require-read-only"],
        None,
    );
    assert_eq!(o.status.code(), Some(3));
    // The server refuses to start with --require-read-only on this role.
    let o = cmd(&store, home.path())
        .args([
            "mcp",
            "--database-url-keychain",
            "admin",
            "--require-read-only",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("can write"), "{err}");
    let pw = admin
        .split_once("://")
        .and_then(|(_, r)| r.split_once('@'))
        .and_then(|(ui, _)| ui.split_once(':'))
        .map(|(_, p)| p.to_string())
        .unwrap_or_default();
    if !pw.is_empty() {
        assert!(!err.contains(&pw));
    }
}
