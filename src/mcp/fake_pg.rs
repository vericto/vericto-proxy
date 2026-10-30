// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! A scripted PostgreSQL that records every byte `vericto-proxy mcp` sends
//! (design §7.6): the exact-bytes, smuggling and property tests assert on what
//! it saw. It speaks enough of the protocol for the executor: startup (trust,
//! cleartext or MD5), simple queries (control statements), and the extended
//! protocol (Parse, Bind, Describe, Execute with a row limit, Sync).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::mcp::config::McpConfig;
use crate::mcp::runtime::{Caller, ClientInfo, EventSink, Runtime, Shared};
use crate::telemetry::{EventQueue, TelemetryEvent};

/// One frontend message as the fake received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Startup(Vec<(String, String)>),
    Password(Vec<u8>),
    /// Simple query text.
    Query(String),
    /// Unnamed or named statement, its text (the bytes up to the NUL).
    Parse {
        name: String,
        text: Vec<u8>,
        param_types: usize,
    },
    Bind {
        params: Vec<Option<Vec<u8>>>,
    },
    Describe(u8),
    Execute {
        max_rows: i32,
    },
    Sync,
    Terminate,
    Other(u8),
    Cancel,
}

/// What a statement answers.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub columns: Vec<(String, u32)>,
    pub rows: Vec<Vec<Option<String>>>,
    pub error: Option<(String, String)>,
    pub delay_ms: u64,
}

impl Answer {
    pub fn rows(columns: &[(&str, u32)], rows: Vec<Vec<Option<&str>>>) -> Self {
        Self {
            columns: columns.iter().map(|(n, o)| (n.to_string(), *o)).collect(),
            rows: rows
                .into_iter()
                .map(|r| r.into_iter().map(|c| c.map(str::to_string)).collect())
                .collect(),
            ..Default::default()
        }
    }

    pub fn error(code: &str, message: &str) -> Self {
        Self {
            error: Some((code.to_string(), message.to_string())),
            ..Default::default()
        }
    }
}

/// How the fake authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Trust,
    Cleartext,
    Md5,
}

#[derive(Clone)]
pub struct FakePg {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<HashMap<String, Answer>>>,
    connections: Arc<Mutex<usize>>,
}

impl FakePg {
    pub async fn start(auth: Auth) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = FakePg {
            addr,
            seen: Arc::default(),
            script: Arc::default(),
            connections: Arc::default(),
        };
        let f = fake.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let f = f.clone();
                *f.connections.lock().unwrap() += 1;
                tokio::spawn(async move {
                    let _ = f.connection(sock, auth).await;
                });
            }
        });
        fake
    }

    /// Scripts the answer to a statement (by its exact text).
    pub fn answer(&self, sql: &str, a: Answer) {
        self.script.lock().unwrap().insert(sql.to_string(), a);
    }

    /// Everything received so far, startup excluded.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| !matches!(s, Seen::Startup(_) | Seen::Password(_)))
            .cloned()
            .collect()
    }

    pub fn all_seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.seen.lock().unwrap().clear();
    }

    pub fn connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }

    /// The texts of every Parse received.
    pub fn parses(&self) -> Vec<Vec<u8>> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Parse { text, .. } => Some(text),
                _ => None,
            })
            .collect()
    }

    /// The texts of every simple query received.
    pub fn queries(&self) -> Vec<String> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Query(q) => Some(q),
                _ => None,
            })
            .collect()
    }

    fn record(&self, s: Seen) {
        self.seen.lock().unwrap().push(s);
    }

    async fn connection(&self, mut sock: TcpStream, auth: Auth) -> std::io::Result<()> {
        let mut len = [0u8; 4];
        sock.read_exact(&mut len).await?;
        let n = i32::from_be_bytes(len) as usize;
        let mut body = vec![0u8; n - 4];
        sock.read_exact(&mut body).await?;
        let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if code == crate::tcp::cancel::CANCEL_REQUEST_CODE {
            self.record(Seen::Cancel);
            return Ok(());
        }
        let mut params = Vec::new();
        let mut parts = body[4..].split(|&b| b == 0);
        while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k.is_empty() {
                break;
            }
            params.push((
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            ));
        }
        self.record(Seen::Startup(params));
        match auth {
            Auth::Trust => {}
            Auth::Cleartext => {
                sock.write_all(&msg(b'R', &3i32.to_be_bytes())).await?;
                let (_, p) = read_msg(&mut sock).await?;
                self.record(Seen::Password(p));
            }
            Auth::Md5 => {
                let mut b = 5i32.to_be_bytes().to_vec();
                b.extend_from_slice(&[1, 2, 3, 4]);
                sock.write_all(&msg(b'R', &b)).await?;
                let (_, p) = read_msg(&mut sock).await?;
                self.record(Seen::Password(p));
            }
        }
        let mut out = msg(b'R', &0i32.to_be_bytes());
        out.extend(param_status("server_version", "17.0"));
        out.extend(param_status("client_encoding", "UTF8"));
        out.extend(param_status("standard_conforming_strings", "on"));
        let mut key = 4242i32.to_be_bytes().to_vec();
        key.extend_from_slice(&[9, 9, 9, 9]);
        out.extend(msg(b'K', &key));
        out.extend(msg(b'Z', b"I"));
        sock.write_all(&out).await?;

        let mut status = b'I';
        let mut failed_extended = false;
        let mut portal: Option<(Answer, usize)> = None;
        let mut statement: Option<String> = None;
        loop {
            let (tag, body) = match read_msg(&mut sock).await {
                Ok(m) => m,
                Err(_) => return Ok(()),
            };
            match tag {
                b'Q' => {
                    let text = cstr(&body);
                    self.record(Seen::Query(text.clone()));
                    let mut out = Vec::new();
                    if text.contains("FAIL_CONTROL") {
                        out.extend(error_msg("42601", "syntax error"));
                        status = if status == b'T' { b'E' } else { status };
                    } else {
                        for stmt in text.split("; ") {
                            let tag = if stmt.starts_with("BEGIN") {
                                status = b'T';
                                "BEGIN"
                            } else if stmt == "ROLLBACK" {
                                status = b'I';
                                "ROLLBACK"
                            } else if stmt.starts_with("SET") {
                                "SET"
                            } else {
                                "SELECT 0"
                            };
                            out.extend(msg(b'C', &cstr_bytes(tag)));
                        }
                    }
                    out.extend(msg(b'Z', &[status]));
                    sock.write_all(&out).await?;
                }
                b'P' => {
                    let name_end = body.iter().position(|&b| b == 0).unwrap();
                    let name = String::from_utf8_lossy(&body[..name_end]).into_owned();
                    let rest = &body[name_end + 1..];
                    let text_end = rest.iter().position(|&b| b == 0).unwrap();
                    let text = rest[..text_end].to_vec();
                    let types =
                        i16::from_be_bytes([rest[text_end + 1], rest[text_end + 2]]) as usize;
                    self.record(Seen::Parse {
                        name,
                        text: text.clone(),
                        param_types: types,
                    });
                    if failed_extended {
                        continue;
                    }
                    let sql = String::from_utf8_lossy(&text).into_owned();
                    if status == b'E' {
                        failed_extended = true;
                        sock.write_all(&error_msg("25P02", "current transaction is aborted"))
                            .await?;
                        continue;
                    }
                    statement = Some(sql);
                    sock.write_all(&msg(b'1', &[])).await?;
                }
                b'B' => {
                    // portal, statement, format codes, values, result formats
                    let mut i = 0;
                    for _ in 0..2 {
                        i += body[i..].iter().position(|&b| b == 0).unwrap() + 1;
                    }
                    let nf = i16::from_be_bytes([body[i], body[i + 1]]) as usize;
                    i += 2 + nf * 2;
                    let nv = i16::from_be_bytes([body[i], body[i + 1]]) as usize;
                    i += 2;
                    let mut params = Vec::new();
                    for _ in 0..nv {
                        let l =
                            i32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
                        i += 4;
                        if l < 0 {
                            params.push(None);
                        } else {
                            params.push(Some(body[i..i + l as usize].to_vec()));
                            i += l as usize;
                        }
                    }
                    self.record(Seen::Bind { params });
                    if failed_extended {
                        continue;
                    }
                    let sql = statement.clone().unwrap_or_default();
                    let a = self
                        .script
                        .lock()
                        .unwrap()
                        .get(&sql)
                        .cloned()
                        .unwrap_or_else(|| {
                            Answer::rows(&[("?column?", 23)], vec![vec![Some("1")]])
                        });
                    portal = Some((a, 0));
                    sock.write_all(&msg(b'2', &[])).await?;
                }
                b'D' => {
                    self.record(Seen::Describe(body.first().copied().unwrap_or(0)));
                    if failed_extended {
                        continue;
                    }
                    let Some((a, _)) = &portal else { continue };
                    if a.error.is_some() || a.columns.is_empty() {
                        if a.error.is_none() {
                            sock.write_all(&msg(b'n', &[])).await?;
                        }
                        continue;
                    }
                    let mut b = (a.columns.len() as i16).to_be_bytes().to_vec();
                    for (name, oid) in &a.columns {
                        b.extend_from_slice(name.as_bytes());
                        b.push(0);
                        b.extend_from_slice(&0i32.to_be_bytes());
                        b.extend_from_slice(&0i16.to_be_bytes());
                        b.extend_from_slice(&oid.to_be_bytes());
                        b.extend_from_slice(&(-1i16).to_be_bytes());
                        b.extend_from_slice(&(-1i32).to_be_bytes());
                        b.extend_from_slice(&0i16.to_be_bytes());
                    }
                    sock.write_all(&msg(b'T', &b)).await?;
                }
                b'E' => {
                    let max_rows = i32::from_be_bytes([
                        body[body.len() - 4],
                        body[body.len() - 3],
                        body[body.len() - 2],
                        body[body.len() - 1],
                    ]);
                    self.record(Seen::Execute { max_rows });
                    if failed_extended {
                        continue;
                    }
                    let Some((a, sent)) = portal.as_mut() else {
                        continue;
                    };
                    if a.delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(a.delay_ms)).await;
                    }
                    if let Some((code, m)) = &a.error {
                        sock.write_all(&error_msg(code, m)).await?;
                        if status == b'T' {
                            status = b'E';
                        }
                        failed_extended = true;
                        continue;
                    }
                    let mut out = Vec::new();
                    let limit = if max_rows <= 0 {
                        usize::MAX
                    } else {
                        max_rows as usize
                    };
                    let mut n = 0;
                    while *sent < a.rows.len() && n < limit {
                        let row = &a.rows[*sent];
                        let mut b = (row.len() as i16).to_be_bytes().to_vec();
                        for c in row {
                            match c {
                                None => b.extend_from_slice(&(-1i32).to_be_bytes()),
                                Some(v) => {
                                    b.extend_from_slice(&(v.len() as i32).to_be_bytes());
                                    b.extend_from_slice(v.as_bytes());
                                }
                            }
                        }
                        out.extend(msg(b'D', &b));
                        *sent += 1;
                        n += 1;
                    }
                    if *sent < a.rows.len() {
                        out.extend(msg(b's', &[]));
                    } else {
                        out.extend(msg(b'C', &cstr_bytes(&format!("SELECT {n}"))));
                    }
                    sock.write_all(&out).await?;
                }
                b'S' => {
                    self.record(Seen::Sync);
                    failed_extended = false;
                    portal = None;
                    sock.write_all(&msg(b'Z', &[status])).await?;
                }
                b'X' => {
                    self.record(Seen::Terminate);
                    return Ok(());
                }
                other => self.record(Seen::Other(other)),
            }
        }
    }
}

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![tag];
    m.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    m.extend_from_slice(body);
    m
}

fn cstr_bytes(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b.strip_suffix(&[0]).unwrap_or(b)).into_owned()
}

fn param_status(k: &str, v: &str) -> Vec<u8> {
    let mut b = cstr_bytes(k);
    b.extend(cstr_bytes(v));
    msg(b'S', &b)
}

fn error_msg(code: &str, m: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for (c, v) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', code),
        (b'M', m),
        (b'D', "a detail with a value 42"),
    ] {
        b.push(c);
        b.extend(cstr_bytes(v));
    }
    b.push(0);
    msg(b'E', &b)
}

async fn read_msg(sock: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    sock.read_exact(&mut h).await?;
    let n = i32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize - 4;
    let mut b = vec![0u8; n];
    sock.read_exact(&mut b).await?;
    Ok((h[0], b))
}

// ── A runtime against a fake (or real) database ──────────────────────────────

/// Settings for [`runtime`].
#[derive(Default)]
pub struct Opts {
    pub extra: Vec<(&'static str, String)>,
    pub require_control_plane: bool,
    pub telemetry: bool,
    /// The control-plane link is configured (the rule tools exist).
    pub linked: bool,
}

/// A runtime for `url` with `shared`, its telemetry captured.
pub fn runtime(
    url: &str,
    shared: Shared,
    opts: Opts,
) -> (Arc<Runtime>, Arc<crate::telemetry::queue::MemoryQueue>) {
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert("VERICTO_MCP_DATABASE_URL".into(), url.to_string());
    for (k, v) in opts.extra {
        map.insert(k.to_string(), v);
    }
    let cfg = McpConfig::from_lookup(&|k: &str| map.get(k).cloned()).expect("test config");
    let queue = Arc::new(crate::telemetry::queue::MemoryQueue::new(10_000));
    let telemetry = opts.telemetry.then(|| EventSink {
        queue: queue.clone() as Arc<dyn EventQueue>,
        database_id: "00000000-0000-4000-8000-000000000001".to_string(),
    });
    let rt = Runtime {
        pool: crate::mcp::pool::Pool::new(
            cfg.database.clone(),
            cfg.pool_size,
            cfg.pool_idle,
            cfg.allow_md5,
        ),
        cfg,
        shared,
        policy_mode: crate::tcp::policy_rules::PolicyRulesMode::Enforce,
        linked: opts.linked || opts.require_control_plane,
        require_control_plane: opts.require_control_plane,
        trusted_keys: true,
        telemetry,
        database_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
        warnings: Vec::new(),
        process_key: Some((
            crate::mcp::identity::sha256_hex(b"vtro_test_key"),
            "abc".into(),
        )),
        local_tokens: Vec::new(),
        session_id: "test-session".to_string(),
    };
    (Arc::new(rt), queue)
}

/// The fake's URL for a runtime.
pub fn url(fake: &FakePg) -> String {
    format!("postgres://agent_ro:pw@127.0.0.1:{}/shop", fake.addr.port())
}

pub fn caller(rt: &Runtime) -> Caller {
    rt.stdio_caller(ClientInfo {
        name: Some("test-client".into()),
        version: Some("1.0".into()),
    })
}

/// Drains the captured events.
pub fn events(q: &crate::telemetry::queue::MemoryQueue) -> Vec<TelemetryEvent> {
    let b = q.drain_batch(10_000);
    let ev = b.events.clone();
    q.ack(&b);
    ev
}

/// The policy with one mask tag on `users.email` (email style).
pub fn shared_with_mask() -> Shared {
    let shared = Shared::built_in();
    let p = vericto_engine::EnforcementPolicy {
        sensitive_columns: vec![serde_json::from_value(serde_json::json!({
        "schema": "public", "table": "users", "column": "email", "policy": "mask", "mask_style": "email"
    }))
    .unwrap()],
        ..Default::default()
    };
    shared.policy.store(Arc::new(p));
    shared
}
