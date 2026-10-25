// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Postgres wire fixes of 4.16.1, driven through the real session entrypoint
//! (`handle_connection`) over TCP, against a scripted Postgres:
//!
//! - **CancelRequest:** taken before `PROXY_TLS_MODE=require` applies, and
//!   forwarded on a new upstream connection only for a key the proxy relayed
//!   to a session that is still open.
//! - **ReadyForQuery of a refused statement with `VERICTO_POLICY_RULES=off`:**
//!   carries the status the server last reported (`I`, `T`, `E`), in the
//!   simple and the extended protocol. Up to 4.16.0 it always said `I`.
//!
//! The real-database counterparts (psql, libpq's cancel, MySQL 8) run when
//! `VERICTO_TEST_PG_URL` / `VERICTO_TEST_MYSQL_URL` are set.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::sensitive_tests::{cstr, pg_error, pg_parse, pg_query, pg_sync, read_pg, timeout};
use crate::tcp::cancel::{BackendKey, CANCEL_REQUEST_CODE};
use crate::tcp::codec::{PgMessage, SSL_REQUEST_CODE};
use crate::tcp::postgres::{PgProxyConfig, handle_connection};

const PID: i32 = 4242;
const SECRET: [u8; 4] = [0x5e, 0xc2, 0x37, 0x01];
/// Refused by the built-in ruleset under the default policy.
const DANGEROUS: &str = "DELETE FROM users";

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    PgMessage {
        tag,
        body: body.to_vec(),
    }
    .encode()
}

fn key(pid: i32, secret: &[u8]) -> BackendKey {
    BackendKey {
        pid,
        secret: secret.into(),
    }
}

/// What the scripted Postgres saw.
struct FakePg {
    addr: SocketAddr,
    /// Every CancelRequest received, as bytes.
    cancels: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Every statement a session received (simple Query or Parse).
    statements: mpsc::UnboundedReceiver<String>,
}

/// A Postgres that trusts every StartupMessage, gives each session the key
/// ([`PID`], [`SECRET`]), and answers statements tracking the transaction
/// status as the server does: `BEGIN` → `T`; `SELECT 1/0` → error, and `E`
/// inside a block; `COMMIT` / `ROLLBACK` → `I`; anything else in `E` → 25P02.
async fn fake_pg() -> FakePg {
    fake_pg_with(None).await
}

/// [`fake_pg`] that answers an SSLRequest with `S` and serves the session
/// over TLS with `tls` (what `UPSTREAM_SSLMODE=require` negotiates).
async fn fake_pg_with(tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>) -> FakePg {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cancel_tx, cancels) = mpsc::unbounded_channel();
    let (stmt_tx, statements) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let cancel_tx = cancel_tx.clone();
            let stmt_tx = stmt_tx.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    None => {
                        let _ = fake_pg_connection(sock, cancel_tx, stmt_tx).await;
                    }
                    Some(config) => {
                        let mut request = [0u8; 8];
                        if sock.read_exact(&mut request).await.is_err()
                            || i32::from_be_bytes([request[4], request[5], request[6], request[7]])
                                != SSL_REQUEST_CODE
                        {
                            return;
                        }
                        if sock.write_all(b"S").await.is_err() {
                            return;
                        }
                        let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(sock).await
                        else {
                            return;
                        };
                        let _ = fake_pg_connection(tls, cancel_tx, stmt_tx).await;
                    }
                }
            });
        }
    });
    FakePg {
        addr,
        cancels,
        statements,
    }
}

/// The DataRows of `SELECT many_rows`: 2,000 small rows, then rows whose frame
/// is just under, at and over the relay's 64 KiB buffer, and one of 200 KB.
fn many_rows() -> Vec<u8> {
    let mut rows = Vec::new();
    for i in 0..2000usize {
        rows.extend(msg(b'D', &vec![b'a' + (i % 26) as u8; 6 + i % 400]));
    }
    for (i, total) in [64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 200_000]
        .into_iter()
        .enumerate()
    {
        rows.extend(msg(b'D', &vec![b'0' + i as u8; total - 5]));
    }
    rows
}

/// The COPY OUT stream of `COPY big TO STDOUT`: CopyOutResponse, 1,000 rows,
/// one row larger than the relay buffer, CopyDone, CommandComplete.
fn copy_out() -> Vec<u8> {
    let mut out = msg(b'H', &[0, 0, 1, 0, 0]);
    for i in 0..1000usize {
        out.extend(msg(b'd', format!("{i}\tcopied row {i}\n").as_bytes()));
    }
    out.extend(msg(b'd', &vec![b'c'; 100_000]));
    out.extend(msg(b'c', b""));
    out.extend(msg(b'C', b"COPY 1001\0"));
    out
}

async fn fake_pg_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut sock: S,
    cancel_tx: mpsc::UnboundedSender<Vec<u8>>,
    stmt_tx: mpsc::UnboundedSender<String>,
) -> std::io::Result<()> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await?;
    let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
    sock.read_exact(&mut body).await?;
    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if code == CANCEL_REQUEST_CODE {
        let mut packet = len.to_vec();
        packet.extend_from_slice(&body);
        let _ = cancel_tx.send(packet);
        return Ok(()); // the server closes a cancel connection, never answers
    }
    let mut reply = msg(b'R', &0i32.to_be_bytes());
    reply.extend(msg(b'S', b"server_version\x0017.0\0"));
    let mut k = PID.to_be_bytes().to_vec();
    k.extend_from_slice(&SECRET);
    reply.extend(msg(b'K', &k));
    reply.extend(msg(b'Z', b"I"));
    sock.write_all(&reply).await?;

    let mut status = b'I';
    // Extended protocol: after an error the server skips to Sync.
    let mut skipping = false;
    // The statement an Execute runs (the last one parsed).
    let mut parsed = String::new();
    loop {
        let m = read_message(&mut sock).await?;
        let mut out = Vec::new();
        let mut split_reply = false;
        // Large replies go out in pieces around the relay's buffer size.
        let mut large_reply = false;
        match m.tag {
            b'X' => return Ok(()),
            b'Q' | b'P' => {
                let sql = if m.tag == b'Q' {
                    cstr(&m.body)
                } else {
                    let rest = &m.body[m.body.iter().position(|&b| b == 0).unwrap() + 1..];
                    cstr(rest)
                };
                let _ = stmt_tx.send(sql.clone());
                if skipping {
                    continue;
                }
                let upper = sql.to_ascii_uppercase();
                if m.tag == b'P' {
                    parsed = upper.clone();
                }
                let (reply, next) = if upper == "SELECT MANY_ROWS" && m.tag == b'Q' {
                    large_reply = true;
                    let mut reply = many_rows();
                    reply.extend(msg(b'C', b"SELECT 2004\0"));
                    (reply, status)
                } else if upper == "COPY BIG TO STDOUT" && m.tag == b'Q' {
                    large_reply = true;
                    (copy_out(), status)
                } else if upper == "SELECT SLOW_LARGE" {
                    split_reply = true;
                    let mut reply = msg(b'D', &vec![b'x'; 32 * 1024 + 37]);
                    reply.extend(msg(b'C', b"SELECT 1\0"));
                    (reply, status)
                } else if upper == "SELECT FROM" {
                    (
                        crate::tcp::codec::build_error_response("42601", "syntax error"),
                        if status == b'I' { b'I' } else { b'E' },
                    )
                } else if status == b'E' && upper != "ROLLBACK" && upper != "COMMIT" {
                    (
                        crate::tcp::codec::build_error_response("25P02", "aborted"),
                        b'E',
                    )
                } else if upper == "BEGIN" {
                    (msg(b'C', b"BEGIN\0"), b'T')
                } else if upper == "COMMIT" || upper == "ROLLBACK" {
                    (msg(b'C', format!("{upper}\0").as_bytes()), b'I')
                } else if upper == "SELECT 1/0" {
                    (
                        crate::tcp::codec::build_error_response("22012", "division by zero"),
                        if status == b'I' { b'I' } else { b'E' },
                    )
                } else {
                    (msg(b'C', b"SELECT 1\0"), status)
                };
                let failed = reply[0] == b'E';
                status = next;
                if m.tag == b'Q' {
                    out.extend(reply);
                    out.extend(msg(b'Z', &[status]));
                } else if failed {
                    out.extend(reply);
                    skipping = true;
                } else {
                    out.extend(msg(b'1', b""));
                }
            }
            b'B' if !skipping => out.extend(msg(b'2', b"")),
            b'C' if !skipping => out.extend(msg(b'3', b"")),
            b'E' if !skipping => {
                if parsed == "SELECT MANY_ROWS" {
                    large_reply = true;
                    out.extend(many_rows());
                    out.extend(msg(b'C', b"SELECT 2004\0"));
                } else {
                    out.extend(msg(b'C', b"SELECT 1\0"));
                }
            }
            b'S' => {
                skipping = false;
                out.extend(msg(b'Z', &[status]));
            }
            _ => {}
        }
        if !out.is_empty() {
            if large_reply {
                let mut offset = 0;
                for width in [65_535usize, 1, 4, 65_537, 5, 6, 4_093, 70_000]
                    .into_iter()
                    .cycle()
                {
                    if offset == out.len() {
                        break;
                    }
                    let end = out.len().min(offset + width);
                    sock.write_all(&out[offset..end]).await?;
                    sock.flush().await?;
                    offset = end;
                    tokio::task::yield_now().await;
                }
            } else if split_reply {
                let mut offset = 0;
                for width in [1usize, 2, 3, 7, 16_383, 5, 8_191, usize::MAX] {
                    if offset == out.len() {
                        break;
                    }
                    let end = out.len().min(offset.saturating_add(width));
                    sock.write_all(&out[offset..end]).await?;
                    sock.flush().await?;
                    offset = end;
                    tokio::task::yield_now().await;
                }
            } else {
                sock.write_all(&out).await?;
            }
            sock.flush().await?;
        }
    }
}

async fn read_message<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<PgMessage> {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).await?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
    s.read_exact(&mut body).await?;
    Ok(PgMessage { tag: tag[0], body })
}

fn proxy_config(upstream: SocketAddr) -> PgProxyConfig {
    let (cfg, _queue) = super::sensitive_tests::config_with(
        (&upstream.ip().to_string(), upstream.port()),
        vericto_engine::EnforcementPolicy::default(),
        crate::tcp::rules_sync::TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    Arc::into_inner(cfg).expect("unshared config")
}

/// The proxy listening on an ephemeral port, every connection handled by the
/// real entrypoint.
async fn spawn_proxy(cfg: Arc<PgProxyConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(handle_connection(sock, cfg.clone()));
        }
    });
    addr
}

fn startup_message() -> Vec<u8> {
    let mut body = 196_608i32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0app\0database\0app\0\0");
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

/// Starts a session on `stream` and reads up to its first ReadyForQuery;
/// returns the BackendKeyData the client received.
async fn start_session<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> BackendKey {
    stream.write_all(&startup_message()).await.unwrap();
    let mut key = None;
    loop {
        let m = read_pg(stream).await;
        match m.tag {
            b'K' => key = BackendKey::parse(&m.body),
            b'Z' => return key.expect("BackendKeyData before ReadyForQuery"),
            _ => {}
        }
    }
}

async fn send_cancel(proxy: SocketAddr, key: &BackendKey) {
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&key.cancel_request()).await.unwrap();
    // Never answered: the proxy closes the connection.
    let mut buf = Vec::new();
    let n = timeout(c.read_to_end(&mut buf)).await.unwrap_or(0);
    assert_eq!(n, 0, "a CancelRequest is never answered");
}

/// The next CancelRequest the database received, or None within `ms`.
async fn next_cancel(pg: &mut FakePg, ms: u64) -> Option<Vec<u8>> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), pg.cancels.recv())
        .await
        .ok()
        .flatten()
}

/// A client that speaks TLS to the proxy, trusting `ca`.
async fn tls_client(
    proxy: SocketAddr,
    roots: tokio_rustls::rustls::RootCertStore,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    let mut ssl = 8i32.to_be_bytes().to_vec();
    ssl.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    tcp.write_all(&ssl).await.unwrap();
    let mut s = [0u8; 1];
    timeout(tcp.read_exact(&mut s)).await.unwrap();
    assert_eq!(s[0], b'S');
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    timeout(connector.connect(name, tcp)).await.unwrap()
}

/// A proxy with `PROXY_TLS_MODE=require` in front of a scripted Postgres, and
/// the roots that trust its certificate.
async fn require_tls_proxy() -> (
    SocketAddr,
    FakePg,
    Arc<PgProxyConfig>,
    tokio_rustls::rustls::RootCertStore,
) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let pg = fake_pg().await;
    let ca = crate::tcp::upstream::test_pki::TestCa::new("proxy test CA");
    let leaf = ca.issue(&["localhost"]);
    let mut cfg = proxy_config(pg.addr);
    cfg.client_tls_acceptor =
        Some(crate::tcp::client_tls::build_acceptor(&leaf.cert_pem, &leaf.key_pem).unwrap());
    let cfg = Arc::new(cfg);
    let proxy = spawn_proxy(cfg.clone()).await;
    (proxy, pg, cfg, ca.roots())
}

// ── CancelRequest ────────────────────────────────────────────────────────────

/// psql's Ctrl+C under `PROXY_TLS_MODE=require`: the session is over TLS, the
/// CancelRequest arrives in plaintext on a new connection, and reaches the
/// database byte for byte on a connection of its own.
#[tokio::test]
async fn require_tls_forwards_a_plaintext_cancel_for_an_open_session() {
    let (proxy, mut pg, cfg, roots) = require_tls_proxy().await;
    let mut session = tls_client(proxy, roots).await;
    let k = start_session(&mut session).await;
    assert_eq!(k, key(PID, &SECRET), "the server's key reaches the client");
    session
        .write_all(&pg_query(
            "SELECT count(*) FROM generate_series(1, 1000000000)",
        ))
        .await
        .unwrap();
    session.flush().await.unwrap();
    assert_eq!(
        timeout(pg.statements.recv()).await.unwrap(),
        "SELECT count(*) FROM generate_series(1, 1000000000)"
    );

    send_cancel(proxy, &k).await;
    assert_eq!(
        next_cancel(&mut pg, 2000).await.as_deref(),
        Some(&k.cancel_request()[..]),
        "the CancelRequest reaches the database unchanged"
    );
    assert_eq!(cfg.cancel_keys.len(), 1);
}

/// libpq 17's `PQcancelCreate` negotiates TLS for the cancel as the session
/// did: also forwarded.
#[tokio::test]
async fn require_tls_forwards_a_cancel_sent_over_tls() {
    let (proxy, mut pg, _cfg, roots) = require_tls_proxy().await;
    let mut session = tls_client(proxy, roots.clone()).await;
    let k = start_session(&mut session).await;
    let mut cancel = tls_client(proxy, roots).await;
    cancel.write_all(&k.cancel_request()).await.unwrap();
    let mut buf = Vec::new();
    let _ = timeout(cancel.read_to_end(&mut buf)).await;
    assert!(buf.is_empty());
    assert_eq!(
        next_cancel(&mut pg, 2000).await.as_deref(),
        Some(&k.cancel_request()[..])
    );
}

/// A wrong secret, a wrong pid, a malformed packet: nothing reaches the
/// database, and the session runs on.
#[tokio::test]
async fn a_cancel_with_a_wrong_key_is_ignored() {
    let (proxy, mut pg, _cfg, roots) = require_tls_proxy().await;
    let mut session = tls_client(proxy, roots).await;
    let k = start_session(&mut session).await;

    let mut wrong_secret = k.secret.to_vec();
    wrong_secret[3] ^= 0x01;
    send_cancel(proxy, &key(PID, &wrong_secret)).await;
    send_cancel(proxy, &key(PID + 1, &SECRET)).await;
    send_cancel(proxy, &key(PID, &[SECRET, SECRET].concat())).await;
    // A 3-byte secret: not a CancelRequest the server would accept either.
    let mut short = TcpStream::connect(proxy).await.unwrap();
    let mut bad = 15i32.to_be_bytes().to_vec();
    bad.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
    bad.extend_from_slice(&PID.to_be_bytes());
    bad.extend_from_slice(&SECRET[..3]);
    short.write_all(&bad).await.unwrap();
    let mut buf = Vec::new();
    let _ = timeout(short.read_to_end(&mut buf)).await;

    assert_eq!(next_cancel(&mut pg, 500).await, None, "nothing forwarded");
    session.write_all(&pg_query("SELECT 1")).await.unwrap();
    assert_eq!(read_pg(&mut session).await.tag, b'C', "the session runs on");
    assert_eq!(read_pg(&mut session).await.body, b"I");
}

/// A cancel while the session is idle is still the server's to judge (it
/// ignores one that finds no query running): forwarded, and the session
/// answers its next statement normally.
#[tokio::test]
async fn a_cancel_while_no_query_runs_is_forwarded_and_the_session_runs_on() {
    let (proxy, mut pg, _cfg, roots) = require_tls_proxy().await;
    let mut session = tls_client(proxy, roots).await;
    let k = start_session(&mut session).await;
    send_cancel(proxy, &k).await;
    assert!(next_cancel(&mut pg, 2000).await.is_some());
    session.write_all(&pg_query("SELECT 1")).await.unwrap();
    let c = read_pg(&mut session).await;
    assert_eq!((c.tag, cstr(&c.body).as_str()), (b'C', "SELECT 1"));
    assert_eq!(read_pg(&mut session).await.body, b"I");
}

/// Once the session closes its key is no longer one the proxy forwards.
#[tokio::test]
async fn a_cancel_after_the_session_closed_is_ignored() {
    let pg_ = fake_pg().await;
    let cfg = Arc::new(proxy_config(pg_.addr));
    let mut pg = pg_;
    let proxy = spawn_proxy(cfg.clone()).await;
    let mut session = TcpStream::connect(proxy).await.unwrap();
    let k = start_session(&mut session).await;
    assert_eq!(cfg.cancel_keys.len(), 1);

    // Plaintext proxy: a plaintext cancel for the open session is forwarded.
    send_cancel(proxy, &k).await;
    assert!(next_cancel(&mut pg, 2000).await.is_some());

    session.write_all(&msg(b'X', b"")).await.unwrap();
    drop(session);
    for _ in 0..100 {
        if cfg.cancel_keys.len() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(cfg.cancel_keys.len(), 0, "the key leaves with the session");
    send_cancel(proxy, &k).await;
    assert_eq!(next_cancel(&mut pg, 500).await, None);
}

// ── ReadyForQuery status of a refused statement, policy rules off ────────────

/// A plaintext session through a proxy with the default ruleset, policy
/// rules off (the default).
async fn flag_off_session() -> (TcpStream, FakePg) {
    let pg = fake_pg().await;
    let cfg = proxy_config(pg.addr);
    assert!(!cfg.policy_rules.mode.is_on(), "policy rules off");
    let proxy = spawn_proxy(Arc::new(cfg)).await;
    let mut s = TcpStream::connect(proxy).await.unwrap();
    start_session(&mut s).await;
    (s, pg)
}

/// Sends `sql` as a simple query; returns the reply's first message tag and the
/// ReadyForQuery status.
async fn simple<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, sql: &str) -> (u8, String, u8) {
    s.write_all(&pg_query(sql)).await.unwrap();
    s.flush().await.unwrap();
    let first = read_pg(s).await;
    let detail = if first.tag == b'E' {
        pg_error(&first.body).0
    } else {
        cstr(&first.body)
    };
    let z = read_pg(s).await;
    assert_eq!(z.tag, b'Z', "{sql}");
    (first.tag, detail, z.body[0])
}

async fn simple_block_status(s: &mut TcpStream, pg: &mut FakePg) -> u8 {
    let (tag, sqlstate, status) = simple(s, DANGEROUS).await;
    assert_eq!((tag, sqlstate.as_str()), (b'E', "42501"), "refused");
    while let Ok(sql) = pg.statements.try_recv() {
        assert_ne!(
            sql, DANGEROUS,
            "a refused statement never reaches the database"
        );
    }
    status
}

#[tokio::test]
async fn pipelined_slow_query_finishes_before_a_local_block() {
    let (mut s, mut pg) = flag_off_session().await;
    let mut pipeline = pg_query("SELECT slow_large");
    pipeline.extend(pg_query(DANGEROUS));
    s.write_all(&pipeline).await.unwrap();

    let row = read_pg(&mut s).await;
    assert_eq!(row.tag, b'D');
    assert_eq!(row.body.len(), 32 * 1024 + 37);
    assert!(row.body.iter().all(|b| *b == b'x'));
    for tag in [b'C', b'Z', b'E', b'Z'] {
        assert_eq!(read_pg(&mut s).await.tag, tag);
    }
    let seen = [
        timeout(pg.statements.recv()).await,
        timeout(pg.statements.recv()).await,
    ];
    assert_eq!(seen[0].as_deref(), Some("SELECT slow_large"));
    assert!(
        seen[1]
            .as_deref()
            .is_some_and(|sql| sql.contains("vericto ordered response marker"))
    );
}

#[tokio::test]
async fn three_pipelined_simple_queries_keep_a_middle_block_in_order() {
    let (mut s, mut pg) = flag_off_session().await;
    let mut pipeline = pg_query("SELECT 1");
    pipeline.extend(pg_query(DANGEROUS));
    pipeline.extend(pg_query("SELECT 2"));
    s.write_all(&pipeline).await.unwrap();

    for tag in [b'C', b'Z', b'E', b'Z', b'C', b'Z'] {
        assert_eq!(read_pg(&mut s).await.tag, tag);
    }
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(timeout(pg.statements.recv()).await);
    }
    assert_eq!(seen[0].as_deref(), Some("SELECT 1"));
    assert!(
        seen[1]
            .as_deref()
            .is_some_and(|sql| sql.contains("vericto ordered response marker"))
    );
    assert_eq!(seen[2].as_deref(), Some("SELECT 2"));
}

#[tokio::test]
async fn flag_off_block_while_idle_reports_idle() {
    let (mut s, mut pg) = flag_off_session().await;
    assert_eq!(simple_block_status(&mut s, &mut pg).await, b'I');
    assert_eq!(simple(&mut s, "SELECT 1").await.2, b'I');
}

#[tokio::test]
async fn flag_off_block_inside_begin_reports_in_transaction() {
    let (mut s, mut pg) = flag_off_session().await;
    assert_eq!(simple(&mut s, "BEGIN").await.2, b'T');
    assert_eq!(simple_block_status(&mut s, &mut pg).await, b'T');
    assert_eq!(simple(&mut s, "SELECT 1").await.2, b'T');
    assert_eq!(simple(&mut s, "COMMIT").await.2, b'I');
    assert_eq!(simple_block_status(&mut s, &mut pg).await, b'I');
}

#[tokio::test]
async fn flag_off_block_after_an_error_in_a_transaction_reports_failed() {
    let (mut s, mut pg) = flag_off_session().await;
    assert_eq!(simple(&mut s, "BEGIN").await.2, b'T');
    let (tag, sqlstate, status) = simple(&mut s, "SELECT 1/0").await;
    assert_eq!((tag, sqlstate.as_str(), status), (b'E', "22012", b'E'));
    assert_eq!(simple_block_status(&mut s, &mut pg).await, b'E');
    assert_eq!(simple(&mut s, "ROLLBACK").await.2, b'I');
    assert_eq!(simple_block_status(&mut s, &mut pg).await, b'I');
}

/// Parse/Bind/Execute/Sync of a refused statement: ErrorResponse, the rest
/// swallowed, and the Sync's ReadyForQuery carries the server's status.
#[tokio::test]
async fn an_earlier_extended_error_suppresses_a_later_local_rejection() {
    let (mut s, _pg) = flag_off_session().await;
    let mut pipeline = pg_parse("first", "SELECT FROM", &[]);
    pipeline.extend(pg_parse("blocked", DANGEROUS, &[]));
    pipeline.extend(msg(b'B', b"\0blocked\0\0\0\0\0\0"));
    pipeline.extend(msg(b'E', b"\0\0\0\0\0"));
    pipeline.extend(pg_sync());
    s.write_all(&pipeline).await.unwrap();

    let e = read_pg(&mut s).await;
    let (state, message) = pg_error(&e.body);
    assert_eq!(state, "42601", "the earlier server error wins: {message}");
    assert!(!message.contains("Vericto"));
    let z = read_pg(&mut s).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"I"[..]));
}

#[tokio::test]
async fn messages_pipelined_after_recovery_sync_keep_their_response_plans() {
    let (mut s, mut pg) = flag_off_session().await;
    s.write_all(&pg_parse("bad", "SELECT FROM", &[]))
        .await
        .unwrap();
    let e = read_pg(&mut s).await;
    assert_eq!(pg_error(&e.body).0, "42601");

    let mut recovery_and_next = pg_sync();
    recovery_and_next.extend(pg_query("SELECT 1"));
    s.write_all(&recovery_and_next).await.unwrap();
    assert_eq!(read_pg(&mut s).await.body, b"I");
    assert_eq!(read_pg(&mut s).await.tag, b'C');
    assert_eq!(read_pg(&mut s).await.body, b"I");
    assert_eq!(
        timeout(pg.statements.recv()).await.as_deref(),
        Some("SELECT FROM")
    );
    assert_eq!(
        timeout(pg.statements.recv()).await.as_deref(),
        Some("SELECT 1")
    );
}

#[tokio::test]
async fn multiple_extended_groups_and_flush_keep_order_without_round_trips() {
    let (mut s, _pg) = flag_off_session().await;
    let mut pipeline = pg_parse("ok", "SELECT 1", &[]);
    pipeline.extend(msg(b'B', b"p\0ok\0\0\0\0\0\0"));
    pipeline.extend(msg(b'E', b"p\0\0\0\0\0"));
    pipeline.extend(pg_parse("blocked", DANGEROUS, &[]));
    pipeline.extend(msg(b'B', b"q\0blocked\0\0\0\0\0\0"));
    pipeline.extend(msg(b'E', b"q\0\0\0\0\0"));
    pipeline.extend(msg(b'H', b""));
    pipeline.extend(pg_sync());
    s.write_all(&pipeline).await.unwrap();

    for tag in [b'1', b'2', b'C', b'E', b'Z'] {
        assert_eq!(read_pg(&mut s).await.tag, tag);
    }
}

#[tokio::test]
async fn flag_off_extended_block_reports_the_real_status_at_sync() {
    let (mut s, _pg) = flag_off_session().await;
    let extended = |sql: &str| {
        let mut b = pg_parse("", sql, &[]);
        b.extend(msg(b'B', b"\0\0\0\0\0\0\0\0"));
        b.extend(msg(b'E', b"\0\0\0\0\0"));
        b.extend(pg_sync());
        b
    };
    async fn blocked_extended(s: &mut TcpStream, bytes: &[u8]) -> u8 {
        s.write_all(bytes).await.unwrap();
        let e = read_pg(s).await;
        assert_eq!((e.tag, pg_error(&e.body).0.as_str()), (b'E', "42501"));
        let z = read_pg(s).await;
        assert_eq!(z.tag, b'Z');
        z.body[0]
    }
    assert_eq!(blocked_extended(&mut s, &extended(DANGEROUS)).await, b'I');
    assert_eq!(simple(&mut s, "BEGIN").await.2, b'T');
    assert_eq!(blocked_extended(&mut s, &extended(DANGEROUS)).await, b'E');
    // The intentionally invalid Parse has PostgreSQL's native transaction
    // semantics: the transaction is failed until rollback.
    s.write_all(&extended("SELECT 1")).await.unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'E');
    assert_eq!(read_pg(&mut s).await.body, b"E");
    assert_eq!(simple(&mut s, "ROLLBACK").await.2, b'I');
    assert_eq!(simple(&mut s, "BEGIN").await.2, b'T');
    // An allowed extended sequence still gets the server's own replies.
    s.write_all(&extended("SELECT 1")).await.unwrap();
    for want in [b'1', b'2', b'C'] {
        assert_eq!(read_pg(&mut s).await.tag, want);
    }
    assert_eq!(read_pg(&mut s).await.body, b"T");
    assert_eq!(simple(&mut s, "SELECT 1/0").await.2, b'E');
    assert_eq!(blocked_extended(&mut s, &extended(DANGEROUS)).await, b'E');
    assert_eq!(simple(&mut s, "ROLLBACK").await.2, b'I');
}

// ── Prepared policy refresh ──────────────────────────────────────────────────

async fn prepared_proxy() -> (TcpStream, FakePg, Arc<PgProxyConfig>) {
    let pg = fake_pg().await;
    let cfg = Arc::new(proxy_config(pg.addr));
    let proxy = spawn_proxy(cfg.clone()).await;
    let mut s = TcpStream::connect(proxy).await.unwrap();
    start_session(&mut s).await;
    (s, pg, cfg)
}

async fn parse_complete(s: &mut TcpStream, pg: &mut FakePg, name: &str, sql: &str) {
    s.write_all(&pg_parse(name, sql, &[])).await.unwrap();
    assert_eq!(timeout(pg.statements.recv()).await.as_deref(), Some(sql));
    assert_eq!(read_pg(s).await.tag, b'1');
}

fn bind_execute_sync(portal: &str, statement: &str) -> Vec<u8> {
    let mut bind = Vec::new();
    bind.extend_from_slice(portal.as_bytes());
    bind.push(0);
    bind.extend_from_slice(statement.as_bytes());
    bind.extend_from_slice(b"\0\0\0\0\0\0");
    let mut execute = portal.as_bytes().to_vec();
    execute.extend_from_slice(b"\0\0\0\0\0");
    let mut bytes = msg(b'B', &bind);
    bytes.extend(msg(b'E', &execute));
    bytes.extend(pg_sync());
    bytes
}

#[tokio::test]
async fn blocked_function_call_closes_without_running_a_query_marker() {
    let (mut s, _pg, cfg) = prepared_proxy().await;
    let deny: vericto_engine::AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "app": { "mode": "enforce", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));
    s.write_all(&msg(b'F', b"\0\0\0\0")).await.unwrap();
    let mut byte = [0u8; 1];
    let read = timeout(s.read(&mut byte)).await.unwrap();
    assert_eq!(read, 0, "the session closes without a marker response");
}

async fn time_policy_prepared_proxy(deadline: &str) -> (TcpStream, FakePg, Arc<PgProxyConfig>) {
    let pg = fake_pg().await;
    let mut cfg = proxy_config(pg.addr);
    let mut rules = crate::tcp::evaluator::default_ruleset();
    rules.push(vericto_engine::Rule {
        rule_id: "time-policy".into(),
        code: "POL-TIME".into(),
        severity: vericto_engine::Severity::High,
        default_action: vericto_engine::EnforcementAction::Block,
        rule_type: vericto_engine::RuleType::Custom,
        ast_condition_yaml: Some(format!(
            "rule: time-policy\napplies_to: {{ ops: [select] }}\ndeny_if: time.now >= timestamp('{deadline}')\naction: block\n"
        )),
    });
    let rules = Arc::new(rules);
    cfg.ruleset.store(Arc::clone(&rules));
    cfg.policy_rules = crate::tcp::policy_rules::PolicyRulesRuntime {
        mode: crate::tcp::policy_rules::PolicyRulesMode::Enforce,
        bundle: Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::tcp::policy_rules::bundle_from_sync(
                crate::tcp::policy_rules::PolicyRulesMode::Enforce,
                rules,
                None,
                "time-v1",
            ),
        )),
        listener: "127.0.0.1:5433".into(),
        database_id: Some("00000000-0000-0000-0000-000000000001".into()),
    };
    let cfg = Arc::new(cfg);
    let proxy = spawn_proxy(Arc::clone(&cfg)).await;
    let mut s = TcpStream::connect(proxy).await.unwrap();
    start_session(&mut s).await;
    (s, pg, cfg)
}

#[tokio::test]
async fn execute_rechecks_time_dependent_policies_without_an_arc_swap() {
    let deadline = (chrono::Utc::now() + chrono::Duration::seconds(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (mut s, mut pg, _cfg) = time_policy_prepared_proxy(&deadline).await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    s.write_all(&bind_execute_sync("portal", "named"))
        .await
        .unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'2');
    let e = read_pg(&mut s).await;
    let (state, message) = pg_error(&e.body);
    assert_eq!(state, "42501");
    assert!(message.contains("POL-TIME"), "{message}");
    assert_eq!(read_pg(&mut s).await.body, b"I");
}

#[tokio::test]
async fn prepared_statement_is_rechecked_after_an_access_policy_swap() {
    let (mut s, mut pg, cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "named", "SELECT id FROM customers").await;
    let deny: vericto_engine::AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "app": { "mode": "enforce", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));

    s.write_all(&bind_execute_sync("portal", "named"))
        .await
        .unwrap();
    let e = read_pg(&mut s).await;
    let (state, message) = pg_error(&e.body);
    assert_eq!(state, "42501");
    assert!(message.contains("VERICTO-087"), "{message}");
    let z = read_pg(&mut s).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"I"[..]));
}

#[tokio::test]
async fn execute_rechecks_a_portal_after_an_access_policy_swap() {
    let (mut s, mut pg, cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "named", "SELECT id FROM customers").await;
    let bind = b"portal\0named\0\0\0\0\0\0".to_vec();
    s.write_all(&msg(b'B', &bind)).await.unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'2');

    let deny: vericto_engine::AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "app": { "mode": "enforce", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));
    let mut execute = msg(b'E', b"portal\0\0\0\0\0");
    execute.extend(pg_sync());
    s.write_all(&execute).await.unwrap();
    let e = read_pg(&mut s).await;
    assert_eq!(pg_error(&e.body).0, "42501");
    let z = read_pg(&mut s).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"I"[..]));
}

#[tokio::test]
async fn portal_keeps_policy_state_after_its_statement_is_closed() {
    let (mut s, mut pg, cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "named", "SELECT id FROM customers").await;
    let mut bind_and_close = msg(b'B', b"portal\0named\0\0\0\0\0\0");
    bind_and_close.extend(msg(b'C', b"Snamed\0"));
    s.write_all(&bind_and_close).await.unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'2');
    assert_eq!(read_pg(&mut s).await.tag, b'3');

    let deny: vericto_engine::AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "app": { "mode": "enforce", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));
    let mut execute = msg(b'E', b"portal\0\0\0\0\0");
    execute.extend(pg_sync());
    s.write_all(&execute).await.unwrap();
    let e = read_pg(&mut s).await;
    assert_eq!(pg_error(&e.body).0, "42501");
    assert_eq!(read_pg(&mut s).await.body, b"I");
}

#[tokio::test]
async fn portal_keeps_the_old_unnamed_statement_after_it_is_replaced() {
    let (mut s, mut pg, cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "", "SELECT id FROM customers").await;
    s.write_all(&msg(b'B', b"portal\0\0\0\0\0\0\0\0"))
        .await
        .unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'2');
    parse_complete(&mut s, &mut pg, "", "SELECT 1").await;

    let deny: vericto_engine::AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "app": { "mode": "enforce", "entries": [] }
    }))
    .unwrap();
    cfg.agent_access.store(Arc::new(deny));
    let mut execute = msg(b'E', b"portal\0\0\0\0\0");
    execute.extend(pg_sync());
    s.write_all(&execute).await.unwrap();
    let e = read_pg(&mut s).await;
    let (_, message) = pg_error(&e.body);
    assert!(message.contains("VERICTO-087"), "{message}");
    assert_eq!(read_pg(&mut s).await.body, b"I");
}

#[tokio::test]
async fn prepared_statement_with_an_unchanged_snapshot_forwards_bind_and_execute() {
    let (mut s, mut pg, _cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    s.write_all(&bind_execute_sync("portal", "named"))
        .await
        .unwrap();
    for tag in [b'2', b'C', b'Z'] {
        assert_eq!(read_pg(&mut s).await.tag, tag);
    }
}

#[tokio::test]
async fn a_changed_prepared_rewrite_requires_reprepare() {
    let (mut s, mut pg, cfg) = prepared_proxy().await;
    parse_complete(&mut s, &mut pg, "named", "SELECT email FROM customers").await;
    let tag: vericto_engine::SensitiveColumn = serde_json::from_value(serde_json::json!({
        "table": "customers", "column": "email", "policy": "mask", "mask_style": "full"
    }))
    .unwrap();
    let policy = vericto_engine::EnforcementPolicy {
        sensitive_columns: vec![tag],
        ..vericto_engine::EnforcementPolicy::default()
    };
    cfg.policy.store(Arc::new(policy));

    s.write_all(&bind_execute_sync("portal", "named"))
        .await
        .unwrap();
    let e = read_pg(&mut s).await;
    let (state, message) = pg_error(&e.body);
    assert_eq!(state, "42501");
    assert!(message.contains("VERICTO-PREPARED-STALE"), "{message}");
    let z = read_pg(&mut s).await;
    assert_eq!((z.tag, z.body.as_slice()), (b'Z', &b"I"[..]));
}

// ── MySQL, policy rules off ──────────────────────────────────────────────────

/// MySQL's counterpart of the ReadyForQuery status is the status flags of an
/// OK / EOF packet (`SERVER_STATUS_IN_TRANS`, `SERVER_STATUS_AUTOCOMMIT`). With
/// policy rules off the proxy's only reply of its own is the ERR_Packet of a
/// refusal, which carries no status flags: the client keeps the flags of the
/// server's last OK, which stay true because the statement never ran. So the
/// refusal is the same bytes idle, inside BEGIN and after an error, and the
/// session's next OK comes from the server.
#[tokio::test]
async fn mysql_flag_off_block_is_a_status_free_err_in_every_state() {
    use super::sensitive_tests::{my_cmd, read_my};
    use crate::tcp::client_tls::{ClientRead, ClientWrite};
    use crate::tcp::codec_mysql::{COM_QUERY, MySqlPacket};
    use tokio::io::DuplexStream;
    use tokio::sync::Mutex;
    const IN_TRANS: u16 = 0x0001;
    const AUTOCOMMIT: u16 = 0x0002;
    let ok = |flags: u16| {
        let mut payload = vec![0x00, 0x00, 0x00];
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&[0, 0]);
        MySqlPacket { seq: 1, payload }.encode()
    };
    let (cfg, _queue) = super::sensitive_tests::config_with(
        ("unused", 0),
        vericto_engine::EnforcementPolicy::default(),
        crate::tcp::rules_sync::TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    assert!(!cfg.policy_rules.mode.is_on());
    // Wired as `run_mysql_session` does with the flag off: a plain relay, no
    // transaction state.
    let (mut client, proxy_client_side) = tokio::io::duplex(1 << 16);
    let (proxy_db_side, mut db) = tokio::io::duplex(1 << 16);
    let (cr, cw) = tokio::io::split(proxy_client_side);
    let (dr, dw) = tokio::io::split(proxy_db_side);
    let mut client_read: ClientRead = Box::new(cr);
    let client_write: Arc<Mutex<ClientWrite>> = Arc::new(Mutex::new(Box::new(cw)));
    let mut server_write: crate::tcp::upstream::UpstreamWrite = Box::new(dw);
    tokio::spawn(crate::tcp::session::relay_upstream_to_client(
        Box::new(dr),
        client_write.clone(),
        None,
    ));
    tokio::spawn(async move {
        crate::tcp::session::intercept_client_to_server(
            &crate::tcp::protocol::mysql::MysqlProtocol,
            &mut client_read,
            &mut server_write,
            &client_write,
            &cfg,
            crate::tcp::session::SessionStart::default(),
        )
        .await
    });

    async fn round(
        client: &mut DuplexStream,
        db: &mut DuplexStream,
        sql: &str,
        reply: Option<Vec<u8>>,
    ) -> MySqlPacket {
        client.write_all(&my_cmd(COM_QUERY, sql)).await.unwrap();
        if let Some(reply) = &reply {
            let m = read_my(db).await;
            assert_eq!(m.extract_sql().as_deref(), Some(sql));
            db.write_all(reply).await.unwrap();
        }
        let back = read_my(client).await;
        if let Some(reply) = reply {
            assert_eq!(back.encode(), reply, "the server's reply, unchanged");
        }
        back
    }
    let (c, d) = (&mut client, &mut db);
    let mut refusals = Vec::new();
    // Idle; inside BEGIN; after an error inside the transaction.
    refusals.push(round(c, d, DANGEROUS, None).await);
    round(c, d, "BEGIN", Some(ok(AUTOCOMMIT | IN_TRANS))).await;
    refusals.push(round(c, d, DANGEROUS, None).await);
    let err = crate::tcp::codec_mysql::build_err_packet(1, 1146, "42S02", "no such table");
    let sql = "SELECT id FROM missing WHERE id = 1 LIMIT 1";
    round(c, d, sql, Some(err)).await;
    refusals.push(round(c, d, DANGEROUS, None).await);
    // The transaction is still open on the server, for the client to end.
    round(c, d, "COMMIT", Some(ok(AUTOCOMMIT))).await;
    for r in &refusals {
        assert_eq!((r.seq, r.payload[0]), (1, 0xff), "an ERR_Packet");
        assert_eq!(r.payload, refusals[0].payload, "the same in every state");
    }
}

// ── Real Postgres (VERICTO_TEST_PG_URL) ──────────────────────────────────────

/// A driver's cancel (tokio-postgres sends a plaintext CancelRequest to the
/// address it connected to, the proxy) stops a running statement with 57014;
/// a cancel while the session is idle changes nothing; the session runs on.
#[tokio::test]
async fn real_pg_client_cancel_through_the_proxy() {
    super::sensitive_tests::with_real_pg(|via| async move {
        let c = super::sensitive_tests::connect(&via).await;
        let token = c.cancel_token();
        let running = tokio::spawn(async move {
            let r = c
                .simple_query("SELECT count(*) FROM generate_series(1, 20000000000)")
                .await;
            (c, r)
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        token.cancel_query(tokio_postgres::NoTls).await.unwrap();
        let (c, r) = timeout(running).await.unwrap();
        let err = r.expect_err("the statement is cancelled");
        assert_eq!(
            err.code(),
            Some(&tokio_postgres::error::SqlState::QUERY_CANCELED),
            "{err}"
        );

        token.cancel_query(tokio_postgres::NoTls).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = c.simple_query("SELECT 41 + 1").await.unwrap();
        let value = rows.iter().find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_string),
            _ => None,
        });
        assert_eq!(value.as_deref(), Some("42"), "the session runs on");
    })
    .await;
}

// ── 4.17.2: the relay's batched framing, end to end ─────────────────────────

/// Reads the client's next messages until `bytes` worth, as raw bytes.
async fn read_raw<S: AsyncRead + Unpin>(s: &mut S, n: usize) -> Vec<u8> {
    let mut got = vec![0u8; n];
    tokio::time::timeout(std::time::Duration::from_secs(20), s.read_exact(&mut got))
        .await
        .expect("the reply arrives")
        .unwrap();
    got
}

/// Long results, COPY OUT and three pipelined extended groups with a local
/// refusal in the middle, through the real session entrypoint, the upstream
/// sending its replies in pieces around the relay's 64 KiB buffer: every
/// byte arrives unchanged and in order, the refusal takes exactly the middle
/// group's place, and the session goes on.
async fn large_results_copy_and_pipelined_groups<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    pg: &mut FakePg,
) {
    let z = msg(b'Z', b"I");
    // Simple protocol: a long result.
    s.write_all(&pg_query("SELECT many_rows")).await.unwrap();
    s.flush().await.unwrap();
    let mut expected = many_rows();
    expected.extend(msg(b'C', b"SELECT 2004\0"));
    expected.extend(&z);
    assert!(read_raw(s, expected.len()).await == expected, "many_rows");

    // COPY OUT.
    s.write_all(&pg_query("COPY big TO STDOUT")).await.unwrap();
    s.flush().await.unwrap();
    let mut expected = copy_out();
    expected.extend(&z);
    assert!(read_raw(s, expected.len()).await == expected, "COPY OUT");

    // Pipelined groups: rows, a refusal, a plain statement.
    let group = |sql: &str| {
        let mut g = pg_parse("", sql, &[]);
        g.extend(msg(b'B', b"\0\0\0\0\0\0\0\0"));
        g.extend(msg(b'E', b"\0\0\0\0\0"));
        g.extend(pg_sync());
        g
    };
    let mut pipeline = group("SELECT many_rows");
    pipeline.extend(group(DANGEROUS));
    pipeline.extend(group("SELECT 1"));
    s.write_all(&pipeline).await.unwrap();
    s.flush().await.unwrap();
    let mut first = msg(b'1', b"");
    first.extend(msg(b'2', b""));
    first.extend(many_rows());
    first.extend(msg(b'C', b"SELECT 2004\0"));
    first.extend(&z);
    assert!(read_raw(s, first.len()).await == first, "first group");
    let refusal = read_pg(s).await;
    assert_eq!(
        (refusal.tag, pg_error(&refusal.body).0.as_str()),
        (b'E', "42501"),
        "the refusal takes the middle group's place"
    );
    assert_eq!(read_pg(s).await.body, b"I");
    let mut third = msg(b'1', b"");
    third.extend(msg(b'2', b""));
    third.extend(msg(b'C', b"SELECT 1\0"));
    third.extend(&z);
    assert!(read_raw(s, third.len()).await == third, "third group");

    let mut seen = Vec::new();
    while let Ok(sql) = pg.statements.try_recv() {
        seen.push(sql);
    }
    assert!(
        !seen.iter().any(|sql| sql == DANGEROUS),
        "never reaches the database"
    );
    // The session goes on.
    let (tag, _, status) = simple(s, "SELECT 1").await;
    assert_eq!((tag, status), (b'C', b'I'));
}

#[tokio::test]
async fn plaintext_relays_large_results_copy_and_pipelined_groups_in_order() {
    let (mut s, mut pg) = flag_off_session().await;
    large_results_copy_and_pipelined_groups(&mut s, &mut pg).await;
}

/// The same with TLS on both legs: `PROXY_TLS_MODE=require` toward the client
/// and `UPSTREAM_SSLMODE=require` toward the database.
#[tokio::test]
async fn tls_on_both_legs_relays_large_results_copy_and_pipelined_groups_in_order() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let db_ca = crate::tcp::upstream::test_pki::TestCa::new("fake postgres CA");
    let db_leaf = db_ca.issue(&["127.0.0.1"]);
    let mut pg = fake_pg_with(Some(crate::tcp::upstream::test_pki::server_config(
        &db_leaf, None,
    )))
    .await;
    let proxy_ca = crate::tcp::upstream::test_pki::TestCa::new("proxy test CA");
    let proxy_leaf = proxy_ca.issue(&["localhost"]);
    let mut cfg = proxy_config(pg.addr);
    cfg.upstream_tls = crate::tcp::upstream::UpstreamTlsMode::Require;
    cfg.client_tls_acceptor = Some(
        crate::tcp::client_tls::build_acceptor(&proxy_leaf.cert_pem, &proxy_leaf.key_pem).unwrap(),
    );
    let proxy = spawn_proxy(Arc::new(cfg)).await;
    let mut s = tls_client(proxy, proxy_ca.roots()).await;
    start_session(&mut s).await;
    large_results_copy_and_pipelined_groups(&mut s, &mut pg).await;
}

/// A real PostgreSQL through the 4.17.2 relay: rows under, at and well over
/// its 64 KiB buffer and a long result, by the simple and the extended
/// protocol, and prepared statements pipelined by the driver (joined
/// futures), each reply matched to its own statement.
#[tokio::test]
async fn real_pg_large_rows_and_pipelined_prepared_statements_through_the_relay() {
    super::sensitive_tests::with_real_pg(|via| async move {
        let c = super::sensitive_tests::connect(&via).await;
        // Simple protocol: 3,000 rows of growing size, then three large ones.
        let sql = "SELECT repeat(chr(97 + n % 26), n) FROM generate_series(1, 3000) n \
                   UNION ALL SELECT repeat('z', 65531) \
                   UNION ALL SELECT repeat('y', 65536) \
                   UNION ALL SELECT repeat('w', 300000)";
        let rows: Vec<String> = c
            .simple_query(sql)
            .await
            .unwrap()
            .iter()
            .filter_map(|m| match m {
                tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_string),
                _ => None,
            })
            .collect();
        assert_eq!(rows.len(), 3003);
        for (i, row) in rows.iter().take(3000).enumerate() {
            let n = i + 1;
            assert_eq!(row.len(), n);
            assert!(row.bytes().all(|b| b == b'a' + (n % 26) as u8), "row {n}");
        }
        assert_eq!(rows[3000].len(), 65531);
        assert_eq!(rows[3001].len(), 65536);
        assert_eq!(rows[3002].len(), 300000);

        // Extended protocol, the same result.
        let rows = c.query(sql, &[]).await.unwrap();
        assert_eq!(rows.len(), 3003);
        assert_eq!(rows[3002].get::<_, String>(0).len(), 300000);

        // Prepared statements, pipelined: every reply is its own.
        let echo = c
            .prepare("SELECT $1::int AS n, repeat('p', $1::int)")
            .await
            .unwrap();
        let sizes: Vec<i32> = (0..64).map(|i| (i * 2_053) % 90_000).collect();
        let mut replies = Vec::new();
        for n in sizes.chunks(8) {
            let p: Vec<[&(dyn tokio_postgres::types::ToSql + Sync); 1]> =
                n.iter().map(|v| [v as _]).collect();
            // Polled together, so the driver pipelines the eight.
            let r = tokio::join!(
                c.query_one(&echo, &p[0]),
                c.query_one(&echo, &p[1]),
                c.query_one(&echo, &p[2]),
                c.query_one(&echo, &p[3]),
                c.query_one(&echo, &p[4]),
                c.query_one(&echo, &p[5]),
                c.query_one(&echo, &p[6]),
                c.query_one(&echo, &p[7]),
            );
            for row in [r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7] {
                replies.push(row.unwrap());
            }
        }
        for (n, row) in sizes.iter().zip(&replies) {
            assert_eq!(row.get::<_, i32>(0), *n);
            assert_eq!(row.get::<_, String>(1).len(), *n as usize);
        }
    })
    .await;
}

// ── 4.17.3: Execute re-evaluation only for time-dependent policies ──────────

/// A business policy on every `select`, as a sync would deliver it.
fn policy_rule(code: &str, body: &str) -> vericto_engine::Rule {
    vericto_engine::Rule {
        rule_id: format!("rule-{code}"),
        code: code.into(),
        severity: vericto_engine::Severity::High,
        default_action: vericto_engine::EnforcementAction::Block,
        rule_type: vericto_engine::RuleType::Custom,
        ast_condition_yaml: Some(format!(
            "rule: {code}\napplies_to: {{ ops: [select] }}\n{body}\naction: block\n"
        )),
    }
}

/// The bundle a sync of the built-in ruleset plus `policies` compiles.
fn policy_bundle(
    policies: &[vericto_engine::Rule],
    version: &str,
) -> crate::tcp::policy_rules::PolicyRules {
    let mut rules = crate::tcp::evaluator::default_ruleset();
    rules.extend(policies.iter().cloned());
    crate::tcp::policy_rules::bundle_from_sync(
        crate::tcp::policy_rules::PolicyRulesMode::Enforce,
        Arc::new(rules),
        None,
        version,
    )
}

/// A session through the real entrypoint with policy rules enforced and
/// `policies` in force; the telemetry queue counts the evaluations.
async fn policy_proxy(
    policies: &[vericto_engine::Rule],
) -> (
    TcpStream,
    FakePg,
    Arc<PgProxyConfig>,
    Arc<crate::telemetry::queue::MemoryQueue>,
) {
    let pg = fake_pg().await;
    let (cfg, queue) = super::sensitive_tests::config_with(
        (&pg.addr.ip().to_string(), pg.addr.port()),
        vericto_engine::EnforcementPolicy::default(),
        crate::tcp::rules_sync::TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let mut cfg = Arc::into_inner(cfg).expect("unshared config");
    let bundle = policy_bundle(policies, "bundle-v1");
    cfg.ruleset
        .store(Arc::clone(bundle.rules.as_ref().unwrap()));
    cfg.policy_rules = crate::tcp::policy_rules::PolicyRulesRuntime {
        mode: crate::tcp::policy_rules::PolicyRulesMode::Enforce,
        bundle: Arc::new(arc_swap::ArcSwap::from_pointee(bundle)),
        listener: "127.0.0.1:5433".into(),
        database_id: Some("00000000-0000-0000-0000-000000000001".into()),
    };
    let cfg = Arc::new(cfg);
    let proxy = spawn_proxy(Arc::clone(&cfg)).await;
    let mut s = TcpStream::connect(proxy).await.unwrap();
    start_session(&mut s).await;
    (s, pg, cfg, queue)
}

/// The evaluations reported for `sql` since the last call.
fn evaluations_of(queue: &crate::telemetry::queue::MemoryQueue, sql: &str) -> usize {
    super::sensitive_tests::events(queue)
        .iter()
        .filter(|e| e["query_text"].as_str() == Some(sql))
        .count()
}

/// Bind (one text parameter when `param` is set), Execute, Sync; asserts
/// BindComplete, CommandComplete and ReadyForQuery.
async fn execute_ok(s: &mut TcpStream, statement: &str, param: Option<&str>) {
    let mut bind = b"portal\0".to_vec();
    bind.extend_from_slice(statement.as_bytes());
    bind.extend_from_slice(b"\0\0\0");
    match param {
        None => bind.extend_from_slice(b"\0\0"),
        Some(value) => {
            bind.extend_from_slice(&1i16.to_be_bytes());
            bind.extend_from_slice(&(value.len() as i32).to_be_bytes());
            bind.extend_from_slice(value.as_bytes());
        }
    }
    bind.extend_from_slice(b"\0\0");
    let mut bytes = msg(b'B', &bind);
    bytes.extend(msg(b'E', b"portal\0\0\0\0\0"));
    bytes.extend(pg_sync());
    s.write_all(&bytes).await.unwrap();
    assert_eq!(read_pg(s).await.tag, b'2');
    let c = read_pg(s).await;
    assert_eq!(c.tag, b'C', "{:?}", pg_error(&c.body));
    assert_eq!(read_pg(s).await.tag, b'Z');
}

/// Bind, Execute, Sync of `statement`: the Bind is refused by `code` (the
/// statement is evaluated again under the new snapshots at its Bind).
async fn bind_refused(s: &mut TcpStream, statement: &str, code: &str) {
    s.write_all(&bind_execute_sync("portal", statement))
        .await
        .unwrap();
    let e = read_pg(s).await;
    let (state, message) = pg_error(&e.body);
    assert_eq!(state, "42501");
    assert!(message.contains(code), "{message}");
    assert_eq!(read_pg(s).await.tag, b'Z');
}

#[test]
fn the_bundle_knows_whether_a_policy_reads_the_time() {
    let reads = |policies: &[vericto_engine::Rule]| policy_bundle(policies, "v").reads_time;
    // Nothing to read: no business policy.
    assert!(!reads(&[]));
    // Time-free: principal, statement, session, ticket and database fields.
    assert!(!reads(&[policy_rule(
        "POL-FREE",
        "deny_if: principal.type == \"agent\" && !stmt.has_where"
    )]));
    assert!(!reads(&[policy_rule(
        "POL-FREE2",
        "deny_if: session.tenant == \"x\" || db.env == \"prod\" || stmt.limit > 10"
    )]));
    // Any time field, with or without in_window; in `when` as in `deny_if`.
    for body in [
        "deny_if: in_window(time.now, \"Wed 03:00-03:01\", \"UTC\")",
        "deny_if: time.hour < 6",
        "deny_if: time.weekday == 0",
        "deny_if: time.tz != \"UTC\"",
        "when: time.minute > 30\ndeny_if: stmt.has_where",
    ] {
        assert!(reads(&[policy_rule("POL-TIME", body)]), "{body}");
    }
    // One time-dependent policy among time-free ones.
    assert!(reads(&[
        policy_rule("POL-A", "deny_if: principal.type == \"agent\""),
        policy_rule("POL-B", "require: time.hour >= 0"),
    ]));
    // A policy whose fields the engine cannot read counts as reading the time.
    assert!(reads(&[policy_rule(
        "POL-BROKEN",
        "deny_if: no.such.field =="
    )]));
}

#[tokio::test]
async fn execute_keeps_the_verdict_of_a_time_free_policy() {
    let (mut s, mut pg, _cfg, queue) = policy_proxy(&[policy_rule(
        "POL-FREE",
        "deny_if: principal.type == \"agent\"",
    )])
    .await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    assert_eq!(evaluations_of(&queue, "SELECT 1"), 1, "evaluated at Parse");
    for _ in 0..3 {
        execute_ok(&mut s, "named", None).await;
    }
    assert_eq!(
        evaluations_of(&queue, "SELECT 1"),
        0,
        "no Execute is evaluated again under the same snapshots"
    );
}

#[tokio::test]
async fn execute_rechecks_a_time_dependent_policy_every_time() {
    let (mut s, mut pg, _cfg, queue) = policy_proxy(&[policy_rule(
        "POL-TIME",
        "deny_if: time.now < timestamp('2000-01-01T00:00:00Z')",
    )])
    .await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    assert_eq!(evaluations_of(&queue, "SELECT 1"), 1);
    for _ in 0..3 {
        execute_ok(&mut s, "named", None).await;
    }
    assert_eq!(evaluations_of(&queue, "SELECT 1"), 3, "one per Execute");
}

#[tokio::test]
async fn a_bundle_swap_invalidates_a_time_free_verdict() {
    let free = policy_rule("POL-FREE", "deny_if: principal.type == \"agent\"");
    let (mut s, mut pg, cfg, queue) = policy_proxy(std::slice::from_ref(&free)).await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    execute_ok(&mut s, "named", None).await;
    assert_eq!(evaluations_of(&queue, "SELECT 1"), 1);

    // The same policies in a new bundle: evaluated again once, then reused.
    cfg.policy_rules.bundle.store(Arc::new(policy_bundle(
        std::slice::from_ref(&free),
        "bundle-v2",
    )));
    execute_ok(&mut s, "named", None).await;
    execute_ok(&mut s, "named", None).await;
    // The Bind finds the statement stale under the new bundle and evaluates
    // it again once; the portal it binds and every later Execute are fresh.
    assert_eq!(evaluations_of(&queue, "SELECT 1"), 1);

    // A bundle whose (time-free) policy now refuses the statement: the next
    // Execute is refused, although its Parse was allowed.
    cfg.policy_rules.bundle.store(Arc::new(policy_bundle(
        &[policy_rule(
            "POL-DENY",
            "deny_if: principal.type != \"agent\"",
        )],
        "bundle-v3",
    )));
    bind_refused(&mut s, "named", "POL-DENY").await;
}

#[tokio::test]
async fn a_session_context_change_invalidates_a_time_free_verdict() {
    let (mut s, mut pg, _cfg, _queue) = policy_proxy(&[policy_rule(
        "POL-TENANT",
        "deny_if: has(session.tenant) && session.tenant == \"acme\"",
    )])
    .await;
    parse_complete(&mut s, &mut pg, "named", "SELECT 1").await;
    execute_ok(&mut s, "named", None).await;
    // Consumed by the proxy: the session context changes.
    s.write_all(&pg_query("SET vericto.tenant = 'acme'"))
        .await
        .unwrap();
    assert_eq!(read_pg(&mut s).await.tag, b'C');
    assert_eq!(read_pg(&mut s).await.tag, b'Z');
    bind_refused(&mut s, "named", "POL-TENANT").await;
}

/// The engine evaluates a statement's SQL, never its Bind parameters, so no
/// verdict depends on a parameter value: a verdict reused across Executes
/// with different parameters is the one any of them would get. Here a
/// `LIMIT $1` is not known at Parse (`stmt.limit` is unknown, and
/// `on_unknown: flag` forwards it, flagged); binding 10 or 1,000,000 changes nothing.
#[tokio::test]
async fn a_reused_verdict_never_depends_on_bind_parameters() {
    let sql = "SELECT 1 LIMIT $1";
    let (mut s, mut pg, _cfg, queue) = policy_proxy(&[policy_rule(
        "POL-LIMIT",
        "deny_if: stmt.limit > 100\non_unknown: flag",
    )])
    .await;
    s.write_all(&pg_parse("named", sql, &[])).await.unwrap();
    let r = read_pg(&mut s).await;
    assert_eq!(r.tag, b'1', "{:?}", pg_error(&r.body));
    assert_eq!(timeout(pg.statements.recv()).await.as_deref(), Some(sql));
    assert_eq!(evaluations_of(&queue, sql), 1);
    for value in ["10", "1000000", "7"] {
        execute_ok(&mut s, "named", Some(value)).await;
    }
    assert_eq!(evaluations_of(&queue, sql), 0);
    // Written out, the bound that matters is refused at Parse whatever runs it.
    s.write_all(&pg_parse("big", "SELECT 1 LIMIT 1000000", &[]))
        .await
        .unwrap();
    let e = read_pg(&mut s).await;
    assert!(pg_error(&e.body).1.contains("POL-LIMIT"));
}

// ── 4.17.3: coalesced frontend writes, end to end ───────────────────────────

/// More Syncs in one client write than the response queue holds (4,096
/// plans): the session goes on as the database's answers free the queue.
/// What the frontend holds unsent never fills the queue on its own (the
/// coalescing bound is below 4,096 of the smallest messages), and it is sent
/// before the frontend waits for room anyway.
#[tokio::test]
async fn a_full_response_queue_sends_what_is_held_before_it_waits() {
    let (mut s, _pg, _cfg) = prepared_proxy().await;
    const SYNCS: usize = 6000;
    let bytes: Vec<u8> = (0..SYNCS).flat_map(|_| pg_sync()).collect();
    let (mut r, mut w) = s.split();
    let write = async { w.write_all(&bytes).await.unwrap() };
    let read = async {
        for _ in 0..SYNCS {
            assert_eq!(read_pg(&mut r).await.tag, b'Z');
        }
    };
    tokio::join!(write, read);
}

/// Extended groups pipelined in one client write, a refused Parse in the
/// middle, a Flush-terminated group: every response in order.
#[tokio::test]
async fn pipelined_groups_and_a_flush_through_coalesced_writes() {
    let (mut s, _pg, _cfg) = prepared_proxy().await;
    let group = |sql: &str| {
        let mut b = pg_parse("", sql, &[]);
        b.extend(msg(b'B', b"\0\0\0\0\0\0\0"));
        b.extend(msg(b'E', b"\0\0\0\0\0"));
        b.extend(pg_sync());
        b
    };
    let mut bytes = group("SELECT 1");
    bytes.extend(group(DANGEROUS));
    bytes.extend(group("SELECT 2"));
    // Then a group ended by Flush: answered without a Sync.
    bytes.extend(pg_parse("", "SELECT 3", &[]));
    bytes.extend(msg(b'B', b"\0\0\0\0\0\0\0"));
    bytes.extend(msg(b'E', b"\0\0\0\0\0"));
    bytes.extend(msg(b'H', b""));
    s.write_all(&bytes).await.unwrap();
    let mut tags = Vec::new();
    for _ in 0..13 {
        tags.push(read_pg(&mut s).await.tag);
    }
    assert_eq!(
        &tags[..],
        b"12CZEZ12CZ12C",
        "{:?}",
        String::from_utf8_lossy(&tags)
    );
}
