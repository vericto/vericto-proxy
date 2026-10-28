// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The upstream's version against the parser's (4.20.0), end to end: through
//! the real PostgreSQL session entrypoint against a scripted server that
//! reports a chosen `server_version`, the warning as it is logged, and the
//! real databases (`VERICTO_TEST_PG_URL`, `VERICTO_TEST_MYSQL_URL`; a
//! PostgreSQL 18 there runs the newer-than-the-parser path for real).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::sensitive_tests::{config_with, timeout};
use crate::tcp::codec::PgMessage;
use crate::tcp::rules_sync::TelemetryQueryMode;
use crate::tcp::upstream_version::{UpstreamVersions, global, parser_pg_major, pg_server_major};
use vericto_engine::EnforcementPolicy;

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    PgMessage {
        tag,
        body: body.to_vec(),
    }
    .encode()
}

/// What the scripted server sends after the StartupMessage, up to ReadyForQuery.
fn startup_reply(server_version: &[u8]) -> Vec<u8> {
    let mut reply = msg(b'R', &0i32.to_be_bytes());
    reply.extend(msg(b'S', b"client_encoding\0UTF8\0"));
    let mut sv = b"server_version\0".to_vec();
    sv.extend_from_slice(server_version);
    sv.push(0);
    reply.extend(msg(b'S', &sv));
    reply.extend(msg(b'S', b"TimeZone\0UTC\0"));
    reply.extend(msg(b'K', &[0, 0, 0, 7, 1, 2, 3, 4]));
    reply.extend(msg(b'Z', b"I"));
    reply
}

/// A PostgreSQL that trusts every StartupMessage, reports `server_version`,
/// and answers every simple Query with `SELECT 1`'s CommandComplete.
async fn scripted_pg(server_version: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                sock.read_exact(&mut len).await?;
                let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
                sock.read_exact(&mut body).await?;
                sock.write_all(&startup_reply(server_version)).await?;
                loop {
                    let mut header = [0u8; 5];
                    sock.read_exact(&mut header).await?;
                    let n = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
                    let mut rest = vec![0u8; n as usize - 4];
                    sock.read_exact(&mut rest).await?;
                    match header[0] {
                        b'X' => return Ok::<_, std::io::Error>(()),
                        b'Q' => {
                            let mut out = msg(b'C', b"SELECT 1\0");
                            out.extend(msg(b'Z', b"I"));
                            sock.write_all(&out).await?;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    addr
}

/// A proxy (default rules and policy) in front of `upstream`; its address.
async fn proxy_for(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let (cfg, _queue) = config_with(
        ("127.0.0.1", upstream.port()),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(crate::tcp::postgres::handle_connection(sock, cfg.clone()));
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

/// One session through the proxy: the startup bytes the client received, and
/// the reply to one simple query.
async fn session(proxy: std::net::SocketAddr, expected_startup: usize) -> (Vec<u8>, Vec<u8>) {
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&startup_message()).await.unwrap();
    let mut startup = vec![0u8; expected_startup];
    timeout(c.read_exact(&mut startup)).await.unwrap();
    c.write_all(&super::sensitive_tests::pg_query("SELECT 1"))
        .await
        .unwrap();
    let mut reply = vec![0u8; msg(b'C', b"SELECT 1\0").len() + 6];
    timeout(c.read_exact(&mut reply)).await.unwrap();
    c.write_all(&msg(b'X', b"")).await.unwrap();
    (startup, reply)
}

/// A server newer than the parser: every byte of its startup is relayed as it
/// came, statements run as before, and five connections give one warning.
#[tokio::test]
async fn a_newer_server_is_recorded_once_and_relayed_unchanged() {
    let upstream = scripted_pg(b"99.1 (Debian 99.1-1.pgdg120+1)").await;
    let target = format!("127.0.0.1:{}", upstream.port());
    let proxy = proxy_for(upstream).await;
    let sent = startup_reply(b"99.1 (Debian 99.1-1.pgdg120+1)");
    for _ in 0..5 {
        let (startup, reply) = session(proxy, sent.len()).await;
        assert_eq!(startup, sent, "the startup reaches the client unchanged");
        let mut expected = msg(b'C', b"SELECT 1\0");
        expected.extend(msg(b'Z', b"I"));
        assert_eq!(reply, expected, "statements are answered as before");
    }
    let r = global().report_for(&target).expect("recorded");
    assert_eq!(r.server_version, "99.1 (Debian 99.1-1.pgdg120+1)");
    assert_eq!(r.server_major, Some(99));
    assert_eq!(r.parser_major, parser_pg_major());
    assert!(r.newer_than_parser);
    assert_eq!(
        global().warnings(&target),
        1,
        "one warning for the upstream"
    );
}

/// Equal, older and unreadable versions: recorded, never warned about, and the
/// session is the same.
#[tokio::test]
async fn equal_older_and_unreadable_versions_do_not_warn() {
    let parser = parser_pg_major().unwrap();
    let equal: &'static [u8] = Box::leak(format!("{parser}.4").into_bytes().into_boxed_slice());
    for (version, major) in [
        (equal, Some(parser)),
        (&b"16.4 (Debian 16.4-1.pgdg120+2)"[..], Some(16)),
        (&b"not-a-version"[..], None),
        (&b"\xff\xfe"[..], None),
    ] {
        let upstream = scripted_pg(version).await;
        let target = format!("127.0.0.1:{}", upstream.port());
        let proxy = proxy_for(upstream).await;
        let sent = startup_reply(version);
        let (startup, _) = session(proxy, sent.len()).await;
        assert_eq!(startup, sent);
        let r = global().report_for(&target).expect("recorded");
        assert_eq!(r.server_major, major, "{version:?}");
        assert!(!r.newer_than_parser, "{version:?}");
        assert_eq!(global().warnings(&target), 0);
    }
}

thread_local! {
    /// The log lines of this thread while [`logged`] runs.
    static CAPTURE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Appends to this thread's [`CAPTURE`], or drops the bytes outside [`logged`].
struct ThreadCapture;

impl std::io::Write for ThreadCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURE.with(|c| {
            if let Some(out) = c.borrow_mut().as_mut() {
                out.extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The JSON log lines `tcp::upstream_version` writes on this thread during `f`.
///
/// Through a process-wide subscriber limited to that module, installed once: a
/// scoped one (`with_default`) can miss events whose callsite another test
/// thread registered first while no subscriber was set (tracing caches that
/// interest), which made this test flaky under the parallel runner.
fn logged(f: impl FnOnce()) -> Vec<serde_json::Value> {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(|| ThreadCapture);
        let only_this_module = tracing_subscriber::filter::Targets::new().with_target(
            concat!(env!("CARGO_CRATE_NAME"), "::tcp::upstream_version"),
            tracing::Level::DEBUG,
        );
        let subscriber = tracing_subscriber::registry().with(layer.with_filter(only_this_module));
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global subscriber in the tests");
    });
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    f();
    let out = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The warning: one, at WARN, under a stable `alert` with both versions and
/// the reason; the next connections log nothing; equal versions log at debug.
#[test]
fn the_warning_is_logged_once_with_what_an_operator_needs() {
    let table = UpstreamVersions::new();
    let lines = logged(|| {
        for _ in 0..3 {
            table.observe_postgres("db.internal:5432", b"99.1");
        }
    });
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(line["level"], "WARN");
    let f = &line["fields"];
    assert_eq!(f["alert"], "upstream_newer_than_parser");
    assert_eq!(f["upstream"], "db.internal:5432");
    assert_eq!(f["server_version"], "99.1");
    assert_eq!(f["server_major"], 99);
    assert_eq!(f["parser_major"], parser_pg_major().unwrap());
    let message = f["message"].as_str().unwrap();
    assert!(message.contains("VERICTO-PARSE-ERROR"), "{message}");
    assert!(message.contains("cannot be parsed"), "{message}");

    let parser = parser_pg_major().unwrap();
    let lines = logged(|| {
        table.observe_postgres("other:5432", format!("{parser}.2").as_bytes());
        table.observe_postgres("bad:5432", b"???");
        table.observe_mysql("my:3306", b"8.0.46");
    });
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().all(|l| l["level"] == "DEBUG"), "{lines:?}");
}

// ── Real databases ───────────────────────────────────────────────────────────

/// The PostgreSQL behind `VERICTO_TEST_PG_URL`: the version the proxy records
/// is the one the server reports, compared with the parser; one warning at most
/// however many sessions (the other real tests share this target). Against a
/// PostgreSQL newer than the parser, a statement only that version accepts is
/// a parse error through the proxy (refused here: `with_real_pg` tags block and
/// mask columns, so parse errors fail closed) while the database accepts it.
#[tokio::test]
async fn real_pg_the_server_version_is_recorded_against_the_parser() {
    let Some(url) = super::sensitive_tests::pg_url() else {
        eprintln!("VERICTO_TEST_PG_URL not set: skipping the real-Postgres test");
        return;
    };
    let admin: tokio_postgres::Config = url.parse().unwrap();
    let host = match &admin.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(h) => h.clone(),
        #[allow(unreachable_patterns)]
        _ => panic!("VERICTO_TEST_PG_URL must use a TCP host"),
    };
    let target = format!(
        "{host}:{}",
        admin.get_ports().first().copied().unwrap_or(5432)
    );
    super::sensitive_tests::with_real_pg(move |via| async move {
        let mut shown = None;
        for _ in 0..3 {
            let c = super::sensitive_tests::connect(&via).await;
            let rows = c.simple_query("SHOW server_version").await.unwrap();
            shown = rows.iter().find_map(|m| match m {
                tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_string),
                _ => None,
            });
        }
        let shown = shown.expect("SHOW server_version");
        let parser = parser_pg_major().unwrap();
        let r = global().report_for(&target).expect("recorded");
        assert_eq!(r.server_version, shown);
        let major = pg_server_major(&shown).unwrap();
        assert_eq!(r.server_major, Some(major));
        assert_eq!(r.newer_than_parser, major > parser, "{shown} vs {parser}");
        assert_eq!(global().warnings(&target), u32::from(major > parser));
        eprintln!(
            "server_version {shown}: parser {parser}, newer_than_parser {}",
            r.newer_than_parser
        );

        if major > parser && major >= 18 {
            // Virtual generated columns are PostgreSQL 18 syntax.
            let ddl = "CREATE TEMP TABLE vgen (a int, b int GENERATED ALWAYS AS (a * 2) VIRTUAL)";
            let c = super::sensitive_tests::connect(&via).await;
            let err = c.batch_execute(ddl).await.expect_err("a parse error");
            assert_eq!(
                err.code(),
                Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
            );
            let text = err.as_db_error().unwrap().message().to_string();
            assert!(text.contains("VERICTO-PARSE-ERROR"), "{text}");
            let direct = super::sensitive_tests::connect(&admin).await;
            direct
                .batch_execute(ddl)
                .await
                .expect("the database accepts it");
        }
    })
    .await;
}

/// The MySQL behind `VERICTO_TEST_MYSQL_URL`: its greeting's version is
/// recorded, with nothing to compare it with.
#[tokio::test]
async fn real_mysql_the_server_version_is_recorded() {
    let Some(url) = super::sensitive_tests::mysql_url() else {
        eprintln!("VERICTO_TEST_MYSQL_URL not set: skipping the real-MySQL test");
        return;
    };
    let admin = mysql_async::Opts::from_url(&url).unwrap();
    let target = format!("{}:{}", admin.ip_or_hostname(), admin.tcp_port());
    super::sensitive_tests::with_real_mysql(move |opts| async move {
        use mysql_async::prelude::Queryable;
        let mut c = mysql_async::Conn::new(opts).await.unwrap();
        let shown: String = c.query_first("SELECT VERSION()").await.unwrap().unwrap();
        c.disconnect().await.unwrap();
        let r = global().report_for(&target).expect("recorded");
        assert_eq!(r.server_version, shown);
        assert_eq!(
            r.dialect,
            crate::tcp::upstream_version::UpstreamDialect::Mysql
        );
        assert_eq!((r.server_major, r.parser_major), (None, None));
        assert!(!r.newer_than_parser);
        assert_eq!(global().warnings(&target), 0);
    })
    .await;
}
