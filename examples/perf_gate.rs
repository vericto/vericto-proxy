// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Workload driver of the CI performance gate (`perf/callgrind-gate.sh`,
//! `docs/PERFORMANCE.md`). Not part of the proxy binary.
//!
//! ```text
//! perf_gate setup --dialect pg|mysql --url URL
//!     creates and fills the corpus tables, directly on the database
//! perf_gate stub --listen ADDR --keys-out FILE [--telemetry sanitized|raw]
//!     a local control plane: one signed /sync/rules bundle (sanitized
//!     telemetry, sensitive-column masks, an agent-access allowlist, a business
//!     policy) and a 202 for every POST
//! perf_gate run --dialect pg|mysql --addr HOST:PORT --workload NAME
//!     --warmup W --count N [--mark CMD]
//!     connects through the proxy, runs W statements, runs CMD, runs N
//!     statements, runs CMD again, and prints one JSON line
//! ```
//!
//! Every workload is a fixed cycle of statements with deterministic literals,
//! sent one at a time (each waits for its answer), so the proxy executes the
//! same code for the same statements on every run. The JSON line carries an
//! outcome digest (rows or SQLSTATE + message of every measured statement): two
//! builds that answer any statement differently do not have the same digest.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Instant;

use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Rows of `perf_accounts`, and of `perf_users` / `perf_orders` / `perf_refunds`.
const ACCOUNTS: i32 = 10_000;
const USERS: i32 = 1_000;
/// Rows of the large-result statement.
const LARGE_ROWS: i32 = 2_000;

fn usage() -> ! {
    eprintln!(
        "usage: perf_gate setup --dialect pg|mysql --url URL\n       \
         perf_gate stub --listen ADDR --keys-out FILE [--telemetry sanitized|raw]\n       \
         perf_gate run --dialect pg|mysql --addr HOST:PORT --workload NAME --warmup W --count N [--mark CMD]\n       \
         perf_gate list"
    );
    std::process::exit(2)
}

struct Args(BTreeMap<String, String>);

impl Args {
    fn parse(raw: &[String]) -> Self {
        let mut map = BTreeMap::new();
        let mut it = raw.iter();
        while let Some(k) = it.next() {
            let Some(name) = k.strip_prefix("--") else {
                usage()
            };
            let Some(v) = it.next() else { usage() };
            map.insert(name.to_string(), v.clone());
        }
        Self(map)
    }
    fn get(&self, k: &str) -> &str {
        self.0.get(k).map(String::as_str).unwrap_or_else(|| usage())
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }
    fn num(&self, k: &str) -> usize {
        self.get(k).parse().unwrap_or_else(|_| usage())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Pg,
    My,
}

fn dialect(a: &Args) -> Dialect {
    match a.get("dialect") {
        "pg" | "postgres" => Dialect::Pg,
        "mysql" => Dialect::My,
        _ => usage(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // rustls is built with two providers (ring and aws-lc-rs): name the one the
    // proxy uses, for PERF_CLIENT_TLS.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else { usage() };
    let a = Args::parse(&argv[1..]);
    match cmd.as_str() {
        "setup" => match dialect(&a) {
            Dialect::Pg => pg::setup(a.get("url")).await,
            Dialect::My => my::setup(a.get("url")).await,
        },
        "stub" => {
            let telemetry = a.opt("telemetry").unwrap_or("sanitized");
            stub(a.get("listen"), a.get("keys-out"), telemetry).await
        }
        "run" => run(&a).await,
        // `dialect name cp`, one workload per line, for the gate script.
        "list" => {
            for w in WORKLOADS {
                println!("{} {} {}", w.dialect, w.name, u8::from(w.cp));
            }
        }
        _ => usage(),
    }
}

/// The workloads, by dialect. `cp` = measured against the stub's bundle (the
/// gate starts that proxy with the control plane), otherwise with none.
pub struct Workload {
    pub dialect: &'static str,
    pub name: &'static str,
    pub cp: bool,
}

pub const WORKLOADS: &[Workload] = &[
    Workload {
        dialect: "pg",
        name: "trivial",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "oltp_simple",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "oltp_extended",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "oltp_prepared",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "large_result",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "connect",
        cp: false,
    },
    Workload {
        dialect: "pg",
        name: "policy_mix",
        cp: true,
    },
    Workload {
        dialect: "pg",
        name: "trivial_cp",
        cp: true,
    },
    Workload {
        dialect: "mysql",
        name: "trivial",
        cp: false,
    },
    Workload {
        dialect: "mysql",
        name: "oltp_text",
        cp: false,
    },
    Workload {
        dialect: "mysql",
        name: "oltp_prepared",
        cp: false,
    },
    Workload {
        dialect: "mysql",
        name: "large_result",
        cp: false,
    },
    Workload {
        dialect: "mysql",
        name: "connect",
        cp: false,
    },
    Workload {
        dialect: "mysql",
        name: "policy_mix",
        cp: true,
    },
    Workload {
        dialect: "mysql",
        name: "trivial_cp",
        cp: true,
    },
];

/// The literals of statement `i`: deterministic and spread over the tables.
fn aid(i: usize) -> i32 {
    ((i as i64 * 7919) % ACCOUNTS as i64) as i32 + 1
}
fn tid(i: usize) -> i32 {
    (i % 10) as i32 + 1
}
fn bid(i: usize) -> i32 {
    (i % 2) as i32 + 1
}
fn delta(i: usize) -> i32 {
    (i % 1000) as i32 - 500
}
fn uid(i: usize) -> i32 {
    ((i as i64 * 31) % USERS as i64) as i32 + 1
}

/// The statements of one pgbench TPC-B-like transaction, in text, for the
/// text-protocol workloads (`$`-free; both dialects accept them).
fn tpcb_text(i: usize, begin: &str) -> [String; 7] {
    let (a, t, b, d) = (aid(i), tid(i), bid(i), delta(i));
    [
        begin.to_string(),
        format!("UPDATE perf_accounts SET abalance = abalance + {d} WHERE aid = {a}"),
        format!("SELECT abalance FROM perf_accounts WHERE aid = {a}"),
        format!("UPDATE perf_tellers SET tbalance = tbalance + {d} WHERE tid = {t}"),
        format!("UPDATE perf_branches SET bbalance = bbalance + {d} WHERE bid = {b}"),
        format!(
            "INSERT INTO perf_history (tid, bid, aid, delta, mtime) VALUES ({t}, {b}, {a}, {d}, CURRENT_TIMESTAMP)"
        ),
        "COMMIT".to_string(),
    ]
}

/// The policy mix, in text: masked columns, a join, writes, statements the
/// built-in rules, the allowlist and the business policy block, and literals
/// for sanitized telemetry to normalize.
fn policy_text(i: usize, d: Dialect) -> [String; 8] {
    let u = uid(i);
    let status = ["open", "shipped", "returned"][i % 3];
    let order_by = if d == Dialect::Pg {
        "ORDER BY o.created_at DESC"
    } else {
        "ORDER BY o.id DESC"
    };
    [
        format!("SELECT id, email, name FROM perf_users WHERE id = {u}"),
        format!(
            "SELECT o.id, o.total, u.name FROM perf_orders o JOIN perf_users u ON u.id = o.user_id \
             WHERE o.status = '{status}' AND o.user_id = {u} {order_by} LIMIT 20"
        ),
        format!("UPDATE perf_orders SET status = '{status}' WHERE id = {u}"),
        format!(
            "INSERT INTO perf_refunds (order_id, amount) VALUES ({u}, {})",
            100 + (i % 50)
        ),
        // Business policy (refund cap): blocked for the agent.
        format!("INSERT INTO perf_refunds (order_id, amount) VALUES ({u}, 950)"),
        // Built-in rule: DELETE without WHERE.
        "DELETE FROM perf_orders".to_string(),
        // Agent access: perf_accounts is not in the allowlist.
        format!("SELECT abalance FROM perf_accounts WHERE aid = {}", aid(i)),
        format!(
            "SELECT count(*) FROM perf_orders WHERE user_id = {u} AND status IN ('open', 'shipped')"
        ),
    ]
}

fn large_text() -> String {
    format!("SELECT aid, bid, abalance, filler FROM perf_accounts WHERE aid <= {LARGE_ROWS}")
}

/// FNV-1a over every outcome, in order.
struct Digest(u64);
impl Digest {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
    fn add(&mut self, s: &str) {
        for b in s.bytes().chain(std::iter::once(0)) {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

#[derive(Default)]
struct Tally {
    ok: usize,
    err: usize,
    rows: usize,
}

async fn run(a: &Args) {
    let d = dialect(a);
    let name = a.get("workload").to_string();
    let warmup = a.num("warmup");
    let count = a.num("count");
    let mark = a.opt("mark").map(str::to_string);
    let addr = a.get("addr");
    let mut digest = Digest::new();
    let mut tally = Tally::default();
    // With the control plane, telemetry events are built off the query path.
    let settle = name == "connect" || WORKLOADS.iter().any(|w| w.name == name && w.cp);
    let mark = mark.as_deref();
    let elapsed = match d {
        Dialect::Pg => {
            pg::run(
                addr,
                &name,
                warmup,
                count,
                settle,
                mark,
                &mut digest,
                &mut tally,
            )
            .await
        }
        Dialect::My => {
            my::run(
                addr,
                &name,
                warmup,
                count,
                settle,
                mark,
                &mut digest,
                &mut tally,
            )
            .await
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "dialect": a.get("dialect"),
            "workload": name,
            "count": count,
            "ok": tally.ok,
            "errors": tally.err,
            "rows": tally.rows,
            "digest": format!("{:016x}", digest.0),
            "elapsed_ms": elapsed.as_millis() as u64,
        })
    );
}

fn run_mark(mark: Option<&str>) {
    if let Some(cmd) = mark {
        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .expect("mark command");
        assert!(status.success(), "mark command failed: {cmd}");
    }
}

/// Runs `warmup` statements, the mark, `count` statements, the mark; only the
/// measured ones enter the digest. Returns the measured wall time.
#[allow(clippy::too_many_arguments)]
async fn phases<F, Fut>(
    warmup: usize,
    count: usize,
    settle: bool,
    mark: Option<&str>,
    digest: &mut Digest,
    tally: &mut Tally,
    mut step: F,
) -> std::time::Duration
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<usize, String>>,
{
    for i in 0..warmup {
        let _ = step(i).await;
    }
    // Work the proxy finishes after answering (the teardown of a connection, a
    // telemetry event built off the query path) belongs to the phase it came
    // from: let it finish before each mark.
    if settle {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    run_mark(mark);
    let start = Instant::now();
    for i in warmup..warmup + count {
        match step(i).await {
            Ok(rows) => {
                tally.ok += 1;
                tally.rows += rows;
                digest.add(&format!("ok {rows}"));
            }
            Err(e) => {
                tally.err += 1;
                digest.add(&e);
            }
        }
    }
    let elapsed = start.elapsed();
    if settle {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    run_mark(mark);
    elapsed
}

mod pg {
    use super::*;
    use tokio_postgres::types::{ToSql, Type};
    use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

    async fn connect(conn: &str) -> Client {
        let (client, connection) = tokio_postgres::connect(conn, NoTls)
            .await
            .unwrap_or_else(|e| panic!("connect {conn}: {e}"));
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    fn outcome(e: tokio_postgres::Error) -> String {
        match e.as_db_error() {
            Some(db) => format!("err {} {}", db.code().code(), db.message()),
            None => format!("err {e}"),
        }
    }

    async fn simple(c: &Client, sql: &str) -> Result<usize, String> {
        let msgs = c.simple_query(sql).await.map_err(outcome)?;
        Ok(msgs
            .iter()
            .filter(|m| matches!(m, SimpleQueryMessage::Row(_)))
            .count())
    }

    pub async fn setup(url: &str) {
        let c = connect(url).await;
        c.batch_execute(&format!(
            "DROP TABLE IF EXISTS perf_accounts, perf_tellers, perf_branches, perf_history, \
                perf_users, perf_orders, perf_refunds;
             CREATE TABLE perf_branches (bid int PRIMARY KEY, bbalance int NOT NULL DEFAULT 0, filler char(88));
             CREATE TABLE perf_tellers (tid int PRIMARY KEY, bid int NOT NULL, tbalance int NOT NULL DEFAULT 0, filler char(84));
             CREATE TABLE perf_accounts (aid int PRIMARY KEY, bid int NOT NULL, abalance int NOT NULL DEFAULT 0, filler char(84));
             CREATE TABLE perf_history (tid int, bid int, aid int, delta int, mtime timestamp, filler char(22));
             CREATE TABLE perf_users (id int PRIMARY KEY, email text NOT NULL, name text NOT NULL, created_at timestamp NOT NULL DEFAULT now());
             CREATE TABLE perf_orders (id int PRIMARY KEY, user_id int NOT NULL, total numeric(10,2) NOT NULL, status text NOT NULL, created_at timestamp NOT NULL DEFAULT now());
             CREATE TABLE perf_refunds (id serial PRIMARY KEY, order_id int NOT NULL, amount numeric(10,2) NOT NULL);
             INSERT INTO perf_branches SELECT g, 0, '' FROM generate_series(1, 2) g;
             INSERT INTO perf_tellers SELECT g, (g % 2) + 1, 0, '' FROM generate_series(1, 10) g;
             INSERT INTO perf_accounts SELECT g, (g % 2) + 1, 0, repeat('x', 84) FROM generate_series(1, {ACCOUNTS}) g;
             INSERT INTO perf_users SELECT g, 'user' || g || '@example.com', 'User ' || g, timestamp '2026-01-01' FROM generate_series(1, {USERS}) g;
             INSERT INTO perf_orders SELECT g, g, g * 1.5, (ARRAY['open','shipped','returned'])[g % 3 + 1], timestamp '2026-01-01' FROM generate_series(1, {USERS}) g;
             "
        ))
        .await
        .expect("setup");
        c.batch_execute("VACUUM ANALYZE").await.expect("vacuum");
        println!("pg setup done");
    }

    /// The pgbench transaction with parameters, for the extended workloads.
    const TPCB: [(&str, &[Type]); 7] = [
        ("BEGIN", &[]),
        (
            "UPDATE perf_accounts SET abalance = abalance + $1 WHERE aid = $2",
            &[Type::INT4, Type::INT4],
        ),
        (
            "SELECT abalance FROM perf_accounts WHERE aid = $1",
            &[Type::INT4],
        ),
        (
            "UPDATE perf_tellers SET tbalance = tbalance + $1 WHERE tid = $2",
            &[Type::INT4, Type::INT4],
        ),
        (
            "UPDATE perf_branches SET bbalance = bbalance + $1 WHERE bid = $2",
            &[Type::INT4, Type::INT4],
        ),
        (
            "INSERT INTO perf_history (tid, bid, aid, delta, mtime) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)",
            &[Type::INT4, Type::INT4, Type::INT4, Type::INT4],
        ),
        ("COMMIT", &[]),
    ];

    fn tpcb_params(i: usize) -> Vec<i32> {
        let (a, t, b, d) = (aid(i / 7), tid(i / 7), bid(i / 7), delta(i / 7));
        match i % 7 {
            1 => vec![d, a],
            2 => vec![a],
            3 => vec![d, t],
            4 => vec![d, b],
            5 => vec![t, b, a, d],
            _ => vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        addr: &str,
        name: &str,
        warmup: usize,
        count: usize,
        settle: bool,
        mark: Option<&str>,
        digest: &mut Digest,
        tally: &mut Tally,
    ) -> std::time::Duration {
        let (host, port) = addr.rsplit_once(':').expect("HOST:PORT");
        let conn_str = format!(
            "host={host} port={port} user=bench password=bench dbname=bench application_name=perf_gate"
        );
        let c = connect(&conn_str).await;
        let c = &c;
        let conn_str = &conn_str;
        match name {
            // A connection per statement: start-up, authentication and teardown
            // through the proxy, then one SELECT 1.
            "connect" => {
                phases(warmup, count, settle, mark, digest, tally, |_| async move {
                    let (client, connection) = tokio_postgres::connect(conn_str, NoTls)
                        .await
                        .map_err(outcome)?;
                    let task = tokio::spawn(connection);
                    let rows = simple(&client, "SELECT 1").await;
                    drop(client);
                    let _ = task.await;
                    rows
                })
                .await
            }
            "trivial" | "trivial_cp" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    simple(c, ["BEGIN", "SELECT 1", "COMMIT"][i % 3]).await
                })
                .await
            }
            "oltp_simple" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    simple(c, &tpcb_text(i / 7, "BEGIN")[i % 7]).await
                })
                .await
            }
            "oltp_extended" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    let (sql, types) = TPCB[i % 7];
                    let params = tpcb_params(i);
                    let typed: Vec<(&(dyn ToSql + Sync), Type)> = params
                        .iter()
                        .zip(types.iter())
                        .map(|(p, t)| (p as &(dyn ToSql + Sync), t.clone()))
                        .collect();
                    c.query_typed(sql, &typed)
                        .await
                        .map(|rows| rows.len())
                        .map_err(outcome)
                })
                .await
            }
            "oltp_prepared" => {
                let mut stmts = Vec::new();
                for (sql, types) in TPCB {
                    stmts.push(c.prepare_typed(sql, types).await.expect("prepare"));
                }
                let stmts = &stmts;
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    let params = tpcb_params(i);
                    let refs: Vec<&(dyn ToSql + Sync)> =
                        params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                    c.query(&stmts[i % 7], &refs)
                        .await
                        .map(|rows| rows.len())
                        .map_err(outcome)
                })
                .await
            }
            "large_result" => {
                let sql = large_text();
                let sql = &sql;
                phases(warmup, count, settle, mark, digest, tally, |_| async move {
                    simple(c, sql).await
                })
                .await
            }
            "policy_mix" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    simple(c, &policy_text(i / 8, Dialect::Pg)[i % 8]).await
                })
                .await
            }
            _ => usage(),
        }
    }
}

mod my {
    use super::*;
    use mysql_async::prelude::*;
    use mysql_async::{Conn, Opts, OptsBuilder};

    async fn connect(opts: Opts) -> Conn {
        Conn::new(opts).await.expect("mysql connect")
    }

    fn outcome(e: mysql_async::Error) -> String {
        match e {
            mysql_async::Error::Server(s) => format!("err {} {}", s.code, s.message),
            other => format!("err {other}"),
        }
    }

    async fn text(c: &mut Conn, sql: &str) -> Result<usize, String> {
        let rows: Vec<mysql_async::Row> = c.query(sql).await.map_err(outcome)?;
        Ok(rows.len())
    }

    pub async fn setup(url: &str) {
        let mut c = connect(Opts::from_url(url).expect("mysql url")).await;
        let stmts = [
            "DROP TABLE IF EXISTS perf_accounts, perf_tellers, perf_branches, perf_history, perf_users, perf_orders, perf_refunds".to_string(),
            "CREATE TABLE perf_branches (bid int PRIMARY KEY, bbalance int NOT NULL DEFAULT 0, filler char(88))".into(),
            "CREATE TABLE perf_tellers (tid int PRIMARY KEY, bid int NOT NULL, tbalance int NOT NULL DEFAULT 0, filler char(84))".into(),
            "CREATE TABLE perf_accounts (aid int PRIMARY KEY, bid int NOT NULL, abalance int NOT NULL DEFAULT 0, filler char(84))".into(),
            "CREATE TABLE perf_history (tid int, bid int, aid int, delta int, mtime timestamp NULL, filler char(22))".into(),
            "CREATE TABLE perf_users (id int PRIMARY KEY, email varchar(255) NOT NULL, name varchar(255) NOT NULL, created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP)".into(),
            "CREATE TABLE perf_orders (id int PRIMARY KEY, user_id int NOT NULL, total decimal(10,2) NOT NULL, status varchar(32) NOT NULL, created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP)".into(),
            "CREATE TABLE perf_refunds (id int AUTO_INCREMENT PRIMARY KEY, order_id int NOT NULL, amount decimal(10,2) NOT NULL)".into(),
            "SET SESSION cte_max_recursion_depth = 100000".into(),
            "INSERT INTO perf_branches VALUES (1, 0, ''), (2, 0, '')".into(),
            "INSERT INTO perf_tellers WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 10) SELECT n, (n % 2) + 1, 0, '' FROM g".into(),
            format!("INSERT INTO perf_accounts WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < {ACCOUNTS}) SELECT n, (n % 2) + 1, 0, REPEAT('x', 84) FROM g"),
            format!("INSERT INTO perf_users WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < {USERS}) SELECT n, CONCAT('user', n, '@example.com'), CONCAT('User ', n), '2026-01-01' FROM g"),
            format!("INSERT INTO perf_orders WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < {USERS}) SELECT n, n, n * 1.5, ELT(n % 3 + 1, 'open', 'shipped', 'returned'), '2026-01-01' FROM g"),
            "ANALYZE TABLE perf_accounts, perf_users, perf_orders".into(),
        ];
        for s in stmts {
            c.query_drop(&s)
                .await
                .unwrap_or_else(|e| panic!("{s}: {e}"));
        }
        println!("mysql setup done");
    }

    /// The pgbench transaction with `?` parameters (COM_STMT_PREPARE once per
    /// text, then COM_STMT_EXECUTE: mysql_async caches the statements).
    const TPCB: [&str; 7] = [
        "BEGIN",
        "UPDATE perf_accounts SET abalance = abalance + ? WHERE aid = ?",
        "SELECT abalance FROM perf_accounts WHERE aid = ?",
        "UPDATE perf_tellers SET tbalance = tbalance + ? WHERE tid = ?",
        "UPDATE perf_branches SET bbalance = bbalance + ? WHERE bid = ?",
        "INSERT INTO perf_history (tid, bid, aid, delta, mtime) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
        "COMMIT",
    ];

    fn tpcb_params(i: usize) -> mysql_async::Params {
        let (a, t, b, d) = (aid(i / 7), tid(i / 7), bid(i / 7), delta(i / 7));
        match i % 7 {
            1 => (d, a).into(),
            2 => (a,).into(),
            3 => (d, t).into(),
            4 => (d, b).into(),
            5 => (t, b, a, d).into(),
            _ => mysql_async::Params::Empty,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        addr: &str,
        name: &str,
        warmup: usize,
        count: usize,
        settle: bool,
        mark: Option<&str>,
        digest: &mut Digest,
        tally: &mut Tally,
    ) -> std::time::Duration {
        let (host, port) = addr.rsplit_once(':').expect("HOST:PORT");
        let opts = OptsBuilder::default()
            .ip_or_hostname(host)
            .tcp_port(port.parse().expect("port"))
            .user(Some("bench"))
            .pass(Some("bench"))
            .db_name(Some("bench"))
            .prefer_socket(false)
            // PERF_CLIENT_TLS=1: TLS to the proxy (PROXY_TLS_MODE=require; MySQL
            // needs TLS on both hops or neither). The proxy's certificate is not
            // verified: the driver measures, it does not authenticate.
            .ssl_opts(
                (std::env::var("PERF_CLIENT_TLS").as_deref() == Ok("1")).then(|| {
                    mysql_async::SslOpts::default().with_danger_accept_invalid_certs(true)
                }),
            );
        // One statement at a time: the lock only lets each step's future
        // borrow the connection mutably.
        let c = tokio::sync::Mutex::new(connect(opts.clone().into()).await);
        let c = &c;
        let opts = &opts;
        match name {
            // A connection per statement: handshake, authentication and COM_QUIT
            // through the proxy, then one SELECT 1.
            "connect" => {
                phases(warmup, count, settle, mark, digest, tally, |_| async move {
                    let mut conn = Conn::new(opts.clone()).await.map_err(outcome)?;
                    let rows = text(&mut conn, "SELECT 1").await;
                    conn.disconnect().await.map_err(outcome)?;
                    rows
                })
                .await
            }
            "trivial" | "trivial_cp" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    text(&mut *c.lock().await, ["BEGIN", "SELECT 1", "COMMIT"][i % 3]).await
                })
                .await
            }
            "oltp_text" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    text(&mut *c.lock().await, &tpcb_text(i / 7, "BEGIN")[i % 7]).await
                })
                .await
            }
            "oltp_prepared" => {
                // BEGIN and COMMIT go as text, as drivers send them.
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    let mut conn = c.lock().await;
                    if i % 7 == 0 || i % 7 == 6 {
                        return text(&mut conn, TPCB[i % 7]).await;
                    }
                    let rows: Result<Vec<mysql_async::Row>, _> =
                        conn.exec(TPCB[i % 7], tpcb_params(i)).await;
                    rows.map(|r| r.len()).map_err(outcome)
                })
                .await
            }
            "large_result" => {
                let sql = large_text();
                let sql = &sql;
                phases(warmup, count, settle, mark, digest, tally, |_| async move {
                    text(&mut *c.lock().await, sql).await
                })
                .await
            }
            "policy_mix" => {
                phases(warmup, count, settle, mark, digest, tally, |i| async move {
                    text(
                        &mut *c.lock().await,
                        &policy_text(i / 8, Dialect::My)[i % 8],
                    )
                    .await
                })
                .await
            }
            _ => usage(),
        }
    }
}

/// The bundle the stub serves: the built-in rules plus the refund-cap business
/// policy, sanitized telemetry, an e-mail mask, and an enforced allowlist for
/// `bench` that leaves `perf_accounts` out (VERICTO-087 in the mix).
fn bundle(telemetry: &str) -> String {
    fn lower<T: std::fmt::Debug>(v: T) -> String {
        format!("{v:?}").to_ascii_lowercase()
    }
    let mut rules: Vec<serde_json::Value> = vericto_engine::standard_rules()
        .iter()
        .map(|r| {
            serde_json::json!({
                "rule_id": r.rule_id, "code": r.code, "severity": lower(r.severity),
                "default_action": lower(r.default_action), "rule_type": lower(r.rule_type),
                "ast_condition_yaml": r.ast_condition_yaml,
            })
        })
        .collect();
    rules.push(serde_json::json!({
        "rule_id": "r-refund-cap", "code": "POL-014", "severity": "high",
        "default_action": "block", "rule_type": "custom",
        "ast_condition_yaml": "rule: refund-cap\napplies_to: { ops: [insert, update], tables: [\"perf_refunds\"], principal_types: [agent] }\ndeny_if: stmt.values(\"perf_refunds.amount\").exists(v, double(v) > 200.0)\naction: block\n",
    }));
    let table = |t: &str, cols: serde_json::Value, access: &str| serde_json::json!({ "table": t, "columns": cols, "access": access });
    serde_json::json!({
        "version": "perf-gate-1",
        "rules": rules,
        "policy": {
            "severity_actions": {"critical": "block", "high": "block", "medium": "flag",
                                 "low": "monitor", "informational": "monitor"},
            "parse_error_action": "allow_report",
            "monitor_mode": false,
            "telemetry_query_mode": telemetry,
        },
        "sensitive_columns": [
            {"schema": null, "table": "perf_users", "column": "email", "policy": "mask", "mask_style": "email"}
        ],
        "agent_access": {
            "bench": { "mode": "enforce", "ddl": "deny", "entries": [
                table("perf_users", serde_json::json!("*"), "read"),
                table("perf_orders", serde_json::json!("*"), "read_write"),
                table("perf_refunds", serde_json::json!("*"), "read_write"),
            ]}
        },
        "principals": {"version": "p1", "entries": [
            {"id": "perf-agent", "type": "agent", "identify": {"db_user": "bench"}}
        ]},
        "telemetry_quota": "ok",
    })
    .to_string()
}

async fn stub(listen: &str, keys_out: &str, telemetry: &str) {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::{any, get};

    // A signing key generated per run: no private key is ever committed.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key");
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(pair.public_key().as_ref());
    let keys = serde_json::json!([{
        "key_id": "perf-gate",
        "public_key": format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64.encode(&spki)),
    }]);
    std::fs::write(keys_out, keys.to_string()).expect("write keys");

    let body = bundle(telemetry);
    let mut input = b"vericto-sync-bundle/1\n".to_vec();
    input.extend_from_slice(body.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let sig = pair.sign(digest.as_ref());
    let header = format!(
        "scheme=ed25519-sha256; key-id=perf-gate; sha256={hex}; sig={}",
        b64.encode(sig.as_ref())
    );
    let app = Router::new()
        .route(
            "/api/v1/sync/rules",
            get(move || {
                let (body, header) = (body.clone(), header.clone());
                async move {
                    (
                        [
                            ("X-Vericto-Bundle-Signature", header),
                            ("ETag", "\"perf-gate-1\"".to_string()),
                            ("Content-Type", "application/json".to_string()),
                        ],
                        body,
                    )
                }
            }),
        )
        .fallback(any(|| async { StatusCode::ACCEPTED }));
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind");
    eprintln!("perf_gate stub on {listen}");
    axum::serve(listener, app).await.expect("serve");
}
