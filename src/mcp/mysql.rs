// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The MySQL and MariaDB client of `vericto-proxy mcp` (5.2.0), on
//! `mysql_async`, configured so it sends no statement of its own: the
//! settings it would read at connect (`SELECT @@max_allowed_packet,
//! @@wait_timeout, @@socket`) are given instead, the statement cache is off,
//! and named parameters are refused before they could be rewritten. Every
//! statement this module sends is a control statement of `control.rs` (as a
//! text-protocol `COM_QUERY`) or the agent's statement, exactly as the
//! evaluator returned it, as one `COM_STMT_PREPARE` (which the server refuses
//! for more than one statement) and `COM_STMT_EXECUTE` with the params bound.
//!
//! Each call: the control batch (session settings, `START TRANSACTION … READ
//! ONLY`), the statement, `ROLLBACK`. Rows are read one at a time and bounded
//! as they arrive (rows, bytes, bytes per cell); a row is held whole while it
//! is converted, and the client refuses a row larger than
//! [`MAX_PACKET_BYTES`]. MySQL has no row limit on an execute: when a result
//! has more rows than the call returns, the connection is closed (the server
//! stops on the closed socket and rolls the transaction back) rather than
//! read to the end.

use std::time::{Duration, Instant};

use mysql_async::consts::{ColumnFlags, ColumnType};
use mysql_async::prelude::Queryable;
use mysql_async::{Opts, OptsBuilder, Params, SslOpts, Value};

use crate::mcp::config::{DatabaseTarget, DbDialect};
use crate::mcp::control;
use crate::mcp::pg::{Cell, Column, ConnectError, DbError, ReadLimits, RunError, RunOutcome};
use crate::tcp::upstream::UpstreamTlsMode;

/// The largest packet (and so row) the client accepts: 16 MiB. Larger is a
/// protocol error that closes the connection.
pub const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;

/// How long a connect (TCP, TLS, login) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// MySQL `ER_QUERY_TIMEOUT` (`max_execution_time` exceeded).
pub const ER_QUERY_TIMEOUT: u16 = 3024;
/// MariaDB `ER_STATEMENT_TIMEOUT` (`max_statement_time` exceeded).
pub const ER_STATEMENT_TIMEOUT: u16 = 1969;
/// `ER_QUERY_INTERRUPTED` (`KILL QUERY`, sent at the client-side deadline).
pub const ER_QUERY_INTERRUPTED: u16 = 1317;

/// One open, authenticated connection.
pub struct MyConn {
    conn: Option<mysql_async::Conn>,
    target: DatabaseTarget,
    /// The server is MariaDB (from the URL scheme or the server version).
    pub mariadb: bool,
    pub server_version: String,
    pub last_used: Instant,
    /// Something went wrong mid-protocol: never reused.
    pub broken: bool,
    /// A transaction was opened and not ended yet.
    pub in_tx: bool,
    id: u32,
}

/// Where to send `KILL QUERY` for a running statement.
#[derive(Clone)]
pub struct CancelHandle {
    target: DatabaseTarget,
    id: u32,
}

impl CancelHandle {
    /// `KILL QUERY <id>` on a new connection of the same user (a user may
    /// always stop its own statements). Best effort: errors are logged.
    pub async fn cancel(&self) {
        let result = async {
            let mut c = mysql_async::Conn::new(opts(&self.target)?).await?;
            c.query_drop(control::mysql_kill_query(self.id)).await?;
            c.disconnect().await
        };
        match tokio::time::timeout(Duration::from_secs(5), result).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %redacted(&e), "Could not send KILL QUERY to the database")
            }
            Err(_) => tracing::warn!("Could not send KILL QUERY to the database (timed out)"),
        }
    }
}

/// The client options: no statement of the driver's own, TLS as the target
/// asks, the database the URL names.
fn opts(t: &DatabaseTarget) -> Result<Opts, mysql_async::Error> {
    let ssl = match t.tls {
        UpstreamTlsMode::Disable => None,
        mode => {
            let mut o = SslOpts::default();
            if let Some(ca) = &t.ca_path {
                o = o.with_root_certs(vec![std::path::PathBuf::from(ca).into()]);
            }
            if let (Some(cert), Some(key)) = (&t.client_cert, &t.client_key) {
                o = o.with_client_identity(Some(mysql_async::ClientIdentity::new(
                    std::path::PathBuf::from(cert).into(),
                    std::path::PathBuf::from(key).into(),
                )));
            }
            match mode {
                UpstreamTlsMode::Require => o
                    .with_danger_accept_invalid_certs(true)
                    .with_danger_skip_domain_validation(true),
                UpstreamTlsMode::VerifyCa => o.with_danger_skip_domain_validation(true),
                _ => o,
            }
            .into()
        }
    };
    let b = OptsBuilder::default()
        .ip_or_hostname(t.host.clone())
        .tcp_port(t.port)
        .user(Some(t.user.clone()))
        .pass(Some(t.password.expose().to_string()))
        .db_name((!t.dbname.is_empty()).then(|| t.dbname.clone()))
        // No `SELECT @@socket`, `@@max_allowed_packet`, `@@wait_timeout`.
        .prefer_socket(false)
        .max_allowed_packet(Some(MAX_PACKET_BYTES))
        .wait_timeout(Some(28_800))
        // Statements are closed explicitly after each call.
        .stmt_cache_size(0)
        .tcp_nodelay(true)
        .ssl_opts(ssl);
    Ok(b.into())
}

/// An error's text without anything that could name the host, the user or a
/// value: the server's code and SQLSTATE, or the kind of failure.
fn redacted(e: &mysql_async::Error) -> String {
    match e {
        mysql_async::Error::Server(s) => format!("server error {} (SQLSTATE {})", s.code, s.state),
        mysql_async::Error::Io(mysql_async::IoError::Tls(_)) => "TLS error".to_string(),
        mysql_async::Error::Io(mysql_async::IoError::Io(e)) => {
            format!("I/O error ({:?})", e.kind())
        }
        mysql_async::Error::Driver(_) => "driver error".to_string(),
        mysql_async::Error::Url(_) => "invalid connection options".to_string(),
        mysql_async::Error::Other(_) => "error".to_string(),
    }
}

fn connect_error(e: &mysql_async::Error, tls: UpstreamTlsMode) -> ConnectError {
    let new = |step: &'static str, m: &str| ConnectError {
        step,
        sqlstate: None,
        message: m.to_string(),
    };
    match e {
        mysql_async::Error::Server(s) => {
            let (step, message) = match s.code {
                1045 => ("auth", "password authentication failed".to_string()),
                1044 => ("auth", "the user may not use this database".to_string()),
                1049 => ("startup", "the database does not exist".to_string()),
                1040 | 1203 => ("startup", "too many connections".to_string()),
                1129 | 1130 => (
                    "auth",
                    "the user is not allowed to log in from here (host)".to_string(),
                ),
                1251 => (
                    "auth",
                    "the server asked for an authentication method this client does not support"
                        .to_string(),
                ),
                3159 => (
                    "tls",
                    "the database requires TLS (set ssl-mode=REQUIRED or verify-full in the URL)"
                        .to_string(),
                ),
                3118 | 3955 => ("auth", "the account is locked or expired".to_string()),
                1862 | 1820 => (
                    "auth",
                    "the password has expired; set a new one for this user".to_string(),
                ),
                c => (
                    "startup",
                    format!("the database refused the connection (error {c})"),
                ),
            };
            ConnectError {
                step,
                // 08004 "too many connections" is reported as PostgreSQL's
                // 53300, which the retry hint knows.
                sqlstate: Some(if matches!(s.code, 1040 | 1203) {
                    "53300".to_string()
                } else {
                    s.state.clone()
                }),
                message,
            }
        }
        mysql_async::Error::Io(mysql_async::IoError::Tls(_)) => new(
            "tls",
            "the database certificate did not verify or the TLS handshake failed (check ssl-mode \
             and UPSTREAM_SSLROOTCERT)",
        ),
        mysql_async::Error::Io(mysql_async::IoError::Io(io)) => {
            let text = io.to_string();
            if tls != UpstreamTlsMode::Disable
                && (text.contains("certificate") || text.contains("Certificate"))
            {
                return new(
                    "tls",
                    "the database certificate did not verify (check ssl-mode and UPSTREAM_SSLROOTCERT)",
                );
            }
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused => new("tcp", "connection refused"),
                std::io::ErrorKind::TimedOut => new("tcp", "connection timed out"),
                std::io::ErrorKind::NotFound
                    if text.contains("lookup") || text.contains("resolve") =>
                {
                    new("dns", "could not resolve the database host")
                }
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => new(
                    "tls",
                    "a TLS file (UPSTREAM_SSLROOTCERT, UPSTREAM_SSLCERT or UPSTREAM_SSLKEY) cannot be read",
                ),
                k => ConnectError {
                    step: "tcp",
                    sqlstate: None,
                    message: format!("could not connect ({k:?})"),
                },
            }
        }
        mysql_async::Error::Driver(d) => {
            let text = d.to_string();
            if text.contains("SSL") || text.contains("TLS") || text.contains("ssl") {
                new("tls", "the database does not accept TLS connections")
            } else if text.contains("auth") || text.contains("plugin") {
                new(
                    "auth",
                    "the server asked for an authentication method this client does not support",
                )
            } else {
                new("protocol", "the database broke the protocol during login")
            }
        }
        mysql_async::Error::Url(_) | mysql_async::Error::Other(_) => {
            new("startup", "the connection options are not valid")
        }
    }
}

/// Connects and authenticates (caching_sha2_password, mysql_native_password;
/// over plaintext, caching_sha2's full authentication uses the server's RSA
/// key, never a cleartext password).
pub async fn connect(target: &DatabaseTarget) -> Result<MyConn, ConnectError> {
    if tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map(|mut a| a.next().is_none())
        .unwrap_or(true)
    {
        return Err(ConnectError {
            step: "dns",
            sqlstate: None,
            message: "could not resolve the database host".to_string(),
        });
    }
    let o = opts(target).map_err(|e| connect_error(&e, target.tls))?;
    let conn = match tokio::time::timeout(CONNECT_TIMEOUT, mysql_async::Conn::new(o)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(connect_error(&e, target.tls)),
        Err(_) => {
            return Err(ConnectError {
                step: "tcp",
                sqlstate: None,
                message: "connection timed out".to_string(),
            });
        }
    };
    let (major, minor, patch) = conn.server_version();
    // MariaDB reports 10.x and later (its handshake's `5.5.5-` prefix is
    // dropped by the driver); MySQL is 5.x, 8.x or 9.x.
    let mariadb = target.dialect == DbDialect::Mariadb || major >= 10;
    let id = conn.id();
    Ok(MyConn {
        conn: Some(conn),
        target: target.clone(),
        mariadb,
        server_version: format!("{major}.{minor}.{patch}"),
        last_used: Instant::now(),
        broken: false,
        in_tx: false,
        id,
    })
}

/// A server error as the agent sees it (SQLSTATE, the server's message, its
/// error number).
fn db_error(s: &mysql_async::ServerError) -> DbError {
    DbError {
        severity: "ERROR".to_string(),
        sqlstate: s.state.clone(),
        message: s.message.clone(),
        code: Some(u32::from(s.code)),
        ..Default::default()
    }
}

/// A column's type: the name reported, the PostgreSQL type whose conversion
/// to JSON it shares (`results.rs`), and whether its values are bytes.
pub fn column_type(c: &mysql_async::Column) -> (String, u32, bool) {
    let unsigned = c.flags().contains(ColumnFlags::UNSIGNED_FLAG);
    let binary_charset = c.character_set() == 63;
    let u = |n: &str| {
        if unsigned {
            format!("{n} unsigned")
        } else {
            n.to_string()
        }
    };
    use ColumnType::*;
    match c.column_type() {
        MYSQL_TYPE_TINY => (u("tinyint"), 23, false),
        MYSQL_TYPE_SHORT => (u("smallint"), 23, false),
        MYSQL_TYPE_INT24 => (u("mediumint"), 23, false),
        MYSQL_TYPE_LONG => (u("int"), 23, false),
        MYSQL_TYPE_YEAR => ("year".to_string(), 23, false),
        // Exact: a JSON number loses precision past 2^53.
        MYSQL_TYPE_LONGLONG => (u("bigint"), 20, false),
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => ("decimal".to_string(), 1700, false),
        MYSQL_TYPE_FLOAT => ("float".to_string(), 700, false),
        MYSQL_TYPE_DOUBLE => ("double".to_string(), 701, false),
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => ("date".to_string(), 1082, false),
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_DATETIME2 => ("datetime".to_string(), 1114, false),
        MYSQL_TYPE_TIMESTAMP | MYSQL_TYPE_TIMESTAMP2 => ("timestamp".to_string(), 1114, false),
        MYSQL_TYPE_TIME | MYSQL_TYPE_TIME2 => ("time".to_string(), 1083, false),
        MYSQL_TYPE_JSON => ("json".to_string(), 114, false),
        MYSQL_TYPE_BIT => ("bit".to_string(), 17, true),
        MYSQL_TYPE_GEOMETRY => ("geometry".to_string(), 17, true),
        MYSQL_TYPE_NULL => ("null".to_string(), 25, false),
        MYSQL_TYPE_ENUM => ("enum".to_string(), 25, false),
        MYSQL_TYPE_SET => ("set".to_string(), 25, false),
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB => {
            if binary_charset {
                ("blob".to_string(), 17, true)
            } else {
                ("text".to_string(), 25, false)
            }
        }
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING => {
            if binary_charset {
                ("varbinary".to_string(), 17, true)
            } else {
                ("varchar".to_string(), 25, false)
            }
        }
        MYSQL_TYPE_STRING => {
            if c.flags().contains(ColumnFlags::ENUM_FLAG) {
                ("enum".to_string(), 25, false)
            } else if c.flags().contains(ColumnFlags::SET_FLAG) {
                ("set".to_string(), 25, false)
            } else if binary_charset {
                ("binary".to_string(), 17, true)
            } else {
                ("char".to_string(), 25, false)
            }
        }
        MYSQL_TYPE_VECTOR => ("vector".to_string(), 17, true),
        other => (format!("mysql:{}", other as u8), 25, binary_charset),
    }
}

/// A value in its text form (what PostgreSQL's text format would carry):
/// integers and floats as written, dates and times in ISO 8601 (the session
/// time zone is UTC), bytes as they are.
pub fn value_text(v: Value, ty: ColumnType) -> Option<Vec<u8>> {
    match v {
        Value::NULL => None,
        Value::Bytes(b) => Some(b),
        Value::Int(i) => Some(i.to_string().into_bytes()),
        Value::UInt(u) => Some(u.to_string().into_bytes()),
        Value::Float(f) => Some(f.to_string().into_bytes()),
        Value::Double(d) => Some(d.to_string().into_bytes()),
        Value::Date(y, mo, d, h, mi, s, us) => {
            let mut t = format!("{y:04}-{mo:02}-{d:02}");
            if !matches!(
                ty,
                ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE
            ) {
                t.push_str(&format!(" {h:02}:{mi:02}:{s:02}"));
                if us > 0 {
                    t.push_str(&format!(".{us:06}"));
                }
            }
            Some(t.into_bytes())
        }
        Value::Time(neg, days, h, mi, s, us) => {
            let hours = u64::from(days) * 24 + u64::from(h);
            let mut t = format!("{}{hours:02}:{mi:02}:{s:02}", if neg { "-" } else { "" });
            if us > 0 {
                t.push_str(&format!(".{us:06}"));
            }
            Some(t.into_bytes())
        }
    }
}

/// The params as the server binds them: a JSON number or boolean as a
/// number, everything else as a string (MySQL converts it as it would a
/// string literal).
fn bind(params: &[Option<String>], numeric: &[bool]) -> Params {
    if params.is_empty() {
        return Params::Empty;
    }
    Params::Positional(
        params
            .iter()
            .enumerate()
            .map(|(i, p)| match p {
                None => Value::NULL,
                Some(s) if numeric.get(i).copied().unwrap_or(false) => {
                    if let Ok(n) = s.parse::<i64>() {
                        Value::Int(n)
                    } else if let Ok(n) = s.parse::<u64>() {
                        Value::UInt(n)
                    } else if s == "true" {
                        Value::Int(1)
                    } else if s == "false" {
                        Value::Int(0)
                    } else if let Ok(f) = s.parse::<f64>() {
                        Value::Double(f)
                    } else {
                        Value::Bytes(s.clone().into_bytes())
                    }
                }
                Some(s) => Value::Bytes(s.clone().into_bytes()),
            })
            .collect(),
    )
}

/// One row cut to the caps, as `pg.rs` cuts a `DataRow`: every value at the
/// cell cap, the first row's values to what is left of the byte cap (a first
/// row is returned cut, never dropped). `None` when a later row does not fit.
pub fn bounded_row(
    values: Vec<Option<Vec<u8>>>,
    limits: ReadLimits,
    used: usize,
    first: bool,
) -> Option<(Vec<Option<Cell>>, usize)> {
    let mut cells = Vec::with_capacity(values.len());
    let mut size = 0usize;
    let mut fits = true;
    for v in values {
        let Some(mut bytes) = v else {
            cells.push(None);
            size += 4;
            continue;
        };
        let len = bytes.len();
        let budget_left = limits.max_result_bytes.saturating_sub(used + size);
        let keep = if fits {
            if first {
                len.min(limits.max_cell_bytes).min(budget_left)
            } else {
                len.min(limits.max_cell_bytes)
            }
        } else {
            0
        };
        bytes.truncate(keep);
        size += keep + 2;
        if !first && used + size > limits.max_result_bytes {
            fits = false;
        }
        cells.push(Some(Cell {
            bytes,
            full_len: len,
        }));
    }
    fits.then_some((cells, size))
}

/// Why `begin` did not open the transaction.
pub enum BeginError {
    /// The connection failed.
    Broken,
    /// The server refused a control statement.
    Db(DbError),
}

impl MyConn {
    pub fn cancel_handle(&self) -> Option<CancelHandle> {
        Some(CancelHandle {
            target: self.target.clone(),
            id: self.id,
        })
    }

    fn conn(&mut self) -> std::io::Result<&mut mysql_async::Conn> {
        self.conn
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the connection is closed"))
    }

    /// The session settings and the read-only transaction
    /// (`control::mysql_read_transaction`), in one round trip.
    pub async fn begin(
        &mut self,
        statement_timeout_ms: u32,
        lock_timeout_ms: u32,
    ) -> Result<(), BeginError> {
        let batch =
            control::mysql_read_transaction(self.mariadb, statement_timeout_ms, lock_timeout_ms);
        let Some(c) = self.conn.as_mut() else {
            return Err(BeginError::Broken);
        };
        match c.query_drop(batch).await {
            Ok(()) => {
                self.in_tx = true;
                Ok(())
            }
            Err(mysql_async::Error::Server(s)) => {
                // The batch stops at the failing statement; whatever it
                // opened is rolled back.
                let _ = c.query_drop(control::ROLLBACK).await;
                Err(BeginError::Db(db_error(&s)))
            }
            Err(e) => {
                tracing::warn!(error = %redacted(&e), "The MySQL control batch failed");
                self.broken = true;
                Err(BeginError::Broken)
            }
        }
    }

    /// Ends the transaction (`ROLLBACK`).
    pub async fn rollback(&mut self) -> Result<(), RunError> {
        let c = self.conn()?;
        match c.query_drop(control::ROLLBACK).await {
            Ok(()) => {
                self.in_tx = false;
                Ok(())
            }
            Err(e) => {
                self.broken = true;
                Err(RunError::Io(std::io::Error::other(redacted(&e))))
            }
        }
    }

    /// Closes the connection now, without reading what the server is still
    /// sending (`COM_QUIT`, then the socket closes).
    pub async fn close(&mut self) {
        self.broken = true;
        self.in_tx = false;
        if let Some(c) = self.conn.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), c.disconnect()).await;
        }
    }

    /// Prepares `sql` exactly (one `COM_STMT_PREPARE`), executes it with
    /// `params`, reads the rows within `limits`, closes the statement and ends
    /// the transaction. A result with more rows than are kept closes the
    /// connection instead.
    pub async fn run(
        &mut self,
        sql: &str,
        params: &[Option<String>],
        numeric: &[bool],
        limits: ReadLimits,
    ) -> Result<RunOutcome, RunError> {
        // The driver rewrites `:name` to `?` before it prepares: a text it
        // would change is never sent (classify refuses it first).
        let parsed =
            mysql_common::named_params::ParsedNamedParams::parse(sql.as_bytes()).map_err(|_| {
                RunError::Io(std::io::Error::other("mixed named and positional params"))
            })?;
        if !parsed.params().is_empty() || parsed.query() != sql.as_bytes() {
            return Err(RunError::Io(std::io::Error::other(
                "the driver would rewrite the statement (named parameters)",
            )));
        }
        let started = Instant::now();
        let mut out = RunOutcome::default();
        let c = self.conn()?;
        let stmt = match c.prep(sql).await {
            Ok(s) => s,
            Err(mysql_async::Error::Server(s)) => {
                out.error = Some(db_error(&s));
                out.db_time = started.elapsed();
                self.rollback().await?;
                return Ok(out);
            }
            Err(e) => {
                self.broken = true;
                return Err(RunError::Io(std::io::Error::other(redacted(&e))));
            }
        };
        let mut used = 0usize;
        let mut cut = false;
        let mut failed: Option<mysql_async::Error> = None;
        {
            let mut result = match c.exec_iter(&stmt, bind(params, numeric)).await {
                Ok(r) => r,
                Err(mysql_async::Error::Server(s)) => {
                    out.error = Some(db_error(&s));
                    out.db_time = started.elapsed();
                    let _ = c.close(stmt).await;
                    self.rollback().await?;
                    return Ok(out);
                }
                Err(e) => {
                    self.broken = true;
                    return Err(RunError::Io(std::io::Error::other(redacted(&e))));
                }
            };
            let cols = result.columns();
            let types: Vec<ColumnType> = cols
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.column_type())
                .collect();
            out.columns = cols
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|c| {
                    let (name, oid, binary) = column_type(c);
                    Column {
                        name: c.name_str().into_owned(),
                        type_oid: oid,
                        type_name: Some(name),
                        binary,
                    }
                })
                .collect();
            loop {
                match result.next().await {
                    Ok(Some(row)) => {
                        if out.rows.len() as u32 >= limits.max_rows {
                            out.more_rows = true;
                            cut = true;
                            break;
                        }
                        let values: Vec<Option<Vec<u8>>> = row
                            .unwrap_raw()
                            .into_iter()
                            .enumerate()
                            .map(|(i, v)| {
                                v.and_then(|v| {
                                    value_text(
                                        v,
                                        types
                                            .get(i)
                                            .copied()
                                            .unwrap_or(ColumnType::MYSQL_TYPE_NULL),
                                    )
                                })
                            })
                            .collect();
                        match bounded_row(values, limits, used, out.rows.is_empty()) {
                            Some((cells, size)) => {
                                used += size;
                                out.rows.push(cells);
                            }
                            None => {
                                out.byte_capped = true;
                                cut = true;
                                break;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        failed = Some(e);
                        break;
                    }
                }
            }
        }
        out.db_time = started.elapsed();
        match failed {
            Some(mysql_async::Error::Server(s)) => {
                // An error mid-result (a timeout, KILL QUERY): the rows read so
                // far are not returned.
                out.rows.clear();
                out.more_rows = false;
                out.byte_capped = false;
                out.error = Some(db_error(&s));
                if let Some(c) = self.conn.as_mut() {
                    let _ = c.close(stmt).await;
                }
                self.rollback().await?;
                return Ok(out);
            }
            Some(e) => {
                self.broken = true;
                return Err(RunError::Io(std::io::Error::other(redacted(&e))));
            }
            None => {}
        }
        if cut {
            self.close().await;
            return Ok(out);
        }
        if let Some(c) = self.conn.as_mut()
            && let Err(e) = c.close(stmt).await
        {
            self.broken = true;
            return Err(RunError::Io(std::io::Error::other(redacted(&e))));
        }
        self.rollback().await?;
        Ok(out)
    }

    /// Runs a control statement in the text protocol and returns its rows as
    /// text (the startup role check: `SHOW GRANTS`, the server's read-only
    /// settings). Never an agent statement.
    pub async fn control_rows(&mut self, text: &str) -> Result<Vec<Vec<Option<String>>>, DbError> {
        let Some(c) = self.conn.as_mut() else {
            return Err(DbError {
                message: "the connection is closed".to_string(),
                ..Default::default()
            });
        };
        let rows: Result<Vec<mysql_async::Row>, _> = c.query(text).await;
        match rows {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|r| {
                    r.unwrap_raw()
                        .into_iter()
                        .map(|v| {
                            v.and_then(|v| value_text(v, ColumnType::MYSQL_TYPE_VAR_STRING))
                                .map(|b| String::from_utf8_lossy(&b).into_owned())
                        })
                        .collect()
                })
                .collect()),
            Err(mysql_async::Error::Server(s)) => Err(db_error(&s)),
            Err(e) => {
                self.broken = true;
                Err(DbError {
                    message: redacted(&e),
                    ..Default::default()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ReadLimits {
        ReadLimits {
            max_rows: 10,
            max_cell_bytes: 4,
            max_result_bytes: 20,
        }
    }

    #[test]
    fn rows_are_cut_like_postgres_data_rows() {
        // The first row is cut to the cell cap and to the byte budget.
        let (cells, size) = bounded_row(
            vec![Some(b"abcdefgh".to_vec()), None, Some(b"xy".to_vec())],
            limits(),
            0,
            true,
        )
        .unwrap();
        let c0 = cells[0].as_ref().unwrap();
        assert_eq!(c0.bytes, b"abcd");
        assert_eq!(c0.full_len, 8);
        assert!(c0.truncated());
        assert!(cells[1].is_none());
        assert_eq!(size, 4 + 2 + 4 + 2 + 2);
        // A later row that does not fit is dropped.
        assert!(bounded_row(vec![Some(b"abcd".to_vec())], limits(), 18, false).is_none());
        assert!(bounded_row(vec![Some(b"ab".to_vec())], limits(), 0, false).is_some());
    }

    #[test]
    fn values_have_the_text_form_of_postgres() {
        use ColumnType::*;
        assert_eq!(value_text(Value::NULL, MYSQL_TYPE_LONG), None);
        assert_eq!(value_text(Value::Int(-5), MYSQL_TYPE_LONG).unwrap(), b"-5");
        assert_eq!(
            value_text(Value::UInt(u64::MAX), MYSQL_TYPE_LONGLONG).unwrap(),
            b"18446744073709551615"
        );
        assert_eq!(
            value_text(Value::Date(2026, 11, 16, 0, 0, 0, 0), MYSQL_TYPE_DATE).unwrap(),
            b"2026-11-16"
        );
        assert_eq!(
            value_text(Value::Date(2026, 11, 16, 9, 5, 7, 120), MYSQL_TYPE_DATETIME).unwrap(),
            b"2026-11-16 09:05:07.000120"
        );
        assert_eq!(
            value_text(Value::Time(true, 1, 2, 3, 4, 0), MYSQL_TYPE_TIME).unwrap(),
            b"-26:03:04"
        );
        assert_eq!(
            value_text(Value::Double(0.5), MYSQL_TYPE_DOUBLE).unwrap(),
            b"0.5"
        );
    }

    #[test]
    fn json_numbers_bind_as_numbers_and_strings_as_strings() {
        let Params::Positional(v) = bind(
            &[
                Some("5".into()),
                Some("5".into()),
                Some("2.5".into()),
                None,
                Some("true".into()),
            ],
            &[true, false, true, false, true],
        ) else {
            panic!("positional")
        };
        assert_eq!(v[0], Value::Int(5));
        assert_eq!(v[1], Value::Bytes(b"5".to_vec()));
        assert_eq!(v[2], Value::Double(2.5));
        assert_eq!(v[3], Value::NULL);
        assert_eq!(v[4], Value::Int(1));
        assert!(matches!(bind(&[], &[]), Params::Empty));
    }

    #[test]
    fn the_driver_leaves_texts_without_named_params_unchanged() {
        for sql in [
            "SELECT 1",
            "SELECT * FROM t WHERE a = ? AND b = ':x' -- :y\n",
            "SELECT `:z`, \"a:b\" FROM t /* :c */",
            "SELECT @a := 1",
        ] {
            let p = mysql_common::named_params::ParsedNamedParams::parse(sql.as_bytes()).unwrap();
            assert!(p.params().is_empty(), "{sql}");
            assert_eq!(p.query(), sql.as_bytes(), "{sql}");
        }
        let p = mysql_common::named_params::ParsedNamedParams::parse(b"SELECT :name").unwrap();
        assert!(!p.params().is_empty());
    }

    #[test]
    fn connect_errors_never_name_the_host_or_user() {
        let e = connect_error(
            &mysql_async::Error::Server(mysql_async::ServerError {
                code: 1045,
                message: "Access denied for user 'agent'@'10.0.0.1' (using password: YES)".into(),
                state: "28000".into(),
            }),
            UpstreamTlsMode::Disable,
        );
        assert_eq!(e.step, "auth");
        assert!(!e.message.contains("agent") && !e.message.contains("10.0.0.1"));
    }
}
