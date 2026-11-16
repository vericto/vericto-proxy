// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! One database connection of `vericto-proxy mcp`, whatever the database:
//! PostgreSQL (`pg.rs`, the extended protocol) or MySQL and MariaDB
//! (`mysql.rs`). Both run a call the same way: [`Conn::begin_read`] opens the
//! read-only transaction with the call's timeouts, [`Conn::run_read`] runs the
//! statement within the caps and ends the transaction with `ROLLBACK`.

use std::time::{Duration, Instant};

use crate::mcp::config::{DatabaseTarget, DbDialect};
use crate::mcp::control;
use crate::mcp::mysql::{self, MyConn};
use crate::mcp::pg::{self, ConnectError, DbError, PgConn, ReadLimits, RunError, RunOutcome};

pub enum Conn {
    Pg(PgConn),
    My(MyConn),
}

/// Where to stop a running statement: a PostgreSQL `CancelRequest`, or MySQL
/// `KILL QUERY`.
#[derive(Clone)]
pub enum CancelHandle {
    Pg(pg::CancelHandle),
    My(mysql::CancelHandle),
}

impl CancelHandle {
    pub async fn cancel(&self) {
        match self {
            CancelHandle::Pg(h) => h.cancel().await,
            CancelHandle::My(h) => h.cancel().await,
        }
    }
}

/// Why the read-only transaction is not open.
#[derive(Debug)]
pub enum BeginError {
    /// The connection failed (never reused).
    Broken,
    /// The database refused a control statement (the connection is fine).
    Db(DbError),
}

impl Conn {
    pub async fn connect(target: &DatabaseTarget, allow_md5: bool) -> Result<Conn, ConnectError> {
        match target.dialect {
            DbDialect::Postgres => pg::connect(target, allow_md5).await.map(Conn::Pg),
            DbDialect::Mysql | DbDialect::Mariadb => mysql::connect(target).await.map(Conn::My),
        }
    }

    pub fn last_used(&self) -> Instant {
        match self {
            Conn::Pg(c) => c.last_used,
            Conn::My(c) => c.last_used,
        }
    }

    pub fn touch(&mut self) {
        let now = Instant::now();
        match self {
            Conn::Pg(c) => c.last_used = now,
            Conn::My(c) => c.last_used = now,
        }
    }

    /// Healthy and outside any transaction: it may go back to the pool.
    pub fn reusable(&self) -> bool {
        match self {
            Conn::Pg(c) => !c.broken && c.status == b'I',
            Conn::My(c) => !c.broken && !c.in_tx,
        }
    }

    pub fn mark_broken(&mut self) {
        match self {
            Conn::Pg(c) => c.broken = true,
            Conn::My(c) => c.broken = true,
        }
    }

    /// The server version (startup message or handshake), for the logs.
    pub fn server_version(&self) -> Option<String> {
        match self {
            Conn::Pg(c) => c.server_version.clone(),
            Conn::My(c) => Some(c.server_version.clone()),
        }
    }

    /// MariaDB (told apart from MySQL by its session variables).
    pub fn is_mariadb(&self) -> bool {
        matches!(self, Conn::My(c) if c.mariadb)
    }

    pub fn cancel_handle(&self) -> Option<CancelHandle> {
        match self {
            Conn::Pg(c) => c.cancel_handle().map(CancelHandle::Pg),
            Conn::My(c) => c.cancel_handle().map(CancelHandle::My),
        }
    }

    /// Opens the read-only transaction of one call, with its statement and
    /// lock timeouts and (PostgreSQL) the search path.
    pub async fn begin_read(
        &mut self,
        statement_timeout_ms: u32,
        lock_timeout_ms: u32,
        search_path: Option<&[String]>,
    ) -> Result<(), BeginError> {
        match self {
            Conn::Pg(c) => {
                let batch =
                    control::read_transaction(statement_timeout_ms, lock_timeout_ms, search_path);
                match c.control(&batch).await {
                    Ok(b'T') => Ok(()),
                    Ok(_) | Err(RunError::Io(_)) => {
                        c.broken = true;
                        Err(BeginError::Broken)
                    }
                    Err(RunError::Control(e)) => {
                        let _ = c.control(control::ROLLBACK).await;
                        Err(BeginError::Db(e))
                    }
                }
            }
            Conn::My(c) => match c.begin(statement_timeout_ms, lock_timeout_ms).await {
                Ok(()) => Ok(()),
                Err(mysql::BeginError::Broken) => Err(BeginError::Broken),
                Err(mysql::BeginError::Db(e)) => Err(BeginError::Db(e)),
            },
        }
    }

    /// Runs `sql` exactly, with `params` (`numeric[i]`: param `i` was a JSON
    /// number or boolean), inside the transaction [`Self::begin_read`] opened,
    /// reads the rows within `limits` and ends the transaction.
    pub async fn run_read(
        &mut self,
        sql: &str,
        params: &[Option<String>],
        numeric: &[bool],
        limits: ReadLimits,
    ) -> Result<RunOutcome, RunError> {
        match self {
            Conn::Pg(c) => c.run(sql, params, limits, control::ROLLBACK).await,
            Conn::My(c) => c.run(sql, params, numeric, limits).await,
        }
    }

    /// Closes a connection that will not be reused (MySQL: without reading
    /// what the server is still sending).
    pub async fn close(self) {
        if let Conn::My(mut c) = self {
            let _ = tokio::time::timeout(Duration::from_secs(3), c.close()).await;
        }
    }
}
