// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The connection pool of `vericto-proxy mcp` (design §5.3):
//! `VERICTO_MCP_POOL_SIZE` connections (default 4, at most 32), opened lazily
//! and closed after `VERICTO_MCP_POOL_IDLE_SECS` (300) without use. A
//! connection that broke mid-protocol, or whose transaction status is not idle
//! after a call, is closed, never reused.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::mcp::config::DatabaseTarget;
use crate::mcp::pg::{ConnectError, PgConn, connect};

/// How long a call waits for a free connection before `DATABASE_UNAVAILABLE`
/// (retry later).
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Pool {
    target: DatabaseTarget,
    allow_md5: bool,
    idle_for: Duration,
    idle: Mutex<Vec<PgConn>>,
    permits: Arc<Semaphore>,
    size: usize,
}

/// A connection out of the pool; back into it with [`Pool::put`].
pub struct Checkout {
    pub conn: PgConn,
    _permit: OwnedSemaphorePermit,
}

/// Why no connection could be had.
#[derive(Debug, Clone)]
pub enum CheckoutError {
    /// Every connection is busy.
    Busy,
    Connect(ConnectError),
}

impl Pool {
    pub fn new(target: DatabaseTarget, size: usize, idle_for: Duration, allow_md5: bool) -> Self {
        Self {
            target,
            allow_md5,
            idle_for,
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(size)),
            size,
        }
    }

    pub async fn get(&self) -> Result<Checkout, CheckoutError> {
        let permit =
            tokio::time::timeout(CHECKOUT_TIMEOUT, Arc::clone(&self.permits).acquire_owned())
                .await
                .map_err(|_| CheckoutError::Busy)?
                .map_err(|_| CheckoutError::Busy)?;
        let reused = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            idle.retain(|c| now.duration_since(c.last_used) < self.idle_for);
            idle.pop()
        };
        let conn = match reused {
            Some(c) => c,
            None => connect(&self.target, self.allow_md5)
                .await
                .map_err(CheckoutError::Connect)?,
        };
        Ok(Checkout {
            conn,
            _permit: permit,
        })
    }

    /// Returns a connection that is healthy and idle; drops any other.
    pub fn put(&self, mut c: Checkout) {
        if c.conn.broken || c.conn.status != b'I' {
            return;
        }
        c.conn.last_used = Instant::now();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < self.size {
            idle.push(c.conn);
        }
    }

    /// Closes the connections idle for longer than the idle timeout (called
    /// periodically).
    pub fn sweep(&self) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        idle.retain(|c| now.duration_since(c.last_used) < self.idle_for);
    }
}
