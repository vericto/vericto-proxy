// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Postgres query cancellation through the proxy (4.16.1).
//!
//! A client cancels a running query by opening a *new* connection and sending
//! a `CancelRequest` (code 80877102) with the process id and secret key of the
//! `BackendKeyData` its session received. libpq's `PQcancel` (psql's Ctrl+C,
//! most drivers) sends it in plaintext, without an `SSLRequest`; libpq 17's
//! `PQcancelCreate` may negotiate TLS first. The proxy accepts both, also with
//! `PROXY_TLS_MODE=require`: the packet carries no credential beyond the key
//! the session was given, and it is never answered.
//!
//! The proxy relays the server's `BackendKeyData` to the client unchanged, so
//! the key a client holds is the one the database checks. On top of that the
//! proxy keeps a registry of the keys it has relayed to sessions that are still
//! open, and forwards a `CancelRequest` to the database only when its
//! `(pid, secret)` is one of them: a cancel can only reach a session that runs
//! through this proxy process, and a wrong secret never leaves the proxy. The
//! registry holds one entry per open Postgres session and is touched twice per
//! session (when the key is relayed, when the session ends), never per
//! statement.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `CancelRequest` magic code (80877102).
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;

/// Longest secret key a server may send (protocol 3.2 allows up to 256 bytes;
/// 3.0 always sends 4).
pub const MAX_SECRET_LEN: usize = 256;

/// How long the proxy waits for the database to close a forwarded cancel
/// connection (it does once the request is processed).
const CANCEL_FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The key a `BackendKeyData` gives a session, and that a `CancelRequest`
/// presents.
#[derive(Clone, PartialEq, Eq)]
pub struct BackendKey {
    pub pid: i32,
    pub secret: Box<[u8]>,
}

// Never print the secret.
impl std::fmt::Debug for BackendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendKey")
            .field("pid", &self.pid)
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl BackendKey {
    /// From a `BackendKeyData` ('K') body or the part of a `CancelRequest`
    /// after its code: Int32 process id, then the secret key (4 to 256 bytes).
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 8 || body.len() > 4 + MAX_SECRET_LEN {
            return None;
        }
        let pid = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        Some(BackendKey {
            pid,
            secret: body[4..].into(),
        })
    }

    /// The `CancelRequest` packet carrying this key.
    pub fn cancel_request(&self) -> Vec<u8> {
        let len = 12 + self.secret.len();
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&(len as i32).to_be_bytes());
        out.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
        out.extend_from_slice(&self.pid.to_be_bytes());
        out.extend_from_slice(&self.secret);
        out
    }
}

/// Compares two secrets without an early exit on the first differing byte.
fn secrets_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// The backend keys this proxy process has relayed to sessions still open.
#[derive(Debug, Default)]
pub struct CancelRegistry {
    sessions: Mutex<HashMap<i32, Box<[u8]>>>,
}

impl CancelRegistry {
    /// Records the key relayed to a session; the entry lives as long as the
    /// returned guard (the session's relay).
    pub fn register(self: &Arc<Self>, key: BackendKey) -> Registration {
        self.lock().insert(key.pid, key.secret.clone());
        Registration {
            registry: Arc::clone(self),
            key,
        }
    }

    /// Whether `key` is the key of a session open on this proxy.
    pub fn contains(&self, key: &BackendKey) -> bool {
        self.lock()
            .get(&key.pid)
            .is_some_and(|secret| secrets_match(secret, &key.secret))
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i32, Box<[u8]>>> {
        // A panic while holding the lock cannot leave the map half-written.
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Removes its session's key from the registry when dropped.
#[derive(Debug)]
pub struct Registration {
    registry: Arc<CancelRegistry>,
    key: BackendKey,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut sessions = self.registry.lock();
        // The server may already have given the pid to a newer session whose
        // key replaced this one: leave that entry alone.
        if sessions
            .get(&self.key.pid)
            .is_some_and(|secret| secrets_match(secret, &self.key.secret))
        {
            sessions.remove(&self.key.pid);
        }
    }
}

/// Handles a `CancelRequest` received on a client connection: forwarded to the
/// database (over upstream TLS when configured) only when its key belongs to a
/// session open on this proxy; otherwise ignored. Never answered, as the
/// server does not answer one either.
pub async fn handle_cancel_request(
    config: &crate::tcp::postgres::PgProxyConfig,
    key: BackendKey,
) -> std::io::Result<()> {
    if !config.cancel_keys.contains(&key) {
        tracing::debug!(
            pid = key.pid,
            "CancelRequest ignored: no open session of this proxy has that key"
        );
        return Ok(());
    }
    let (mut server_read, mut server_write) = crate::tcp::upstream::connect_upstream(
        &config.upstream_host,
        config.upstream_port,
        config.upstream_tls,
        config.upstream_ca_path.as_deref(),
        config.upstream_client_cert.as_deref(),
        config.upstream_client_key.as_deref(),
    )
    .await?;
    server_write.write_all(&key.cancel_request()).await?;
    server_write.flush().await?;
    // The server closes the connection once it has processed the request.
    // Waiting for that, rather than closing first, means the request is never
    // lost to a reset of a socket with unread bytes (a TLS session ticket).
    let mut sink = [0u8; 256];
    let drained = tokio::time::timeout(CANCEL_FORWARD_TIMEOUT, async {
        while server_read.read(&mut sink).await? > 0 {}
        Ok::<(), std::io::Error>(())
    })
    .await;
    let _ = server_write.shutdown().await;
    tracing::info!(pid = key.pid, "CancelRequest forwarded to the database");
    match drained {
        Ok(r) => r,
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: i32, secret: &[u8]) -> BackendKey {
        BackendKey {
            pid,
            secret: secret.into(),
        }
    }

    #[test]
    fn parse_reads_protocol_3_0_and_3_2_keys() {
        let mut body = 42i32.to_be_bytes().to_vec();
        body.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(BackendKey::parse(&body), Some(key(42, &[1, 2, 3, 4])));
        let mut long = 7i32.to_be_bytes().to_vec();
        long.extend_from_slice(&[9; 32]);
        assert_eq!(BackendKey::parse(&long).unwrap().secret.len(), 32);
        assert_eq!(BackendKey::parse(&[0; 7]), None);
        assert_eq!(BackendKey::parse(&vec![0; 4 + MAX_SECRET_LEN + 1]), None);
    }

    #[test]
    fn cancel_request_bytes() {
        let bytes = key(0x0102_0304, &[0xaa, 0xbb, 0xcc, 0xdd]).cancel_request();
        assert_eq!(
            bytes,
            [
                0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd
            ]
        );
    }

    #[test]
    fn registry_matches_only_the_exact_key_while_registered() {
        let reg = Arc::new(CancelRegistry::default());
        let guard = reg.register(key(10, &[1, 2, 3, 4]));
        assert!(reg.contains(&key(10, &[1, 2, 3, 4])));
        assert!(!reg.contains(&key(10, &[1, 2, 3, 5])), "wrong secret");
        assert!(!reg.contains(&key(10, &[1, 2, 3])), "wrong length");
        assert!(!reg.contains(&key(11, &[1, 2, 3, 4])), "wrong pid");
        drop(guard);
        assert!(!reg.contains(&key(10, &[1, 2, 3, 4])), "session ended");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn an_old_session_ending_keeps_a_newer_session_with_the_same_pid() {
        let reg = Arc::new(CancelRegistry::default());
        let old = reg.register(key(10, &[1; 4]));
        let new = reg.register(key(10, &[2; 4]));
        drop(old);
        assert!(reg.contains(&key(10, &[2; 4])));
        drop(new);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let s = format!("{:?}", key(5, &[0xde, 0xad, 0xbe, 0xef]));
        assert!(!s.contains("222") && !s.contains("de") && s.contains("secret_len"));
    }
}
