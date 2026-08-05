//! Health-check listener (`healthz`) — a dedicated TCP port for load-balancer
//! health checks, kept entirely separate from the wire-protocol traffic port.
//!
//! Why a dedicated port instead of the traffic port: MySQL is server-first, so
//! the proxy must connect upstream the moment it accepts a connection (it has to
//! read the real server's Initial Handshake before the client speaks). A TCP
//! health check on the traffic port would therefore open — and immediately
//! discard — a full connection to the database on every probe. A separate
//! `healthz` port answers probes without ever touching the upstream, and behaves
//! identically for Postgres and MySQL.
//!
//! What it verifies (see `Readiness`):
//!   - liveness — the process is alive and its listener accepts connections;
//!   - readiness — the proxy has finished warm-up (the initial ruleset resolved)
//!     and is ready to evaluate traffic.
//!
//! What it deliberately does NOT verify: the upstream database. A probe that
//! pinged the DB would couple a database outage to a proxy outage — the LB would
//! pull every task out of rotation on a transient DB blip, destroying the
//! proxy's ability to answer clients with a graceful native error. Health checks
//! test the service, not its dependencies.
//!
//! Readiness gate mechanism: a TCP health check completes the kernel three-way
//! handshake as soon as the port is in the `listen` state — before user space
//! ever calls `accept()`. So "don't accept yet" is not enough to report
//! unhealthy; we must not *bind* the port until the proxy is ready. During
//! warm-up the port is closed (probes get connection-refused → unhealthy); once
//! ready we bind and accept+close forever (→ healthy). Process death closes the
//! port automatically, which is exactly the liveness signal we want.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Shared readiness signal. Starts not-ready; flipped to ready exactly once when
/// warm-up completes. Cloneable via `Arc`; readers await [`Readiness::wait_ready`].
#[derive(Debug, Default)]
pub struct Readiness {
    ready: AtomicBool,
    notify: Notify,
}

impl Readiness {
    /// Creates a shared, not-yet-ready signal.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Marks the proxy ready. Idempotent: only the first call wakes waiters, so
    /// callers (e.g. the syncer loop) may call it every iteration cheaply.
    pub fn mark_ready(&self) {
        if !self.ready.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    /// Whether the proxy has completed warm-up.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Resolves as soon as the proxy is (or becomes) ready.
    pub async fn wait_ready(&self) {
        loop {
            // Register interest BEFORE checking the flag, so a `mark_ready` that
            // races between the check and the await cannot be missed.
            let notified = self.notify.notified();
            if self.is_ready() {
                return;
            }
            notified.await;
        }
    }
}

/// Runs the health-check listener forever. Blocks (does not bind the port) until
/// `readiness` reports ready, then serves accept+close probes. Never contacts the
/// upstream database.
pub async fn run_healthz(port: u16, readiness: Arc<Readiness>) -> std::io::Result<()> {
    readiness.wait_ready().await;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "healthz TCP listener ready (proxy warmed up)");
    serve_healthz(listener).await
}

/// Accept loop for the health-check port: accept a connection and immediately
/// close it. A successful TCP connect is the health signal; no bytes are
/// exchanged and the upstream is never touched.
async fn serve_healthz(listener: TcpListener) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((socket, _)) => drop(socket), // accepted → healthy; close immediately
            Err(e) => tracing::warn!(error = %e, "healthz accept error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    #[test]
    fn readiness_starts_not_ready_and_flips_once() {
        let r = Readiness::new();
        assert!(!r.is_ready());
        r.mark_ready();
        assert!(r.is_ready());
        // Idempotent: second call is a no-op, still ready.
        r.mark_ready();
        assert!(r.is_ready());
    }

    #[tokio::test]
    async fn wait_ready_returns_immediately_when_already_ready() {
        let r = Readiness::new();
        r.mark_ready();
        // Should not hang.
        tokio::time::timeout(Duration::from_secs(1), r.wait_ready())
            .await
            .expect("wait_ready should return immediately when ready");
    }

    #[tokio::test]
    async fn wait_ready_wakes_when_marked_later() {
        let r = Readiness::new();
        let r2 = r.clone();
        let waiter = tokio::spawn(async move { r2.wait_ready().await });
        // Not ready yet: the waiter must still be pending.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        r.mark_ready();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should wake after mark_ready")
            .expect("waiter task should not panic");
    }

    #[tokio::test]
    async fn serve_healthz_accepts_and_closes_without_touching_upstream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_healthz(listener));

        // A probe connects successfully and observes a clean close (EOF) — the
        // server exchanges no bytes and never dials any upstream.
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("read should not hang")
            .expect("read should succeed");
        assert_eq!(n, 0, "healthz should close the connection with no data");
    }
}
