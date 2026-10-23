// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
//!
//! ## `GET /metrics` (since 4.12.0, opt-in)
//!
//! With `VERICTO_METRICS_PROMETHEUS` on, the same listener also answers
//! `GET /metrics` with the telemetry pipeline's metrics in the Prometheus text
//! format (`telemetry::metrics`). It is served here and only here: never on the
//! database listener, whose port clients reach. A connection that sends nothing
//! (a TCP probe, which connects and closes) is closed as before, at the latest
//! after [`REQUEST_TIMEOUT`]; anything else gets a 404 and is closed. Bind the
//! listener to a private address with `VERICTO_HEALTHZ_ADDR` (default `0.0.0.0`,
//! as up to 4.11) and never expose it to the internet.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};

use crate::telemetry::heartbeat::StatsSource;

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

/// Longest a connection to the health-check port may take to send its request
/// before it is closed. A TCP probe sends nothing and closes first; a scraper
/// sends its request at once.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest request head read (a scrape's is ~100 bytes).
const MAX_REQUEST_BYTES: usize = 2048;

/// Connections served at once; past it a connection is closed at once, which is
/// still a successful TCP probe.
const MAX_CONCURRENT: usize = 32;

/// What the listener serves besides the TCP probe.
#[derive(Clone, Default)]
pub struct HealthzExtras {
    /// `GET /metrics`, when `VERICTO_METRICS_PROMETHEUS` is on.
    pub metrics: bool,
    /// The telemetry pipeline, when the control-plane link is on.
    pub stats: Option<StatsSource>,
}

/// `VERICTO_HEALTHZ_ADDR`: the address the health-check listener binds, default
/// `0.0.0.0` (all interfaces, as up to 4.11). An unparseable value is a
/// configuration error rather than a silent fallback to all interfaces.
pub fn bind_addr_from(value: Option<&str>) -> Result<IpAddr, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(IpAddr::from([0, 0, 0, 0])),
        Some(v) => v
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("VERICTO_HEALTHZ_ADDR={v:?} is not an IP address")),
    }
}

/// Runs the health-check listener forever. Blocks (does not bind the port) until
/// `readiness` reports ready, then serves accept+close probes (and `/metrics`
/// when enabled). Never contacts the upstream database.
pub async fn run_healthz(
    addr: IpAddr,
    port: u16,
    readiness: Arc<Readiness>,
    extras: HealthzExtras,
) -> std::io::Result<()> {
    readiness.wait_ready().await;
    let listener = TcpListener::bind((addr, port)).await?;
    tracing::info!(%addr, port, metrics = extras.metrics, "healthz TCP listener ready (proxy warmed up)");
    serve_healthz(listener, extras).await
}

/// Accept loop for the health-check port. A successful TCP connect is the health
/// signal; a connection that sends nothing is closed with no bytes exchanged, and
/// the upstream is never touched.
async fn serve_healthz(listener: TcpListener, extras: HealthzExtras) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(socket); // busy: still a successful probe
                    continue;
                };
                let extras = extras.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_connection(socket, &extras).await;
                });
            }
            Err(e) => tracing::warn!(error = %e, "healthz accept error"),
        }
    }
}

/// One connection: closed as soon as the peer closes or stays silent past
/// [`REQUEST_TIMEOUT`]; an HTTP request gets `/metrics` or a 404.
async fn serve_connection(mut socket: TcpStream, extras: &HealthzExtras) {
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    let read = tokio::time::timeout(REQUEST_TIMEOUT, async {
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() >= MAX_REQUEST_BYTES
                    {
                        return true;
                    }
                }
            }
        }
    })
    .await;
    if !matches!(read, Ok(true)) {
        return; // a probe, or a peer that said nothing: close
    }
    let response = respond(&head, extras).await;
    let _ = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let _ = socket.write_all(&response).await;
        let _ = socket.shutdown().await;
    })
    .await;
}

/// The response to a request head.
async fn respond(head: &[u8], extras: &HealthzExtras) -> Vec<u8> {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    if extras.metrics && method == "GET" && path == "/metrics" {
        let stats = extras.stats.clone();
        let snapshot = match stats {
            Some(s) => tokio::task::spawn_blocking(move || s.pipeline()).await.ok(),
            None => None,
        };
        let body = crate::telemetry::metrics::render_prometheus(snapshot.as_ref());
        return http_response("200 OK", "text/plain; version=0.0.4; charset=utf-8", &body);
    }
    http_response("404 Not Found", "text/plain; charset=utf-8", "not found\n")
}

fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Longest the `healthcheck` subcommand waits for the TCP connect. Below the
/// image's `HEALTHCHECK --timeout` (5s) and the ECS task health check timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Where the `healthcheck` subcommand connects, from `VERICTO_HEALTHZ_PORT` and
/// `VERICTO_HEALTHZ_ADDR` as read through `env`. `Ok(None)`: no port is set, so
/// the listener is off and there is nothing to probe. A listener bound to all
/// interfaces is probed on loopback; one bound to a specific address, on it.
pub fn probe_target(
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<std::net::SocketAddr>, String> {
    let Some(port) = env("VERICTO_HEALTHZ_PORT").filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    // The proxy ignores an unparseable port and leaves the listener off; the probe
    // says so instead of reporting healthy for a port that was asked for.
    let port: u16 = port.trim().parse().map_err(|_| {
        format!("VERICTO_HEALTHZ_PORT={port:?} is not a port number: the healthz listener is off")
    })?;
    let addr = match bind_addr_from(env("VERICTO_HEALTHZ_ADDR").as_deref())? {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::from([127, 0, 0, 1]),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        a => a,
    };
    Ok(Some((addr, port).into()))
}

/// `vericto-proxy healthcheck`: the container health check, for images without a
/// shell (the runtime image has none since 4.15.2). Connects to the healthz
/// listener and closes, as a load-balancer TCP probe does, and returns the exit
/// code: 0 when the connect succeeds or no `VERICTO_HEALTHZ_PORT` is set (an
/// optional listener that is off is not a failure), 1 otherwise. It never
/// contacts the upstream database.
pub fn healthcheck_command(env: &dyn Fn(&str) -> Option<String>) -> i32 {
    let target = match probe_target(env) {
        Ok(Some(target)) => target,
        Ok(None) => return 0,
        Err(e) => {
            eprintln!("healthcheck: {e}");
            return 1;
        }
    };
    match std::net::TcpStream::connect_timeout(&target, PROBE_TIMEOUT) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("healthcheck: {target}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn the_probe_target_follows_the_listener_configuration() {
        assert_eq!(probe_target(&lookup(&[])).unwrap(), None);
        assert_eq!(
            probe_target(&lookup(&[("VERICTO_HEALTHZ_PORT", " ")])).unwrap(),
            None
        );
        let t = |vars: &[(&str, &str)]| probe_target(&lookup(vars)).unwrap().unwrap().to_string();
        assert_eq!(t(&[("VERICTO_HEALTHZ_PORT", "8081")]), "127.0.0.1:8081");
        assert_eq!(
            t(&[
                ("VERICTO_HEALTHZ_PORT", "8081"),
                ("VERICTO_HEALTHZ_ADDR", "::")
            ]),
            "[::1]:8081"
        );
        assert_eq!(
            t(&[
                ("VERICTO_HEALTHZ_PORT", "8081"),
                ("VERICTO_HEALTHZ_ADDR", "10.0.3.7")
            ]),
            "10.0.3.7:8081"
        );
        assert!(probe_target(&lookup(&[("VERICTO_HEALTHZ_PORT", "-1")])).is_err());
        assert!(
            probe_target(&lookup(&[
                ("VERICTO_HEALTHZ_PORT", "8081"),
                ("VERICTO_HEALTHZ_ADDR", "localhost")
            ]))
            .is_err()
        );
    }

    #[test]
    fn the_healthcheck_command_succeeds_only_against_an_open_listener() {
        // No port configured: the optional listener is off, which is healthy.
        assert_eq!(healthcheck_command(&lookup(&[])), 0);
        assert_eq!(
            healthcheck_command(&lookup(&[("VERICTO_HEALTHZ_PORT", "x")])),
            1
        );

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let open = lookup(&[("VERICTO_HEALTHZ_PORT", &port)]);
        assert_eq!(healthcheck_command(&open), 0);

        // The same port once nothing listens on it (warm-up, or a dead process).
        drop(listener);
        assert_eq!(healthcheck_command(&open), 1);
    }

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

    async fn serve(extras: HealthzExtras) -> std::net::SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_healthz(listener, extras));
        addr
    }

    #[tokio::test]
    async fn serve_healthz_accepts_and_closes_without_touching_upstream() {
        let addr = serve(HealthzExtras::default()).await;

        // A probe connects successfully and closes its side; the server closes too
        // (EOF), exchanges no bytes and never dials any upstream.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("read should not hang")
            .expect("read should succeed");
        assert_eq!(n, 0, "healthz should close the connection with no data");
    }

    /// A peer that connects and says nothing is closed after the request timeout,
    /// still with no bytes.
    #[tokio::test]
    async fn a_silent_connection_is_closed_with_no_data() {
        let addr = serve(HealthzExtras::default()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(REQUEST_TIMEOUT * 2, client.read(&mut buf))
            .await
            .expect("closed within the request timeout")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut out))
            .await
            .unwrap()
            .unwrap();
        out
    }

    #[tokio::test]
    async fn metrics_are_served_only_when_enabled() {
        let off = serve(HealthzExtras::default()).await;
        assert!(get(off, "/metrics").await.starts_with("HTTP/1.1 404"));

        let on = serve(HealthzExtras {
            metrics: true,
            stats: None,
        })
        .await;
        let page = get(on, "/metrics").await;
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert!(page.contains("text/plain; version=0.0.4"));
        assert!(page.contains("vericto_proxy_telemetry_enabled 0"));
        assert!(get(on, "/").await.starts_with("HTTP/1.1 404"));
        assert!(get(on, "/metrics/../x").await.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn the_bind_address_defaults_to_all_interfaces() {
        assert_eq!(bind_addr_from(None).unwrap().to_string(), "0.0.0.0");
        assert_eq!(bind_addr_from(Some(" ")).unwrap().to_string(), "0.0.0.0");
        assert_eq!(
            bind_addr_from(Some("127.0.0.1")).unwrap().to_string(),
            "127.0.0.1"
        );
        assert_eq!(bind_addr_from(Some("[::1]")).unwrap().to_string(), "::1");
        assert!(bind_addr_from(Some("localhost")).is_err());
    }
}
