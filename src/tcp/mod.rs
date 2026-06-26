//! Transparent PostgreSQL wire-protocol TCP proxy.
//!
//! Lets any driver/ORM connect to Vetro as if it were Postgres (only the
//! connection string host changes), without modifying application code. Every
//! query passes through the AST evaluation engine before reaching the real
//! database.

pub mod codec;
pub mod evaluator;
pub mod postgres;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::tcp::postgres::{handle_connection, PgProxyConfig, TelemetrySink};
use crate::tcp::rules_sync::{SharedPolicy, SharedRuleset, SharedTelemetryMode};

/// TCP proxy startup configuration, resolved from the environment.
pub struct TcpProxyOptions {
    pub listen_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Database this proxy fronts, used to tag telemetry. Optional.
    pub database_id: Option<String>,
}

impl TcpProxyOptions {
    /// Reads the TCP proxy configuration from environment variables.
    /// Returns `None` if the upstream is not configured (TCP proxy disabled).
    pub fn from_env() -> Option<Self> {
        let upstream_host = std::env::var("UPSTREAM_PG_HOST").ok()?;
        let listen_port = std::env::var("PROXY_PG_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5433);
        let upstream_port = std::env::var("UPSTREAM_PG_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5432);
        Some(Self {
            listen_port,
            upstream_host,
            upstream_port,
            database_id: std::env::var("VETRO_DATABASE_ID").ok(),
        })
    }
}

/// Starts the Postgres TCP proxy listener. Runs indefinitely.
///
/// `ruleset` is shared and reloadable by the syncer; `telemetry` is optional
/// (None disables reporting, e.g. in dev/air-gapped mode).
pub async fn run_pg_proxy(
    opts: TcpProxyOptions,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    telemetry_mode: SharedTelemetryMode,
    telemetry: Option<TelemetrySink>,
) -> std::io::Result<()> {
    let config = Arc::new(PgProxyConfig {
        upstream_host: opts.upstream_host.clone(),
        upstream_port: opts.upstream_port,
        ruleset,
        policy,
        telemetry_mode,
        telemetry,
    });

    let addr = format!("0.0.0.0:{}", opts.listen_port);
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!(
        listen = %addr,
        upstream = %format!("{}:{}", opts.upstream_host, opts.upstream_port),
        "PostgreSQL TCP proxy listening"
    );

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                // Disable Nagle's algorithm to minimize latency.
                let _ = socket.set_nodelay(true);
                let config = config.clone();
                tokio::spawn(handle_connection(socket, config));
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error accepting TCP connection");
            }
        }
    }
}

pub mod rules_sync;
