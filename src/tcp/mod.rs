//! Transparent PostgreSQL wire-protocol TCP proxy.
//!
//! Lets any driver/ORM connect to Vetro as if it were Postgres (only the
//! connection string host changes), without modifying application code. Every
//! query passes through the AST evaluation engine before reaching the real
//! database.

pub mod codec;
pub mod evaluator;
pub mod postgres;
pub mod upstream;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::tcp::client_tls::ClientTlsMode;
use crate::tcp::postgres::{handle_connection, PgProxyConfig, TelemetrySink};
use crate::tcp::rules_sync::{SharedPolicy, SharedRuleset, SharedTelemetryMode};

pub mod client_tls;

/// TCP proxy startup configuration, resolved from the environment.
pub struct TcpProxyOptions {
    pub listen_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Database this proxy fronts, used to tag telemetry. Optional.
    pub database_id: Option<String>,
    /// TLS mode for the proxy→database hop (default: disable).
    pub upstream_tls: crate::tcp::upstream::UpstreamTlsMode,
    /// CA bundle (PEM) used to verify the upstream cert in verify-full mode.
    pub upstream_ca_path: Option<String>,
    /// Client certificate (PEM) for upstream mutual TLS (optional).
    pub upstream_client_cert: Option<String>,
    /// Private key (PEM) for the upstream mutual-TLS client certificate.
    pub upstream_client_key: Option<String>,
    /// TLS mode for the client→proxy hop (default: disable).
    pub client_tls: ClientTlsMode,
    /// Server certificate (PEM) presented to clients when client TLS is enabled.
    pub client_tls_cert: Option<String>,
    /// Private key (PEM) for the server certificate.
    pub client_tls_key: Option<String>,
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
            upstream_tls: crate::tcp::upstream::UpstreamTlsMode::from_env_str(
                &std::env::var("UPSTREAM_PG_SSLMODE").unwrap_or_default(),
            ),
            upstream_ca_path: std::env::var("UPSTREAM_PG_SSLROOTCERT").ok(),
            upstream_client_cert: std::env::var("UPSTREAM_PG_SSLCERT").ok(),
            upstream_client_key: std::env::var("UPSTREAM_PG_SSLKEY").ok(),
            client_tls: ClientTlsMode::from_env_str(
                &std::env::var("PROXY_TLS_MODE").unwrap_or_default(),
            ),
            client_tls_cert: std::env::var("PROXY_TLS_CERT").ok(),
            client_tls_key: std::env::var("PROXY_TLS_KEY").ok(),
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
    // Resolve client→proxy TLS once at startup. Fail fast if require mode is set
    // without a usable certificate/key, rather than per connection.
    let client_tls_acceptor = match opts.client_tls {
        ClientTlsMode::Require => {
            let cert = opts.client_tls_cert.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "PROXY_TLS_MODE=require but PROXY_TLS_CERT is not set",
                )
            })?;
            let key = opts.client_tls_key.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "PROXY_TLS_MODE=require but PROXY_TLS_KEY is not set",
                )
            })?;
            Some(crate::tcp::client_tls::build_acceptor(cert, key)?)
        }
        ClientTlsMode::Disable => None,
    };
    let client_tls_enabled = client_tls_acceptor.is_some();

    let config = Arc::new(PgProxyConfig {
        upstream_host: opts.upstream_host.clone(),
        upstream_port: opts.upstream_port,
        upstream_tls: opts.upstream_tls,
        upstream_ca_path: opts.upstream_ca_path.clone(),
        upstream_client_cert: opts.upstream_client_cert.clone(),
        upstream_client_key: opts.upstream_client_key.clone(),
        client_tls_acceptor,
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
        upstream_tls = ?opts.upstream_tls,
        client_tls = client_tls_enabled,
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
