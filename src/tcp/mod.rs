//! Transparent PostgreSQL wire-protocol TCP proxy.
//!
//! Lets any driver/ORM connect to Vericto as if it were Postgres (only the
//! connection string host changes), without modifying application code. Every
//! query passes through the AST evaluation engine before reaching the real
//! database.

pub mod codec;
pub mod codec_mysql;
pub mod evaluator;
pub mod healthz;
pub mod postgres;
pub mod protocol;
pub mod query_limit;
pub mod session;
pub mod upstream;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::tcp::client_tls::ClientTlsMode;
use crate::tcp::postgres::{PgProxyConfig, TelemetrySink, handle_connection};
use crate::tcp::rules_sync::{
    SharedAccessPolicies, SharedPolicy, SharedRuleset, SharedTelemetryMode,
};

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
    /// Dedicated TCP port for load-balancer health checks (`healthz`). When set,
    /// a separate listener answers probes without touching the upstream. `None`
    /// disables it (the default; e.g. dev, or when the LB probes the traffic port).
    pub healthz_port: Option<u16>,
}

impl TcpProxyOptions {
    /// Reads the TCP proxy configuration from environment variables.
    /// Returns `None` if the upstream is not configured (TCP proxy disabled).
    ///
    /// The variables are dialect-agnostic — the same `UPSTREAM_*` / `PROXY_*`
    /// names apply to every engine. The wire protocol is chosen by
    /// `VERICTO_WIRE_PROTOCOL` (postgres|mysql, default postgres); it only changes
    /// the DEFAULT ports (Postgres 5432/5433, MySQL 3306/3307) when they are not
    /// set explicitly.
    pub fn from_env() -> Option<Self> {
        let is_mysql = matches!(
            std::env::var("VERICTO_WIRE_PROTOCOL").as_deref(),
            Ok("mysql")
        );
        // Protocol-derived port defaults (upstream, listen). Only used when the
        // corresponding env var is absent.
        let (default_upstream_port, default_listen_port) =
            if is_mysql { (3306, 3307) } else { (5432, 5433) };

        let upstream_host = std::env::var("UPSTREAM_HOST").ok()?;
        let upstream_port = std::env::var("UPSTREAM_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_upstream_port);
        let listen_port = std::env::var("PROXY_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_listen_port);

        Some(Self {
            listen_port,
            upstream_host,
            upstream_port,
            database_id: std::env::var("VERICTO_DATABASE_ID").ok(),
            // Upstream TLS (proxy→database): UPSTREAM_SSLMODE=require|verify-full.
            upstream_tls: crate::tcp::upstream::UpstreamTlsMode::from_env_str(
                &std::env::var("UPSTREAM_SSLMODE").unwrap_or_default(),
            ),
            upstream_ca_path: std::env::var("UPSTREAM_SSLROOTCERT").ok(),
            // Upstream mutual TLS (client cert the proxy presents to the DB).
            // Currently honored on the Postgres hop; ignored by the MySQL path.
            upstream_client_cert: std::env::var("UPSTREAM_SSLCERT").ok(),
            upstream_client_key: std::env::var("UPSTREAM_SSLKEY").ok(),
            // Client TLS (client→proxy): PROXY_TLS_MODE + PROXY_TLS_CERT/KEY.
            client_tls: ClientTlsMode::from_env_str(
                &std::env::var("PROXY_TLS_MODE").unwrap_or_default(),
            ),
            client_tls_cert: std::env::var("PROXY_TLS_CERT").ok(),
            client_tls_key: std::env::var("PROXY_TLS_KEY").ok(),
            // Dedicated health-check port (opt-in). Ignored if unparseable.
            healthz_port: std::env::var("VERICTO_HEALTHZ_PORT")
                .ok()
                .and_then(|v| v.parse().ok()),
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
    agent_access: SharedAccessPolicies,
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
        agent_access,
        telemetry_mode,
        telemetry,
        // Resolved here rather than per query: the wire protocol is fixed at
        // startup, so the clamp and its warning belong here too.
        max_query_bytes: query_limit::effective_max_query_bytes(
            query_limit::configured_max_query_bytes(),
            vericto_engine::Dialect::Postgres,
        ),
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

/// Starts the MySQL TCP proxy listener. Runs indefinitely.
///
/// Mirrors `run_pg_proxy` but for the MySQL wire protocol: no client-side TLS
/// acceptor (Phase 1, trusted network), plaintext upstream. The shared
/// `PgProxyConfig` carries the ruleset/policy/telemetry regardless of protocol
/// (the name is historical; it is the generic proxy config).
pub async fn run_mysql_proxy(
    opts: TcpProxyOptions,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    agent_access: SharedAccessPolicies,
    telemetry_mode: SharedTelemetryMode,
    telemetry: Option<TelemetrySink>,
) -> std::io::Result<()> {
    // Optional client→proxy TLS acceptor (same as the PG path).
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
        upstream_client_cert: None,
        upstream_client_key: None,
        client_tls_acceptor,
        ruleset,
        policy,
        agent_access,
        telemetry_mode,
        telemetry,
        max_query_bytes: query_limit::effective_max_query_bytes(
            query_limit::configured_max_query_bytes(),
            vericto_engine::Dialect::Mysql,
        ),
    });

    let addr = format!("0.0.0.0:{}", opts.listen_port);
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!(
        listen = %addr,
        upstream = %format!("{}:{}", opts.upstream_host, opts.upstream_port),
        upstream_tls = ?opts.upstream_tls,
        client_tls = client_tls_enabled,
        "MySQL TCP proxy listening"
    );

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let _ = socket.set_nodelay(true);
                let config = config.clone();
                tokio::spawn(crate::tcp::session::handle_mysql_connection(socket, config));
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error accepting TCP connection");
            }
        }
    }
}

pub mod rules_cache;
pub mod rules_sync;

#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod mysql_auth_tests;
#[cfg(test)]
mod sensitive_tests;
