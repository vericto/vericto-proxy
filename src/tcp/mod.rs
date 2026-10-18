// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
    /// Returns `Ok(None)` if the upstream is not configured (TCP proxy disabled),
    /// and `Err` naming the variable when `UPSTREAM_SSLMODE` or `PROXY_TLS_MODE`
    /// holds a value the proxy does not support.
    ///
    /// The variables are dialect-agnostic — the same `UPSTREAM_*` / `PROXY_*`
    /// names apply to every engine. The wire protocol is chosen by
    /// `VERICTO_WIRE_PROTOCOL` (postgres|mysql, default postgres); it only changes
    /// the DEFAULT ports (Postgres 5432/5433, MySQL 3306/3307) when they are not
    /// set explicitly.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// [`Self::from_env`] reading each variable through `env`, so tests can pass
    /// their own values without touching the process environment.
    fn from_lookup(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let is_mysql = matches!(env("VERICTO_WIRE_PROTOCOL").as_deref(), Some("mysql"));
        // Protocol-derived port defaults (upstream, listen). Only used when the
        // corresponding env var is absent.
        let (default_upstream_port, default_listen_port) =
            if is_mysql { (3306, 3307) } else { (5432, 5433) };

        let Some(upstream_host) = env("UPSTREAM_HOST") else {
            return Ok(None);
        };
        let upstream_port = env("UPSTREAM_PORT")
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_upstream_port);
        let listen_port = env("PROXY_LISTEN_PORT")
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_listen_port);

        Ok(Some(Self {
            listen_port,
            upstream_host,
            upstream_port,
            database_id: env("VERICTO_DATABASE_ID"),
            // Upstream TLS (proxy→database):
            // UPSTREAM_SSLMODE=disable|require|verify-ca|verify-full.
            upstream_tls: crate::tcp::upstream::UpstreamTlsMode::parse(
                env("UPSTREAM_SSLMODE").as_deref(),
            )?,
            upstream_ca_path: env("UPSTREAM_SSLROOTCERT"),
            // Upstream mutual TLS (client cert the proxy presents to the DB),
            // on both the Postgres and the MySQL hop.
            upstream_client_cert: env("UPSTREAM_SSLCERT"),
            upstream_client_key: env("UPSTREAM_SSLKEY"),
            // Client TLS (client→proxy): PROXY_TLS_MODE + PROXY_TLS_CERT/KEY.
            client_tls: ClientTlsMode::parse(env("PROXY_TLS_MODE").as_deref())?,
            client_tls_cert: env("PROXY_TLS_CERT"),
            client_tls_key: env("PROXY_TLS_KEY"),
            // Dedicated health-check port (opt-in). Ignored if unparseable.
            healthz_port: env("VERICTO_HEALTHZ_PORT").and_then(|v| v.parse().ok()),
        }))
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

    // Same for proxy→database TLS: each connection loads the CA bundle and the
    // mutual-TLS pair, so load them once here and fail fast if one is missing,
    // empty or unparseable, rather than on every connection.
    crate::tcp::upstream::validate_upstream_tls(
        opts.upstream_tls,
        opts.upstream_ca_path.as_deref(),
        opts.upstream_client_cert.as_deref(),
        opts.upstream_client_key.as_deref(),
    )?;

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
/// Mirrors `run_pg_proxy` for the MySQL wire protocol, with the same optional
/// TLS on each hop. The shared `PgProxyConfig` carries the
/// ruleset/policy/telemetry regardless of protocol (the name is historical; it
/// is the generic proxy config).
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

    // The MySQL hop uses the same CA bundle and mutual-TLS pair as Postgres
    // (since 4.12.3), so it fails fast on the same bad material.
    crate::tcp::upstream::validate_upstream_tls(
        opts.upstream_tls,
        opts.upstream_ca_path.as_deref(),
        opts.upstream_client_cert.as_deref(),
        opts.upstream_client_key.as_deref(),
    )?;

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
#[cfg(test)]
mod session_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::upstream::UpstreamTlsMode;
    use arc_swap::ArcSwap;
    use std::collections::HashMap;

    fn try_options(vars: &[(&str, &str)]) -> Result<Option<TcpProxyOptions>, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        TcpProxyOptions::from_lookup(&move |key| map.get(key).cloned())
    }

    fn options(vars: &[(&str, &str)]) -> Option<TcpProxyOptions> {
        try_options(vars).expect("a valid configuration")
    }

    /// Both TLS modes are read in any case, with surrounding whitespace ignored;
    /// unset or empty keeps the documented default, `disable`.
    #[test]
    fn tls_modes_ignore_case_and_whitespace_and_unset_is_disable() {
        let o = options(&[
            ("UPSTREAM_HOST", "db"),
            ("UPSTREAM_SSLMODE", " Verify-CA "),
            ("PROXY_TLS_MODE", "REQUIRE\n"),
        ])
        .unwrap();
        assert_eq!(o.upstream_tls, UpstreamTlsMode::VerifyCa);
        assert_eq!(o.client_tls, ClientTlsMode::Require);

        for blank in ["", "  "] {
            let o = options(&[
                ("UPSTREAM_HOST", "db"),
                ("UPSTREAM_SSLMODE", blank),
                ("PROXY_TLS_MODE", blank),
            ])
            .unwrap();
            assert_eq!(o.upstream_tls, UpstreamTlsMode::Disable, "{blank:?}");
            assert_eq!(o.client_tls, ClientTlsMode::Disable, "{blank:?}");
        }
    }

    /// An unknown TLS mode used to start the proxy with that hop in plaintext.
    /// It is now a startup error naming the variable and the accepted values.
    #[test]
    fn an_unknown_tls_mode_is_a_startup_error() {
        for (var, raw, accepted) in [
            ("UPSTREAM_SSLMODE", "verify", "`verify-ca`"),
            ("UPSTREAM_SSLMODE", "required", "`verify-full`"),
            ("UPSTREAM_SSLMODE", "prefer", "plaintext"),
            ("UPSTREAM_SSLMODE", "allow", "plaintext"),
            ("PROXY_TLS_MODE", "required", "`require`"),
            ("PROXY_TLS_MODE", "verify-full", "`disable`"),
            ("PROXY_TLS_MODE", "on", "`require`"),
        ] {
            let err = match try_options(&[("UPSTREAM_HOST", "db"), (var, raw)]) {
                Err(e) => e,
                Ok(_) => panic!("{var}={raw} must fail startup"),
            };
            assert!(err.contains(var), "{err}");
            assert!(err.contains(&format!("{raw:?}")), "{err}");
            assert!(err.contains(accepted), "{err}");
        }
        // Without UPSTREAM_HOST the proxy is off and nothing else is read.
        assert!(
            try_options(&[("UPSTREAM_SSLMODE", "bogus")])
                .unwrap()
                .is_none()
        );
    }

    /// Without UPSTREAM_HOST there is nothing to proxy to: the TCP proxy is off.
    #[test]
    fn no_upstream_host_means_no_proxy() {
        assert!(options(&[]).is_none());
        assert!(options(&[("UPSTREAM_PORT", "5432")]).is_none());
    }

    /// The wire protocol only changes the default ports; everything else is off
    /// or plaintext until it is set.
    #[test]
    fn default_ports_follow_the_wire_protocol() {
        let pg = options(&[("UPSTREAM_HOST", "db")]).unwrap();
        assert_eq!((pg.upstream_port, pg.listen_port), (5432, 5433));
        assert_eq!(pg.upstream_tls, UpstreamTlsMode::Disable);
        assert_eq!(pg.client_tls, ClientTlsMode::Disable);
        assert_eq!(pg.healthz_port, None);
        assert!(pg.database_id.is_none() && pg.upstream_ca_path.is_none());

        let my = options(&[("UPSTREAM_HOST", "db"), ("VERICTO_WIRE_PROTOCOL", "mysql")]).unwrap();
        assert_eq!((my.upstream_port, my.listen_port), (3306, 3307));
    }

    #[test]
    fn every_variable_reaches_its_option_and_bad_ports_fall_back() {
        let o = options(&[
            ("UPSTREAM_HOST", "db.internal"),
            ("UPSTREAM_PORT", "6543"),
            ("PROXY_LISTEN_PORT", "7000"),
            ("VERICTO_DATABASE_ID", "db-1"),
            ("UPSTREAM_SSLMODE", "verify-full"),
            ("UPSTREAM_SSLROOTCERT", "/etc/ca.pem"),
            ("UPSTREAM_SSLCERT", "/etc/c.pem"),
            ("UPSTREAM_SSLKEY", "/etc/k.pem"),
            ("PROXY_TLS_MODE", "require"),
            ("PROXY_TLS_CERT", "/etc/s.pem"),
            ("PROXY_TLS_KEY", "/etc/s.key"),
            ("VERICTO_HEALTHZ_PORT", "8080"),
        ])
        .unwrap();
        assert_eq!(o.upstream_host, "db.internal");
        assert_eq!((o.upstream_port, o.listen_port), (6543, 7000));
        assert_eq!(o.database_id.as_deref(), Some("db-1"));
        assert_eq!(o.upstream_tls, UpstreamTlsMode::VerifyFull);
        assert_eq!(o.upstream_ca_path.as_deref(), Some("/etc/ca.pem"));
        assert_eq!(o.upstream_client_cert.as_deref(), Some("/etc/c.pem"));
        assert_eq!(o.upstream_client_key.as_deref(), Some("/etc/k.pem"));
        assert_eq!(o.client_tls, ClientTlsMode::Require);
        assert_eq!(o.client_tls_cert.as_deref(), Some("/etc/s.pem"));
        assert_eq!(o.client_tls_key.as_deref(), Some("/etc/s.key"));
        assert_eq!(o.healthz_port, Some(8080));

        let bad = options(&[
            ("UPSTREAM_HOST", "db"),
            ("UPSTREAM_PORT", "99999"),
            ("PROXY_LISTEN_PORT", "x"),
            ("VERICTO_HEALTHZ_PORT", "-1"),
        ])
        .unwrap();
        assert_eq!((bad.upstream_port, bad.listen_port), (5432, 5433));
        assert_eq!(bad.healthz_port, None);
    }

    type Shared = (
        SharedRuleset,
        SharedPolicy,
        SharedAccessPolicies,
        SharedTelemetryMode,
    );

    fn shared() -> Shared {
        (
            Arc::new(ArcSwap::from_pointee(
                crate::tcp::evaluator::default_ruleset(),
            )),
            Arc::new(ArcSwap::from_pointee(
                vericto_engine::EnforcementPolicy::default(),
            )),
            Arc::new(ArcSwap::from_pointee(
                vericto_engine::AccessPolicyMap::default(),
            )),
            Arc::new(ArcSwap::from_pointee(
                crate::tcp::rules_sync::TelemetryQueryMode::default(),
            )),
        )
    }

    async fn run(protocol: &str, opts: TcpProxyOptions) -> std::io::Error {
        let (rules, policy, access, mode) = shared();
        let run = async {
            match protocol {
                "mysql" => run_mysql_proxy(opts, rules, policy, access, mode, None).await,
                _ => run_pg_proxy(opts, rules, policy, access, mode, None).await,
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("a startup error returns at once")
            .expect_err("startup must fail")
    }

    fn base(listen_port: u16) -> TcpProxyOptions {
        options(&[
            ("UPSTREAM_HOST", "127.0.0.1"),
            ("PROXY_LISTEN_PORT", &listen_port.to_string()),
        ])
        .unwrap()
    }

    /// PROXY_TLS_MODE=require without a certificate or key fails at startup with
    /// the variable named, on both protocols, instead of failing per connection.
    #[tokio::test]
    async fn client_tls_without_material_fails_at_startup() {
        for protocol in ["postgres", "mysql"] {
            let mut no_cert = base(0);
            no_cert.client_tls = ClientTlsMode::Require;
            let err = run(protocol, no_cert).await;
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("PROXY_TLS_CERT"), "{err}");

            let mut no_key = base(0);
            no_key.client_tls = ClientTlsMode::Require;
            no_key.client_tls_cert = Some("/etc/vericto/cert.pem".into());
            let err = run(protocol, no_key).await;
            assert!(err.to_string().contains("PROXY_TLS_KEY"), "{err}");

            let mut missing = base(0);
            missing.client_tls = ClientTlsMode::Require;
            missing.client_tls_cert = Some("/nonexistent/vericto/cert.pem".into());
            missing.client_tls_key = Some("/nonexistent/vericto/key.pem".into());
            let err = run(protocol, missing).await;
            assert!(err.to_string().contains("/nonexistent/vericto"), "{err}");
        }
    }

    /// Upstream TLS material is loaded at startup on both protocols (MySQL since
    /// 4.12.3): a CA bundle without a certificate, a missing one, verify-ca
    /// without one, or half a mutual-TLS pair stops the proxy before it listens.
    /// A usable bundle gets as far as the listener (here: a taken port).
    #[tokio::test]
    async fn bad_upstream_tls_material_fails_at_startup() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty-ca.pem");
        std::fs::write(&empty, "").unwrap();
        let empty = empty.to_str().unwrap().to_string();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, crate::tcp::upstream::TEST_CA_CERT).unwrap();

        for protocol in ["postgres", "mysql"] {
            for mode in [UpstreamTlsMode::VerifyCa, UpstreamTlsMode::VerifyFull] {
                let mut no_cert_in_ca = base(0);
                no_cert_in_ca.upstream_tls = mode;
                no_cert_in_ca.upstream_ca_path = Some(empty.clone());
                let err = run(protocol, no_cert_in_ca).await;
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{protocol}");
                assert!(
                    err.to_string()
                        .contains("no certificates found in UPSTREAM_SSLROOTCERT"),
                    "{protocol}: {err}"
                );
                assert!(err.to_string().contains(&empty), "{err}");

                let mut missing_ca = base(0);
                missing_ca.upstream_tls = mode;
                missing_ca.upstream_ca_path = Some("/nonexistent/vericto/ca.pem".into());
                let err = run(protocol, missing_ca).await;
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{protocol}");
                assert!(
                    err.to_string().contains("/nonexistent/vericto/ca.pem"),
                    "{protocol}: {err}"
                );
            }

            let mut verify_ca_without_ca = base(0);
            verify_ca_without_ca.upstream_tls = UpstreamTlsMode::VerifyCa;
            let err = run(protocol, verify_ca_without_ca).await;
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{protocol}");
            assert!(
                err.to_string().contains("UPSTREAM_SSLROOTCERT"),
                "{protocol}: {err}"
            );

            let mut half_pair = base(0);
            half_pair.upstream_tls = UpstreamTlsMode::Require;
            half_pair.upstream_client_cert = Some("/etc/vericto/client.pem".into());
            let err = run(protocol, half_pair).await;
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{protocol}");
            assert!(
                err.to_string().contains("UPSTREAM_SSLKEY"),
                "{protocol}: {err}"
            );

            for mode in [UpstreamTlsMode::VerifyCa, UpstreamTlsMode::VerifyFull] {
                let taken = TcpListener::bind("0.0.0.0:0").await.unwrap();
                let mut good = base(taken.local_addr().unwrap().port());
                good.upstream_tls = mode;
                good.upstream_ca_path = Some(ca.to_str().unwrap().into());
                let err = run(protocol, good).await;
                assert_eq!(
                    err.kind(),
                    std::io::ErrorKind::AddrInUse,
                    "{protocol}: {err}"
                );
            }
        }
    }

    /// A listen port already taken is a startup error, not a silent hang.
    #[tokio::test]
    async fn a_taken_listen_port_is_a_startup_error() {
        let taken = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = taken.local_addr().unwrap().port();
        for protocol in ["postgres", "mysql"] {
            let err = run(protocol, base(port)).await;
            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}");
        }
    }
}
