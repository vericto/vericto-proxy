//! vericto-proxy — Deterministic SQL firewall (TCP wire-protocol mode).
//!
//! Customer-facing component: intercepts every query via the PostgreSQL or MySQL
//! wire protocol, evaluates it with the vericto-engine AST parser, and either
//! forwards it to the real database or blocks it.
//!
//! Telemetry is reported to the Vericto API (HTTPS) in batches; the ruleset is
//! pulled from the API on a configurable polling interval (default: 5 min).
//!
//! Required env vars for TCP mode:
//!   UPSTREAM_HOST — the real database host to forward safe queries to
//!                   (dialect-agnostic; VERICTO_WIRE_PROTOCOL selects the protocol)
//!
//! Optional env vars for control-plane link:
//!   VERICTO_API_URL    — e.g. https://api.vericto.com
//!   VERICTO_API_KEY    — workspace API key (vtro_...)
//!   VERICTO_DATABASE_ID — UUID of the database record in the Vericto platform

mod config;
mod tcp;
mod telemetry;

use arc_swap::ArcSwap;
use std::sync::Arc;

use vericto_engine::{AccessPolicyMap, EnforcementPolicy};

use crate::tcp::evaluator::default_ruleset;
use crate::tcp::rules_sync::{
    SharedAccessPolicies, SharedPolicy, SharedRuleset, SharedTelemetryMode, TelemetryQueryMode,
};

// vericto-engine re-exports through the tcp evaluator module's imports

#[tokio::main]
async fn main() {
    init_tracing();

    // Install the process-default rustls crypto provider (ring) before any TLS
    // is used (upstream TLS client + telemetry/rule-sync HTTPS). Idempotent.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let Some(tcp_opts) = tcp::TcpProxyOptions::from_env() else {
        tracing::error!(
            "UPSTREAM_HOST is not set — vericto-proxy requires a database upstream to proxy to. \
             Set UPSTREAM_HOST to the hostname of your production database."
        );
        std::process::exit(1);
    };

    // Shared, hot-swappable ruleset seeded with the built-in critical rules.
    // Protective from the first connection even before the first API sync.
    let ruleset: SharedRuleset = Arc::new(ArcSwap::from_pointee(default_ruleset()));

    // Shared, hot-swappable enforcement policy. Defaults until the first API
    // sync (Critical/High → BLOCK, Medium → FLAG, Low/Informational → MONITOR,
    // parse-error → allow_report).
    let policy: SharedPolicy = Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default()));

    // Shared, hot-swappable agent-access allowlists keyed by database user. Empty
    // (no user restricted) until a sync sends some: the built-in posture is
    // today's behaviour, and the rules cache restores them across a restart.
    let agent_access: SharedAccessPolicies =
        Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default()));

    // Shared, hot-swappable telemetry query mode. Defaults to Raw until the
    // first API sync resolves the workspace's reporting privacy preference.
    let telemetry_mode: SharedTelemetryMode =
        Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default()));

    // Readiness signal for the health-check listener: not-ready until warm-up
    // completes. When the control-plane link is enabled, the syncer flips it
    // after its first sync attempt; when disabled, we're ready immediately (the
    // built-in default ruleset is already active and protective).
    let readiness = crate::tcp::healthz::Readiness::new();

    // Control-plane link (telemetry + rule sync) — optional.
    let telemetry_sink = match config::ControlPlaneConfig::from_env() {
        Some(cp) => {
            tracing::info!(
                buffer = ?cp.buffer_mode,
                rules_sync_secs = cp.rules_sync_interval.as_secs(),
                "Control-plane link enabled (telemetry + rule sync)"
            );

            // Rule syncer: polls GET /sync/rules and swaps the ruleset and
            // policy in place. Flips `readiness` after its first attempt.
            let sync_cfg = cp.clone();
            let sync_ruleset = ruleset.clone();
            let sync_policy = policy.clone();
            let sync_agent_access = agent_access.clone();
            let sync_telemetry_mode = telemetry_mode.clone();
            let sync_readiness = readiness.clone();
            tokio::spawn(async move {
                crate::tcp::rules_sync::run(
                    sync_cfg,
                    sync_ruleset,
                    sync_policy,
                    sync_agent_access,
                    sync_telemetry_mode,
                    sync_readiness,
                )
                .await
            });

            // Telemetry reporter: drains the queue and POSTs to /ingest/events.
            let queue: Arc<dyn telemetry::EventQueue> = Arc::from(telemetry::new_queue(&cp));
            let reporter = telemetry::Reporter::new(cp.clone(), queue.clone());
            tokio::spawn(async move { reporter.run().await });

            tcp_opts
                .database_id
                .clone()
                .map(|database_id| tcp::postgres::TelemetrySink { queue, database_id })
        }
        None => {
            tracing::info!(
                "Control-plane link disabled \
                 (set VERICTO_API_URL and VERICTO_API_KEY to enable telemetry and rule sync)"
            );
            // No syncer to flip readiness; the default ruleset is already active.
            readiness.mark_ready();
            None
        }
    };

    // Health-check listener (opt-in via VERICTO_HEALTHZ_PORT): a dedicated TCP
    // port for load-balancer probes that never touches the upstream. It binds
    // only once the proxy is ready, so probes fail (connection-refused) during
    // warm-up and succeed afterwards.
    if let Some(healthz_port) = tcp_opts.healthz_port {
        let healthz_readiness = readiness.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::tcp::healthz::run_healthz(healthz_port, healthz_readiness).await
            {
                tracing::error!(error = %e, port = healthz_port, "healthz listener failed");
            }
        });
    }

    // Wire protocol selected per deployment (Option A): one protocol per proxy
    // instance, derived from the fronted database's dialect.
    let wire_protocol =
        std::env::var("VERICTO_WIRE_PROTOCOL").unwrap_or_else(|_| "postgres".into());

    tracing::info!(
        upstream = %format!("{}:{}", tcp_opts.upstream_host, tcp_opts.upstream_port),
        wire_protocol = %wire_protocol,
        "vericto-proxy starting"
    );

    let result = match wire_protocol.as_str() {
        "mysql" => {
            tcp::run_mysql_proxy(
                tcp_opts,
                ruleset,
                policy,
                agent_access,
                telemetry_mode,
                telemetry_sink,
            )
            .await
        }
        _ => {
            tcp::run_pg_proxy(
                tcp_opts,
                ruleset,
                policy,
                agent_access,
                telemetry_mode,
                telemetry_sink,
            )
            .await
        }
    };

    if let Err(e) = result {
        tracing::error!(error = %e, wire_protocol = %wire_protocol, "The TCP proxy failed");
        std::process::exit(1);
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,vericto_proxy=debug"));
    fmt().with_env_filter(filter).json().init();
}
