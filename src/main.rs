//! vetro-proxy — Deterministic SQL firewall (TCP wire-protocol mode).
//!
//! Customer-facing component: intercepts every query via the PostgreSQL wire
//! protocol, evaluates it with the vetro-engine AST parser, and either forwards
//! it to the real database or blocks it — all in <2ms.
//!
//! Telemetry is reported to the Vetro API (HTTPS) in batches; the ruleset is
//! pulled from the API on a configurable polling interval (default: 5 min).
//!
//! Required env vars for TCP mode:
//!   UPSTREAM_PG_HOST — the real PostgreSQL host to forward safe queries to
//!
//! Optional env vars for control-plane link:
//!   VETRO_API_URL    — e.g. https://api.vetro.dev
//!   VETRO_API_KEY    — workspace API key (vtro_...)
//!   VETRO_DATABASE_ID — UUID of the database record in the Vetro platform

mod config;
mod tcp;
mod telemetry;

use std::sync::Arc;
use arc_swap::ArcSwap;

use vetro_engine::EnforcementPolicy;

use crate::tcp::evaluator::default_ruleset;
use crate::tcp::rules_sync::{SharedPolicy, SharedRuleset};

// vetro-engine re-exports through the tcp evaluator module's imports


#[tokio::main]
async fn main() {
    init_tracing();

    let Some(tcp_opts) = tcp::TcpProxyOptions::from_env() else {
        tracing::error!(
            "UPSTREAM_PG_HOST is not set — vetro-proxy requires a PostgreSQL upstream to proxy to. \
             Set UPSTREAM_PG_HOST to the hostname of your production database."
        );
        std::process::exit(1);
    };

    // Shared, hot-swappable ruleset seeded with the built-in critical rules.
    // Protective from the first connection even before the first API sync.
    let ruleset: SharedRuleset =
        Arc::new(ArcSwap::from_pointee(default_ruleset()));

    // Shared, hot-swappable enforcement policy. Defaults until the first API
    // sync (Critical/High → BLOCK, Medium → FLAG, Low/Informational → MONITOR,
    // parse-error → allow_report).
    let policy: SharedPolicy =
        Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default()));

    // Control-plane link (telemetry + rule sync) — optional.
    let telemetry_sink = match config::ControlPlaneConfig::from_env() {
        Some(cp) => {
            tracing::info!(
                buffer = ?cp.buffer_mode,
                rules_sync_secs = cp.rules_sync_interval.as_secs(),
                "Control-plane link enabled (telemetry + rule sync)"
            );

            // Rule syncer: polls GET /sync/rules and swaps the ruleset and
            // policy in place.
            let sync_cfg = cp.clone();
            let sync_ruleset = ruleset.clone();
            let sync_policy = policy.clone();
            tokio::spawn(async move {
                crate::tcp::rules_sync::run(sync_cfg, sync_ruleset, sync_policy).await
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
                 (set VETRO_API_URL and VETRO_API_KEY to enable telemetry and rule sync)"
            );
            None
        }
    };

    tracing::info!(
        upstream = %format!("{}:{}", tcp_opts.upstream_host, tcp_opts.upstream_port),
        "vetro-proxy starting"
    );

    if let Err(e) = tcp::run_pg_proxy(tcp_opts, ruleset, policy, telemetry_sink).await {
        tracing::error!(error = %e, "The PostgreSQL TCP proxy failed");
        std::process::exit(1);
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,vetro_proxy=debug"));
    fmt().with_env_filter(filter).json().init();
}
