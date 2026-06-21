//! Vetro Proxy — deterministic AST evaluation service.
//!
//! Exposes a local HTTP endpoint that the Fastify API calls to decide whether a
//! SQL query is safe or destructive, using AST parsing (pg_query + sqlparser-rs)
//! with no AI and no stochastic heuristics.
//!
//! Routes:
//!   POST /evaluate  — evaluate a query against the active ruleset
//!   GET  /health    — health check
//!   GET  /metrics   — counters and latency percentiles

mod cache;
mod config;
mod error;
mod metrics;
mod parser;
mod proxy;
mod rules;
mod tcp;
mod telemetry;

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use axum::{
    routing::{get, post},
    Json, Router,
};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::error::MAX_QUERY_SIZE_BYTES;
use crate::proxy::AppState;

#[tokio::main]
async fn main() {
    init_tracing();

    let state = Arc::new(AppState::new());

    let app = Router::new()
        .route("/evaluate", post(proxy::evaluate))
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        // Request body limit aligned with the max query size (+ slack).
        .layer(RequestBodyLimitLayer::new(MAX_QUERY_SIZE_BYTES + 8 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = std::env::var("PROXY_EVAL_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5434);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("vetro-proxy AST engine listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("could not bind to the proxy port");

    // Start the PostgreSQL TCP proxy if the upstream is configured.
    // It runs in parallel with the AST evaluation HTTP server.
    if let Some(tcp_opts) = tcp::TcpProxyOptions::from_env() {
        // Shared, hot-swappable ruleset. Seeded with the local default so the
        // proxy is protective from the first connection, even before the first
        // sync (or with no control-plane configured at all).
        let ruleset: rules::sync::SharedRuleset =
            Arc::new(ArcSwap::from_pointee(tcp::evaluator::default_ruleset()));

        // Control-plane link (telemetry + rule sync) is optional. When the
        // VETRO_API_URL/VETRO_API_KEY env vars are set, wire up both.
        let telemetry_sink = match config::ControlPlaneConfig::from_env() {
            Some(cp) => {
                tracing::info!(
                    buffer = ?cp.buffer_mode,
                    rules_sync_secs = cp.rules_sync_interval.as_secs(),
                    "Control-plane link enabled (telemetry + rule sync)"
                );

                // Rule syncer: polls the API and swaps `ruleset` in place.
                let sync_cfg = cp.clone();
                let sync_ruleset = ruleset.clone();
                tokio::spawn(async move { rules::sync::run(sync_cfg, sync_ruleset).await });

                // Telemetry: shared queue + background reporter.
                let queue: Arc<dyn telemetry::EventQueue> = Arc::from(telemetry::new_queue(&cp));
                let reporter = telemetry::Reporter::new(cp.clone(), queue.clone());
                tokio::spawn(async move { reporter.run().await });

                tcp_opts.database_id.clone().map(|database_id| tcp::postgres::TelemetrySink {
                    queue,
                    database_id,
                })
            }
            None => {
                tracing::info!(
                    "Control-plane link disabled (set VETRO_API_URL and VETRO_API_KEY to enable it)"
                );
                None
            }
        };

        tokio::spawn(async move {
            if let Err(e) = tcp::run_pg_proxy(tcp_opts, ruleset, telemetry_sink).await {
                tracing::error!(error = %e, "The PostgreSQL TCP proxy failed");
            }
        });
    } else {
        tracing::info!(
            "PostgreSQL TCP proxy disabled (set UPSTREAM_PG_HOST to enable it)"
        );
    }

    axum::serve(listener, app)
        .await
        .expect("the proxy server failed");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "vetro-proxy",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Json<crate::metrics::MetricsSnapshot> {
    Json(state.metrics.snapshot())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,vetro_proxy=debug"));
    fmt().with_env_filter(filter).json().init();
}
