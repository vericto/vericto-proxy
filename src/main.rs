// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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

// No `unsafe` in the proxy itself; keep it that way without a reviewed opt-out.
#![forbid(unsafe_code)]

mod config;
mod runtime_sizing;
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

fn main() {
    // `vericto-proxy healthcheck` (4.15.2): the container health check, since the
    // runtime image has no shell. Any other argument is ignored, as before. It
    // needs no runtime (4.16.2: none is started for it).
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(crate::tcp::healthz::healthcheck_command(&|key| {
            std::env::var(key).ok()
        }));
    }

    init_tracing();

    // 4.16.2: as many async workers as the CPU time the proxy may use, not one per
    // CPU it may run on (runtime_sizing). A 0.5 vCPU Fargate task saw 2 CPUs and
    // started 2 workers for half a CPU.
    let sizing = match runtime_sizing::from_environment() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().worker_threads(sizing.worker_threads);
    let runtime = match builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "Could not start the async runtime");
            std::process::exit(1);
        }
    };
    tracing::info!(
        worker_threads = sizing.worker_threads,
        source = sizing.source.as_str(),
        cpu_limit = sizing.cpu_limit,
        available_cpus = sizing.available_cpus,
        "Runtime sizing"
    );
    runtime.block_on(run());
}

async fn run() {
    // Install the process-default rustls crypto provider (ring) before any TLS
    // is used (upstream TLS client + telemetry/rule-sync HTTPS). Idempotent.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    if let Ok(wire_protocol) = std::env::var("VERICTO_WIRE_PROTOCOL")
        && let Err(e) = config::check_wire_protocol(&wire_protocol)
    {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    let tcp_opts = match tcp::TcpProxyOptions::from_env() {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            tracing::error!(
                "UPSTREAM_HOST is not set — vericto-proxy requires a database upstream to proxy to. \
                 Set UPSTREAM_HOST to the hostname of your production database."
            );
            std::process::exit(1);
        }
        // An unsupported UPSTREAM_SSLMODE / PROXY_TLS_MODE: never start that hop
        // in plaintext by mistake.
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
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

    // Business policy rules (VERICTO_POLICY_RULES, default off, since 4.15.0):
    // the principals and policies of the last sync. Empty until one arrives,
    // and never filled with the flag off.
    let policy_rules: tcp::policy_rules::SharedPolicyRules = Arc::new(ArcSwap::from_pointee(
        tcp::policy_rules::PolicyRules::default(),
    ));

    // Readiness signal for the health-check listener: not-ready until warm-up
    // completes. When the control-plane link is enabled, the syncer flips it
    // after its first sync attempt; when disabled, we're ready immediately (the
    // built-in default ruleset is already active and protective).
    let readiness = crate::tcp::healthz::Readiness::new();

    // Metrics (4.12.0): `/metrics` on the healthz listener and CloudWatch EMF on
    // stdout, both opt-in; the healthz bind address; per-task spool directories.
    let metrics_cfg = telemetry::metrics::MetricsConfig::from_env();
    let healthz_addr = match crate::tcp::healthz::bind_addr_from(
        std::env::var("VERICTO_HEALTHZ_ADDR").ok().as_deref(),
    ) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    let subdir = match telemetry::spool_dir::SubdirConfig::from_env() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    // The task id names the EMF `TaskId` dimension and, with
    // VERICTO_TELEMETRY_SPOOL_SUBDIR=task, the spool directory.
    let task_id = if metrics_cfg.emf
        || matches!(
            subdir.mode,
            telemetry::spool_dir::SubdirMode::Task | telemetry::spool_dir::SubdirMode::Hostname
        ) {
        Some(telemetry::spool_dir::instance_name().await)
    } else {
        None
    };

    // Control-plane link (telemetry + rule sync) — optional.
    let control_plane = match config::ControlPlaneConfig::from_env() {
        Ok(cp) => cp,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    let mut shutdown_flush: Option<ShutdownFlush> = None;
    let mut metrics_stats: Option<telemetry::heartbeat::StatsSource> = None;
    let mut bundle_verifier: Option<Arc<tcp::bundle_signature::BundleVerifier>> = None;
    let telemetry_sink = match control_plane {
        Some(mut cp) => {
            // One spool directory per proxy on a shared volume (4.12.0,
            // telemetry::spool_dir). The rules cache keeps its path, resolved from
            // the shared directory.
            let mut layout = None;
            if cp.buffer_mode == config::BufferMode::Disk {
                if let Some(name) =
                    telemetry::spool_dir::resolve_name(&subdir.mode, task_id.as_deref()).await
                {
                    match telemetry::spool_dir::SpoolLayout::new(&cp.disk_spool_path, &name)
                        .prepare(subdir.orphan_after)
                    {
                        Ok(l) => {
                            tracing::info!(
                                shared = %cp.disk_spool_path,
                                own = %l.own_dir().display(),
                                orphan_after_secs = subdir.orphan_after.as_secs(),
                                "Telemetry spool: one directory per proxy"
                            );
                            cp.disk_spool_path = l.own_dir().to_string_lossy().into_owned();
                            layout = Some(Arc::new(l));
                        }
                        Err(e) => tracing::error!(
                            error = %e,
                            dir = %cp.disk_spool_path,
                            "Could not set up this proxy's spool subdirectory; spooling to the shared directory"
                        ),
                    }
                }
            }

            tracing::info!(
                buffer = ?cp.buffer_mode,
                rules_sync_secs = cp.rules_sync_interval.as_secs(),
                "Control-plane link enabled (telemetry + rule sync)"
            );

            // Telemetry reporter: drains the queue and POSTs to /ingest/events. The
            // queue is gated by the monthly-quota pause it shares with the reporter
            // and the rule syncer (4.12.0, telemetry::quota).
            let quota_gate = Arc::new(telemetry::quota::QuotaGate::new());
            let queue: Arc<dyn telemetry::EventQueue> =
                Arc::new(telemetry::quota::QuotaGatedQueue::new(
                    telemetry::new_queue(&cp),
                    Arc::clone(&quota_gate),
                ));
            let reporter =
                telemetry::Reporter::new(cp.clone(), queue.clone()).with_quota_gate(quota_gate);
            // Its counters ride on every rule sync (4.12.0).
            let spool_max_bytes = if queue.spool_dir().is_some() {
                cp.spool.max_bytes
            } else {
                0
            };
            let sync_stats = telemetry::heartbeat::StatsSource::new(
                cp.buffer_mode,
                queue.clone(),
                reporter.clone(),
            )
            .with_spool_max_bytes(spool_max_bytes);
            metrics_stats = Some(sync_stats.clone());
            // Adopt orphaned spools and keep this one's lease (only for a disk
            // spool that opened: never move another proxy's events into memory).
            let layout = layout.filter(|_| queue.spool_dir().is_some());
            if let Some(layout) = &layout {
                let (layout, queue) = (Arc::clone(layout), queue.clone());
                let orphan_after = subdir.orphan_after;
                tokio::spawn(async move {
                    telemetry::spool_dir::run_maintenance(layout, queue, orphan_after).await
                });
            }

            // Bundle signatures (4.16.0): with policy rules on, the syncer applies
            // only bundles signed by a trusted key. The keyring is resolved here,
            // once; a malformed override stops the proxy instead of trusting less
            // (or more) than the operator meant.
            bundle_verifier = if tcp_opts.policy_rules.is_on() {
                match tcp::bundle_signature::Keyring::from_vars(&cp.api_url, |k| {
                    std::env::var(k).ok()
                }) {
                    Ok(keyring) => {
                        if keyring.is_empty() {
                            tracing::warn!(
                                alert = "bundle_signature_no_trusted_key",
                                api_url = %cp.api_url,
                                "VERICTO_POLICY_RULES is on but no bundle-signing key is trusted for this \
                                 VERICTO_API_URL: every sync bundle will be refused and the built-in ruleset \
                                 stays in effect. Set VERICTO_BUNDLE_SIGNING_KEYS or \
                                 VERICTO_BUNDLE_SIGNING_KEYS_FILE to the control plane's public key(s)"
                            );
                        } else {
                            tracing::info!(
                                key_ids = ?keyring.key_ids(),
                                source = ?keyring.source(),
                                "Sync bundles must carry a valid Ed25519 signature (VERICTO_POLICY_RULES is on)"
                            );
                        }
                        Some(Arc::new(tcp::bundle_signature::BundleVerifier::new(
                            keyring,
                        )))
                    }
                    Err(e) => {
                        tracing::error!("{e}");
                        std::process::exit(1);
                    }
                }
            } else {
                if [
                    tcp::bundle_signature::KEYS_ENV,
                    tcp::bundle_signature::KEYS_FILE_ENV,
                ]
                .iter()
                .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()))
                {
                    tracing::info!(
                        "VERICTO_BUNDLE_SIGNING_KEYS(_FILE) is set but VERICTO_POLICY_RULES is off: \
                         sync bundles are not verified, the keys are ignored"
                    );
                }
                None
            };

            // Rule syncer: polls GET /sync/rules and swaps the ruleset and
            // policy in place. Flips `readiness` after its first attempt.
            let sync_cfg = cp.clone();
            let sync_ruleset = ruleset.clone();
            let sync_policy = policy.clone();
            let sync_agent_access = agent_access.clone();
            let sync_telemetry_mode = telemetry_mode.clone();
            let sync_readiness = readiness.clone();
            let sync_policy_rules = crate::tcp::rules_sync::PolicyRulesSync {
                mode: tcp_opts.policy_rules,
                bundle: policy_rules.clone(),
                verifier: bundle_verifier.clone(),
            };
            tokio::spawn(async move {
                crate::tcp::rules_sync::run_with_policy_rules(
                    sync_cfg,
                    sync_ruleset,
                    sync_policy,
                    sync_agent_access,
                    sync_telemetry_mode,
                    sync_policy_rules,
                    sync_readiness,
                    Some(sync_stats),
                )
                .await
            });

            shutdown_flush = Some(ShutdownFlush {
                queue: queue.clone(),
                reporter: reporter.clone(),
                timeout: cp.spool.shutdown_timeout,
                layout,
            });
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
        let extras = crate::tcp::healthz::HealthzExtras {
            metrics: metrics_cfg.prometheus,
            stats: metrics_stats.clone(),
            bundle_signatures: bundle_verifier.as_ref().map(|v| Arc::clone(&v.stats)),
        };
        tokio::spawn(async move {
            if let Err(e) = crate::tcp::healthz::run_healthz(
                healthz_addr,
                healthz_port,
                healthz_readiness,
                extras,
            )
            .await
            {
                tracing::error!(error = %e, port = healthz_port, "healthz listener failed");
            }
        });
    } else if metrics_cfg.prometheus {
        tracing::warn!(
            "VERICTO_METRICS_PROMETHEUS is set but VERICTO_HEALTHZ_PORT is not: /metrics is served on the healthz listener only, so it is off"
        );
    }

    // CloudWatch EMF (4.12.0): one line of metrics per interval on stdout.
    if metrics_cfg.emf {
        match metrics_stats.clone() {
            Some(stats) => {
                let cfg = metrics_cfg.clone();
                let task_id = task_id.clone();
                tokio::spawn(async move { telemetry::metrics::run_emf(cfg, stats, task_id).await });
            }
            None => tracing::warn!(
                "VERICTO_METRICS_EMF is set but the control-plane link is off: there is no telemetry pipeline to report"
            ),
        }
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

    let proxy = async {
        match wire_protocol.as_str() {
            "mysql" => {
                tcp::run_mysql_proxy(
                    tcp_opts,
                    ruleset,
                    policy,
                    agent_access,
                    telemetry_mode,
                    policy_rules,
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
                    policy_rules,
                    telemetry_sink,
                )
                .await
            }
        }
    };

    tokio::select! {
        result = proxy => {
            if let Err(e) = result {
                tracing::error!(error = %e, wire_protocol = %wire_protocol, "The TCP proxy failed");
                std::process::exit(1);
            }
        }
        signal = shutdown_signal() => {
            tracing::info!(signal, "Shutting down");
            if let Some(flush) = shutdown_flush {
                flush.run().await;
            }
            // Exit now: open sessions and blocking-pool work are abandoned, as
            // they would be by the default disposition of the signal.
            std::process::exit(0);
        }
    }
}

/// What the proxy does with buffered telemetry when it is asked to stop.
struct ShutdownFlush {
    queue: Arc<dyn telemetry::EventQueue>,
    reporter: telemetry::Reporter,
    timeout: std::time::Duration,
    /// This proxy's spool directory on a shared volume: its lease is released
    /// after the flush, so another proxy adopts what is left at its next scan.
    layout: Option<Arc<telemetry::spool_dir::SpoolLayout>>,
}

impl ShutdownFlush {
    /// Within `timeout` in total: write what is still queued to the spool (disk
    /// mode), then deliver what can be delivered. What is not delivered stays
    /// on disk for the next process (disk mode) or is lost (memory mode, as on
    /// any restart).
    async fn run(self) {
        let started = std::time::Instant::now();
        let queue = self.queue.clone();
        let timeout = self.timeout;
        let persisted = tokio::task::spawn_blocking(move || queue.flush(timeout))
            .await
            .unwrap_or(false);
        let left = timeout.saturating_sub(started.elapsed());
        let delivered = tokio::time::timeout(left, self.reporter.deliver_pending())
            .await
            .ok();
        let stats = self.queue.stats();
        tracing::info!(
            persisted,
            delivered = delivered.unwrap_or(0),
            delivery_finished = delivered.is_some(),
            queue_depth = stats.queue_depth,
            spooled = stats.spooled,
            dropped_queue_full = stats.dropped_queue_full,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Telemetry flushed at shutdown"
        );
        if let Some(layout) = self.layout {
            let _ = tokio::task::spawn_blocking(move || layout.release()).await;
        }
    }
}

/// Resolves on SIGTERM (what ECS, Kubernetes and `docker stop` send) or SIGINT.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = tokio::signal::ctrl_c() => "SIGINT",
            },
            Err(e) => {
                tracing::warn!(error = %e, "Cannot listen for SIGTERM; only SIGINT triggers a clean shutdown");
                let _ = tokio::signal::ctrl_c().await;
                "SIGINT"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    // Default `info`, as documented in docs/CONFIGURATION.md and set by the
    // Dockerfile. `RUST_LOG=info,vericto_proxy=debug` turns the debug lines back on.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).json().init();
}
