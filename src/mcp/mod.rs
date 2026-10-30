// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `vericto-proxy mcp`: **Proxy mode** (design "MCP execution modes",
//! milestone M1, the read tier). An MCP server, in the existing binary, that
//! evaluates and runs SQL on one PostgreSQL database for an agent that holds
//! no database credential: what is checked is what runs.
//!
//! * Transports: stdio (the default; logs on stderr, never stdout) and
//!   stateless Streamable HTTP (`--transport http`). One database per process.
//! * Tools: `execute_sql` (reads only), `describe_schema`, `check_sql`
//!   (evaluated locally) and `whoami`.
//! * Reused from the TCP proxy: the evaluator (rules, policy, masks, agent
//!   access, business policies), rule sync with signed bundles (the signature
//!   is always required in this mode), the rules cache, the kill switch,
//!   telemetry (events tagged `source: mcp_proxy`) and the upstream TLS.
//! * The TCP listener is off in this mode.

pub mod check;
pub mod classify;
pub mod config;
pub mod control;
pub mod env_warning;
pub mod errors;
pub mod execute;
pub mod http;
pub mod identity;
pub mod next_steps;
pub mod pg;
pub mod pool;
pub mod results;
pub mod runtime;
pub mod schema;
pub mod server;
pub mod stack;
pub mod stdio;
pub mod tools;

#[cfg(test)]
mod exact_bytes_tests;
#[cfg(test)]
mod fake_pg;
#[cfg(test)]
mod prop_tests;
#[cfg(test)]
mod protocol_tests;
#[cfg(test)]
mod real_pg_tests;

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use crate::mcp::config::{McpConfig, Transport};
use crate::mcp::runtime::{EventSink, Runtime, Shared};
use crate::tcp::policy_rules::PolicyRulesMode;

/// The control plane `VERICTO_API_URL` defaults to in `mcp` mode when a key
/// is set (design §5.5), so the one-line setup needs only the key and the
/// database id.
pub const DEFAULT_API_URL: &str = "https://api.vericto.com";

/// The rule-sync interval in `mcp` mode when none is set: 30 s instead of the
/// TCP proxy's 300 s, so a revoked key or a kill switch applies sooner (§11.2).
pub const DEFAULT_SYNC_SECS: &str = "30";

/// Flags over the environment, plus the `mcp`-mode defaults.
pub fn layered(
    flags: HashMap<String, String>,
    env: impl Fn(&str) -> Option<String> + 'static,
) -> impl Fn(&str) -> Option<String> {
    move |key: &str| {
        if let Some(v) = flags.get(key) {
            return Some(v.clone());
        }
        let v = env(key);
        if v.is_some() {
            return v;
        }
        match key {
            "VERICTO_API_URL" if env("VERICTO_API_KEY").is_some_and(|k| !k.trim().is_empty()) => {
                Some(DEFAULT_API_URL.to_string())
            }
            "VERICTO_RULES_SYNC_INTERVAL_SECS" => Some(DEFAULT_SYNC_SECS.to_string()),
            _ => None,
        }
    }
}

/// `VERICTO_POLICY_RULES` in `mcp` mode: `enforce` by default. `off` is
/// refused: bundles are always verified here, which means announcing `cel/1`,
/// and a proxy that announces it must evaluate the business policies it gets.
pub fn policy_mode(raw: Option<&str>) -> Result<PolicyRulesMode, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(PolicyRulesMode::Enforce),
        Some(v) => match PolicyRulesMode::parse(Some(v))? {
            PolicyRulesMode::Off => Err(
                "VERICTO_POLICY_RULES=off is not supported in mcp mode: its bundles are always \
                 signed and verified, and carry the business policies (use enforce, the default, \
                 or observe)"
                    .to_string(),
            ),
            m => Ok(m),
        },
    }
}

fn fail(msg: &str) -> ! {
    tracing::error!("{msg}");
    eprintln!("vericto-proxy mcp: {msg}");
    std::process::exit(1)
}

/// Entry point of `vericto-proxy mcp …` (tracing already set up, on stderr).
pub async fn run(args: Vec<String>) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let parsed = match config::parse_args(&args) {
        Ok(a) => a,
        Err(e) => fail(&e),
    };
    if parsed.help {
        eprint!("{}", config::help_text());
        std::process::exit(0);
    }
    if parsed.version {
        eprintln!("vericto-proxy {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let lookup = layered(parsed.settings, |k| std::env::var(k).ok());
    let cfg = match McpConfig::from_lookup(&lookup) {
        Ok(c) => c,
        Err(e) => fail(&e),
    };
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }
    let t = &cfg.database;
    if let Err(e) = crate::tcp::upstream::validate_upstream_tls(
        t.tls,
        t.ca_path.as_deref(),
        t.client_cert.as_deref(),
        t.client_key.as_deref(),
    ) {
        fail(&format!("the database TLS settings do not load: {e}"));
    }
    if cfg.source_is_env() {
        tracing::warn!(
            alert = "database_url_in_environment",
            "VERICTO_MCP_DATABASE_URL holds the database password in the environment, which leaks \
             through `ps e`, crash reports and child processes; prefer VERICTO_MCP_DATABASE_URL_FILE"
        );
    }
    let policy_mode = match policy_mode(lookup("VERICTO_POLICY_RULES").as_deref()) {
        Ok(m) => m,
        Err(e) => fail(&e),
    };
    let control_plane = match crate::config::ControlPlaneConfig::from_lookup(&lookup) {
        Ok(cp) => cp,
        Err(e) => fail(&e),
    };
    let shared = Shared::built_in();
    let mut warnings = Vec::new();

    // The agent's environment (design §12.1).
    let exposure = env_warning::inspect(
        std::env::vars(),
        std::env::var_os("HOME")
            .as_deref()
            .map(std::path::Path::new),
        cfg.database.secret_file.as_deref(),
    );
    if exposure.any() {
        let what = exposure.describe();
        tracing::warn!(
            alert = "agent_environment_has_db_credentials",
            exposes = %what,
            "This process's environment also exposes database credentials: an agent that can read \
             them can run SQL around Vericto, and the guarantee that what is checked is what runs \
             does not hold. Remove them from the agent's environment (docs/MCP.md, Security)"
        );
        warnings.push(json!({
            "code": "agent_environment_has_db_credentials",
            "message": format!("the agent's environment also exposes database credentials ({what}); the guarantee holds only if the agent has no other way to reach the database"),
        }));
    }

    let mut trusted_keys = false;
    let mut shutdown_flush = None;
    let (telemetry, linked, database_id, process_key) = match control_plane {
        None => {
            tracing::warn!(
                "Control-plane link disabled (set VERICTO_API_KEY and VERICTO_DATABASE_ID): the \
                 built-in ruleset only, no masks, allowlists, kill switch or reporting"
            );
            warnings.push(json!({
                "code": "no_control_plane",
                "message": "no control-plane link: the built-in ruleset only, without the workspace's rules, masks, allowlists, kill switch or reporting",
            }));
            (None, false, None, None)
        }
        Some(cp) => {
            if cp.database_id.is_none() {
                tracing::warn!(
                    "VERICTO_DATABASE_ID is not set: the workspace-level ruleset applies (no per-database masks or allowlists) and no event is reported"
                );
                warnings.push(json!({
                    "code": "no_database_id",
                    "message": "VERICTO_DATABASE_ID is not set: per-database masks and allowlists do not apply, and nothing is reported",
                }));
            }
            let keyring = match crate::tcp::bundle_signature::Keyring::from_vars(&cp.api_url, |k| {
                lookup(k)
            }) {
                Ok(k) => k,
                Err(e) => fail(&e),
            };
            trusted_keys = !keyring.is_empty();
            if !trusted_keys {
                tracing::warn!(
                    alert = "bundle_signature_no_trusted_key",
                    api_url = %cp.api_url,
                    "No bundle-signing key is trusted for this VERICTO_API_URL: every sync bundle is \
                     refused. Set VERICTO_BUNDLE_SIGNING_KEYS or VERICTO_BUNDLE_SIGNING_KEYS_FILE"
                );
                warnings.push(json!({
                    "code": "no_trusted_bundle_key",
                    "message": "no bundle-signing key is trusted for this control plane: no bundle can be applied",
                }));
            }
            let verifier = Arc::new(crate::tcp::bundle_signature::BundleVerifier::new(keyring));
            let quota_gate = Arc::new(crate::telemetry::quota::QuotaGate::new());
            let queue: Arc<dyn crate::telemetry::EventQueue> =
                Arc::new(crate::telemetry::quota::QuotaGatedQueue::new(
                    crate::telemetry::new_queue(&cp),
                    Arc::clone(&quota_gate),
                ));
            let reporter = crate::telemetry::Reporter::new(cp.clone(), queue.clone())
                .with_quota_gate(quota_gate);
            let stats = crate::telemetry::heartbeat::StatsSource::new(
                cp.buffer_mode,
                queue.clone(),
                reporter.clone(),
            );
            let sync = crate::tcp::rules_sync::PolicyRulesSync {
                mode: policy_mode,
                bundle: shared.policy_rules.clone(),
                verifier: Some(verifier),
                require_signature: true,
                watch: Some(Arc::clone(&shared.watch)),
            };
            let readiness = crate::tcp::healthz::Readiness::new();
            let s = shared.clone();
            let sync_cfg = cp.clone();
            tokio::spawn(async move {
                crate::tcp::rules_sync::run_with_policy_rules(
                    sync_cfg,
                    s.ruleset,
                    s.policy,
                    s.agent_access,
                    s.kill_switch,
                    s.telemetry_mode,
                    sync,
                    readiness,
                    Some(stats),
                )
                .await
            });
            shutdown_flush = Some(crate::ShutdownFlush {
                queue: queue.clone(),
                reporter: reporter.clone(),
                timeout: cp.spool.shutdown_timeout,
                layout: None,
            });
            tokio::spawn(async move { reporter.run().await });
            tracing::info!(
                api_url = %cp.api_url,
                rules_sync_secs = cp.rules_sync_interval.as_secs(),
                policy_rules = policy_mode.as_str(),
                "Control-plane link enabled (signed rule sync, telemetry source mcp_proxy)"
            );
            let sink = cp
                .database_id
                .clone()
                .map(|database_id| EventSink { queue, database_id });
            let key = (
                identity::sha256_hex(cp.api_key.as_bytes()),
                identity::fingerprint(&cp.api_key),
            );
            (sink, true, cp.database_id.clone(), Some(key))
        }
    };
    let require_control_plane = cfg.require_control_plane.unwrap_or(linked) && linked;
    let local_tokens = match &cfg.auth_tokens_file {
        Some(p) => match identity::load_tokens_file(p) {
            Ok(t) => t,
            Err(e) => fail(&e),
        },
        None => Vec::new(),
    };
    let rt = Arc::new(Runtime {
        pool: pool::Pool::new(
            cfg.database.clone(),
            cfg.pool_size,
            cfg.pool_idle,
            cfg.allow_md5,
        ),
        cfg,
        shared,
        policy_mode,
        linked,
        require_control_plane,
        trusted_keys,
        telemetry,
        database_id,
        warnings,
        process_key,
        local_tokens,
        session_id: uuid::Uuid::new_v4().to_string(),
    });
    {
        let rt = Arc::clone(&rt);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                rt.pool.sweep();
            }
        });
    }
    tracing::info!(
        transport = ?rt.cfg.transport,
        database = %rt.cfg.database.dbname,
        tls = ?rt.cfg.database.tls,
        require_control_plane = rt.require_control_plane,
        "vericto-proxy mcp starting (Proxy mode, read tier)"
    );
    match rt.cfg.transport {
        Transport::Stdio => {
            stdio::serve(Arc::clone(&rt), tokio::io::stdin(), tokio::io::stdout()).await;
            if let Some(flush) = shutdown_flush {
                flush.run().await;
            }
            std::process::exit(0);
        }
        Transport::Http => {
            let tls = match http_tls(&lookup, &rt.cfg) {
                Ok(t) => t,
                Err(e) => fail(&e),
            };
            if rt.local_tokens.is_empty() && !rt.linked {
                tracing::warn!(
                    "HTTP mode with no control plane and no VERICTO_MCP_AUTH_TOKENS_FILE: every request is refused (401)"
                );
            }
            let listener = match tokio::net::TcpListener::bind(rt.cfg.listen).await {
                Ok(l) => l,
                Err(e) => fail(&format!("cannot listen on {}: {e}", rt.cfg.listen)),
            };
            tracing::info!(listen = %rt.cfg.listen, tls = tls.is_some(), "MCP Streamable HTTP listening on /mcp");
            if let Some(port) =
                lookup("VERICTO_HEALTHZ_PORT").and_then(|p| p.trim().parse::<u16>().ok())
            {
                let addr =
                    crate::tcp::healthz::bind_addr_from(lookup("VERICTO_HEALTHZ_ADDR").as_deref())
                        .unwrap_or_else(|e| fail(&e));
                let ready = crate::tcp::healthz::Readiness::new();
                ready.mark_ready();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::tcp::healthz::run_healthz(addr, port, ready, Default::default())
                            .await
                    {
                        tracing::error!(error = %e, "healthz listener failed");
                    }
                });
            }
            tokio::select! {
                r = http::serve(Arc::clone(&rt), listener, tls) => {
                    if let Err(e) = r { fail(&format!("the HTTP listener failed: {e}")); }
                }
                signal = crate::shutdown_signal() => {
                    tracing::info!(signal, "Shutting down");
                    if let Some(flush) = shutdown_flush { flush.run().await; }
                    std::process::exit(0);
                }
            }
        }
    }
}

/// The TLS of the HTTP listener: `PROXY_TLS_MODE=require` with
/// `PROXY_TLS_CERT`/`PROXY_TLS_KEY`. Off loopback, plaintext needs
/// `VERICTO_MCP_ALLOW_PLAINTEXT_HTTP=true`.
fn http_tls(
    lookup: &dyn Fn(&str) -> Option<String>,
    cfg: &McpConfig,
) -> Result<Option<tokio_rustls::TlsAcceptor>, String> {
    use crate::tcp::client_tls::{ClientTlsMode, build_acceptor};
    let mode = ClientTlsMode::parse(lookup("PROXY_TLS_MODE").as_deref())?;
    match mode {
        ClientTlsMode::Require => {
            let cert = lookup("PROXY_TLS_CERT")
                .ok_or("PROXY_TLS_MODE=require but PROXY_TLS_CERT is not set")?;
            let key = lookup("PROXY_TLS_KEY")
                .ok_or("PROXY_TLS_MODE=require but PROXY_TLS_KEY is not set")?;
            build_acceptor(&cert, &key)
                .map(Some)
                .map_err(|e| format!("PROXY_TLS_CERT/PROXY_TLS_KEY do not load: {e}"))
        }
        ClientTlsMode::Disable => {
            if !cfg.listen.ip().is_loopback() && !cfg.allow_plaintext_http {
                return Err(format!(
                    "VERICTO_MCP_LISTEN={} is not loopback: set PROXY_TLS_MODE=require with \
                     PROXY_TLS_CERT and PROXY_TLS_KEY, or VERICTO_MCP_ALLOW_PLAINTEXT_HTTP=true \
                     behind a TLS-terminating sidecar",
                    cfg.listen
                ));
            }
            Ok(None)
        }
    }
}
