//! Rule syncer: periodically polls GET /sync/rules and hot-swaps the active
//! ruleset (and enforcement policy) used by the TCP proxy. Uses ETag
//! conditional requests so an unchanged ruleset costs a single 304.
//!
//! Both the ruleset and the policy are held in `ArcSwap` so the hot path reads
//! them lock-free; the syncer replaces the whole `Arc<…>` atomically on change.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::config::ControlPlaneConfig;
use crate::tcp::rules_cache::RulesCache;
use vericto_engine::{
    EnforcementAction, EnforcementPolicy, ParseErrorAction, Rule, RuleType, Severity,
};

/// Shared, hot-swappable ruleset.
pub type SharedRuleset = Arc<ArcSwap<Vec<Rule>>>;

/// Shared, hot-swappable enforcement policy (swapped together with the ruleset).
pub type SharedPolicy = Arc<ArcSwap<EnforcementPolicy>>;

/// How query text is reported in telemetry. Swapped together with the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelemetryQueryMode {
    /// Report the full query text (default; max forensic detail).
    #[default]
    Raw,
    /// Normalize literals to placeholders before reporting (no user data leaves).
    Sanitized,
}

impl TelemetryQueryMode {
    /// Parses the API token; anything other than "sanitized" is `Raw` (safe default).
    fn from_api(raw: Option<&str>) -> Self {
        match raw.map(|s| s.to_ascii_lowercase()) {
            Some(ref s) if s == "sanitized" => TelemetryQueryMode::Sanitized,
            _ => TelemetryQueryMode::Raw,
        }
    }
}

/// Shared, hot-swappable telemetry query mode (swapped together with the policy).
pub type SharedTelemetryMode = Arc<ArcSwap<TelemetryQueryMode>>;

#[derive(Debug, Deserialize)]
struct SyncResponse {
    #[allow(dead_code)]
    version: String,
    rules: Vec<ApiRule>,
    /// Absent when the proxy talks to an older API during the compatibility
    /// window; falls back to `EnforcementPolicy::default()`.
    #[serde(default)]
    policy: Option<ApiPolicy>,
    /// Dashboard-configured proxy settings (hot-reloaded).
    #[serde(default)]
    proxy_config: Option<ProxyConfig>,
}

/// Settings configurable from the Vericto dashboard, applied without restart.
/// TLS to the upstream database (UPSTREAM_SSLMODE + certificate) is NOT here —
/// it's an env var because it requires mounting a CA certificate in the container.
#[derive(Debug, Deserialize, Default)]
struct ProxyConfig {
    rules_sync_interval_secs: Option<u64>,
    telemetry_batch_size: Option<usize>,
    telemetry_flush_secs: Option<u64>,
    telemetry_memory_capacity: Option<usize>,
    /// SQL dialect of the fronted database, as configured in the dashboard
    /// (postgres | mysql | oracle | mssql). The wire protocol is fixed at
    /// startup by `VERICTO_WIRE_PROTOCOL`; this is surfaced so an operator can
    /// detect a mismatch between the deployed protocol and the dashboard's
    /// dialect (logged as a warning on sync).
    #[serde(default)]
    dialect: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiRule {
    rule_id: String,
    code: String,
    /// Severity in legacy (critical|warning|info) or canonical
    /// (critical|high|medium|low|informational) vocabulary.
    severity: String,
    /// "block" | "flag" | "monitor" — built-in recommended action (R13).
    #[serde(default)]
    default_action: Option<String>,
    /// "standard" | "custom"
    rule_type: String,
    ast_condition_yaml: Option<String>,
}

/// Per-workspace enforcement policy as returned by the API.
#[derive(Debug, Deserialize)]
struct ApiPolicy {
    /// Maps a canonical severity ("critical"…"informational") to an action
    /// ("block" | "flag" | "monitor").
    #[serde(default)]
    severity_actions: HashMap<String, String>,
    /// "allow_report" | "block"
    #[serde(default)]
    parse_error_action: Option<String>,
    #[serde(default)]
    monitor_mode: bool,
    /// "raw" | "sanitized" — how query text is reported in telemetry.
    #[serde(default)]
    telemetry_query_mode: Option<String>,
}

impl ApiRule {
    fn into_rule(self) -> Rule {
        // `from_legacy` accepts both legacy and canonical vocabularies.
        let severity = Severity::from_legacy(&self.severity);
        let default_action = self
            .default_action
            .as_deref()
            .map(parse_action)
            // Fall back to the action the default policy would resolve for the
            // severity, keeping severity↔action consistent (R13).
            .unwrap_or_else(|| EnforcementPolicy::default().action_for(severity));
        let rule_type = if self.rule_type == "custom" {
            RuleType::Custom
        } else {
            RuleType::Standard
        };
        Rule {
            rule_id: self.rule_id,
            code: self.code,
            severity,
            default_action,
            rule_type,
            ast_condition_yaml: self.ast_condition_yaml,
        }
    }
}

/// Parses an enforcement-action token, defaulting unknown values to `Flag`
/// (the safe non-blocking-but-visible action) with a warning.
fn parse_action(raw: &str) -> EnforcementAction {
    match raw.to_ascii_lowercase().as_str() {
        "block" => EnforcementAction::Block,
        "flag" => EnforcementAction::Flag,
        "monitor" => EnforcementAction::Monitor,
        other => {
            tracing::warn!(
                action = other,
                "unknown enforcement action, defaulting to flag"
            );
            EnforcementAction::Flag
        }
    }
}

/// Builds an `EnforcementPolicy` from the API policy object. When `api` is
/// `None` (older API during the compatibility window) the default policy is
/// used. Present severity actions override the corresponding default level.
fn build_policy(api: Option<ApiPolicy>) -> EnforcementPolicy {
    let mut policy = EnforcementPolicy::default();
    let Some(api) = api else {
        return policy;
    };

    for (severity, action) in &api.severity_actions {
        let action = parse_action(action);
        match Severity::from_legacy(severity) {
            Severity::Critical => policy.critical = action,
            Severity::High => policy.high = action,
            Severity::Medium => policy.medium = action,
            Severity::Low => policy.low = action,
            Severity::Informational => policy.informational = action,
        }
    }

    if let Some(pe) = api.parse_error_action.as_deref() {
        policy.parse_error = match pe.to_ascii_lowercase().as_str() {
            "block" => ParseErrorAction::Block,
            _ => ParseErrorAction::AllowReport,
        };
    }

    policy.monitor_mode = api.monitor_mode;
    policy
}

/// What [`apply`] put in effect, for logging and the dashboard-driven settings.
struct Applied {
    count: usize,
    monitor_mode: bool,
    mode: TelemetryQueryMode,
    proxy_config: Option<ProxyConfig>,
}

/// Swaps in the ruleset, policy and telemetry mode from one `/sync/rules` response.
/// Shared by the live sync and the rules cache, so both enforce a response the same way.
fn apply(
    body: SyncResponse,
    ruleset: &SharedRuleset,
    policy: &SharedPolicy,
    telemetry_mode: &SharedTelemetryMode,
) -> Applied {
    let mode = TelemetryQueryMode::from_api(
        body.policy
            .as_ref()
            .and_then(|p| p.telemetry_query_mode.as_deref()),
    );
    let new_policy = build_policy(body.policy);
    let monitor_mode = new_policy.monitor_mode;
    let rules: Vec<Rule> = body.rules.into_iter().map(ApiRule::into_rule).collect();
    let count = rules.len();
    ruleset.store(Arc::new(rules));
    policy.store(Arc::new(new_policy));
    telemetry_mode.store(Arc::new(mode));
    Applied {
        count,
        monitor_mode,
        mode,
        proxy_config: body.proxy_config,
    }
}

/// Applies the dashboard-configured proxy settings (hot-reload).
fn apply_proxy_config(
    pc: &ProxyConfig,
    sync_interval: &mut Duration,
    ticker: &mut tokio::time::Interval,
) {
    if let Some(interval_secs) = pc.rules_sync_interval_secs {
        let new_interval = Duration::from_secs(interval_secs.max(30));
        if new_interval != *sync_interval {
            *sync_interval = new_interval;
            *ticker = tokio::time::interval(new_interval);
            tracing::info!(
                secs = interval_secs,
                "Rules sync interval updated from dashboard"
            );
        }
    }
    // Note: telemetry_batch_size, flush_secs, memory_capacity
    // are applied by the Reporter which re-reads config each cycle.
    if pc.telemetry_batch_size.is_some()
        || pc.telemetry_flush_secs.is_some()
        || pc.telemetry_memory_capacity.is_some()
    {
        tracing::debug!(config = ?pc, "Proxy config received from dashboard");
    }
    // Warn if the dashboard's dialect for this database does not
    // match the wire protocol this proxy was started with. The
    // protocol is fixed at startup (a live listener can't change
    // protocol), so a mismatch means the proxy was deployed with
    // the wrong VERICTO_WIRE_PROTOCOL for this database.
    if let Some(dialect) = pc.dialect.as_deref() {
        let proto = std::env::var("VERICTO_WIRE_PROTOCOL").unwrap_or_else(|_| "postgres".into());
        let expected = matches!(
            (proto.as_str(), dialect),
            ("postgres", "postgres") | ("mysql", "mysql")
        );
        if !expected {
            tracing::warn!(
                wire_protocol = %proto,
                dashboard_dialect = %dialect,
                "Wire protocol does not match the database dialect configured \
                 in the dashboard — this proxy may be fronting the wrong database. \
                 Redeploy with the correct VERICTO_WIRE_PROTOCOL."
            );
        }
    }
}

/// Runs forever: polls the API on the configured interval and swaps the ruleset
/// and policy when they change. Failures are logged; the last-good ruleset and
/// policy stay in effect, and with a rules cache they also survive a restart.
pub async fn run(
    cfg: ControlPlaneConfig,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    telemetry_mode: SharedTelemetryMode,
    readiness: Arc<crate::tcp::healthz::Readiness>,
) {
    let mut url = format!("{}/api/v1/sync/rules", cfg.api_url);
    if let Some(ref db_id) = cfg.database_id {
        url = format!("{url}?database_id={db_id}");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build rule-sync HTTP client");

    let mut etag: Option<String> = None;
    let mut sync_interval = cfg.rules_sync_interval;
    let mut ticker = tokio::time::interval(sync_interval);

    // Resume with the last-good response before the first request, so a restart while
    // the control plane is down keeps the workspace's rules and policy instead of
    // falling back to the built-in ruleset. Its ETag goes on the first request: if
    // nothing changed meanwhile the API answers 304 and the cached copy stays.
    let cache = RulesCache::from_config(&cfg);
    if let Some(cached) = cache.as_ref().and_then(RulesCache::load) {
        match serde_json::from_str::<SyncResponse>(&cached.body) {
            Ok(body) => {
                let applied = apply(body, &ruleset, &policy, &telemetry_mode);
                if let Some(pc) = &applied.proxy_config {
                    apply_proxy_config(pc, &mut sync_interval, &mut ticker);
                }
                etag = cached.etag;
                tracing::info!(
                    count = applied.count,
                    monitor_mode = applied.monitor_mode,
                    saved_at = %cached.saved_at,
                    "Ruleset and policy loaded from the rules cache"
                );
            }
            Err(e) => tracing::warn!(error = %e, "Rules cache body no longer parses; ignoring it"),
        }
    }

    loop {
        ticker.tick().await;

        let mut req = client.get(&url).header("X-API-Key", &cfg.api_key);
        if let Some(tag) = &etag {
            req = req.header("If-None-Match", tag.clone());
        }

        match req.send().await {
            Ok(res) if res.status().as_u16() == 304 => {
                tracing::debug!("Ruleset unchanged (304)");
            }
            Ok(res) if res.status().is_success() => {
                let new_etag = res
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                // Read the body as text so the exact bytes accepted can be cached.
                match res
                    .text()
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|text| {
                        serde_json::from_str::<SyncResponse>(&text)
                            .map(|body| (text, body))
                            .map_err(|e| e.to_string())
                    }) {
                    Ok((text, body)) => {
                        let applied = apply(body, &ruleset, &policy, &telemetry_mode);
                        if let Some(pc) = &applied.proxy_config {
                            apply_proxy_config(pc, &mut sync_interval, &mut ticker);
                        }
                        // Cached only after it parsed and was applied: the file always
                        // holds a response this proxy has enforced, never a bad one.
                        if let Some(cache) = &cache {
                            cache.store(new_etag.as_deref(), &text);
                        }
                        etag = new_etag;
                        tracing::info!(
                            count = applied.count,
                            monitor_mode = applied.monitor_mode,
                            telemetry_query_mode = ?applied.mode,
                            "Ruleset and policy updated from API"
                        );
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to parse /sync/rules response"),
                }
            }
            Ok(res) => {
                tracing::warn!(status = %res.status(), "Rule sync returned non-OK; keeping last-good ruleset");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Rule sync request failed; keeping last-good ruleset");
            }
        }

        // Warm-up complete after the FIRST sync attempt — success or failure.
        // On failure the built-in default ruleset (seeded at startup) stays in
        // effect and is fully protective, so the proxy is ready to serve even if
        // the control plane is unreachable. Gating readiness on sync *success*
        // would couple a control-plane outage to a proxy outage; we deliberately
        // do not. Idempotent, so calling it every iteration is cheap.
        readiness.mark_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_policy_none_yields_default() {
        let policy = build_policy(None);
        assert_eq!(policy, EnforcementPolicy::default());
    }

    #[test]
    fn build_policy_overrides_only_present_levels() {
        let mut severity_actions = HashMap::new();
        severity_actions.insert("medium".to_string(), "monitor".to_string());
        let api = ApiPolicy {
            severity_actions,
            parse_error_action: Some("block".to_string()),
            monitor_mode: true,
            telemetry_query_mode: None,
        };
        let policy = build_policy(Some(api));
        // Overridden level.
        assert_eq!(policy.medium, EnforcementAction::Monitor);
        // Untouched levels keep their defaults.
        assert_eq!(policy.critical, EnforcementAction::Block);
        assert_eq!(policy.high, EnforcementAction::Block);
        assert_eq!(policy.parse_error, ParseErrorAction::Block);
        assert!(policy.monitor_mode);
    }

    #[test]
    fn into_rule_uses_from_legacy_and_default_action_fallback() {
        let api = ApiRule {
            rule_id: "r1".to_string(),
            code: "VERICTO-050".to_string(),
            severity: "warning".to_string(), // legacy → High
            default_action: None,
            rule_type: "standard".to_string(),
            ast_condition_yaml: None,
        };
        let rule = api.into_rule();
        assert_eq!(rule.severity, Severity::High);
        // No explicit action → resolved from default policy for High → Block.
        assert_eq!(rule.default_action, EnforcementAction::Block);
    }

    #[test]
    fn into_rule_respects_explicit_default_action() {
        let api = ApiRule {
            rule_id: "r2".to_string(),
            code: "VERICTO-050".to_string(),
            severity: "medium".to_string(),
            default_action: Some("flag".to_string()),
            rule_type: "standard".to_string(),
            ast_condition_yaml: None,
        };
        let rule = api.into_rule();
        assert_eq!(rule.severity, Severity::Medium);
        assert_eq!(rule.default_action, EnforcementAction::Flag);
    }

    #[test]
    fn telemetry_query_mode_parses_from_api() {
        assert_eq!(
            TelemetryQueryMode::from_api(Some("sanitized")),
            TelemetryQueryMode::Sanitized
        );
        assert_eq!(
            TelemetryQueryMode::from_api(Some("SANITIZED")),
            TelemetryQueryMode::Sanitized
        );
        assert_eq!(
            TelemetryQueryMode::from_api(Some("raw")),
            TelemetryQueryMode::Raw
        );
        assert_eq!(
            TelemetryQueryMode::from_api(Some("bogus")),
            TelemetryQueryMode::Raw
        );
        assert_eq!(TelemetryQueryMode::from_api(None), TelemetryQueryMode::Raw);
        assert_eq!(TelemetryQueryMode::default(), TelemetryQueryMode::Raw);
    }

    /// A restart while the control plane is down resumes with the last-good response:
    /// the custom rule and the workspace policy, not the built-in ruleset.
    #[tokio::test]
    async fn restart_during_an_outage_resumes_from_the_rules_cache() {
        use crate::config::BufferMode;
        use axum::{Router, http::header, routing::get};

        const BODY: &str = r#"{
            "version": "v7",
            "rules": [{"rule_id": "custom-1", "code": "ACME-001", "severity": "high",
                       "default_action": "block", "rule_type": "custom",
                       "ast_condition_yaml": "node: DropStmt"}],
            "policy": {"severity_actions": {"high": "flag"}, "monitor_mode": true,
                       "telemetry_query_mode": "sanitized"}
        }"#;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/sync/rules",
            get(|| async { ([(header::ETAG, "\"v7\"")], BODY) }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("rules-cache.json");
        let cfg = ControlPlaneConfig {
            api_url: format!("http://{addr}"),
            api_key: "vk_test".into(),
            database_id: Some("db-1".into()),
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: Some(cache_path.clone()),
            buffer_mode: BufferMode::Disk,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
        };
        let fresh = || {
            (
                Arc::new(ArcSwap::from_pointee(
                    crate::tcp::evaluator::default_ruleset(),
                )),
                Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
                Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                crate::tcp::healthz::Readiness::new(),
            )
        };

        // 1. Control plane up: the first sync writes the cache.
        let (rules, pol, mode, ready) = fresh();
        let first = tokio::spawn(run(cfg.clone(), rules, pol, mode, ready.clone()));
        ready.wait_ready().await;
        first.abort();
        assert!(
            cache_path.exists(),
            "a successful sync must write the cache"
        );

        // 2. Control plane down, proxy restarted.
        server.abort();
        let _ = server.await;
        let (rules, pol, mode, ready) = fresh();
        let second = tokio::spawn(run(
            cfg,
            rules.clone(),
            pol.clone(),
            mode.clone(),
            ready.clone(),
        ));
        ready.wait_ready().await;
        second.abort();

        let rules = rules.load();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].code, "ACME-001");
        assert_eq!(rules[0].rule_type, RuleType::Custom);
        let pol = pol.load();
        assert!(pol.monitor_mode);
        assert_eq!(pol.high, EnforcementAction::Flag);
        assert_eq!(**mode.load(), TelemetryQueryMode::Sanitized);
    }

    /// Without a cache the same outage falls back to the built-in ruleset (unchanged).
    #[tokio::test]
    async fn without_a_cache_an_outage_keeps_the_built_in_ruleset() {
        use crate::config::BufferMode;

        let cfg = ControlPlaneConfig {
            // Port 9 (discard) on loopback: refused immediately.
            api_url: "http://127.0.0.1:9".into(),
            api_key: "vk_test".into(),
            database_id: None,
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: None,
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
        };
        let builtin = crate::tcp::evaluator::default_ruleset();
        let rules: SharedRuleset = Arc::new(ArcSwap::from_pointee(builtin.clone()));
        let ready = crate::tcp::healthz::Readiness::new();
        let task = tokio::spawn(run(
            cfg,
            rules.clone(),
            Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
            ready.clone(),
        ));
        ready.wait_ready().await;
        task.abort();
        assert_eq!(rules.load().len(), builtin.len());
    }
}
