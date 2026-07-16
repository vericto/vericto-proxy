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

/// Runs forever: polls the API on the configured interval and swaps the ruleset
/// and policy when they change. Failures are logged; the last-good ruleset and
/// policy stay in effect.
pub async fn run(
    cfg: ControlPlaneConfig,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    telemetry_mode: SharedTelemetryMode,
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
                match res.json::<SyncResponse>().await {
                    Ok(body) => {
                        let new_mode = TelemetryQueryMode::from_api(
                            body.policy
                                .as_ref()
                                .and_then(|p| p.telemetry_query_mode.as_deref()),
                        );
                        let new_policy = build_policy(body.policy);
                        let rules: Vec<Rule> =
                            body.rules.into_iter().map(ApiRule::into_rule).collect();
                        let count = rules.len();
                        ruleset.store(Arc::new(rules));
                        policy.store(Arc::new(new_policy));
                        telemetry_mode.store(Arc::new(new_mode));
                        etag = new_etag;

                        // Apply dashboard-configured proxy settings (hot-reload)
                        if let Some(pc) = body.proxy_config {
                            if let Some(interval_secs) = pc.rules_sync_interval_secs {
                                let new_interval = Duration::from_secs(interval_secs.max(30));
                                if new_interval != sync_interval {
                                    sync_interval = new_interval;
                                    ticker = tokio::time::interval(sync_interval);
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
                                let proto = std::env::var("VERICTO_WIRE_PROTOCOL")
                                    .unwrap_or_else(|_| "postgres".into());
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

                        tracing::info!(
                            count,
                            monitor_mode = new_policy.monitor_mode,
                            telemetry_query_mode = ?new_mode,
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
}
