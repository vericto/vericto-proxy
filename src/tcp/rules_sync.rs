//! Rule syncer: periodically polls GET /sync/rules and hot-swaps the active
//! ruleset used by the TCP proxy. Uses ETag conditional requests so an
//! unchanged ruleset costs a single 304.
//!
//! The ruleset is held in an `ArcSwap` so the hot path reads it lock-free; the
//! syncer replaces the whole `Arc<Vec<Rule>>` atomically on change.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::config::ControlPlaneConfig;
use vetro_engine::{Rule, RuleType, Severity};

/// Shared, hot-swappable ruleset.
pub type SharedRuleset = Arc<ArcSwap<Vec<Rule>>>;

#[derive(Debug, Deserialize)]
struct SyncResponse {
    #[allow(dead_code)]
    version: String,
    rules: Vec<ApiRule>,
}

#[derive(Debug, Deserialize)]
struct ApiRule {
    rule_id: String,
    code: String,
    /// API severities are critical|warning|info (DB CHECK constraint).
    severity: String,
    /// "standard" | "custom"
    rule_type: String,
    ast_condition_yaml: Option<String>,
}

impl ApiRule {
    fn into_rule(self) -> Rule {
        // Map API severity vocabulary -> proxy severity vocabulary.
        let severity = match self.severity.as_str() {
            "critical" => Severity::Critical,
            "warning" => Severity::High,
            _ => Severity::Medium, // "info" and anything else
        };
        let rule_type = if self.rule_type == "custom" {
            RuleType::Custom
        } else {
            RuleType::Standard
        };
        Rule {
            rule_id: self.rule_id,
            code: self.code,
            severity,
            rule_type,
            ast_condition_yaml: self.ast_condition_yaml,
        }
    }
}

/// Runs forever: polls the API on the configured interval and swaps the ruleset
/// when it changes. Failures are logged; the last-good ruleset stays in effect.
pub async fn run(cfg: ControlPlaneConfig, ruleset: SharedRuleset) {
    let url = format!("{}/api/v1/sync/rules", cfg.api_url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build rule-sync HTTP client");

    let mut etag: Option<String> = None;
    let mut ticker = tokio::time::interval(cfg.rules_sync_interval);

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
                        let rules: Vec<Rule> =
                            body.rules.into_iter().map(ApiRule::into_rule).collect();
                        let count = rules.len();
                        ruleset.store(Arc::new(rules));
                        etag = new_etag;
                        tracing::info!(count, "Ruleset updated from API");
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
