// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
use crate::tcp::bundle_signature::{BundleSource, BundleVerifier, Keyring, SIGNATURE_HEADER};
use crate::tcp::kill_switch::{KillSwitch, SharedKillSwitch};
use crate::tcp::rules_cache::RulesCache;
use vericto_engine::{
    AccessPolicyMap, EnforcementAction, EnforcementPolicy, ParseErrorAction, Rule, RuleType,
    SensitiveColumn, Severity,
};

/// Shared, hot-swappable ruleset.
pub type SharedRuleset = Arc<ArcSwap<Vec<Rule>>>;

/// Shared, hot-swappable enforcement policy (swapped together with the ruleset).
pub type SharedPolicy = Arc<ArcSwap<EnforcementPolicy>>;

/// Shared, hot-swappable agent-access allowlists of the fronted database, keyed by
/// database user (VERICTO-087). Swapped together with the policy. Each session
/// selects its user's policy from it on every statement (`AccessPolicyMap::for_user`),
/// so a sync that changes a policy applies to open sessions on their next statement.
pub type SharedAccessPolicies = Arc<ArcSwap<AccessPolicyMap>>;

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
    /// The bundle's version (also its ETag): reported as `policy_bundle_version`.
    version: String,
    rules: Vec<ApiRule>,
    /// Absent when the proxy talks to an older API during the compatibility
    /// window; falls back to `EnforcementPolicy::default()`.
    #[serde(default)]
    policy: Option<ApiPolicy>,
    /// Dashboard-configured proxy settings (hot-reloaded).
    #[serde(default)]
    proxy_config: Option<ProxyConfig>,
    /// The database's sensitive-column tags (VERICTO-085), per database and so
    /// only sent for `?database_id=`. Element shape and its fail-safe parsing
    /// (an unknown policy reads as `block`, an unknown mask style as `full`) are
    /// the engine's own `Deserialize` (engine contract §2), not re-implemented
    /// here. Absent, `null` or `[]` = no tags = the policy is exactly what it was
    /// before the field existed. A malformed element fails the whole response,
    /// which keeps the last-good ruleset, tags included.
    #[serde(default)]
    sensitive_columns: Option<Vec<SensitiveColumn>>,
    /// The database's agent-access allowlists (VERICTO-087), keyed by database
    /// user, `"*"` optionally the default for users not listed (engine contract
    /// §2). Per database, like the tags. The element shape and its fail-safe
    /// parsing (an unknown mode reads as `enforce`, an unknown access as `read`)
    /// are the engine's own `Deserialize`. Absent, `null` or `{}` = no allowlist
    /// for any user = exactly the behaviour before the field existed. A malformed
    /// policy fails the whole response, which keeps the last-good one.
    #[serde(default)]
    agent_access: Option<AccessPolicyMap>,
    /// "ok" | "exceeded": the workspace's monthly query quota (API 4.12-era).
    /// Absent from an older API: the quota pause is then left as it is.
    #[serde(default)]
    telemetry_quota: Option<String>,
    /// When the quota resets (RFC 3339), with `telemetry_quota`.
    #[serde(default)]
    telemetry_quota_resets_at: Option<String>,
    /// The database's principals (business policy rules, contract M2 §2), sent
    /// only to a proxy that announces `cel/1`. Kept as raw JSON and read
    /// fail-safe by [`PrincipalMap::from_sync`](crate::tcp::policy_rules::PrincipalMap::from_sync):
    /// a malformed section is ignored, it never fails the response. Read only
    /// with `VERICTO_POLICY_RULES` on.
    #[serde(default)]
    principals: Option<serde_json::Value>,
    /// The active kill-switch blocks of this database (VERICTO-105, since
    /// 4.18.0), present only while one is active. Kept as raw JSON and read
    /// entry by entry by [`KillSwitch::from_sync`]: a malformed entry is skipped
    /// and logged, never the response refused, because the same bundle carries
    /// the deny-all allowlist (VERICTO-087) that blocks that user too.
    #[serde(default)]
    kill_switch: Option<serde_json::Value>,
}

/// What the rule sync does for business policy rules: with the mode on it
/// announces `cel/1` and compiles each synced ruleset into `bundle`; off, it
/// does neither (the request and its handling are those of 4.14.3).
#[derive(Clone, Default)]
pub struct PolicyRulesSync {
    pub mode: crate::tcp::policy_rules::PolicyRulesMode,
    pub bundle: crate::tcp::policy_rules::SharedPolicyRules,
    /// The bundle-signature check (4.16.0), used only with the mode on. `None`
    /// with the mode on trusts no key: every bundle is refused (fail safe).
    pub verifier: Option<Arc<BundleVerifier>>,
}

impl PolicyRulesSync {
    /// Whether a bundle may be applied: always with the mode off (nothing is read
    /// or hashed), only with a signature that verifies with the mode on.
    fn accepts(&self, body: &[u8], header: Option<&str>, source: BundleSource) -> bool {
        if !self.mode.is_on() {
            return true;
        }
        match &self.verifier {
            Some(v) => v.check(body, header, source),
            None => BundleVerifier::new(Keyring::new(
                Vec::new(),
                crate::tcp::bundle_signature::KeySource::None,
            ))
            .check(body, header, source),
        }
    }
}

/// What a sync says about the monthly quota (see `telemetry::quota`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaWord {
    Ok,
    Exceeded(chrono::DateTime<chrono::Utc>),
}

impl SyncResponse {
    fn quota_word(&self) -> Option<QuotaWord> {
        match self.telemetry_quota.as_deref() {
            Some("ok") => Some(QuotaWord::Ok),
            Some("exceeded") => self
                .telemetry_quota_resets_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| QuotaWord::Exceeded(t.with_timezone(&chrono::Utc))),
            _ => None,
        }
    }
}

/// Pauses or resumes telemetry on the API's word. A 304 means the API's state is
/// still the one of the last body, so the caller applies that one again: a pause
/// entered meanwhile by an ingest 429 ends if the API says the quota is fine.
fn apply_quota(word: Option<QuotaWord>, gate: Option<&crate::telemetry::quota::QuotaGate>) {
    let (Some(word), Some(gate)) = (word, gate) else {
        return;
    };
    match word {
        QuotaWord::Ok => {
            gate.resume("rules_sync");
        }
        QuotaWord::Exceeded(resets_at) => {
            gate.pause(resets_at, "rules_sync");
        }
    }
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

/// Builds an `EnforcementPolicy` from the API policy object and the database's
/// sensitive-column tags. When `api` is `None` (older API during the
/// compatibility window) the default policy is used. Present severity actions
/// override the corresponding default level. The tags are set either way: they
/// are per database, the policy object is per workspace.
fn build_policy(api: Option<ApiPolicy>, tags: Option<Vec<SensitiveColumn>>) -> EnforcementPolicy {
    let mut policy = EnforcementPolicy {
        sensitive_columns: tags.unwrap_or_default(),
        ..EnforcementPolicy::default()
    };
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
    /// Number of sensitive-column tags in force.
    sensitive_columns: usize,
    /// Number of database users (incl. `"*"`) with an agent-access policy.
    agent_access: usize,
    /// Number of kill-switch blocks in force (blocked users, plus the workspace switch).
    kill_switch: usize,
    mode: TelemetryQueryMode,
    proxy_config: Option<ProxyConfig>,
    quota: Option<QuotaWord>,
}

/// Swaps in the ruleset, policy and telemetry mode from one `/sync/rules` response.
/// Shared by the live sync and the rules cache, so both enforce a response the same way.
fn apply(
    body: SyncResponse,
    ruleset: &SharedRuleset,
    policy: &SharedPolicy,
    agent_access: &SharedAccessPolicies,
    kill_switch: &SharedKillSwitch,
    telemetry_mode: &SharedTelemetryMode,
    policy_rules: &PolicyRulesSync,
) -> Applied {
    let quota = body.quota_word();
    let mode = TelemetryQueryMode::from_api(
        body.policy
            .as_ref()
            .and_then(|p| p.telemetry_query_mode.as_deref()),
    );
    let new_policy = build_policy(body.policy, body.sensitive_columns);
    let monitor_mode = new_policy.monitor_mode;
    let sensitive_columns = new_policy.sensitive_columns.len();
    let access = body.agent_access.unwrap_or_default();
    let access_users = access.0.len();
    let blocks = KillSwitch::from_sync(body.kill_switch);
    let blocked = blocks.as_ref().map_or(0, KillSwitch::len);
    let rules: Vec<Rule> = body.rules.into_iter().map(ApiRule::into_rule).collect();
    let count = rules.len();
    let rules = Arc::new(rules);
    if policy_rules.mode.is_on() {
        // Compiled once here, never per statement; stored with the very rules it
        // was compiled from.
        policy_rules
            .bundle
            .store(Arc::new(crate::tcp::policy_rules::bundle_from_sync(
                policy_rules.mode,
                Arc::clone(&rules),
                body.principals,
                &body.version,
            )));
    }
    ruleset.store(rules);
    policy.store(Arc::new(new_policy));
    agent_access.store(Arc::new(access));
    kill_switch.store(blocks.map(Arc::new));
    telemetry_mode.store(Arc::new(mode));
    Applied {
        count,
        monitor_mode,
        sensitive_columns,
        agent_access: access_users,
        kill_switch: blocked,
        mode,
        proxy_config: body.proxy_config,
        quota,
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
        if dialect.eq_ignore_ascii_case("snowflake") {
            tracing::warn!(
                wire_protocol = %proto,
                dashboard_dialect = %dialect,
                "The dashboard registers this database as Snowflake, which has no TCP wire \
                 protocol: no proxy can front it. Check its SQL through the Vericto HTTP API, \
                 the CLI or MCP, and point this proxy at a Postgres or MySQL database."
            );
        } else if !expected {
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
///
/// With `stats`, every poll also carries the telemetry pipeline's counters in the
/// [`STATS_HEADER`](crate::telemetry::heartbeat::STATS_HEADER) header (since
/// 4.12.0), so the API sees what this proxy delivered and dropped.
#[cfg(test)]
async fn run(
    cfg: ControlPlaneConfig,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    agent_access: SharedAccessPolicies,
    telemetry_mode: SharedTelemetryMode,
    readiness: Arc<crate::tcp::healthz::Readiness>,
    stats: Option<crate::telemetry::heartbeat::StatsSource>,
) {
    run_with_policy_rules(
        cfg,
        ruleset,
        policy,
        agent_access,
        SharedKillSwitch::default(),
        telemetry_mode,
        PolicyRulesSync::default(),
        readiness,
        stats,
    )
    .await
}

/// [`run`] with business policy rules: `policy_rules.mode` on announces
/// `cel/1` on every request and compiles every applied response.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_policy_rules(
    cfg: ControlPlaneConfig,
    ruleset: SharedRuleset,
    policy: SharedPolicy,
    agent_access: SharedAccessPolicies,
    kill_switch: SharedKillSwitch,
    telemetry_mode: SharedTelemetryMode,
    policy_rules: PolicyRulesSync,
    readiness: Arc<crate::tcp::healthz::Readiness>,
    stats: Option<crate::telemetry::heartbeat::StatsSource>,
) {
    let mut url = format!("{}/api/v1/sync/rules", cfg.api_url);
    if let Some(ref db_id) = cfg.database_id {
        url = format!("{url}?database_id={db_id}");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(crate::config::same_origin_redirects())
        .build()
        .expect("failed to build rule-sync HTTP client");

    let mut etag: Option<String> = None;
    // The quota state of the last body applied (re-applied on a 304).
    let mut last_quota: Option<QuotaWord> = None;
    let quota_gate = stats.as_ref().map(|s| s.quota_gate());
    let mut sync_interval = cfg.rules_sync_interval;
    let mut ticker = tokio::time::interval(sync_interval);

    // Resume with the last-good response before the first request, so a restart while
    // the control plane is down keeps the workspace's rules and policy instead of
    // falling back to the built-in ruleset. Its ETag goes on the first request: if
    // nothing changed meanwhile the API answers 304 and the cached copy stays.
    //
    // With policy rules on, the cached body is verified like a live one (4.16.0):
    // a file anyone with write access to the volume could edit is not a trust
    // anchor. A cache that does not verify (a 4.15.x file has no signature) is
    // ignored, and so is its ETag, so the first request gets a full body.
    let cache = RulesCache::from_config(&cfg);
    // Whether a synced bundle (live or cached) is in effect, for the log of a
    // refused one: without it the built-in ruleset is what runs.
    let mut have_bundle = false;
    let cached = cache.as_ref().and_then(RulesCache::load).filter(|c| {
        policy_rules.accepts(
            c.body.as_bytes(),
            c.signature.as_deref(),
            BundleSource::Cache,
        )
    });
    if let Some(cached) = cached {
        match serde_json::from_str::<SyncResponse>(&cached.body) {
            Ok(body) => {
                let applied = apply(
                    body,
                    &ruleset,
                    &policy,
                    &agent_access,
                    &kill_switch,
                    &telemetry_mode,
                    &policy_rules,
                );
                if let Some(pc) = &applied.proxy_config {
                    apply_proxy_config(pc, &mut sync_interval, &mut ticker);
                }
                last_quota = applied.quota;
                apply_quota(last_quota, quota_gate.as_deref());
                etag = cached.etag;
                have_bundle = true;
                tracing::info!(
                    count = applied.count,
                    monitor_mode = applied.monitor_mode,
                    sensitive_columns = applied.sensitive_columns,
                    agent_access_users = applied.agent_access,
                    kill_switch_blocks = applied.kill_switch,
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
        if let Some(stats) = &stats {
            req = req.header(
                crate::telemetry::heartbeat::STATS_HEADER,
                stats.header_value(),
            );
        }
        if policy_rules.mode.is_on() {
            req = req.header(
                crate::tcp::policy_rules::POLICY_LANGUAGE_HEADER,
                crate::tcp::policy_rules::POLICY_LANGUAGE_ANNOUNCEMENT,
            );
        }
        if let Some(tag) = &etag {
            req = req.header("If-None-Match", tag.clone());
        }

        match req.send().await {
            Ok(res) if res.status().as_u16() == 304 => {
                tracing::debug!("Ruleset unchanged (304)");
                apply_quota(last_quota, quota_gate.as_deref());
            }
            Ok(res) if res.status().is_success() => {
                let new_etag = res
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                // The bundle signature (4.16.0), read only with policy rules on.
                let signature = policy_rules
                    .mode
                    .is_on()
                    .then(|| {
                        res.headers()
                            .get(SIGNATURE_HEADER)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                    })
                    .flatten();
                // Read the body as text so the exact bytes accepted can be cached.
                // With policy rules on, as raw bytes that must be UTF-8 (JSON is),
                // so the bytes verified are exactly the bytes received: `text()`
                // decodes by the declared charset, lossily.
                let received = if policy_rules.mode.is_on() {
                    res.bytes()
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|b| String::from_utf8(b.to_vec()).map_err(|e| e.to_string()))
                } else {
                    res.text().await.map_err(|e| e.to_string())
                };
                if let Ok(text) = &received
                    && !policy_rules.accepts(
                        text.as_bytes(),
                        signature.as_deref(),
                        BundleSource::Sync,
                    )
                {
                    // Not applied, not cached, and its ETag not adopted: the next
                    // poll asks again with the last good ETag and gets a full body.
                    if !have_bundle {
                        tracing::warn!(
                            "No verified sync bundle yet: the built-in ruleset stays in effect, \
                             without the workspace's rules or business policies"
                        );
                    }
                    readiness.mark_ready();
                    continue;
                }
                match received.and_then(|text| {
                    serde_json::from_str::<SyncResponse>(&text)
                        .map(|body| (text, body))
                        .map_err(|e| e.to_string())
                }) {
                    Ok((text, body)) => {
                        let applied = apply(
                            body,
                            &ruleset,
                            &policy,
                            &agent_access,
                            &kill_switch,
                            &telemetry_mode,
                            &policy_rules,
                        );
                        if let Some(pc) = &applied.proxy_config {
                            apply_proxy_config(pc, &mut sync_interval, &mut ticker);
                        }
                        last_quota = applied.quota;
                        apply_quota(last_quota, quota_gate.as_deref());
                        // Cached only after it parsed and was applied: the file always
                        // holds a response this proxy has enforced, never a bad one.
                        if let Some(cache) = &cache {
                            cache.store(new_etag.as_deref(), &text, signature.as_deref());
                        }
                        etag = new_etag;
                        have_bundle = true;
                        tracing::info!(
                            count = applied.count,
                            monitor_mode = applied.monitor_mode,
                            sensitive_columns = applied.sensitive_columns,
                            agent_access_users = applied.agent_access,
                            kill_switch_blocks = applied.kill_switch,
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
        let policy = build_policy(None, None);
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
        let policy = build_policy(Some(api), None);
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
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
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
        let no_access = || Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default()));

        // 1. Control plane up: the first sync writes the cache.
        let (rules, pol, mode, ready) = fresh();
        let first = tokio::spawn(run(
            cfg.clone(),
            rules,
            pol,
            no_access(),
            mode,
            ready.clone(),
            None,
        ));
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
            no_access(),
            mode.clone(),
            ready.clone(),
            None,
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

    /// A failed first sync (server error, auth failure, a body that does not
    /// parse, or no API at all) keeps the built-in ruleset and default policy,
    /// writes no cache, and still marks the proxy ready: a control-plane outage
    /// must not become a proxy outage.
    #[tokio::test]
    async fn a_failed_sync_keeps_the_built_in_ruleset_and_still_gets_ready() {
        use crate::config::BufferMode;
        use axum::{Router, http::StatusCode, routing::get};

        async fn first_sync_against(api_url: String) -> (usize, EnforcementPolicy, bool) {
            let dir = tempfile::tempdir().unwrap();
            let cache_path = dir.path().join("rules-cache.json");
            let cfg = ControlPlaneConfig {
                api_url,
                api_key: "vk_test".into(),
                database_id: None,
                rules_sync_interval: Duration::from_secs(3600),
                rules_cache_path: Some(cache_path.clone()),
                buffer_mode: BufferMode::Memory,
                disk_spool_path: String::new(),
                memory_capacity: 10,
                batch_size: 10,
                flush_interval: Duration::from_secs(5),
                spool: crate::config::SpoolTuning::default(),
                delivery: crate::config::DeliveryTuning::default(),
            };
            let rules = Arc::new(ArcSwap::from_pointee(
                crate::tcp::evaluator::default_ruleset(),
            ));
            let pol = Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default()));
            let ready = crate::tcp::healthz::Readiness::new();
            let task = tokio::spawn(run(
                cfg,
                rules.clone(),
                pol.clone(),
                Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
                Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                ready.clone(),
                None,
            ));
            tokio::time::timeout(Duration::from_secs(10), ready.wait_ready())
                .await
                .expect("ready after the first attempt, even a failed one");
            task.abort();
            let n = rules.load().len();
            let p = (**pol.load()).clone();
            (n, p, cache_path.exists())
        }

        let built_in = crate::tcp::evaluator::default_ruleset().len();
        let app = Router::new()
            .route(
                "/500/api/v1/sync/rules",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
            )
            .route(
                "/401/api/v1/sync/rules",
                get(|| async { (StatusCode::UNAUTHORIZED, "{\"error\":\"bad key\"}") }),
            )
            .route(
                "/garbage/api/v1/sync/rules",
                get(|| async { "{\"rules\": \"not a list\"" }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        for case in ["500", "401", "garbage"] {
            let (n, policy, cached) = first_sync_against(format!("http://{addr}/{case}")).await;
            assert_eq!(n, built_in, "{case}: the built-in ruleset stays");
            assert_eq!(policy, EnforcementPolicy::default(), "{case}");
            assert!(!cached, "{case}: a failed sync is never cached");
        }
        server.abort();

        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let (n, _, cached) = first_sync_against(format!("http://{dead}")).await;
        assert_eq!(n, built_in, "unreachable API: the built-in ruleset stays");
        assert!(!cached);
    }

    /// The dashboard can slow the sync down or speed it up, but never below the
    /// 30-second floor that protects the API.
    #[tokio::test]
    async fn the_dashboard_sync_interval_is_applied_with_a_floor() {
        let mut interval = Duration::from_secs(300);
        let mut ticker = tokio::time::interval(interval);
        let pc = |secs: Option<u64>, dialect: Option<&str>| ProxyConfig {
            rules_sync_interval_secs: secs,
            telemetry_batch_size: Some(10),
            dialect: dialect.map(str::to_string),
            ..ProxyConfig::default()
        };
        apply_proxy_config(&pc(Some(5), None), &mut interval, &mut ticker);
        assert_eq!(interval, Duration::from_secs(30));
        assert_eq!(ticker.period(), Duration::from_secs(30));
        apply_proxy_config(
            &pc(Some(600), Some("snowflake")),
            &mut interval,
            &mut ticker,
        );
        assert_eq!(interval, Duration::from_secs(600));
        // No interval in the config: unchanged (a dialect mismatch only warns).
        apply_proxy_config(&pc(None, Some("oracle")), &mut interval, &mut ticker);
        assert_eq!(ticker.period(), Duration::from_secs(600));
    }

    #[test]
    fn an_unknown_action_falls_back_to_flag() {
        assert_eq!(parse_action("BLOCK"), EnforcementAction::Block);
        assert_eq!(parse_action("Monitor"), EnforcementAction::Monitor);
        assert_eq!(parse_action("quarantine"), EnforcementAction::Flag);
        assert_eq!(parse_action(""), EnforcementAction::Flag);
    }

    /// Every poll carries the pipeline counters (4.12.0); an API that does not know
    /// the header answers exactly as before, which is what this stand-in does.
    #[tokio::test]
    async fn every_sync_carries_the_telemetry_counters() {
        use crate::config::BufferMode;
        use axum::{Router, http::HeaderMap, routing::get};
        use std::sync::Mutex;

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_by_api = Arc::clone(&seen);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/sync/rules",
            get(move |headers: HeaderMap| {
                let seen = Arc::clone(&seen_by_api);
                async move {
                    if let Some(v) = headers.get(crate::telemetry::heartbeat::STATS_HEADER) {
                        seen.lock().unwrap().push(v.to_str().unwrap().to_string());
                    }
                    r#"{"version": "v1", "rules": []}"#
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let cfg = ControlPlaneConfig {
            api_url: format!("http://{addr}"),
            api_key: "vk_test".into(),
            database_id: None,
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: None,
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        };
        let queue: Arc<dyn crate::telemetry::EventQueue> =
            Arc::new(crate::telemetry::queue::MemoryQueue::new(10));
        let reporter = crate::telemetry::Reporter::new(cfg.clone(), Arc::clone(&queue));
        let stats =
            crate::telemetry::heartbeat::StatsSource::new(BufferMode::Memory, queue, reporter);
        let ready = crate::tcp::healthz::Readiness::new();
        let sync = tokio::spawn(run(
            cfg,
            Arc::new(ArcSwap::from_pointee(Vec::new())),
            Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
            Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
            ready.clone(),
            Some(stats),
        ));
        ready.wait_ready().await;
        sync.abort();
        server.abort();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the first sync sends the header");
        let json: serde_json::Value = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["buffer"], "memory");
        assert_eq!(json["enqueued"], 0);
    }

    #[test]
    fn the_quota_word_is_read_from_the_body() {
        let parse = |extra: &str| -> Option<QuotaWord> {
            serde_json::from_str::<SyncResponse>(&format!(
                r#"{{"version": "v1", "rules": []{extra}}}"#
            ))
            .unwrap()
            .quota_word()
        };
        assert_eq!(parse(""), None, "an older API says nothing");
        assert_eq!(parse(r#", "telemetry_quota": "ok""#), Some(QuotaWord::Ok));
        assert_eq!(
            parse(
                r#", "telemetry_quota": "exceeded", "telemetry_quota_resets_at": "2026-11-01T00:00:00.000Z""#
            ),
            Some(QuotaWord::Exceeded(
                chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            ))
        );
        assert_eq!(
            parse(r#", "telemetry_quota": "exceeded""#),
            None,
            "exceeded without a reset time is not acted on"
        );
        assert_eq!(parse(r#", "telemetry_quota": "something-new""#), None);
    }

    /// The rule sync pauses telemetry when the API says the quota is exceeded,
    /// keeps that state across 304s (re-applying the last body: a pause ended by
    /// hand comes back while the API still says exceeded), and resumes when the
    /// API says "ok" again (an upgrade, or the new month).
    #[tokio::test]
    async fn the_rule_sync_pauses_and_resumes_telemetry_on_the_apis_word() {
        use crate::config::BufferMode;
        use axum::{
            Router,
            http::{HeaderMap, StatusCode, header},
            response::IntoResponse,
            routing::get,
        };
        use std::sync::atomic::{AtomicBool, Ordering};

        let exceeded = Arc::new(AtomicBool::new(true));
        let api_state = Arc::clone(&exceeded);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/sync/rules",
            get(move |headers: HeaderMap| {
                let exceeded = api_state.load(Ordering::SeqCst);
                async move {
                    let tag = if exceeded { "\"q-exceeded\"" } else { "\"q-ok\"" };
                    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(tag) {
                        return StatusCode::NOT_MODIFIED.into_response();
                    }
                    let body = if exceeded {
                        r#"{"version": "v1", "rules": [], "telemetry_quota": "exceeded", "telemetry_quota_resets_at": "2099-01-01T00:00:00.000Z"}"#
                    } else {
                        r#"{"version": "v1", "rules": [], "telemetry_quota": "ok", "telemetry_quota_resets_at": "2099-01-01T00:00:00.000Z"}"#
                    };
                    ([(header::ETAG, tag)], body).into_response()
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let cfg = ControlPlaneConfig {
            api_url: format!("http://{addr}"),
            api_key: "vk_test".into(),
            database_id: None,
            rules_sync_interval: Duration::from_millis(100),
            rules_cache_path: None,
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        };
        let queue: Arc<dyn crate::telemetry::EventQueue> =
            Arc::new(crate::telemetry::queue::MemoryQueue::new(10));
        let reporter = crate::telemetry::Reporter::new(cfg.clone(), Arc::clone(&queue));
        let stats =
            crate::telemetry::heartbeat::StatsSource::new(BufferMode::Memory, queue, reporter);
        let gate = stats.quota_gate();
        let sync = tokio::spawn(run(
            cfg,
            Arc::new(ArcSwap::from_pointee(Vec::new())),
            Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
            Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
            crate::tcp::healthz::Readiness::new(),
            Some(stats),
        ));
        let until = |cond: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !cond() {
                assert!(std::time::Instant::now() < deadline, "timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let g = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || until(&|| g.is_paused()))
            .await
            .unwrap();

        // Resumed by hand; the next 304 re-applies "exceeded".
        assert!(gate.resume("test"));
        let g = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || until(&|| g.is_paused()))
            .await
            .unwrap();

        // The API lifts it (new ETag, body "ok"): resumed.
        exceeded.store(false, Ordering::SeqCst);
        let g = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || until(&|| !g.is_paused()))
            .await
            .unwrap();
        sync.abort();
        server.abort();
    }

    fn applied_policy(body: &str) -> EnforcementPolicy {
        applied(body).0
    }

    /// The policy and the agent-access map one `/sync/rules` body puts in effect.
    fn applied(body: &str) -> (EnforcementPolicy, AccessPolicyMap) {
        let body: SyncResponse = serde_json::from_str(body).expect("sync body parses");
        let ruleset: SharedRuleset = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let policy: SharedPolicy = Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default()));
        let access: SharedAccessPolicies =
            Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default()));
        let mode: SharedTelemetryMode = Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::Raw));
        apply(
            body,
            &ruleset,
            &policy,
            &access,
            &SharedKillSwitch::default(),
            &mode,
            &PolicyRulesSync::default(),
        );
        ((**policy.load()).clone(), (**access.load()).clone())
    }

    /// The database's tags travel in `/sync/rules` (engine contract §2) and end
    /// up in the policy every query is evaluated with.
    #[test]
    fn sync_payload_with_sensitive_columns_carries_them_into_the_policy() {
        use vericto_engine::{MaskStyle, SensitivePolicy};
        let policy = applied_policy(
            r#"{
                "version": "v8", "rules": [],
                "policy": {"severity_actions": {}, "parse_error_action": "allow_report"},
                "sensitive_columns": [
                    {"schema": "public", "table": "customers", "column": "email", "policy": "mask", "mask_style": "email"},
                    {"schema": null, "table": "customers", "column": "ssn", "policy": "block"},
                    {"schema_name": "billing", "table_name": "cards", "column_name": "pan", "policy": "FLAG"},
                    {"table": "customers", "column": "dob", "policy": "something-newer"}
                ]
            }"#,
        );
        let tags = &policy.sensitive_columns;
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[0].schema.as_deref(), Some("public"));
        assert_eq!(tags[0].policy, SensitivePolicy::Mask);
        assert_eq!(tags[0].mask_style, MaskStyle::Email);
        assert_eq!(tags[1].schema, None);
        assert_eq!(tags[1].policy, SensitivePolicy::Block);
        // The DB column names are accepted as aliases; the policy is case-insensitive.
        assert_eq!(
            (tags[2].table.as_str(), tags[2].column.as_str()),
            ("cards", "pan")
        );
        assert_eq!(tags[2].policy, SensitivePolicy::Flag);
        // An unknown policy is a block: a newer dashboard never disables protection.
        assert_eq!(tags[3].policy, SensitivePolicy::Block);
        // The rest of the policy is built as before.
        assert_eq!(policy.parse_error, ParseErrorAction::AllowReport);
        // ... and a block or mask tag makes a parse error block.
        assert_eq!(policy.effective_parse_error(), ParseErrorAction::Block);
    }

    /// An API that does not send the field (or sends null / []) gives exactly
    /// the policy the proxy built before the field existed.
    #[test]
    fn sync_payload_without_sensitive_columns_is_unchanged() {
        let policy_json = r#""policy": {"severity_actions": {"medium": "monitor"}, "parse_error_action": "allow_report"}"#;
        let expected = EnforcementPolicy {
            medium: EnforcementAction::Monitor,
            ..EnforcementPolicy::default()
        };
        for extra in [
            "",
            r#", "sensitive_columns": null"#,
            r#", "sensitive_columns": []"#,
        ] {
            let policy = applied_policy(&format!(
                r#"{{"version": "v1", "rules": [], {policy_json}{extra}}}"#
            ));
            assert_eq!(policy, expected, "with {extra:?}");
            assert_eq!(
                policy.effective_parse_error(),
                ParseErrorAction::AllowReport
            );
        }
        // Tags without a policy object: default policy plus the tags.
        let policy = applied_policy(
            r#"{"version": "v1", "rules": [],
                "sensitive_columns": [{"table": "t", "column": "c", "policy": "flag"}]}"#,
        );
        assert_eq!(policy.sensitive_columns.len(), 1);
        assert_eq!(
            EnforcementPolicy {
                sensitive_columns: Vec::new(),
                ..policy
            },
            EnforcementPolicy::default()
        );
    }

    /// The last-good cache holds the tags too: a restart during an outage keeps
    /// enforcing them instead of reading the tagged columns in clear.
    #[tokio::test]
    async fn restart_during_an_outage_keeps_the_sensitive_columns() {
        use crate::config::BufferMode;
        use axum::{Router, http::header, routing::get};
        use vericto_engine::{MaskStyle, SensitivePolicy};

        const BODY: &str = r#"{
            "version": "v9", "rules": [],
            "policy": {"severity_actions": {}},
            "sensitive_columns": [
                {"schema": "public", "table": "customers", "column": "email", "policy": "mask", "mask_style": "last4"}
            ]
        }"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/sync/rules",
            get(|| async { ([(header::ETAG, "\"v9\"")], BODY) }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let dir = tempfile::tempdir().unwrap();
        let cfg = ControlPlaneConfig {
            api_url: format!("http://{addr}"),
            api_key: "vk_test".into(),
            database_id: Some("db-1".into()),
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: Some(dir.path().join("rules-cache.json")),
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        };
        let start = |cfg: ControlPlaneConfig| {
            let pol: SharedPolicy = Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default()));
            let ready = crate::tcp::healthz::Readiness::new();
            let task = tokio::spawn(run(
                cfg,
                Arc::new(ArcSwap::from_pointee(Vec::new())),
                pol.clone(),
                Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
                Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                ready.clone(),
                None,
            ));
            (pol, ready, task)
        };

        // Live sync: the tags are in effect and the cache is written.
        let (pol, ready, task) = start(cfg.clone());
        ready.wait_ready().await;
        task.abort();
        assert_eq!(pol.load().sensitive_columns.len(), 1);

        // Control plane down, proxy restarted: the cache restores them.
        server.abort();
        let _ = server.await;
        let (pol, ready, task) = start(cfg);
        ready.wait_ready().await;
        task.abort();
        let pol = pol.load();
        assert_eq!(pol.sensitive_columns.len(), 1);
        let tag = &pol.sensitive_columns[0];
        assert_eq!(tag.schema.as_deref(), Some("public"));
        assert_eq!(
            (tag.table.as_str(), tag.column.as_str()),
            ("customers", "email")
        );
        assert_eq!(tag.policy, SensitivePolicy::Mask);
        assert_eq!(tag.mask_style, MaskStyle::Last4);
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
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        };
        let builtin = crate::tcp::evaluator::default_ruleset();
        let rules: SharedRuleset = Arc::new(ArcSwap::from_pointee(builtin.clone()));
        let ready = crate::tcp::healthz::Readiness::new();
        let task = tokio::spawn(run(
            cfg,
            rules.clone(),
            Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
            Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
            ready.clone(),
            None,
        ));
        ready.wait_ready().await;
        task.abort();
        assert_eq!(rules.load().len(), builtin.len());
    }

    const AGENT_ACCESS_BODY: &str = r#"{
        "version": "v10", "rules": [],
        "policy": {"severity_actions": {}, "parse_error_action": "allow_report"},
        "agent_access": {
            "support_agent": {"mode": "enforce", "ddl": "deny", "entries": [
                {"schema": "public", "table": "orders", "columns": "*", "access": "read"},
                {"schema": null, "table": "customers", "columns": ["id", "name"], "access": "read"},
                {"table": "tickets", "columns": ["id", "status"], "access": "read_write"}
            ]},
            "reporting_bot": {"mode": "OBSERVE", "entries": []},
            "*": {"entries": [{"table": "status", "columns": "*"}]}
        }
    }"#;

    /// `agent_access` (engine contract §2) parses into the map every session
    /// selects its user's policy from; the workspace policy is untouched by it.
    #[test]
    fn sync_payload_with_agent_access_carries_the_map() {
        use vericto_engine::{AccessColumns, AccessLevel, AccessMode};
        let (policy, access) = applied(AGENT_ACCESS_BODY);
        assert_eq!(access.0.len(), 3);
        let agent = access.for_user("support_agent").expect("exact key");
        assert_eq!(agent.mode, AccessMode::Enforce);
        assert_eq!(agent.entries.len(), 3);
        assert_eq!(agent.entries[0].schema.as_deref(), Some("public"));
        assert_eq!(agent.entries[0].columns, AccessColumns::AllColumns);
        assert_eq!(
            agent.entries[1].columns,
            AccessColumns::List(vec!["id".into(), "name".into()])
        );
        assert_eq!(agent.entries[2].access, AccessLevel::ReadWrite);
        // Case-insensitive mode; absent mode and access are the fail-safe ones.
        assert_eq!(
            access.for_user("reporting_bot").unwrap().mode,
            AccessMode::Observe
        );
        let default = access.for_user("anyone_else").expect("the \"*\" default");
        assert_eq!(default.mode, AccessMode::Enforce);
        assert_eq!(default.entries[0].access, AccessLevel::Read);
        // User names match exactly (Postgres and MySQL user names are case-sensitive).
        assert!(std::ptr::eq(
            access.for_user("Support_Agent").unwrap(),
            default
        ));
        // The policy the proxy builds is exactly what it was without the field:
        // the allowlist is selected per session, never stored in the shared policy.
        assert_eq!(policy.access_policy, None);
        assert_eq!(
            policy,
            applied_policy(
                r#"{"version": "v10", "rules": [],
            "policy": {"severity_actions": {}, "parse_error_action": "allow_report"}}"#
            )
        );
    }

    /// fmw's `/sync/rules` since engine 3.8.1 (`toEnginePolicy`): Postgres names
    /// that are not plain lower case arrive double-quoted (embedded `"` doubled),
    /// and the database's `default_schema` rides on each policy, absent when the
    /// database has none. Both reach the engine as sent.
    #[test]
    fn sync_payload_carries_default_schema_and_quoted_names() {
        let (_, access) = applied(
            r#"{"version": "v11", "rules": [],
            "policy": {"severity_actions": {}},
            "agent_access": {
                "support_agent": {"mode": "enforce", "ddl": "deny", "entries": [
                    {"schema": "\"Sales\"", "table": "\"Customers\"", "columns": ["id", "\"Email\""], "access": "read"},
                    {"schema": null, "table": "orders", "columns": "*", "access": "read_write"}
                ], "default_schema": "app"},
                "reporting_bot": {"mode": "observe", "ddl": "deny", "entries": []}
            }}"#,
        );
        let agent = access.for_user("support_agent").unwrap();
        assert_eq!(agent.default_schema.as_deref(), Some("app"));
        assert_eq!(agent.entries[0].schema.as_deref(), Some("\"Sales\""));
        assert_eq!(agent.entries[0].table, "\"Customers\"");
        assert_eq!(agent.entries[1].schema, None);
        assert_eq!(
            access.for_user("reporting_bot").unwrap().default_schema,
            None
        );
    }

    /// Absent, `null` or `{}`: no user has a policy, as before the field existed.
    #[test]
    fn sync_payload_without_agent_access_is_unchanged() {
        for extra in ["", r#", "agent_access": null"#, r#", "agent_access": {}"#] {
            let (policy, access) = applied(&format!(
                r#"{{"version": "v1", "rules": [], "policy": {{"severity_actions": {{}}}}{extra}}}"#
            ));
            assert!(access.0.is_empty(), "with {extra:?}");
            assert_eq!(access.for_user("postgres"), None);
            assert_eq!(policy, EnforcementPolicy::default());
        }
    }

    /// A malformed policy fails the whole response: the last-good one stays.
    /// The kill switch (4.18.0) one `/sync/rules` body puts in effect, with its
    /// agent-access map.
    fn applied_kill_switch(body: &str) -> (Option<Arc<KillSwitch>>, AccessPolicyMap) {
        let body: SyncResponse = serde_json::from_str(body).expect("sync body parses");
        let access: SharedAccessPolicies =
            Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default()));
        // A block from an earlier sync: every body replaces it.
        let kill = SharedKillSwitch::default();
        kill.store(
            KillSwitch::from_sync(Some(serde_json::json!({
                "workspace": {"block_id": "old", "message": "m"}
            })))
            .map(Arc::new),
        );
        apply(
            body,
            &Arc::new(ArcSwap::from_pointee(Vec::new())),
            &Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            &access,
            &kill,
            &Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::Raw)),
            &PolicyRulesSync::default(),
        );
        (kill.load_full(), (**access.load()).clone())
    }

    /// `kill_switch` is applied with the rest of the body, and a body without it
    /// (the block lifted, or a control plane that predates it) clears it. The
    /// deny-all allowlist of the same body applies either way.
    #[test]
    fn sync_payload_with_kill_switch_applies_and_without_it_clears() {
        let (ks, access) = applied_kill_switch(
            r#"{"version": "v1", "rules": [],
                "agent_access": {"agent": {"mode": "enforce", "ddl": "deny", "entries": []}},
                "kill_switch": {"db_users": {"agent": {"block_id": "b-1", "target_type": "db_user",
                    "message": "Vericto blocked this query [VERICTO-105]: stop"}}}}"#,
        );
        let ks = ks.expect("a block is in force");
        let b = ks.for_user(Some("agent")).unwrap();
        assert_eq!(b.block_id, "b-1");
        assert_eq!(b.message, "Vericto blocked this query [VERICTO-105]: stop");
        assert!(ks.for_user(Some("app")).is_none());
        assert!(access.for_user("agent").is_some());

        for extra in ["", r#", "kill_switch": null"#, r#", "kill_switch": {}"#] {
            let (ks, _) =
                applied_kill_switch(&format!(r#"{{"version": "v1", "rules": []{extra}}}"#));
            assert!(ks.is_none(), "{extra:?} must clear the block");
        }
    }

    /// A malformed `kill_switch` never refuses the bundle: its allowlists (the
    /// deny-all of the blocked users among them) still apply, so the agents stay
    /// blocked as VERICTO-087, as on a 4.17.x proxy.
    #[test]
    fn a_malformed_kill_switch_keeps_the_rest_of_the_bundle() {
        let (ks, access) = applied_kill_switch(
            r#"{"version": "v1", "rules": [],
                "agent_access": {"agent": {"mode": "enforce", "ddl": "deny", "entries": []}},
                "kill_switch": {"db_users": {"agent": {"block_id": 7}}}}"#,
        );
        assert!(ks.is_none());
        assert!(access.for_user("agent").is_some());
    }

    #[test]
    fn a_malformed_agent_access_policy_rejects_the_response() {
        let bad = r#"{"version": "v1", "rules": [], "agent_access": {"u": {"entries": [{"columns": "*"}]}}}"#;
        assert!(serde_json::from_str::<SyncResponse>(bad).is_err());
    }

    /// The last-good cache holds the allowlists too: a restart during an outage
    /// keeps restricting the agent users instead of letting them in unrestricted.
    #[tokio::test]
    async fn restart_during_an_outage_keeps_the_agent_access_policies() {
        use crate::config::BufferMode;
        use axum::{Router, http::header, routing::get};
        use vericto_engine::AccessMode;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/sync/rules",
            get(|| async { ([(header::ETAG, "\"v10\"")], AGENT_ACCESS_BODY) }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let dir = tempfile::tempdir().unwrap();
        let cfg = ControlPlaneConfig {
            api_url: format!("http://{addr}"),
            api_key: "vk_test".into(),
            database_id: Some("db-1".into()),
            rules_sync_interval: Duration::from_secs(3600),
            rules_cache_path: Some(dir.path().join("rules-cache.json")),
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
            spool: crate::config::SpoolTuning::default(),
            delivery: crate::config::DeliveryTuning::default(),
        };
        let start = |cfg: ControlPlaneConfig| {
            let access: SharedAccessPolicies =
                Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default()));
            let ready = crate::tcp::healthz::Readiness::new();
            let task = tokio::spawn(run(
                cfg,
                Arc::new(ArcSwap::from_pointee(Vec::new())),
                Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
                access.clone(),
                Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                ready.clone(),
                None,
            ));
            (access, ready, task)
        };

        // Live sync: the map is in effect and the cache is written.
        let (access, ready, task) = start(cfg.clone());
        ready.wait_ready().await;
        task.abort();
        let live = (**access.load()).clone();
        assert_eq!(live.0.len(), 3);

        // Control plane down, proxy restarted: the cache restores the same map.
        server.abort();
        let _ = server.await;
        let (access, ready, task) = start(cfg);
        ready.wait_ready().await;
        task.abort();
        let restored = (**access.load()).clone();
        assert_eq!(restored, live);
        assert_eq!(
            restored.for_user("reporting_bot").unwrap().mode,
            AccessMode::Observe
        );
        assert_eq!(restored.for_user("support_agent").unwrap().entries.len(), 3);
    }

    /// The `policy_language: cel/1` announcement (with `rewrite_limit` since
    /// 4.17.0) and the principals section (4.15.0). Off: no header, nothing
    /// compiled, the principals ignored, so
    /// the request and what it puts in effect are those of 4.14.3. On: the
    /// header on every request, and the response compiled into the bundle with
    /// its version. A malformed principals section never fails the sync.
    #[tokio::test]
    async fn policy_rules_announce_cel_and_compile_the_bundle_only_when_on() {
        use crate::config::BufferMode;
        use crate::tcp::policy_rules::{POLICY_LANGUAGE_HEADER, PolicyRules, PolicyRulesMode};
        use axum::{Router, http::HeaderMap, routing::get};
        use std::sync::Mutex;

        const BODY: &str = r#"{"version": "v-cel", "rules": [
            {"rule_id": "r-refunds", "code": "POL-014", "severity": "high", "rule_type": "custom",
             "default_action": "block",
             "ast_condition_yaml": "rule: refund-cap\napplies_to: { ops: [insert], tables: [\"public.refunds\"] }\ndeny_if: stmt.values(\"public.refunds.amount\").exists(v, double(v) > 200.0)\naction: block\n"}
        ], "principals": {"version": "p1", "entries": [
            {"id": "bot", "type": "agent", "identify": {"db_user": "support_bot"}}
        ]}}"#;
        const MALFORMED: &str =
            r#"{"version": "v-bad", "rules": [], "principals": {"entries": 7}}"#;

        async fn sync_once(
            mode: PolicyRulesMode,
            body: &'static str,
        ) -> (Vec<Option<String>>, Arc<PolicyRules>, usize) {
            // The bodies are signed (4.16.0): with the mode on, an unsigned one is
            // never applied (see the bundle-signature tests below).
            let signer = crate::tcp::bundle_signature::test_support::TestSigner::new("k");
            let signature = signer.header(body.as_bytes());
            let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_by_api = Arc::clone(&seen);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = Router::new().route(
                "/api/v1/sync/rules",
                get(move |headers: HeaderMap| {
                    let seen = Arc::clone(&seen_by_api);
                    let signature = signature.clone();
                    async move {
                        seen.lock().unwrap().push(
                            headers
                                .get(POLICY_LANGUAGE_HEADER)
                                .map(|v| v.to_str().unwrap().to_string()),
                        );
                        ([(SIGNATURE_HEADER, signature)], body)
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, app).await });
            let cfg = ControlPlaneConfig {
                api_url: format!("http://{addr}"),
                api_key: "vk_test".into(),
                database_id: None,
                rules_sync_interval: Duration::from_secs(3600),
                rules_cache_path: None,
                buffer_mode: BufferMode::Memory,
                disk_spool_path: String::new(),
                memory_capacity: 10,
                batch_size: 10,
                flush_interval: Duration::from_secs(5),
                spool: crate::config::SpoolTuning::default(),
                delivery: crate::config::DeliveryTuning::default(),
            };
            let ruleset: SharedRuleset = Arc::new(ArcSwap::from_pointee(Vec::new()));
            let policy_rules = PolicyRulesSync {
                mode,
                bundle: Default::default(),
                verifier: Some(Arc::new(BundleVerifier::new(
                    crate::tcp::bundle_signature::test_support::ring_of(&[&signer]),
                ))),
            };
            let ready = crate::tcp::healthz::Readiness::new();
            let sync = tokio::spawn(run_with_policy_rules(
                cfg,
                ruleset.clone(),
                Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
                Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
                SharedKillSwitch::default(),
                Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                policy_rules.clone(),
                ready.clone(),
                None,
            ));
            ready.wait_ready().await;
            sync.abort();
            server.abort();
            let seen = seen.lock().unwrap().clone();
            (seen, policy_rules.bundle.load_full(), ruleset.load().len())
        }

        let (headers, bundle, rules) = sync_once(PolicyRulesMode::Off, BODY).await;
        assert_eq!(headers, vec![None], "off: no announcement");
        assert_eq!(rules, 1, "the ruleset is applied as always");
        assert!(bundle.policies.is_empty() && bundle.version.is_none());
        assert!(bundle.principals.entries.is_empty() && bundle.rules.is_none());

        for mode in [PolicyRulesMode::Observe, PolicyRulesMode::Enforce] {
            let (headers, bundle, _) = sync_once(mode, BODY).await;
            assert_eq!(
                headers,
                vec![Some("cel/1, rewrite_limit".to_string())],
                "{mode:?}"
            );
            assert_eq!(bundle.policies.len(), 1, "{mode:?}");
            assert!(
                bundle.policies.errors().is_empty(),
                "{:?}",
                bundle.policies.errors()
            );
            assert_eq!(bundle.version.as_deref(), Some("v-cel"));
            assert_eq!(bundle.principals.entries.len(), 1);
            assert_eq!(bundle.principals.version.as_deref(), Some("p1"));
            assert_eq!(bundle.rules.as_ref().map(|r| r.len()), Some(1));
        }

        let (_, bundle, _) = sync_once(PolicyRulesMode::Enforce, MALFORMED).await;
        assert_eq!(
            bundle.version.as_deref(),
            Some("v-bad"),
            "the sync was applied"
        );
        assert!(bundle.principals.entries.is_empty());
    }

    // ── Bundle signatures (4.16.0) ───────────────────────────────────────────

    mod bundle_signatures {
        use super::*;
        use crate::config::BufferMode;
        use crate::tcp::bundle_signature::test_support::{TestSigner, ring_of};
        use crate::tcp::policy_rules::{PolicyRules, PolicyRulesMode};
        use axum::{
            Router,
            http::{HeaderMap, StatusCode, header},
            response::IntoResponse,
            routing::get,
        };
        use std::sync::Mutex;

        /// A policy bundle: one custom rule `code`, one business policy.
        fn body(version: &str, code: &str) -> String {
            serde_json::json!({
                "version": version,
                "rules": [
                    {"rule_id": "c-1", "code": code, "severity": "high", "rule_type": "custom",
                     "default_action": "block", "ast_condition_yaml": "node_type: DropStmt"},
                    {"rule_id": "r-refunds", "code": "POL-014", "severity": "high", "rule_type": "custom",
                     "default_action": "block",
                     "ast_condition_yaml": "rule: refund-cap\napplies_to: { ops: [insert], tables: [\"public.refunds\"] }\ndeny_if: stmt.values(\"public.refunds.amount\").exists(v, double(v) > 200.0)\naction: block\n"}
                ],
                "policy": {"severity_actions": {"high": "block"}}
            })
            .to_string()
        }

        /// What the fake API answers: a body, its signature header, and its ETag.
        #[derive(Clone, Default)]
        struct Served {
            body: String,
            signature: Option<String>,
            etag: String,
        }

        struct Api {
            served: Arc<Mutex<Served>>,
            /// The If-None-Match of every request, in order.
            seen: Arc<Mutex<Vec<Option<String>>>>,
            url: String,
            server: tokio::task::JoinHandle<()>,
        }

        impl Api {
            async fn start(first: Served) -> Self {
                let served = Arc::new(Mutex::new(first));
                let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
                let (s2, seen2) = (Arc::clone(&served), Arc::clone(&seen));
                let app = Router::new().route(
                    "/api/v1/sync/rules",
                    get(move |headers: HeaderMap| {
                        let (served, seen) = (Arc::clone(&s2), Arc::clone(&seen2));
                        async move {
                            let inm = headers
                                .get(header::IF_NONE_MATCH)
                                .map(|v| v.to_str().unwrap().to_string());
                            seen.lock().unwrap().push(inm.clone());
                            let now = served.lock().unwrap().clone();
                            let etag = format!("\"{}\"", now.etag);
                            if inm.as_deref() == Some(etag.as_str()) {
                                return StatusCode::NOT_MODIFIED.into_response();
                            }
                            let mut h = HeaderMap::new();
                            h.insert(header::ETAG, etag.parse().unwrap());
                            if let Some(sig) = now.signature {
                                h.insert(SIGNATURE_HEADER, sig.parse().unwrap());
                            }
                            (h, now.body).into_response()
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let _ = axum::serve(listener, app).await;
                });
                Self {
                    served,
                    seen,
                    url,
                    server,
                }
            }

            fn serve(&self, next: Served) {
                *self.served.lock().unwrap() = next;
            }

            fn requests(&self) -> usize {
                self.seen.lock().unwrap().len()
            }

            fn last_if_none_match(&self) -> Option<String> {
                self.seen.lock().unwrap().last().cloned().flatten()
            }

            /// Waits until `n` more requests than now have been answered, plus a beat
            /// for the syncer to handle the last one.
            async fn polls(&self, n: usize) {
                let target = self.requests() + n;
                tokio::time::timeout(Duration::from_secs(10), async {
                    while self.requests() < target {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("the syncer kept polling");
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }

        fn signed(signer: &TestSigner, version: &str, code: &str) -> Served {
            let b = body(version, code);
            Served {
                signature: Some(signer.header(b.as_bytes())),
                body: b,
                etag: version.into(),
            }
        }

        fn cfg(
            api_url: &str,
            cache: Option<std::path::PathBuf>,
            every: Duration,
        ) -> ControlPlaneConfig {
            ControlPlaneConfig {
                api_url: api_url.into(),
                api_key: "vk_test".into(),
                database_id: Some("db-1".into()),
                rules_sync_interval: every,
                rules_cache_path: cache,
                buffer_mode: BufferMode::Memory,
                disk_spool_path: String::new(),
                memory_capacity: 10,
                batch_size: 10,
                flush_interval: Duration::from_secs(5),
                spool: crate::config::SpoolTuning::default(),
                delivery: crate::config::DeliveryTuning::default(),
            }
        }

        struct Proxy {
            ruleset: SharedRuleset,
            bundle: crate::tcp::policy_rules::SharedPolicyRules,
            verifier: Arc<BundleVerifier>,
            ready: Arc<crate::tcp::healthz::Readiness>,
            task: tokio::task::JoinHandle<()>,
        }

        impl Proxy {
            fn start(cfg: ControlPlaneConfig, mode: PolicyRulesMode, keyring: Keyring) -> Self {
                let ruleset: SharedRuleset = Arc::new(ArcSwap::from_pointee(
                    crate::tcp::evaluator::default_ruleset(),
                ));
                let verifier = Arc::new(BundleVerifier::new(keyring));
                let sync = PolicyRulesSync {
                    mode,
                    bundle: Default::default(),
                    verifier: Some(Arc::clone(&verifier)),
                };
                let ready = crate::tcp::healthz::Readiness::new();
                let task = tokio::spawn(run_with_policy_rules(
                    cfg,
                    ruleset.clone(),
                    Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
                    Arc::new(ArcSwap::from_pointee(AccessPolicyMap::default())),
                    SharedKillSwitch::default(),
                    Arc::new(ArcSwap::from_pointee(TelemetryQueryMode::default())),
                    sync.clone(),
                    ready.clone(),
                    None,
                ));
                Self {
                    ruleset,
                    bundle: sync.bundle,
                    verifier,
                    ready,
                    task,
                }
            }

            fn codes(&self) -> Vec<String> {
                self.ruleset.load().iter().map(|r| r.code.clone()).collect()
            }

            fn bundle(&self) -> Arc<PolicyRules> {
                self.bundle.load_full()
            }

            fn rejected(&self, reason: &str) -> u64 {
                self.verifier.stats.rejected(reason)
            }
        }

        fn built_in_codes() -> Vec<String> {
            crate::tcp::evaluator::default_ruleset()
                .into_iter()
                .map(|r| r.code)
                .collect()
        }

        fn cached_body(path: &std::path::Path) -> String {
            let file: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            file["body"].as_str().unwrap().to_string()
        }

        /// A valid bundle is applied and cached with its signature. A tampered one,
        /// one signed by an untrusted key id and one signed by another key under the
        /// trusted id are refused: the last good bundle stays in memory and on disk,
        /// and the refused ETag is never adopted, so every poll asks again.
        #[tokio::test]
        async fn only_verified_bundles_are_applied_and_the_last_good_one_is_kept() {
            let signer = TestSigner::new("k-2026");
            let api = Api::start(signed(&signer, "v1", "ACME-001")).await;
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("rules-cache.json");
            let proxy = Proxy::start(
                cfg(&api.url, Some(cache.clone()), Duration::from_millis(40)),
                PolicyRulesMode::Enforce,
                ring_of(&[&signer]),
            );
            proxy.ready.wait_ready().await;
            api.polls(1).await;

            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);
            assert_eq!(proxy.bundle().policies.len(), 1);
            assert_eq!(proxy.bundle().version.as_deref(), Some("v1"));
            assert_eq!(proxy.verifier.stats.accepted(), 1);
            assert!(proxy.verifier.stats.verified_in_effect());
            let good = cached_body(&cache);
            let file: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&cache).unwrap()).unwrap();
            assert!(
                file["signature"]
                    .as_str()
                    .unwrap()
                    .contains("key-id=k-2026")
            );

            // 1. Tampered: v2's body under v1's signature.
            let tampered = Served {
                signature: Some(signer.header(body("v1", "ACME-001").as_bytes())),
                body: body("v2", "EVIL-001"),
                etag: "v2".into(),
            };
            api.serve(tampered);
            api.polls(3).await;
            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"], "last good kept");
            assert_eq!(proxy.bundle().version.as_deref(), Some("v1"));
            assert!(proxy.rejected("digest_mismatch") >= 2);
            assert_eq!(cached_body(&cache), good, "the cache is untouched");
            assert_eq!(
                api.last_if_none_match().as_deref(),
                Some("\"v1\""),
                "the refused ETag is not adopted"
            );

            // 2. Signed with a key id this proxy does not trust.
            let stranger = TestSigner::new("k-stranger");
            api.serve(signed(&stranger, "v3", "EVIL-003"));
            api.polls(2).await;
            assert!(proxy.rejected("unknown_key_id") >= 1);
            // 3. Another key under the trusted id.
            let impostor = TestSigner::new("k-2026");
            api.serve(signed(&impostor, "v4", "EVIL-004"));
            api.polls(2).await;
            assert!(proxy.rejected("bad_signature") >= 1);
            // 4. No signature at all.
            api.serve(Served {
                signature: None,
                body: body("v5", "EVIL-005"),
                etag: "v5".into(),
            });
            api.polls(2).await;
            assert!(proxy.rejected("missing") >= 1);

            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);
            assert_eq!(cached_body(&cache), good);
            assert_eq!(proxy.verifier.stats.accepted(), 1);

            // 5. A valid bundle again is applied at once.
            api.serve(signed(&signer, "v6", "ACME-006"));
            api.polls(2).await;
            assert_eq!(proxy.codes(), vec!["ACME-006", "POL-014"]);
            assert_eq!(cached_body(&cache), body("v6", "ACME-006"));

            proxy.task.abort();
            api.server.abort();
        }

        /// Rotation: with both keys trusted, bundles of the old and of the new key
        /// verify; once the old key is dropped from the ring, its bundles are refused.
        #[tokio::test]
        async fn key_rotation_trusts_every_key_in_the_ring() {
            let old = TestSigner::new("vericto-2026");
            let new = TestSigner::new("vericto-2027");
            let api = Api::start(signed(&old, "v1", "OLD-001")).await;
            let proxy = Proxy::start(
                cfg(&api.url, None, Duration::from_millis(40)),
                PolicyRulesMode::Observe,
                ring_of(&[&old, &new]),
            );
            proxy.ready.wait_ready().await;
            api.polls(1).await;
            assert_eq!(proxy.codes()[0], "OLD-001");
            // The control plane switches its active key.
            api.serve(signed(&new, "v2", "NEW-002"));
            api.polls(2).await;
            assert_eq!(proxy.codes()[0], "NEW-002");
            proxy.task.abort();

            // A proxy that trusts only the new key refuses the old key's bundles.
            api.serve(signed(&old, "v3", "OLD-003"));
            let after = Proxy::start(
                cfg(&api.url, None, Duration::from_secs(3600)),
                PolicyRulesMode::Enforce,
                ring_of(&[&new]),
            );
            after.ready.wait_ready().await;
            after.task.abort();
            assert_eq!(after.codes(), built_in_codes());
            assert_eq!(after.rejected("unknown_key_id"), 1);
            api.server.abort();
        }

        /// The first sync, with no good bundle yet (no cache) and an unsigned or
        /// invalid response: the built-in ruleset stays, no policy is compiled,
        /// nothing is cached, and the proxy still gets ready (the same fail-safe as
        /// an unreachable control plane: never an unverified bundle, never an outage).
        #[tokio::test]
        async fn a_first_sync_with_no_verified_bundle_keeps_the_built_in_ruleset() {
            let signer = TestSigner::new("k");
            let unsigned = Served {
                signature: None,
                body: body("v1", "ACME-001"),
                etag: "v1".into(),
            };
            let stranger = TestSigner::new("other");
            for (served, reason, keyring) in [
                (unsigned.clone(), "missing", ring_of(&[&signer])),
                (
                    signed(&stranger, "v1", "ACME-001"),
                    "unknown_key_id",
                    ring_of(&[&signer]),
                ),
                (
                    signed(&signer, "v1", "ACME-001"),
                    "no_trusted_key",
                    Keyring::embedded_for("https://self-hosted.example"),
                ),
            ] {
                let api = Api::start(served).await;
                let dir = tempfile::tempdir().unwrap();
                let cache = dir.path().join("rules-cache.json");
                let proxy = Proxy::start(
                    cfg(&api.url, Some(cache.clone()), Duration::from_secs(3600)),
                    PolicyRulesMode::Enforce,
                    keyring,
                );
                tokio::time::timeout(Duration::from_secs(5), proxy.ready.wait_ready())
                    .await
                    .expect("ready even without a verified bundle");
                proxy.task.abort();
                api.server.abort();
                assert_eq!(proxy.codes(), built_in_codes(), "{reason}");
                let bundle = proxy.bundle();
                assert!(
                    bundle.rules.is_none() && bundle.policies.is_empty(),
                    "{reason}"
                );
                assert!(!cache.exists(), "{reason}: nothing cached");
                assert_eq!(proxy.rejected(reason), 1, "{reason}");
                assert!(!proxy.verifier.stats.verified_in_effect());
            }
        }

        /// With the flag off nothing is verified: an unsigned body is applied and
        /// cached exactly as before 4.16.0, and the verifier is never consulted.
        #[tokio::test]
        async fn with_the_flag_off_bundles_are_applied_unverified() {
            let api = Api::start(Served {
                signature: None,
                body: body("v1", "ACME-001"),
                etag: "v1".into(),
            })
            .await;
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("rules-cache.json");
            let proxy = Proxy::start(
                cfg(&api.url, Some(cache.clone()), Duration::from_secs(3600)),
                PolicyRulesMode::Off,
                Keyring::embedded_for("https://self-hosted.example"),
            );
            proxy.ready.wait_ready().await;
            proxy.task.abort();
            api.server.abort();
            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);
            assert!(
                proxy.bundle().rules.is_none(),
                "nothing compiled with the flag off"
            );
            assert_eq!(cached_body(&cache), body("v1", "ACME-001"));
            let file = std::fs::read_to_string(&cache).unwrap();
            assert!(!file.contains("\"signature\""), "{file}");
            assert_eq!(proxy.verifier.stats.accepted(), 0);
            for reason in crate::tcp::bundle_signature::REASONS {
                assert_eq!(proxy.rejected(reason), 0, "{reason}");
            }
        }

        /// The rules cache is verified when it is loaded. A verified cache resumes
        /// during an outage; a tampered one, or a 4.15.x one without a signature, is
        /// ignored with the flag on (its ETag too, so the API sends a full body),
        /// while the flag off still resumes from the unsigned one.
        #[tokio::test]
        async fn the_rules_cache_is_verified_on_load() {
            let signer = TestSigner::new("k");
            let dir = tempfile::tempdir().unwrap();
            let cache_path = dir.path().join("rules-cache.json");
            let unreachable = "http://127.0.0.1:9".to_string();
            let link = cfg(
                &unreachable,
                Some(cache_path.clone()),
                Duration::from_secs(3600),
            );
            let cache = RulesCache::from_config(&link).unwrap();

            let resume = |mode: PolicyRulesMode| {
                let proxy = Proxy::start(link.clone(), mode, ring_of(&[&signer]));
                async move {
                    proxy.ready.wait_ready().await;
                    proxy.task.abort();
                    proxy
                }
            };

            // Verified cache, control plane down: resumed.
            let good = body("v1", "ACME-001");
            cache.store(Some("\"v1\""), &good, Some(&signer.header(good.as_bytes())));
            let proxy = resume(PolicyRulesMode::Enforce).await;
            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);
            assert_eq!(proxy.bundle().policies.len(), 1);
            assert_eq!(proxy.verifier.stats.accepted(), 1);

            // Tampered body on disk: ignored.
            let evil = body("v1", "EVIL-001");
            cache.store(Some("\"v1\""), &evil, Some(&signer.header(good.as_bytes())));
            let proxy = resume(PolicyRulesMode::Enforce).await;
            assert_eq!(proxy.codes(), built_in_codes());
            assert_eq!(proxy.rejected("digest_mismatch"), 1);

            // A 4.15.x cache (no signature): ignored with the flag on, used with it off.
            cache.store(Some("\"v1\""), &good, None);
            let proxy = resume(PolicyRulesMode::Observe).await;
            assert_eq!(proxy.codes(), built_in_codes());
            assert_eq!(proxy.rejected("missing"), 1);
            let proxy = resume(PolicyRulesMode::Off).await;
            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);

            // An ignored cache does not lend its ETag: the API answers with a body.
            let api = Api::start(signed(&signer, "v1", "ACME-001")).await;
            cache.store(Some("\"v1\""), &good, None);
            let proxy = Proxy::start(
                cfg(
                    &api.url,
                    Some(cache_path.clone()),
                    Duration::from_secs(3600),
                ),
                PolicyRulesMode::Enforce,
                ring_of(&[&signer]),
            );
            proxy.ready.wait_ready().await;
            proxy.task.abort();
            api.server.abort();
            assert_eq!(api.seen.lock().unwrap()[0], None, "no If-None-Match");
            assert_eq!(proxy.codes(), vec!["ACME-001", "POL-014"]);
            assert!(proxy.verifier.stats.verified_in_effect());
        }
    }
}
