//! AST evaluation handler.
//!
//! Exposes the HTTP endpoint consumed by the Fastify API (`callRustProxy`). It
//! receives a query, its dialect, and the workspace's active ruleset, runs the
//! deterministic AST parsing, and returns the block-or-allow decision.
//!
//! Although the component is called "TCP proxy" in the specs, the critical
//! security path is this AST evaluation engine; the Postgres/MySQL wire-protocol
//! termination delegates the decision to this service over local HTTP.

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::cache::ruleset::RulesetCache;
use crate::error::{ProxyError, MAX_QUERY_SIZE_BYTES};
use crate::metrics::Metrics;
use crate::parser::{parser_for, Dialect};
use crate::rules::engine::{Decision, Rule, RuleEngine, RuleType, Severity};

/// Shared service state.
pub struct AppState {
    pub cache: RulesetCache,
    pub metrics: Metrics,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            cache: RulesetCache::new(),
            metrics: Metrics::new(),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Request/response DTOs
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RuleDto {
    pub rule_id: String,
    pub code: String,
    pub severity: String,
    #[serde(default = "default_rule_type")]
    pub rule_type: String,
    #[serde(default)]
    pub ast_condition_yaml: Option<String>,
}

fn default_rule_type() -> String {
    "standard".to_string()
}

#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub query: String,
    pub dialect: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub ruleset_version: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleDto>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    /// "ALLOWED" | "BLOCKED" | "PARSE_ERROR"
    pub decision: String,
    pub rule_id: Option<String>,
    pub rule_code: Option<String>,
    pub severity: Option<String>,
    pub ast_node_path: Option<String>,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
    pub parse_error: Option<String>,
    pub latency_ms: f64,
}

// ----------------------------------------------------------------------------
// Handler
// ----------------------------------------------------------------------------

/// POST /evaluate — evaluate a query against the active ruleset.
pub async fn evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> (StatusCode, Json<EvaluateResponse>) {
    let start = Instant::now();

    // 1) Query size limit (fail-closed against oversized queries).
    if req.query.len() > MAX_QUERY_SIZE_BYTES {
        let latency_us = start.elapsed().as_micros() as u64;
        state.metrics.record_blocked(latency_us);
        return blocked_parse_error(ProxyError::QueryTooLarge.to_string(), latency_us);
    }

    // 2) Resolve dialect.
    let dialect = match Dialect::from_str(&req.dialect) {
        Ok(d) => d,
        Err(e) => {
            let latency_us = start.elapsed().as_micros() as u64;
            state.metrics.record_blocked(latency_us);
            return blocked_parse_error(e.to_string(), latency_us);
        }
    };

    // 3) AST parsing. A query that does not parse is blocked (fail-closed).
    let parser = parser_for(dialect);
    let parsed = match parser.parse(&req.query) {
        Ok(p) => p,
        Err(e) => {
            let latency_us = start.elapsed().as_micros() as u64;
            state.metrics.record_parse_error(latency_us);
            return blocked_parse_error(e.to_string(), latency_us);
        }
    };

    // 4) Resolve the ruleset (with per-workspace cache if a version is present).
    let rules = resolve_rules(&state.cache, &req);

    // 5) Evaluate.
    let outcome = RuleEngine::evaluate(&parsed, &rules);
    let latency_us = start.elapsed().as_micros() as u64;
    let latency_ms = latency_us as f64 / 1000.0;

    match outcome.decision {
        Decision::Allowed => {
            state.metrics.record_allowed(latency_us);
            (
                StatusCode::OK,
                Json(EvaluateResponse {
                    decision: "ALLOWED".to_string(),
                    rule_id: None,
                    rule_code: None,
                    severity: None,
                    ast_node_path: None,
                    estimated_rows_affected: outcome.estimated_rows_affected,
                    suggested_safe_query: None,
                    parse_error: None,
                    latency_ms,
                }),
            )
        }
        Decision::Blocked => {
            state.metrics.record_blocked(latency_us);
            (
                StatusCode::OK,
                Json(EvaluateResponse {
                    decision: "BLOCKED".to_string(),
                    rule_id: outcome.rule_id,
                    rule_code: outcome.rule_code,
                    severity: outcome.severity.map(|s| s.as_str().to_string()),
                    ast_node_path: outcome.ast_node_path,
                    estimated_rows_affected: outcome.estimated_rows_affected,
                    suggested_safe_query: outcome.suggested_safe_query,
                    parse_error: None,
                    latency_ms,
                }),
            )
        }
    }
}

/// Resolves the ruleset from the cache or builds it from the request DTO.
fn resolve_rules(cache: &RulesetCache, req: &EvaluateRequest) -> Vec<Rule> {
    if let (Some(ws), Some(version)) = (&req.workspace_id, &req.ruleset_version) {
        if let Some(cached) = cache.get(ws, version) {
            return cached;
        }
        let rules = build_rules(&req.rules);
        cache.put(ws, version, rules.clone());
        return rules;
    }
    build_rules(&req.rules)
}

fn build_rules(dtos: &[RuleDto]) -> Vec<Rule> {
    dtos.iter()
        .map(|d| Rule {
            rule_id: d.rule_id.clone(),
            code: d.code.clone(),
            severity: parse_severity(&d.severity),
            rule_type: match d.rule_type.as_str() {
                "custom" => RuleType::Custom,
                _ => RuleType::Standard,
            },
            ast_condition_yaml: d.ast_condition_yaml.clone(),
        })
        .collect()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        _ => Severity::Medium,
    }
}

/// Response for a query blocked by a parse or validation error.
/// Returns 200 with `decision: PARSE_ERROR` so the API decides the final HTTP
/// response to the client.
fn blocked_parse_error(message: String, latency_us: u64) -> (StatusCode, Json<EvaluateResponse>) {
    (
        StatusCode::OK,
        Json(EvaluateResponse {
            decision: "PARSE_ERROR".to_string(),
            rule_id: None,
            rule_code: None,
            severity: None,
            ast_node_path: Some("PARSE_ERROR".to_string()),
            estimated_rows_affected: None,
            suggested_safe_query: None,
            parse_error: Some(message),
            latency_ms: latency_us as f64 / 1000.0,
        }),
    )
}
