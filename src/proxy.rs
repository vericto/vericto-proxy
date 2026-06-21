//! Handler de evaluación AST.
//!
//! Expone el endpoint HTTP que consume la API Fastify (`callRustProxy`). Recibe
//! una query, su dialecto y el ruleset activo del workspace, ejecuta el parsing
//! AST determinístico y devuelve la decisión de bloqueo o paso.
//!
//! Aunque el componente se llama "proxy TCP" en las specs, el path crítico de
//! seguridad es este motor de evaluación AST; la terminación del wire-protocol
//! de Postgres/MySQL delega la decisión a este servicio vía HTTP local.

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::cache::ruleset::RulesetCache;
use crate::error::{ProxyError, MAX_QUERY_SIZE_BYTES};
use crate::metrics::Metrics;
use crate::parser::{parser_for, Dialect};
use crate::rules::engine::{Decision, Rule, RuleEngine, RuleType, Severity};

/// Estado compartido del servicio.
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
// DTOs de request/response
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

/// POST /evaluate — evalúa una query contra el ruleset activo.
pub async fn evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> (StatusCode, Json<EvaluateResponse>) {
    let start = Instant::now();

    // 1) Límite de tamaño de query (fail-closed ante queries gigantes).
    if req.query.len() > MAX_QUERY_SIZE_BYTES {
        let latency_us = start.elapsed().as_micros() as u64;
        state.metrics.record_blocked(latency_us);
        return blocked_parse_error(
            ProxyError::QueryTooLarge.to_string(),
            latency_us,
        );
    }

    // 2) Resolver dialecto.
    let dialect = match Dialect::from_str(&req.dialect) {
        Ok(d) => d,
        Err(e) => {
            let latency_us = start.elapsed().as_micros() as u64;
            state.metrics.record_blocked(latency_us);
            return blocked_parse_error(e.to_string(), latency_us);
        }
    };

    // 3) Parsing AST. Una query que no parsea se bloquea (fail-closed).
    let parser = parser_for(dialect);
    let parsed = match parser.parse(&req.query) {
        Ok(p) => p,
        Err(e) => {
            let latency_us = start.elapsed().as_micros() as u64;
            state.metrics.record_parse_error(latency_us);
            return blocked_parse_error(e.to_string(), latency_us);
        }
    };

    // 4) Resolver el ruleset (con caché por workspace si hay versión).
    let rules = resolve_rules(&state.cache, &req);

    // 5) Evaluar.
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

/// Resuelve el ruleset desde la caché o lo construye desde el request DTO.
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

/// Respuesta de query bloqueada por error de parsing o validación.
/// Devuelve 200 con `decision: PARSE_ERROR` para que la API decida la respuesta
/// HTTP final hacia el cliente.
fn blocked_parse_error(
    message: String,
    latency_us: u64,
) -> (StatusCode, Json<EvaluateResponse>) {
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
