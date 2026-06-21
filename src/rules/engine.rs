//! Tipos del dominio de reglas y orquestación de la evaluación.

use serde::{Deserialize, Serialize};

use crate::parser::ParsedQuery;
use crate::rules::evaluator;

/// Severidad de una regla. El orden importa: Critical > High > Medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }
}

/// Tipo de regla: estándar (built-in) o custom (definida por el usuario en YAML).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Standard,
    Custom,
}

/// Una regla activa del workspace, tal como la envía la API.
#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_id: String,
    pub code: String,
    pub severity: Severity,
    pub rule_type: RuleType,
    /// Condición YAML para reglas custom.
    pub ast_condition_yaml: Option<String>,
}

/// Decisión final sobre una query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allowed,
    Blocked,
}

/// Resultado de la evaluación de una query contra el ruleset activo.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub decision: Decision,
    pub rule_id: Option<String>,
    pub rule_code: Option<String>,
    pub severity: Option<Severity>,
    pub ast_node_path: Option<String>,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
}

impl EvaluationOutcome {
    pub fn allowed() -> Self {
        Self {
            decision: Decision::Allowed,
            rule_id: None,
            rule_code: None,
            severity: None,
            ast_node_path: None,
            estimated_rows_affected: None,
            suggested_safe_query: None,
        }
    }
}

/// El motor de reglas. Evalúa una query parseada contra las reglas activas y
/// devuelve la violación de mayor severidad (o ALLOWED si ninguna se viola).
pub struct RuleEngine;

impl RuleEngine {
    /// Evalúa `parsed` contra `rules`. Las reglas se evalúan todas; gana la
    /// violación de mayor severidad. El parsing AST ya garantizó que la query
    /// es sintácticamente válida.
    pub fn evaluate(parsed: &ParsedQuery, rules: &[Rule]) -> EvaluationOutcome {
        let mut best: Option<(Severity, evaluator::Violation)> = None;

        for rule in rules {
            if let Some(violation) = evaluator::evaluate_rule(rule, parsed) {
                let is_better = match &best {
                    None => true,
                    Some((sev, _)) => rule.severity > *sev,
                };
                if is_better {
                    best = Some((rule.severity, violation));
                }
            }
        }

        match best {
            None => EvaluationOutcome::allowed(),
            Some((severity, v)) => EvaluationOutcome {
                decision: Decision::Blocked,
                rule_id: Some(v.rule_id),
                rule_code: Some(v.rule_code),
                severity: Some(severity),
                ast_node_path: Some(v.ast_node_path),
                estimated_rows_affected: v.estimated_rows_affected,
                suggested_safe_query: v.suggested_safe_query,
            },
        }
    }
}
