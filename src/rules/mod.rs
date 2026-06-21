//! Motor de reglas AST.
//!
//! - [`engine`]: tipos del dominio (Rule, Severity, Decision) y el `RuleEngine`
//!   que orquesta la evaluación.
//! - [`evaluator`]: lógica que evalúa cada regla (built-in y custom) contra el
//!   AST normalizado.

pub mod engine;
pub mod evaluator;
pub mod sync;
