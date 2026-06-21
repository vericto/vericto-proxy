//! AST rule engine.
//!
//! - [`engine`]: domain types (Rule, Severity, Decision) and the `RuleEngine`
//!   that orchestrates evaluation.
//! - [`evaluator`]: logic that evaluates each rule (built-in and custom) against
//!   the normalized AST.

pub mod engine;
pub mod evaluator;
pub mod sync;
