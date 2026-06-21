//! Vetro proxy error types.
//!
//! `ProxyError` covers failures in the AST evaluation path. Parse errors get
//! special treatment: a query that does not parse is blocked as a precaution
//! (fail-closed) and reported as `PARSE_ERROR`.

use thiserror::Error;

/// Query size limit (64KB) enforced by the coding standards.
pub const MAX_QUERY_SIZE_BYTES: usize = 64 * 1024;

/// Maximum AST depth that is walked (50 levels).
pub const MAX_AST_DEPTH: usize = 50;

#[derive(Debug, Error)]
pub enum ProxyError {
    /// The SQL query has invalid or malformed syntax.
    /// Client-facing code: `VETRO-PARSE-ERROR`.
    #[error("VETRO-PARSE-ERROR: {0}")]
    ParseError(String),

    /// The query exceeds the maximum allowed size (64KB).
    #[error("VETRO-QUERY-TOO-LARGE: query exceeds the {MAX_QUERY_SIZE_BYTES} byte limit")]
    QueryTooLarge,

    /// The AST exceeds the maximum nesting depth (50 levels).
    /// Possible evasion attempt via excessive nesting.
    #[error("VETRO-AST-TOO-DEEP: AST exceeds the maximum depth of {MAX_AST_DEPTH} levels")]
    AstTooDeep,

    /// Unsupported dialect.
    #[error("VETRO-UNSUPPORTED-DIALECT: dialect '{0}' is not supported")]
    UnsupportedDialect(String),

    /// A custom YAML rule is malformed.
    #[error("VETRO-INVALID-RULE: invalid custom rule: {0}")]
    InvalidCustomRule(String),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
