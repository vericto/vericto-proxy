//! PostgreSQL AST parser.
//!
//! Uses `pg_query` (a binding for libpg_query — PostgreSQL's internal parser)
//! as the primary parser: it builds the exact syntax tree the engine would
//! produce and walks it in [`crate::parser::pg_ast`] to detect destructive
//! statements, including those nested in data-modifying CTEs
//! (`WITH x AS (DELETE ...)`).
//!
//! This guarantees full fidelity: what Vetro analyses is identical to what
//! PostgreSQL would execute, and any query with invalid syntax is blocked as
//! `PARSE_ERROR` before reaching the database.

use crate::error::Result;
use crate::parser::pg_ast;
use crate::parser::{ParsedQuery, SqlParser};

pub struct PostgresParser;

impl PostgresParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PostgresParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for PostgresParser {
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        // Direct AST parsing with libpg_query (PostgreSQL's official parser).
        pg_ast::parse_postgres(sql)
    }

    fn dialect_name(&self) -> &'static str {
        "postgres"
    }
}
