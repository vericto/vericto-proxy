//! Parser AST para Oracle SQL.
//!
//! Uses `sqlparser-rs` with `GenericDialect` as the closest approximation to
//! Oracle's SQL syntax. A dedicated OracleDialect is not yet shipped in
//! sqlparser-rs (as of 0.52), so GenericDialect covers the vast majority of
//! DML statements (SELECT, INSERT, UPDATE, DELETE, TRUNCATE, DROP) and is
//! sufficient for Vetro's rule evaluation.
//!
//! Oracle-specific syntax that diverges from standard SQL (e.g. ROWNUM,
//! CONNECT BY, hierarchical queries, MERGE) will parse as `PARSE_ERROR` and
//! be handled conservatively (fail-closed → BLOCKED).

use crate::error::Result;
use crate::parser::walk::parse_with_dialect;
use crate::parser::{ParsedQuery, SqlParser};

use sqlparser::dialect::GenericDialect;

pub struct OracleParser {
    dialect: GenericDialect,
}

impl OracleParser {
    pub fn new() -> Self {
        Self {
            dialect: GenericDialect {},
        }
    }
}

impl Default for OracleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for OracleParser {
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        parse_with_dialect(&self.dialect, sql)
    }

    fn dialect_name(&self) -> &'static str {
        "oracle"
    }
}
