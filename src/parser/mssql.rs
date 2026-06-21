//! Parser AST para Microsoft SQL Server (T-SQL).
//!
//! Uses `sqlparser-rs` with `MsSqlDialect`, which handles T-SQL specifics
//! such as square-bracket identifier quoting ([TableName]), TOP N clauses,
//! and GO batch separators.

use crate::error::Result;
use crate::parser::walk::parse_with_dialect;
use crate::parser::{ParsedQuery, SqlParser};

use sqlparser::dialect::MsSqlDialect;

pub struct MsSqlParser {
    dialect: MsSqlDialect,
}

impl MsSqlParser {
    pub fn new() -> Self {
        Self {
            dialect: MsSqlDialect {},
        }
    }
}

impl Default for MsSqlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for MsSqlParser {
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        parse_with_dialect(&self.dialect, sql)
    }

    fn dialect_name(&self) -> &'static str {
        "mssql"
    }
}
