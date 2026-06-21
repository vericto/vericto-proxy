//! MySQL AST parser.
//!
//! Uses `sqlparser-rs` with `MySqlDialect`, which understands MySQL-specific
//! syntax — for example `DELETE ... LIMIT N`, which is valid in MySQL (and
//! bounds the delete) but does not exist in PostgreSQL.

use crate::error::Result;
use crate::parser::walk::parse_with_dialect;
use crate::parser::{ParsedQuery, SqlParser};

use sqlparser::dialect::MySqlDialect;

pub struct MySqlParser {
    dialect: MySqlDialect,
}

impl MySqlParser {
    pub fn new() -> Self {
        Self {
            dialect: MySqlDialect {},
        }
    }
}

impl Default for MySqlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for MySqlParser {
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        parse_with_dialect(&self.dialect, sql)
    }

    fn dialect_name(&self) -> &'static str {
        "mysql"
    }
}
