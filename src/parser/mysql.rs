//! Parser AST para MySQL.
//!
//! Usa `sqlparser-rs` con `MySqlDialect`, que conoce las particularidades
//! sintácticas de MySQL — por ejemplo `DELETE ... LIMIT N`, que es válido en
//! MySQL (y acota el borrado) pero no existe en PostgreSQL.

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
