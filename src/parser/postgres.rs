//! Parser AST para PostgreSQL.
//!
//! Usa `pg_query` (binding de libpg_query — el parser interno de PostgreSQL) como
//! parser principal: construye el árbol sintáctico exacto que produciría el motor
//! y lo recorre en [`crate::parser::pg_ast`] para detectar sentencias destructivas,
//! incluyendo las anidadas en CTEs data-modifying (`WITH x AS (DELETE ...)`).
//!
//! Esto garantiza fidelidad total: lo que Vetro analiza es idéntico a lo que
//! PostgreSQL ejecutaría, y cualquier query con sintaxis inválida se bloquea como
//! `PARSE_ERROR` antes de tocar la base de datos.

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
        // Parsing AST directo con libpg_query (el parser oficial de PostgreSQL).
        pg_ast::parse_postgres(sql)
    }

    fn dialect_name(&self) -> &'static str {
        "postgres"
    }
}
