//! Multi-dialect AST parsers (Strategy Pattern).
//!
//! `PostgresParser`, `MySqlParser`, `OracleParser`, and `MsSqlParser` implement
//! the same [`SqlParser`] trait and produce a normalized [`ParsedQuery`] that
//! the rule engine evaluates dialect-agnostically.

pub mod mssql;
pub mod mysql;
pub mod oracle;
pub mod pg_ast;
pub mod postgres;
pub(crate) mod walk;

use crate::error::{ProxyError, Result};

/// Supported SQL dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Mysql,
    Oracle,
    MsSql,
}

impl Dialect {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Dialect::Postgres),
            "mysql" => Ok(Dialect::Mysql),
            "oracle" => Ok(Dialect::Oracle),
            "mssql" | "sqlserver" | "tsql" => Ok(Dialect::MsSql),
            other => Err(ProxyError::UnsupportedDialect(other.to_string())),
        }
    }
}

/// Statement type detected in the AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    Delete,
    Update,
    Drop,
    Truncate,
    Select,
    Insert,
    /// ALTER TABLE (DROP COLUMN, RENAME, ADD CONSTRAINT, …)
    AlterTable,
    /// Function call detected inside a query (SLEEP, PG_SLEEP, …)
    FunctionCall,
    Other,
}

/// Object type in a DROP statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropObjectKind {
    Table,
    Database,
    Schema,
    Index,
    Other,
}

/// Subtype of an ALTER TABLE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlterTableKind {
    DropColumn,
    Rename,
    Other,
}

/// Presence and quality of a WHERE clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WherePresence {
    /// No WHERE clause present.
    Absent,
    /// WHERE with an effective predicate (can be false for some value).
    Present,
    /// WHERE with a trivially-true predicate (1=1, true, …).
    /// Semantically equivalent to no WHERE.
    AlwaysTrue,
}

/// Normalized information for a single AST statement.
#[derive(Debug, Clone)]
pub struct StatementInfo {
    pub kind: StatementKind,
    /// Name of the primary relation affected, if extractable.
    pub relation: Option<String>,
    /// WHERE clause state (relevant for DELETE / UPDATE / SELECT).
    pub where_presence: WherePresence,
    /// Object type for DROP statements.
    pub drop_object: Option<DropObjectKind>,
    /// Subtype for ALTER TABLE statements.
    pub alter_table_kind: Option<AlterTableKind>,
    /// `true` when nested inside a CTE or subquery.
    pub is_nested: bool,
    /// AST node path, e.g. `DeleteStmt > WhereClause = NULL`.
    pub ast_node_path: String,
    // --- extra attributes used by specific rules ---
    /// DELETE LIMIT value, if present (MySQL/SQLite extension).
    pub delete_limit: Option<i64>,
    /// Whether DROP INDEX includes IF EXISTS.
    pub drop_index_if_exists: bool,
    /// Number of rows in an INSERT … VALUES batch.
    pub insert_row_count: Option<usize>,
    /// Whether INSERT specifies explicit column list.
    pub insert_has_columns: bool,
    /// Whether INSERT uses a SELECT as its source.
    pub insert_has_select: bool,
    /// Whether SELECT uses LIMIT.
    pub select_has_limit: bool,
    /// Whether SELECT target list is `*` (star).
    pub select_is_star: bool,
    /// Name of a called function (for VETRO-070).
    pub function_name: Option<String>,
    /// Whether the WHERE clause contains a trivially-true OR branch
    /// (e.g. `WHERE id = 1 OR 1=1`). Used by VETRO-090 to detect
    /// SQL injection tautologies. Populated for all statement types that
    /// have a WHERE clause (DELETE, UPDATE, SELECT).
    pub has_or_tautology: bool,
}

impl Default for StatementInfo {
    fn default() -> Self {
        Self {
            kind: StatementKind::Other,
            relation: None,
            where_presence: WherePresence::Absent,
            drop_object: None,
            alter_table_kind: None,
            is_nested: false,
            ast_node_path: String::new(),
            delete_limit: None,
            drop_index_if_exists: false,
            insert_row_count: None,
            insert_has_columns: false,
            insert_has_select: false,
            select_has_limit: false,
            select_is_star: false,
            function_name: None,
            has_or_tautology: false,
        }
    }
}

/// Result of parsing a complete query (may contain multiple statements).
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub statements: Vec<StatementInfo>,
}

/// Common interface for dialect-specific parsers (Strategy Pattern).
pub trait SqlParser: Send + Sync {
    /// Parses the query and returns the normalized representation.
    /// Returns `ProxyError::ParseError` for invalid syntax.
    fn parse(&self, sql: &str) -> Result<ParsedQuery>;

    fn dialect_name(&self) -> &'static str;
}

/// Factory: returns the parser for the given dialect.
pub fn parser_for(dialect: Dialect) -> Box<dyn SqlParser> {
    match dialect {
        Dialect::Postgres => Box::new(postgres::PostgresParser::new()),
        Dialect::Mysql => Box::new(mysql::MySqlParser::new()),
        Dialect::Oracle => Box::new(oracle::OracleParser::new()),
        Dialect::MsSql => Box::new(mssql::MsSqlParser::new()),
    }
}
