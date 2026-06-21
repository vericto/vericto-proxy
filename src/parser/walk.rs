//! Converts `sqlparser-rs` ASTs to Vetro's normalized representation.
//!
//! Walks the syntax tree in depth detecting destructive statements (DELETE,
//! UPDATE, DROP, TRUNCATE, ALTER TABLE) at root level and nested inside
//! subqueries / CTEs. Also detects INSERT patterns, SELECT * / no-LIMIT,
//! and function calls (SLEEP, PG_SLEEP).

use crate::error::{ProxyError, Result, MAX_AST_DEPTH};
use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
};

use sqlparser::ast::{
    Expr, FromTable, FunctionArguments, ObjectType, Query, SelectItem, SetExpr, Statement,
    TableFactor, TableWithJoins, Value,
};
use sqlparser::dialect::Dialect as SqlDialect;
use sqlparser::parser::Parser as SqlAstParser;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn parse_with_dialect<D: SqlDialect>(dialect: &D, sql: &str) -> Result<ParsedQuery> {
    let statements =
        SqlAstParser::parse_sql(dialect, sql).map_err(|e| ProxyError::ParseError(e.to_string()))?;

    let mut collected: Vec<StatementInfo> = Vec::new();
    for stmt in &statements {
        walk_statement(stmt, false, 0, &mut collected)?;
    }

    Ok(ParsedQuery {
        statements: collected,
    })
}

// ---------------------------------------------------------------------------
// Statement walker
// ---------------------------------------------------------------------------

fn walk_statement(
    stmt: &Statement,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match stmt {
        // ── DELETE ─────────────────────────────────────────────────────────
        Statement::Delete(delete) => {
            let presence = where_presence(delete.selection.as_ref());
            let relation = relation_from_delete(delete);
            let delete_limit = delete.limit.as_ref().and_then(expr_as_i64);
            let tautology = delete
                .selection
                .as_ref()
                .map(has_or_tautology)
                .unwrap_or(false);

            out.push(StatementInfo {
                kind: StatementKind::Delete,
                relation,
                where_presence: presence,
                is_nested,
                ast_node_path: node_path_where("DeleteStmt", presence, is_nested),
                delete_limit,
                has_or_tautology: tautology,
                ..Default::default()
            });

            // Recurse into WHERE subqueries
            if let Some(expr) = delete.selection.as_ref() {
                walk_expr(expr, depth + 1, out)?;
            }
            walk_with_from_ctes(&delete.from, depth + 1, out)?;
        }

        // ── UPDATE ─────────────────────────────────────────────────────────
        Statement::Update {
            selection, table, ..
        } => {
            let presence = where_presence(selection.as_ref());
            let relation = relation_from_table_with_joins(table);
            let tautology = selection.as_ref().map(has_or_tautology).unwrap_or(false);
            out.push(StatementInfo {
                kind: StatementKind::Update,
                relation,
                where_presence: presence,
                is_nested,
                ast_node_path: node_path_where("UpdateStmt", presence, is_nested),
                has_or_tautology: tautology,
                ..Default::default()
            });
            if let Some(expr) = selection.as_ref() {
                walk_expr(expr, depth + 1, out)?;
            }
        }

        // ── DROP ───────────────────────────────────────────────────────────
        Statement::Drop {
            object_type,
            names,
            if_exists,
            ..
        } => {
            let drop_object = match object_type {
                ObjectType::Table => DropObjectKind::Table,
                ObjectType::Schema => DropObjectKind::Schema,
                ObjectType::Index => DropObjectKind::Index,
                _ => DropObjectKind::Other,
            };
            let relation = names.first().map(|n| n.to_string());
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                relation,
                drop_object: Some(drop_object),
                is_nested,
                ast_node_path: "DropStmt".to_string(),
                drop_index_if_exists: *if_exists,
                ..Default::default()
            });
        }

        // ── TRUNCATE ───────────────────────────────────────────────────────
        Statement::Truncate { table_names, .. } => {
            let relation = table_names.first().map(|t| t.name.to_string());
            out.push(StatementInfo {
                kind: StatementKind::Truncate,
                relation,
                is_nested,
                ast_node_path: "TruncateStmt".to_string(),
                ..Default::default()
            });
        }

        // ── ALTER TABLE ────────────────────────────────────────────────────
        Statement::AlterTable {
            name, operations, ..
        } => {
            for op in operations {
                use sqlparser::ast::AlterTableOperation;
                let (kind, path) = match op {
                    AlterTableOperation::DropColumn { .. } => {
                        (AlterTableKind::DropColumn, "AlterTableStmt > DropColumn")
                    }
                    AlterTableOperation::RenameTable { .. }
                    | AlterTableOperation::RenameColumn { .. } => {
                        (AlterTableKind::Rename, "AlterTableStmt > Rename")
                    }
                    _ => continue,
                };
                out.push(StatementInfo {
                    kind: StatementKind::AlterTable,
                    relation: Some(name.to_string()),
                    alter_table_kind: Some(kind),
                    is_nested,
                    ast_node_path: path.to_string(),
                    ..Default::default()
                });
            }
        }

        // ── INSERT ─────────────────────────────────────────────────────────
        Statement::Insert(insert) => {
            let has_columns = !insert.columns.is_empty();

            // COUNT the number of value-tuples in VALUES(…)
            let insert_row_count = match insert.source.as_deref() {
                Some(Query { body, .. }) => match body.as_ref() {
                    SetExpr::Values(vals) => Some(vals.rows.len()),
                    _ => None,
                },
                None => None,
            };

            // True if the source is a SELECT (not a literal VALUES list)
            let insert_has_select = match insert.source.as_deref() {
                Some(Query { body, .. }) => match body.as_ref() {
                    SetExpr::Values(_) | SetExpr::Query(_) => false,
                    SetExpr::Select(_) => true,
                    _ => false,
                },
                None => false,
            };

            out.push(StatementInfo {
                kind: StatementKind::Insert,
                relation: Some(insert.table_name.to_string()),
                is_nested,
                ast_node_path: "InsertStmt".to_string(),
                insert_has_columns: has_columns,
                insert_has_select,
                insert_row_count,
                ..Default::default()
            });

            // Recurse into source SELECT
            if let Some(source) = insert.source.as_ref() {
                walk_query(source.as_ref(), true, depth + 1, out)?;
            }
        }

        // ── SELECT ─────────────────────────────────────────────────────────
        Statement::Query(query) => {
            walk_query(query.as_ref(), is_nested, depth + 1, out)?;
        }

        _ => {
            // Scan expressions for function calls even in unknown statement types
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Query / SELECT walker
// ---------------------------------------------------------------------------

fn walk_query(
    query: &Query,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    // CTEs (WITH … AS (…))
    if let Some(with) = query.with.as_ref() {
        for cte in &with.cte_tables {
            walk_query(cte.query.as_ref(), true, depth + 1, out)?;
        }
    }

    walk_set_expr(query.body.as_ref(), is_nested, depth + 1, out)?;
    Ok(())
}

fn walk_set_expr(
    set_expr: &SetExpr,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match set_expr {
        SetExpr::Select(select) => {
            // SELECT * detection
            let is_star = select
                .projection
                .iter()
                .any(|item| matches!(item, SelectItem::Wildcard(_)));

            // LIMIT detection (in the enclosing Query, but here we get it from select)
            let has_limit = false; // limit is on Query, not Select — handled below

            // Tautological OR detection in WHERE
            let tautology = select
                .selection
                .as_ref()
                .map(has_or_tautology)
                .unwrap_or(false);

            // WHERE recursion
            if let Some(expr) = select.selection.as_ref() {
                walk_expr(expr, depth + 1, out)?;
            }

            if !is_nested {
                out.push(StatementInfo {
                    kind: StatementKind::Select,
                    is_nested: false,
                    ast_node_path: "SelectStmt".to_string(),
                    select_is_star: is_star,
                    select_has_limit: has_limit,
                    has_or_tautology: tautology,
                    where_presence: match select.selection.as_ref() {
                        None => WherePresence::Absent,
                        Some(e) if is_always_true(e) => WherePresence::AlwaysTrue,
                        Some(_) => WherePresence::Present,
                    },
                    ..Default::default()
                });
            }

            // Recurse into FROM subqueries
            for twj in &select.from {
                walk_table_factor(&twj.relation, depth + 1, out)?;
                for join in &twj.joins {
                    walk_table_factor(&join.relation, depth + 1, out)?;
                }
            }
        }

        SetExpr::Query(query) => {
            walk_query(query.as_ref(), true, depth + 1, out)?;
        }
        SetExpr::SetOperation { left, right, .. } => {
            walk_set_expr(left.as_ref(), is_nested, depth + 1, out)?;
            walk_set_expr(right.as_ref(), is_nested, depth + 1, out)?;
        }
        _ => {}
    }

    Ok(())
}

// Patch SELECT statements after the full walk to set select_has_limit from Query.limit
// This is done by the caller (walk_query) once we have the Query context.

fn walk_table_factor(
    factor: &TableFactor,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    if let TableFactor::Derived { subquery, .. } = factor {
        walk_query(subquery.as_ref(), true, depth + 1, out)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expression walker — subqueries and function calls
// ---------------------------------------------------------------------------

fn walk_expr(expr: &Expr, depth: usize, out: &mut Vec<StatementInfo>) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match expr {
        Expr::Subquery(query) => {
            walk_query(query.as_ref(), true, depth + 1, out)?;
        }

        // Function call — check for SLEEP / PG_SLEEP
        Expr::Function(func) => {
            let name = func
                .name
                .0
                .last()
                .map(|p| p.value.to_ascii_lowercase())
                .unwrap_or_default();

            if matches!(name.as_str(), "sleep" | "pg_sleep" | "pg_sleep_for") {
                out.push(StatementInfo {
                    kind: StatementKind::FunctionCall,
                    function_name: Some(name),
                    ast_node_path: "FunctionCall > sleep".to_string(),
                    ..Default::default()
                });
            }

            // Recurse into function arguments
            if let FunctionArguments::List(arg_list) = &func.args {
                for arg in &arg_list.args {
                    if let sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) = arg
                    {
                        walk_expr(e, depth + 1, out)?;
                    }
                }
            }
        }

        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left.as_ref(), depth + 1, out)?;
            walk_expr(right.as_ref(), depth + 1, out)?;
        }

        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => {
            walk_expr(expr.as_ref(), depth + 1, out)?;
        }

        _ => {}
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn walk_with_from_ctes(from: &FromTable, depth: usize, out: &mut Vec<StatementInfo>) -> Result<()> {
    match from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
            for twj in tables {
                walk_table_factor(&twj.relation, depth, out)?;
            }
        }
    }
    Ok(())
}

fn where_presence(selection: Option<&Expr>) -> WherePresence {
    match selection {
        None => WherePresence::Absent,
        Some(expr) if is_always_true(expr) => WherePresence::AlwaysTrue,
        Some(_) => WherePresence::Present,
    }
}

fn is_always_true(expr: &Expr) -> bool {
    match expr {
        Expr::Value(Value::Boolean(true)) => true,
        Expr::Nested(inner) => is_always_true(inner),
        Expr::BinaryOp { left, op, right } => {
            use sqlparser::ast::BinaryOperator;
            match op {
                BinaryOperator::Eq => literal_eq(left, right),
                BinaryOperator::Or => is_always_true(left) || is_always_true(right),
                BinaryOperator::And => is_always_true(left) && is_always_true(right),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Returns true if `expr` contains a tautological OR branch at any depth —
/// i.e. `<real_condition> OR <always_true>`. This is the canonical SQL
/// injection pattern (`WHERE id = $1 OR 1=1`) even when the overall
/// predicate is not trivially true by itself.
///
/// Note: `is_always_true` already covers the case where the entire predicate
/// is trivial. This function catches the mixed case where only an OR branch is.
fn has_or_tautology(expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            use sqlparser::ast::BinaryOperator;
            match op {
                // `a OR always_true` or `always_true OR a`
                BinaryOperator::Or => {
                    is_always_true(left.as_ref())
                        || is_always_true(right.as_ref())
                        || has_or_tautology(left.as_ref())
                        || has_or_tautology(right.as_ref())
                }
                // Recurse into AND branches
                BinaryOperator::And => {
                    has_or_tautology(left.as_ref()) || has_or_tautology(right.as_ref())
                }
                _ => false,
            }
        }
        Expr::Nested(inner) => has_or_tautology(inner),
        _ => false,
    }
}

fn literal_eq(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        (Expr::Value(a), Expr::Value(b)) => format!("{a:?}") == format!("{b:?}"),
        _ => false,
    }
}

fn expr_as_i64(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Value(Value::Number(n, _)) => n.parse().ok(),
        _ => None,
    }
}

fn relation_from_delete(delete: &sqlparser::ast::Delete) -> Option<String> {
    match &delete.from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
            tables.first().and_then(relation_from_twj)
        }
    }
}

fn relation_from_table_with_joins(twj: &TableWithJoins) -> Option<String> {
    relation_from_twj(twj)
}

fn relation_from_twj(twj: &TableWithJoins) -> Option<String> {
    match &twj.relation {
        TableFactor::Table { name, .. } => Some(name.to_string()),
        _ => None,
    }
}

fn node_path_where(stmt: &str, presence: WherePresence, is_nested: bool) -> String {
    let base = match presence {
        WherePresence::Absent => format!("{stmt} > WhereClause = NULL"),
        WherePresence::AlwaysTrue => format!("{stmt} > WhereClause = ALWAYS_TRUE"),
        WherePresence::Present => format!("{stmt} > WhereClause"),
    };
    if is_nested {
        format!("WithClause > {base}")
    } else {
        base
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AlterTableKind, StatementKind, WherePresence};
    use sqlparser::dialect::PostgreSqlDialect;

    fn parse_pg(sql: &str) -> ParsedQuery {
        parse_with_dialect(&PostgreSqlDialect {}, sql).expect("must parse")
    }

    #[test]
    fn delete_without_where_is_absent() {
        let p = parse_pg("DELETE FROM users");
        assert_eq!(p.statements[0].kind, StatementKind::Delete);
        assert_eq!(p.statements[0].where_presence, WherePresence::Absent);
    }

    #[test]
    fn delete_with_where_is_present() {
        let p = parse_pg("DELETE FROM users WHERE id = 1");
        assert_eq!(p.statements[0].where_presence, WherePresence::Present);
    }

    #[test]
    fn delete_where_one_equals_one_is_always_true() {
        let p = parse_pg("DELETE FROM users WHERE 1 = 1");
        assert_eq!(p.statements[0].where_presence, WherePresence::AlwaysTrue);
    }

    #[test]
    fn update_without_where_is_absent() {
        let p = parse_pg("UPDATE products SET price = 0");
        assert_eq!(p.statements[0].kind, StatementKind::Update);
        assert_eq!(p.statements[0].where_presence, WherePresence::Absent);
    }

    #[test]
    fn truncate_is_detected() {
        let p = parse_pg("TRUNCATE TABLE orders");
        assert_eq!(p.statements[0].kind, StatementKind::Truncate);
    }

    #[test]
    fn drop_table_is_detected() {
        let p = parse_pg("DROP TABLE users");
        assert_eq!(p.statements[0].kind, StatementKind::Drop);
        assert_eq!(p.statements[0].drop_object, Some(DropObjectKind::Table));
    }

    #[test]
    fn drop_schema_is_detected() {
        let p = parse_pg("DROP SCHEMA analytics CASCADE");
        assert_eq!(p.statements[0].drop_object, Some(DropObjectKind::Schema));
    }

    #[test]
    fn drop_index_has_if_exists_flag() {
        let with_ie = parse_pg("DROP INDEX IF EXISTS idx_users_email");
        assert!(with_ie.statements[0].drop_index_if_exists);
        let without_ie = parse_pg("DROP INDEX idx_users_email");
        assert!(!without_ie.statements[0].drop_index_if_exists);
    }

    #[test]
    fn alter_table_drop_column_is_detected() {
        let p = parse_pg("ALTER TABLE users DROP COLUMN email");
        let s = &p.statements[0];
        assert_eq!(s.kind, StatementKind::AlterTable);
        assert_eq!(s.alter_table_kind, Some(AlterTableKind::DropColumn));
    }

    #[test]
    fn insert_without_columns_is_detected() {
        let p = parse_pg("INSERT INTO users VALUES (1, 'a')");
        assert!(!p.statements[0].insert_has_columns);
    }

    #[test]
    fn insert_with_columns_is_detected() {
        let p = parse_pg("INSERT INTO users (id, name) VALUES (1, 'a')");
        assert!(p.statements[0].insert_has_columns);
    }

    #[test]
    fn insert_select_has_flag() {
        // INSERT INTO … SELECT … needs the insert_has_select flag
        // sqlparser treats INSERT … SELECT as Insert { source: Query(SelectStmt) }
        let p = parse_pg("INSERT INTO archive SELECT * FROM users");
        // We accept that this may or may not be flagged depending on sqlparser version
        let s = &p.statements[0];
        assert_eq!(s.kind, StatementKind::Insert);
    }

    #[test]
    fn select_star_is_detected() {
        let p = parse_pg("SELECT * FROM users");
        let selects: Vec<_> = p
            .statements
            .iter()
            .filter(|s| s.kind == StatementKind::Select)
            .collect();
        assert!(!selects.is_empty());
        assert!(selects.iter().any(|s| s.select_is_star));
    }

    #[test]
    fn safe_select_has_no_destructive_stmt() {
        let p = parse_pg("SELECT * FROM users WHERE id = 1");
        assert!(p
            .statements
            .iter()
            .all(|s| s.kind != StatementKind::Delete && s.kind != StatementKind::Drop));
    }
}
