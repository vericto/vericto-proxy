//! Walker of the `pg_query` protobuf AST (libpg_query, PostgreSQL's internal
//! parser) into Vetro's normalized representation.
//!
//! Unlike `walk.rs` (which uses the sqlparser-rs AST), this module operates on
//! the exact syntax tree PostgreSQL would produce, guaranteeing that what Vetro
//! analyses is identical to what the engine would execute. It detects DELETE,
//! UPDATE, DROP, and TRUNCATE — including those nested inside data-modifying
//! CTEs (`WITH x AS (DELETE ...)`), which sqlparser-rs does not handle.

use crate::error::{ProxyError, Result, MAX_AST_DEPTH};
use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
};

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{Node, ObjectType, RangeVar, WithClause};

/// Parse a PostgreSQL query with libpg_query and return the normalized
/// representation. Returns `ParseError` on invalid syntax.
pub fn parse_postgres(sql: &str) -> Result<ParsedQuery> {
    let result = pg_query::parse(sql).map_err(|e| ProxyError::ParseError(e.to_string()))?;

    let mut out: Vec<StatementInfo> = Vec::new();
    for raw in &result.protobuf.stmts {
        if let Some(node) = raw.stmt.as_ref() {
            if let Some(inner) = node.node.as_ref() {
                walk_node(inner, false, 0, &mut out)?;
            }
        }
    }

    Ok(ParsedQuery { statements: out })
}

/// Walk an AST node, recording destructive statements and recursing into
/// WITH clauses (CTEs) and sub-selects.
fn walk_node(
    node: &NodeEnum,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match node {
        NodeEnum::DeleteStmt(stmt) => {
            let presence = where_presence(stmt.where_clause.as_deref());
            out.push(StatementInfo {
                kind: StatementKind::Delete,
                relation: relname(stmt.relation.as_ref()),
                where_presence: presence,
                is_nested,
                ast_node_path: node_path("DeleteStmt", presence, is_nested),
                has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        NodeEnum::UpdateStmt(stmt) => {
            let presence = where_presence(stmt.where_clause.as_deref());
            out.push(StatementInfo {
                kind: StatementKind::Update,
                relation: relname(stmt.relation.as_ref()),
                where_presence: presence,
                is_nested,
                ast_node_path: node_path("UpdateStmt", presence, is_nested),
                has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        NodeEnum::DropStmt(stmt) => {
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                is_nested,
                ast_node_path: "DropStmt".to_string(),
                drop_object: Some(drop_kind(stmt.remove_type)),
                // `missing_ok` is libpg_query's representation of IF EXISTS.
                drop_index_if_exists: stmt.missing_ok,
                ..Default::default()
            });
        }

        // ALTER TABLE … DROP COLUMN (VETRO-015). libpg_query emits an
        // AlterTableStmt whose `cmds` carry the subtype; RENAME is a separate
        // RenameStmt node handled below.
        NodeEnum::AlterTableStmt(stmt) => {
            use pg_query::protobuf::AlterTableType;
            for cmd in &stmt.cmds {
                let Some(NodeEnum::AlterTableCmd(c)) = cmd.node.as_ref() else {
                    continue;
                };
                if let Some(AlterTableType::AtDropColumn) = AlterTableType::from_i32(c.subtype) {
                    out.push(StatementInfo {
                        kind: StatementKind::AlterTable,
                        relation: relname(stmt.relation.as_ref()),
                        alter_table_kind: Some(AlterTableKind::DropColumn),
                        is_nested,
                        ast_node_path: "AlterTableStmt > DropColumn".to_string(),
                        ..Default::default()
                    });
                }
            }
        }

        // ALTER TABLE … RENAME TO / RENAME COLUMN (VETRO-016). PostgreSQL
        // models renames as a dedicated RenameStmt rather than an
        // AlterTableCmd subtype.
        NodeEnum::RenameStmt(stmt) => {
            if matches!(
                ObjectType::from_i32(stmt.rename_type),
                Some(ObjectType::ObjectTable) | Some(ObjectType::ObjectColumn)
            ) {
                out.push(StatementInfo {
                    kind: StatementKind::AlterTable,
                    relation: relname(stmt.relation.as_ref()),
                    alter_table_kind: Some(AlterTableKind::Rename),
                    is_nested,
                    ast_node_path: "AlterTableStmt > Rename".to_string(),
                    ..Default::default()
                });
            }
        }

        NodeEnum::TruncateStmt(_) => {
            out.push(StatementInfo {
                kind: StatementKind::Truncate,
                is_nested,
                ast_node_path: "TruncateStmt".to_string(),
                ..Default::default()
            });
        }

        NodeEnum::SelectStmt(stmt) => {
            if !is_nested {
                // Populate the SELECT-specific attributes the rule engine
                // consumes (VETRO-050 needs LIMIT presence, VETRO-051 needs
                // SELECT * + WHERE state). Without this every PostgreSQL SELECT
                // defaulted to `select_has_limit = false` / `where = Absent`,
                // causing those rules to fire on every read.
                let presence = where_presence(stmt.where_clause.as_deref());
                out.push(StatementInfo {
                    kind: StatementKind::Select,
                    where_presence: presence,
                    is_nested: false,
                    ast_node_path: "SelectStmt".to_string(),
                    select_has_limit: stmt.limit_count.is_some(),
                    select_is_star: target_list_has_star(&stmt.target_list),
                    has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
                    ..Default::default()
                });
            }
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        NodeEnum::InsertStmt(stmt) => {
            let has_cols = !stmt.cols.is_empty();
            out.push(StatementInfo {
                kind: StatementKind::Insert,
                relation: relname(stmt.relation.as_ref()),
                is_nested,
                ast_node_path: "InsertStmt".to_string(),
                insert_has_columns: has_cols,
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
            if let Some(sel) = stmt.select_stmt.as_deref() {
                if let Some(inner) = sel.node.as_ref() {
                    walk_node(inner, true, depth + 1, out)?;
                }
            }
        }

        _ => {}
    }

    Ok(())
}

/// Walk the CTEs of a WITH clause. Each CTE body (`ctequery`) can be a
/// data-modifying statement (DELETE/UPDATE) that must be evaluated.
fn walk_with_clause(
    with: Option<&WithClause>,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let Some(with) = with else { return Ok(()) };

    for cte_node in &with.ctes {
        let Some(NodeEnum::CommonTableExpr(cte)) = cte_node.node.as_ref() else {
            continue;
        };
        if let Some(ctequery) = cte.ctequery.as_deref() {
            if let Some(inner) = ctequery.node.as_ref() {
                walk_node(inner, true, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

/// Determine WHERE clause state from a protobuf node.
fn where_presence(where_clause: Option<&Node>) -> WherePresence {
    match where_clause {
        None => WherePresence::Absent,
        Some(node) => match node.node.as_ref() {
            Some(inner) if is_always_true(inner) => WherePresence::AlwaysTrue,
            _ => WherePresence::Present,
        },
    }
}

/// Detect trivially-true predicates in the pg_query AST:
/// - boolean constant `true`
/// - equality between two identical constants (`1 = 1`)
fn is_always_true(node: &NodeEnum) -> bool {
    match node {
        // Boolean constant TRUE.
        NodeEnum::AConst(c) => match c.val.as_ref() {
            Some(pg_query::protobuf::a_const::Val::Boolval(b)) => b.boolval,
            _ => false,
        },
        // "=" operator with both sides being identical constants.
        NodeEnum::AExpr(expr) => {
            if operator_name(&expr.name) != Some("=".to_string()) {
                return false;
            }
            match (expr.lexpr.as_deref(), expr.rexpr.as_deref()) {
                (Some(l), Some(r)) => const_eq(l, r),
                _ => false,
            }
        }
        // BoolExpr AND/OR: AND requires both children true; OR requires any.
        // pg_query protobuf enums expose from_i32() rather than TryFrom<i32>.
        NodeEnum::BoolExpr(b) => {
            use pg_query::protobuf::BoolExprType;
            let children: Vec<bool> = b
                .args
                .iter()
                .filter_map(|n| n.node.as_ref())
                .map(is_always_true)
                .collect();
            match BoolExprType::from_i32(b.boolop) {
                Some(BoolExprType::AndExpr) => !children.is_empty() && children.iter().all(|x| *x),
                Some(BoolExprType::OrExpr) => children.iter().any(|x| *x),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Returns `true` when a WHERE predicate contains a trivially-true OR branch
/// at any depth (e.g. `id = $1 OR 1=1`). Used by VETRO-090 to detect the
/// canonical SQL injection tautology on the PostgreSQL path. Mirrors the
/// sqlparser walker so behaviour is identical across dialects.
fn where_has_or_tautology(where_clause: Option<&Node>) -> bool {
    where_clause
        .and_then(|n| n.node.as_ref())
        .map(has_or_tautology)
        .unwrap_or(false)
}

/// Recursively detect a tautological OR branch: an `OR` whose any operand is
/// always true, or an `AND` containing such an `OR` deeper down.
fn has_or_tautology(node: &NodeEnum) -> bool {
    use pg_query::protobuf::BoolExprType;
    let NodeEnum::BoolExpr(b) = node else {
        return false;
    };
    let children = || b.args.iter().filter_map(|n| n.node.as_ref());
    match BoolExprType::from_i32(b.boolop) {
        Some(BoolExprType::OrExpr) => {
            children().any(is_always_true) || children().any(has_or_tautology)
        }
        Some(BoolExprType::AndExpr) => children().any(has_or_tautology),
        _ => false,
    }
}

/// Compare two nodes to determine whether they represent the same literal constant.
fn const_eq(left: &Node, right: &Node) -> bool {
    match (left.node.as_ref(), right.node.as_ref()) {
        (Some(NodeEnum::AConst(a)), Some(NodeEnum::AConst(b))) => {
            format!("{:?}", a.val) == format!("{:?}", b.val)
        }
        _ => false,
    }
}

/// Extract the operator name from an `A_Expr` (list of String nodes).
fn operator_name(name: &[Node]) -> Option<String> {
    let first = name.first()?;
    match first.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.clone()),
        _ => None,
    }
}

/// Extract the relation name from a `RangeVar`.
fn relname(range_var: Option<&RangeVar>) -> Option<String> {
    range_var
        .map(|rv| rv.relname.clone())
        .filter(|s| !s.is_empty())
}

/// Returns `true` when a SELECT target list contains a `*` wildcard
/// (e.g. `SELECT *` or `SELECT t.*`). pg_query represents this as a
/// `ResTarget` whose value is a `ColumnRef` containing an `A_Star` field.
fn target_list_has_star(target_list: &[Node]) -> bool {
    target_list.iter().any(|node| {
        let Some(NodeEnum::ResTarget(res)) = node.node.as_ref() else {
            return false;
        };
        let Some(val) = res.val.as_deref() else {
            return false;
        };
        let Some(NodeEnum::ColumnRef(col)) = val.node.as_ref() else {
            return false;
        };
        col.fields
            .iter()
            .any(|f| matches!(f.node.as_ref(), Some(NodeEnum::AStar(_))))
    })
}

/// Map the `remove_type` integer (ObjectType protobuf enum) to `DropObjectKind`.
/// Uses `from_i32()` rather than `TryFrom<i32>` — the pg_query protobuf enums
/// do not implement the latter.
fn drop_kind(remove_type: i32) -> DropObjectKind {
    match ObjectType::from_i32(remove_type) {
        Some(ObjectType::ObjectTable) => DropObjectKind::Table,
        Some(ObjectType::ObjectSchema) => DropObjectKind::Schema,
        Some(ObjectType::ObjectIndex) => DropObjectKind::Index,
        _ => DropObjectKind::Other,
    }
}

/// Build the AST node path string included in the block response.
fn node_path(stmt: &str, presence: WherePresence, is_nested: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::StatementKind;

    #[test]
    fn delete_without_where() {
        let parsed = parse_postgres("DELETE FROM users").unwrap();
        assert_eq!(parsed.statements[0].kind, StatementKind::Delete);
        assert_eq!(parsed.statements[0].where_presence, WherePresence::Absent);
    }

    #[test]
    fn delete_with_where() {
        let parsed = parse_postgres("DELETE FROM users WHERE id = 1").unwrap();
        assert_eq!(parsed.statements[0].where_presence, WherePresence::Present);
    }

    #[test]
    fn delete_one_equals_one() {
        let parsed = parse_postgres("DELETE FROM users WHERE 1 = 1").unwrap();
        assert_eq!(
            parsed.statements[0].where_presence,
            WherePresence::AlwaysTrue
        );
    }

    #[test]
    fn update_in_cte_without_where_is_nested() {
        let sql = "WITH x AS (UPDATE sessions SET status = 'e' RETURNING id) SELECT * FROM x";
        let parsed = parse_postgres(sql).unwrap();
        let update = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Update)
            .expect("must detect the nested UPDATE");
        assert!(update.is_nested);
        assert_eq!(update.where_presence, WherePresence::Absent);
    }

    #[test]
    fn invalid_syntax_is_parse_error() {
        assert!(parse_postgres("DELETE FORM users").is_err());
    }

    // ── SELECT attribute population (VETRO-050 / VETRO-051) ─────────────────

    #[test]
    fn select_with_limit_sets_has_limit() {
        // `SELECT 1 LIMIT 1` must record a LIMIT so VETRO-050 does not fire.
        let parsed = parse_postgres("SELECT 1 LIMIT 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.select_has_limit, "LIMIT 1 must set select_has_limit");
    }

    #[test]
    fn select_without_limit_has_no_limit() {
        let parsed = parse_postgres("SELECT id FROM users WHERE id = 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.select_has_limit);
    }

    #[test]
    fn select_star_is_detected() {
        let parsed = parse_postgres("SELECT * FROM users").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.select_is_star, "SELECT * must set select_is_star");
        assert_eq!(select.where_presence, WherePresence::Absent);
    }

    #[test]
    fn select_explicit_columns_is_not_star() {
        let parsed = parse_postgres("SELECT id, name FROM users").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.select_is_star);
    }

    #[test]
    fn select_with_where_records_presence() {
        let parsed = parse_postgres("SELECT * FROM users WHERE id = 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert_eq!(select.where_presence, WherePresence::Present);
    }

    // ── ALTER TABLE / RENAME / DROP INDEX / OR-tautology ───────────────────

    #[test]
    fn alter_table_drop_column_is_detected() {
        let parsed = parse_postgres("ALTER TABLE users DROP COLUMN email").unwrap();
        let s = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::AlterTable)
            .expect("must detect ALTER TABLE");
        assert_eq!(
            s.alter_table_kind,
            Some(crate::parser::AlterTableKind::DropColumn)
        );
    }

    #[test]
    fn alter_table_rename_is_detected() {
        let parsed = parse_postgres("ALTER TABLE users RENAME TO accounts").unwrap();
        let s = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::AlterTable)
            .expect("must detect ALTER TABLE RENAME");
        assert_eq!(
            s.alter_table_kind,
            Some(crate::parser::AlterTableKind::Rename)
        );
    }

    #[test]
    fn drop_index_if_exists_flag() {
        let with_ie = parse_postgres("DROP INDEX IF EXISTS idx_users_email").unwrap();
        assert!(with_ie.statements[0].drop_index_if_exists);
        let without_ie = parse_postgres("DROP INDEX idx_users_email").unwrap();
        assert!(!without_ie.statements[0].drop_index_if_exists);
    }

    #[test]
    fn or_tautology_is_detected() {
        let parsed = parse_postgres("SELECT * FROM users WHERE id = 1 OR 1=1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.has_or_tautology);
    }

    #[test]
    fn nested_or_tautology_is_detected() {
        let parsed = parse_postgres(
            "SELECT * FROM users WHERE status = 'active' AND (role = 'user' OR 1=1)",
        )
        .unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.has_or_tautology);
    }

    #[test]
    fn legitimate_or_is_not_tautology() {
        let parsed =
            parse_postgres("SELECT * FROM products WHERE category = 'A' OR category = 'B'")
                .unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.has_or_tautology);
    }
}
