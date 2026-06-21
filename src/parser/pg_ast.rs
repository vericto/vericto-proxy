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
    DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
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
                ..Default::default()
            });
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
                out.push(StatementInfo {
                    kind: StatementKind::Select,
                    is_nested: false,
                    ast_node_path: "SelectStmt".to_string(),
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
    range_var.map(|rv| rv.relname.clone()).filter(|s| !s.is_empty())
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
        assert_eq!(parsed.statements[0].where_presence, WherePresence::AlwaysTrue);
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
}
