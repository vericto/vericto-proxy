//! Rule evaluators against the normalized AST.
//!
//! Each built-in rule is a deterministic predicate on the detected statements.
//! Custom rules are defined in YAML and compiled to predicates on the same nodes.

use serde::Deserialize;

use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
};
use crate::rules::engine::{Rule, RuleType};

/// A violation detected by a rule.
pub struct Violation {
    pub rule_id: String,
    pub rule_code: String,
    pub ast_node_path: String,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
}

/// Evaluates a rule against the parsed query. Returns `Some(Violation)` if triggered.
pub fn evaluate_rule(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    match rule.rule_type {
        RuleType::Standard => evaluate_builtin(rule, parsed),
        RuleType::Custom => evaluate_custom(rule, parsed),
    }
}

/// Dispatches the built-in rule code to its predicate.
fn evaluate_builtin(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    let stmts = &parsed.statements;
    match rule.code.as_str() {

        // ── CRITICAL rules ─────────────────────────────────────────────────

        // VETRO-001: DELETE without WHERE clause.
        "VETRO-001" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.where_presence == WherePresence::Absent
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VETRO-003: DELETE with a trivially-true WHERE (1=1, true).
        "VETRO-003" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.where_presence == WherePresence::AlwaysTrue
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VETRO-010: DROP TABLE, DROP DATABASE, DROP SCHEMA (excludes DROP INDEX,
        // which has its own rule VETRO-013).
        "VETRO-010" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && !matches!(s.drop_object, Some(DropObjectKind::Index))
        })
        .map(|s| violation(rule, s, Some(suggest_migration()))),

        // VETRO-011: TRUNCATE TABLE.
        "VETRO-011" => find(stmts, |s| s.kind == StatementKind::Truncate)
            .map(|s| violation(rule, s, suggest_truncate(s))),

        // VETRO-012: DROP SCHEMA specifically.
        "VETRO-012" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && matches!(s.drop_object, Some(DropObjectKind::Schema))
        })
        .map(|s| violation(rule, s, Some(suggest_migration()))),

        // VETRO-030: UPDATE without WHERE — alias targeting 'primary tables'.
        // Identical predicate to VETRO-042; separate code allows independent
        // configuration per workspace (e.g. different severity or scope).
        "VETRO-030" => find(stmts, |s| {
            s.kind == StatementKind::Update && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // VETRO-042: UPDATE without WHERE clause (includes always-true WHERE).
        "VETRO-042" => find(stmts, |s| {
            s.kind == StatementKind::Update && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // ── HIGH rules ─────────────────────────────────────────────────────

        // VETRO-002: DELETE with LIMIT 0 (MySQL/SQLite). A LIMIT of 0 deletes
        // zero rows, but it is syntactically indistinguishable from a
        // misconfigured attempt to scope a DELETE.
        "VETRO-002" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.delete_limit == Some(0)
        })
        .map(|s| {
            let mut v = violation(rule, s, suggest_delete(s));
            v.ast_node_path = "DeleteStmt > LimitCount = 0".to_string();
            v
        }),

        // VETRO-013: DROP INDEX without IF EXISTS. Without IF EXISTS the
        // statement will error if the index is missing, potentially breaking
        // scripts. With IF EXISTS it is idempotent.
        "VETRO-013" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && matches!(s.drop_object, Some(DropObjectKind::Index))
                && !s.drop_index_if_exists
        })
        .map(|s| {
            let mut v = violation(rule, s, Some("DROP INDEX IF EXISTS <index_name>".to_string()));
            v.ast_node_path = "DropStmt > ObjectType = INDEX (no IF EXISTS)".to_string();
            v
        }),

        // VETRO-015: ALTER TABLE DROP COLUMN — irreversible schema change.
        "VETRO-015" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::DropColumn))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use soft-delete (nullable column) or a versioned migration tool".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > AlterTableCmd.subtype = DROP_COLUMN".to_string();
            v
        }),

        // VETRO-016: ALTER TABLE RENAME — renames a table or column, breaking
        // any code that references the old name.
        "VETRO-016" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::Rename))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use a versioned migration tool and update all code references first".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > Rename".to_string();
            v
        }),

        // VETRO-031: UPDATE without WHERE nested inside a CTE.
        "VETRO-031" => find(stmts, |s| {
            s.kind == StatementKind::Update
                && s.is_nested
                && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // VETRO-033: DELETE without WHERE in a subquery or CTE.
        "VETRO-033" => find(stmts, |s| {
            s.kind == StatementKind::Delete
                && s.is_nested
                && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VETRO-040: INSERT INTO … SELECT without a WHERE filter on the SELECT.
        // This copies every row from the source, which can be accidental.
        "VETRO-040" => find(stmts, |s| {
            s.kind == StatementKind::Insert && s.insert_has_select
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some(format!(
                    "INSERT INTO {} SELECT ... WHERE <condition> LIMIT N",
                    s.relation.as_deref().unwrap_or("{table}")
                )),
            );
            v.ast_node_path = "InsertStmt > source = SelectStmt (no WHERE)".to_string();
            v
        }),

        // VETRO-070: Use of SLEEP() or PG_SLEEP() — indicates intentional delays,
        // usually for DoS or timing-based SQL injection probing.
        "VETRO-070" => find(stmts, |s| {
            s.kind == StatementKind::FunctionCall
        })
        .map(|s| {
            let fname = s.function_name.as_deref().unwrap_or("sleep");
            let mut v = violation(rule, s, None);
            v.ast_node_path = format!("FunctionCall > {}()", fname);
            v
        }),

        // ── MEDIUM rules ───────────────────────────────────────────────────

        // VETRO-050: SELECT without LIMIT. Without table-size statistics in the
        // proxy we cannot distinguish large from small tables, so we flag all
        // unbounded SELECTs with MEDIUM severity (log-only by default).
        "VETRO-050" => find(stmts, |s| {
            s.kind == StatementKind::Select && !s.select_has_limit
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("SELECT ... WHERE <condition> LIMIT 1000".to_string()),
            );
            v.ast_node_path = "SelectStmt > LimitCount = NULL".to_string();
            v
        }),

        // VETRO-051: SELECT * without any WHERE clause.
        "VETRO-051" => find(stmts, |s| {
            s.kind == StatementKind::Select
                && s.select_is_star
                && s.where_presence == WherePresence::Absent
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("SELECT col1, col2 FROM ... WHERE <condition>".to_string()),
            );
            v.ast_node_path = "SelectStmt > TargetEntry = STAR & WhereClause = NULL".to_string();
            v
        }),

        // VETRO-060: INSERT without explicit column list. Relies on table
        // column order, which breaks on schema changes.
        "VETRO-060" => find(stmts, |s| {
            s.kind == StatementKind::Insert && !s.insert_has_columns
        })
        .map(|s| {
            let rel = s.relation.as_deref().unwrap_or("{table}");
            let mut v = violation(
                rule,
                s,
                Some(format!("INSERT INTO {rel} (col1, col2) VALUES ($1, $2)")),
            );
            v.ast_node_path = "InsertStmt > Cols = NULL".to_string();
            v
        }),

        // VETRO-061: INSERT … VALUES with more than 10,000 row tuples.
        "VETRO-061" => find(stmts, |s| {
            s.kind == StatementKind::Insert
                && s.insert_row_count.map(|n| n > 10_000).unwrap_or(false)
        })
        .map(|s| {
            let count = s.insert_row_count.unwrap_or(0);
            let mut v = violation(
                rule,
                s,
                Some("Split the batch into chunks of ≤1,000 rows with COPY or multiple INSERT statements".to_string()),
            );
            v.ast_node_path = format!("InsertStmt > ValuesList count = {count}");
            v
        }),

        // ── SQL injection ─────────────────────────────────────────────────

        // VETRO-090: SQL injection tautology — OR branch in WHERE is always true
        // (e.g. `WHERE id = $1 OR 1=1`, `WHERE name = 'x' OR 'a'='a'`).
        //
        // Zero-false-positive guarantee: no well-behaved LLM has a legitimate
        // reason to include `OR 1=1` or any OR branch with a literal tautology.
        // This pattern is exclusively a SQL injection bypass technique.
        //
        // Covers SELECT, DELETE, and UPDATE WHERE clauses.
        "VETRO-090" => find(stmts, |s| {
            matches!(
                s.kind,
                StatementKind::Select | StatementKind::Delete | StatementKind::Update
            ) && s.has_or_tautology
        })
        .map(|s| {
            let stmt_name = match s.kind {
                StatementKind::Select => "SelectStmt",
                StatementKind::Delete => "DeleteStmt",
                StatementKind::Update => "UpdateStmt",
                _ => "Stmt",
            };
            let suggestion = match s.kind {
                StatementKind::Select => "SELECT ... WHERE id = $1  -- use parameterized queries",
                StatementKind::Delete => "DELETE FROM {table} WHERE id = $1",
                _                     => "UPDATE {table} SET col = $1 WHERE id = $2",
            };
            let mut v = violation(rule, s, Some(suggestion.to_string()));
            v.ast_node_path = format!(
                "{stmt_name} > WhereClause > BoolExpr(OR) > always_true_branch"
            );
            v
        }),

        // Unknown or not-yet-implemented built-in codes: pass through.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Custom rule evaluator (YAML-defined)
// ---------------------------------------------------------------------------

/// Condition structure for a YAML-defined custom rule.
#[derive(Debug, Deserialize)]
struct CustomCondition {
    #[allow(dead_code)]
    rule: Option<String>,
    node_type: String,
    relation: Option<String>,
    where_null: Option<bool>,
}

fn evaluate_custom(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    let yaml = rule.ast_condition_yaml.as_ref()?;
    let cond: CustomCondition = serde_yaml::from_str(yaml).ok()?;

    let target_kind = match cond.node_type.as_str() {
        "DeleteStmt" => StatementKind::Delete,
        "UpdateStmt" => StatementKind::Update,
        "DropStmt" => StatementKind::Drop,
        "TruncateStmt" => StatementKind::Truncate,
        "InsertStmt" => StatementKind::Insert,
        "SelectStmt" => StatementKind::Select,
        "AlterTableStmt" => StatementKind::AlterTable,
        _ => return None,
    };

    find(&parsed.statements, |s| {
        if s.kind != target_kind {
            return false;
        }
        if let Some(rel) = &cond.relation {
            match &s.relation {
                Some(actual) if relation_matches(actual, rel) => {}
                _ => return false,
            }
        }
        if cond.where_null == Some(true) && s.where_presence == WherePresence::Present {
            return false;
        }
        true
    })
    .map(|s| violation(rule, s, None))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find<'a, F>(stmts: &'a [StatementInfo], pred: F) -> Option<&'a StatementInfo>
where
    F: Fn(&StatementInfo) -> bool,
{
    stmts.iter().find(|s| pred(s))
}

fn violation(rule: &Rule, stmt: &StatementInfo, suggestion: Option<String>) -> Violation {
    Violation {
        rule_id: rule.rule_id.clone(),
        rule_code: rule.code.clone(),
        ast_node_path: stmt.ast_node_path.clone(),
        estimated_rows_affected: None,
        suggested_safe_query: suggestion,
    }
}

fn relation_matches(actual: &str, expected: &str) -> bool {
    let normalize = |s: &str| {
        s.rsplit('.')
            .next()
            .unwrap_or(s)
            .trim_matches('"')
            .trim_matches('`')
            .to_ascii_lowercase()
    };
    normalize(actual) == normalize(expected)
}

fn rel_or_placeholder(stmt: &StatementInfo) -> String {
    stmt.relation
        .clone()
        .unwrap_or_else(|| "{table}".to_string())
}

fn suggest_delete(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "DELETE FROM {} WHERE id = $1",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_update(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "UPDATE {} SET {{col}} = $1 WHERE id = $2",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_truncate(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "DELETE FROM {} WHERE created_at < NOW() - INTERVAL '90 days'",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_migration() -> String {
    "Use a versioned migration tool (Flyway, Prisma Migrate, Alembic, Rails migrations)".to_string()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parser_for, Dialect, ParsedQuery};
    use crate::rules::engine::{Rule, RuleType, Severity};

    fn parse(sql: &str, dialect: Dialect) -> ParsedQuery {
        parser_for(dialect).parse(sql).expect("must parse")
    }

    fn make_rule(code: &str) -> Rule {
        Rule {
            rule_id: code.to_string(),
            code: code.to_string(),
            severity: Severity::Critical,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        }
    }

    // ── VETRO-001 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_001_blocks_delete_without_where() {
        let p = parse("DELETE FROM users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-001"), &p).is_some());
    }

    #[test]
    fn vetro_001_allows_delete_with_where() {
        let p = parse("DELETE FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-001"), &p).is_none());
    }

    // ── VETRO-003 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_003_blocks_delete_where_always_true() {
        let p = parse("DELETE FROM users WHERE 1 = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-003"), &p).is_some());
    }

    // ── VETRO-010 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_010_blocks_drop_table() {
        let p = parse("DROP TABLE users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-010"), &p).is_some());
    }

    #[test]
    fn vetro_010_blocks_drop_database() {
        // sqlparser represents DROP DATABASE under the generic DropStmt
        let p = parse("DROP TABLE prod", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-010"), &p).is_some());
    }

    // ── VETRO-011 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_011_blocks_truncate() {
        let p = parse("TRUNCATE TABLE orders", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-011"), &p).is_some());
    }

    // ── VETRO-012 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_012_blocks_drop_schema() {
        let p = parse("DROP SCHEMA analytics CASCADE", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-012"), &p).is_some());
    }

    // ── VETRO-013 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_013_blocks_drop_index_without_if_exists() {
        let p = parse("DROP INDEX idx_users_email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-013"), &p).is_some());
    }

    #[test]
    fn vetro_013_allows_drop_index_with_if_exists() {
        let p = parse("DROP INDEX IF EXISTS idx_users_email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-013"), &p).is_none());
    }

    // ── VETRO-015 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_015_blocks_alter_table_drop_column() {
        let p = parse("ALTER TABLE users DROP COLUMN email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-015"), &p).is_some());
    }

    // ── VETRO-016 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_016_blocks_alter_table_rename() {
        let p = parse("ALTER TABLE users RENAME TO accounts", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-016"), &p).is_some());
    }

    // ── VETRO-030 / VETRO-042 ──────────────────────────────────────────────
    #[test]
    fn vetro_042_blocks_update_without_where() {
        let p = parse("UPDATE products SET price = 0", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-042"), &p).is_some());
        assert!(evaluate_rule(&make_rule("VETRO-030"), &p).is_some());
    }

    #[test]
    fn vetro_042_allows_update_with_where() {
        let p = parse(
            "UPDATE products SET price = 0 WHERE id = 1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-042"), &p).is_none());
    }

    // ── VETRO-031 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_031_blocks_update_in_cte_without_where() {
        let sql = "WITH x AS (UPDATE sessions SET status = 'expired' RETURNING id) SELECT * FROM x";
        let p = parse(sql, Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-031"), &p).is_some());
    }

    // ── VETRO-060 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_060_blocks_insert_without_columns() {
        let p = parse("INSERT INTO users VALUES (1, 'a')", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-060"), &p).is_some());
    }

    #[test]
    fn vetro_060_allows_insert_with_columns() {
        let p = parse(
            "INSERT INTO users (id, name) VALUES (1, 'a')",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-060"), &p).is_none());
    }

    // ── VETRO-090: SQL injection tautology ─────────────────────────────────

    #[test]
    fn vetro_090_blocks_select_with_or_one_equals_one() {
        let p = parse("SELECT * FROM users WHERE id = 1 OR 1=1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_select_with_or_string_tautology() {
        let p = parse(
            "SELECT * FROM users WHERE name = 'x' OR 'a'='a'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_delete_with_or_true() {
        let p = parse(
            "DELETE FROM sessions WHERE user_id = $1 OR 1=1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_update_with_or_tautology() {
        let p = parse(
            "UPDATE users SET role = 'admin' WHERE id = 1 OR 1=1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_allows_select_with_legitimate_or() {
        // Legitimate: OR with two real conditions, neither always-true
        let p = parse(
            "SELECT * FROM products WHERE category = 'A' OR category = 'B'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_allows_select_without_where() {
        let p = parse("SELECT * FROM config", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_allows_select_with_normal_where() {
        let p = parse(
            "SELECT * FROM users WHERE id = $1 AND status = 'active'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_blocks_deeply_nested_or_tautology() {
        // Tautology buried inside AND: `a AND (b OR 1=1)` — still caught
        let p = parse(
            "SELECT * FROM users WHERE status = 'active' AND (role = 'user' OR 1=1)",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VETRO-090"), &p).is_some());
    }

    // ── VETRO-050 / VETRO-051: SELECT limit & star (Postgres path) ─────────

    #[test]
    fn vetro_050_allows_select_with_limit() {
        // Regression: `SELECT 1 LIMIT 1` was blocked because the pg_query
        // path never populated select_has_limit. It must now pass.
        let p = parse("SELECT 1 LIMIT 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-050"), &p).is_none());
    }

    #[test]
    fn vetro_050_flags_select_without_limit() {
        let p = parse("SELECT id FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-050"), &p).is_some());
    }

    #[test]
    fn vetro_051_flags_select_star_without_where() {
        let p = parse("SELECT * FROM users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-051"), &p).is_some());
    }

    #[test]
    fn vetro_051_allows_select_star_with_where() {
        let p = parse("SELECT * FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VETRO-051"), &p).is_none());
    }
}
