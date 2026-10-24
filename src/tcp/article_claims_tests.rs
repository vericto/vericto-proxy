// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Public regression checks for the SQL trees and verdicts printed in the
//! PostgreSQL wire-protocol article. The external companion under
//! `examples/postgres-wire-article` covers the network behavior.

use vericto_engine::{Decision, Dialect, EnforcementPolicy, evaluate, standard_rules};

fn outcome(sql: &str) -> vericto_engine::EvaluationOutcome {
    evaluate(
        sql,
        Dialect::Postgres,
        &standard_rules(),
        &EnforcementPolicy::default(),
    )
}

fn only(code: &str, sql: &str) -> vericto_engine::EvaluationOutcome {
    let rules = standard_rules()
        .into_iter()
        .filter(|rule| rule.code == code)
        .collect::<Vec<_>>();
    evaluate(
        sql,
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
    )
}

#[test]
fn article_pg_query_trees_are_postgresql_17_7_shapes() {
    let bare = pg_query::parse("DELETE FROM orders").unwrap();
    assert_eq!(bare.protobuf.version, 170_007);
    let bare_json = serde_json::to_value(&bare.protobuf).unwrap();
    let bare_delete = &bare_json["stmts"][0]["stmt"]["node"]["DeleteStmt"];
    assert!(bare_delete.is_object(), "{bare_json}");
    assert!(bare_delete["where_clause"].is_null(), "{bare_json}");

    let filtered = pg_query::parse("DELETE FROM orders WHERE id = 1").unwrap();
    let filtered_json = serde_json::to_value(&filtered.protobuf).unwrap();
    let filtered_delete = &filtered_json["stmts"][0]["stmt"]["node"]["DeleteStmt"];
    assert!(filtered_delete.is_object(), "{filtered_json}");
    assert!(
        filtered_delete["where_clause"].is_object(),
        "{filtered_json}"
    );

    let stacked = pg_query::parse("SELECT 1; DROP TABLE users").unwrap();
    assert_eq!(stacked.protobuf.stmts.len(), 2);
}

#[test]
fn article_engine_examples_keep_their_verdicts_and_paths() {
    for sql in [
        "delete   from ORDERS",
        "/* WHERE id = 1 */ DELETE FROM orders",
        "DELETE FROM orders -- WHERE id = 1",
    ] {
        let got = outcome(sql);
        assert_eq!(got.decision, Decision::Block, "{sql}");
        assert_eq!(got.rule_code.as_deref(), Some("VERICTO-001"), "{sql}");
        assert_eq!(
            got.ast_node_path.as_deref(),
            Some("DeleteStmt > WhereClause = NULL"),
            "{sql}"
        );
    }

    assert_eq!(
        only("VERICTO-001", "DELETE FROM orders WHERE id = 1").decision,
        Decision::Allow
    );

    let literal = outcome("SELECT 'DROP TABLE users' AS note");
    assert_eq!(literal.decision, Decision::Flag);
    assert_eq!(literal.rule_code.as_deref(), Some("VERICTO-050"));
    assert!(
        !literal
            .violations
            .iter()
            .any(|violation| violation.rule_code == "VERICTO-010")
    );

    let cte = outcome("WITH gone AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM gone");
    assert_eq!(cte.rule_code.as_deref(), Some("VERICTO-001"));
    assert_eq!(
        cte.ast_node_path.as_deref(),
        Some("WithClause > DeleteStmt > WhereClause = NULL")
    );

    let tautology = outcome("SELECT id, total FROM orders WHERE user_id = 1 OR 1=1 LIMIT 50");
    assert_eq!(tautology.rule_code.as_deref(), Some("VERICTO-090"));
    assert_eq!(
        tautology.ast_node_path.as_deref(),
        Some("SelectStmt > WhereClause > BoolExpr(OR) > always_true_branch")
    );

    for sql in [
        "SELECT * FROM orders WHERE name LIKE '%' LIMIT 1",
        "SELECT * FROM orders WHERE id IS NOT NULL LIMIT 1",
        "SELECT * FROM orders WHERE NULL = NULL LIMIT 1",
        "SELECT * FROM orders WHERE 1 NOT IN (2, NULL) LIMIT 1",
    ] {
        assert_eq!(only("VERICTO-090", sql).decision, Decision::Allow, "{sql}");
    }

    let self_compare = outcome("DELETE FROM orders WHERE id = id");
    assert_eq!(self_compare.rule_code.as_deref(), Some("VERICTO-003"));

    let stacked = outcome("SELECT 1; DROP TABLE users");
    assert_eq!(stacked.rule_code.as_deref(), Some("VERICTO-010"));
    assert_eq!(
        stacked
            .violations
            .iter()
            .map(|violation| violation.rule_code.as_str())
            .collect::<Vec<_>>(),
        vec!["VERICTO-010", "VERICTO-050"]
    );
}

#[test]
fn article_determinism_and_documented_limits_are_pinned() {
    let sql = "DELETE FROM orders -- WHERE id = 1";
    let first = outcome(sql);
    for _ in 0..1_000 {
        let got = outcome(sql);
        assert_eq!(got.decision, first.decision);
        assert_eq!(got.rule_code, first.rule_code);
        assert_eq!(got.ast_node_path, first.ast_node_path);
    }

    let copy_program = outcome("COPY (SELECT 1) TO PROGRAM 'cat >/tmp/x'");
    assert_eq!(copy_program.rule_code.as_deref(), Some("VERICTO-080"));
    assert_eq!(copy_program.decision, Decision::Block);

    let copy_from_file = outcome("COPY orders FROM '/tmp/orders.csv'");
    assert_eq!(copy_from_file.rule_code.as_deref(), Some("VERICTO-061"));
    assert_eq!(copy_from_file.decision, Decision::Flag);

    let copy_to_file = outcome("COPY orders TO '/tmp/orders.csv'");
    assert_eq!(copy_to_file.decision, Decision::Allow);
    assert_eq!(copy_to_file.rule_code, None);

    let version_skew = outcome("CREATE TABLE t (a int, b int GENERATED ALWAYS AS (a * 2) VIRTUAL)");
    assert_eq!(version_skew.decision, Decision::Flag);
    assert_eq!(
        version_skew.rule_code.as_deref(),
        Some("VERICTO-PARSE-ERROR")
    );
}
