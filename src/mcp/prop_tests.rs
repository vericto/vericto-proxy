// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Property test of the exact-text guarantee (design §7.6): random statements
//! assembled from a corpus (reads, writes, DDL, session commands, comments,
//! strings and dollar quotes holding `;`, NUL bytes, look-alike characters,
//! placeholders) never produce a `Parse` whose text the evaluator did not
//! return for that input, never more than one `Parse` per call, and never a
//! simple query other than the control statements.

use std::sync::Arc;

use proptest::prelude::*;
use serde_json::json;

use crate::mcp::control;
use crate::mcp::fake_pg::{self, Auth, FakePg, Opts};
use crate::tcp::evaluator::TcpDecision;

const FRAGMENTS: &[&str] = &[
    "SELECT 1",
    "SELECT id, email FROM users",
    "SELECT email FROM users WHERE id = 1",
    "SELECT * FROM orders WHERE total > 10 ORDER BY id LIMIT 5",
    "WITH a AS (SELECT 1 AS x) SELECT x FROM a",
    "VALUES (1, 'a')",
    "TABLE orders",
    "EXPLAIN SELECT * FROM users",
    "SHOW search_path",
    "SELECT ';'",
    "SELECT $$ ; DROP TABLE users; $$",
    "SELECT 'it''s; fine'",
    "SELECT \"weird;name\" FROM t",
    "DELETE FROM users",
    "DELETE FROM users WHERE id = 1",
    "UPDATE users SET email = 'x' WHERE id = 1",
    "INSERT INTO users (email) VALUES ('x')",
    "DROP TABLE users",
    "TRUNCATE users",
    "SET search_path = evil",
    "COPY users TO STDOUT",
    "BEGIN",
    "COMMIT",
    "SELECT pg_terminate_backend(1)",
    "SELECT set_config('a', 'b', false)",
    "SELECT * FROM users FOR UPDATE",
    "SELEC 1",
    "SELECT 1；DROP TABLE users",
    "SELECT * FROM users WHERE id = $1",
];

const GLUE: &[&str] = &[
    "",
    " ",
    ";",
    "; ",
    ";\n",
    " -- c\n",
    " /* ; */ ",
    "\u{0}",
    "\n",
    "\t;",
    " /* x */;",
];

fn statement() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(0..FRAGMENTS.len(), 1..3),
        proptest::collection::vec(0..GLUE.len(), 0..3),
        any::<bool>(),
    )
        .prop_map(|(frags, glue, trailing)| {
            let mut s = String::new();
            for (i, f) in frags.iter().enumerate() {
                s.push_str(FRAGMENTS[*f]);
                if let Some(g) = glue.get(i) {
                    s.push_str(GLUE[*g]);
                }
            }
            if trailing {
                s.push(';');
            }
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 160, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn a_parse_only_ever_carries_what_the_evaluator_returned(sql in statement(), with_param in any::<bool>()) {
        let rt_tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt_tokio.block_on(async {
            let fake = FakePg::start(Auth::Trust).await;
            let (rt, _) = fake_pg::runtime(&fake_pg::url(&fake), fake_pg::shared_with_mask(), Opts::default());
            let caller = fake_pg::caller(&rt);
            let args = if with_param { json!({ "sql": sql, "params": ["1"] }) } else { json!({ "sql": sql }) };
            let out = crate::mcp::execute::execute_sql(&rt, &caller, &args).await;
            let parses = fake.parses();
            prop_assert!(parses.len() <= 1, "{sql:?}: {} parses", parses.len());
            for q in fake.queries() {
                prop_assert!(control::is_control(&q), "{sql:?}: non-control query {q:?}");
            }
            if let Some(sent) = parses.first() {
                let e = rt.evaluate(&sql, crate::tcp::protocol::QueryKind::Prepared, &caller, None, rt.policy_for_db_user());
                let expected = match e.decision {
                    TcpDecision::Forward { rewritten_query, .. } => rewritten_query.unwrap_or_else(|| sql.clone()),
                    TcpDecision::Block { .. } => {
                        return Err(TestCaseError::fail(format!("{sql:?}: blocked by the evaluator but sent")));
                    }
                };
                prop_assert_eq!(sent.as_slice(), expected.as_bytes(), "{:?}", sql);
                prop_assert!(!sql.contains('\0'));
                prop_assert_eq!(out.structured["status"].as_str(), Some("EXECUTED"));
                prop_assert_eq!(out.structured["executed_sql"].as_str(), Some(expected.as_str()));
            } else {
                prop_assert!(out.is_error, "{sql:?}: not run but not an error: {}", out.text);
            }
            let _ = Arc::strong_count(&rt);
            Ok(())
        })?;
    }
}
