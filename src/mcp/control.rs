// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The only SQL `vericto-proxy mcp` writes itself (design "MCP execution
//! modes" §7.3): the transaction around every call, `ROLLBACK`, and the fixed
//! catalog queries of `describe_schema`. Everything else that reaches the
//! database is the agent's statement, as the evaluator returned it.
//!
//! Numbers are formatted from validated integers and the search path from
//! validated schema names (`config::parse_search_path`), never from agent
//! input. `control_statements_are_the_only_sql_literals` below fails if SQL
//! text appears anywhere else in the module's non-test code.

/// Every agent statement runs inside this, and the transaction always ends in
/// [`ROLLBACK`]: a read that a denylist missed still cannot persist anything.
pub const BEGIN_READ_ONLY: &str = "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY";

/// How every call ends.
pub const ROLLBACK: &str = "ROLLBACK";

/// The session settings every call pins inside its transaction (`SET LOCAL`,
/// so a pooler in transaction mode cannot hand the next call a session with
/// other settings). The values are fixed: results in UTC and ISO 8601, exact
/// floats, and the string-literal rules libpg_query parses with.
const PINNED: &str = "SET LOCAL TimeZone = 'UTC'; \
SET LOCAL DateStyle = 'ISO, YMD'; \
SET LOCAL IntervalStyle = 'iso_8601'; \
SET LOCAL extra_float_digits = 3; \
SET LOCAL standard_conforming_strings = on; \
SET LOCAL bytea_output = 'hex'";

/// The control batch sent (as one simple query) before an agent statement:
/// the read-only transaction, its timeouts and the pinned settings.
pub fn read_transaction(
    statement_timeout_ms: u32,
    lock_timeout_ms: u32,
    search_path: Option<&[String]>,
) -> String {
    // The transaction may stay open only a little longer than the statement.
    let idle_ms = statement_timeout_ms.saturating_add(5_000);
    let mut s = format!(
        "{BEGIN_READ_ONLY}; SET LOCAL statement_timeout = {statement_timeout_ms}; \
         SET LOCAL lock_timeout = {lock_timeout_ms}; \
         SET LOCAL idle_in_transaction_session_timeout = {idle_ms}; {PINNED}"
    );
    if let Some(path) = search_path.filter(|p| !p.is_empty()) {
        // Quoted identifiers, `"` doubled: a name from the signed bundle (the
        // allowlist's default schema) is used as it is, never as SQL.
        let quoted: Vec<String> = path
            .iter()
            .filter(|n| !n.is_empty() && !n.contains('\0'))
            .map(|n| format!("\"{}\"", n.replace('"', "\"\"")))
            .collect();
        s.push_str("; SET LOCAL search_path = ");
        s.push_str(&quoted.join(", "));
    }
    s
}

/// `describe_schema`'s columns: one row per column of every table and view the
/// role can see (`information_schema` lists only what it has a privilege on),
/// outside the system schemas. `$1` schema, `$2` table, both optional.
pub const CATALOG_COLUMNS: &str = "SELECT c.table_schema::text, c.table_name::text, t.table_type::text, \
c.column_name::text, c.data_type::text, c.udt_name::text, c.is_nullable::text, \
c.column_default::text, c.ordinal_position::int4 \
FROM information_schema.columns c \
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema') \
AND c.table_schema NOT LIKE 'pg\\_toast%' AND c.table_schema NOT LIKE 'pg\\_temp%' \
AND ($1::text IS NULL OR c.table_schema = $1::text) \
AND ($2::text IS NULL OR c.table_name = $2::text) \
ORDER BY c.table_schema, c.table_name, c.ordinal_position \
LIMIT 5001";

/// `describe_schema`'s primary and foreign keys, with the same filters. Only
/// the keys of the tables [`CATALOG_COLUMNS`] returned are reported.
pub const CATALOG_KEYS: &str = "SELECT n.nspname::text, cl.relname::text, con.contype::text, \
con.conname::text, pg_catalog.pg_get_constraintdef(con.oid)::text \
FROM pg_catalog.pg_constraint con \
JOIN pg_catalog.pg_class cl ON cl.oid = con.conrelid \
JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace \
WHERE con.contype IN ('p', 'f') \
AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
AND ($1::text IS NULL OR n.nspname = $1::text) \
AND ($2::text IS NULL OR cl.relname = $2::text) \
ORDER BY 1, 2, 3, 4 \
LIMIT 5001";

/// The statement `describe_schema` asks the engine about, under an enforced
/// allowlist, to learn which columns of a table the database user may read.
/// Evaluated only: it is never sent to the database.
pub fn access_probe(schema: &str, table: &str, columns: &[&str]) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let list: Vec<String> = columns.iter().map(|c| q(c)).collect();
    format!("SELECT {} FROM {}.{}", list.join(", "), q(schema), q(table))
}

/// Whether `text` is one of the control statements above (any validated
/// timeouts and search path), for the "no other SQL" tests.
#[cfg(test)]
pub fn is_control(text: &str) -> bool {
    text == ROLLBACK
        || text == CATALOG_COLUMNS
        || text == CATALOG_KEYS
        || (text.starts_with(BEGIN_READ_ONLY) && text.contains(PINNED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_batch_parses_and_is_read_only() {
        let s = read_transaction(15_000, 2_000, Some(&["app".into(), "public".into()]));
        let parts = pg_query::split_with_parser(&s).unwrap();
        assert_eq!(parts.len(), 11, "{s}");
        assert!(s.starts_with(BEGIN_READ_ONLY));
        assert!(s.contains("statement_timeout = 15000"));
        assert!(s.contains("lock_timeout = 2000"));
        assert!(s.contains("idle_in_transaction_session_timeout = 20000"));
        assert!(s.ends_with("search_path = \"app\", \"public\""));
        assert!(is_control(&s));
        // A name from the bundle is an identifier, never SQL.
        let s = read_transaction(15_000, 2_000, Some(&["x\"; DROP TABLE t; --".into()]));
        assert!(
            s.ends_with("search_path = \"x\"\"; DROP TABLE t; --\""),
            "{s}"
        );
        assert_eq!(pg_query::split_with_parser(&s).unwrap().len(), 11);
        assert!(pg_query::parse(CATALOG_COLUMNS).is_ok());
        assert!(pg_query::parse(CATALOG_KEYS).is_ok());
    }

    /// The design's rule (§7.3): the control statements are listed in one
    /// module, and a test fails if any other literal SQL is added to the MCP
    /// code. Scans the non-test part of every file of `src/mcp` that builds or
    /// sends statements for string literals that start like SQL (classify.rs
    /// and next_steps.rs only name statement kinds in messages), and checks
    /// that only pg.rs encodes a query or a Parse.
    #[test]
    fn control_statements_are_the_only_sql_literals() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
        let keywords = [
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SET ",
            "SHOW ",
            "WITH ",
            "CREATE ",
            "DROP ",
            "ALTER ",
            "TRUNCATE ",
            "COPY ",
            "EXPLAIN ",
        ];
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            // control.rs itself, and the test-only modules (the fake database
            // answers statements by their text).
            if !name.ends_with(".rs")
                || name == "control.rs"
                || name == "fake_pg.rs"
                || name.ends_with("_tests.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap();
            if name != "pg.rs"
                && (code.contains("frontend::query(") || code.contains("frontend::parse("))
            {
                offenders.push(format!("{name}: encodes a statement (only pg.rs may)"));
            }
            if name == "classify.rs" || name == "next_steps.rs" {
                continue;
            }
            for (i, line) in code.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for part in line.split('"').skip(1).step_by(2) {
                    if keywords.iter().any(|k| part.starts_with(k)) {
                        offenders.push(format!("{name}:{}: {part}", i + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "SQL text outside src/mcp/control.rs: {offenders:#?}"
        );
    }
}
