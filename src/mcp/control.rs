// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

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

/// The read-only check at startup (5.2.0), PostgreSQL: one row about the
/// connected role. Columns: the user; superuser, CREATEROLE, CREATEDB,
/// REPLICATION, BYPASSRLS; `default_transaction_read_only`; a hot standby;
/// INSERT, UPDATE, DELETE or TRUNCATE on any table or view outside the system
/// schemas; CREATE on any such schema; CREATE on the database; membership of
/// `pg_write_all_data`. Runs in the read-only transaction, like any call.
pub const ROLE_CHECK: &str = "SELECT current_user::text, r.rolsuper, r.rolcreaterole, \
r.rolcreatedb, r.rolreplication, r.rolbypassrls, \
pg_catalog.current_setting('default_transaction_read_only')::text, \
pg_catalog.pg_is_in_recovery(), \
EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') \
AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%' \
AND pg_catalog.has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')), \
EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n \
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%' \
AND pg_catalog.has_schema_privilege(n.oid, 'CREATE')), \
pg_catalog.has_database_privilege(pg_catalog.current_database(), 'CREATE'), \
EXISTS (SELECT 1 FROM pg_catalog.pg_roles w \
WHERE w.rolname = 'pg_write_all_data' AND pg_catalog.pg_has_role(w.oid, 'USAGE')) \
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";

// ---------------------------------------------------------------------------
// MySQL and MariaDB (5.2.0)
// ---------------------------------------------------------------------------

/// The `sql_mode` every MySQL call pins: MySQL 8's default. What matters is
/// what it leaves out: `ANSI_QUOTES` (`"…"` stays a string, as the parser reads
/// it), `NO_BACKSLASH_ESCAPES` (`\'` stays an escaped quote) and
/// `PIPES_AS_CONCAT`, so the server reads the statement as the evaluator did.
pub const MYSQL_SQL_MODE: &str = "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,\
NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION";

/// MariaDB's default `sql_mode`, with the same modes left out.
pub const MARIADB_SQL_MODE: &str = "STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,\
NO_ENGINE_SUBSTITUTION";

/// The read-only transaction of every MySQL call. It always ends in
/// [`ROLLBACK`].
pub const MYSQL_START_READ_ONLY: &str = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";

/// The control batch sent (one text-protocol query) before a MySQL agent
/// statement: the character set, the pinned `sql_mode`, UTC, the statement
/// timeout (`max_execution_time` in ms on MySQL, `max_statement_time` in
/// seconds on MariaDB), the lock waits (whole seconds, at least 1), then the
/// read-only transaction.
pub fn mysql_read_transaction(
    mariadb: bool,
    statement_timeout_ms: u32,
    lock_timeout_ms: u32,
) -> String {
    let lock_s = lock_timeout_ms.div_ceil(1000).max(1);
    let (mode, timeout) = if mariadb {
        (
            MARIADB_SQL_MODE,
            format!(
                "max_statement_time = {}.{:03}",
                statement_timeout_ms / 1000,
                statement_timeout_ms % 1000
            ),
        )
    } else {
        (
            MYSQL_SQL_MODE,
            format!("max_execution_time = {statement_timeout_ms}"),
        )
    };
    format!(
        "SET NAMES utf8mb4; SET SESSION sql_mode = '{mode}', time_zone = '+00:00', {timeout}, \
         lock_wait_timeout = {lock_s}, innodb_lock_wait_timeout = {lock_s}; \
         SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; {MYSQL_START_READ_ONLY}"
    )
}

/// Stops the statement running on connection `id` (the client-side deadline
/// and the kill switch), from a second connection of the same user.
pub fn mysql_kill_query(id: u32) -> String {
    format!("KILL QUERY {id}")
}

/// `describe_schema`'s columns on MySQL: every column of the tables and views
/// the user can see (`information_schema` lists only what it has a privilege
/// on), outside the system databases. Params: the schema twice, the table
/// twice (`?` is positional); without a schema, the database the URL names.
pub const MYSQL_CATALOG_COLUMNS: &str = "SELECT c.TABLE_SCHEMA, c.TABLE_NAME, t.TABLE_TYPE, \
c.COLUMN_NAME, c.DATA_TYPE, c.COLUMN_TYPE, c.IS_NULLABLE, c.COLUMN_DEFAULT, c.ORDINAL_POSITION \
FROM information_schema.COLUMNS c \
JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME \
WHERE c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') \
AND ((? IS NULL AND (DATABASE() IS NULL OR c.TABLE_SCHEMA = DATABASE())) OR c.TABLE_SCHEMA = ?) \
AND (? IS NULL OR c.TABLE_NAME = ?) \
ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION \
LIMIT 5001";

/// `describe_schema`'s primary and foreign keys on MySQL, with the same
/// filters, written as PostgreSQL's `pg_get_constraintdef` writes them.
pub const MYSQL_CATALOG_KEYS: &str = "SELECT k.TABLE_SCHEMA, k.TABLE_NAME, \
IF(k.CONSTRAINT_NAME = 'PRIMARY', 'p', 'f'), k.CONSTRAINT_NAME, \
CONCAT(IF(k.CONSTRAINT_NAME = 'PRIMARY', 'PRIMARY KEY (', 'FOREIGN KEY ('), \
GROUP_CONCAT(k.COLUMN_NAME ORDER BY k.ORDINAL_POSITION SEPARATOR ', '), ')', \
IF(k.CONSTRAINT_NAME = 'PRIMARY', '', CONCAT(' REFERENCES ', MAX(k.REFERENCED_TABLE_SCHEMA), '.', \
MAX(k.REFERENCED_TABLE_NAME), '(', \
GROUP_CONCAT(k.REFERENCED_COLUMN_NAME ORDER BY k.ORDINAL_POSITION SEPARATOR ', '), ')'))) \
FROM information_schema.KEY_COLUMN_USAGE k \
WHERE (k.CONSTRAINT_NAME = 'PRIMARY' OR k.REFERENCED_TABLE_NAME IS NOT NULL) \
AND k.TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') \
AND ((? IS NULL AND (DATABASE() IS NULL OR k.TABLE_SCHEMA = DATABASE())) OR k.TABLE_SCHEMA = ?) \
AND (? IS NULL OR k.TABLE_NAME = ?) \
GROUP BY k.TABLE_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME \
ORDER BY 1, 2, 3, 4 \
LIMIT 5001";

/// The read-only check at startup, MySQL and MariaDB: the user's grants…
pub const MYSQL_SHOW_GRANTS: &str = "SHOW GRANTS";

/// …and the server's read-only settings (MySQL: `read_only`,
/// `super_read_only`).
pub const MYSQL_READ_ONLY_SETTINGS: &str =
    "SELECT CURRENT_USER(), @@GLOBAL.read_only, @@GLOBAL.super_read_only";

/// MariaDB has no `super_read_only`.
pub const MARIADB_READ_ONLY_SETTINGS: &str = "SELECT CURRENT_USER(), @@GLOBAL.read_only, 0";

/// The statement `describe_schema` asks the engine about, under an enforced
/// allowlist, to learn which columns of a table the database user may read.
/// Evaluated only: it is never sent to the database.
pub fn access_probe(mysql: bool, schema: &str, table: &str, columns: &[&str]) -> String {
    let q = |s: &str| {
        if mysql {
            format!("`{}`", s.replace('`', "``"))
        } else {
            format!("\"{}\"", s.replace('"', "\"\""))
        }
    };
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
        || text == ROLE_CHECK
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
        assert!(pg_query::parse(ROLE_CHECK).is_ok());
    }

    #[test]
    fn the_mysql_control_statements_parse_and_classify() {
        use sqlparser::dialect::MySqlDialect;
        use sqlparser::parser::Parser;
        let s = mysql_read_transaction(false, 15_000, 2_500);
        assert!(s.contains("max_execution_time = 15000"), "{s}");
        assert!(s.contains("lock_wait_timeout = 3,"), "{s}");
        assert!(s.ends_with(MYSQL_START_READ_ONLY));
        assert!(!s.contains("ANSI_QUOTES") && !s.contains("NO_BACKSLASH_ESCAPES"));
        let m = mysql_read_transaction(true, 1_500, 1);
        assert!(m.contains("max_statement_time = 1.500"), "{m}");
        assert!(m.contains("innodb_lock_wait_timeout = 1;"), "{m}");
        for q in [
            MYSQL_CATALOG_COLUMNS,
            MYSQL_CATALOG_KEYS,
            MYSQL_READ_ONLY_SETTINGS,
        ] {
            Parser::parse_sql(&MySqlDialect {}, q).unwrap_or_else(|e| panic!("{q}: {e}"));
            // The catalog statements are reads in the agent's own check.
            assert_eq!(
                crate::mcp::classify::mysql::classify(q).unwrap().class,
                crate::mcp::classify::Class::Tier(crate::mcp::classify::Tier::Read),
                "{q}"
            );
        }
        assert_eq!(mysql_kill_query(42), "KILL QUERY 42");
        assert_eq!(
            access_probe(true, "shop", "we`ird", &["a", "b"]),
            "SELECT `a`, `b` FROM `shop`.`we``ird`"
        );
    }

    /// The design's rule (§7.3): the control statements are listed in one
    /// module, and a test fails if any other literal SQL is added to the MCP
    /// code. Scans the non-test part of every file of `src/mcp` that builds or
    /// sends statements for string literals that start like SQL (classify.rs
    /// and next_steps.rs only name statement kinds in messages, readonly.rs
    /// privileges), and checks that only pg.rs encodes a query or a Parse and
    /// only mysql.rs hands a statement to the MySQL driver.
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
            if name != "mysql.rs"
                && [
                    ".query_drop(",
                    ".prep(",
                    ".exec_iter(",
                    ".query_iter(",
                    ".query(",
                ]
                .iter()
                .any(|m| code.contains(m))
            {
                offenders.push(format!(
                    "{name}: sends a MySQL statement (only mysql.rs may)"
                ));
            }
            // These name statement kinds (classify.rs, next_steps.rs) and
            // privileges (readonly.rs) in messages; they build no SQL.
            if name == "classify.rs" || name == "next_steps.rs" || name == "readonly.rs" {
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
