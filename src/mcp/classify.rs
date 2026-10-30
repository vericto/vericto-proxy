// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The statement-class check of `execute_sql` (design "MCP execution modes"
//! §8.4 and §9.1): which permission tier a PostgreSQL statement needs, computed
//! from its AST, never from what the agent declares.
//!
//! * `read`: `SELECT` (without `FOR UPDATE/SHARE` or `INTO`), a `WITH` whose
//!   parts are all reads, `VALUES`, `TABLE`, `EXPLAIN` without `ANALYZE` of a
//!   read, `SHOW`.
//! * `write`, `delete`, `ddl`: what §9.1 lists. A statement whose parts have
//!   different tiers gets the highest (`WITH d AS (DELETE …) SELECT …` is
//!   `delete`).
//! * Never through `execute_sql`: roles and privileges, extensions, functions,
//!   triggers, `COPY`, `DO`, `CALL`, `LOCK`, `VACUUM`, `SET`/`RESET`,
//!   `LISTEN`/`NOTIFY`, `PREPARE`/`EXECUTE`, transaction control, cursors, and
//!   every statement type this module does not know (fail closed).
//! * A function with side effects a `SELECT` can call (the denylist below) makes
//!   the statement "never", except `nextval`/`setval`, which are `write`.
//!
//! The walk is over the parser's full tree (serialized), not a hand-picked list
//! of fields, so a call hidden in `LIMIT`, `VALUES`, a window clause or a
//! default cannot be missed. A statement that does not parse cannot be
//! classified and is refused at every tier, whatever the parse-error policy.

use serde_json::Value;

/// The permission tiers of design §9.1, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Read,
    Write,
    Delete,
    Ddl,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Read => "read",
            Tier::Write => "write",
            Tier::Delete => "delete",
            Tier::Ddl => "ddl",
        }
    }

    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "read" => Some(Tier::Read),
            "write" => Some(Tier::Write),
            "delete" => Some(Tier::Delete),
            "ddl" => Some(Tier::Ddl),
            _ => None,
        }
    }
}

/// What a statement is, for `execute_sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// It needs this tier.
    Tier(Tier),
    /// It never runs through `execute_sql`, at any tier. The label names what
    /// it is (`SET`, `COPY`, `SELECT … FOR UPDATE`, the denied function …).
    Never(String),
}

/// The classification of one statement text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub class: Class,
    /// The command keyword (`SELECT`, `DELETE`, `CREATE TABLE` …), for messages.
    pub command: String,
    /// The `$n` placeholders, sorted and deduplicated.
    pub placeholders: Vec<i32>,
    /// The denylisted functions it calls (lowercased, last name part), if any.
    pub denied_functions: Vec<String>,
}

/// Why a text could not be classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unclassifiable {
    /// The parser could not read it.
    Parse(String),
    /// More than one statement.
    MultipleStatements(usize),
    /// Only whitespace or comments.
    Empty,
}

/// Functions with side effects (or that run SQL text or read files) that a
/// read could otherwise call: the list of design §8.4, plus the functions that
/// execute a query or read a table given as a string (they would read around
/// the evaluator, masks included). A trailing `*` is a prefix. Versioned with
/// the read-only statement-class check: change it with a CHANGELOG entry.
pub const DENIED_FUNCTIONS: &[&str] = &[
    // Sessions and server state.
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_start_backup",
    "pg_stop_backup",
    "pg_wal_replay_pause",
    "pg_wal_replay_resume",
    "pg_log_backend_memory_contexts",
    "pg_stat_reset*",
    "pg_import_system_collations",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_drop_replication_slot",
    "pg_copy_physical_replication_slot",
    "pg_copy_logical_replication_slot",
    "pg_replication_slot_advance",
    "pg_replication_origin_*",
    "pg_logical_slot_*",
    "pg_logical_emit_message",
    // Files.
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_*",
    "pg_stat_file",
    "pg_file_*",
    "pg_logdir_ls",
    // Large objects.
    "lo_*",
    "loread",
    "lowrite",
    // Other connections and SQL given as text.
    "dblink*",
    "query_to_xml*",
    "query_to_xmlschema",
    "table_to_xml*",
    "cursor_to_xml*",
    "schema_to_xml*",
    "database_to_xml*",
    "ts_stat",
    "crosstab*",
    "connectby",
    "xpath_table",
    // Settings, locks, notifications, transaction ids.
    "set_config",
    "pg_advisory_*",
    "pg_try_advisory_*",
    "pg_notify",
    "txid_*",
    "pg_current_xact_id*",
    // Sequences (allowed from `write` up, design §9.1).
    "nextval",
    "setval",
];

/// The functions of [`DENIED_FUNCTIONS`] that are `write`, not "never".
const WRITE_FUNCTIONS: &[&str] = &["nextval", "setval"];

fn denied(name: &str) -> bool {
    DENIED_FUNCTIONS.iter().any(|d| match d.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *d,
    })
}

/// Classifies `sql` (one statement, the text that would run).
pub fn classify(sql: &str) -> Result<Classified, Unclassifiable> {
    let parsed = pg_query::parse(sql).map_err(|e| Unclassifiable::Parse(e.to_string()))?;
    let stmts = &parsed.protobuf.stmts;
    match stmts.len() {
        0 => return Err(Unclassifiable::Empty),
        1 => {}
        n => return Err(Unclassifiable::MultipleStatements(n)),
    }
    let tree = serde_json::to_value(&parsed.protobuf)
        .map_err(|e| Unclassifiable::Parse(format!("the parse tree did not serialize: {e}")))?;
    let stmt = tree
        .get("stmts")
        .and_then(|s| s.get(0))
        .and_then(|s| s.get("stmt"))
        .and_then(|s| s.get("node"))
        .and_then(Value::as_object)
        .and_then(|o| o.iter().next())
        .ok_or_else(|| Unclassifiable::Parse("empty statement".to_string()))?;
    let (kind, body) = (stmt.0.as_str(), stmt.1);

    let mut facts = Facts::default();
    walk(&tree, &mut facts);

    let (base, command) = top_level(kind, body);
    let mut class = base;
    // Data-modifying parts anywhere in the tree raise the tier.
    if let Class::Tier(t) = &mut class {
        if facts.delete {
            *t = (*t).max(Tier::Delete);
        }
        if facts.write {
            *t = (*t).max(Tier::Write);
        }
        if facts.into {
            *t = (*t).max(Tier::Ddl);
        }
    }
    if facts.locking && matches!(class, Class::Tier(Tier::Read)) {
        class = Class::Never(
            "SELECT … FOR UPDATE/SHARE (a row lock has no effect in a one-statement call)"
                .to_string(),
        );
    }
    let mut denied_functions: Vec<String> =
        facts.functions.into_iter().filter(|f| denied(f)).collect();
    denied_functions.sort();
    denied_functions.dedup();
    if let Some(never) = denied_functions
        .iter()
        .find(|f| !WRITE_FUNCTIONS.contains(&f.as_str()))
    {
        class = Class::Never(format!(
            "a call to {never}, which has side effects or runs SQL given as text"
        ));
    } else if !denied_functions.is_empty()
        && let Class::Tier(t) = &mut class
    {
        *t = (*t).max(Tier::Write);
    }
    let mut placeholders = facts.params;
    placeholders.sort_unstable();
    placeholders.dedup();
    Ok(Classified {
        class,
        command,
        placeholders,
        denied_functions,
    })
}

#[derive(Default)]
struct Facts {
    write: bool,
    delete: bool,
    into: bool,
    locking: bool,
    functions: Vec<String>,
    params: Vec<i32>,
}

/// Every node of the serialized tree.
fn walk(v: &Value, facts: &mut Facts) {
    match v {
        Value::Object(map) => {
            for (key, child) in map {
                match key.as_str() {
                    "InsertStmt" | "UpdateStmt" => facts.write = true,
                    "DeleteStmt" => facts.delete = true,
                    "MergeStmt" => {
                        facts.write = true;
                        if merge_deletes(child) {
                            facts.delete = true;
                        }
                    }
                    "IntoClause" => facts.into = true,
                    // SelectStmt.into_clause is a struct field, not a node.
                    "into_clause" if !child.is_null() => facts.into = true,
                    "LockingClause" => facts.locking = true,
                    "FuncCall" => {
                        if let Some(name) = function_name(child) {
                            facts.functions.push(name);
                        }
                    }
                    "ParamRef" => {
                        if let Some(n) = child.get("number").and_then(Value::as_i64) {
                            facts.params.push(n as i32);
                        }
                    }
                    _ => {}
                }
                walk(child, facts);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| walk(i, facts)),
        _ => {}
    }
}

/// The last part of a function's name, lowercased (a quoted mixed-case name is
/// another function, so lowercasing can only add matches, never miss one).
fn function_name(call: &Value) -> Option<String> {
    let parts = call.get("funcname")?.as_array()?;
    let last = parts.last()?;
    let s = last.get("node")?.get("String")?.get("sval")?.as_str()?;
    Some(s.to_ascii_lowercase())
}

/// Whether a MERGE has a `DELETE` action (command type CMD_DELETE).
fn merge_deletes(merge: &Value) -> bool {
    // CmdType: CMD_UNKNOWN=1, CMD_SELECT=2, CMD_UPDATE=3, CMD_INSERT=4,
    // CMD_DELETE=5, CMD_MERGE=6, CMD_UTILITY=7, CMD_NOTHING=8 (pg_query 6).
    let delete = pg_query::protobuf::CmdType::CmdDelete as i64;
    merge
        .get("merge_when_clauses")
        .and_then(Value::as_array)
        .is_some_and(|clauses| {
            clauses.iter().any(|c| {
                c.get("node")
                    .and_then(|n| n.get("MergeWhenClause"))
                    .and_then(|m| m.get("command_type"))
                    .and_then(Value::as_i64)
                    == Some(delete)
            })
        })
}

/// The class of the top-level statement type, and its command keyword.
fn top_level(kind: &str, body: &Value) -> (Class, String) {
    let tier = |t: Tier, cmd: &str| (Class::Tier(t), cmd.to_string());
    let never = |cmd: &str| (Class::Never(cmd.to_string()), cmd.to_string());
    match kind {
        "SelectStmt" => {
            let values = body
                .get("values_lists")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty());
            tier(Tier::Read, if values { "VALUES" } else { "SELECT" })
        }
        "VariableShowStmt" => tier(Tier::Read, "SHOW"),
        "ExplainStmt" => {
            let analyze = body
                .get("options")
                .and_then(Value::as_array)
                .is_some_and(|opts| opts.iter().any(explain_option_executes));
            if analyze {
                return never("EXPLAIN ANALYZE (it executes the statement)");
            }
            match body
                .get("query")
                .and_then(|q| q.get("node"))
                .and_then(Value::as_object)
                .and_then(|o| o.iter().next())
            {
                Some((k, b)) => {
                    let (inner, cmd) = top_level(k, b);
                    match inner {
                        Class::Tier(Tier::Read) => tier(Tier::Read, "EXPLAIN"),
                        other => (other, format!("EXPLAIN {cmd}")),
                    }
                }
                None => never("EXPLAIN"),
            }
        }
        "InsertStmt" => tier(Tier::Write, "INSERT"),
        "UpdateStmt" => tier(Tier::Write, "UPDATE"),
        "DeleteStmt" => tier(Tier::Delete, "DELETE"),
        "MergeStmt" => {
            if merge_deletes(body) {
                tier(Tier::Delete, "MERGE")
            } else {
                tier(Tier::Write, "MERGE")
            }
        }
        "CreateStmt" => tier(Tier::Ddl, "CREATE TABLE"),
        "AlterTableStmt" => tier(Tier::Ddl, "ALTER TABLE"),
        "DropStmt" => tier(Tier::Ddl, "DROP"),
        "IndexStmt" => {
            if body.get("concurrent").and_then(Value::as_bool) == Some(true) {
                never("CREATE INDEX CONCURRENTLY (cannot run inside a transaction)")
            } else {
                tier(Tier::Ddl, "CREATE INDEX")
            }
        }
        "ViewStmt" => tier(Tier::Ddl, "CREATE VIEW"),
        "CreateTableAsStmt" => tier(Tier::Ddl, "CREATE TABLE AS"),
        "RefreshMatViewStmt" => tier(Tier::Ddl, "REFRESH MATERIALIZED VIEW"),
        "CreateSeqStmt" => tier(Tier::Ddl, "CREATE SEQUENCE"),
        "AlterSeqStmt" => tier(Tier::Ddl, "ALTER SEQUENCE"),
        "CompositeTypeStmt" | "CreateEnumStmt" | "CreateRangeStmt" => {
            tier(Tier::Ddl, "CREATE TYPE")
        }
        "AlterEnumStmt" => tier(Tier::Ddl, "ALTER TYPE"),
        "CommentStmt" => tier(Tier::Ddl, "COMMENT"),
        "TruncateStmt" => tier(Tier::Ddl, "TRUNCATE"),
        "RenameStmt" => tier(Tier::Ddl, "ALTER … RENAME"),
        "CreateSchemaStmt" => tier(Tier::Ddl, "CREATE SCHEMA"),
        "VariableSetStmt" => never("SET / RESET"),
        "CopyStmt" => never("COPY"),
        "DoStmt" => never("DO"),
        "CallStmt" => never("CALL"),
        "LockStmt" => never("LOCK"),
        "VacuumStmt" => never("VACUUM / ANALYZE"),
        "TransactionStmt" => never("transaction control (BEGIN, COMMIT, ROLLBACK, SAVEPOINT)"),
        "ListenStmt" => never("LISTEN"),
        "UnlistenStmt" => never("UNLISTEN"),
        "NotifyStmt" => never("NOTIFY"),
        "PrepareStmt" => never("PREPARE"),
        "ExecuteStmt" => never("EXECUTE"),
        "DeallocateStmt" => never("DEALLOCATE"),
        "DiscardStmt" => never("DISCARD"),
        "DeclareCursorStmt" | "FetchStmt" | "ClosePortalStmt" => never("cursors"),
        "GrantStmt" | "GrantRoleStmt" => never("GRANT / REVOKE"),
        "CreateRoleStmt" | "AlterRoleStmt" | "AlterRoleSetStmt" | "DropRoleStmt" => never("roles"),
        "CreateExtensionStmt" | "AlterExtensionStmt" | "AlterExtensionContentsStmt" => {
            never("extensions")
        }
        "CreateFunctionStmt" | "AlterFunctionStmt" => never("functions and procedures"),
        "CreateTrigStmt" | "CreateEventTrigStmt" => never("triggers"),
        "RuleStmt" => never("rules"),
        "AlterSystemStmt" => never("ALTER SYSTEM"),
        "CheckPointStmt" => never("CHECKPOINT"),
        "LoadStmt" => never("LOAD"),
        other => (
            Class::Never(format!("{other} (not a statement execute_sql runs)")),
            other.trim_end_matches("Stmt").to_string(),
        ),
    }
}

/// `ANALYZE` (any value but false/off/0) makes an EXPLAIN execute.
fn explain_option_executes(opt: &Value) -> bool {
    let Some(def) = opt.get("node").and_then(|n| n.get("DefElem")) else {
        return false;
    };
    if def.get("defname").and_then(Value::as_str) != Some("analyze") {
        return false;
    }
    let Some(arg) = def.get("arg").and_then(|a| a.get("node")) else {
        return true; // EXPLAIN (ANALYZE)
    };
    let text = arg
        .get("String")
        .and_then(|s| s.get("sval"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            arg.get("Boolean").map(|b| {
                if b.get("boolval").and_then(Value::as_bool) == Some(true) {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            })
        })
        .or_else(|| {
            arg.get("Integer").map(|i| {
                i.get("ival")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    .to_string()
            })
        });
    !matches!(text.as_deref(), Some("false" | "off" | "0" | "no"))
}

/// The number of statements in `sql` for the "one statement per call" check,
/// also for text the parser cannot read: the parser's split when it parses,
/// otherwise the scanner's tokens (strings, quoted identifiers, dollar quotes
/// and comments are one token each), counting the segments between `;` that
/// hold anything but comments. Text the scanner cannot read counts as one.
pub fn statement_count(sql: &str) -> usize {
    if let Ok(parts) = pg_query::split_with_parser(sql) {
        return parts.iter().filter(|p| !p.trim().is_empty()).count();
    }
    let Ok(scan) = pg_query::scan(sql) else {
        return 1;
    };
    use pg_query::protobuf::Token;
    let mut count = 0;
    let mut segment_has_code = false;
    for t in &scan.tokens {
        match Token::try_from(t.token) {
            Ok(Token::Ascii59) => {
                count += usize::from(segment_has_code);
                segment_has_code = false;
            }
            Ok(Token::SqlComment | Token::CComment) => {}
            _ => segment_has_code = true,
        }
    }
    (count + usize::from(segment_has_code)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(sql: &str) -> Class {
        classify(sql)
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"))
            .class
    }

    #[test]
    fn reads_are_read() {
        for sql in [
            "SELECT 1",
            "select id, email from users where id = $1",
            "WITH a AS (SELECT 1) SELECT * FROM a",
            "VALUES (1), (2)",
            "TABLE users",
            "EXPLAIN SELECT * FROM users",
            "EXPLAIN (ANALYZE false) SELECT 1",
            "EXPLAIN (COSTS off, FORMAT json) SELECT 1",
            "SHOW search_path",
            "SELECT * FROM a UNION SELECT * FROM b",
            "SELECT count(*) FROM (SELECT 1) s",
            "SELECT 1;",
            "-- a comment\nSELECT 1 /* another */",
        ] {
            assert_eq!(tier(sql), Class::Tier(Tier::Read), "{sql}");
        }
    }

    #[test]
    fn the_highest_part_wins() {
        assert_eq!(tier("INSERT INTO t VALUES (1)"), Class::Tier(Tier::Write));
        assert_eq!(
            tier("UPDATE t SET a = 1 WHERE id = 2"),
            Class::Tier(Tier::Write)
        );
        assert_eq!(
            tier("DELETE FROM t WHERE id = 1"),
            Class::Tier(Tier::Delete)
        );
        assert_eq!(
            tier("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"),
            Class::Tier(Tier::Delete)
        );
        assert_eq!(
            tier("WITH d AS (DELETE FROM t RETURNING *) INSERT INTO u SELECT * FROM d"),
            Class::Tier(Tier::Delete)
        );
        assert_eq!(
            tier("WITH u AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM u"),
            Class::Tier(Tier::Write)
        );
        assert_eq!(
            tier("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"),
            Class::Tier(Tier::Delete)
        );
        assert_eq!(
            tier("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1"),
            Class::Tier(Tier::Write)
        );
        assert_eq!(tier("SELECT * INTO newt FROM t"), Class::Tier(Tier::Ddl));
        assert_eq!(tier("CREATE TABLE x (a int)"), Class::Tier(Tier::Ddl));
        assert_eq!(tier("DROP TABLE x"), Class::Tier(Tier::Ddl));
        assert_eq!(tier("TRUNCATE x"), Class::Tier(Tier::Ddl));
        assert_eq!(tier("EXPLAIN DELETE FROM t"), Class::Tier(Tier::Delete));
        assert_eq!(tier("SELECT nextval('s')"), Class::Tier(Tier::Write));
    }

    #[test]
    fn never_through_execute_sql() {
        for sql in [
            "SET search_path = evil",
            "RESET ALL",
            "COPY t TO STDOUT",
            "DO $$ BEGIN END $$",
            "CALL p()",
            "LOCK TABLE t",
            "VACUUM t",
            "BEGIN",
            "COMMIT",
            "LISTEN x",
            "NOTIFY x",
            "PREPARE p AS SELECT 1",
            "EXECUTE p",
            "DISCARD ALL",
            "GRANT SELECT ON t TO u",
            "CREATE ROLE r",
            "CREATE EXTENSION dblink",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            "ALTER SYSTEM SET work_mem = '1GB'",
            "CREATE INDEX CONCURRENTLY i ON t (a)",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM (SELECT * FROM t FOR SHARE) s",
            "EXPLAIN ANALYZE SELECT 1",
            "EXPLAIN (ANALYZE) SELECT 1",
            "EXPLAIN (ANALYZE true) DELETE FROM t",
            "DECLARE c CURSOR FOR SELECT 1",
            "CHECKPOINT",
        ] {
            assert!(
                matches!(tier(sql), Class::Never(_)),
                "{sql}: {:?}",
                tier(sql)
            );
        }
    }

    #[test]
    fn side_effect_functions_are_found_anywhere() {
        for sql in [
            "SELECT pg_terminate_backend(1)",
            "SELECT pg_catalog.pg_cancel_backend(1)",
            "SELECT 1 LIMIT pg_terminate_backend(1)::int",
            "VALUES (pg_reload_conf())",
            "SELECT * FROM t ORDER BY pg_read_file('/etc/passwd')",
            "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)",
            "SELECT lo_import('/etc/passwd')",
            "SELECT set_config('search_path', 'evil', false)",
            "SELECT pg_advisory_lock(1)",
            "SELECT txid_current()",
            "SELECT query_to_xml('select ssn from people', true, false, '')",
            "SELECT table_to_xml('people', true, false, '')",
            "SELECT * FROM ts_stat('select body from tickets')",
            "WITH x AS (SELECT pg_notify('c', 'p')) SELECT * FROM x",
            "SELECT count(*) FILTER (WHERE pg_sleep(0) IS NULL AND pg_ls_dir('.') IS NOT NULL) FROM t",
            "SELECT sum(a) OVER (PARTITION BY pg_current_xact_id()::text) FROM t",
            "SELECT \"PG_TERMINATE_BACKEND\"(1)",
        ] {
            assert!(
                matches!(tier(sql), Class::Never(_)),
                "{sql}: {:?}",
                tier(sql)
            );
        }
        // Harmless built-ins stay reads.
        for sql in [
            "SELECT now(), lower('A'), pg_sleep(0)",
            "SELECT current_setting('search_path')",
            "SELECT pg_size_pretty(pg_total_relation_size('t'))",
        ] {
            assert_eq!(tier(sql), Class::Tier(Tier::Read), "{sql}");
        }
    }

    #[test]
    fn unclassifiable_text_is_reported() {
        assert!(matches!(classify("SELEC 1"), Err(Unclassifiable::Parse(_))));
        assert_eq!(
            classify("SELECT 1; SELECT 2"),
            Err(Unclassifiable::MultipleStatements(2))
        );
        assert_eq!(classify("-- nothing"), Err(Unclassifiable::Empty));
    }

    #[test]
    fn placeholders_are_collected() {
        let c = classify("SELECT * FROM t WHERE a = $2 AND b = $1 OR c = $2").unwrap();
        assert_eq!(c.placeholders, vec![1, 2]);
        let c = classify("SELECT 1 LIMIT $3").unwrap();
        assert_eq!(c.placeholders, vec![3]);
    }

    #[test]
    fn statements_are_counted_also_when_they_do_not_parse() {
        assert_eq!(statement_count("SELECT 1"), 1);
        assert_eq!(statement_count("SELECT 1;"), 1);
        assert_eq!(statement_count("SELECT 1; SELECT 2"), 2);
        assert_eq!(statement_count("SELEC 1; DROP TABLE x"), 2);
        assert_eq!(statement_count("SELECT ';' AS a"), 1);
        assert_eq!(statement_count("SELECT 1; -- trailing comment"), 1);
        assert_eq!(statement_count("SELEC 1; /* x */ ; DROP TABLE x"), 2);
        assert_eq!(statement_count("SELEC $$;$$ 1"), 1);
        assert_eq!(statement_count("SELEC 'a;b' -- ;\n"), 1);
    }
}
