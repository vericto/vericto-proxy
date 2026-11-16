// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-only check at startup (5.2.0): can the database role this server
//! logs in as write? `execute_sql` refuses writes twice already (the statement
//! class, and a transaction that is read-only and always rolled back); a role
//! with `SELECT` only is the third line, and the one that still holds if both
//! were bypassed. The check tells whether that third line is there.
//!
//! * PostgreSQL ([`control::ROLE_CHECK`]): superuser, CREATEROLE, CREATEDB,
//!   any of INSERT/UPDATE/DELETE/TRUNCATE on a table or view, CREATE on a
//!   schema or the database, `pg_write_all_data`. A hot standby is read-only
//!   whatever the role. `default_transaction_read_only` is reported, never
//!   trusted: a session can turn it off.
//! * MySQL and MariaDB (`SHOW GRANTS`, `read_only`, `super_read_only`): any
//!   privilege that writes data or schema or administers the server. Grants
//!   through roles are not expanded, so they make the result "unverified".
//!
//! `--require-read-only` refuses to start unless the role is verified
//! read-only; otherwise a role that can write is a startup warning and a
//! `whoami` notice.

use serde_json::{Value, json};

use crate::mcp::control;
use crate::mcp::db::{BeginError, Conn};
use crate::mcp::pg::ReadLimits;

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCheck {
    /// The user the server is logged in as.
    pub user: Option<String>,
    /// `Some(true)`: it can write; `Some(false)`: it cannot; `None`: not
    /// verified (the check failed, or privileges come from roles).
    pub can_write: Option<bool>,
    /// Why it can write, or why it could not be verified.
    pub reasons: Vec<String>,
    /// Informational findings.
    pub notes: Vec<String>,
}

impl RoleCheck {
    pub fn read_only(&self) -> bool {
        self.can_write == Some(false)
    }

    pub fn unverified(reason: impl Into<String>) -> Self {
        Self {
            user: None,
            can_write: None,
            reasons: vec![reason.into()],
            notes: Vec::new(),
        }
    }

    /// The `database_role` object of `whoami` and of `credential test`.
    pub fn json(&self) -> Value {
        json!({
            "read_only": match self.can_write {
                Some(w) => Value::Bool(!w),
                None => Value::Null,
            },
            "verified": self.can_write.is_some(),
            "user": self.user,
            "reasons": self.reasons,
            "notes": self.notes,
        })
    }

    /// The notice for `whoami` and the startup log, when there is one.
    pub fn notice(&self) -> Option<Value> {
        match self.can_write {
            Some(false) => None,
            Some(true) => Some(json!({
                "code": "database_role_can_write",
                "message": format!(
                    "the database role can write ({}); execute_sql still runs reads only in a read-only transaction, but a role with SELECT only is the safer setup (docs/MCP.md, Hard mode)",
                    self.reasons.join("; ")
                ),
            })),
            None => Some(json!({
                "code": "database_role_unverified",
                "message": format!(
                    "whether the database role can write could not be verified ({})",
                    self.reasons.join("; ")
                ),
            })),
        }
    }
}

fn truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("t" | "true" | "1" | "on" | "yes")
    )
}

/// The PostgreSQL row of [`control::ROLE_CHECK`], as text.
pub fn from_postgres_row(row: &[Option<String>]) -> RoleCheck {
    let get = |i: usize| row.get(i).and_then(|v| v.as_deref());
    let mut c = RoleCheck {
        user: get(0).map(str::to_string),
        can_write: Some(false),
        reasons: Vec::new(),
        notes: Vec::new(),
    };
    if truthy(get(7)) {
        c.notes
            .push("the server is a hot standby (read replica): nothing can be written".to_string());
        return c;
    }
    for (i, why) in [
        (1, "superuser"),
        (2, "CREATEROLE (it can create a role that writes)"),
        (3, "CREATEDB"),
        (
            8,
            "INSERT, UPDATE, DELETE or TRUNCATE on at least one table or view",
        ),
        (
            9,
            "CREATE on a schema (on PostgreSQL 14 and earlier, PUBLIC has CREATE on schema public unless revoked)",
        ),
        (10, "CREATE on the database"),
        (11, "member of pg_write_all_data"),
    ] {
        if truthy(get(i)) {
            c.reasons.push(why.to_string());
        }
    }
    if truthy(get(4)) {
        c.notes.push("the role has REPLICATION".to_string());
    }
    if truthy(get(5)) {
        c.notes
            .push("the role has BYPASSRLS (row-level security does not apply to it)".to_string());
    }
    if truthy(get(6)) {
        c.notes.push(
            "default_transaction_read_only is on for this role; a session can turn it off, so it is not counted"
                .to_string(),
        );
    }
    if !c.reasons.is_empty() {
        c.can_write = Some(true);
    }
    c
}

/// MySQL privileges that write data or schema, or administer the server.
const MYSQL_WRITE_PRIVILEGES: &[&str] = &[
    "ALL",
    "ALL PRIVILEGES",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DELETE HISTORY",
    "CREATE",
    "DROP",
    "ALTER",
    "INDEX",
    "CREATE VIEW",
    "CREATE ROUTINE",
    "ALTER ROUTINE",
    "CREATE TABLESPACE",
    "EVENT",
    "TRIGGER",
    "FILE",
    "SUPER",
    "CREATE USER",
    "CREATE ROLE",
    "DROP ROLE",
    "RELOAD",
    "SHUTDOWN",
    "PROXY",
    "SET USER",
    "SET_USER_ID",
    "SET_ANY_DEFINER",
    "SYSTEM_USER",
];

/// Privileges that let a client write on a `read_only` server.
const MYSQL_BYPASS_READ_ONLY: &[&str] = &["ALL", "ALL PRIVILEGES", "SUPER", "CONNECTION_ADMIN"];

/// One `SHOW GRANTS` line: the privileges, or `None` for a role grant
/// (`GRANT `r`@`%` TO …`), and whether it carries `WITH GRANT OPTION`.
pub fn parse_grant(line: &str) -> Option<(Vec<String>, bool)> {
    let rest = line.trim().strip_prefix("GRANT ")?;
    let upper = rest.to_ascii_uppercase();
    let on = upper.find(" ON ")?;
    let mut privileges = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in upper[..on].chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                privileges.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        if depth == 0 && ch != ')' {
            cur.push(ch);
        }
    }
    privileges.push(cur.trim().to_string());
    // `SELECT (a, b)` → `SELECT`.
    let privileges = privileges
        .into_iter()
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|p| !p.is_empty())
        .collect();
    Some((privileges, upper.contains("WITH GRANT OPTION")))
}

/// The MySQL check from `SHOW GRANTS` and the settings row (`CURRENT_USER()`,
/// `read_only`, `super_read_only`).
pub fn from_mysql(grants: &[String], settings: &[Option<String>]) -> RoleCheck {
    let get = |i: usize| settings.get(i).and_then(|v| v.as_deref());
    let mut c = RoleCheck {
        user: get(0).map(str::to_string),
        can_write: Some(false),
        reasons: Vec::new(),
        notes: Vec::new(),
    };
    if truthy(get(2)) {
        c.notes
            .push("super_read_only is on: no client can write on this server".to_string());
        return c;
    }
    let mut all = Vec::new();
    let mut role_grants = false;
    for line in grants {
        match parse_grant(line) {
            Some((privs, grant_option)) => {
                if grant_option && !c.reasons.iter().any(|r| r == "WITH GRANT OPTION") {
                    c.reasons.push("WITH GRANT OPTION".to_string());
                }
                all.extend(privs);
            }
            None if line.trim_start().starts_with("GRANT ") => role_grants = true,
            None => {}
        }
    }
    all.sort();
    all.dedup();
    let writes: Vec<&String> = all
        .iter()
        .filter(|p| {
            MYSQL_WRITE_PRIVILEGES.contains(&p.as_str())
                || p.ends_with("_ADMIN")
                || p.ends_with(" ADMIN")
        })
        .collect();
    if truthy(get(1))
        && !all
            .iter()
            .any(|p| MYSQL_BYPASS_READ_ONLY.contains(&p.as_str()))
    {
        c.notes.push(
            "read_only is on and the user cannot bypass it: nothing can be written".to_string(),
        );
        return c;
    }
    if !writes.is_empty() {
        const SHOWN: usize = 8;
        let names: Vec<&str> = writes.iter().take(SHOWN).map(|s| s.as_str()).collect();
        let more = match writes.len().saturating_sub(SHOWN) {
            0 => String::new(),
            n => format!(" and {n} more"),
        };
        c.reasons
            .push(format!("privileges {}{more}", names.join(", ")));
    }
    if all.iter().any(|p| p == "CREATE TEMPORARY TABLES") {
        c.notes.push(
            "CREATE TEMPORARY TABLES (session-only tables, refused by execute_sql)".to_string(),
        );
    }
    if !c.reasons.is_empty() {
        c.can_write = Some(true);
    } else if role_grants {
        c.can_write = None;
        c.reasons.push(
            "privileges granted through roles are not inspected; grant SELECT to the user directly"
                .to_string(),
        );
    }
    c
}

/// Takes a connection from the pool and runs [`check`] on it; a connection
/// that cannot be had is an unverified result.
pub async fn check_pool(pool: &crate::mcp::pool::Pool) -> RoleCheck {
    match pool.get().await {
        Ok(mut c) => {
            let r = check(&mut c.conn).await;
            pool.put(c);
            r
        }
        Err(crate::mcp::pool::CheckoutError::Busy) => {
            RoleCheck::unverified("every database connection is busy")
        }
        Err(crate::mcp::pool::CheckoutError::Connect(e)) => RoleCheck::unverified(format!(
            "could not connect to the database ({}: {})",
            e.step, e.message
        )),
    }
}

/// Runs the check on one connection: PostgreSQL inside the read-only
/// transaction; MySQL with two text-protocol control statements.
pub async fn check(conn: &mut Conn) -> RoleCheck {
    match conn {
        Conn::Pg(_) => {
            match conn.begin_read(10_000, 2_000, None).await {
                Ok(()) => {}
                Err(BeginError::Broken) => {
                    return RoleCheck::unverified("the connection failed during the check");
                }
                Err(BeginError::Db(e)) => {
                    return RoleCheck::unverified(format!(
                        "the read-only transaction could not be opened (SQLSTATE {})",
                        e.sqlstate
                    ));
                }
            }
            let limits = ReadLimits {
                max_rows: 1,
                max_cell_bytes: 1024,
                max_result_bytes: 64 * 1024,
            };
            match conn.run_read(control::ROLE_CHECK, &[], &[], limits).await {
                Ok(o) => match (&o.error, o.rows.first()) {
                    (Some(e), _) => RoleCheck::unverified(format!(
                        "the role check failed (SQLSTATE {})",
                        e.sqlstate
                    )),
                    (None, Some(row)) => {
                        let row: Vec<Option<String>> = row
                            .iter()
                            .map(|c| {
                                c.as_ref()
                                    .map(|c| String::from_utf8_lossy(&c.bytes).into_owned())
                            })
                            .collect();
                        from_postgres_row(&row)
                    }
                    (None, None) => RoleCheck::unverified("the role is not in pg_roles"),
                },
                Err(_) => RoleCheck::unverified("the connection failed during the check"),
            }
        }
        Conn::My(c) => {
            let grants = match c.control_rows(control::MYSQL_SHOW_GRANTS).await {
                Ok(rows) => rows
                    .into_iter()
                    .filter_map(|r| r.into_iter().next().flatten())
                    .collect::<Vec<_>>(),
                Err(e) => {
                    return RoleCheck::unverified(format!(
                        "SHOW GRANTS failed ({})",
                        e.code
                            .map(|n| format!("error {n}"))
                            .unwrap_or_else(|| e.message.clone())
                    ));
                }
            };
            let q = if c.mariadb {
                control::MARIADB_READ_ONLY_SETTINGS
            } else {
                control::MYSQL_READ_ONLY_SETTINGS
            };
            let settings = match c.control_rows(q).await {
                Ok(mut rows) if !rows.is_empty() => rows.swap_remove(0),
                Ok(_) => Vec::new(),
                Err(_) => Vec::new(),
            };
            from_mysql(&grants, &settings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(v: &[&str]) -> Vec<Option<String>> {
        v.iter().map(|s| Some(s.to_string())).collect()
    }

    #[test]
    fn a_select_only_postgres_role_is_read_only() {
        let c = from_postgres_row(&row(&[
            "agent_ro", "f", "f", "f", "f", "f", "off", "f", "f", "f", "f", "f",
        ]));
        assert!(c.read_only(), "{c:?}");
        assert!(c.notice().is_none());
    }

    #[test]
    fn postgres_write_paths_are_named() {
        let c = from_postgres_row(&row(&[
            "postgres", "t", "f", "f", "f", "t", "on", "f", "t", "t", "f", "f",
        ]));
        assert_eq!(c.can_write, Some(true));
        assert!(c.reasons.iter().any(|r| r == "superuser"));
        assert!(c.reasons.iter().any(|r| r.contains("TRUNCATE")));
        assert!(c.reasons.iter().any(|r| r.contains("schema")));
        assert!(
            c.notes
                .iter()
                .any(|n| n.contains("default_transaction_read_only"))
        );
        assert_eq!(c.notice().unwrap()["code"], "database_role_can_write");
        // A standby is read-only whatever the role.
        let c = from_postgres_row(&row(&[
            "postgres", "t", "t", "t", "f", "f", "off", "t", "t", "t", "t", "t",
        ]));
        assert!(c.read_only());
    }

    #[test]
    fn mysql_grants_are_read() {
        assert_eq!(
            parse_grant("GRANT SELECT, SHOW VIEW ON `shop`.* TO `ro`@`%`"),
            Some((vec!["SELECT".into(), "SHOW VIEW".into()], false))
        );
        assert_eq!(
            parse_grant(
                "GRANT SELECT (a, b), UPDATE (c) ON `shop`.`t` TO `u`@`%` WITH GRANT OPTION"
            ),
            Some((vec!["SELECT".into(), "UPDATE".into()], true))
        );
        assert_eq!(parse_grant("GRANT `reader`@`%` TO `u`@`%`"), None);

        let ro = from_mysql(
            &[
                "GRANT USAGE ON *.* TO `ro`@`%`".into(),
                "GRANT SELECT, SHOW VIEW ON `shop`.* TO `ro`@`%`".into(),
            ],
            &row(&["ro@%", "0", "0"]),
        );
        assert!(ro.read_only(), "{ro:?}");

        let rw = from_mysql(
            &["GRANT SELECT, INSERT, UPDATE ON `shop`.* TO `app`@`%`".into()],
            &row(&["app@%", "0", "0"]),
        );
        assert_eq!(rw.can_write, Some(true));
        assert!(rw.reasons[0].contains("INSERT, UPDATE"), "{rw:?}");

        let admin = from_mysql(
            &[
                "GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION".into(),
                "GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `root`@`%`".into(),
            ],
            &row(&["root@%", "0", "0"]),
        );
        assert_eq!(admin.can_write, Some(true));

        // Read-only servers.
        assert!(
            from_mysql(
                &["GRANT ALL PRIVILEGES ON *.* TO `r`@`%`".into()],
                &row(&["r@%", "1", "1"])
            )
            .read_only()
        );
        assert!(
            from_mysql(
                &["GRANT INSERT ON *.* TO `r`@`%`".into()],
                &row(&["r@%", "1", "0"])
            )
            .read_only()
        );
        assert_eq!(
            from_mysql(
                &["GRANT SUPER, INSERT ON *.* TO `r`@`%`".into()],
                &row(&["r@%", "1", "0"])
            )
            .can_write,
            Some(true)
        );

        // Role grants cannot be verified.
        let roles = from_mysql(
            &[
                "GRANT USAGE ON *.* TO `u`@`%`".into(),
                "GRANT `app_rw`@`%` TO `u`@`%`".into(),
            ],
            &row(&["u@%", "0", "0"]),
        );
        assert_eq!(roles.can_write, None);
        assert_eq!(roles.notice().unwrap()["code"], "database_role_unverified");
    }
}
