// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Database errors as the agent sees them (design "MCP execution modes" §15,
//! T5). A value can leak through an error: `SELECT 1 WHERE CAST(ssn AS int) =
//! 0` makes PostgreSQL print the value (`invalid input syntax for type
//! integer: "123-45-6789"`), and a unique violation prints the key in
//! `DETAIL`. With `VERICTO_MCP_RESULT_DETAIL=sanitized` (the default) `DETAIL`,
//! `HINT`, `WHERE` and `CONTEXT` are dropped, and every quoted part of the
//! message is redacted for the classes whose messages quote data.

use crate::mcp::config::ResultDetail;
use crate::mcp::pg::DbError;

/// SQLSTATE classes whose messages quote values: data exceptions (22),
/// integrity constraint violations (23), PL/pgSQL raise (P0), and the
/// cardinality class (21), which can quote a row.
const VALUE_CLASSES: &[&str] = &["21", "22", "23", "P0"];

/// What the agent gets of an `ErrorResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentError {
    pub sqlstate: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<String>,
}

pub fn for_agent(e: &DbError, mode: ResultDetail) -> AgentError {
    match mode {
        ResultDetail::Full => AgentError {
            sqlstate: e.sqlstate.clone(),
            message: e.message.clone(),
            detail: e.detail.clone(),
            hint: e.hint.clone(),
            position: e.position.clone(),
        },
        ResultDetail::Sanitized => {
            let class = e.sqlstate.get(..2).unwrap_or("");
            let message = if VALUE_CLASSES.contains(&class) {
                redact_quoted(&e.message)
            } else {
                e.message.clone()
            };
            AgentError {
                sqlstate: e.sqlstate.clone(),
                message: bound(&message),
                detail: None,
                hint: None,
                position: e.position.clone(),
            }
        }
    }
}

/// Every `"…"` and `'…'` part of `msg` replaced by `"…"`.
pub fn redact_quoted(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut chars = msg.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            // Skip to the matching quote (or the end).
            let mut closed = false;
            for d in chars.by_ref() {
                if d == c {
                    closed = true;
                    break;
                }
            }
            out.push(c);
            out.push('…');
            if closed {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Longest message passed on (a server message is short; this bounds a
/// raise from a function).
const MAX_MESSAGE_CHARS: usize = 1024;

fn bound(s: &str) -> String {
    if s.chars().count() <= MAX_MESSAGE_CHARS {
        return s.to_string();
    }
    let mut t: String = s.chars().take(MAX_MESSAGE_CHARS).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: &str, msg: &str) -> DbError {
        DbError {
            severity: "ERROR".into(),
            sqlstate: code.into(),
            message: msg.into(),
            detail: Some("Key (email)=(a@b.com) already exists.".into()),
            hint: Some("hint".into()),
            position: Some("12".into()),
            where_: Some("SQL function".into()),
        }
    }

    #[test]
    fn values_never_leak_through_a_sanitized_error() {
        let e = for_agent(
            &err(
                "22P02",
                "invalid input syntax for type integer: \"123-45-6789\"",
            ),
            ResultDetail::Sanitized,
        );
        assert_eq!(e.message, "invalid input syntax for type integer: \"…\"");
        assert!(e.detail.is_none() && e.hint.is_none());
        assert_eq!(e.position.as_deref(), Some("12"));
        let e = for_agent(
            &err(
                "23505",
                "duplicate key value violates unique constraint \"users_email_key\"",
            ),
            ResultDetail::Sanitized,
        );
        assert!(!e.message.contains("users_email_key"));
        assert!(e.detail.is_none());
        let e = for_agent(&err("P0001", "secret is 'hunter2"), ResultDetail::Sanitized);
        assert!(!e.message.contains("hunter2"), "{}", e.message);
    }

    #[test]
    fn other_classes_keep_their_message_and_full_keeps_everything() {
        let e = for_agent(
            &err("42P01", "relation \"orders\" does not exist"),
            ResultDetail::Sanitized,
        );
        assert_eq!(e.message, "relation \"orders\" does not exist");
        assert!(e.detail.is_none());
        let e = for_agent(&err("22P02", "x \"v\""), ResultDetail::Full);
        assert_eq!(e.message, "x \"v\"");
        assert!(e.detail.is_some());
    }
}
