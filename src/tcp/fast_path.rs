// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The verdict of a trivial statement, remembered per session (4.19.0,
//! `VERICTO_TRIVIAL_FAST_PATH`).
//!
//! `BEGIN`, `COMMIT`, `SELECT 1` and the like cost a session as much evaluation
//! as a real query (a libpg_query or sqlparser parse and the whole ruleset), 75 to
//! 80% of what such a statement costs the proxy, and an OLTP application sends two
//! of them per transaction. This is not a table of verdicts: the proxy never
//! decides a statement here. The first time a session sends one of the
//! [`ENTRIES`], the full evaluation runs as for any statement, and its decision is
//! kept with what it was reached under; the session's next occurrence of the
//! **same bytes**, under the **same** ruleset and effective policy (the same
//! `Arc`s, held by the entry so they cannot be freed and their address reused),
//! gets that decision without evaluating again. Evaluation is a pure function of
//! those inputs (no time, randomness or state), so the remembered decision is the
//! one the full path returns, under every policy configuration, including custom
//! rules, monitor mode, agent-access allowlists and sensitive columns. What is not
//! kept:
//!
//! - **Any statement whose text is not an entry**, after trimming ASCII whitespace
//!   and one trailing `;` (letters compared without regard to ASCII case). Only
//!   membership is judged on the trimmed text: the key is the statement's exact
//!   bytes, so `begin;` and `BEGIN` are evaluated, and remembered, apart. A comment,
//!   a second statement, any other whitespace or a Unicode look-alike is not an
//!   entry, and is evaluated every time.
//! - **Sessions under business policy rules** (`VERICTO_POLICY_RULES` on): a
//!   verdict there also depends on the session's declared context and on the time.
//! - **A changed ruleset or policy**: a sync, a change of the session's database or
//!   user, anything that gives the session another snapshot, misses, evaluates, and
//!   replaces what was kept (the old snapshots are released).
//!
//! The kill switch, the size limit, `SET vericto.*` and everything after the
//! decision (forwarding, telemetry, transaction state) run as before: only the
//! evaluation call is skipped. The telemetry event is built from the same decision
//! and is identical except for `latency_ms`, the evaluation time.

use std::sync::Arc;

use vericto_engine::{EnforcementPolicy, Rule};

use crate::tcp::evaluator::TcpDecision;
use crate::tcp::protocol::QueryKind;

/// The statements whose verdict a session remembers, compared after trimming
/// ASCII whitespace and one trailing `;`, without regard to ASCII case.
/// Transaction control and the connection checks of drivers and pools; `SET`
/// statements only as these exact texts (never `SET ROLE`, `SET SESSION
/// AUTHORIZATION` or `search_path`, which the engine judges per session).
pub(crate) const ENTRIES: &[&str] = &[
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "END",
    "START TRANSACTION",
    "SELECT 1",
    "SET autocommit=0",
    "SET autocommit=1",
    "SET NAMES utf8mb4",
];

/// How many distinct texts a session remembers (each a few hundred bytes).
const CAPACITY: usize = 16;

/// Whether `sql` is one of the [`ENTRIES`].
pub(crate) fn is_entry(sql: &str) -> bool {
    let t = sql.trim_matches(|c: char| c.is_ascii_whitespace());
    let t = t.strip_suffix(';').unwrap_or(t);
    let t = t.trim_end_matches(|c: char| c.is_ascii_whitespace());
    ENTRIES.iter().any(|e| e.eq_ignore_ascii_case(t))
}

/// One remembered decision and everything it was reached under.
struct Kept {
    sql: String,
    kind: QueryKind,
    rules: Arc<Vec<Rule>>,
    policy: Arc<EnforcementPolicy>,
    decision: TcpDecision,
}

/// A session's remembered decisions.
#[derive(Default)]
pub(crate) struct Verdicts {
    kept: Vec<Kept>,
}

impl Verdicts {
    /// The decision the full evaluation reached for exactly `sql` and `kind`
    /// under exactly these snapshots, if this session kept one. A miss caused by
    /// other snapshots drops every kept decision (they are all stale).
    pub(crate) fn get(
        &mut self,
        sql: &str,
        kind: QueryKind,
        rules: &Arc<Vec<Rule>>,
        policy: &Arc<EnforcementPolicy>,
    ) -> Option<&TcpDecision> {
        if self
            .kept
            .first()
            .is_some_and(|k| !Arc::ptr_eq(&k.rules, rules) || !Arc::ptr_eq(&k.policy, policy))
        {
            self.kept.clear();
            return None;
        }
        self.kept
            .iter()
            .find(|k| k.kind == kind && k.sql == sql)
            .map(|k| &k.decision)
    }

    /// Keeps `decision`, which the full evaluation reached for `sql` and `kind`
    /// under these snapshots. Only [`ENTRIES`], and at most [`CAPACITY`] texts.
    pub(crate) fn keep(
        &mut self,
        sql: &str,
        kind: QueryKind,
        rules: &Arc<Vec<Rule>>,
        policy: &Arc<EnforcementPolicy>,
        decision: &TcpDecision,
    ) {
        if !is_entry(sql) || self.kept.len() >= CAPACITY {
            return;
        }
        if self
            .kept
            .first()
            .is_some_and(|k| !Arc::ptr_eq(&k.rules, rules) || !Arc::ptr_eq(&k.policy, policy))
        {
            self.kept.clear();
        }
        if self.kept.iter().any(|k| k.kind == kind && k.sql == sql) {
            return;
        }
        self.kept.push(Kept {
            sql: sql.to_string(),
            kind,
            rules: Arc::clone(rules),
            policy: Arc::clone(policy),
            decision: decision.clone(),
        });
    }
}

/// `VERICTO_TRIVIAL_FAST_PATH`: `on` (the default, also when unset or empty) or
/// `off`, in any case. Anything else is a startup error.
pub(crate) fn enabled_from(raw: Option<&str>) -> Result<bool, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("on") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("off") => Ok(false),
        Some(v) => Err(format!(
            "VERICTO_TRIVIAL_FAST_PATH={v:?} is not supported: use `on` (the default) or `off`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_match_after_trimming_only() {
        for sql in [
            "BEGIN",
            "begin",
            "  BEGIN  ",
            "BEGIN;",
            "BEGIN ;",
            "\tCOMMIT;\n",
            "select 1",
            "SET autocommit=1",
            "START TRANSACTION",
        ] {
            assert!(is_entry(sql), "{sql:?}");
        }
        for sql in [
            "BEGIN;;",
            "BEGIN; DROP TABLE users",
            "BEGIN -- c",
            "/* c */ BEGIN",
            "BEGIN\u{00a0}",
            "BEGIN\u{200b}",
            "B\u{0130}GIN",
            "\u{0392}EGIN",
            "SELECT  1",
            "SELECT 01",
            "SELECT 1 FROM users",
            "SET ROLE admin",
            "SET SESSION AUTHORIZATION admin",
            "SET search_path TO evil",
            "SET autocommit = 1",
            "START TRANSACTION READ ONLY",
            "ROLLBACK TO SAVEPOINT a",
            "",
            ";",
        ] {
            assert!(!is_entry(sql), "{sql:?}");
        }
    }

    fn allowed() -> TcpDecision {
        TcpDecision::Forward {
            observation: None,
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    }

    /// Kept per exact text and kind, only for entries, and only while the same
    /// snapshots are in force; another snapshot drops everything.
    #[test]
    fn verdicts_are_kept_per_text_kind_and_snapshot() {
        let rules = Arc::new(crate::tcp::evaluator::default_ruleset());
        let policy = Arc::new(EnforcementPolicy::default());
        let mut v = Verdicts::default();
        assert!(v.get("BEGIN", QueryKind::Simple, &rules, &policy).is_none());
        v.keep("BEGIN", QueryKind::Simple, &rules, &policy, &allowed());
        assert!(v.get("BEGIN", QueryKind::Simple, &rules, &policy).is_some());
        assert!(
            v.get("begin", QueryKind::Simple, &rules, &policy).is_none(),
            "exact bytes"
        );
        assert!(
            v.get("BEGIN", QueryKind::Prepared, &rules, &policy)
                .is_none(),
            "per kind"
        );

        v.keep(
            "DELETE FROM users",
            QueryKind::Simple,
            &rules,
            &policy,
            &allowed(),
        );
        assert!(
            v.get("DELETE FROM users", QueryKind::Simple, &rules, &policy)
                .is_none()
        );

        // The same contents in another Arc are another snapshot.
        let other = Arc::new(EnforcementPolicy::default());
        assert!(v.get("BEGIN", QueryKind::Simple, &rules, &other).is_none());
        assert!(v.kept.is_empty(), "stale decisions are dropped");
        assert!(v.get("BEGIN", QueryKind::Simple, &rules, &policy).is_none());
    }

    #[test]
    fn at_most_capacity_texts() {
        let rules = Arc::new(Vec::new());
        let policy = Arc::new(EnforcementPolicy::default());
        let mut v = Verdicts::default();
        for i in 0..CAPACITY + 4 {
            let sql = format!("{}BEGIN", " ".repeat(i));
            v.keep(&sql, QueryKind::Simple, &rules, &policy, &allowed());
        }
        assert_eq!(v.kept.len(), CAPACITY);
    }

    #[test]
    fn the_setting_is_on_by_default_and_refuses_garbage() {
        assert_eq!(enabled_from(None), Ok(true));
        assert_eq!(enabled_from(Some(" ")), Ok(true));
        assert_eq!(enabled_from(Some("ON")), Ok(true));
        assert_eq!(enabled_from(Some("off")), Ok(false));
        assert!(enabled_from(Some("yes")).is_err());
    }
}
