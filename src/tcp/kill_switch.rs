// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The agent kill switch (VERICTO-105) on the wire, since 4.18.0.
//!
//! The dashboard's "Block all statements" stops one agent, or every agent of the
//! workspace, until an owner or admin lifts it. `/sync/rules` delivers the active
//! blocks that cover this proxy's database in its `kill_switch` field:
//!
//! ```json
//! "kill_switch": {
//!   "workspace": { "block_id": "…", "target_type": "workspace", "message": "…" },
//!   "db_users":  { "<db user>": { "block_id": "…", "target_type": "db_user", "message": "…" } }
//! }
//! ```
//!
//! A session whose database user is blocked (or any session under the workspace
//! switch) has every statement refused with VERICTO-105 and the block's message,
//! the text the Runtime API answers, before anything else is evaluated and in
//! every mode (monitor mode included): `SELECT 1`, `SET`, `BEGIN`, `SET vericto.*`,
//! Bind/Execute of a statement prepared before the block, MySQL COM_STMT_EXECUTE.
//! Only protocol plumbing passes (see `WireProtocol::kill_switch_scope`). The
//! state is read again for every message, so an open session is refused from the
//! first sync that carries the block and released by the first one without it.
//!
//! The control plane keeps sending the deny-all agent-access allowlist (VERICTO-087)
//! for the same users, which is how 4.17.x and older proxies (they ignore unknown
//! fields) enforce the block. Absent field = no block: an older control plane
//! then enforces through that allowlist exactly as before.
//!
//! Parsing: each entry needs a non-empty `block_id` and `message`; a malformed
//! entry is skipped and logged as an error, never applied as "no block", and the
//! rest of the bundle (the deny-all allowlist of the same user included) applies.
//! The field is part of the body the bundle signature covers.
//!
//! Cost: `None` when no block is active, so a statement pays one atomic load and
//! an `is_none`; with blocks, one hash lookup by the session user.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use serde::Deserialize;

/// Rule code of a statement the kill switch refused (the control plane's).
pub const KILL_SWITCH_RULE_CODE: &str = "VERICTO-105";

/// Longest message accepted from the bundle, in bytes. The control plane's is a
/// few hundred; a larger one is malformed rather than sent to every client.
const MAX_MESSAGE_BYTES: usize = 2048;

/// One active block as a session is refused by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillBlock {
    pub block_id: String,
    /// `workspace` | `db_user` | `principal`: the AST path names it.
    pub target_type: String,
    /// The error text the client gets, verbatim.
    pub message: String,
}

impl KillBlock {
    /// The AST path recorded for a refusal (`KillSwitch > db_user`), as the
    /// control plane records one on its own paths.
    pub fn ast_node_path(&self) -> String {
        format!("KillSwitch > {}", self.target_type)
    }
}

/// The active blocks of the last sync. Only built when there is at least one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KillSwitch {
    workspace: Option<Arc<KillBlock>>,
    db_users: HashMap<String, Arc<KillBlock>>,
    /// The block a session whose user could not be read is refused with when
    /// only per-user blocks exist: it might be one of them (the allowlists treat
    /// such a session the same way). The one of the smallest user name, so the
    /// choice is stable.
    unknown_user: Option<Arc<KillBlock>>,
}

impl KillSwitch {
    /// The block that refuses a session of `user`: its own, else the workspace's.
    pub fn for_user(&self, user: Option<&str>) -> Option<&Arc<KillBlock>> {
        match user {
            Some(u) => self.db_users.get(u).or(self.workspace.as_ref()),
            None => self.workspace.as_ref().or(self.unknown_user.as_ref()),
        }
    }

    /// Number of blocked database users, plus one for the workspace switch.
    pub fn len(&self) -> usize {
        self.db_users.len() + usize::from(self.workspace.is_some())
    }

    /// The `kill_switch` field of a sync body. `None` for an absent or `null`
    /// field and when no valid entry is left.
    pub fn from_sync(raw: Option<serde_json::Value>) -> Option<Self> {
        let raw = raw.filter(|v| !v.is_null())?;
        let Some(section) = raw.as_object() else {
            tracing::error!(
                alert = "kill_switch_malformed",
                "Sync bundle kill_switch is not an object: ignored; the deny-all \
                 allowlists of the same bundle still block the agents (VERICTO-087)"
            );
            return None;
        };
        let mut out = KillSwitch::default();
        let mut skipped = 0usize;
        match section.get("workspace") {
            None | Some(serde_json::Value::Null) => {}
            Some(v) => match entry(v, "workspace") {
                Some(b) => out.workspace = Some(Arc::new(b)),
                None => skipped += 1,
            },
        }
        match section.get("db_users") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Object(users)) => {
                for (user, v) in users {
                    match entry(v, "db_user") {
                        Some(b) if !user.is_empty() => {
                            out.db_users.insert(user.clone(), Arc::new(b));
                        }
                        _ => skipped += 1,
                    }
                }
            }
            Some(_) => skipped += 1,
        }
        if skipped > 0 {
            tracing::error!(
                alert = "kill_switch_malformed",
                skipped,
                applied = out.len(),
                "Sync bundle kill_switch has malformed entries: skipped; the deny-all \
                 allowlists of the same bundle still block those agents (VERICTO-087)"
            );
        }
        out.unknown_user = out
            .db_users
            .iter()
            .min_by(|a, b| a.0.cmp(b.0))
            .map(|(_, b)| Arc::clone(b));
        (out.len() > 0).then_some(out)
    }
}

#[derive(Deserialize)]
struct RawEntry {
    block_id: String,
    #[serde(default)]
    target_type: Option<String>,
    message: String,
}

/// One entry, or `None` when it lacks a usable id or message.
fn entry(v: &serde_json::Value, default_target: &str) -> Option<KillBlock> {
    let e = RawEntry::deserialize(v).ok()?;
    let target_type = e
        .target_type
        .filter(|t| !t.is_empty() && t.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'))
        .unwrap_or_else(|| default_target.to_string());
    let ok = !e.block_id.trim().is_empty()
        && e.block_id.len() <= 64
        && !e.message.trim().is_empty()
        && e.message.len() <= MAX_MESSAGE_BYTES;
    ok.then_some(KillBlock {
        block_id: e.block_id,
        target_type,
        message: e.message,
    })
}

/// Shared, hot-swappable kill-switch state, swapped with the rest of a sync.
/// `None` = no active block.
pub type SharedKillSwitch = Arc<ArcSwapOption<KillSwitch>>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn block(id: &str, target: &str) -> serde_json::Value {
        json!({ "block_id": id, "target_type": target, "message": format!("Vericto blocked this query [VERICTO-105]: {id}") })
    }

    #[test]
    fn absent_null_and_empty_mean_no_block() {
        assert_eq!(KillSwitch::from_sync(None), None);
        assert_eq!(KillSwitch::from_sync(Some(serde_json::Value::Null)), None);
        assert_eq!(KillSwitch::from_sync(Some(json!({}))), None);
        assert_eq!(KillSwitch::from_sync(Some(json!({ "db_users": {} }))), None);
    }

    #[test]
    fn a_user_block_wins_over_the_workspace_switch() {
        let ks = KillSwitch::from_sync(Some(json!({
            "workspace": block("w", "workspace"),
            "db_users": { "agent": block("a", "principal") }
        })))
        .unwrap();
        assert_eq!(ks.len(), 2);
        assert_eq!(ks.for_user(Some("agent")).unwrap().block_id, "a");
        assert_eq!(
            ks.for_user(Some("agent")).unwrap().ast_node_path(),
            "KillSwitch > principal"
        );
        assert_eq!(ks.for_user(Some("other")).unwrap().block_id, "w");
        assert_eq!(ks.for_user(None).unwrap().block_id, "w");
    }

    #[test]
    fn only_the_blocked_user_is_refused_and_an_unreadable_user_is_too() {
        let ks = KillSwitch::from_sync(Some(json!({
            "db_users": { "b_agent": block("b", "db_user"), "a_agent": block("a", "db_user") }
        })))
        .unwrap();
        assert_eq!(ks.for_user(Some("b_agent")).unwrap().block_id, "b");
        assert!(ks.for_user(Some("app")).is_none());
        // Exact names: no case folding, as the allowlists.
        assert!(ks.for_user(Some("A_AGENT")).is_none());
        assert_eq!(ks.for_user(None).unwrap().block_id, "a");
    }

    #[test]
    fn a_missing_target_type_defaults_by_section() {
        let ks = KillSwitch::from_sync(Some(json!({
            "workspace": { "block_id": "w", "message": "m" },
            "db_users": { "u": { "block_id": "u1", "message": "m", "future": 1 } }
        })))
        .unwrap();
        assert_eq!(ks.for_user(None).unwrap().target_type, "workspace");
        assert_eq!(ks.for_user(Some("u")).unwrap().target_type, "db_user");
    }

    #[test]
    fn malformed_entries_are_skipped_and_the_valid_ones_kept() {
        let ks = KillSwitch::from_sync(Some(json!({
            "workspace": { "block_id": "", "message": "m" },
            "db_users": {
                "ok": block("ok", "db_user"),
                "no_message": { "block_id": "x" },
                "blank": { "block_id": "y", "message": "  " },
                "huge": { "block_id": "z", "message": "x".repeat(MAX_MESSAGE_BYTES + 1) },
                "": block("e", "db_user"),
                "not_object": 7
            }
        })))
        .unwrap();
        assert_eq!(ks.len(), 1);
        assert!(ks.for_user(Some("ok")).is_some());
        assert!(ks.for_user(Some("no_message")).is_none());
        // A malformed section as a whole: nothing applied from it.
        assert_eq!(KillSwitch::from_sync(Some(json!("block everyone"))), None);
        assert_eq!(KillSwitch::from_sync(Some(json!({ "db_users": [] }))), None);
    }
}
