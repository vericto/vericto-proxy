// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Who calls `vericto-proxy mcp` (design "MCP execution modes" §11.2).
//!
//! * **stdio**: the client that spawned the process is the only caller. Its
//!   identity is the control-plane key (`VERICTO_API_KEY`) plus the
//!   `clientInfo` the client declared at `initialize` (recorded, not verified).
//! * **Streamable HTTP**: every request carries `Authorization: Bearer …`.
//!   The key is checked locally and offline: the signed bundle's
//!   `mcp_identities` section lists, for each key allowed on the database,
//!   `{ key_id, sha256, name, principal_id, expires_at }`; the server hashes
//!   what it is shown and looks it up, so a revoked key stops at the next
//!   sync. Air-gapped (or before the control plane sends the section), the
//!   operator lists tokens in `VERICTO_MCP_AUTH_TOKENS_FILE`.
//!
//! Keys are long random values, so their SHA-256 reveals nothing usable; the
//! comparison does not stop at the first differing byte.

use std::path::Path;

use serde_json::Value;

/// One credential allowed to call this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The key's id in the control plane (`None` for a local token).
    pub key_id: Option<String>,
    pub name: Option<String>,
    pub principal_id: Option<String>,
    /// Lowercase hex SHA-256 of the full key.
    pub sha256: String,
    /// RFC 3339; a key past it is refused.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The kill-switch block that stops this key (the bundle's
    /// `identities[].kill_switch`), if any.
    pub kill_switch: Option<crate::tcp::kill_switch::KillBlock>,
}

/// Lowercase hex SHA-256 of `s`.
pub fn sha256_hex(s: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The first 12 hex digits of a key's hash: shown in `whoami`, never the key.
pub fn fingerprint(key: &str) -> String {
    sha256_hex(key.as_bytes())[..12].to_string()
}

fn eq_ct(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// A `kill_switch` entry of the `mcp` section (`{block_id, message}`).
pub fn kill_block(v: Option<&Value>) -> Option<crate::tcp::kill_switch::KillBlock> {
    let v = v.filter(|v| !v.is_null())?;
    let id = v
        .get("block_id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())?;
    let message = v
        .get("message")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())?;
    Some(crate::tcp::kill_switch::KillBlock {
        block_id: id.chars().take(64).collect(),
        target_type: "api_key".to_string(),
        message: message.chars().take(2048).collect(),
    })
}

/// The `identities` of the bundle's `mcp` section (sync-mcp.json): every
/// runtime key with `sql:read`, `key_sha256` the lowercase hex SHA-256 of the
/// key. Only sent in a signed body. A malformed entry is skipped (logged),
/// never trusted.
pub fn from_bundle(section: Option<&Value>) -> Vec<Identity> {
    let Some(raw) = section
        .and_then(|s| s.get("identities"))
        .filter(|v| !v.is_null())
    else {
        return Vec::new();
    };
    let Some(list) = raw.as_array() else {
        tracing::warn!(
            "The identities of the mcp section of /sync/rules are malformed; no key is accepted from them"
        );
        return Vec::new();
    };
    let mut out = Vec::with_capacity(list.len());
    for e in list {
        let s = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_string);
        let Some(sha) = s("key_sha256")
            .or_else(|| s("sha256"))
            .map(|h| h.to_ascii_lowercase())
        else {
            tracing::warn!("Skipping an mcp identity without key_sha256");
            continue;
        };
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            tracing::warn!("Skipping an mcp_identities entry whose sha256 is not 64 hex digits");
            continue;
        }
        let expires_at = match s("expires_at") {
            None => None,
            Some(t) => match chrono::DateTime::parse_from_rfc3339(&t) {
                Ok(t) => Some(t.with_timezone(&chrono::Utc)),
                Err(_) => {
                    tracing::warn!(
                        "Skipping an mcp_identities entry with an unreadable expires_at"
                    );
                    continue;
                }
            },
        };
        out.push(Identity {
            key_id: s("key_id"),
            name: s("name"),
            principal_id: s("principal_id"),
            sha256: sha,
            expires_at,
            kill_switch: kill_block(e.get("kill_switch")),
        });
    }
    out
}

/// Shortest token accepted in `VERICTO_MCP_AUTH_TOKENS_FILE`.
pub const MIN_TOKEN_CHARS: usize = 32;

/// `VERICTO_MCP_AUTH_TOKENS_FILE`: one token per line, either the token
/// itself (at least 32 characters) or `sha256:<64 hex>`, optionally followed
/// by whitespace and a name; `#` starts a comment.
pub fn load_tokens_file(path: &Path) -> Result<Vec<Identity>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "VERICTO_MCP_AUTH_TOKENS_FILE: cannot read {} ({})",
            path.display(),
            e.kind()
        )
    })?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let token = parts.next().unwrap_or("");
        let name = parts
            .next()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .or_else(|| Some(format!("local token {}", i + 1)));
        let sha256 = match token.strip_prefix("sha256:") {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                h.to_ascii_lowercase()
            }
            Some(_) => {
                return Err(format!(
                    "VERICTO_MCP_AUTH_TOKENS_FILE line {}: sha256: needs 64 hex digits",
                    i + 1
                ));
            }
            None if token.chars().count() >= MIN_TOKEN_CHARS => sha256_hex(token.as_bytes()),
            None => {
                return Err(format!(
                    "VERICTO_MCP_AUTH_TOKENS_FILE line {}: a token must have at least {MIN_TOKEN_CHARS} characters",
                    i + 1
                ));
            }
        };
        out.push(Identity {
            key_id: None,
            name,
            principal_id: None,
            sha256,
            expires_at: None,
            kill_switch: None,
        });
    }
    Ok(out)
}

/// The identity `token` belongs to, among `known`, if it is allowed now.
pub fn authenticate<'a>(
    token: &str,
    known: impl IntoIterator<Item = &'a Identity>,
) -> Option<Identity> {
    let hash = sha256_hex(token.as_bytes());
    let now = chrono::Utc::now();
    let mut found = None;
    // Every entry is compared, so the time does not depend on which matched.
    for id in known {
        if eq_ct(&id.sha256, &hash) && id.expires_at.is_none_or(|t| t > now) && found.is_none() {
            found = Some(id.clone());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_key_in_the_bundle_authenticates_and_an_expired_one_does_not() {
        let key = "vtro_0123456789abcdef0123456789abcdef";
        let section = json!({"version": "1", "identities": [
            {"key_id": "k1", "key_sha256": sha256_hex(key.as_bytes()), "name": "cursor-laptop", "principal_id": "p1", "kill_switch": null},
            {"key_id": "k2", "key_sha256": sha256_hex(b"vtro_old"), "expires_at": "2000-01-01T00:00:00Z"},
            {"key_id": "bad", "key_sha256": "xyz"},
            {"key_id": "k3", "key_sha256": sha256_hex(b"vtro_blocked"), "kill_switch": {"block_id": "b1", "message": "stopped"}},
        ]});
        let ids = from_bundle(Some(&section));
        assert_eq!(ids.len(), 3);
        assert_eq!(
            ids[2].kill_switch.as_ref().map(|b| b.block_id.as_str()),
            Some("b1")
        );
        let who = authenticate(key, &ids).unwrap();
        assert_eq!(who.key_id.as_deref(), Some("k1"));
        assert_eq!(who.name.as_deref(), Some("cursor-laptop"));
        assert!(authenticate("vtro_old", &ids).is_none());
        assert!(authenticate("vtro_wrong", &ids).is_none());
        assert!(from_bundle(Some(&json!({"identities": "nope"}))).is_empty());
        assert!(from_bundle(None).is_empty());
    }

    #[test]
    fn the_tokens_file_accepts_tokens_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tokens");
        let long = "a".repeat(40);
        std::fs::write(
            &p,
            format!(
                "# agents\n{long} ci-bot\nsha256:{}\n",
                sha256_hex(b"another-long-token-0123456789-abcdef")
            ),
        )
        .unwrap();
        let ids = load_tokens_file(&p).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].name.as_deref(), Some("ci-bot"));
        assert!(authenticate(&long, &ids).is_some());
        assert!(authenticate("another-long-token-0123456789-abcdef", &ids).is_some());
        std::fs::write(&p, "short\n").unwrap();
        assert!(load_tokens_file(&p).is_err());
    }

    #[test]
    fn a_fingerprint_is_not_the_key() {
        let f = fingerprint("vtro_secret_value");
        assert_eq!(f.len(), 12);
        assert!(!f.contains("secret"));
    }
}
