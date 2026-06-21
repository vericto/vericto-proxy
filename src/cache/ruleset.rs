//! Per-workspace active ruleset cache.
//!
//! The API sends the ruleset on every request, but caching it avoids
//! recompiling the YAML conditions of custom rules on every query from the same
//! workspace. An entry is invalidated by TTL or when the ruleset version changes.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::rules::engine::Rule;

/// Default TTL for a cache entry (5 seconds), aligned with the documented
/// custom-rule propagation time (<5s).
const DEFAULT_TTL: Duration = Duration::from_secs(5);

struct CacheEntry {
    version: String,
    rules: Vec<Rule>,
    inserted_at: Instant,
}

/// Thread-safe per-workspace ruleset cache.
pub struct RulesetCache {
    inner: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl RulesetCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl: DEFAULT_TTL,
        }
    }

    /// Returns the cached ruleset if it exists, is still valid, and the version matches.
    pub fn get(&self, workspace_id: &str, version: &str) -> Option<Vec<Rule>> {
        let guard = self.inner.read().ok()?;
        let entry = guard.get(workspace_id)?;
        if entry.version != version {
            return None;
        }
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.rules.clone())
    }

    /// Inserts or updates a workspace's ruleset.
    pub fn put(&self, workspace_id: &str, version: &str, rules: Vec<Rule>) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                workspace_id.to_string(),
                CacheEntry {
                    version: version.to_string(),
                    rules,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Explicitly invalidates a workspace's entry.
    pub fn invalidate(&self, workspace_id: &str) {
        if let Ok(mut guard) = self.inner.write() {
            guard.remove(workspace_id);
        }
    }
}

impl Default for RulesetCache {
    fn default() -> Self {
        Self::new()
    }
}

// Note: `Rule` derives `Clone`, so `get` returns a copy and does not hold the
// lock during evaluation.
