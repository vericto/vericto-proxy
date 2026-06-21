//! Caché del ruleset activo por workspace.
//!
//! La API envía el ruleset en cada request, pero cachearlo evita recompilar las
//! condiciones YAML de las reglas custom en cada query del mismo workspace. La
//! entrada se invalida por TTL o cuando cambia la versión del ruleset.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::rules::engine::Rule;

/// TTL por defecto de una entrada de caché (5 segundos), alineado con el tiempo
/// de propagación de reglas custom documentado (<5s).
const DEFAULT_TTL: Duration = Duration::from_secs(5);

struct CacheEntry {
    version: String,
    rules: Vec<Rule>,
    inserted_at: Instant,
}

/// Caché thread-safe del ruleset por workspace.
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

    /// Devuelve el ruleset cacheado si existe, está vigente y la versión coincide.
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

    /// Inserta o actualiza el ruleset de un workspace.
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

    /// Invalida explícitamente la entrada de un workspace.
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

// Nota: `Rule` deriva `Clone`, por lo que `get` devuelve una copia y no mantiene
// el lock durante la evaluación.
