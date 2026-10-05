//! On-disk copy of the last-good `/sync/rules` response.
//!
//! Without it, a proxy that restarts while the control plane is unreachable comes
//! back with only the built-in critical rules: the workspace's custom rules and its
//! enforcement policy are gone until the next successful sync. With it, the syncer
//! loads the last response it accepted before its first request, so a restart
//! during an outage resumes with the same rules and policy it had before.
//!
//! The file holds the response body exactly as the API sent it, plus its ETag. The
//! ETag is sent on the first request, so an unchanged ruleset still costs a 304.
//!
//! A cache is only reused by the same link: it records the API URL, the database id
//! and a SHA-256 fingerprint of the API key (never the key). A proxy moved to another
//! workspace or database ignores the old file instead of enforcing someone else's
//! rules until its first sync.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ControlPlaneConfig;

/// Bumped when the file layout changes; other versions are ignored, not migrated.
const FORMAT: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    format: u32,
    /// Which link wrote it (see [`link_id`]).
    link: String,
    saved_at: String,
    etag: Option<String>,
    /// The `/sync/rules` response body, verbatim.
    body: String,
}

/// A response read back from the cache.
#[derive(Debug, PartialEq, Eq)]
pub struct CachedSync {
    pub etag: Option<String>,
    pub body: String,
    pub saved_at: String,
}

/// Last-good ruleset store for one control-plane link.
pub struct RulesCache {
    path: PathBuf,
    link: String,
}

impl RulesCache {
    /// `None` when the cache is disabled (`rules_cache_path` unset).
    pub fn from_config(cfg: &ControlPlaneConfig) -> Option<Self> {
        let path = cfg.rules_cache_path.clone()?;
        Some(Self {
            path,
            link: link_id(cfg),
        })
    }

    /// The cached response, if there is one this link wrote. Never fails: a missing,
    /// unreadable or foreign file just means "no cache" (logged), and the proxy keeps
    /// the built-in ruleset until the first sync.
    pub fn load(&self) -> Option<CachedSync> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(file = %self.path.display(), "No rules cache yet");
                return None;
            }
            Err(e) => {
                tracing::warn!(file = %self.path.display(), error = %e, "Rules cache unreadable; ignoring it");
                return None;
            }
        };
        let file: CacheFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(file = %self.path.display(), error = %e, "Rules cache is not valid JSON; ignoring it");
                return None;
            }
        };
        if file.format != FORMAT {
            tracing::warn!(file = %self.path.display(), format = file.format, "Rules cache has an unknown format; ignoring it");
            return None;
        }
        if file.link != self.link {
            tracing::info!(
                file = %self.path.display(),
                "Rules cache was written for another API URL, API key or database; ignoring it"
            );
            return None;
        }
        Some(CachedSync {
            etag: file.etag,
            body: file.body,
            saved_at: file.saved_at,
        })
    }

    /// Replaces the cache with `body`. Written to a temporary file and renamed into
    /// place, so a crash mid-write leaves the previous copy, never a truncated one.
    /// Failures are logged and otherwise ignored: the cache is an optimization for
    /// restarts, and the live ruleset is already in memory.
    pub fn store(&self, etag: Option<&str>, body: &str) {
        let file = CacheFile {
            format: FORMAT,
            link: self.link.clone(),
            saved_at: chrono::Utc::now().to_rfc3339(),
            etag: etag.map(str::to_string),
            body: body.to_string(),
        };
        if let Err(e) = write_atomic(&self.path, &file) {
            tracing::warn!(file = %self.path.display(), error = %e, "Failed to write rules cache");
        }
    }
}

fn write_atomic(path: &Path, file: &CacheFile) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(file)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // The workspace's custom rules and policy are configuration, not secrets, but
    // nobody besides the proxy needs to read them.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(&bytes)?;
        f.sync_all()
    });
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Identifies the link a cache belongs to without storing the API key.
fn link_id(cfg: &ControlPlaneConfig) -> String {
    let key = ring::digest::digest(&ring::digest::SHA256, cfg.api_key.as_bytes());
    let fingerprint: String = key.as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "{}|{}|{}",
        cfg.api_url,
        cfg.database_id.as_deref().unwrap_or(""),
        fingerprint
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BufferMode;
    use std::time::Duration;

    fn cfg(path: &Path, api_key: &str, database_id: Option<&str>) -> ControlPlaneConfig {
        ControlPlaneConfig {
            api_url: "https://api.example.test".into(),
            api_key: api_key.into(),
            database_id: database_id.map(str::to_string),
            rules_sync_interval: Duration::from_secs(300),
            rules_cache_path: Some(path.to_path_buf()),
            buffer_mode: BufferMode::Memory,
            disk_spool_path: String::new(),
            memory_capacity: 10,
            batch_size: 10,
            flush_interval: Duration::from_secs(5),
        }
    }

    #[test]
    fn disabled_without_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(&dir.path().join("rules.json"), "k", None);
        c.rules_cache_path = None;
        assert!(RulesCache::from_config(&c).is_none());
    }

    #[test]
    fn round_trips_body_and_etag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("rules.json");
        let cache = RulesCache::from_config(&cfg(&path, "k1", Some("db1"))).unwrap();
        assert!(cache.load().is_none());

        cache.store(Some("\"v1\""), r#"{"version":"1","rules":[]}"#);
        let got = cache.load().unwrap();
        assert_eq!(got.etag.as_deref(), Some("\"v1\""));
        assert_eq!(got.body, r#"{"version":"1","rules":[]}"#);

        // A later store replaces it; no temporary file is left behind.
        cache.store(None, "{}");
        assert_eq!(cache.load().unwrap().body, "{}");
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn never_stores_the_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let key = "vk_live_supersecretvalue123";
        RulesCache::from_config(&cfg(&path, key, None))
            .unwrap()
            .store(None, "{}");
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(key));
    }

    #[test]
    fn ignores_a_cache_from_another_key_or_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        RulesCache::from_config(&cfg(&path, "k1", Some("db1")))
            .unwrap()
            .store(None, "{}");

        let other_key = RulesCache::from_config(&cfg(&path, "k2", Some("db1"))).unwrap();
        assert!(other_key.load().is_none());
        let other_db = RulesCache::from_config(&cfg(&path, "k1", Some("db2"))).unwrap();
        assert!(other_db.load().is_none());
        let same = RulesCache::from_config(&cfg(&path, "k1", Some("db1"))).unwrap();
        assert!(same.load().is_some());
    }

    #[test]
    fn ignores_a_corrupt_or_unknown_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let cache = RulesCache::from_config(&cfg(&path, "k", None)).unwrap();

        fs::write(&path, b"{ truncated").unwrap();
        assert!(cache.load().is_none());

        fs::write(
            &path,
            br#"{"format":99,"link":"x","saved_at":"","etag":null,"body":""}"#,
        )
        .unwrap();
        assert!(cache.load().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn is_readable_only_by_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        RulesCache::from_config(&cfg(&path, "k", None))
            .unwrap()
            .store(None, "{}");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// With the disk buffer the cache lives in the spool dir; the spool must neither
    /// read it as an event nor discard it as an unreadable one.
    #[test]
    fn the_disk_spool_leaves_the_cache_alone() {
        use crate::telemetry::queue::{DiskQueue, EventQueue};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::config::RULES_CACHE_FILE);
        RulesCache::from_config(&cfg(&path, "k", None))
            .unwrap()
            .store(None, "{}");

        let spool = DiskQueue::new(dir.path().to_string_lossy().into_owned(), 10).unwrap();
        assert!(spool.drain_batch(10).events.is_empty());
        assert!(path.exists());
    }
}
