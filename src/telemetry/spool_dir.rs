//! One spool directory per proxy on a shared volume (since 4.12.0,
//! `VERICTO_TELEMETRY_SPOOL_SUBDIR`).
//!
//! ## Why
//!
//! A disk spool belongs to one process: it numbers its segment files from its own
//! counter, bounds them by its own `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` and removes
//! each file when the API acknowledges it. Several replicas that mount one volume
//! at the same path (an ECS service with one EFS access point, as the Vericto
//! Enterprise kit runs three tasks) used to share one directory: each indexed the
//! others' files, sent them too (duplicates), counted them against its own bound
//! and evicted them, and two writers could pick the same segment name.
//!
//! ## Layout
//!
//! With `VERICTO_TELEMETRY_SPOOL_SUBDIR` set, a proxy spools to
//! `<VERICTO_TELEMETRY_DISK_PATH>/tasks/<name>/`, where `<name>` is the ECS task id
//! (`task`: from the ECS task metadata endpoint, or the hostname outside ECS), the
//! hostname (`hostname`), or a fixed name. The rules cache stays where it was,
//! `<VERICTO_TELEMETRY_DISK_PATH>/.rules-cache`, shared by every replica (they
//! sync the same rules; each writes it atomically under its own temporary name).
//!
//! ## Nobody's spool is orphaned for good
//!
//! A task that is stopped or replaced leaves its undelivered events in its
//! directory, and its replacement has another task id. So:
//!
//! - **Lease.** Each proxy keeps `tasks/<name>/.lease` (owner, heartbeat time),
//!   rewritten atomically every [`HEARTBEAT_EVERY`]. On a clean shutdown it is
//!   marked released.
//! - **Adoption.** At startup and every [`SCAN_EVERY`], a proxy looks at the other
//!   directories under `tasks/`. One whose lease is released, or whose heartbeat
//!   is older than `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` (default 10 minutes;
//!   without a readable lease, the directory's own mtime), is adopted: renamed into
//!   the adopter's own `adopted/` directory, and its files join the adopter's
//!   spool, oldest first, under the adopter's byte bound.
//! - **Exactly one adopter.** The claim is the rename itself: renaming a directory
//!   is atomic on a local filesystem and on NFSv4 (EFS), so when two proxies race
//!   for the same orphan, one rename succeeds and the other finds nothing to
//!   rename. Nobody ever reads a directory it did not rename into its own.
//! - **Upgrade.** Spool files left at the top of the shared directory by a proxy
//!   that did not use subdirectories are claimed one file at a time, by the same
//!   kind of rename, so each file goes to exactly one proxy.
//! - **Drained adopted directories are removed**, at the next scan.
//!
//! A proxy alive but unable to write its lease for the whole orphan window (its
//! volume unreachable for ten minutes) can have its directory adopted under it. It
//! notices at its next heartbeat, logs it and starts a fresh directory; the events
//! moved away are delivered by the adopter, and what it was sending at that moment
//! may be sent twice (the API deduplicates by event id).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::telemetry::queue::{ADOPTED_DIR, EventQueue};

/// Subdirectory of the spool path that holds one directory per proxy.
pub const TASKS_DIR: &str = "tasks";
/// The lease file inside each proxy's directory.
pub const LEASE_FILE: &str = ".lease";
/// How often a proxy rewrites its lease.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
/// How often a proxy looks for orphaned directories.
pub const SCAN_EVERY: Duration = Duration::from_secs(60);
/// Default and minimum of `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS`: well above the
/// heartbeat, so a slow write or a short volume hiccup never looks like a death.
pub const DEFAULT_ORPHAN_AFTER: Duration = Duration::from_secs(600);
const MIN_ORPHAN_SECS: u64 = 120;
/// Longest directory name taken from the environment or the host.
const MAX_NAME_CHARS: usize = 128;

/// How a proxy names its own spool directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubdirMode {
    /// One directory for the whole spool path (default; the behaviour up to 4.11).
    Off,
    /// The ECS task id, else the hostname.
    Task,
    /// The hostname.
    Hostname,
    /// This name.
    Fixed(String),
}

/// `VERICTO_TELEMETRY_SPOOL_SUBDIR` and `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubdirConfig {
    pub mode: SubdirMode,
    pub orphan_after: Duration,
}

impl SubdirConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_values(
            std::env::var("VERICTO_TELEMETRY_SPOOL_SUBDIR")
                .ok()
                .as_deref(),
            std::env::var("VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS")
                .ok()
                .as_deref(),
        )
    }

    fn from_values(subdir: Option<&str>, orphan_secs: Option<&str>) -> Result<Self, String> {
        let mode = match subdir.map(str::trim) {
            None | Some("") => SubdirMode::Off,
            Some(v) if v.eq_ignore_ascii_case("task") => SubdirMode::Task,
            Some(v) if v.eq_ignore_ascii_case("hostname") => SubdirMode::Hostname,
            Some(v) => SubdirMode::Fixed(sanitize_name(v).ok_or_else(|| {
                format!(
                    "VERICTO_TELEMETRY_SPOOL_SUBDIR={v:?} is not usable as a directory name: \
                     use `task`, `hostname`, or letters, digits, `.`, `_` and `-` (not starting with `.`)"
                )
            })?),
        };
        let orphan_after = orphan_secs
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| Duration::from_secs(s.max(MIN_ORPHAN_SECS)))
            .unwrap_or(DEFAULT_ORPHAN_AFTER);
        Ok(Self { mode, orphan_after })
    }
}

/// `raw` as a directory name: letters, digits, `.`, `_`, `-`; not hidden, not
/// `.`/`..`; at most [`MAX_NAME_CHARS`]. `None` when nothing usable remains.
pub fn sanitize_name(raw: &str) -> Option<String> {
    let name: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_NAME_CHARS)
        .collect();
    let name = name.trim_start_matches('.').to_string();
    (!name.is_empty() && name.chars().any(|c| c.is_ascii_alphanumeric())).then_some(name)
}

/// The ECS task id of this container, from the task metadata endpoint v4
/// (`ECS_CONTAINER_METADATA_URI_V4`), or `None` outside ECS or when it does not
/// answer within two seconds.
pub async fn ecs_task_id() -> Option<String> {
    let base = std::env::var("ECS_CONTAINER_METADATA_URI_V4").ok()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let body: serde_json::Value = client
        .get(format!("{}/task", base.trim_end_matches('/')))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    task_id_from_arn(body.get("TaskARN")?.as_str()?)
}

/// `arn:aws:ecs:<region>:<account>:task/<cluster>/<id>` → `<id>`.
fn task_id_from_arn(arn: &str) -> Option<String> {
    arn.rsplit('/').next().and_then(sanitize_name)
}

/// The hostname, from `HOSTNAME` or the kernel.
pub fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .and_then(|h| sanitize_name(&h))
}

/// A name for this process that is stable for its life: the ECS task id when
/// there is one, else the hostname, else a random id.
pub async fn instance_name() -> String {
    match ecs_task_id().await {
        Some(id) => id,
        None => hostname().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
    }
}

/// The name of this proxy's spool directory for `mode`; `None` for `Off`.
pub async fn resolve_name(mode: &SubdirMode, task_id: Option<&str>) -> Option<String> {
    match mode {
        SubdirMode::Off => None,
        SubdirMode::Task => Some(match task_id {
            Some(id) => id.to_string(),
            None => instance_name().await,
        }),
        SubdirMode::Hostname => Some(
            hostname()
                .or_else(|| task_id.map(str::to_string))
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        ),
        SubdirMode::Fixed(name) => Some(name.clone()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Lease {
    /// Random per process.
    owner: String,
    /// Unix seconds of the last heartbeat.
    heartbeat: i64,
    #[serde(default)]
    released: bool,
}

/// This proxy's place on a shared spool volume.
#[derive(Debug, Clone)]
pub struct SpoolLayout {
    base: PathBuf,
    tasks: PathBuf,
    own: PathBuf,
    name: String,
    owner: String,
}

/// What a scan did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanOutcome {
    pub adopted_dirs: usize,
    pub adopted_events: usize,
    pub legacy_files: usize,
}

fn unix_now(now: SystemTime) -> i64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl SpoolLayout {
    /// The layout for a proxy named `name` (already sanitized) on `base`.
    pub fn new(base: impl Into<PathBuf>, name: &str) -> Self {
        let base = base.into();
        let tasks = base.join(TASKS_DIR);
        Self {
            own: tasks.join(name),
            tasks,
            base,
            name: name.to_string(),
            owner: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// This proxy's spool directory.
    pub fn own_dir(&self) -> &Path {
        &self.own
    }

    /// Creates the directories and takes the lease. A directory under this name
    /// whose lease another live process holds (two proxies configured with the
    /// same fixed name, or a restart within the orphan window that did not shut
    /// down cleanly) is left to it: this process takes `<name>-<random>` instead,
    /// and the other directory is adopted once its lease goes stale.
    pub fn prepare(mut self, orphan_after: Duration) -> std::io::Result<Self> {
        create_private_dir(&self.tasks)?;
        if let Some(lease) = read_lease(&self.own) {
            let age = unix_now(SystemTime::now()).saturating_sub(lease.heartbeat);
            if !lease.released && age < orphan_after.as_secs() as i64 {
                let suffix = &self.owner[..8];
                let name = format!("{}-{suffix}", self.name);
                tracing::warn!(
                    dir = %self.own.display(),
                    heartbeat_age_secs = age,
                    using = %name,
                    "Telemetry spool directory is leased by another process; using a new one (the other is adopted once its lease goes stale)"
                );
                self.own = self.tasks.join(&name);
                self.name = name;
            }
        }
        create_private_dir(&self.own)?;
        self.write_lease(false, SystemTime::now())?;
        Ok(self)
    }

    fn write_lease(&self, released: bool, now: SystemTime) -> std::io::Result<()> {
        let lease = Lease {
            owner: self.owner.clone(),
            heartbeat: unix_now(now),
            released,
        };
        let tmp = self
            .own
            .join(format!("{LEASE_FILE}.{}.tmp", &self.owner[..8]));
        let body = serde_json::to_vec(&lease).map_err(std::io::Error::other)?;
        let written = create_private_file(&tmp)
            .and_then(|mut f| {
                f.write_all(&body)?;
                f.sync_all()
            })
            .and_then(|()| fs::rename(&tmp, self.own.join(LEASE_FILE)));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    /// Rewrites the lease. If the directory was adopted by another proxy (this
    /// one looked dead for the whole orphan window), says so once and starts a
    /// fresh directory under the same name: what was moved is delivered by the
    /// adopter.
    pub fn heartbeat(&self, now: SystemTime) -> std::io::Result<()> {
        let held = read_lease(&self.own).is_some_and(|l| l.owner == self.owner);
        if !held {
            tracing::error!(
                dir = %self.own.display(),
                "Telemetry spool directory was adopted by another proxy (this one missed its lease for the whole orphan window); continuing in a fresh directory, the adopter delivers what was moved"
            );
            create_private_dir(&self.own)?;
        }
        self.write_lease(false, now)
    }

    /// Marks the lease released, so another proxy adopts what is left at its next
    /// scan instead of waiting for the orphan window. At shutdown, after the flush.
    pub fn release(&self) {
        if let Err(e) = self.write_lease(true, SystemTime::now()) {
            tracing::warn!(dir = %self.own.display(), error = %e, "Could not release the telemetry spool lease; another proxy adopts the directory once the lease goes stale");
        }
    }

    /// Directories under `tasks/` other than this one's that nobody holds: lease
    /// released or stale, or no readable lease and no change for `orphan_after`.
    fn orphans(&self, now: SystemTime, orphan_after: Duration) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.tasks) else {
            return Vec::new();
        };
        let horizon = unix_now(now) - orphan_after.as_secs() as i64;
        let mut out: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|name| !name.starts_with('.') && *name != self.name)
            .filter(|name| {
                let dir = self.tasks.join(name);
                match read_lease(&dir) {
                    Some(lease) => lease.released || lease.heartbeat < horizon,
                    None => {
                        // Without a readable lease: the newest of the lease file's
                        // and the directory's mtime (a writer touches the latter).
                        let touched = [dir.join(LEASE_FILE), dir.clone()]
                            .iter()
                            .filter_map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
                            .max();
                        touched.is_some_and(|t| unix_now(t) < horizon)
                    }
                }
            })
            .collect();
        out.sort();
        out
    }

    /// Where an adopted directory goes: `<own>/adopted/<name>-<unix secs>`, a name
    /// not taken yet.
    fn adoption_target(&self, name: &str, now: SystemTime) -> std::io::Result<PathBuf> {
        let adopted = self.own.join(ADOPTED_DIR);
        create_private_dir(&adopted)?;
        let stamp = unix_now(now);
        let mut target = adopted.join(format!("{name}-{stamp}"));
        let mut n = 1;
        while target.exists() {
            target = adopted.join(format!("{name}-{stamp}-{n}"));
            n += 1;
        }
        Ok(target)
    }

    /// Claims the orphan `name` by renaming it into this proxy's `adopted/`.
    /// `Ok(None)` when another proxy renamed it first.
    fn claim(&self, name: &str, now: SystemTime) -> std::io::Result<Option<PathBuf>> {
        let target = self.adoption_target(name, now)?;
        match fs::rename(self.tasks.join(name), &target) {
            Ok(()) => {
                clean_leftovers(&target);
                Ok(Some(target))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Spool files at the top of the shared path, written by a proxy that did not
    /// use subdirectories: moved one by one into a fresh `adopted/legacy-<unix>`.
    /// Each rename is the claim of that one file. `Ok(None)` when there were none.
    fn claim_legacy(&self, now: SystemTime) -> std::io::Result<Option<(PathBuf, usize)>> {
        let files: Vec<PathBuf> = fs::read_dir(&self.base)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(is_spool_file_name)
            })
            .collect();
        if files.is_empty() {
            return Ok(None);
        }
        let target = self.adoption_target("legacy", now)?;
        create_private_dir(&target)?;
        let mut moved = 0;
        for file in files {
            let Some(name) = file.file_name() else {
                continue;
            };
            match fs::rename(&file, target.join(name)) {
                Ok(()) => moved += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(file = %file.display(), error = %e, "Could not claim a telemetry spool file from the shared directory")
                }
            }
        }
        if moved == 0 {
            let _ = fs::remove_dir(&target);
            return Ok(None);
        }
        Ok(Some((target, moved)))
    }

    /// One scan: claims the orphans and the shared directory's own files, hands
    /// them to `queue`, and removes adopted directories that are fully delivered.
    pub fn scan(
        &self,
        queue: &dyn EventQueue,
        now: SystemTime,
        orphan_after: Duration,
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        self.prune_adopted();
        let mut claimed = Vec::new();
        match self.claim_legacy(now) {
            Ok(Some((dir, files))) => {
                outcome.legacy_files = files;
                claimed.push(dir);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(dir = %self.base.display(), error = %e, "Could not look for telemetry spool files in the shared directory")
            }
        }
        for name in self.orphans(now, orphan_after) {
            match self.claim(&name, now) {
                Ok(Some(dir)) => {
                    outcome.adopted_dirs += 1;
                    claimed.push(dir);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(dir = %self.tasks.join(&name).display(), error = %e, "Could not adopt an orphaned telemetry spool directory")
                }
            }
        }
        for dir in claimed {
            match queue.adopt(&dir) {
                Ok((segments, events)) => {
                    outcome.adopted_events += events;
                    tracing::info!(
                        from = %dir.display(),
                        segments,
                        events,
                        "Adopted an orphaned telemetry spool; its events are delivered with this proxy's"
                    );
                }
                Err(e) => {
                    tracing::warn!(dir = %dir.display(), error = %e, "Adopted telemetry spool could not be read; it stays on disk and is read again at the next restart")
                }
            }
        }
        outcome
    }

    /// Removes the adopted directories whose files have all been delivered.
    fn prune_adopted(&self) {
        prune_empty(&self.own.join(ADOPTED_DIR), 0);
    }
}

/// A spool file name as written by any version: a segment or a legacy event.
fn is_spool_file_name(name: &str) -> bool {
    !name.starts_with('.')
        && ((name.starts_with("seg-") && name.ends_with(".jsonl")) || name.ends_with(".json"))
}

fn read_lease(dir: &Path) -> Option<Lease> {
    let body = fs::read(dir.join(LEASE_FILE)).ok()?;
    serde_json::from_slice(&body).ok()
}

/// Removes an adopted directory's lease and the temporaries its writer left (a
/// crash between write and rename): nobody writes into it any more.
fn clean_leftovers(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == LEASE_FILE || (name.starts_with('.') && name.ends_with(".tmp")) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Removes the drained spools under an `adopted/` directory: each child is a
/// spool with, possibly, its own `adopted/`, pruned first. Only `adopted/`
/// directories are listed, never a spool's files (a large one may be draining):
/// `remove_dir` fails while any file remains, which is the point. A claimed
/// directory's lease and temporaries were removed when it was claimed.
fn prune_empty(adopted: &Path, depth: usize) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = fs::read_dir(adopted) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let spool = entry.path();
        let nested = spool.join(ADOPTED_DIR);
        if nested.is_dir() {
            prune_empty(&nested, depth + 1);
            let _ = fs::remove_dir(&nested);
        }
        let _ = fs::remove_dir(&spool);
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Keeps the lease and adopts orphans, forever: a heartbeat every
/// [`HEARTBEAT_EVERY`], a scan every [`SCAN_EVERY`]. File work runs on the
/// blocking pool.
pub async fn run_maintenance(
    layout: Arc<SpoolLayout>,
    queue: Arc<dyn EventQueue>,
    orphan_after: Duration,
) {
    let mut heartbeat = tokio::time::interval(HEARTBEAT_EVERY);
    let mut scan = tokio::time::interval(SCAN_EVERY);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Both fire at once first: the first scan is the startup adoption, in the
    // background so a large orphan never delays the listener.
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let layout = Arc::clone(&layout);
                let result = tokio::task::spawn_blocking(move || layout.heartbeat(SystemTime::now())).await;
                if let Ok(Err(e)) = result {
                    tracing::warn!(error = %e, "Could not renew the telemetry spool lease");
                }
            }
            _ = scan.tick() => {
                let layout = Arc::clone(&layout);
                let queue = Arc::clone(&queue);
                let _ = tokio::task::spawn_blocking(move || {
                    layout.scan(queue.as_ref(), SystemTime::now(), orphan_after)
                })
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::queue::{DiskOptions, DiskQueue};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vericto-spooldir-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn event(id: &str) -> crate::telemetry::TelemetryEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": id, "database_id": "db-1", "query_text": "SELECT 1",
            "dialect": "postgres", "status": "ALLOWED", "occurred_at": "2026-10-14T00:00:00Z"
        }))
        .unwrap()
    }

    fn open(dir: &Path) -> DiskQueue {
        DiskQueue::with_options(dir, DiskOptions::default()).unwrap()
    }

    fn ids(q: &dyn EventQueue) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let batch = q.drain_batch(100);
            if batch.events.is_empty() {
                break;
            }
            out.extend(batch.events.iter().map(|e| e.event_id.clone()));
            q.ack(&batch);
        }
        out.sort();
        out
    }

    const ORPHAN: Duration = Duration::from_secs(600);

    /// A task writes to its own directory; once it is gone (its lease stale), a
    /// live task adopts it and delivers its events with its own.
    #[test]
    fn a_stale_spool_is_adopted_and_delivered() {
        let base = scratch("adopt");
        let dead = SpoolLayout::new(&base, "task-a").prepare(ORPHAN).unwrap();
        {
            let q = open(dead.own_dir());
            for i in 0..5 {
                q.push(event(&format!("a{i}")));
            }
            assert!(q.flush(Duration::from_secs(10)));
        }
        let live = SpoolLayout::new(&base, "task-b").prepare(ORPHAN).unwrap();
        let q = open(live.own_dir());
        q.push(event("b0"));
        assert!(q.flush(Duration::from_secs(10)));

        // Within the orphan window nothing is taken.
        let now = SystemTime::now();
        assert_eq!(live.scan(&q, now, ORPHAN), ScanOutcome::default());
        // Past it, the dead task's directory is adopted, events first.
        let later = now + ORPHAN + Duration::from_secs(1);
        let outcome = live.scan(&q, later, ORPHAN);
        assert_eq!(outcome.adopted_dirs, 1);
        assert_eq!(outcome.adopted_events, 5);
        assert!(!dead.own_dir().exists(), "renamed away");
        assert_eq!(q.stats().spooled, 6);
        assert_eq!(ids(&q), vec!["a0", "a1", "a2", "a3", "a4", "b0"]);
        // Drained: the adopted directory is removed at the next scan.
        live.scan(&q, later, ORPHAN);
        let adopted: Vec<_> = fs::read_dir(live.own_dir().join(ADOPTED_DIR))
            .unwrap()
            .collect();
        assert!(adopted.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    /// Two live tasks scanning at once never both take the same orphan: the
    /// rename is the claim.
    #[test]
    fn an_orphan_goes_to_exactly_one_adopter() {
        let base = scratch("race");
        let dead = SpoolLayout::new(&base, "task-dead")
            .prepare(ORPHAN)
            .unwrap();
        {
            let q = open(dead.own_dir());
            for i in 0..20 {
                q.push(event(&format!("d{i}")));
            }
            assert!(q.flush(Duration::from_secs(10)));
        }
        dead.release();
        let a = Arc::new(SpoolLayout::new(&base, "task-1").prepare(ORPHAN).unwrap());
        let b = Arc::new(SpoolLayout::new(&base, "task-2").prepare(ORPHAN).unwrap());
        let qa: Arc<dyn EventQueue> = Arc::new(open(a.own_dir()));
        let qb: Arc<dyn EventQueue> = Arc::new(open(b.own_dir()));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let run = |l: Arc<SpoolLayout>, q: Arc<dyn EventQueue>, bar: Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                bar.wait();
                l.scan(q.as_ref(), SystemTime::now(), ORPHAN)
            })
        };
        let ta = run(Arc::clone(&a), Arc::clone(&qa), Arc::clone(&barrier));
        let tb = run(Arc::clone(&b), Arc::clone(&qb), Arc::clone(&barrier));
        let (oa, ob) = (ta.join().unwrap(), tb.join().unwrap());
        assert_eq!(oa.adopted_dirs + ob.adopted_dirs, 1, "{oa:?} {ob:?}");
        let mut all = ids(qa.as_ref());
        all.extend(ids(qb.as_ref()));
        assert_eq!(all.len(), 20, "every event once, none twice");
        let _ = fs::remove_dir_all(base);
    }

    /// A released lease (clean shutdown) is adopted at once, without waiting for
    /// the orphan window; a live one is never touched.
    #[test]
    fn a_released_spool_is_adopted_at_once_and_a_live_one_never() {
        let base = scratch("released");
        let gone = SpoolLayout::new(&base, "gone").prepare(ORPHAN).unwrap();
        let alive = SpoolLayout::new(&base, "alive").prepare(ORPHAN).unwrap();
        gone.release();
        let me = SpoolLayout::new(&base, "me").prepare(ORPHAN).unwrap();
        let q = open(me.own_dir());
        let outcome = me.scan(&q, SystemTime::now(), ORPHAN);
        assert_eq!(outcome.adopted_dirs, 1);
        assert!(!gone.own_dir().exists());
        assert!(alive.own_dir().exists());
        // The live one keeps its lease with heartbeats and stays put.
        alive.heartbeat(SystemTime::now()).unwrap();
        assert_eq!(me.scan(&q, SystemTime::now(), ORPHAN).adopted_dirs, 0);
        let _ = fs::remove_dir_all(base);
    }

    /// The shared directory's own files (a proxy without subdirectories, before
    /// the upgrade) are claimed file by file; the rules cache stays.
    #[test]
    fn files_of_the_shared_directory_are_claimed_and_the_rules_cache_stays() {
        let base = scratch("legacy");
        {
            let q = open(&base);
            for i in 0..3 {
                q.push(event(&format!("old{i}")));
            }
            assert!(q.flush(Duration::from_secs(10)));
        }
        fs::write(base.join(crate::config::RULES_CACHE_FILE), b"{}").unwrap();
        let me = SpoolLayout::new(&base, "me").prepare(ORPHAN).unwrap();
        let q = open(me.own_dir());
        let outcome = me.scan(&q, SystemTime::now(), ORPHAN);
        assert!(outcome.legacy_files >= 1);
        assert_eq!(outcome.adopted_events, 3);
        assert!(base.join(crate::config::RULES_CACHE_FILE).exists());
        assert_eq!(ids(&q), vec!["old0", "old1", "old2"]);
        let _ = fs::remove_dir_all(base);
    }

    /// What was adopted survives a restart of the adopter: its index is rebuilt
    /// from its own directory, adopted subdirectories included, oldest first.
    #[test]
    fn adopted_events_survive_the_adopters_restart() {
        let base = scratch("restart");
        let dead = SpoolLayout::new(&base, "dead").prepare(ORPHAN).unwrap();
        {
            let q = open(dead.own_dir());
            q.push(event("x0"));
            q.push(event("x1"));
            assert!(q.flush(Duration::from_secs(10)));
        }
        dead.release();
        let me = SpoolLayout::new(&base, "me").prepare(ORPHAN).unwrap();
        {
            let q = open(me.own_dir());
            q.push(event("y0"));
            assert!(q.flush(Duration::from_secs(10)));
            assert_eq!(me.scan(&q, SystemTime::now(), ORPHAN).adopted_events, 2);
        }
        let q = open(me.own_dir());
        assert_eq!(q.stats().spooled, 3);
        assert_eq!(ids(&q), vec!["x0", "x1", "y0"]);
        let _ = fs::remove_dir_all(base);
    }

    /// A chain of replacements (a adopted by b, b gone before delivering it,
    /// adopted by c) loses nothing, and every drained directory is pruned.
    #[test]
    fn a_chain_of_adoptions_delivers_everything_and_prunes() {
        let base = scratch("chain");
        let push = |l: &SpoolLayout, ids: &[&str]| {
            let q = open(l.own_dir());
            for id in ids {
                q.push(event(id));
            }
            assert!(q.flush(Duration::from_secs(10)));
            q
        };
        let a = SpoolLayout::new(&base, "a").prepare(ORPHAN).unwrap();
        drop(push(&a, &["a0"]));
        a.release();
        let b = SpoolLayout::new(&base, "b").prepare(ORPHAN).unwrap();
        {
            let q = push(&b, &["b0"]);
            assert_eq!(b.scan(&q, SystemTime::now(), ORPHAN).adopted_dirs, 1);
        }
        b.release();
        let c = SpoolLayout::new(&base, "c").prepare(ORPHAN).unwrap();
        let q = push(&c, &["c0"]);
        assert_eq!(c.scan(&q, SystemTime::now(), ORPHAN).adopted_events, 2);
        assert_eq!(ids(&q), vec!["a0", "b0", "c0"]);
        c.scan(&q, SystemTime::now(), ORPHAN);
        assert_eq!(
            fs::read_dir(c.own_dir().join(ADOPTED_DIR)).unwrap().count(),
            0,
            "every drained spool removed, nested ones included"
        );
        let _ = fs::remove_dir_all(base);
    }

    /// A directory under this name leased by another live process is not shared.
    #[test]
    fn a_name_held_by_a_live_process_is_not_shared() {
        let base = scratch("collide");
        let first = SpoolLayout::new(&base, "same").prepare(ORPHAN).unwrap();
        let second = SpoolLayout::new(&base, "same").prepare(ORPHAN).unwrap();
        assert_ne!(first.own_dir(), second.own_dir());
        // After a clean shutdown the name is reused.
        first.release();
        let third = SpoolLayout::new(&base, "same").prepare(ORPHAN).unwrap();
        assert_eq!(third.own_dir(), first.own_dir());
        let _ = fs::remove_dir_all(base);
    }

    /// A proxy whose directory was adopted under it (it looked dead) notices at its
    /// next heartbeat and carries on in a fresh directory.
    #[test]
    fn a_proxy_whose_directory_was_adopted_starts_a_fresh_one() {
        let base = scratch("lost");
        let slow = SpoolLayout::new(&base, "slow").prepare(ORPHAN).unwrap();
        let other = SpoolLayout::new(&base, "other").prepare(ORPHAN).unwrap();
        let q = open(other.own_dir());
        let later = SystemTime::now() + ORPHAN + Duration::from_secs(1);
        assert_eq!(other.scan(&q, later, ORPHAN).adopted_dirs, 1);
        assert!(!slow.own_dir().exists());
        slow.heartbeat(SystemTime::now()).unwrap();
        assert!(slow.own_dir().join(LEASE_FILE).exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn subdir_settings() {
        let off = SubdirConfig::from_values(None, None).unwrap();
        assert_eq!(off.mode, SubdirMode::Off);
        assert_eq!(off.orphan_after, DEFAULT_ORPHAN_AFTER);
        assert_eq!(
            SubdirConfig::from_values(Some("TASK"), Some("30")).unwrap(),
            SubdirConfig {
                mode: SubdirMode::Task,
                orphan_after: Duration::from_secs(MIN_ORPHAN_SECS)
            }
        );
        assert_eq!(
            SubdirConfig::from_values(Some("hostname"), None)
                .unwrap()
                .mode,
            SubdirMode::Hostname
        );
        assert_eq!(
            SubdirConfig::from_values(Some("replica-1"), Some("900")).unwrap(),
            SubdirConfig {
                mode: SubdirMode::Fixed("replica-1".into()),
                orphan_after: Duration::from_secs(900)
            }
        );
        assert!(SubdirConfig::from_values(Some(".."), None).is_err());
        assert!(SubdirConfig::from_values(Some("///"), None).is_err());
        assert_eq!(sanitize_name("../etc/x").as_deref(), Some("_etc_x"));
        assert_eq!(
            sanitize_name(" ip-10-0-1-5.ec2.internal\n").as_deref(),
            Some("ip-10-0-1-5.ec2.internal")
        );
        assert_eq!(
            task_id_from_arn("arn:aws:ecs:us-east-1:123456789012:task/cluster/0123456789abcdef")
                .as_deref(),
            Some("0123456789abcdef")
        );
    }
}
