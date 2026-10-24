// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! How many async worker threads the proxy starts (4.16.2).
//!
//! tokio's default is one worker per CPU the process may run on
//! (`std::thread::available_parallelism`). That counts CPUs, not CPU time, and
//! the two differ exactly where the proxy is usually deployed:
//!
//! - **ECS Fargate** (platform 1.4.0, cgroup v1, measured 2026-10-23): the CPU
//!   quota of the task is set on the task's cgroup, above the container's, and
//!   is not visible from inside the container. A 0.5 vCPU task runs on a
//!   2-vCPU host and sees 2 CPUs and no quota (`cpu.cfs_quota_us` = -1), so
//!   tokio started 2 workers for half a CPU of time. The task metadata endpoint
//!   does report the limit (`Limits.CPU` = 0.5).
//! - **A visible quota that is not a whole number**: std rounds it down
//!   (1.5 vCPU gives 1 worker); a fraction of a CPU left unused is capacity
//!   lost, a fraction more is only queueing, so this rounds up.
//!
//! More workers than CPU time do not add throughput: with a quota the extra
//! threads spend it faster in parallel and the whole process is then throttled
//! until the next CFS period (100 ms by default), which is a stall for every
//! connection at once.
//!
//! Order: `VERICTO_WORKER_THREADS`, then `TOKIO_WORKER_THREADS` (honoured by
//! tokio's default before 4.16.2, so kept), then the CPU limit rounded up (the
//! lower of the cgroup quota visible to the process and the ECS task limit),
//! then the CPUs available. Never more workers than CPUs, never fewer than one.
//!
//! The evaluation pool (`spawn_blocking`) keeps tokio's default bound: capping
//! it at 4 threads made no measurable difference at 0.5 vCPU (2026-10-23, up to
//! 90% of the published saturation rate), and a low cap would let a few large
//! statements hold every evaluation thread.

use std::path::Path;
use std::time::Duration;

/// Upper bound accepted for either thread setting: far above any useful value,
/// low enough to catch a unit mistake (a byte count, a millisecond value).
const MAX_THREADS: usize = 1024;

/// Where the worker count came from, for the startup log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `VERICTO_WORKER_THREADS`.
    Configured,
    /// `TOKIO_WORKER_THREADS`.
    TokioEnv,
    /// The cgroup CPU quota visible to the process.
    CgroupQuota,
    /// `Limits.CPU` of the ECS task metadata.
    EcsTaskLimit,
    /// No limit found: one worker per available CPU (tokio's default).
    AvailableCpus,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Configured => "VERICTO_WORKER_THREADS",
            Source::TokioEnv => "TOKIO_WORKER_THREADS",
            Source::CgroupQuota => "cgroup_cpu_quota",
            Source::EcsTaskLimit => "ecs_task_cpu_limit",
            Source::AvailableCpus => "available_cpus",
        }
    }
}

/// The runtime the proxy builds.
#[derive(Debug, Clone, PartialEq)]
pub struct Sizing {
    pub worker_threads: usize,
    pub source: Source,
    /// The CPU limit found, in CPUs (`None` when there is none or it was not
    /// looked up because a thread count was configured).
    pub cpu_limit: Option<f64>,
    /// `std::thread::available_parallelism` (CPUs, quota rounded down by std).
    pub available_cpus: usize,
}

/// What [`plan`] decides from.
#[derive(Debug, Default, Clone)]
pub struct Inputs<'a> {
    pub worker_threads_env: Option<&'a str>,
    pub tokio_worker_threads_env: Option<&'a str>,
    pub cgroup_limit: Option<f64>,
    pub ecs_limit: Option<f64>,
    pub available_cpus: usize,
}

/// A thread count from `name`: a whole number from 1 to [`MAX_THREADS`].
/// Empty counts as unset.
fn parse_threads(name: &str, value: Option<&str>) -> Result<Option<usize>, String> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match raw.parse::<usize>() {
        Ok(n) if (1..=MAX_THREADS).contains(&n) => Ok(Some(n)),
        _ => Err(format!(
            "{name}={raw:?} is not a thread count: expected a whole number from 1 to {MAX_THREADS}"
        )),
    }
}

/// Workers for a CPU limit: rounded up, at least 1, at most the CPUs available.
fn workers_for(limit: f64, available: usize) -> usize {
    let available = available.max(1);
    // A limit is a positive, finite number of CPUs; anything else is ignored upstream.
    let up = limit.ceil();
    if up >= available as f64 {
        available
    } else {
        (up as usize).max(1)
    }
}

/// The sizing for `inputs`. `Err` only for a malformed thread setting, which
/// stops the proxy at startup like every other malformed variable.
pub fn plan(inputs: &Inputs<'_>) -> Result<Sizing, String> {
    let available = inputs.available_cpus.max(1);
    let configured = parse_threads("VERICTO_WORKER_THREADS", inputs.worker_threads_env)?;
    let tokio_env = parse_threads("TOKIO_WORKER_THREADS", inputs.tokio_worker_threads_env)?;
    let sized = |worker_threads, source, cpu_limit| Sizing {
        worker_threads,
        source,
        cpu_limit,
        available_cpus: available,
    };
    // An explicit count is the operator's call, even above the CPUs available.
    if let Some(n) = configured {
        return Ok(sized(n, Source::Configured, None));
    }
    if let Some(n) = tokio_env {
        return Ok(sized(n, Source::TokioEnv, None));
    }
    let valid = |v: Option<f64>| v.filter(|l| l.is_finite() && *l > 0.0);
    let limit = match (valid(inputs.cgroup_limit), valid(inputs.ecs_limit)) {
        (Some(c), Some(e)) if e < c => Some((e, Source::EcsTaskLimit)),
        (Some(c), _) => Some((c, Source::CgroupQuota)),
        (None, Some(e)) => Some((e, Source::EcsTaskLimit)),
        (None, None) => None,
    };
    Ok(match limit {
        Some((l, source)) => sized(workers_for(l, available), source, Some(l)),
        None => sized(available, Source::AvailableCpus, None),
    })
}

/// [`plan`] for this process: its environment, its cgroup, the ECS task
/// metadata when `ECS_CONTAINER_METADATA_URI_V4` is set, and its CPUs.
pub fn from_environment() -> Result<Sizing, String> {
    let worker = std::env::var("VERICTO_WORKER_THREADS").ok();
    let tokio_env = std::env::var("TOKIO_WORKER_THREADS").ok();
    let explicit = [&worker, &tokio_env]
        .iter()
        .any(|v| v.as_deref().is_some_and(|s| !s.trim().is_empty()));
    let (cgroup_limit, ecs_limit) = if explicit {
        (None, None)
    } else {
        (cgroup_cpu_limit(Path::new("/")), ecs_task_cpu_limit())
    };
    plan(&Inputs {
        worker_threads_env: worker.as_deref(),
        tokio_worker_threads_env: tokio_env.as_deref(),
        cgroup_limit,
        ecs_limit,
        available_cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
    })
}

// ---- cgroup ------------------------------------------------------------------

/// The CPU quota of this process's cgroup in CPUs: the lowest quota/period of
/// its cgroup and every ancestor visible under the mount (cgroup v2 `cpu.max`,
/// v1 `cpu.cfs_quota_us` / `cpu.cfs_period_us`). `None` without a quota or
/// outside Linux. `root` prefixes every path read (`/` in production, a
/// directory tree in tests).
pub fn cgroup_cpu_limit(root: &Path) -> Option<f64> {
    let cgroups = std::fs::read_to_string(root.join("proc/self/cgroup")).ok()?;
    let mountinfo = std::fs::read_to_string(root.join("proc/self/mountinfo")).ok()?;
    let mut best: Option<f64> = None;
    for line in cgroups.lines() {
        // `hierarchy-id:controllers:path`; v2 is `0::path`.
        let mut parts = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let v2 = controllers.is_empty();
        if !v2 && !controllers.split(',').any(|c| c == "cpu") {
            continue;
        }
        let Some((mount_root, mount_point)) = find_mount(&mountinfo, v2) else {
            continue;
        };
        let base = root.join(mount_point.trim_start_matches('/'));
        let rel = path.strip_prefix(&mount_root).unwrap_or("");
        let mut dir = base.join(rel.trim_start_matches('/'));
        loop {
            let quota = if v2 {
                read_cpu_max(&dir)
            } else {
                read_cfs_quota(&dir)
            };
            if let Some(q) = quota {
                best = Some(best.map_or(q, |b: f64| b.min(q)));
            }
            if dir == base || !dir.pop() || !dir.starts_with(&base) {
                break;
            }
        }
    }
    best
}

/// `(root, mount point)` of the cgroup2 mount (`v2`) or of the v1 hierarchy with
/// the `cpu` controller, from `/proc/self/mountinfo`.
fn find_mount(mountinfo: &str, v2: bool) -> Option<(String, String)> {
    for line in mountinfo.lines() {
        // `id parent major:minor root mount-point options [optional...] - fstype source super-options`
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre: Vec<&str> = pre.split(' ').collect();
        let post: Vec<&str> = post.split(' ').collect();
        if pre.len() < 5 || post.is_empty() {
            continue;
        }
        let matches = if v2 {
            post[0] == "cgroup2"
        } else {
            post[0] == "cgroup"
                && post
                    .get(2)
                    .is_some_and(|o| o.split(',').any(|c| c == "cpu"))
        };
        if matches {
            return Some((unescape(pre[3]), unescape(pre[4])));
        }
    }
    None
}

/// mountinfo escapes space, tab, newline and backslash as octal (`\\040`).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // At most \\377: a byte.
        let octal = b.get(i + 1..i + 4).filter(|d| {
            (b'0'..=b'3').contains(&d[0]) && d[1..].iter().all(|c| (b'0'..=b'7').contains(c))
        });
        match (b[i], octal) {
            (b'\\', Some(d)) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_cpu_max(dir: &Path) -> Option<f64> {
    let raw = std::fs::read_to_string(dir.join("cpu.max")).ok()?;
    let mut it = raw.split_whitespace();
    let quota = it.next()?;
    let period: f64 = it.next()?.parse().ok()?;
    if quota == "max" || period <= 0.0 {
        return None;
    }
    let quota: f64 = quota.parse().ok()?;
    (quota > 0.0).then(|| quota / period)
}

fn read_cfs_quota(dir: &Path) -> Option<f64> {
    let read = |name: &str| -> Option<f64> {
        std::fs::read_to_string(dir.join(name))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    let quota = read("cpu.cfs_quota_us")?;
    let period = read("cpu.cfs_period_us")?;
    (quota > 0.0 && period > 0.0).then(|| quota / period)
}

// ---- ECS task metadata -----------------------------------------------------------

/// `Limits.CPU` (vCPUs) of the ECS task metadata (`/task` under
/// `ECS_CONTAINER_METADATA_URI_V4`), or `None` outside ECS, without a
/// task-level limit, or when the endpoint does not answer within two seconds.
/// Runs before the proxy's runtime exists, on a throwaway single-threaded one.
fn ecs_task_cpu_limit() -> Option<f64> {
    let base = std::env::var("ECS_CONTAINER_METADATA_URI_V4").ok()?;
    let url = format!("{}/task", base.trim_end_matches('/'));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let body: serde_json::Value = rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .ok()?;
        client.get(url).send().await.ok()?.json().await.ok()
    })?;
    task_cpu_limit(&body)
}

/// `Limits.CPU` of a task metadata document, when positive.
fn task_cpu_limit(task: &serde_json::Value) -> Option<f64> {
    task.get("Limits")?
        .get("CPU")?
        .as_f64()
        .filter(|c| c.is_finite() && *c > 0.0)
}

/// For tests: a path under `root`.
#[cfg(test)]
fn under(root: &Path, p: &str) -> std::path::PathBuf {
    root.join(p.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(cgroup: Option<f64>, ecs: Option<f64>, cpus: usize) -> Inputs<'static> {
        Inputs {
            cgroup_limit: cgroup,
            ecs_limit: ecs,
            available_cpus: cpus,
            ..Default::default()
        }
    }

    #[test]
    fn half_a_cpu_is_one_worker() {
        let s = plan(&inputs(Some(0.5), None, 8)).unwrap();
        assert_eq!((s.worker_threads, s.source), (1, Source::CgroupQuota));
    }

    #[test]
    fn fargate_half_vcpu_uses_the_task_limit() {
        // What a 0.5 vCPU Fargate task sees: 2 CPUs, no quota in its cgroup.
        let s = plan(&inputs(None, Some(0.5), 2)).unwrap();
        assert_eq!((s.worker_threads, s.source), (1, Source::EcsTaskLimit));
        assert_eq!(s.cpu_limit, Some(0.5));
    }

    #[test]
    fn a_fraction_rounds_up_and_never_exceeds_the_cpus() {
        assert_eq!(plan(&inputs(Some(1.5), None, 8)).unwrap().worker_threads, 2);
        assert_eq!(plan(&inputs(Some(2.0), None, 8)).unwrap().worker_threads, 2);
        assert_eq!(plan(&inputs(Some(6.0), None, 4)).unwrap().worker_threads, 4);
        assert_eq!(
            plan(&inputs(Some(0.01), None, 4)).unwrap().worker_threads,
            1
        );
    }

    #[test]
    fn the_lower_limit_wins() {
        let s = plan(&inputs(Some(4.0), Some(1.0), 8)).unwrap();
        assert_eq!((s.worker_threads, s.source), (1, Source::EcsTaskLimit));
        let s = plan(&inputs(Some(1.0), Some(4.0), 8)).unwrap();
        assert_eq!((s.worker_threads, s.source), (1, Source::CgroupQuota));
    }

    #[test]
    fn no_limit_is_one_worker_per_cpu() {
        let s = plan(&inputs(None, None, 8)).unwrap();
        assert_eq!((s.worker_threads, s.source), (8, Source::AvailableCpus));
        let s = plan(&inputs(Some(f64::NAN), Some(0.0), 0)).unwrap();
        assert_eq!((s.worker_threads, s.source), (1, Source::AvailableCpus));
    }

    #[test]
    fn configured_counts_win_in_order() {
        let mut i = inputs(Some(0.5), Some(0.5), 2);
        i.tokio_worker_threads_env = Some("3");
        assert_eq!(plan(&i).unwrap().worker_threads, 3);
        assert_eq!(plan(&i).unwrap().source, Source::TokioEnv);
        i.worker_threads_env = Some(" 6 ");
        let s = plan(&i).unwrap();
        assert_eq!(
            (s.worker_threads, s.source, s.cpu_limit),
            (6, Source::Configured, None)
        );
        i.worker_threads_env = Some("");
        assert_eq!(plan(&i).unwrap().source, Source::TokioEnv);
    }

    #[test]
    fn malformed_counts_are_startup_errors() {
        for bad in ["0", "-1", "1.5", "two", "1025"] {
            let mut i = inputs(None, None, 2);
            i.worker_threads_env = Some(bad);
            assert!(
                plan(&i).unwrap_err().contains("VERICTO_WORKER_THREADS"),
                "{bad}"
            );
        }
    }

    fn write(root: &Path, p: &str, body: &str) {
        let path = under(root, p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn cgroup_v2_in_a_container_namespace() {
        // docker --cpus=0.5 on a cgroup v2 host (private cgroup namespace).
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        write(r, "proc/self/cgroup", "0::/\n");
        write(
            r,
            "proc/self/mountinfo",
            "30 25 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n",
        );
        write(r, "sys/fs/cgroup/cpu.max", "50000 100000\n");
        assert_eq!(cgroup_cpu_limit(r), Some(0.5));
        write(r, "sys/fs/cgroup/cpu.max", "max 100000\n");
        assert_eq!(cgroup_cpu_limit(r), None);
    }

    #[test]
    fn cgroup_v2_takes_the_lowest_ancestor() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        write(r, "proc/self/cgroup", "0::/system.slice/task/app\n");
        write(
            r,
            "proc/self/mountinfo",
            "1 2 3 / /proc rw - proc proc rw\n30 25 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        );
        write(
            r,
            "sys/fs/cgroup/system.slice/task/app/cpu.max",
            "max 100000\n",
        );
        write(
            r,
            "sys/fs/cgroup/system.slice/task/cpu.max",
            "150000 100000\n",
        );
        write(r, "sys/fs/cgroup/system.slice/cpu.max", "400000 100000\n");
        assert_eq!(cgroup_cpu_limit(r), Some(1.5));
    }

    #[test]
    fn cgroup_v1_fargate_shows_no_quota() {
        // What a Fargate container sees (platform 1.4.0): its own cgroup
        // bind-mounted as the root, no quota on it.
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        write(
            r,
            "proc/self/cgroup",
            "5:cpu,cpuacct:/ecs/t1/t1-c1\n3:cpuset:/ecs/t1/t1-c1\n0::/ecs/t1/t1-c1\n",
        );
        write(
            r,
            "proc/self/mountinfo",
            "1130 1128 0:120 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n\
             1137 1130 0:37 /ecs/t1/t1-c1 /sys/fs/cgroup/cpu,cpuacct ro,nosuid - cgroup cgroup rw,seclabel,cpu,cpuacct\n",
        );
        write(r, "sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us", "-1\n");
        write(r, "sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us", "100000\n");
        assert_eq!(cgroup_cpu_limit(r), None);
        // With a quota on the container's own cgroup it is found.
        write(r, "sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us", "25000\n");
        assert_eq!(cgroup_cpu_limit(r), Some(0.25));
    }

    #[test]
    fn no_cgroup_files_is_no_limit() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(cgroup_cpu_limit(t.path()), None);
    }

    #[test]
    fn task_metadata_limit() {
        let doc =
            serde_json::json!({"Limits": {"CPU": 0.5, "Memory": 1024}, "LaunchType": "FARGATE"});
        assert_eq!(task_cpu_limit(&doc), Some(0.5));
        assert_eq!(
            task_cpu_limit(&serde_json::json!({"Limits": {"Memory": 512}})),
            None
        );
        assert_eq!(
            task_cpu_limit(&serde_json::json!({"Limits": {"CPU": 0}})),
            None
        );
        assert_eq!(task_cpu_limit(&serde_json::json!({})), None);
    }

    #[test]
    fn mountinfo_octal_escapes() {
        assert_eq!(unescape("/a\\040b"), "/a b");
        assert_eq!(unescape("/plain"), "/plain");
        assert_eq!(unescape("/x\\777\\04"), "/x\\777\\04");
    }
}
