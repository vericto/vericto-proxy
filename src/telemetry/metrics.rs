//! The telemetry pipeline as metrics (since 4.12.0): a Prometheus text page,
//! `GET /metrics` on the health-check listener (`tcp::healthz`), and a CloudWatch
//! Embedded Metric Format (EMF) line on stdout every interval, for deployments
//! whose logs go to CloudWatch (the Enterprise kit turns it on).
//!
//! Both say the same thing as the rule-sync heartbeat (`telemetry::heartbeat`),
//! locally and every minute instead of to the API every five: how far behind
//! delivery is, how full the spool is, and what was dropped and why.
//!
//! ## What they carry, and what they never carry
//!
//! Counters, gauges and a fixed set of labels: `cause` (five fixed values),
//! `version` and `buffer` (one value each per process). No query text, no
//! database user, no client address, no workspace, database or API key id, and no
//! label whose value comes from traffic, so the number of series is fixed. The
//! EMF dimensions are the operator's `VERICTO_METRICS_PROXY_NAME` and the task id
//! (`VERICTO_METRICS_EMF_TASK_DIMENSION`, on by default): two dimension sets,
//! `[ProxyName]` (alarm on it: the worst task) and `[ProxyName, TaskId]`.
//!
//! `/metrics` is opt-in (`VERICTO_METRICS_PROMETHEUS`) and served only by the
//! health-check listener, never by the database listener. Bind that listener to a
//! private address (`VERICTO_HEALTHZ_ADDR`) and never expose it to the internet:
//! the figures are not secret, but they say how busy the database is.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::Duration;

use crate::telemetry::heartbeat::{PipelineSnapshot, StatsSource};

/// Prefix of every metric name, Prometheus and EMF alike.
pub const PREFIX: &str = "vericto_proxy_";

/// The five causes of `vericto_proxy_telemetry_dropped_total`, as labels.
pub const DROP_CAUSES: [&str; 5] = [
    "queue_full",
    "evicted",
    "permanent",
    "write_failure",
    "quota",
];

/// Default CloudWatch namespace of the EMF line.
pub const DEFAULT_EMF_NAMESPACE: &str = "Vericto/Proxy";
/// Default `ProxyName` dimension.
pub const DEFAULT_PROXY_NAME: &str = "vericto-proxy";
/// Default and bounds of `VERICTO_METRICS_EMF_INTERVAL_SECS`.
const DEFAULT_EMF_INTERVAL: Duration = Duration::from_secs(60);
const MIN_EMF_INTERVAL_SECS: u64 = 10;
const MAX_EMF_INTERVAL_SECS: u64 = 3600;
/// CloudWatch's limit for a dimension value is 1024 characters; names are short.
const MAX_DIMENSION_CHARS: usize = 255;

/// How the metrics are exposed. Read from the environment once, at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    /// `GET /metrics` on the health-check listener. `VERICTO_METRICS_PROMETHEUS`,
    /// default off.
    pub prometheus: bool,
    /// One EMF line per interval on stdout. `VERICTO_METRICS_EMF`, default off.
    pub emf: bool,
    /// `VERICTO_METRICS_EMF_NAMESPACE`, default [`DEFAULT_EMF_NAMESPACE`].
    pub emf_namespace: String,
    /// `VERICTO_METRICS_EMF_INTERVAL_SECS`, default 60 (10–3600).
    pub emf_interval: Duration,
    /// `VERICTO_METRICS_PROXY_NAME`, default [`DEFAULT_PROXY_NAME`].
    pub proxy_name: String,
    /// Add the `[ProxyName, TaskId]` dimension set.
    /// `VERICTO_METRICS_EMF_TASK_DIMENSION`, default on.
    pub task_dimension: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus: false,
            emf: false,
            emf_namespace: DEFAULT_EMF_NAMESPACE.to_string(),
            emf_interval: DEFAULT_EMF_INTERVAL,
            proxy_name: DEFAULT_PROXY_NAME.to_string(),
            task_dimension: true,
        }
    }
}

impl MetricsConfig {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        Self::from_vars(var)
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Self {
        let d = Self::default();
        let flag = |k: &str, default: bool| {
            var(k)
                .map(|v| {
                    matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(default)
        };
        let text = |k: &str, default: String| {
            var(k)
                .map(|v| dimension_value(&v))
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
        };
        Self {
            prometheus: flag("VERICTO_METRICS_PROMETHEUS", d.prometheus),
            emf: flag("VERICTO_METRICS_EMF", d.emf),
            emf_namespace: text("VERICTO_METRICS_EMF_NAMESPACE", d.emf_namespace),
            emf_interval: var("VERICTO_METRICS_EMF_INTERVAL_SECS")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.clamp(MIN_EMF_INTERVAL_SECS, MAX_EMF_INTERVAL_SECS)))
                .unwrap_or(d.emf_interval),
            proxy_name: text("VERICTO_METRICS_PROXY_NAME", d.proxy_name),
            task_dimension: flag("VERICTO_METRICS_EMF_TASK_DIMENSION", d.task_dimension),
        }
    }
}

/// An operator-supplied name as a dimension value: printable ASCII, no quotes or
/// backslashes, at most [`MAX_DIMENSION_CHARS`].
pub fn dimension_value(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\')
        .take(MAX_DIMENSION_CHARS)
        .collect()
}

/// One metric of the snapshot: name (without [`PREFIX`]), kind, help, EMF unit.
struct Gauge {
    name: &'static str,
    help: &'static str,
    unit: &'static str,
    value: u64,
}

fn gauges(p: &PipelineSnapshot) -> [Gauge; 8] {
    let used_percent = spool_used_percent(p);
    [
        Gauge {
            name: "telemetry_oldest_undelivered_age_seconds",
            help: "Age of the oldest telemetry event not yet delivered to the Vericto API; 0 when none waits.",
            unit: "Seconds",
            value: p.oldest_undelivered_age_s,
        },
        Gauge {
            name: "telemetry_seconds_since_last_delivery",
            help: "Seconds without a successful delivery while events wait; 0 when none waits.",
            unit: "Seconds",
            value: p.seconds_since_last_delivery,
        },
        Gauge {
            name: "telemetry_spool_bytes",
            help: "Bytes of spool files holding undelivered events (disk buffer).",
            unit: "Bytes",
            value: p.spool_bytes,
        },
        Gauge {
            name: "telemetry_spool_events",
            help: "Events buffered and not yet delivered.",
            unit: "Count",
            value: p.spooled_events,
        },
        Gauge {
            name: "telemetry_spool_capacity_bytes",
            help: "Byte bound of the disk spool (VERICTO_TELEMETRY_SPOOL_MAX_BYTES); 0 for the memory buffer.",
            unit: "Bytes",
            value: p.spool_max_bytes,
        },
        Gauge {
            name: "telemetry_spool_used_percent",
            help: "Spool bytes as a percentage of its bound; 0 for the memory buffer.",
            unit: "Percent",
            value: used_percent,
        },
        Gauge {
            name: "telemetry_quota_paused",
            help: "1 while telemetry is paused because the workspace is over its monthly quota.",
            unit: "None",
            value: u64::from(p.quota_paused),
        },
        Gauge {
            name: "telemetry_requests_in_flight",
            help: "Telemetry requests to the Vericto API outstanding.",
            unit: "Count",
            value: p.in_flight,
        },
    ]
}

fn spool_used_percent(p: &PipelineSnapshot) -> u64 {
    if p.spool_max_bytes == 0 {
        return 0;
    }
    ((p.spool_bytes as u128 * 100) / p.spool_max_bytes as u128).min(100) as u64
}

/// Dropped events by cause, in [`DROP_CAUSES`] order.
fn drops(p: &PipelineSnapshot) -> [u64; 5] {
    [
        p.dropped_queue_full,
        p.evicted_oldest,
        p.dropped_permanent,
        p.write_failures,
        p.dropped_quota,
    ]
}

/// The Prometheus text exposition (format 0.0.4) of `snapshot`; `None` when the
/// control-plane link is off (no telemetry pipeline).
pub fn render_prometheus(snapshot: Option<&PipelineSnapshot>) -> String {
    let mut out = String::with_capacity(4096);
    let buffer = snapshot.map(|p| p.buffer).unwrap_or("none");
    let _ = writeln!(
        out,
        "# HELP {PREFIX}info vericto-proxy build and telemetry buffer (always 1).\n\
         # TYPE {PREFIX}info gauge\n\
         {PREFIX}info{{version=\"{}\",buffer=\"{buffer}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        out,
        "# HELP {PREFIX}telemetry_enabled 1 when the control-plane link (telemetry) is configured.\n\
         # TYPE {PREFIX}telemetry_enabled gauge\n\
         {PREFIX}telemetry_enabled {}",
        u8::from(snapshot.is_some())
    );
    let Some(p) = snapshot else {
        return out;
    };
    for g in gauges(p) {
        let _ = writeln!(
            out,
            "# HELP {PREFIX}{name} {help}\n# TYPE {PREFIX}{name} gauge\n{PREFIX}{name} {value}",
            name = g.name,
            help = g.help,
            value = g.value
        );
    }
    let last = p.last_delivery_at.map(|t| t.timestamp()).unwrap_or(0);
    let _ = writeln!(
        out,
        "# HELP {PREFIX}telemetry_last_delivery_timestamp_seconds Unix time of the last successful delivery; 0 before the first.\n\
         # TYPE {PREFIX}telemetry_last_delivery_timestamp_seconds gauge\n\
         {PREFIX}telemetry_last_delivery_timestamp_seconds {last}"
    );
    for (name, help, value) in [
        (
            "telemetry_enqueued_total",
            "Telemetry events accepted into the buffer since the process started.",
            p.enqueued,
        ),
        (
            "telemetry_delivered_total",
            "Telemetry events the Vericto API accepted since the process started.",
            p.delivered,
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {PREFIX}{name} {help}\n# TYPE {PREFIX}{name} counter\n{PREFIX}{name} {value}"
        );
    }
    let _ = writeln!(
        out,
        "# HELP {PREFIX}telemetry_dropped_total Telemetry events dropped since the process started, by cause (quota = not recorded while over the monthly quota).\n\
         # TYPE {PREFIX}telemetry_dropped_total counter"
    );
    for (cause, value) in DROP_CAUSES.iter().zip(drops(p)) {
        let _ = writeln!(
            out,
            "{PREFIX}telemetry_dropped_total{{cause=\"{cause}\"}} {value}"
        );
    }
    out
}

/// Builds the EMF lines, keeping the counters of the previous one so each line
/// carries what happened during its interval (CloudWatch sums those).
pub struct EmfEmitter {
    namespace: String,
    proxy_name: String,
    task_id: Option<String>,
    previous: Option<[u64; 6]>,
}

impl EmfEmitter {
    pub fn new(cfg: &MetricsConfig, task_id: Option<&str>) -> Self {
        Self {
            namespace: cfg.emf_namespace.clone(),
            proxy_name: cfg.proxy_name.clone(),
            task_id: task_id
                .filter(|_| cfg.task_dimension)
                .map(dimension_value)
                .filter(|t| !t.is_empty()),
            previous: None,
        }
    }

    /// One EMF document (a single line of JSON) for `p` at `timestamp_ms`.
    pub fn line(&mut self, p: &PipelineSnapshot, timestamp_ms: i64) -> String {
        let d = drops(p);
        let now = [p.delivered, d[0], d[1], d[2], d[3], d[4]];
        // The first line counts from the process start (the counters' zero); a
        // counter that went down (it cannot) counts from zero again.
        let before = self.previous.unwrap_or([0; 6]);
        let delta: Vec<u64> = now
            .iter()
            .zip(before)
            .map(|(n, b)| if *n >= b { n - b } else { *n })
            .collect();
        self.previous = Some(now);

        let mut metrics = Vec::new();
        let mut doc = serde_json::Map::new();
        for g in gauges(p) {
            let name = format!("{PREFIX}{}", g.name);
            metrics.push(serde_json::json!({ "Name": name, "Unit": g.unit }));
            doc.insert(name, g.value.into());
        }
        let counts = [
            ("telemetry_delivered", delta[0]),
            ("telemetry_dropped_queue_full", delta[1]),
            ("telemetry_dropped_evicted", delta[2]),
            ("telemetry_dropped_permanent", delta[3]),
            ("telemetry_dropped_write_failure", delta[4]),
            ("telemetry_dropped_quota", delta[5]),
            (
                "telemetry_dropped_loss",
                delta[1] + delta[2] + delta[3] + delta[4],
            ),
        ];
        for (name, value) in counts {
            let name = format!("{PREFIX}{name}");
            metrics.push(serde_json::json!({ "Name": name, "Unit": "Count" }));
            doc.insert(name, value.into());
        }
        let mut dimensions = vec![serde_json::json!(["ProxyName"])];
        doc.insert("ProxyName".into(), self.proxy_name.clone().into());
        if let Some(task) = &self.task_id {
            dimensions.push(serde_json::json!(["ProxyName", "TaskId"]));
            doc.insert("TaskId".into(), task.clone().into());
        }
        doc.insert("type".into(), "vericto_proxy_metrics".into());
        doc.insert(
            "_aws".into(),
            serde_json::json!({
                "Timestamp": timestamp_ms,
                "CloudWatchMetrics": [{
                    "Namespace": self.namespace,
                    "Dimensions": dimensions,
                    "Metrics": metrics,
                }]
            }),
        );
        serde_json::Value::Object(doc).to_string()
    }
}

/// Writes one EMF line per interval to stdout, forever. Stdout is where the
/// container's logs go (awslogs on ECS), and CloudWatch Logs turns each line into
/// metrics. Written whole under the stdout lock, so it never interleaves with a
/// log line.
pub async fn run_emf(cfg: MetricsConfig, source: StatsSource, task_id: Option<String>) {
    let mut emitter = EmfEmitter::new(&cfg, task_id.as_deref());
    let mut ticker = tokio::time::interval(cfg.emf_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tracing::info!(
        namespace = %cfg.emf_namespace,
        interval_secs = cfg.emf_interval.as_secs(),
        proxy_name = %cfg.proxy_name,
        task_dimension = emitter.task_id.is_some(),
        "CloudWatch EMF metrics enabled"
    );
    loop {
        ticker.tick().await;
        let source = source.clone();
        let Ok(snapshot) = tokio::task::spawn_blocking(move || source.pipeline()).await else {
            continue;
        };
        let line = emitter.line(&snapshot, chrono::Utc::now().timestamp_millis());
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn snapshot() -> PipelineSnapshot {
        PipelineSnapshot {
            buffer: "disk",
            enqueued: 100,
            delivered: 80,
            dropped_queue_full: 1,
            evicted_oldest: 2,
            dropped_permanent: 3,
            write_failures: 4,
            dropped_quota: 5,
            spooled_events: 10,
            spool_bytes: 858_993_460,
            spool_max_bytes: 1 << 30,
            quota_paused: false,
            quota_resets_at: None,
            oldest_undelivered_age_s: 42,
            seconds_since_last_delivery: 7,
            last_delivery_at: Some(chrono::DateTime::from_timestamp(1_760_400_000, 0).unwrap()),
            in_flight: 2,
        }
    }

    /// Every sample line of the page: `(name, labels)`.
    fn samples(page: &str) -> Vec<(String, BTreeSet<String>)> {
        page.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let series = l.rsplit_once(' ').unwrap().0;
                match series.split_once('{') {
                    None => (series.to_string(), BTreeSet::new()),
                    Some((name, labels)) => (
                        name.to_string(),
                        labels
                            .trim_end_matches('}')
                            .split(',')
                            .map(|kv| kv.split_once('=').unwrap().0.to_string())
                            .collect(),
                    ),
                }
            })
            .collect()
    }

    /// The exposed label set is exactly this, whatever the traffic: no query,
    /// user, address, workspace or database id can appear as a label.
    #[test]
    fn the_label_set_is_fixed_and_carries_no_identifiers() {
        let page = render_prometheus(Some(&snapshot()));
        let mut labels = BTreeSet::new();
        for (name, l) in samples(&page) {
            assert!(name.starts_with(PREFIX), "{name}");
            labels.extend(l);
        }
        let expected: BTreeSet<String> = ["buffer", "cause", "version"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(labels, expected);
        // Bounded cardinality: one series per name, five for the drops.
        let series = samples(&page).len();
        assert_eq!(series, 2 + 8 + 1 + 2 + 5, "{page}");
        let causes: BTreeSet<&str> = page
            .lines()
            .filter_map(|l| {
                l.split_once("cause=\"")
                    .map(|(_, r)| r.split('"').next().unwrap())
            })
            .collect();
        assert_eq!(causes, DROP_CAUSES.iter().copied().collect());
        for forbidden in [
            "query",
            "user",
            "addr",
            "ip",
            "workspace",
            "database",
            "key",
        ] {
            assert!(
                !labels.iter().any(|l| l.contains(forbidden)),
                "label containing {forbidden}"
            );
        }
    }

    #[test]
    fn the_page_has_the_figures() {
        let page = render_prometheus(Some(&snapshot()));
        for line in [
            "vericto_proxy_telemetry_enabled 1",
            "vericto_proxy_telemetry_oldest_undelivered_age_seconds 42",
            "vericto_proxy_telemetry_seconds_since_last_delivery 7",
            "vericto_proxy_telemetry_spool_bytes 858993460",
            "vericto_proxy_telemetry_spool_capacity_bytes 1073741824",
            "vericto_proxy_telemetry_spool_used_percent 80",
            "vericto_proxy_telemetry_quota_paused 0",
            "vericto_proxy_telemetry_requests_in_flight 2",
            "vericto_proxy_telemetry_last_delivery_timestamp_seconds 1760400000",
            "vericto_proxy_telemetry_delivered_total 80",
            "vericto_proxy_telemetry_dropped_total{cause=\"queue_full\"} 1",
            "vericto_proxy_telemetry_dropped_total{cause=\"evicted\"} 2",
            "vericto_proxy_telemetry_dropped_total{cause=\"permanent\"} 3",
            "vericto_proxy_telemetry_dropped_total{cause=\"write_failure\"} 4",
            "vericto_proxy_telemetry_dropped_total{cause=\"quota\"} 5",
        ] {
            assert!(page.lines().any(|l| l == line), "missing {line}\n{page}");
        }
        assert!(page.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn without_telemetry_only_the_info_is_exposed() {
        let page = render_prometheus(None);
        assert!(page.contains("buffer=\"none\""));
        assert!(page.contains("vericto_proxy_telemetry_enabled 0"));
        assert_eq!(samples(&page).len(), 2);
    }

    #[test]
    fn emf_lines_carry_deltas_under_bounded_dimensions() {
        let cfg = MetricsConfig {
            emf: true,
            proxy_name: "acme-proxy".into(),
            ..MetricsConfig::default()
        };
        let mut emf = EmfEmitter::new(&cfg, Some("0123abcd"));
        let first: serde_json::Value =
            serde_json::from_str(&emf.line(&snapshot(), 1_760_400_000_000)).unwrap();
        let aws = &first["_aws"]["CloudWatchMetrics"][0];
        assert_eq!(aws["Namespace"], "Vericto/Proxy");
        assert_eq!(
            aws["Dimensions"],
            serde_json::json!([["ProxyName"], ["ProxyName", "TaskId"]])
        );
        assert_eq!(first["_aws"]["Timestamp"], 1_760_400_000_000i64);
        assert_eq!(first["ProxyName"], "acme-proxy");
        assert_eq!(first["TaskId"], "0123abcd");
        assert_eq!(
            first["vericto_proxy_telemetry_oldest_undelivered_age_seconds"],
            42
        );
        assert_eq!(first["vericto_proxy_telemetry_spool_used_percent"], 80);
        assert_eq!(first["vericto_proxy_telemetry_delivered"], 80);
        assert_eq!(first["vericto_proxy_telemetry_dropped_loss"], 10);
        assert_eq!(first["vericto_proxy_telemetry_dropped_quota"], 5);
        // Every metric declared is present, and every name has the prefix.
        let names: Vec<&str> = aws["Metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["Name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 15);
        for n in &names {
            assert!(n.starts_with(PREFIX) && first.get(*n).is_some(), "{n}");
        }
        // The only non-metric keys are the two dimensions, the type and _aws.
        let extra: BTreeSet<&str> = first
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| !k.starts_with(PREFIX))
            .collect();
        assert_eq!(
            extra,
            ["ProxyName", "TaskId", "_aws", "type"]
                .into_iter()
                .collect()
        );

        // The next line counts only what happened since.
        let mut later = snapshot();
        later.delivered = 95;
        later.evicted_oldest = 12;
        let second: serde_json::Value =
            serde_json::from_str(&emf.line(&later, 1_760_400_060_000)).unwrap();
        assert_eq!(second["vericto_proxy_telemetry_delivered"], 15);
        assert_eq!(second["vericto_proxy_telemetry_dropped_evicted"], 10);
        assert_eq!(second["vericto_proxy_telemetry_dropped_loss"], 10);
        assert_eq!(second["vericto_proxy_telemetry_dropped_quota"], 0);
        assert!(!emf.line(&later, 0).contains('\n'), "one line per document");
    }

    #[test]
    fn the_task_dimension_can_be_turned_off() {
        let cfg = MetricsConfig {
            task_dimension: false,
            ..MetricsConfig::default()
        };
        let mut emf = EmfEmitter::new(&cfg, Some("0123abcd"));
        let v: serde_json::Value = serde_json::from_str(&emf.line(&snapshot(), 0)).unwrap();
        assert_eq!(
            v["_aws"]["CloudWatchMetrics"][0]["Dimensions"],
            serde_json::json!([["ProxyName"]])
        );
        assert!(v.get("TaskId").is_none());
    }

    #[test]
    fn config_defaults_and_overrides() {
        let none = MetricsConfig::from_vars(|_| None);
        assert_eq!(none, MetricsConfig::default());
        assert!(!none.prometheus && !none.emf, "both off by default");
        let set = MetricsConfig::from_vars(|k| {
            Some(
                match k {
                    "VERICTO_METRICS_PROMETHEUS" => "true",
                    "VERICTO_METRICS_EMF" => "1",
                    "VERICTO_METRICS_EMF_NAMESPACE" => "Acme/Proxy",
                    "VERICTO_METRICS_EMF_INTERVAL_SECS" => "1",
                    "VERICTO_METRICS_PROXY_NAME" => " acme \"db\" ",
                    "VERICTO_METRICS_EMF_TASK_DIMENSION" => "false",
                    _ => return None,
                }
                .to_string(),
            )
        });
        assert!(set.prometheus && set.emf && !set.task_dimension);
        assert_eq!(set.emf_namespace, "Acme/Proxy");
        assert_eq!(set.emf_interval, Duration::from_secs(10), "clamped");
        assert_eq!(set.proxy_name, "acmedb", "quotes and spaces removed");
    }
}
