//! Configuration for the control-plane link to the Vericto API.
//!
//! When the proxy runs in customer infrastructure (wire-protocol mode), it
//! reports evaluations to the Vericto API and pulls its ruleset from it, both
//! over HTTPS authenticated with a workspace API key.
//!
//! All settings are optional: if `VERICTO_API_URL` / `VERICTO_API_KEY` are unset,
//! the control-plane link is disabled (the proxy still evaluates with its local
//! default ruleset — useful for dev / air-gapped deployments).

use std::path::PathBuf;
use std::time::Duration;

/// Minimum allowed rules-sync polling interval.
/// Values below this are clamped to prevent excessive API load.
const RULES_SYNC_MIN_SECS: u64 = 30;

/// Where telemetry events are buffered before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMode {
    /// In-memory ring buffer (default). Lost on restart; zero disk footprint.
    Memory,
    /// On-disk spool. Survives restarts and long API outages.
    Disk,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub api_url: String,
    pub api_key: String,
    pub database_id: Option<String>,
    /// How often to poll GET /sync/rules.
    pub rules_sync_interval: Duration,
    /// Where the last-good `/sync/rules` response is kept so a restart during a
    /// control-plane outage resumes with it (src/tcp/rules_cache.rs). `None` = off.
    pub rules_cache_path: Option<PathBuf>,
    /// Telemetry buffering strategy.
    pub buffer_mode: BufferMode,
    /// Spool directory when buffer_mode = Disk.
    pub disk_spool_path: String,
    /// Max undelivered events kept in the memory ring before the oldest are
    /// dropped. `VERICTO_TELEMETRY_MEMORY_CAPACITY`, default 10,000. The disk spool
    /// is bounded by [`SpoolTuning::max_bytes`] instead (since 4.12.0), and by this
    /// count only when the variable is set (see [`SpoolTuning::max_events`]).
    pub memory_capacity: usize,
    /// Max events in one POST /ingest/events batch, and the number of pending
    /// events that triggers a send. `VERICTO_TELEMETRY_BATCH_SIZE`, default 500,
    /// at most [`MAX_INGEST_BATCH`].
    pub batch_size: usize,
    /// Longest the oldest pending event waits before a partial batch is sent.
    /// `VERICTO_TELEMETRY_FLUSH_SECS`, default 5.
    pub flush_interval: Duration,
    /// How the disk spool is fed and how long shutdown may take to flush it.
    pub spool: SpoolTuning,
    /// How batches are sent: concurrency, compression, retry backoff.
    pub delivery: DeliveryTuning,
}

/// The most events `/api/v1/ingest/events` accepts in one request: a larger batch
/// is refused (400) as a whole, so `VERICTO_TELEMETRY_BATCH_SIZE` is capped here.
pub const MAX_INGEST_BATCH: usize = 500;

/// How the reporter sends batches (since 4.11.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryTuning {
    /// POSTs in flight at once. `VERICTO_TELEMETRY_MAX_IN_FLIGHT`, default 4.
    pub max_in_flight: usize,
    /// Send the body gzip-compressed (`Content-Encoding: gzip`).
    /// `VERICTO_TELEMETRY_GZIP`, default true. Turned off for the rest of the
    /// process if the API refuses a compressed body that it accepts uncompressed.
    pub gzip: bool,
    /// First wait after a retryable failure; doubles on each consecutive one.
    /// `VERICTO_TELEMETRY_RETRY_BASE_MS`, default 1000.
    pub retry_base: Duration,
    /// Longest wait between retries. `VERICTO_TELEMETRY_RETRY_MAX_SECS`, default 60.
    pub retry_max: Duration,
}

impl Default for DeliveryTuning {
    fn default() -> Self {
        Self {
            max_in_flight: 4,
            gzip: true,
            retry_base: Duration::from_millis(1000),
            retry_max: Duration::from_secs(60),
        }
    }
}

impl DeliveryTuning {
    fn from_lookup(env: Lookup<'_>) -> Self {
        let d = Self::default();
        let retry_base = env_u64(env, "VERICTO_TELEMETRY_RETRY_BASE_MS")
            .map(|ms| Duration::from_millis(ms.max(1)))
            .unwrap_or(d.retry_base);
        Self {
            max_in_flight: env_usize(env, "VERICTO_TELEMETRY_MAX_IN_FLIGHT")
                .unwrap_or(d.max_in_flight)
                .clamp(1, 64),
            gzip: env("VERICTO_TELEMETRY_GZIP")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(d.gzip),
            retry_base,
            retry_max: env_u64(env, "VERICTO_TELEMETRY_RETRY_MAX_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.retry_max)
                .max(retry_base),
        }
    }
}

/// `VERICTO_TELEMETRY_BATCH_SIZE`, between 1 and [`MAX_INGEST_BATCH`]; a larger
/// value is lowered with a warning rather than having every batch refused.
fn batch_size_from(value: Option<usize>) -> usize {
    match value {
        Some(v) if v > MAX_INGEST_BATCH => {
            tracing::warn!(
                configured = v,
                maximum = MAX_INGEST_BATCH,
                "VERICTO_TELEMETRY_BATCH_SIZE is above what the API accepts in one request; using the maximum"
            );
            MAX_INGEST_BATCH
        }
        Some(v) => v.max(1),
        None => MAX_INGEST_BATCH,
    }
}

/// Tuning of the asynchronous telemetry pipeline (since 4.9.1).
///
/// With `BufferMode::Disk` the query path no longer touches the spool: it hands
/// the event to a bounded in-memory channel and a background writer persists the
/// channel's contents in batches. These are its knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolTuning {
    /// Events the channel in front of the disk writer holds before new events
    /// are dropped (counted and logged; the query is never held back).
    /// `VERICTO_TELEMETRY_QUEUE_CAPACITY`, default 2048.
    pub queue_capacity: usize,
    /// Longest an event waits in the channel before its batch is written and
    /// fsynced. A batch is also written as soon as it holds `segment_max`
    /// events. `VERICTO_TELEMETRY_SPOOL_FLUSH_MS`, default 50.
    pub flush_every: Duration,
    /// Most events written in one segment (one write and fsync).
    /// `VERICTO_TELEMETRY_SPOOL_BATCH_MAX`, default 1000.
    pub segment_max: usize,
    /// On SIGTERM/SIGINT, how long the proxy may spend writing what is still
    /// queued to the spool and delivering what it can before it exits.
    /// `VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS`, default 5000.
    pub shutdown_timeout: Duration,
    /// Most bytes of spool files kept on disk before the oldest are dropped
    /// (since 4.12.0). `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`, default 1 GiB
    /// ([`crate::telemetry::queue::DEFAULT_SPOOL_MAX_BYTES`]), at least 1 MiB.
    pub max_bytes: u64,
    /// Most undelivered events kept on disk, on top of `max_bytes`.
    /// `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS`; unset, `VERICTO_TELEMETRY_MEMORY_CAPACITY`
    /// when that is set (it bounded the spool up to 4.11, so a deployment that set
    /// it keeps its bound); `None` = bounded by bytes only.
    pub max_events: Option<usize>,
}

/// The smallest `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` accepted: one full segment of
/// 1,000 events at the largest event the proxy reports is a few MiB, and a smaller
/// bound would evict every segment as it is written.
pub const SPOOL_MIN_BYTES: u64 = 1024 * 1024;

impl Default for SpoolTuning {
    fn default() -> Self {
        Self {
            queue_capacity: 2048,
            flush_every: Duration::from_millis(50),
            segment_max: 1000,
            shutdown_timeout: Duration::from_millis(5000),
            max_bytes: crate::telemetry::queue::DEFAULT_SPOOL_MAX_BYTES,
            max_events: None,
        }
    }
}

impl SpoolTuning {
    fn from_lookup(env: Lookup<'_>) -> Self {
        let d = Self::default();
        Self {
            queue_capacity: env_usize(env, "VERICTO_TELEMETRY_QUEUE_CAPACITY")
                .unwrap_or(d.queue_capacity)
                .max(1),
            flush_every: env_u64(env, "VERICTO_TELEMETRY_SPOOL_FLUSH_MS")
                .map(|ms| Duration::from_millis(ms.max(1)))
                .unwrap_or(d.flush_every),
            segment_max: env_usize(env, "VERICTO_TELEMETRY_SPOOL_BATCH_MAX")
                .unwrap_or(d.segment_max)
                .max(1),
            shutdown_timeout: env_u64(env, "VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS")
                .map(Duration::from_millis)
                .unwrap_or(d.shutdown_timeout),
            max_bytes: env_u64(env, "VERICTO_TELEMETRY_SPOOL_MAX_BYTES")
                .map(|b| b.max(SPOOL_MIN_BYTES))
                .unwrap_or(d.max_bytes),
            max_events: spool_max_events(
                env_usize(env, "VERICTO_TELEMETRY_SPOOL_MAX_EVENTS"),
                env_usize(env, "VERICTO_TELEMETRY_MEMORY_CAPACITY"),
            ),
        }
    }
}

/// The disk spool's event bound: `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS`, else
/// `VERICTO_TELEMETRY_MEMORY_CAPACITY` when set, else none (bytes only).
fn spool_max_events(explicit: Option<usize>, memory_capacity: Option<usize>) -> Option<usize> {
    explicit.or(memory_capacity).map(|n| n.max(1))
}

impl ControlPlaneConfig {
    /// Build from environment. `Ok(None)` when the link is not configured; `Err`
    /// when it is, but `VERICTO_API_URL` would send the API key in clear text
    /// (see [`check_api_url`]).
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// [`Self::from_env`] reading each variable through `env`, so tests can pass
    /// their own values without touching the process environment.
    fn from_lookup(env: Lookup<'_>) -> Result<Option<Self>, String> {
        let (Some(api_url), Some(api_key)) = (env("VERICTO_API_URL"), env("VERICTO_API_KEY"))
        else {
            return Ok(None);
        };
        if api_url.is_empty() || api_key.is_empty() {
            return Ok(None);
        }
        check_api_url(&api_url, env_flag(env, "VERICTO_ALLOW_INSECURE_API_URL"))?;

        let rules_sync_interval = Duration::from_secs(
            // Minimum 30 seconds to avoid hammering the API.
            // Values below the minimum are silently clamped — a warning is logged
            // so operators can spot the misconfiguration without a hard failure.
            env_u64(env, "VERICTO_RULES_SYNC_INTERVAL_SECS")
                .map(|v| {
                    if v < RULES_SYNC_MIN_SECS {
                        tracing::warn!(
                            configured = v,
                            minimum = RULES_SYNC_MIN_SECS,
                            "VERICTO_RULES_SYNC_INTERVAL_SECS is below the minimum — \
                             clamping to {} seconds",
                            RULES_SYNC_MIN_SECS
                        );
                        RULES_SYNC_MIN_SECS
                    } else {
                        v
                    }
                })
                .unwrap_or(300), // default: 5 min
        );

        let buffer_mode = buffer_mode_from(env("VERICTO_TELEMETRY_BUFFER").as_deref())?;

        let disk_spool_path = env("VERICTO_TELEMETRY_DISK_PATH")
            .unwrap_or_else(|| "/var/lib/vericto/spool".to_string());

        let rules_cache_path = rules_cache_path(
            env("VERICTO_RULES_CACHE_PATH"),
            buffer_mode,
            &disk_spool_path,
        );

        Ok(Some(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            api_key,
            database_id: env("VERICTO_DATABASE_ID"),
            rules_sync_interval,
            rules_cache_path,
            buffer_mode,
            disk_spool_path,
            memory_capacity: env_usize(env, "VERICTO_TELEMETRY_MEMORY_CAPACITY").unwrap_or(10_000),
            batch_size: batch_size_from(env_usize(env, "VERICTO_TELEMETRY_BATCH_SIZE")),
            flush_interval: Duration::from_secs(
                env_u64(env, "VERICTO_TELEMETRY_FLUSH_SECS")
                    .unwrap_or(5)
                    .max(1),
            ),
            spool: SpoolTuning::from_lookup(env),
            delivery: DeliveryTuning::from_lookup(env),
        }))
    }
}

/// Parses `VERICTO_TELEMETRY_BUFFER`: `memory` (the default, also when unset or
/// empty) or `disk`, in any case and with surrounding whitespace ignored.
///
/// Any other value is a startup error, as for `VERICTO_TELEMETRY_SPOOL_SUBDIR`:
/// up to 4.12.1 a value other than exactly `disk` (`DISK`, `Disk`, `disc`)
/// silently selected the memory buffer, so an operator who asked for a durable
/// spool got none, and no rules cache either, with nothing in the log.
fn buffer_mode_from(raw: Option<&str>) -> Result<BufferMode, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(BufferMode::Memory),
        Some(v) if v.eq_ignore_ascii_case("memory") => Ok(BufferMode::Memory),
        Some(v) if v.eq_ignore_ascii_case("disk") => Ok(BufferMode::Disk),
        Some(v) => Err(format!(
            "VERICTO_TELEMETRY_BUFFER={v:?} is not supported: use `memory` (the default) \
             or `disk` (a durable spool at VERICTO_TELEMETRY_DISK_PATH)"
        )),
    }
}

/// Every request to the control plane carries the workspace API key, so the URL
/// must be `https://`. Plain `http://` is accepted only for a loopback host (a
/// local stand-in for the API) or when `VERICTO_ALLOW_INSECURE_API_URL` is set,
/// for a development stack on a private network.
pub fn check_api_url(api_url: &str, allow_insecure: bool) -> Result<(), String> {
    let url = reqwest::Url::parse(api_url)
        .map_err(|e| format!("VERICTO_API_URL is not a valid URL ({e})"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure || is_loopback(&url) => Ok(()),
        "http" => Err(
            "VERICTO_API_URL uses http://, which would send the API key in clear text. \
             Use https://, or set VERICTO_ALLOW_INSECURE_API_URL=true for a development stack."
                .to_string(),
        ),
        other => Err(format!(
            "VERICTO_API_URL must be an https:// URL, not {other}://"
        )),
    }
}

/// `VERICTO_WIRE_PROTOCOL` names the database protocol this proxy speaks. A
/// Snowflake value is a configuration error, not a fallback: Snowflake has no
/// TCP wire protocol a proxy could sit on (clients reach it over HTTPS), so the
/// proxy would otherwise start as a Postgres proxy in front of nothing it can
/// serve. Snowflake SQL is checked through the HTTP API, the CLI or MCP instead.
pub fn check_wire_protocol(value: &str) -> Result<(), String> {
    if value.trim().eq_ignore_ascii_case("snowflake") {
        return Err(
            "VERICTO_WIRE_PROTOCOL=snowflake is not supported: Snowflake has no TCP wire \
             protocol for vericto-proxy to front. Check Snowflake SQL through the Vericto \
             HTTP API, the CLI or MCP instead, and set VERICTO_WIRE_PROTOCOL to postgres or mysql \
             for a proxy."
                .to_string(),
        );
    }
    Ok(())
}

fn is_loopback(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// A redirect policy for requests that carry the API key: follow a redirect
/// only within the same origin (scheme, host and port). reqwest strips
/// `Authorization` on a cross-host redirect, but not a custom header such as
/// `X-API-Key`, and by default it also follows https → http.
pub fn same_origin_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let same_origin = attempt
            .previous()
            .first()
            .is_some_and(|first| first.origin() == attempt.url().origin());
        if attempt.previous().len() > 5 {
            attempt.error("too many redirects")
        } else if same_origin {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// Reads one configuration variable: the process environment in production, a
/// fixed map in tests.
type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn env_flag(env: Lookup<'_>, key: &str) -> bool {
    env(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// File name of the rules cache inside the spool dir when `VERICTO_TELEMETRY_BUFFER=disk`.
/// Hidden and without a `.json` extension, so the spool (which only reads `*.json`)
/// never mistakes it for a telemetry event.
pub const RULES_CACHE_FILE: &str = ".rules-cache";

/// Resolves the rules-cache path. An explicit `VERICTO_RULES_CACHE_PATH` wins, and an
/// empty one turns the cache off. Unset, it follows the telemetry buffer: an operator
/// who chose `disk` has already mounted durable storage at the spool dir precisely so
/// state survives a restart, so the cache defaults on and lives there (the image's
/// non-root user can't write anywhere else under /var/lib). With the in-memory buffer
/// there may be no writable volume at all, so it stays off rather than logging a write
/// failure on every rules change.
fn rules_cache_path(
    explicit: Option<String>,
    buffer_mode: BufferMode,
    disk_spool_path: &str,
) -> Option<PathBuf> {
    match explicit {
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(PathBuf::from(p)),
        None if buffer_mode == BufferMode::Disk => {
            Some(PathBuf::from(disk_spool_path).join(RULES_CACHE_FILE))
        }
        None => None,
    }
}

fn env_u64(env: Lookup<'_>, key: &str) -> Option<u64> {
    env(key).and_then(|v| v.parse().ok())
}

fn env_usize(env: Lookup<'_>, key: &str) -> Option<usize> {
    env(key).and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API refuses a batch of more than 500 events as a whole (400, dropped),
    /// so a larger setting is lowered instead of losing every batch.
    #[test]
    fn telemetry_batch_size_defaults_to_and_is_capped_at_the_api_limit() {
        assert_eq!(batch_size_from(None), 500);
        assert_eq!(batch_size_from(Some(100)), 100);
        assert_eq!(batch_size_from(Some(5_000)), MAX_INGEST_BATCH);
        assert_eq!(batch_size_from(Some(0)), 1);
    }

    #[test]
    fn spool_is_bounded_by_bytes_unless_an_event_count_is_set() {
        let d = SpoolTuning::default();
        assert_eq!(d.max_bytes, 1024 * 1024 * 1024);
        assert_eq!(d.max_events, None);
        assert_eq!(spool_max_events(None, None), None);
        // A deployment that bounded its spool with the memory capacity keeps it.
        assert_eq!(spool_max_events(None, Some(10_000)), Some(10_000));
        assert_eq!(spool_max_events(Some(500_000), Some(10_000)), Some(500_000));
        assert_eq!(spool_max_events(Some(0), None), Some(1));
    }

    #[test]
    fn delivery_defaults() {
        let d = DeliveryTuning::default();
        assert_eq!(d.max_in_flight, 4);
        assert!(d.gzip);
        assert_eq!(d.retry_base, Duration::from_secs(1));
        assert_eq!(d.retry_max, Duration::from_secs(60));
    }

    #[test]
    fn api_url_must_be_https_unless_loopback_or_allowed() {
        assert!(check_api_url("https://api.vericto.com", false).is_ok());
        assert!(check_api_url("http://127.0.0.1:4000", false).is_ok());
        assert!(check_api_url("http://localhost:4000", false).is_ok());
        assert!(check_api_url("http://[::1]:4000", false).is_ok());
        assert!(check_api_url("http://api.vericto.com", false).is_err());
        assert!(check_api_url("http://api:4000", false).is_err());
        assert!(check_api_url("http://api:4000", true).is_ok());
        assert!(check_api_url("ftp://api.vericto.com", true).is_err());
        assert!(check_api_url("api.vericto.com", false).is_err());
    }

    #[test]
    fn snowflake_wire_protocol_is_a_config_error() {
        for value in ["snowflake", "Snowflake", " SNOWFLAKE "] {
            let err = check_wire_protocol(value).expect_err(value);
            assert!(err.contains("Snowflake has no TCP wire"), "{err}");
            assert!(err.contains("HTTP API, the CLI or MCP"), "{err}");
        }
        for value in ["postgres", "mysql"] {
            assert!(check_wire_protocol(value).is_ok(), "{value}");
        }
    }

    /// The API key never follows a redirect to another origin: the client
    /// stops at the 3xx instead.
    #[tokio::test]
    async fn api_key_is_not_sent_across_origins_on_redirect() {
        use axum::{Router, http::HeaderMap, routing::get};
        use std::sync::{Arc, Mutex};

        let leaked = Arc::new(Mutex::new(false));
        let seen = leaked.clone();
        let other = Router::new().route(
            "/",
            get(move |headers: HeaderMap| {
                let seen = seen.clone();
                async move {
                    *seen.lock().unwrap() = headers.contains_key("x-api-key");
                    "ok"
                }
            }),
        );
        let other_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_url = format!("http://{}/", other_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(other_listener, other).await });

        let target = other_url.clone();
        let api = Router::new().route(
            "/",
            get(move || {
                let target = target.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }),
        );
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_url = format!("http://{}/", api_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(api_listener, api).await });

        let client = reqwest::Client::builder()
            .redirect(same_origin_redirects())
            .build()
            .unwrap();
        let res = client
            .get(&api_url)
            .header("X-API-Key", "vtro_test")
            .send()
            .await
            .unwrap();
        assert!(
            res.status().is_redirection(),
            "a cross-origin redirect is not followed"
        );
        assert!(
            !*leaked.lock().unwrap(),
            "the API key reached another origin"
        );
    }

    /// Builds a configuration from `vars` only, never the process environment.
    fn from_vars(vars: &[(&str, &str)]) -> Result<Option<ControlPlaneConfig>, String> {
        let map: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ControlPlaneConfig::from_lookup(&move |key| map.get(key).cloned())
    }

    const LINK: [(&str, &str); 2] = [
        ("VERICTO_API_URL", "https://api.vericto.com/"),
        ("VERICTO_API_KEY", "vtro_test"),
    ];

    /// Without both the URL and the key the link is off, and that is not an error:
    /// the proxy runs on its built-in ruleset (dev, air-gapped).
    #[test]
    fn the_link_is_off_unless_both_url_and_key_are_set() {
        assert!(from_vars(&[]).unwrap().is_none());
        assert!(from_vars(&LINK[..1]).unwrap().is_none());
        assert!(from_vars(&LINK[1..]).unwrap().is_none());
        assert!(
            from_vars(&[("VERICTO_API_URL", ""), ("VERICTO_API_KEY", "vtro_test")])
                .unwrap()
                .is_none()
        );
        assert!(
            from_vars(&[("VERICTO_API_URL", "https://x"), ("VERICTO_API_KEY", "")])
                .unwrap()
                .is_none()
        );
    }

    /// Only the URL and the key set: every other setting takes its documented default.
    #[test]
    fn a_minimal_link_uses_the_documented_defaults() {
        let cfg = from_vars(&LINK).unwrap().expect("link configured");
        assert_eq!(
            cfg.api_url, "https://api.vericto.com",
            "trailing slash trimmed"
        );
        assert_eq!(cfg.api_key, "vtro_test");
        assert_eq!(cfg.database_id, None);
        assert_eq!(cfg.rules_sync_interval, Duration::from_secs(300));
        assert_eq!(cfg.buffer_mode, BufferMode::Memory);
        assert_eq!(cfg.disk_spool_path, "/var/lib/vericto/spool");
        assert_eq!(
            cfg.rules_cache_path, None,
            "no cache with the memory buffer"
        );
        assert_eq!(cfg.memory_capacity, 10_000);
        assert_eq!(cfg.batch_size, MAX_INGEST_BATCH);
        assert_eq!(cfg.flush_interval, Duration::from_secs(5));
        assert_eq!(cfg.spool, SpoolTuning::default());
        assert_eq!(cfg.delivery, DeliveryTuning::default());
    }

    /// An http:// API URL would send the key in clear text: refused at startup
    /// unless the operator opts in, and a URL that does not parse is refused too.
    #[test]
    fn an_insecure_or_invalid_api_url_is_a_startup_error() {
        let insecure = [
            ("VERICTO_API_URL", "http://api.internal:4000"),
            ("VERICTO_API_KEY", "vtro_test"),
        ];
        let err = from_vars(&insecure).expect_err("http:// to a remote host");
        assert!(err.contains("clear text"), "{err}");
        assert!(!err.contains("vtro_test"), "the key is never echoed: {err}");

        let mut allowed = insecure.to_vec();
        allowed.push(("VERICTO_ALLOW_INSECURE_API_URL", "TRUE"));
        assert!(from_vars(&allowed).unwrap().is_some());

        let mut not_a_flag = insecure.to_vec();
        not_a_flag.push(("VERICTO_ALLOW_INSECURE_API_URL", "maybe"));
        assert!(from_vars(&not_a_flag).is_err(), "only 1/true/yes opt in");

        let err = from_vars(&[
            ("VERICTO_API_URL", "not a url"),
            ("VERICTO_API_KEY", "vtro_test"),
        ])
        .expect_err("unparseable URL");
        assert!(err.contains("not a valid URL"), "{err}");
    }

    /// Every tuning variable set: each one reaches its field.
    #[test]
    fn every_setting_is_read_from_its_variable() {
        let mut vars = LINK.to_vec();
        vars.extend([
            ("VERICTO_DATABASE_ID", "db-123"),
            ("VERICTO_RULES_SYNC_INTERVAL_SECS", "120"),
            ("VERICTO_TELEMETRY_BUFFER", "disk"),
            ("VERICTO_TELEMETRY_DISK_PATH", "/data/spool"),
            ("VERICTO_TELEMETRY_MEMORY_CAPACITY", "2000"),
            ("VERICTO_TELEMETRY_BATCH_SIZE", "50"),
            ("VERICTO_TELEMETRY_FLUSH_SECS", "9"),
            ("VERICTO_TELEMETRY_QUEUE_CAPACITY", "64"),
            ("VERICTO_TELEMETRY_SPOOL_FLUSH_MS", "10"),
            ("VERICTO_TELEMETRY_SPOOL_BATCH_MAX", "25"),
            ("VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS", "750"),
            ("VERICTO_TELEMETRY_SPOOL_MAX_BYTES", "8388608"),
            ("VERICTO_TELEMETRY_SPOOL_MAX_EVENTS", "40000"),
            ("VERICTO_TELEMETRY_MAX_IN_FLIGHT", "8"),
            ("VERICTO_TELEMETRY_GZIP", "no"),
            ("VERICTO_TELEMETRY_RETRY_BASE_MS", "250"),
            ("VERICTO_TELEMETRY_RETRY_MAX_SECS", "30"),
        ]);
        let cfg = from_vars(&vars).unwrap().unwrap();
        assert_eq!(cfg.database_id.as_deref(), Some("db-123"));
        assert_eq!(cfg.rules_sync_interval, Duration::from_secs(120));
        assert_eq!(cfg.buffer_mode, BufferMode::Disk);
        assert_eq!(cfg.disk_spool_path, "/data/spool");
        assert_eq!(
            cfg.rules_cache_path,
            Some(PathBuf::from("/data/spool").join(RULES_CACHE_FILE)),
            "the disk buffer turns the rules cache on, inside the spool"
        );
        assert_eq!(cfg.memory_capacity, 2000);
        assert_eq!(cfg.batch_size, 50);
        assert_eq!(cfg.flush_interval, Duration::from_secs(9));
        assert_eq!(
            cfg.spool,
            SpoolTuning {
                queue_capacity: 64,
                flush_every: Duration::from_millis(10),
                segment_max: 25,
                shutdown_timeout: Duration::from_millis(750),
                max_bytes: 8 * 1024 * 1024,
                max_events: Some(40_000),
            }
        );
        assert_eq!(
            cfg.delivery,
            DeliveryTuning {
                max_in_flight: 8,
                gzip: false,
                retry_base: Duration::from_millis(250),
                retry_max: Duration::from_secs(30),
            }
        );
    }

    /// Out-of-range values are clamped to something that works rather than
    /// failing startup or hammering the API; unparseable ones use the default.
    #[test]
    fn out_of_range_settings_are_clamped_and_garbage_uses_the_default() {
        let mut vars = LINK.to_vec();
        vars.extend([
            ("VERICTO_RULES_SYNC_INTERVAL_SECS", "1"),
            ("VERICTO_TELEMETRY_BATCH_SIZE", "100000"),
            ("VERICTO_TELEMETRY_FLUSH_SECS", "0"),
            ("VERICTO_TELEMETRY_QUEUE_CAPACITY", "0"),
            ("VERICTO_TELEMETRY_SPOOL_FLUSH_MS", "0"),
            ("VERICTO_TELEMETRY_SPOOL_BATCH_MAX", "0"),
            ("VERICTO_TELEMETRY_SPOOL_MAX_BYTES", "1"),
            ("VERICTO_TELEMETRY_MAX_IN_FLIGHT", "1000"),
            ("VERICTO_TELEMETRY_GZIP", "yes please"),
            ("VERICTO_TELEMETRY_RETRY_BASE_MS", "0"),
            ("VERICTO_TELEMETRY_RETRY_MAX_SECS", "0"),
            ("VERICTO_TELEMETRY_MEMORY_CAPACITY", "lots"),
            ("VERICTO_RULES_CACHE_PATH", ""),
        ]);
        let cfg = from_vars(&vars).unwrap().unwrap();
        assert_eq!(
            cfg.rules_sync_interval,
            Duration::from_secs(RULES_SYNC_MIN_SECS)
        );
        assert_eq!(cfg.batch_size, MAX_INGEST_BATCH);
        assert_eq!(cfg.flush_interval, Duration::from_secs(1));
        assert_eq!(cfg.spool.queue_capacity, 1);
        assert_eq!(cfg.spool.flush_every, Duration::from_millis(1));
        assert_eq!(cfg.spool.segment_max, 1);
        assert_eq!(cfg.spool.max_bytes, SPOOL_MIN_BYTES);
        assert_eq!(cfg.spool.max_events, None, "unparseable capacity is unset");
        assert_eq!(cfg.memory_capacity, 10_000);
        assert_eq!(cfg.delivery.max_in_flight, 64);
        assert!(cfg.delivery.gzip, "only 0/false/no turn gzip off");
        assert_eq!(cfg.delivery.retry_base, Duration::from_millis(1));
        assert_eq!(
            cfg.delivery.retry_max,
            Duration::from_millis(1),
            "the longest wait is never below the first one"
        );
        assert_eq!(cfg.rules_cache_path, None);
    }

    /// The buffer is chosen case-insensitively, with whitespace trimmed; unset or
    /// empty is the documented default (memory).
    #[test]
    fn the_buffer_mode_ignores_case_and_whitespace() {
        for (raw, want) in [
            ("disk", BufferMode::Disk),
            ("DISK", BufferMode::Disk),
            ("Disk", BufferMode::Disk),
            ("  disk\n", BufferMode::Disk),
            ("memory", BufferMode::Memory),
            ("MEMORY", BufferMode::Memory),
            (" Memory ", BufferMode::Memory),
            ("", BufferMode::Memory),
            ("   ", BufferMode::Memory),
        ] {
            let mut vars = LINK.to_vec();
            vars.push(("VERICTO_TELEMETRY_BUFFER", raw));
            let cfg = from_vars(&vars).unwrap().unwrap();
            assert_eq!(cfg.buffer_mode, want, "VERICTO_TELEMETRY_BUFFER={raw:?}");
        }
        assert_eq!(buffer_mode_from(None), Ok(BufferMode::Memory));

        // DISK used to select memory silently: no spool and no rules cache.
        let mut vars = LINK.to_vec();
        vars.push(("VERICTO_TELEMETRY_BUFFER", "DISK"));
        let cfg = from_vars(&vars).unwrap().unwrap();
        assert_eq!(
            cfg.rules_cache_path,
            Some(PathBuf::from("/var/lib/vericto/spool").join(RULES_CACHE_FILE)),
            "an upper-case DISK turns the rules cache on too"
        );
    }

    /// A buffer value the proxy cannot honour fails startup with the variable and
    /// the accepted values named, instead of silently using the memory buffer.
    #[test]
    fn an_unknown_buffer_mode_is_a_startup_error() {
        for raw in ["disc", "file", "durable", "disk,memory", "1"] {
            let mut vars = LINK.to_vec();
            vars.push(("VERICTO_TELEMETRY_BUFFER", raw));
            let err = from_vars(&vars).expect_err(raw);
            assert!(err.contains("VERICTO_TELEMETRY_BUFFER"), "{err}");
            assert!(err.contains(&format!("{raw:?}")), "{err}");
            assert!(err.contains("`memory`") && err.contains("`disk`"), "{err}");
        }
        // Without the control-plane link there is no telemetry, so the buffer
        // setting is not read and cannot fail startup.
        assert!(
            from_vars(&[("VERICTO_TELEMETRY_BUFFER", "disc")])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rules_cache_follows_the_buffer_mode_unless_set() {
        let spool = "/var/lib/vericto/spool";
        assert_eq!(rules_cache_path(None, BufferMode::Memory, spool), None);
        assert_eq!(
            rules_cache_path(None, BufferMode::Disk, spool),
            Some(PathBuf::from("/var/lib/vericto/spool/.rules-cache"))
        );
        assert_eq!(
            rules_cache_path(Some("/data/rules.json".into()), BufferMode::Memory, spool),
            Some(PathBuf::from("/data/rules.json"))
        );
        // Empty disables it, even with the disk buffer.
        assert_eq!(
            rules_cache_path(Some(" ".into()), BufferMode::Disk, spool),
            None
        );
    }
}
