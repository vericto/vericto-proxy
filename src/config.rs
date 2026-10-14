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
    /// Max undelivered events kept (memory ring, or the disk spool) before the
    /// oldest are dropped.
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
    fn from_env() -> Self {
        let d = Self::default();
        let retry_base = env_u64("VERICTO_TELEMETRY_RETRY_BASE_MS")
            .map(|ms| Duration::from_millis(ms.max(1)))
            .unwrap_or(d.retry_base);
        Self {
            max_in_flight: env_usize("VERICTO_TELEMETRY_MAX_IN_FLIGHT")
                .unwrap_or(d.max_in_flight)
                .clamp(1, 64),
            gzip: std::env::var("VERICTO_TELEMETRY_GZIP")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(d.gzip),
            retry_base,
            retry_max: env_u64("VERICTO_TELEMETRY_RETRY_MAX_SECS")
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
}

impl Default for SpoolTuning {
    fn default() -> Self {
        Self {
            queue_capacity: 2048,
            flush_every: Duration::from_millis(50),
            segment_max: 1000,
            shutdown_timeout: Duration::from_millis(5000),
        }
    }
}

impl SpoolTuning {
    fn from_env() -> Self {
        let d = Self::default();
        Self {
            queue_capacity: env_usize("VERICTO_TELEMETRY_QUEUE_CAPACITY")
                .unwrap_or(d.queue_capacity)
                .max(1),
            flush_every: env_u64("VERICTO_TELEMETRY_SPOOL_FLUSH_MS")
                .map(|ms| Duration::from_millis(ms.max(1)))
                .unwrap_or(d.flush_every),
            segment_max: env_usize("VERICTO_TELEMETRY_SPOOL_BATCH_MAX")
                .unwrap_or(d.segment_max)
                .max(1),
            shutdown_timeout: env_u64("VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS")
                .map(Duration::from_millis)
                .unwrap_or(d.shutdown_timeout),
        }
    }
}

impl ControlPlaneConfig {
    /// Build from environment. `Ok(None)` when the link is not configured; `Err`
    /// when it is, but `VERICTO_API_URL` would send the API key in clear text
    /// (see [`check_api_url`]).
    pub fn from_env() -> Result<Option<Self>, String> {
        let (Ok(api_url), Ok(api_key)) = (
            std::env::var("VERICTO_API_URL"),
            std::env::var("VERICTO_API_KEY"),
        ) else {
            return Ok(None);
        };
        if api_url.is_empty() || api_key.is_empty() {
            return Ok(None);
        }
        check_api_url(&api_url, env_flag("VERICTO_ALLOW_INSECURE_API_URL"))?;

        let rules_sync_interval = Duration::from_secs(
            // Minimum 30 seconds to avoid hammering the API.
            // Values below the minimum are silently clamped — a warning is logged
            // so operators can spot the misconfiguration without a hard failure.
            env_u64("VERICTO_RULES_SYNC_INTERVAL_SECS")
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

        let buffer_mode = match std::env::var("VERICTO_TELEMETRY_BUFFER").as_deref() {
            Ok("disk") => BufferMode::Disk,
            _ => BufferMode::Memory,
        };

        let disk_spool_path = std::env::var("VERICTO_TELEMETRY_DISK_PATH")
            .unwrap_or_else(|_| "/var/lib/vericto/spool".to_string());

        let rules_cache_path = rules_cache_path(
            std::env::var("VERICTO_RULES_CACHE_PATH").ok(),
            buffer_mode,
            &disk_spool_path,
        );

        Ok(Some(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            api_key,
            database_id: std::env::var("VERICTO_DATABASE_ID").ok(),
            rules_sync_interval,
            rules_cache_path,
            buffer_mode,
            disk_spool_path,
            memory_capacity: env_usize("VERICTO_TELEMETRY_MEMORY_CAPACITY").unwrap_or(10_000),
            batch_size: batch_size_from(env_usize("VERICTO_TELEMETRY_BATCH_SIZE")),
            flush_interval: Duration::from_secs(
                env_u64("VERICTO_TELEMETRY_FLUSH_SECS").unwrap_or(5).max(1),
            ),
            spool: SpoolTuning::from_env(),
            delivery: DeliveryTuning::from_env(),
        }))
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

fn env_flag(key: &str) -> bool {
    std::env::var(key)
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

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
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
