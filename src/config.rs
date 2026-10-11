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
    /// Max events held in memory before the oldest are dropped.
    pub memory_capacity: usize,
    /// Max events flushed in one POST /ingest/events batch.
    pub batch_size: usize,
    /// How often the reporter flushes the buffer.
    pub flush_interval: Duration,
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
            batch_size: env_usize("VERICTO_TELEMETRY_BATCH_SIZE").unwrap_or(100),
            flush_interval: Duration::from_secs(
                env_u64("VERICTO_TELEMETRY_FLUSH_SECS").unwrap_or(5),
            ),
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
