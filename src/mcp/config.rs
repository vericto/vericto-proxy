// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Configuration of `vericto-proxy mcp` (design "MCP execution modes" §5.5).
//!
//! Every setting is an environment variable and, for the ones an MCP client
//! configuration usually passes, a `--flag` of the subcommand (`--transport
//! http` is `VERICTO_MCP_TRANSPORT=http`). A flag wins over the variable.
//!
//! The database credential is read once into [`DatabaseTarget`], whose `Debug`
//! never shows the password, and is never logged or echoed back to the agent.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::tcp::upstream::UpstreamTlsMode;

/// Reads one setting (flags first, then the environment).
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The flags `vericto-proxy mcp` accepts, and the variable each one sets.
pub const FLAGS: &[(&str, &str)] = &[
    ("transport", "VERICTO_MCP_TRANSPORT"),
    ("listen", "VERICTO_MCP_LISTEN"),
    ("database-url-file", "VERICTO_MCP_DATABASE_URL_FILE"),
    ("tiers", "VERICTO_MCP_TIERS"),
    ("max-rows", "VERICTO_MCP_MAX_ROWS"),
    ("max-rows-cap", "VERICTO_MCP_MAX_ROWS_CAP"),
    ("max-result-bytes", "VERICTO_MCP_MAX_RESULT_BYTES"),
    ("max-cell-bytes", "VERICTO_MCP_MAX_CELL_BYTES"),
    ("statement-timeout-ms", "VERICTO_MCP_STATEMENT_TIMEOUT_MS"),
    (
        "statement-timeout-cap-ms",
        "VERICTO_MCP_STATEMENT_TIMEOUT_CAP_MS",
    ),
    ("lock-timeout-ms", "VERICTO_MCP_LOCK_TIMEOUT_MS"),
    ("pool-size", "VERICTO_MCP_POOL_SIZE"),
    ("pool-idle-secs", "VERICTO_MCP_POOL_IDLE_SECS"),
    ("require-control-plane", "VERICTO_MCP_REQUIRE_CONTROL_PLANE"),
    ("result-detail", "VERICTO_MCP_RESULT_DETAIL"),
    ("search-path", "VERICTO_MCP_SEARCH_PATH"),
    ("allow-plaintext-http", "VERICTO_MCP_ALLOW_PLAINTEXT_HTTP"),
    ("allow-plaintext-db", "VERICTO_MCP_ALLOW_PLAINTEXT_DB"),
    ("allowed-hosts", "VERICTO_MCP_ALLOWED_HOSTS"),
    ("allowed-origins", "VERICTO_MCP_ALLOWED_ORIGINS"),
    ("auth-tokens-file", "VERICTO_MCP_AUTH_TOKENS_FILE"),
    ("database-id", "VERICTO_DATABASE_ID"),
];

/// What the command line asked for.
#[derive(Debug, Default)]
pub struct Args {
    /// Settings given as flags, by variable name.
    pub settings: HashMap<String, String>,
    pub help: bool,
    pub version: bool,
}

/// Parses the arguments after `mcp`: `--flag value`, `--flag=value`, a bare
/// `--allow-*` / `--require-*` flag (which means `true`), `--help`, `--version`.
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        match arg.as_str() {
            "-h" | "--help" | "help" => {
                out.help = true;
                continue;
            }
            "-V" | "--version" => {
                out.version = true;
                continue;
            }
            _ => {}
        }
        let Some(flag) = arg.strip_prefix("--") else {
            return Err(format!(
                "unexpected argument {arg:?}; see `vericto-proxy mcp --help`"
            ));
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        if name == "database-url" {
            return Err(
                "--database-url is not accepted: a password on the command line is visible to \
                 every user of the machine (`ps`). Put the URL in a file with mode 0600 and pass \
                 --database-url-file, or set VERICTO_MCP_DATABASE_URL"
                    .to_string(),
            );
        }
        let Some((_, var)) = FLAGS.iter().find(|(f, _)| *f == name) else {
            return Err(format!(
                "unknown flag --{name}; see `vericto-proxy mcp --help`"
            ));
        };
        let boolean = name.starts_with("allow-") || name.starts_with("require-");
        let value = match inline {
            Some(v) => v,
            None if boolean
                && args
                    .get(i)
                    .is_none_or(|next| next.starts_with("--") || !is_bool_word(next)) =>
            {
                "true".to_string()
            }
            None => {
                let Some(v) = args.get(i) else {
                    return Err(format!("--{name} needs a value"));
                };
                i += 1;
                v.clone()
            }
        };
        out.settings.insert((*var).to_string(), value);
    }
    Ok(out)
}

fn is_bool_word(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
    )
}

/// The help text of `vericto-proxy mcp --help` (to stderr: stdout is the
/// protocol in stdio mode).
pub fn help_text() -> String {
    let mut s = String::from(
        "vericto-proxy mcp: an MCP server that checks and runs SQL on one PostgreSQL database\n\
         (Proxy mode). The agent gets execute_sql, describe_schema, check_sql and whoami, and\n\
         no database credential. See docs/MCP.md.\n\n\
         Usage: vericto-proxy mcp [--flag value]...\n\nFlags (each is also an environment variable):\n",
    );
    for (flag, var) in FLAGS {
        s.push_str(&format!("  --{flag:<26} {var}\n"));
    }
    s.push_str(
        "\nThe database: VERICTO_MCP_DATABASE_URL_FILE (preferred), VERICTO_MCP_DATABASE_URL, or\n\
         UPSTREAM_HOST/UPSTREAM_PORT/UPSTREAM_USER/UPSTREAM_PASSWORD_FILE/UPSTREAM_DBNAME.\n\
         The control plane (optional): VERICTO_API_KEY and VERICTO_DATABASE_ID (VERICTO_API_URL\n\
         defaults to https://api.vericto.com when a key is set). With none of the three set the\n\
         server runs locally on the built-in ruleset and reports nothing; HTTP mode then needs\n\
         VERICTO_MCP_AUTH_TOKENS_FILE.\n",
    );
    s
}

/// `stdio` (default) or `http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Stdio,
    Http,
}

/// How database error messages reach the agent (design §15, T5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultDetail {
    /// `DETAIL`, `HINT`, `WHERE` and `CONTEXT` dropped; quoted values in the
    /// message redacted for data and constraint errors (the default).
    Sanitized,
    /// The server's fields as sent.
    Full,
}

/// Where the database URL came from (for the startup warnings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    UrlFile,
    UrlEnv,
    Upstream,
}

/// A password that never prints.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "<none>"
        } else {
            "<redacted>"
        })
    }
}

/// The one database this process serves.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Secret,
    pub dbname: String,
    pub tls: UpstreamTlsMode,
    pub ca_path: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub source: CredentialSource,
    /// The path of the secret file, when the credential came from one.
    pub secret_file: Option<PathBuf>,
}

impl std::fmt::Debug for DatabaseTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password)
            .field("dbname", &self.dbname)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl DatabaseTarget {
    /// Whether the host is this machine (the only case where plaintext is
    /// the default).
    pub fn is_loopback(&self) -> bool {
        is_loopback_host(&self.host)
    }
}

/// `localhost`, `127.0.0.0/8`, `::1`, or a Unix-socket-like path is loopback.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost") || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Result caps and timeouts (design §8.1), already clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_rows: u32,
    pub max_rows_cap: u32,
    pub max_result_bytes: usize,
    pub max_cell_bytes: usize,
    pub statement_timeout_ms: u32,
    pub statement_timeout_cap_ms: u32,
    pub lock_timeout_ms: u32,
}

/// The largest statement `execute_sql` takes by default (64 KiB).
pub const MCP_DEFAULT_MAX_QUERY_BYTES: usize = vericto_engine::error::MAX_QUERY_SIZE_BYTES;
/// The most `VERICTO_MAX_QUERY_BYTES` can raise it to in `mcp` mode.
pub const MCP_MAX_QUERY_BYTES_CEILING: usize = 1024 * 1024;

/// Hard ceilings of the caps: an operator can lower a default, and raise it
/// only up to these.
pub const ROWS_CEILING: u32 = 1000;
pub const RESULT_BYTES_CEILING: usize = 1024 * 1024;
pub const CELL_BYTES_CEILING: usize = 64 * 1024;
pub const STATEMENT_TIMEOUT_CEILING_MS: u32 = 60_000;
pub const LOCK_TIMEOUT_CEILING_MS: u32 = 10_000;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 200,
            max_rows_cap: ROWS_CEILING,
            max_result_bytes: 256 * 1024,
            max_cell_bytes: 8 * 1024,
            statement_timeout_ms: 15_000,
            statement_timeout_cap_ms: STATEMENT_TIMEOUT_CEILING_MS,
            lock_timeout_ms: 2_000,
        }
    }
}

/// Everything `vericto-proxy mcp` needs besides the control-plane link.
#[derive(Debug, Clone)]
pub struct McpConfig {
    pub transport: Transport,
    pub listen: SocketAddr,
    pub database: DatabaseTarget,
    pub limits: Limits,
    pub pool_size: usize,
    pub pool_idle: Duration,
    /// `VERICTO_MCP_REQUIRE_CONTROL_PLANE`; `None` = the default (true when the
    /// control-plane link is configured).
    pub require_control_plane: Option<bool>,
    pub result_detail: ResultDetail,
    /// `VERICTO_MCP_SEARCH_PATH`, already validated (identifiers only).
    pub search_path: Option<Vec<String>>,
    pub allow_plaintext_http: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
    /// MD5 password authentication is refused unless set (`VERICTO_MCP_ALLOW_MD5`).
    pub allow_md5: bool,
    /// Tiers asked for in `VERICTO_MCP_TIERS` above `read`: reported, never
    /// enabled in this release (the write gate, design §9.11).
    pub requested_tiers_above_read: Vec<String>,
    /// `VERICTO_MAX_QUERY_BYTES` (clamped as for the TCP proxy).
    pub max_query_bytes: usize,
    /// `VERICTO_MAX_BINARY_OPERATORS`, shared with the TCP proxy.
    pub max_binary_operators: usize,
    /// Settings the operator wrote that this release ignores, for a warning.
    pub warnings: Vec<String>,
}

impl McpConfig {
    /// The database URL came from the environment (warned about at startup).
    pub fn source_is_env(&self) -> bool {
        self.database.source == CredentialSource::UrlEnv
    }
}

fn flag(env: Lookup<'_>, key: &str) -> Option<bool> {
    env(key).map(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn num<T: std::str::FromStr>(env: Lookup<'_>, key: &str) -> Result<Option<T>, String> {
    match env(key).map(|v| v.trim().to_string()) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|_| format!("{key}={v:?} is not a valid number")),
    }
}

fn list(env: Lookup<'_>, key: &str) -> Vec<String> {
    env(key)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

impl McpConfig {
    /// Builds the configuration from `env` (flags layered over the process
    /// environment by the caller). Errors name the setting.
    pub fn from_lookup(env: Lookup<'_>) -> Result<Self, String> {
        let mut warnings = Vec::new();
        let transport = match env("VERICTO_MCP_TRANSPORT")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("stdio") => Transport::Stdio,
            Some("http") => Transport::Http,
            Some(v) => {
                return Err(format!(
                    "VERICTO_MCP_TRANSPORT={v:?} is not supported: use `stdio` (the default) or `http`"
                ));
            }
        };
        let listen: SocketAddr = match env("VERICTO_MCP_LISTEN") {
            None => SocketAddr::from(([127, 0, 0, 1], 8808)),
            Some(v) => v.trim().parse().map_err(|_| {
                format!("VERICTO_MCP_LISTEN={v:?} is not an address:port (e.g. 127.0.0.1:8808)")
            })?,
        };

        let database = database_target(env)?;

        let d = Limits::default();
        let max_rows_cap = num::<u32>(env, "VERICTO_MCP_MAX_ROWS_CAP")?
            .unwrap_or(d.max_rows_cap)
            .clamp(1, ROWS_CEILING);
        let max_rows = num::<u32>(env, "VERICTO_MCP_MAX_ROWS")?
            .unwrap_or(d.max_rows)
            .clamp(1, max_rows_cap);
        let statement_timeout_cap_ms = num::<u32>(env, "VERICTO_MCP_STATEMENT_TIMEOUT_CAP_MS")?
            .unwrap_or(d.statement_timeout_cap_ms)
            .clamp(100, STATEMENT_TIMEOUT_CEILING_MS);
        let limits = Limits {
            max_rows,
            max_rows_cap,
            max_result_bytes: num::<usize>(env, "VERICTO_MCP_MAX_RESULT_BYTES")?
                .unwrap_or(d.max_result_bytes)
                .clamp(1024, RESULT_BYTES_CEILING),
            max_cell_bytes: num::<usize>(env, "VERICTO_MCP_MAX_CELL_BYTES")?
                .unwrap_or(d.max_cell_bytes)
                .clamp(64, CELL_BYTES_CEILING),
            statement_timeout_ms: num::<u32>(env, "VERICTO_MCP_STATEMENT_TIMEOUT_MS")?
                .unwrap_or(d.statement_timeout_ms)
                .clamp(100, statement_timeout_cap_ms),
            statement_timeout_cap_ms,
            lock_timeout_ms: num::<u32>(env, "VERICTO_MCP_LOCK_TIMEOUT_MS")?
                .unwrap_or(d.lock_timeout_ms)
                .clamp(1, LOCK_TIMEOUT_CEILING_MS),
        };

        let pool_size = num::<usize>(env, "VERICTO_MCP_POOL_SIZE")?
            .unwrap_or(4)
            .clamp(1, 32);
        let pool_idle = Duration::from_secs(
            num::<u64>(env, "VERICTO_MCP_POOL_IDLE_SECS")?
                .unwrap_or(300)
                .max(1),
        );

        let result_detail = match env("VERICTO_MCP_RESULT_DETAIL")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("sanitized") => ResultDetail::Sanitized,
            Some("full") => ResultDetail::Full,
            Some(v) => {
                return Err(format!(
                    "VERICTO_MCP_RESULT_DETAIL={v:?} is not supported: use `sanitized` (the default) or `full`"
                ));
            }
        };

        let search_path = match env("VERICTO_MCP_SEARCH_PATH") {
            None => None,
            Some(v) if v.trim().is_empty() => None,
            Some(v) => Some(parse_search_path(&v)?),
        };

        // Tiers (design §9.1): only `read` exists in this release. A tier above
        // it is reported and ignored: the write gate (§9.11) keeps it off,
        // whatever this variable says.
        let mut requested_tiers_above_read = Vec::new();
        let tiers = list(env, "VERICTO_MCP_TIERS");
        for t in &tiers {
            match t.to_ascii_lowercase().as_str() {
                "read" => {}
                "write" | "delete" | "ddl" => {
                    requested_tiers_above_read.push(t.to_ascii_lowercase())
                }
                other => {
                    return Err(format!(
                        "VERICTO_MCP_TIERS has {other:?}: the tiers are read, write, delete and ddl"
                    ));
                }
            }
        }
        if !tiers.is_empty() && !tiers.iter().any(|t| t.eq_ignore_ascii_case("read")) {
            return Err(
                "VERICTO_MCP_TIERS must include `read` (every other tier needs it)".to_string(),
            );
        }
        if !requested_tiers_above_read.is_empty() {
            warnings.push(format!(
                "VERICTO_MCP_TIERS asks for {}: tiers above read are not available in this release \
                 (the write gate); execute_sql runs reads only",
                requested_tiers_above_read.join(", ")
            ));
        }
        if env("VERICTO_MCP_WRITE_APPROVAL").is_some() {
            warnings.push(
                "VERICTO_MCP_WRITE_APPROVAL is ignored: there is no tier above read to approve"
                    .to_string(),
            );
        }

        let allowed_hosts = list(env, "VERICTO_MCP_ALLOWED_HOSTS");
        let allowed_origins = list(env, "VERICTO_MCP_ALLOWED_ORIGINS");

        // An agent's statement is small: 64 KiB by default (the engine's
        // MAX_QUERY_SIZE_BYTES and the contract's example), at most 1 MiB, the
        // most the parse thread's stack holds (stack.rs).
        let max_query_bytes = match num::<usize>(env, "VERICTO_MAX_QUERY_BYTES")? {
            None => MCP_DEFAULT_MAX_QUERY_BYTES,
            Some(v) if v > MCP_MAX_QUERY_BYTES_CEILING => {
                warnings.push(format!(
                    "VERICTO_MAX_QUERY_BYTES={v} is above what mcp mode accepts; using {MCP_MAX_QUERY_BYTES_CEILING}"
                ));
                MCP_MAX_QUERY_BYTES_CEILING
            }
            Some(v) => v.max(1024),
        };
        let max_binary_operators = crate::tcp::query_limit::max_binary_operators_from(
            env("VERICTO_MAX_BINARY_OPERATORS").as_deref(),
        );

        Ok(Self {
            transport,
            listen,
            database,
            limits,
            pool_size,
            pool_idle,
            require_control_plane: flag(env, "VERICTO_MCP_REQUIRE_CONTROL_PLANE"),
            result_detail,
            search_path,
            allow_plaintext_http: flag(env, "VERICTO_MCP_ALLOW_PLAINTEXT_HTTP").unwrap_or(false),
            allowed_hosts,
            allowed_origins,
            auth_tokens_file: env("VERICTO_MCP_AUTH_TOKENS_FILE")
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from),
            allow_md5: flag(env, "VERICTO_MCP_ALLOW_MD5").unwrap_or(false),
            requested_tiers_above_read,
            max_query_bytes,
            max_binary_operators,
            warnings,
        })
    }
}

/// `VERICTO_MCP_SEARCH_PATH`: comma-separated schema names, letters, digits,
/// `_` and `$` only (they are written into a fixed `SET LOCAL search_path`,
/// quoted, so nothing else may reach it).
pub fn parse_search_path(v: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = v
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() || names.len() > 16 {
        return Err("VERICTO_MCP_SEARCH_PATH must name 1 to 16 schemas".to_string());
    }
    for n in &names {
        let ok = n.len() <= 63
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            && !n.starts_with(|c: char| c.is_ascii_digit() || c == '$');
        if !ok {
            return Err(format!(
                "VERICTO_MCP_SEARCH_PATH has {n:?}: only plain schema names (letters, digits, _) are accepted"
            ));
        }
    }
    // Unquoted names fold to lower case, as PostgreSQL folds them.
    Ok(names.into_iter().map(|n| n.to_ascii_lowercase()).collect())
}

/// The database URL or the `UPSTREAM_*` variables.
fn database_target(env: Lookup<'_>) -> Result<DatabaseTarget, String> {
    let file = env("VERICTO_MCP_DATABASE_URL_FILE").filter(|v| !v.trim().is_empty());
    let inline = env("VERICTO_MCP_DATABASE_URL").filter(|v| !v.trim().is_empty());
    let mut target = match (file, inline) {
        (Some(path), _) => {
            let path = expand_home(path.trim(), env);
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "VERICTO_MCP_DATABASE_URL_FILE: cannot read {} ({})",
                    path.display(),
                    e.kind()
                )
            })?;
            let mut t = parse_database_url(raw.trim())
                .map_err(|e| format!("VERICTO_MCP_DATABASE_URL_FILE: {e}"))?;
            t.source = CredentialSource::UrlFile;
            t.secret_file = Some(path);
            t
        }
        (None, Some(url)) => {
            let mut t = parse_database_url(url.trim())
                .map_err(|e| format!("VERICTO_MCP_DATABASE_URL: {e}"))?;
            t.source = CredentialSource::UrlEnv;
            t
        }
        (None, None) => upstream_target(env)?,
    };

    // UPSTREAM_SSL* apply on top of the URL's own parameters, and the default
    // mode in `mcp` mode is verify-full for any host that is not loopback
    // (design §12.1, Q17): the TCP default `disable` assumes a trusted network
    // next to the database, which a laptop talking to a hosted database is not.
    if let Some(mode) = env("UPSTREAM_SSLMODE").filter(|v| !v.trim().is_empty()) {
        target.tls = UpstreamTlsMode::parse(Some(&mode))?;
    }
    if let Some(v) = env("UPSTREAM_SSLROOTCERT").filter(|v| !v.trim().is_empty()) {
        target.ca_path = Some(v);
    }
    if let Some(v) = env("UPSTREAM_SSLCERT").filter(|v| !v.trim().is_empty()) {
        target.client_cert = Some(v);
    }
    if let Some(v) = env("UPSTREAM_SSLKEY").filter(|v| !v.trim().is_empty()) {
        target.client_key = Some(v);
    }
    if target.tls == UpstreamTlsMode::Disable
        && !target.is_loopback()
        && !flag(env, "VERICTO_MCP_ALLOW_PLAINTEXT_DB").unwrap_or(false)
    {
        return Err(
            "the database host is not loopback and TLS is disabled: refused, because the \
             credential and every result would cross the network in clear text. Use \
             sslmode=verify-full (the default in mcp mode), or set \
             VERICTO_MCP_ALLOW_PLAINTEXT_DB=true for a trusted private network"
                .to_string(),
        );
    }
    Ok(target)
}

fn expand_home(path: &str, env: Lookup<'_>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = env("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

fn upstream_target(env: Lookup<'_>) -> Result<DatabaseTarget, String> {
    let Some(host) = env("UPSTREAM_HOST").filter(|v| !v.trim().is_empty()) else {
        return Err(
            "no database configured: set VERICTO_MCP_DATABASE_URL_FILE (a file holding a \
             postgres:// URL, preferred), VERICTO_MCP_DATABASE_URL, or UPSTREAM_HOST with \
             UPSTREAM_USER and UPSTREAM_PASSWORD_FILE"
                .to_string(),
        );
    };
    let port = match env("UPSTREAM_PORT") {
        None => 5432,
        Some(p) => p
            .trim()
            .parse()
            .map_err(|_| format!("UPSTREAM_PORT={p:?} is not a port"))?,
    };
    let user = env("UPSTREAM_USER")
        .filter(|v| !v.trim().is_empty())
        .ok_or("UPSTREAM_USER is not set (the database role vericto-proxy mcp logs in as)")?;
    let mut secret_file = None;
    let password = match env("UPSTREAM_PASSWORD_FILE").filter(|v| !v.trim().is_empty()) {
        Some(path) => {
            let path = expand_home(path.trim(), env);
            let p = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "UPSTREAM_PASSWORD_FILE: cannot read {} ({})",
                    path.display(),
                    e.kind()
                )
            })?;
            secret_file = Some(path);
            p.trim_end_matches(['\n', '\r']).to_string()
        }
        None => String::new(),
    };
    let tls = default_tls(&host);
    Ok(DatabaseTarget {
        dbname: env("UPSTREAM_DBNAME")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| user.clone()),
        host: host.trim().to_string(),
        port,
        user,
        password: Secret::new(password),
        tls,
        ca_path: None,
        client_cert: None,
        client_key: None,
        source: CredentialSource::Upstream,
        secret_file,
    })
}

fn default_tls(host: &str) -> UpstreamTlsMode {
    if is_loopback_host(host) {
        UpstreamTlsMode::Disable
    } else {
        UpstreamTlsMode::VerifyFull
    }
}

/// Parses a `postgres://` / `postgresql://` URL: user, password, one host,
/// port, database and the `sslmode`, `sslrootcert`, `sslcert`, `sslkey`
/// parameters. Errors never include the URL (it holds the password).
pub fn parse_database_url(raw: &str) -> Result<DatabaseTarget, String> {
    let (scheme, _) = raw.split_once("://").ok_or(
        "not a postgres:// URL (it should look like postgres://user:password@host:5432/dbname)",
    )?;
    if !scheme.eq_ignore_ascii_case("postgres") && !scheme.eq_ignore_ascii_case("postgresql") {
        return Err(format!(
            "the URL scheme is {scheme:?}; only postgres:// and postgresql:// are supported (PostgreSQL only)"
        ));
    }
    let url = reqwest::Url::parse(raw).map_err(|_| {
        "the URL does not parse (check for unescaped @, : or / in the password; percent-encode them)"
            .to_string()
    })?;
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or("the URL has no host (Unix sockets are not supported)")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.contains(',') {
        return Err("several hosts in one URL are not supported; name one".to_string());
    }
    let decode = |s: &str| -> Result<String, String> { percent_decode(s) };
    let user = decode(url.username())?;
    if user.is_empty() {
        return Err("the URL has no user (postgres://user:password@host/dbname)".to_string());
    }
    let password = url.password().map(decode).transpose()?.unwrap_or_default();
    let dbname = decode(url.path().trim_start_matches('/'))?;
    let mut target = DatabaseTarget {
        tls: default_tls(&host),
        dbname: if dbname.is_empty() {
            user.clone()
        } else {
            dbname
        },
        port: url.port().unwrap_or(5432),
        host,
        user,
        password: Secret::new(password),
        ca_path: None,
        client_cert: None,
        client_key: None,
        source: CredentialSource::UrlEnv,
        secret_file: None,
    };
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "sslmode" => {
                target.tls = match v.to_ascii_lowercase().as_str() {
                    // libpq's `prefer`/`allow` may fall back to plaintext; here
                    // they mean "encrypt", never less than the URL asked.
                    "prefer" | "allow" => UpstreamTlsMode::Require,
                    other => UpstreamTlsMode::parse(Some(other))?,
                }
            }
            "sslrootcert" => target.ca_path = Some(v.into_owned()),
            "sslcert" => target.client_cert = Some(v.into_owned()),
            "sslkey" => target.client_key = Some(v.into_owned()),
            "options" => {
                return Err(
                    "the URL's `options` parameter is not supported: session settings are fixed \
                     by vericto-proxy mcp (search_path: VERICTO_MCP_SEARCH_PATH)"
                        .to_string(),
                );
            }
            // Informational parameters that change nothing about what runs.
            "application_name"
            | "connect_timeout"
            | "channel_binding"
            | "target_session_attrs"
            | "gssencmode"
            | "pgbouncer" => {}
            other => {
                return Err(format!(
                    "the URL parameter {other:?} is not supported by vericto-proxy mcp"
                ));
            }
        }
    }
    Ok(target)
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("the URL has an invalid percent-encoding")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the URL decodes to invalid UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn a_url_parses_and_its_password_never_prints() {
        let t = parse_database_url(
            "postgres://agent_ro:s3cr%40t%2Fpw@db.example.com:6543/shop?sslmode=verify-full",
        )
        .unwrap();
        assert_eq!(t.host, "db.example.com");
        assert_eq!(t.port, 6543);
        assert_eq!(t.user, "agent_ro");
        assert_eq!(t.password.expose(), "s3cr@t/pw");
        assert_eq!(t.dbname, "shop");
        assert_eq!(t.tls, UpstreamTlsMode::VerifyFull);
        let shown = format!("{t:?}");
        assert!(!shown.contains("s3cr"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn url_errors_never_echo_the_url() {
        for bad in [
            "mysql://u:hunter2@h/db",
            "postgres://:hunter2@h/db",
            "postgres://u:hunter2@h/db?options=-c%20search_path%3Dx",
            "postgres://u:hunter2@h/db?bogus=1",
            "postgres://u:hun%zzter2@h/db",
        ] {
            let e = parse_database_url(bad).unwrap_err();
            assert!(!e.contains("hunter2"), "{e}");
        }
    }

    #[test]
    fn tls_defaults_to_verify_full_off_loopback_and_plaintext_is_refused() {
        let t = parse_database_url("postgres://u:p@db.example.com/x").unwrap();
        assert_eq!(t.tls, UpstreamTlsMode::VerifyFull);
        let t = parse_database_url("postgres://u:p@127.0.0.1/x").unwrap();
        assert_eq!(t.tls, UpstreamTlsMode::Disable);
        let env = lookup(&[(
            "VERICTO_MCP_DATABASE_URL",
            "postgres://u:p@db.example.com/x?sslmode=disable",
        )]);
        let e = McpConfig::from_lookup(&env).unwrap_err();
        assert!(e.contains("VERICTO_MCP_ALLOW_PLAINTEXT_DB"), "{e}");
        let env = lookup(&[
            (
                "VERICTO_MCP_DATABASE_URL",
                "postgres://u:p@db.example.com/x?sslmode=disable",
            ),
            ("VERICTO_MCP_ALLOW_PLAINTEXT_DB", "true"),
        ]);
        assert!(McpConfig::from_lookup(&env).is_ok());
        // `prefer` never means plaintext here.
        let t = parse_database_url("postgres://u:p@db.example.com/x?sslmode=prefer").unwrap();
        assert_eq!(t.tls, UpstreamTlsMode::Require);
    }

    #[test]
    fn limits_are_clamped_to_their_caps() {
        let env = lookup(&[
            ("VERICTO_MCP_DATABASE_URL", "postgres://u:p@localhost/x"),
            ("VERICTO_MCP_MAX_ROWS", "5000"),
            ("VERICTO_MCP_MAX_RESULT_BYTES", "99999999"),
            ("VERICTO_MCP_MAX_CELL_BYTES", "99999999"),
            ("VERICTO_MCP_STATEMENT_TIMEOUT_MS", "999999"),
            ("VERICTO_MCP_LOCK_TIMEOUT_MS", "999999"),
            ("VERICTO_MCP_POOL_SIZE", "500"),
        ]);
        let c = McpConfig::from_lookup(&env).unwrap();
        assert_eq!(c.limits.max_rows, 1000);
        assert_eq!(c.limits.max_result_bytes, RESULT_BYTES_CEILING);
        assert_eq!(c.limits.max_cell_bytes, CELL_BYTES_CEILING);
        assert_eq!(c.limits.statement_timeout_ms, 60_000);
        assert_eq!(c.limits.lock_timeout_ms, 10_000);
        assert_eq!(c.pool_size, 32);
        let env = lookup(&[("VERICTO_MCP_DATABASE_URL", "postgres://u:p@localhost/x")]);
        let c = McpConfig::from_lookup(&env).unwrap();
        assert_eq!(c.limits, Limits::default());
        assert_eq!(c.transport, Transport::Stdio);
        assert_eq!(c.listen.to_string(), "127.0.0.1:8808");
        assert_eq!(
            c.max_binary_operators,
            crate::tcp::query_complexity::DEFAULT_MAX_BINARY_OPERATORS
        );
        let env = lookup(&[
            ("VERICTO_MCP_DATABASE_URL", "postgres://u:p@localhost/x"),
            ("VERICTO_MAX_BINARY_OPERATORS", "25000"),
        ]);
        assert_eq!(
            McpConfig::from_lookup(&env).unwrap().max_binary_operators,
            25_000
        );
    }

    #[test]
    fn tiers_above_read_are_reported_never_enabled() {
        let env = lookup(&[
            ("VERICTO_MCP_DATABASE_URL", "postgres://u:p@localhost/x"),
            ("VERICTO_MCP_TIERS", "read,write"),
        ]);
        let c = McpConfig::from_lookup(&env).unwrap();
        assert_eq!(c.requested_tiers_above_read, vec!["write"]);
        assert!(!c.warnings.is_empty());
        let env = lookup(&[
            ("VERICTO_MCP_DATABASE_URL", "postgres://u:p@localhost/x"),
            ("VERICTO_MCP_TIERS", "write"),
        ]);
        assert!(McpConfig::from_lookup(&env).is_err());
    }

    #[test]
    fn flags_map_to_variables() {
        let a = parse_args(&[
            "--transport".into(),
            "http".into(),
            "--listen=0.0.0.0:8808".into(),
            "--allow-plaintext-http".into(),
            "--max-rows".into(),
            "50".into(),
        ])
        .unwrap();
        assert_eq!(a.settings["VERICTO_MCP_TRANSPORT"], "http");
        assert_eq!(a.settings["VERICTO_MCP_LISTEN"], "0.0.0.0:8808");
        assert_eq!(a.settings["VERICTO_MCP_ALLOW_PLAINTEXT_HTTP"], "true");
        assert_eq!(a.settings["VERICTO_MCP_MAX_ROWS"], "50");
        assert!(parse_args(&["--database-url".into(), "postgres://u:p@h/d".into()]).is_err());
        assert!(parse_args(&["--nope".into()]).is_err());
        assert!(parse_args(&["stray".into()]).is_err());
    }

    #[test]
    fn search_path_accepts_plain_names_only() {
        assert_eq!(
            parse_search_path("App, public").unwrap(),
            vec!["app", "public"]
        );
        for bad in ["a;b", "\"x\"", "x y", "1abc", ""] {
            assert!(parse_search_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_password_file_is_read_and_its_newline_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("pw");
        std::fs::write(&pw, "hunter2\n").unwrap();
        let env = lookup(&[
            ("UPSTREAM_HOST", "localhost"),
            ("UPSTREAM_USER", "ro"),
            ("UPSTREAM_PASSWORD_FILE", pw.to_str().unwrap()),
        ]);
        let c = McpConfig::from_lookup(&env).unwrap();
        assert_eq!(c.database.password.expose(), "hunter2");
        assert_eq!(c.database.dbname, "ro");
        assert_eq!(c.database.source, CredentialSource::Upstream);
    }
}
