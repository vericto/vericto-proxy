//! PostgreSQL TCP proxy session handler.
//!
//! Terminates the PostgreSQL wire protocol transparently: the client (Prisma,
//! SQLAlchemy, psql, ...) connects believing it talks to Postgres. The proxy:
//!   1. Negotiates the startup phase (declines TLS/GSS, forwards StartupMessage).
//!   2. Opens an upstream connection to the real Postgres and forwards startup.
//!   3. Relays server→client untouched.
//!   4. Intercepts client→server: extracts the SQL from Query ('Q') and Parse
//!      ('P') messages, evaluates it with the AST engine, and if destructive,
//!      responds with a native ErrorResponse WITHOUT forwarding the query to the
//!      real engine.
//!
//! Best practices applied:
//! - Read by complete message (read_exact handles TCP segmentation).
//! - The enforcement action is resolved by the workspace policy; parse errors
//!   are fail-open by default (forward + report) unless the policy opts into
//!   fail-closed.
//! - Client writes serialized with a Mutex (relay + error injection).
//! - Message size limits (codec) to mitigate DoS.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::tcp::client_tls::{ClientRead, ClientWrite};
use crate::tcp::codec::{StartupPacket, StartupParams, read_startup_packet};
use crate::tcp::evaluator::TcpDecision;
use vericto_engine::EnforcementAction;
use vericto_engine::parser::Dialect;

/// PostgreSQL TCP proxy configuration.
pub struct PgProxyConfig {
    pub upstream_host: String,
    pub upstream_port: u16,
    /// TLS mode for the proxy→database hop.
    pub upstream_tls: crate::tcp::upstream::UpstreamTlsMode,
    /// CA bundle (PEM) for verify-full upstream TLS.
    pub upstream_ca_path: Option<String>,
    /// Client certificate (PEM) presented to the database for upstream mutual TLS.
    pub upstream_client_cert: Option<String>,
    /// Private key (PEM) for the upstream mutual-TLS client certificate.
    pub upstream_client_key: Option<String>,
    /// Server-side TLS acceptor for the client→proxy hop. `None` declines client
    /// TLS (trusted-network deployment); `Some` terminates TLS as the server.
    pub client_tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    /// Hot-swappable ruleset shared with the rule syncer. Read lock-free per query.
    pub ruleset: crate::tcp::rules_sync::SharedRuleset,
    /// Hot-swappable enforcement policy shared with the rule syncer.
    pub policy: crate::tcp::rules_sync::SharedPolicy,
    /// Hot-swappable agent-access allowlists (VERICTO-087) keyed by database user,
    /// shared with the rule syncer. Each session applies its own user's policy.
    pub agent_access: crate::tcp::rules_sync::SharedAccessPolicies,
    /// Hot-swappable telemetry query mode (raw | sanitized) shared with the syncer.
    pub telemetry_mode: crate::tcp::rules_sync::SharedTelemetryMode,
    /// Optional telemetry sink: when set, each evaluation is reported. The
    /// database_id identifies which connected database this proxy fronts.
    pub telemetry: Option<TelemetrySink>,
    /// Largest query this proxy will evaluate, already clamped to what the wire
    /// protocol can deliver. Resolved once at startup — see `tcp::query_limit`.
    pub max_query_bytes: usize,
}

/// Where the TCP proxy pushes evaluation telemetry (non-blocking).
#[derive(Clone)]
pub struct TelemetrySink {
    pub queue: Arc<dyn crate::telemetry::EventQueue>,
    pub database_id: String,
}

/// Handles a complete incoming connection. Any error closes the connection.
pub async fn handle_connection(client: TcpStream, config: Arc<PgProxyConfig>) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    if let Err(e) = run_session(client, config).await {
        tracing::debug!(peer = %peer, error = %e, "TCP session ended");
    }
}

async fn run_session(client: TcpStream, config: Arc<PgProxyConfig>) -> std::io::Result<()> {
    // ── Phase 1: negotiate startup. Optionally terminate client TLS, then read
    // the StartupMessage. Returns the (possibly TLS) client halves.
    // The StartupMessage `user` is the session's identity for the agent-access
    // allowlists: the role the server authenticates, fixed for the session.
    let (mut client_read, mut client_write, startup_raw, startup) =
        negotiate_startup(client, config.client_tls_acceptor.as_ref()).await?;
    let session_user = startup.user;

    // `search_path` (and the identity settings) set by the StartupMessage are
    // the `SET` the engine denies under an allowlist: evaluated as that `SET`,
    // and a blocked one refuses the connection before it reaches the database.
    let refused = {
        let config = Arc::clone(&config);
        let user = session_user.clone();
        let settings = startup.access_settings;
        tokio::task::spawn_blocking(move || {
            crate::tcp::session::startup_settings_block(&config, user.as_deref(), &settings)
        })
        .await
        .expect("startup evaluation task panicked")
    };
    if let Some(message) = refused {
        client_write
            .write_all(&crate::tcp::codec::build_error_response(
                crate::tcp::codec::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                &message,
            ))
            .await?;
        client_write.flush().await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "StartupMessage setting denied by the agent access policy",
        ));
    }

    // ── Phase 2: connect upstream (optionally over TLS) and forward the StartupMessage
    let (server_read, mut server_write) = match crate::tcp::upstream::connect_upstream(
        &config.upstream_host,
        config.upstream_port,
        config.upstream_tls,
        config.upstream_ca_path.as_deref(),
        config.upstream_client_cert.as_deref(),
        config.upstream_client_key.as_deref(),
    )
    .await
    {
        Ok(halves) => halves,
        Err(e) => {
            // The database is unreachable. The client is still in the connection
            // phase (nothing has been sent to it yet), so it's safe and far more
            // useful to answer with a native ErrorResponse than to drop the
            // socket. The detail (host/port/cause) goes to logs only — the client
            // gets a generic message so we don't leak internal topology.
            tracing::warn!(
                host = %config.upstream_host,
                port = config.upstream_port,
                error = %e,
                "upstream connect failed; returning ErrorResponse to client"
            );
            let _ = client_write
                .write_all(&crate::tcp::codec::build_error_response(
                    crate::tcp::codec::SQLSTATE_CONNECTION_FAILURE,
                    "Vericto: the database is temporarily unavailable",
                ))
                .await;
            let _ = client_write.flush().await;
            return Err(e);
        }
    };
    server_write.write_all(&startup_raw).await?;
    server_write.flush().await?;

    // ── Phase 3: the client write half is shared (relay + errors)
    let client_write = Arc::new(Mutex::new(client_write));

    // Tracks whether the relay has forwarded any server byte to the client. Once
    // it has, the client is mid-stream and injecting an ErrorResponse would
    // corrupt the protocol; before then we can still surface a typed error.
    let relay_wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Relay server→client (auth, data, notices) without intercepting.
    let relay_handle = tokio::spawn(relay_server_to_client(
        server_read,
        client_write.clone(),
        relay_wrote.clone(),
    ));

    // ── Phase 4: client→server interception loop
    //
    // Run the intercept loop and the relay CONCURRENTLY and let whichever ends
    // first tear down the other. This matters for resilience: if the upstream
    // dies (e.g. mid-auth), the relay task finishes on EOF while the intercept
    // loop is still blocked reading from the client — the client is waiting for
    // a server reply that will never come. Without this join, `run_session`
    // would await the intercept forever and leak a hung client connection.
    // `select!` returns as soon as the relay completes, and dropping this
    // function's futures closes the sockets, unwinding the client side too.
    let mut relay_handle = relay_handle;
    let result = tokio::select! {
        r = intercept_client_to_server(&mut client_read, &mut server_write, &client_write, &config, session_user) => {
            // Client ended or a block/forward error unwound the loop: stop the relay.
            relay_handle.abort();
            r
        }
        _ = &mut relay_handle => {
            // Upstream closed/errored: the relay ended. If it never delivered a
            // byte to the client (the upstream died during the connection phase,
            // e.g. mid-auth), the client is still waiting for a startup reply, so
            // send a native ErrorResponse before closing. If bytes were already
            // relayed, the stream is mid-session and injecting one would corrupt
            // it — fall back to a plain close.
            if !relay_wrote.load(std::sync::atomic::Ordering::Relaxed) {
                let mut w = client_write.lock().await;
                let _ = w
                    .write_all(&crate::tcp::codec::build_error_response(
                        crate::tcp::codec::SQLSTATE_CONNECTION_FAILURE,
                        "Vericto: the database connection was lost",
                    ))
                    .await;
                let _ = w.flush().await;
            }
            Ok(())
        }
    };

    result
}

/// Negotiates the startup phase and returns the client transport halves, the
/// raw StartupMessage bytes and its parameters.
///
/// When `acceptor` is `Some` and the client sends an `SSLRequest`, the proxy
/// answers `'S'`, performs the server-side TLS handshake, and reads the
/// StartupMessage over the encrypted channel. Otherwise it declines encryption
/// (`'N'`) and continues in plaintext — the trusted-network deployment model.
///
/// `acceptor` is `Some` only for `PROXY_TLS_MODE=require`, so a StartupMessage
/// sent in plaintext (the client skipped `SSLRequest`, e.g. `sslmode=disable`)
/// is refused with a native `ErrorResponse` (28000) and never reaches the
/// upstream — the MySQL path refuses the same case (`session.rs`).
async fn negotiate_startup(
    mut client: TcpStream,
    acceptor: Option<&tokio_rustls::TlsAcceptor>,
) -> std::io::Result<(ClientRead, ClientWrite, Vec<u8>, StartupParams)> {
    loop {
        match read_startup_packet(&mut client).await? {
            StartupPacket::SslRequest => {
                if let Some(acceptor) = acceptor {
                    // Accept TLS: confirm with 'S', handshake, then read the real
                    // StartupMessage over the encrypted channel.
                    client.write_all(b"S").await?;
                    client.flush().await?;
                    let (mut read, write) =
                        crate::tcp::client_tls::accept_tls(acceptor, client).await?;
                    let (raw, params) = read_startup_message(&mut read).await?;
                    return Ok((read, write, raw, params));
                }
                // TLS not enabled: decline ('N') and keep negotiating in plaintext.
                client.write_all(b"N").await?;
                client.flush().await?;
            }
            StartupPacket::GssRequest => {
                // GSSAPI encryption is not supported; decline and continue.
                client.write_all(b"N").await?;
                client.flush().await?;
            }
            StartupPacket::Startup { raw, params } => {
                if acceptor.is_some() {
                    tracing::warn!(
                        user = ?params.user,
                        database = ?params.database,
                        "PROXY_TLS_MODE=require but the client started without TLS; rejected"
                    );
                    client
                        .write_all(&crate::tcp::codec::build_error_response(
                            crate::tcp::codec::SQLSTATE_INVALID_AUTHORIZATION,
                            "Vericto: this proxy requires SSL (PROXY_TLS_MODE=require); connect with sslmode=require",
                        ))
                        .await?;
                    client.flush().await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "PROXY_TLS_MODE=require but the client did not request TLS",
                    ));
                }
                tracing::debug!(
                    user = ?params.user,
                    database = ?params.database,
                    "StartupMessage received"
                );
                let (read, write) = tokio::io::split(client);
                return Ok((Box::new(read), Box::new(write), raw, params));
            }
        }
    }
}

/// Reads a single startup packet expecting the StartupMessage (used after a TLS
/// handshake, where the next message must be the StartupMessage).
async fn read_startup_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<(Vec<u8>, StartupParams)> {
    match read_startup_packet(reader).await? {
        StartupPacket::Startup { raw, params } => {
            tracing::debug!(
                user = ?params.user,
                database = ?params.database,
                "StartupMessage received (over TLS)"
            );
            Ok((raw, params))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected StartupMessage after TLS handshake",
        )),
    }
}

/// Relays bytes from the server to the client without intercepting.
///
/// `wrote_any` is flipped to `true` the first time a byte is successfully
/// written to the client. `run_session` reads it when the relay ends to decide
/// whether it is still safe to inject a native `ErrorResponse`: once server
/// bytes have reached the client (auth/rows in flight), injecting one would
/// corrupt the protocol stream, so it must fall back to a plain close.
async fn relay_server_to_client(
    mut server_read: crate::tcp::upstream::UpstreamRead,
    client_write: Arc<Mutex<ClientWrite>>,
    wrote_any: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match server_read.read(&mut buf).await {
            Ok(0) => break, // upstream closed
            Ok(n) => {
                let mut writer = client_write.lock().await;
                if writer.write_all(&buf[..n]).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
                wrote_any.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            Err(_) => break,
        }
    }
}

/// Main loop: delegates to the protocol-agnostic interception loop with the
/// PostgreSQL wire-protocol strategy. The framing/classification/block bytes
/// (previously inline here) now live in `protocol::postgres`; evaluation,
/// telemetry and enforcement live in `session`. Behavior is unchanged — the
/// regression suite guards the Postgres path.
async fn intercept_client_to_server(
    client_read: &mut ClientRead,
    server_write: &mut crate::tcp::upstream::UpstreamWrite,
    client_write: &Arc<Mutex<ClientWrite>>,
    config: &Arc<PgProxyConfig>,
    session_user: Option<String>,
) -> std::io::Result<()> {
    let proto = crate::tcp::protocol::postgres::PostgresProtocol;
    crate::tcp::session::intercept_client_to_server(
        &proto,
        client_read,
        server_write,
        client_write,
        config,
        crate::tcp::session::SessionStart {
            user: session_user,
            ..Default::default()
        },
    )
    .await
}

pub(crate) fn log_block(sql: &str, rule_code: &str, ast_node_path: &str) {
    let preview: String = sql.chars().take(80).collect();
    tracing::info!(
        rule_code,
        ast_node_path,
        query_preview = %preview,
        "Query BLOCKED at TCP proxy"
    );
}

/// Textual representation of an enforcement action for telemetry.
fn action_str(action: EnforcementAction) -> &'static str {
    match action {
        EnforcementAction::Block => "block",
        EnforcementAction::Flag => "flag",
        EnforcementAction::Monitor => "monitor",
    }
}

/// Canonical lowercase name for a dialect, as expected by the control plane
/// (and accepted back by `Dialect::parse_dialect`). Reported verbatim in
/// telemetry so the dashboard reflects the wire protocol the proxy is fronting.
fn dialect_name(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "postgres",
        Dialect::Mysql => "mysql",
        Dialect::Oracle => "oracle",
        Dialect::MsSql => "mssql",
    }
}

/// Who issued a query, for its telemetry event: the session's database user and,
/// when an agent-access policy applied, its mode.
#[derive(Debug, Clone, Default)]
pub struct EventIdentity {
    pub db_user: Option<String>,
    pub access_mode: Option<vericto_engine::AccessMode>,
}

/// [`build_event`] in raw mode, for the tests that only exercise the mapping.
#[cfg(test)]
fn build_telemetry_event(
    database_id: &str,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
) -> crate::telemetry::TelemetryEvent {
    build_event(
        database_id,
        sql,
        dialect,
        decision,
        latency_us,
        crate::tcp::rules_sync::TelemetryQueryMode::Raw,
        &EventIdentity::default(),
    )
}

/// Builds a telemetry event from an evaluation decision. Pure (no I/O) so it can
/// be unit-tested.
///
/// In sanitized `mode` every SQL text that leaves is normalized first: the
/// query, the rewritten query of a mask, and a VERICTO-085 suggestion (which
/// under `monitor_mode` is the would-be rewrite). Sanitizing happens before the
/// size cut, because a cut statement no longer parses and would only ever be
/// reported as redacted.
fn build_event(
    database_id: &str,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
    mode: crate::tcp::rules_sync::TelemetryQueryMode,
    identity: &EventIdentity,
) -> crate::telemetry::TelemetryEvent {
    use crate::tcp::evaluator::SENSITIVE_RULE_CODE;
    use crate::tcp::rules_sync::TelemetryQueryMode;

    // Privacy: when the workspace policy selects "sanitized", normalize literals
    // to placeholders before any query text leaves the customer network. Rule
    // evaluation already happened on the full query — this only affects reporting.
    let sanitized = mode == TelemetryQueryMode::Sanitized;
    let reported = |text: &str| -> String {
        if sanitized {
            sanitize_for(text, dialect)
        } else {
            text.to_string()
        }
    };

    let mut severity: Option<String> = None;
    let mut enforcement_action: Option<String> = None;
    let mut parse_error: Option<String> = None;

    let (status, rule_code, ast_node_path) = match decision {
        // No violation: forwarded silently.
        TcpDecision::Forward {
            observation: None, ..
        } => ("ALLOWED".to_string(), None, None),

        // Non-blocking violation (Flag/Monitor) or parse-error allow-report.
        TcpDecision::Forward {
            observation: Some(obs),
            ..
        } => {
            severity = Some(obs.severity.as_str().to_string());
            enforcement_action = Some(action_str(obs.action).to_string());
            let status = if obs.parse_error.is_some() {
                parse_error = obs.parse_error.clone();
                "PARSE_ERROR"
            } else {
                match obs.action {
                    EnforcementAction::Monitor => "MONITORED",
                    _ => "FLAGGED",
                }
            };
            (
                status.to_string(),
                Some(obs.rule_code.clone()),
                Some(obs.ast_node_path.clone()),
            )
        }

        // Rejected query (or fail-closed parse error).
        TcpDecision::Block {
            rule_code,
            ast_node_path,
            severity: sev,
            ..
        } => {
            severity = Some(sev.as_str().to_string());
            enforcement_action = Some("block".to_string());
            let status = if rule_code == "VERICTO-PARSE-ERROR" {
                // ast_node_path holds "PARSE_ERROR: <msg>".
                parse_error = Some(ast_node_path.clone());
                "PARSE_ERROR"
            } else {
                "BLOCKED"
            };
            (
                status.to_string(),
                Some(rule_code.clone()),
                Some(ast_node_path.clone()),
            )
        }
    };

    let (violations, touched, rewritten, denied) = match decision {
        TcpDecision::Forward {
            violations,
            sensitive_columns,
            rewritten_query,
            access_denied,
            ..
        } => (
            violations,
            sensitive_columns,
            rewritten_query.as_deref(),
            access_denied,
        ),
        TcpDecision::Block {
            violations,
            sensitive_columns,
            access_denied,
            ..
        } => (violations, sensitive_columns, None, access_denied),
    };

    // VERICTO-087 names what the query referenced. In sanitized mode a name that
    // may have been a literal is not reported (see `AccessRedaction`); the
    // allowlist's own path is then rebuilt from the redacted names.
    let redaction = AccessRedaction::new(sanitized, sql, dialect, denied);
    let access_path = |path: &str| -> String {
        crate::telemetry::truncate_reported_ast_path(&redaction.path(path))
    };

    // The full violation set, capped and mapped to the wire shape. Taken from the
    // decision rather than rebuilt from `rule_code`: the engine's ordering is the
    // contract that makes entry 0 the winner, and re-deriving it here could
    // disagree with the decision the proxy already acted on.
    let violations: Vec<crate::telemetry::ReportedViolationPayload> = violations
        .iter()
        .take(crate::telemetry::MAX_REPORTED_VIOLATIONS)
        .map(|v| {
            let sensitive = v.rule_code == SENSITIVE_RULE_CODE;
            let suggestion = v.suggested_safe_query.as_deref().and_then(|s| {
                if sensitive && Some(s) == rewritten {
                    // A successful mask repeats the rewritten SQL here; the event
                    // already carries it in `rewritten_query`.
                    None
                } else if sensitive && sanitized {
                    Some(sanitize_suggestion(s, dialect))
                } else {
                    Some(s.to_string())
                }
            });
            crate::telemetry::ReportedViolationPayload {
                rule_code: v.rule_code.clone(),
                severity: v.severity.as_str().to_string(),
                enforcement_action: action_str(v.action).to_string(),
                ast_node_path: Some(if v.rule_code == vericto_engine::ACCESS_RULE_CODE {
                    access_path(&v.ast_node_path)
                } else {
                    crate::telemetry::truncate_reported_ast_path(&v.ast_node_path)
                }),
                suggested_safe_query: suggestion
                    .as_deref()
                    .map(crate::telemetry::truncate_reported_suggestion),
                estimated_rows_affected: v.estimated_rows_affected,
            }
        })
        .collect();

    let sensitive_columns = touched
        .iter()
        .take(crate::telemetry::MAX_REPORTED_SENSITIVE_COLUMNS)
        .map(|c| crate::telemetry::SensitiveColumnPayload {
            schema: c.schema.clone(),
            table: c.table.clone(),
            column: c.column.clone(),
            policy: c.policy.as_str().to_string(),
        })
        .collect();

    let reported_sql = reported(sql);
    let (query_text, rewritten_query) = match rewritten {
        Some(r) => {
            let (o, r) = crate::telemetry::truncate_reported_pair(&reported_sql, &reported(r));
            (o, Some(r))
        }
        None => (
            crate::telemetry::truncate_reported_query(&reported_sql),
            None,
        ),
    };

    crate::telemetry::TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        database_id: database_id.to_string(),
        query_text,
        dialect: dialect_name(dialect).to_string(),
        ast_node_path: ast_node_path.map(|p| {
            if rule_code.as_deref() == Some(vericto_engine::ACCESS_RULE_CODE) {
                access_path(&p)
            } else {
                crate::telemetry::truncate_reported_ast_path(&p)
            }
        }),
        status,
        rule_code,
        severity,
        enforcement_action,
        violations,
        parse_error: parse_error
            .as_deref()
            .map(crate::telemetry::truncate_reported_parse_error),
        latency_ms: Some(latency_us as f64 / 1000.0),
        client_ip: None,
        occurred_at: chrono::Utc::now().to_rfc3339(),
        rewritten_query,
        sensitive_columns,
        db_user: identity.db_user.clone(),
        access_policy_mode: identity.access_mode.map(|m| match m {
            vericto_engine::AccessMode::Observe => "observe".to_string(),
            vericto_engine::AccessMode::Enforce => "enforce".to_string(),
        }),
        access_denied: redaction.payload(),
    }
}

/// The VERICTO-087 denials of an event, made safe to report.
///
/// Names are not values, so they are reported in sanitized mode too, with one
/// exception: on MySQL a double-quoted `"x"` is a string unless ANSI_QUOTES is
/// on, and the engine conservatively also reads it as a column `x` (contract
/// §5). A denied "column" can therefore be a literal the client sent. In
/// sanitized mode a MySQL name is kept only when the query spells it as an
/// identifier (bare or backticked); otherwise it is reported as `?` and the
/// rule's path is rebuilt from the redacted names. Catalogue schemas, `*` and
/// the keyword of a denied statement come from the engine, not from the text.
struct AccessRedaction<'a> {
    denied: &'a [vericto_engine::DeniedRef],
    /// `Some` when a name had to be redacted: the redacted list, else the list
    /// is reported as the engine gave it.
    redacted: Option<Vec<vericto_engine::DeniedRef>>,
}

impl<'a> AccessRedaction<'a> {
    fn new(
        sanitized: bool,
        sql: &str,
        dialect: Dialect,
        denied: &'a [vericto_engine::DeniedRef],
    ) -> Self {
        let mut this = Self {
            denied,
            redacted: None,
        };
        if !sanitized || dialect != Dialect::Mysql || denied.is_empty() {
            return this;
        }
        let words = mysql_identifier_words(sql);
        let keep = |name: &str| -> bool {
            name == "*"
                || words
                    .as_ref()
                    .is_some_and(|w| w.contains(&name.to_ascii_lowercase()))
        };
        let mut changed = false;
        let list = denied
            .iter()
            .map(|d| {
                let mut d = d.clone();
                if d.needed != vericto_engine::Needed::Ddl {
                    if let Some(s) = &d.schema
                        && !is_system_schema(s)
                        && !keep(s)
                    {
                        d.schema = Some("?".into());
                        changed = true;
                    }
                    if !keep(&d.table) {
                        d.table = "?".into();
                        changed = true;
                    }
                    if let Some(c) = &d.column
                        && !keep(c)
                    {
                        d.column = Some("?".into());
                        changed = true;
                    }
                }
                d
            })
            .collect();
        if changed {
            this.redacted = Some(list);
        }
        this
    }

    /// The rule's path: unchanged, or rebuilt from the first redacted denial.
    fn path(&self, original: &str) -> String {
        let Some(list) = &self.redacted else {
            return original.to_string();
        };
        let first = &list[0];
        let mut name = String::new();
        if let Some(s) = &first.schema {
            name.push_str(s);
            name.push('.');
        }
        name.push_str(&first.table);
        if let Some(c) = &first.column {
            name.push('.');
            name.push_str(c);
        }
        let more = match list.len() {
            1 => String::new(),
            n => format!(" (+{} more)", n - 1),
        };
        format!(
            "AccessPolicy > {name} ({}): name redacted (sanitized telemetry){more}",
            first.needed.as_str()
        )
    }

    /// The `access_denied` field: capped and with every name bounded to the
    /// ingest schema's limits, so one long name cannot reject the batch.
    fn payload(&self) -> Vec<crate::telemetry::AccessDeniedPayload> {
        self.redacted
            .as_deref()
            .unwrap_or(self.denied)
            .iter()
            .take(crate::telemetry::MAX_REPORTED_ACCESS_DENIED)
            .map(crate::telemetry::AccessDeniedPayload::from_denied)
            .collect()
    }
}

/// Catalogue and system schemas (engine contract §5): names the engine itself
/// assigns (`pg_catalog` for an unqualified `pg_*`), never a literal.
fn is_system_schema(s: &str) -> bool {
    [
        "information_schema",
        "pg_catalog",
        "pg_toast",
        "mysql",
        "performance_schema",
        "sys",
    ]
    .iter()
    .any(|k| k.eq_ignore_ascii_case(s))
}

/// Lowercased words the MySQL lexer reads as identifiers or keywords (bare or
/// backticked; not `"…"` or `'…'`), or `None` when the text does not lex.
fn mysql_identifier_words(sql: &str) -> Option<std::collections::HashSet<String>> {
    use sqlparser::tokenizer::{Token, Tokenizer};
    let tokens = Tokenizer::new(&sqlparser::dialect::MySqlDialect {}, sql)
        .tokenize()
        .ok()?;
    Some(
        tokens
            .into_iter()
            .filter_map(|t| match t {
                Token::Word(w) if w.quote_style.is_none_or(|q| q == '`') => {
                    Some(w.value.to_ascii_lowercase())
                }
                _ => None,
            })
            .collect(),
    )
}

/// Push a telemetry event for an evaluation. Non-blocking and best-effort: if no
/// sink is configured this is a no-op, and the queue never blocks the SQL path.
pub(crate) fn report_telemetry(
    config: &PgProxyConfig,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
    identity: &EventIdentity,
) {
    let Some(sink) = &config.telemetry else {
        return;
    };
    let event = build_event(
        &sink.database_id,
        sql,
        dialect,
        decision,
        latency_us,
        **config.telemetry_mode.load(),
        identity,
    );
    sink.queue.push(event);
}

/// A VERICTO-085 suggestion in sanitized mode. It is either SQL (the would-be
/// rewrite under `monitor_mode`, which carries the query's literals) or the
/// engine's fixed advice to list the columns, which carries none. SQL is
/// normalized; the advice is kept; anything else is redacted, because it can
/// only be text the proxy has not seen and cannot vouch for.
fn sanitize_suggestion(s: &str, dialect: Dialect) -> String {
    if s.starts_with("List the columns explicitly") {
        return s.to_string();
    }
    match normalize_for(s, dialect) {
        Some(normalized) => normalized,
        None => "<suggestion redacted>".to_string(),
    }
}

/// [`sanitize_query`] with the lexer of the query's own dialect. MySQL text is
/// not Postgres text: there `"…"` is a string (libpg_query would keep it as an
/// identifier, in clear), `\'` escapes a quote, `#` starts a comment, and every
/// mask rewrite quotes its aliases with backticks, which libpg_query rejects.
fn sanitize_for(sql: &str, dialect: Dialect) -> String {
    match dialect {
        Dialect::Mysql => {
            normalize_mysql(sql).unwrap_or_else(|| "<unparseable query redacted>".to_string())
        }
        _ => sanitize_query(sql),
    }
}

fn normalize_for(sql: &str, dialect: Dialect) -> Option<String> {
    match dialect {
        Dialect::Mysql => normalize_mysql(sql),
        _ => pg_query::normalize(sql).ok(),
    }
}

/// MySQL text with every literal (string, number, hex/bit, national) replaced
/// by `?` and every comment by a space; keywords, identifiers, operators and
/// the client's own `?` placeholders are kept. `None` when it does not lex, so
/// the caller redacts it rather than report it raw. The token kinds are those
/// of the sqlparser version pinned with the engine.
fn normalize_mysql(sql: &str) -> Option<String> {
    use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};
    let tokens = Tokenizer::new(&sqlparser::dialect::MySqlDialect {}, sql)
        .tokenize()
        .ok()?;
    let mut out = String::with_capacity(sql.len());
    for t in &tokens {
        match t {
            Token::Number(..)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedByteStringLiteral(_)
            | Token::TripleDoubleQuotedByteStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_)
            | Token::TripleSingleQuotedRawStringLiteral(_)
            | Token::TripleDoubleQuotedRawStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_) => out.push('?'),
            Token::Whitespace(
                Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_),
            ) => out.push(' '),
            other => out.push_str(&other.to_string()),
        }
    }
    Some(out.trim().to_string())
}

/// Normalizes a SQL statement so no user data (literals) is reported: constants
/// are replaced with placeholders ($1, $2, …) via libpg_query. If the query
/// cannot be parsed (e.g. malformed SQL), nothing is leaked — a fixed redaction
/// marker is returned instead of the raw text.
fn sanitize_query(sql: &str) -> String {
    match pg_query::normalize(sql) {
        Ok(normalized) => normalized,
        Err(_) => "<unparseable query redacted>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::evaluator::Observation;
    use vericto_engine::{ReportedViolation, Severity};

    /// Builds a ReportedViolation without depending on a real evaluation, so the
    /// mapping can be tested independently of which rules happen to exist.
    fn violation(code: &str, sev: Severity, action: EnforcementAction) -> ReportedViolation {
        ReportedViolation {
            // Inside this proxy a rule's identity IS its code; the field is set
            // that way by rules_sync and is deliberately not reported.
            rule_id: code.to_string(),
            rule_code: code.to_string(),
            severity: sev,
            action,
            ast_node_path: "SelectStmt".to_string(),
            estimated_rows_affected: Some(7),
            suggested_safe_query: Some("SELECT id FROM t LIMIT 100".to_string()),
        }
    }

    #[test]
    fn telemetry_reports_every_violation_not_only_the_winner() {
        // The defect this covers: a SELECT * without LIMIT violates VERICTO-050 and
        // VERICTO-051, and only the winner used to reach the database.
        let decision = TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: "VERICTO-050".to_string(),
                ast_node_path: "SelectStmt".to_string(),
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: None,
            }),
            violations: vec![
                violation("VERICTO-050", Severity::Medium, EnforcementAction::Flag),
                violation("VERICTO-051", Severity::Medium, EnforcementAction::Flag),
            ],
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT * FROM t", Dialect::Postgres, &decision, 10);

        assert_eq!(ev.violations.len(), 2);
        assert_eq!(ev.violations[0].rule_code, "VERICTO-050");
        assert_eq!(ev.violations[1].rule_code, "VERICTO-051");
        // The winner stays where it was, so a consumer that ignores the new field
        // sees exactly what it saw before.
        assert_eq!(ev.rule_code.as_deref(), Some("VERICTO-050"));
    }

    #[test]
    fn telemetry_carries_each_violations_own_action_and_metadata() {
        // A per-class cap can leave a lower-severity violation resolving to a
        // stronger action than the winner, so the action cannot be derived from the
        // event and has to travel per violation.
        let decision = TcpDecision::Block {
            rule_code: "VERICTO-001".to_string(),
            ast_node_path: "DeleteStmt".to_string(),
            suggested_safe_query: None,
            severity: Severity::Critical,
            violations: vec![
                violation("VERICTO-001", Severity::Critical, EnforcementAction::Block),
                violation(
                    "VERICTO-090",
                    Severity::Critical,
                    EnforcementAction::Monitor,
                ),
            ],
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "DELETE FROM t", Dialect::Postgres, &decision, 10);

        assert_eq!(ev.violations[0].enforcement_action, "block");
        assert_eq!(ev.violations[1].enforcement_action, "monitor");
        assert_eq!(ev.violations[0].severity, "critical");
        assert_eq!(ev.violations[0].estimated_rows_affected, Some(7));
        assert_eq!(
            ev.violations[0].ast_node_path.as_deref(),
            Some("SelectStmt")
        );
    }

    #[test]
    fn telemetry_caps_the_violation_list() {
        // The cap protects the API's 1 MiB batch body limit. Truncation keeps the
        // head of the list, which the engine orders most-severe-first, so the
        // winner is never the entry dropped.
        let muchas: Vec<ReportedViolation> = (0..20)
            .map(|i| {
                violation(
                    &format!("VERICTO-{i:03}"),
                    Severity::Medium,
                    EnforcementAction::Flag,
                )
            })
            .collect();
        let decision = TcpDecision::Forward {
            observation: None,
            violations: muchas,
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 10);

        assert_eq!(
            ev.violations.len(),
            crate::telemetry::MAX_REPORTED_VIOLATIONS
        );
        assert_eq!(ev.violations[0].rule_code, "VERICTO-000");
    }

    #[test]
    fn telemetry_omits_the_field_for_an_allowed_query() {
        // `skip_serializing_if` keeps an ALLOWED event exactly as small as before:
        // these dominate real traffic and must not grow.
        let decision = TcpDecision::Forward {
            observation: None,
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 10);
        assert!(ev.violations.is_empty());
        let json = serde_json::to_string(&ev).expect("event serializes");
        assert!(
            !json.contains("violations"),
            "ALLOWED events must not carry the key"
        );
    }

    #[test]
    fn telemetry_never_reports_rule_id() {
        // The API types rule_id as a UUID and zod parses the whole body at once, so
        // sending this proxy's code-shaped rule_id would reject the ENTIRE batch.
        let decision = TcpDecision::Forward {
            observation: None,
            violations: vec![violation(
                "VERICTO-050",
                Severity::Medium,
                EnforcementAction::Flag,
            )],
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 10);
        let json = serde_json::to_string(&ev).expect("event serializes");
        assert!(!json.contains("rule_id"), "rule_id must not reach the API");
    }

    fn forward_observation(action: EnforcementAction) -> TcpDecision {
        TcpDecision::Forward {
            violations: Vec::new(),
            observation: Some(Observation {
                rule_code: "VERICTO-050".to_string(),
                ast_node_path: "SelectStmt".to_string(),
                severity: Severity::Medium,
                action,
                parse_error: None,
            }),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        }
    }

    #[test]
    fn telemetry_allowed_when_no_observation() {
        let ev = build_telemetry_event(
            "db1",
            "SELECT 1",
            Dialect::Postgres,
            &TcpDecision::Forward {
                observation: None,
                violations: Vec::new(),
                rewritten_query: None,
                sensitive_columns: Vec::new(),
                access_denied: Vec::new(),
            },
            42,
        );
        assert_eq!(ev.status, "ALLOWED");
        assert!(ev.rule_code.is_none());
        assert!(ev.enforcement_action.is_none());
        assert!(ev.severity.is_none());
    }

    #[test]
    fn telemetry_flagged_populates_severity_and_action() {
        let ev = build_telemetry_event(
            "db1",
            "SELECT * FROM t",
            Dialect::Postgres,
            &forward_observation(EnforcementAction::Flag),
            150,
        );
        assert_eq!(ev.status, "FLAGGED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("flag"));
        assert_eq!(ev.severity.as_deref(), Some("medium"));
        assert_eq!(ev.rule_code.as_deref(), Some("VERICTO-050"));
    }

    #[test]
    fn telemetry_monitored_includes_rule_code() {
        let ev = build_telemetry_event(
            "db1",
            "INSERT INTO t VALUES (1)",
            Dialect::Postgres,
            &forward_observation(EnforcementAction::Monitor),
            200,
        );
        assert_eq!(ev.status, "MONITORED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("monitor"));
        assert_eq!(ev.severity.as_deref(), Some("medium"));
        // MONITOR telemetry carries the rule identifier (R7.4).
        assert_eq!(ev.rule_code.as_deref(), Some("VERICTO-050"));
    }

    /// The bound has to be applied where the event is built, not where the batch
    /// is sent: the queue holds up to `memory_capacity` events and the disk spool
    /// writes each one to a file, so an untruncated field is a memory and disk
    /// problem before it is ever an HTTP one.
    #[test]
    fn telemetry_truncates_an_oversized_query() {
        let decision = TcpDecision::Forward {
            observation: None,
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let sql = format!(
            "SELECT * FROM t WHERE x IN ({})",
            "1,".repeat(crate::telemetry::MAX_REPORTED_QUERY_BYTES)
        );
        let ev = build_telemetry_event("db1", &sql, Dialect::Postgres, &decision, 10);
        assert!(
            ev.query_text.len() <= crate::telemetry::MAX_REPORTED_QUERY_BYTES,
            "reported query_text is {} bytes",
            ev.query_text.len()
        );
        assert!(ev.query_text.contains("truncated"));
        // The head of the statement survives, which is what makes the record
        // useful for an audit trail.
        assert!(ev.query_text.starts_with("SELECT * FROM t WHERE x IN ("));
    }

    #[test]
    fn telemetry_keeps_a_normal_query_verbatim() {
        let decision = TcpDecision::Forward {
            observation: None,
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.query_text, "SELECT 1");
    }

    #[test]
    fn telemetry_blocked_populates_action_block() {
        let decision = TcpDecision::Block {
            violations: Vec::new(),
            rule_code: "VERICTO-001".to_string(),
            ast_node_path: "DeleteStmt".to_string(),
            suggested_safe_query: None,
            severity: Severity::Critical,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "DELETE FROM t", Dialect::Mysql, &decision, 80);
        assert_eq!(ev.status, "BLOCKED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("block"));
        assert_eq!(ev.severity.as_deref(), Some("critical"));
        assert_eq!(ev.rule_code.as_deref(), Some("VERICTO-001"));
        // The reported dialect reflects the wire protocol, not a hardcoded default.
        assert_eq!(ev.dialect, "mysql");
    }

    #[test]
    fn telemetry_parse_error_fail_open_carries_message() {
        let decision = TcpDecision::Forward {
            violations: Vec::new(),
            observation: Some(Observation {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: "PARSE_ERROR: boom".to_string(),
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: Some("boom".to_string()),
            }),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "@@@", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.parse_error.as_deref(), Some("boom"));
        assert_eq!(ev.enforcement_action.as_deref(), Some("flag"));
    }

    #[test]
    fn telemetry_parse_error_message_is_bounded() {
        let decision = TcpDecision::Forward {
            violations: Vec::new(),
            observation: Some(Observation {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: "PARSE_ERROR: long".to_string(),
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: Some("x".repeat(10_000)),
            }),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "@@@", Dialect::Postgres, &decision, 10);
        let msg = ev.parse_error.expect("message kept");
        assert!(msg.len() <= crate::telemetry::MAX_REPORTED_PARSE_ERROR_BYTES);
        assert!(msg.starts_with("xxx"));
    }

    #[test]
    fn telemetry_parse_error_fail_closed_is_block() {
        let decision = TcpDecision::Block {
            violations: Vec::new(),
            rule_code: "VERICTO-PARSE-ERROR".to_string(),
            ast_node_path: "PARSE_ERROR: boom".to_string(),
            suggested_safe_query: None,
            severity: Severity::Medium,
            sensitive_columns: Vec::new(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "@@@", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.enforcement_action.as_deref(), Some("block"));
        assert_eq!(ev.parse_error.as_deref(), Some("PARSE_ERROR: boom"));
    }

    fn touched(i: usize, policy: vericto_engine::SensitivePolicy) -> vericto_engine::TouchedColumn {
        vericto_engine::TouchedColumn {
            schema: Some("public".into()),
            table: "customers".into(),
            column: format!("c{i}"),
            policy,
        }
    }

    fn sensitive_violation(suggestion: &str) -> ReportedViolation {
        ReportedViolation {
            suggested_safe_query: Some(suggestion.to_string()),
            ..violation("VERICTO-085", Severity::High, EnforcementAction::Flag)
        }
    }

    /// A mask reports the original, the rewrite and the columns; the rewrite is
    /// not repeated in the VERICTO-085 violation.
    #[test]
    fn telemetry_reports_a_masked_query() {
        let rewritten = "SELECT '[redacted]'::text AS c0 FROM customers";
        let decision = TcpDecision::Forward {
            observation: None,
            violations: vec![sensitive_violation(rewritten)],
            rewritten_query: Some(rewritten.to_string()),
            sensitive_columns: vec![touched(0, vericto_engine::SensitivePolicy::Mask)],
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event(
            "db1",
            "SELECT c0 FROM customers",
            Dialect::Postgres,
            &decision,
            1,
        );
        assert_eq!(ev.query_text, "SELECT c0 FROM customers");
        assert_eq!(ev.rewritten_query.as_deref(), Some(rewritten));
        assert_eq!(ev.violations[0].suggested_safe_query, None);
        assert_eq!(
            ev.sensitive_columns,
            vec![crate::telemetry::SensitiveColumnPayload {
                schema: Some("public".into()),
                table: "customers".into(),
                column: "c0".into(),
                policy: "mask".into(),
            }]
        );
    }

    /// Under monitor_mode the would-be rewrite is only in the suggestion, so in
    /// sanitized mode that is where its literals must be removed.
    #[test]
    fn sanitized_mode_sanitizes_a_sensitive_suggestion() {
        let decision = TcpDecision::Forward {
            observation: None,
            violations: vec![
                sensitive_violation(
                    "SELECT '[redacted]'::text AS email FROM customers WHERE name = 'Alice'",
                ),
                sensitive_violation(
                    "List the columns explicitly: `*`, `t.*`, whole-row references and `COPY table TO` read every tagged column",
                ),
            ],
            rewritten_query: None,
            sensitive_columns: vec![touched(0, vericto_engine::SensitivePolicy::Mask)],
            access_denied: Vec::new(),
        };
        let ev = build_event(
            "db1",
            "SELECT email FROM customers WHERE name = 'Alice'",
            Dialect::Postgres,
            &decision,
            1,
            crate::tcp::rules_sync::TelemetryQueryMode::Sanitized,
            &EventIdentity::default(),
        );
        let s0 = ev.violations[0].suggested_safe_query.as_deref().unwrap();
        assert!(!s0.contains("Alice"), "{s0}");
        assert!(s0.contains("customers"), "{s0}");
        let s1 = ev.violations[1].suggested_safe_query.as_deref().unwrap();
        assert!(s1.starts_with("List the columns explicitly"));
        assert!(!ev.query_text.contains("Alice"));
    }

    /// The ingest schema rejects the whole batch over 64 columns.
    #[test]
    fn telemetry_caps_the_touched_columns() {
        let decision = TcpDecision::Block {
            rule_code: "VERICTO-085".into(),
            ast_node_path: "SensitiveColumn > … (block)".into(),
            suggested_safe_query: None,
            severity: Severity::High,
            violations: Vec::new(),
            sensitive_columns: (0..100)
                .map(|i| touched(i, vericto_engine::SensitivePolicy::Block))
                .collect(),
            access_denied: Vec::new(),
        };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 1);
        assert_eq!(
            ev.sensitive_columns.len(),
            crate::telemetry::MAX_REPORTED_SENSITIVE_COLUMNS
        );
        assert_eq!(ev.rewritten_query, None);
    }

    #[test]
    fn sanitize_query_normalizes_literals() {
        let out =
            sanitize_query("DELETE FROM users WHERE email = 'alice@acme.com' AND tenant_id = 42");
        // Literals are replaced with placeholders; no user data remains.
        assert!(out.contains("$1"), "expected placeholder, got: {out}");
        assert!(out.contains("$2"), "expected placeholder, got: {out}");
        assert!(!out.contains("alice@acme.com"), "PII leaked: {out}");
    }

    /// MySQL text is normalized with the MySQL lexer: a double-quoted value is a
    /// string there (libpg_query reads it as an identifier and keeps it), and a
    /// backtick-quoted identifier, which every MySQL rewrite uses, is not an
    /// error. Literals and comments go; identifiers and placeholders stay.
    #[test]
    fn sanitize_mysql_text_with_the_mysql_lexer() {
        let my = Dialect::Mysql;
        let out = sanitize_for(
            "SELECT CONCAT('****', RIGHT(CAST(`card` AS CHAR), 4)) AS `card` FROM customers \
             WHERE name = \"Alice Secret\" AND note = 'it\\'s' AND id = 42 AND x = ? \
             AND h = x'4142' /* Bob */ -- Carol\n# Dave\n LIMIT 5",
            my,
        );
        for leaked in [
            "Alice", "it", "42", "4142", "Bob", "Carol", "Dave", "'****'", "4)", "5",
        ] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        assert!(out.contains("AS `card` FROM customers"), "{out}");
        assert!(out.contains("x = ?"), "{out}");
        // Not lexable: redacted, never raw.
        assert_eq!(
            sanitize_for("SELECT 'abc", my),
            "<unparseable query redacted>"
        );
        // Postgres keeps libpg_query.
        assert_eq!(
            sanitize_for("SELECT 1", Dialect::Postgres),
            sanitize_query("SELECT 1")
        );
    }

    /// The masked rewrite of a MySQL query is reported sanitized, not redacted.
    #[test]
    fn sanitized_mode_reports_a_mysql_rewrite() {
        let rewritten =
            "SELECT CONCAT('****', RIGHT(`card`, 4)) AS `card` FROM customers WHERE name = 'Alice'";
        let decision = TcpDecision::Forward {
            observation: None,
            violations: vec![sensitive_violation(rewritten)],
            rewritten_query: Some(rewritten.to_string()),
            sensitive_columns: vec![touched(0, vericto_engine::SensitivePolicy::Mask)],
            access_denied: Vec::new(),
        };
        let ev = build_event(
            "db1",
            "SELECT card FROM customers WHERE name = \"Alice\"",
            Dialect::Mysql,
            &decision,
            1,
            crate::tcp::rules_sync::TelemetryQueryMode::Sanitized,
            &EventIdentity::default(),
        );
        assert_eq!(ev.query_text, "SELECT card FROM customers WHERE name = ?");
        assert_eq!(
            ev.rewritten_query.as_deref(),
            Some("SELECT CONCAT(?, RIGHT(`card`, ?)) AS `card` FROM customers WHERE name = ?")
        );
    }

    #[test]
    fn sanitize_query_redacts_unparseable() {
        // Malformed SQL must not leak — a fixed marker is returned instead.
        let out = sanitize_query("SELEC * FORM users WHER id = 1");
        assert_eq!(out, "<unparseable query redacted>");
    }

    // ── Upstream-failure resilience ──────────────────────────────────────────
    //
    // The proxy sits in the production hot path, so its behavior when the real
    // database is unreachable or drops mid-session must be verified, not
    // assumed. These tests drive the REAL session entrypoint (`handle_connection`
    // → `run_session`) against a controllable fake upstream and assert the
    // observable contract from the client's side:
    //
    //   * connection phase: if the upstream refuses or dies before startup is
    //     forwarded, the client connection is closed (fail-closed to traffic —
    //     no query ever reaches a database), and the proxy task terminates
    //     rather than hanging a connection open.
    //   * command phase: if the upstream dies after startup, the relay/intercept
    //     loops unwind and the session ends (no dangling task, no deadlock).
    //
    // During the connection phase the proxy answers a native ErrorResponse
    // (SQLSTATE 08006, connection_failure) so the driver surfaces a typed error
    // instead of a bare closed socket. Once server bytes are already flowing the
    // stream is mid-session and it falls back to a plain close (injecting there
    // would corrupt the protocol).
    use crate::tcp::codec::{PgMessage, SQLSTATE_CONNECTION_FAILURE};
    use arc_swap::ArcSwap;
    use tokio::net::{TcpListener, TcpStream};

    /// Reads one message from the client socket and asserts it is a PostgreSQL
    /// `ErrorResponse` ('E') carrying the given SQLSTATE (field 'C'). Returns the
    /// decoded fields for further inspection.
    async fn read_error_response(client: &mut TcpStream, expect_sqlstate: &str) {
        let mut header = [0u8; 5]; // tag + Int32 len
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut header),
        )
        .await
        .expect("client read must not hang")
        .expect("expected an ErrorResponse, got EOF/error");
        assert_eq!(header[0], b'E', "expected ErrorResponse tag 'E'");
        let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut body = vec![0u8; len - 4];
        client
            .read_exact(&mut body)
            .await
            .expect("short ErrorResponse body");
        // Body is a sequence of [field-byte][cstring]; find the 'C' (SQLSTATE).
        let mut i = 0;
        let mut sqlstate = None;
        while i < body.len() && body[i] != 0 {
            let field = body[i];
            i += 1;
            let start = i;
            while i < body.len() && body[i] != 0 {
                i += 1;
            }
            let value = std::str::from_utf8(&body[start..i]).unwrap_or("");
            if field == b'C' {
                sqlstate = Some(value.to_string());
            }
            i += 1; // skip the cstring terminator
        }
        assert_eq!(
            sqlstate.as_deref(),
            Some(expect_sqlstate),
            "ErrorResponse must carry SQLSTATE {expect_sqlstate}"
        );
    }

    /// Builds a minimal `PgProxyConfig` pointing at `upstream` (host, port), with
    /// the built-in ruleset, default policy, no client TLS and no telemetry.
    fn test_config(upstream_host: &str, upstream_port: u16) -> Arc<PgProxyConfig> {
        Arc::new(PgProxyConfig {
            upstream_host: upstream_host.to_string(),
            upstream_port,
            upstream_tls: crate::tcp::upstream::UpstreamTlsMode::Disable,
            upstream_ca_path: None,
            upstream_client_cert: None,
            upstream_client_key: None,
            client_tls_acceptor: None,
            ruleset: Arc::new(ArcSwap::from_pointee(
                crate::tcp::evaluator::default_ruleset(),
            )),
            policy: Arc::new(ArcSwap::from_pointee(
                vericto_engine::EnforcementPolicy::default(),
            )),
            agent_access: Arc::new(ArcSwap::from_pointee(
                vericto_engine::AccessPolicyMap::default(),
            )),
            telemetry_mode: Arc::new(ArcSwap::from_pointee(
                crate::tcp::rules_sync::TelemetryQueryMode::default(),
            )),
            telemetry: None,
            max_query_bytes: crate::tcp::query_limit::DEFAULT_MAX_QUERY_BYTES,
        })
    }

    /// A minimal, well-formed pgwire v3 StartupMessage (protocol 3.0) carrying
    /// `user=app`. Enough to get the proxy past startup parsing and into the
    /// upstream-connect phase.
    fn startup_message() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&196_608i32.to_be_bytes()); // protocol 3.0
        body.extend_from_slice(b"user\0app\0");
        body.push(0); // terminator
        let mut msg = Vec::new();
        msg.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    /// Reserves a TCP port and immediately drops the listener, yielding an
    /// address where `connect` will be refused (nothing is listening).
    async fn dead_upstream_addr() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        addr
    }

    #[tokio::test]
    async fn upstream_connection_refused_closes_client_without_hanging() {
        let dead = dead_upstream_addr().await;
        let config = test_config(&dead.ip().to_string(), dead.port());

        // The proxy listens; a client connects and completes startup.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            // Drive the real session handler; it must return (not hang) once the
            // upstream connect fails.
            handle_connection(client, config).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        client.flush().await.unwrap();

        // Fail-closed to traffic (no query ever reaches a database), but the
        // client gets a typed error rather than a bare EOF: a native
        // ErrorResponse with SQLSTATE 08006 (connection_failure).
        read_error_response(&mut client, SQLSTATE_CONNECTION_FAILURE).await;

        // The session task must have terminated (no dangling connection).
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("session task must terminate when upstream connect fails")
            .unwrap();
    }

    #[tokio::test]
    async fn upstream_accepts_then_drops_during_auth_ends_session() {
        // Fake upstream that accepts the TCP connection, reads the forwarded
        // StartupMessage, then drops the socket — simulating a DB that dies
        // right after accepting (before completing the auth handshake).
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 128];
            let _ = sock.read(&mut buf).await; // read the forwarded startup
            drop(sock); // die mid-auth
        });

        let config = test_config(&upstream_addr.ip().to_string(), upstream_addr.port());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            handle_connection(client, config).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        client.flush().await.unwrap();

        // The upstream dropped after startup but before any byte reached the
        // client, so the client is still in the connection phase: it must get a
        // native ErrorResponse (08006), not a hang and not a bare EOF. This is
        // the case that used to deadlock.
        read_error_response(&mut client, SQLSTATE_CONNECTION_FAILURE).await;

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("session task must terminate when upstream drops mid-auth")
            .unwrap();
        let _ = upstream_task.await;
    }

    #[tokio::test]
    async fn no_query_reaches_a_database_when_upstream_is_down() {
        // Guard the security-relevant invariant explicitly: with the upstream
        // unreachable, the session ends during connect — the interception loop
        // (which forwards allowed queries) is never entered, so no client SQL
        // can slip through to a database. We assert the session returns quickly
        // and the client is closed before any command-phase byte is exchanged.
        let dead = dead_upstream_addr().await;
        let config = test_config(&dead.ip().to_string(), dead.port());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            handle_connection(client, config).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        client.flush().await.unwrap();
        // Try to push a query as if authenticated; it must never be forwarded
        // (there is no upstream to forward to and the session is unwinding).
        let query = PgMessage {
            tag: b'Q',
            body: b"SELECT 1\0".to_vec(),
        }
        .encode();
        let _ = client.write_all(&query).await; // may error if already closed

        // The only thing the client receives is the connection-failure
        // ErrorResponse — never a result for its query, because the upstream was
        // unreachable and the interception loop (which forwards allowed queries)
        // was never entered.
        read_error_response(&mut client, SQLSTATE_CONNECTION_FAILURE).await;

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("session must terminate")
            .unwrap();
    }

    #[tokio::test]
    async fn upstream_death_after_data_flowing_falls_back_to_close() {
        // Once the upstream has sent bytes that the relay forwarded to the client
        // (session established), a later upstream death must NOT inject an
        // ErrorResponse — that would corrupt the mid-stream protocol. The client
        // instead sees the relayed bytes followed by a clean close (EOF).
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 128];
            let _ = sock.read(&mut buf).await; // read forwarded startup
            // Send a byte pattern that is NOT an ErrorResponse (tag 'R' =
            // Authentication), so the test can tell relayed data from an injected
            // error, then die.
            let _ = sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]).await;
            let _ = sock.flush().await;
            drop(sock);
        });

        let config = test_config(&upstream_addr.ip().to_string(), upstream_addr.port());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            handle_connection(client, config).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        client.flush().await.unwrap();

        // First byte the client sees is the relayed server message (tag 'R'),
        // NOT an injected ErrorResponse ('E').
        let mut tag = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut tag),
        )
        .await
        .expect("must not hang")
        .expect("expected relayed server bytes");
        assert_eq!(
            tag[0], b'R',
            "expected relayed server byte, not an injected error"
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("session must terminate after upstream dies mid-session")
            .unwrap();
        let _ = upstream_task.await;
    }

    /// A `TlsAcceptor` for tests that never complete a handshake: it has no
    /// certificate at all, which is enough to put `negotiate_startup` in
    /// `PROXY_TLS_MODE=require` mode.
    fn require_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
        use tokio_rustls::rustls::sign::CertifiedKey;

        #[derive(Debug)]
        struct NoCert;
        impl ResolvesServerCert for NoCert {
            fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                None
            }
        }
        // The same provider main() installs; idempotent across tests.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCert));
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    /// An upstream that records whether anything ever connected to it.
    async fn watched_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<bool>) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_millis(500), upstream.accept())
                .await
                .is_ok()
        });
        (addr, task)
    }

    #[tokio::test]
    async fn require_tls_rejects_a_plaintext_startup_before_the_upstream() {
        let (upstream_addr, upstream_contacted) = watched_upstream().await;
        let mut config = test_config(&upstream_addr.ip().to_string(), upstream_addr.port());
        Arc::get_mut(&mut config).unwrap().client_tls_acceptor = Some(require_tls_acceptor());

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            handle_connection(client, config).await;
        });

        // The client skips SSLRequest and sends its StartupMessage in plaintext.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        client.flush().await.unwrap();

        read_error_response(
            &mut client,
            crate::tcp::codec::SQLSTATE_INVALID_AUTHORIZATION,
        )
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("session must terminate after the rejection")
            .unwrap();
        assert!(
            !upstream_contacted.await.unwrap(),
            "a plaintext client must never reach the database under PROXY_TLS_MODE=require"
        );
    }

    #[tokio::test]
    async fn require_tls_still_accepts_an_ssl_request() {
        let (upstream_addr, _upstream) = watched_upstream().await;
        let mut config = test_config(&upstream_addr.ip().to_string(), upstream_addr.port());
        Arc::get_mut(&mut config).unwrap().client_tls_acceptor = Some(require_tls_acceptor());

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            handle_connection(client, config).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        // SSLRequest: Int32 length 8, Int32 code 80877103.
        client
            .write_all(&[0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F])
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut reply = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut reply),
        )
        .await
        .expect("must not hang")
        .unwrap();
        assert_eq!(reply[0], b'S', "an SSLRequest must still be accepted");
    }
}
