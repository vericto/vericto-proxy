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
use crate::tcp::codec::{StartupPacket, read_startup_packet};
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
    /// Hot-swappable telemetry query mode (raw | sanitized) shared with the syncer.
    pub telemetry_mode: crate::tcp::rules_sync::SharedTelemetryMode,
    /// Optional telemetry sink: when set, each evaluation is reported. The
    /// database_id identifies which connected database this proxy fronts.
    pub telemetry: Option<TelemetrySink>,
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
    let (mut client_read, mut client_write, startup_raw) =
        negotiate_startup(client, config.client_tls_acceptor.as_ref()).await?;

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
        r = intercept_client_to_server(&mut client_read, &mut server_write, &client_write, &config) => {
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

/// Negotiates the startup phase and returns the client transport halves plus the
/// raw StartupMessage bytes.
///
/// When `acceptor` is `Some` and the client sends an `SSLRequest`, the proxy
/// answers `'S'`, performs the server-side TLS handshake, and reads the
/// StartupMessage over the encrypted channel. Otherwise it declines encryption
/// (`'N'`) and continues in plaintext — the trusted-network deployment model.
async fn negotiate_startup(
    mut client: TcpStream,
    acceptor: Option<&tokio_rustls::TlsAcceptor>,
) -> std::io::Result<(ClientRead, ClientWrite, Vec<u8>)> {
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
                    let raw = read_startup_message(&mut read).await?;
                    return Ok((read, write, raw));
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
                tracing::debug!(
                    user = ?params.user,
                    database = ?params.database,
                    "StartupMessage received"
                );
                let (read, write) = tokio::io::split(client);
                return Ok((Box::new(read), Box::new(write), raw));
            }
        }
    }
}

/// Reads a single startup packet expecting the StartupMessage (used after a TLS
/// handshake, where the next message must be the StartupMessage).
async fn read_startup_message<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    match read_startup_packet(reader).await? {
        StartupPacket::Startup { raw, params } => {
            tracing::debug!(
                user = ?params.user,
                database = ?params.database,
                "StartupMessage received (over TLS)"
            );
            Ok(raw)
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
    config: &PgProxyConfig,
) -> std::io::Result<()> {
    let proto = crate::tcp::protocol::postgres::PostgresProtocol;
    crate::tcp::session::intercept_client_to_server(
        &proto,
        client_read,
        server_write,
        client_write,
        config,
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

/// Builds a telemetry event from an evaluation decision. Pure (no I/O) so it can
/// be unit-tested. Returns `None` only when there is nothing to report (never,
/// currently — every decision maps to a status).
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

fn build_telemetry_event(
    database_id: &str,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
) -> crate::telemetry::TelemetryEvent {
    let mut severity: Option<String> = None;
    let mut enforcement_action: Option<String> = None;
    let mut parse_error: Option<String> = None;

    let (status, rule_code, ast_node_path) = match decision {
        // No violation: forwarded silently.
        TcpDecision::Forward { observation: None } => ("ALLOWED".to_string(), None, None),

        // Non-blocking violation (Flag/Monitor) or parse-error allow-report.
        TcpDecision::Forward {
            observation: Some(obs),
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

    crate::telemetry::TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        database_id: database_id.to_string(),
        query_text: crate::telemetry::truncate_reported_query(sql),
        dialect: dialect_name(dialect).to_string(),
        status,
        rule_code,
        ast_node_path,
        severity,
        enforcement_action,
        parse_error,
        latency_ms: Some(latency_us as f64 / 1000.0),
        client_ip: None,
        occurred_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Push a telemetry event for an evaluation. Non-blocking and best-effort: if no
/// sink is configured this is a no-op, and the queue never blocks the SQL path.
pub(crate) fn report_telemetry(
    config: &PgProxyConfig,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
) {
    use crate::tcp::rules_sync::TelemetryQueryMode;

    let Some(sink) = &config.telemetry else {
        return;
    };

    // Privacy: when the workspace policy selects "sanitized", normalize literals
    // to placeholders before the query text leaves the customer network. Rule
    // evaluation already happened on the full query — this only affects reporting.
    let reported_sql: std::borrow::Cow<'_, str> = match **config.telemetry_mode.load() {
        TelemetryQueryMode::Raw => std::borrow::Cow::Borrowed(sql),
        TelemetryQueryMode::Sanitized => std::borrow::Cow::Owned(sanitize_query(sql)),
    };

    let event = build_telemetry_event(
        &sink.database_id,
        &reported_sql,
        dialect,
        decision,
        latency_us,
    );
    sink.queue.push(event);
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
    use vericto_engine::Severity;

    fn forward_observation(action: EnforcementAction) -> TcpDecision {
        TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: "VERICTO-050".to_string(),
                ast_node_path: "SelectStmt".to_string(),
                severity: Severity::Medium,
                action,
                parse_error: None,
            }),
        }
    }

    #[test]
    fn telemetry_allowed_when_no_observation() {
        let ev = build_telemetry_event(
            "db1",
            "SELECT 1",
            Dialect::Postgres,
            &TcpDecision::Forward { observation: None },
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
        let decision = TcpDecision::Forward { observation: None };
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
        let decision = TcpDecision::Forward { observation: None };
        let ev = build_telemetry_event("db1", "SELECT 1", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.query_text, "SELECT 1");
    }

    #[test]
    fn telemetry_blocked_populates_action_block() {
        let decision = TcpDecision::Block {
            rule_code: "VERICTO-001".to_string(),
            ast_node_path: "DeleteStmt".to_string(),
            suggested_safe_query: None,
            severity: Severity::Critical,
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
            observation: Some(Observation {
                rule_code: "VERICTO-PARSE-ERROR".to_string(),
                ast_node_path: "PARSE_ERROR: boom".to_string(),
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: Some("boom".to_string()),
            }),
        };
        let ev = build_telemetry_event("db1", "@@@", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.parse_error.as_deref(), Some("boom"));
        assert_eq!(ev.enforcement_action.as_deref(), Some("flag"));
    }

    #[test]
    fn telemetry_parse_error_fail_closed_is_block() {
        let decision = TcpDecision::Block {
            rule_code: "VERICTO-PARSE-ERROR".to_string(),
            ast_node_path: "PARSE_ERROR: boom".to_string(),
            suggested_safe_query: None,
            severity: Severity::Medium,
        };
        let ev = build_telemetry_event("db1", "@@@", Dialect::Postgres, &decision, 10);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.enforcement_action.as_deref(), Some("block"));
        assert_eq!(ev.parse_error.as_deref(), Some("PARSE_ERROR: boom"));
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
            telemetry_mode: Arc::new(ArcSwap::from_pointee(
                crate::tcp::rules_sync::TelemetryQueryMode::default(),
            )),
            telemetry: None,
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
}
