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

use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::tcp::client_tls::{ClientRead, ClientWrite};
use crate::tcp::codec::{
    build_error_response, build_ready_for_query, extract_parse_query, extract_simple_query,
    read_message, read_startup_packet, StartupPacket, SQLSTATE_INSUFFICIENT_PRIVILEGE,
};
use crate::tcp::evaluator::{evaluate, TcpDecision};
use vetro_engine::parser::Dialect;
use vetro_engine::EnforcementAction;

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
    let (mut client_read, client_write, startup_raw) =
        negotiate_startup(client, config.client_tls_acceptor.as_ref()).await?;

    // ── Phase 2: connect upstream (optionally over TLS) and forward the StartupMessage
    let (server_read, mut server_write) = crate::tcp::upstream::connect_upstream(
        &config.upstream_host,
        config.upstream_port,
        config.upstream_tls,
        config.upstream_ca_path.as_deref(),
        config.upstream_client_cert.as_deref(),
        config.upstream_client_key.as_deref(),
    )
    .await?;
    server_write.write_all(&startup_raw).await?;
    server_write.flush().await?;

    // ── Phase 3: the client write half is shared (relay + errors)
    let client_write = Arc::new(Mutex::new(client_write));

    // Relay server→client (auth, data, notices) without intercepting.
    let relay_handle = tokio::spawn(relay_server_to_client(server_read, client_write.clone()));

    // ── Phase 4: client→server interception loop
    let result =
        intercept_client_to_server(&mut client_read, &mut server_write, &client_write, &config)
            .await;

    relay_handle.abort();
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
async fn relay_server_to_client(
    mut server_read: crate::tcp::upstream::UpstreamRead,
    client_write: Arc<Mutex<ClientWrite>>,
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
            }
            Err(_) => break,
        }
    }
}

/// Main loop: reads client messages, intercepts Query/Parse, forwards the rest.
async fn intercept_client_to_server(
    client_read: &mut ClientRead,
    server_write: &mut crate::tcp::upstream::UpstreamWrite,
    client_write: &Arc<Mutex<ClientWrite>>,
    config: &PgProxyConfig,
) -> std::io::Result<()> {
    // In the extended protocol, if we block at Parse we must swallow the
    // following messages until Sync ('S') and then send ReadyForQuery.
    let mut skip_until_sync = false;

    loop {
        let msg = match read_message(client_read).await? {
            Some(m) => m,
            None => break, // client closed
        };

        if skip_until_sync {
            if msg.tag == b'S' {
                // Sync: close the aborted extended sequence.
                send_to_client(client_write, &build_ready_for_query()).await?;
                skip_until_sync = false;
            }
            continue; // swallow Bind/Describe/Execute/Flush
        }

        match msg.tag {
            // Simple Query
            b'Q' => {
                if let Some(sql) = extract_simple_query(&msg) {
                    // Read the current ruleset and policy lock-free (syncer may swap them).
                    let rules = config.ruleset.load();
                    let policy = config.policy.load();
                    let eval_start = Instant::now();
                    let decision = evaluate(&sql, Dialect::Postgres, &rules, &policy);
                    let eval_us = eval_start.elapsed().as_micros();
                    // Telemetry is emitted before any forwarding (R5.7).
                    report_telemetry(config, &sql, &decision, eval_us);
                    if let TcpDecision::Block {
                        rule_code,
                        ast_node_path,
                        suggested_safe_query,
                        ..
                    } = decision
                    {
                        log_block(&sql, &rule_code, &ast_node_path);
                        send_block_simple(
                            client_write,
                            &rule_code,
                            &ast_node_path,
                            suggested_safe_query.as_deref(),
                        )
                        .await?;
                        continue;
                    }
                }
                forward(server_write, &msg.encode()).await?;
            }

            // Parse (extended protocol)
            b'P' => {
                if let Some(sql) = extract_parse_query(&msg) {
                    let rules = config.ruleset.load();
                    let policy = config.policy.load();
                    let eval_start = Instant::now();
                    let decision = evaluate(&sql, Dialect::Postgres, &rules, &policy);
                    let eval_us = eval_start.elapsed().as_micros();
                    // Telemetry is emitted before any forwarding (R5.7).
                    report_telemetry(config, &sql, &decision, eval_us);
                    if let TcpDecision::Block {
                        rule_code,
                        ast_node_path,
                        ..
                    } = decision
                    {
                        log_block(&sql, &rule_code, &ast_node_path);
                        let err = build_error_response(
                            SQLSTATE_INSUFFICIENT_PRIVILEGE,
                            &block_message(&rule_code, &ast_node_path, None),
                        );
                        send_to_client(client_write, &err).await?;
                        skip_until_sync = true;
                        continue;
                    }
                }
                forward(server_write, &msg.encode()).await?;
            }

            // Terminate
            b'X' => {
                forward(server_write, &msg.encode()).await?;
                break;
            }

            // Rest (Bind, Execute, Sync, PasswordMessage, etc.): forward as-is.
            _ => {
                forward(server_write, &msg.encode()).await?;
            }
        }
    }

    Ok(())
}

/// Sends a block in the simple protocol: ErrorResponse + ReadyForQuery.
async fn send_block_simple(
    client_write: &Arc<Mutex<ClientWrite>>,
    rule_code: &str,
    ast_node_path: &str,
    suggestion: Option<&str>,
) -> std::io::Result<()> {
    let err = build_error_response(
        SQLSTATE_INSUFFICIENT_PRIVILEGE,
        &block_message(rule_code, ast_node_path, suggestion),
    );
    let mut out = err;
    out.extend_from_slice(&build_ready_for_query());
    send_to_client(client_write, &out).await
}

fn block_message(rule_code: &str, ast_node_path: &str, suggestion: Option<&str>) -> String {
    let base = format!("Vetro blocked this query [{rule_code}] — AST node: {ast_node_path}");
    match suggestion {
        Some(s) => format!("{base}. Suggestion: {s}"),
        None => base,
    }
}

async fn send_to_client(
    client_write: &Arc<Mutex<ClientWrite>>,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut writer = client_write.lock().await;
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn forward(
    server_write: &mut crate::tcp::upstream::UpstreamWrite,
    bytes: &[u8],
) -> std::io::Result<()> {
    server_write.write_all(bytes).await?;
    server_write.flush().await
}

fn log_block(sql: &str, rule_code: &str, ast_node_path: &str) {
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
fn build_telemetry_event(
    database_id: &str,
    sql: &str,
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
            let status = if rule_code == "VETRO-PARSE-ERROR" {
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
        query_text: sql.to_string(),
        dialect: "postgres".to_string(),
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
fn report_telemetry(config: &PgProxyConfig, sql: &str, decision: &TcpDecision, latency_us: u128) {
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

    let event = build_telemetry_event(&sink.database_id, &reported_sql, decision, latency_us);
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
    use vetro_engine::Severity;

    fn forward_observation(action: EnforcementAction) -> TcpDecision {
        TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: "VETRO-050".to_string(),
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
            &forward_observation(EnforcementAction::Flag),
            150,
        );
        assert_eq!(ev.status, "FLAGGED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("flag"));
        assert_eq!(ev.severity.as_deref(), Some("medium"));
        assert_eq!(ev.rule_code.as_deref(), Some("VETRO-050"));
    }

    #[test]
    fn telemetry_monitored_includes_rule_code() {
        let ev = build_telemetry_event(
            "db1",
            "INSERT INTO t VALUES (1)",
            &forward_observation(EnforcementAction::Monitor),
            200,
        );
        assert_eq!(ev.status, "MONITORED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("monitor"));
        assert_eq!(ev.severity.as_deref(), Some("medium"));
        // MONITOR telemetry carries the rule identifier (R7.4).
        assert_eq!(ev.rule_code.as_deref(), Some("VETRO-050"));
    }

    #[test]
    fn telemetry_blocked_populates_action_block() {
        let decision = TcpDecision::Block {
            rule_code: "VETRO-001".to_string(),
            ast_node_path: "DeleteStmt".to_string(),
            suggested_safe_query: None,
            severity: Severity::Critical,
        };
        let ev = build_telemetry_event("db1", "DELETE FROM t", &decision, 80);
        assert_eq!(ev.status, "BLOCKED");
        assert_eq!(ev.enforcement_action.as_deref(), Some("block"));
        assert_eq!(ev.severity.as_deref(), Some("critical"));
        assert_eq!(ev.rule_code.as_deref(), Some("VETRO-001"));
    }

    #[test]
    fn telemetry_parse_error_fail_open_carries_message() {
        let decision = TcpDecision::Forward {
            observation: Some(Observation {
                rule_code: "VETRO-PARSE-ERROR".to_string(),
                ast_node_path: "PARSE_ERROR: boom".to_string(),
                severity: Severity::Medium,
                action: EnforcementAction::Flag,
                parse_error: Some("boom".to_string()),
            }),
        };
        let ev = build_telemetry_event("db1", "@@@", &decision, 10);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.parse_error.as_deref(), Some("boom"));
        assert_eq!(ev.enforcement_action.as_deref(), Some("flag"));
    }

    #[test]
    fn telemetry_parse_error_fail_closed_is_block() {
        let decision = TcpDecision::Block {
            rule_code: "VETRO-PARSE-ERROR".to_string(),
            ast_node_path: "PARSE_ERROR: boom".to_string(),
            suggested_safe_query: None,
            severity: Severity::Medium,
        };
        let ev = build_telemetry_event("db1", "@@@", &decision, 10);
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
}
