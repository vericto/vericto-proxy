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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use vetro_engine::parser::Dialect;
use vetro_engine::EnforcementAction;
use crate::tcp::codec::{
    build_error_response, build_ready_for_query, extract_parse_query, extract_simple_query,
    read_message, read_startup_packet, StartupPacket, SQLSTATE_INSUFFICIENT_PRIVILEGE,
};
use crate::tcp::evaluator::{evaluate, TcpDecision};

/// PostgreSQL TCP proxy configuration.
pub struct PgProxyConfig {
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Hot-swappable ruleset shared with the rule syncer. Read lock-free per query.
    pub ruleset: crate::tcp::rules_sync::SharedRuleset,
    /// Hot-swappable enforcement policy shared with the rule syncer.
    pub policy: crate::tcp::rules_sync::SharedPolicy,
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

async fn run_session(mut client: TcpStream, config: Arc<PgProxyConfig>) -> std::io::Result<()> {
    // ── Phase 1: negotiate startup (decline TLS/GSS until StartupMessage arrives)
    let startup_raw = negotiate_startup(&mut client).await?;

    // ── Phase 2: connect upstream and forward the StartupMessage
    let upstream =
        TcpStream::connect((config.upstream_host.as_str(), config.upstream_port)).await?;
    // Disable Nagle's algorithm on the upstream socket. Without this, small
    // forwarded messages interact with TCP delayed-ACK and incur a ~40ms delay
    // per round-trip (classic Nagle + delayed-ACK stall).
    let _ = upstream.set_nodelay(true);
    let (server_read, mut server_write) = upstream.into_split();
    server_write.write_all(&startup_raw).await?;
    server_write.flush().await?;

    // ── Phase 3: split the client; the write half is shared (relay + errors)
    let (mut client_read, client_write) = client.into_split();
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

/// Declines TLS/GSS and returns the raw bytes of the real StartupMessage.
async fn negotiate_startup(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    loop {
        match read_startup_packet(client).await? {
            StartupPacket::SslRequest | StartupPacket::GssRequest => {
                // Decline proxy-level encryption ('N'). In a TLS deployment, TLS
                // termination would happen here. The proxy↔upstream traffic goes
                // over the trusted internal network.
                client.write_all(b"N").await?;
                client.flush().await?;
            }
            StartupPacket::Startup { raw, params } => {
                tracing::debug!(
                    user = ?params.user,
                    database = ?params.database,
                    "StartupMessage received"
                );
                return Ok(raw);
            }
        }
    }
}

/// Relays bytes from the server to the client without intercepting.
async fn relay_server_to_client(
    mut server_read: OwnedReadHalf,
    client_write: Arc<Mutex<OwnedWriteHalf>>,
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
    client_read: &mut OwnedReadHalf,
    server_write: &mut OwnedWriteHalf,
    client_write: &Arc<Mutex<OwnedWriteHalf>>,
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
                    let decision = evaluate(&sql, Dialect::Postgres, &rules, &policy);
                    // Telemetry is emitted before any forwarding (R5.7).
                    report_telemetry(config, &sql, &decision);
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
                    let decision = evaluate(&sql, Dialect::Postgres, &rules, &policy);
                    // Telemetry is emitted before any forwarding (R5.7).
                    report_telemetry(config, &sql, &decision);
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
    client_write: &Arc<Mutex<OwnedWriteHalf>>,
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
    client_write: &Arc<Mutex<OwnedWriteHalf>>,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut writer = client_write.lock().await;
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn forward(server_write: &mut OwnedWriteHalf, bytes: &[u8]) -> std::io::Result<()> {
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
        latency_ms: None,
        client_ip: None,
        occurred_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Push a telemetry event for an evaluation. Non-blocking and best-effort: if no
/// sink is configured this is a no-op, and the queue never blocks the SQL path.
fn report_telemetry(config: &PgProxyConfig, sql: &str, decision: &TcpDecision) {
    let Some(sink) = &config.telemetry else {
        return;
    };
    let event = build_telemetry_event(&sink.database_id, sql, decision);
    sink.queue.push(event);
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
        let ev = build_telemetry_event("db1", "DELETE FROM t", &decision);
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
        let ev = build_telemetry_event("db1", "@@@", &decision);
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
        let ev = build_telemetry_event("db1", "@@@", &decision);
        assert_eq!(ev.status, "PARSE_ERROR");
        assert_eq!(ev.enforcement_action.as_deref(), Some("block"));
        assert_eq!(ev.parse_error.as_deref(), Some("PARSE_ERROR: boom"));
    }
}
