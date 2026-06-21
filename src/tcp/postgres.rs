//! Handler de sesión del proxy TCP de PostgreSQL.
//!
//! Termina el protocolo de wire de PostgreSQL de forma transparente: el cliente
//! (Prisma, SQLAlchemy, psql, ...) se conecta creyendo que habla con Postgres.
//! El proxy:
//!   1. Negocia la fase de startup (declina TLS/GSS, reenvía StartupMessage).
//!   2. Abre una conexión upstream al Postgres real y reenvía el startup.
//!   3. Relaya server→cliente sin tocar.
//!   4. Intercepta cliente→server: extrae el SQL de los mensajes Query ('Q') y
//!      Parse ('P'), lo evalúa con el motor AST y, si es destructivo, responde
//!      un ErrorResponse nativo SIN reenviar la query al motor real.
//!
//! Best practices aplicadas:
//! - Lectura por mensaje completo (read_exact gestiona TCP segmentado).
//! - Fail-closed: una query que no parsea o un fallo de evaluación bloquea.
//! - Escritura al cliente serializada con un Mutex (relay + inyección de errores).
//! - Límites de tamaño de mensaje (codec) para mitigar DoS.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::parser::Dialect;
use crate::tcp::codec::{
    build_error_response, build_ready_for_query, extract_parse_query,
    extract_simple_query, read_message, read_startup_packet, StartupPacket,
    SQLSTATE_INSUFFICIENT_PRIVILEGE,
};
use crate::tcp::evaluator::{evaluate, TcpDecision};

/// Configuración del proxy TCP de Postgres.
pub struct PgProxyConfig {
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Hot-swappable ruleset shared with the rule syncer. Read lock-free per query.
    pub ruleset: crate::rules::sync::SharedRuleset,
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

/// Gestiona una conexión entrante completa. Cualquier error cierra la conexión.
pub async fn handle_connection(client: TcpStream, config: Arc<PgProxyConfig>) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    if let Err(e) = run_session(client, config).await {
        tracing::debug!(peer = %peer, error = %e, "Sesión TCP terminada");
    }
}

async fn run_session(
    mut client: TcpStream,
    config: Arc<PgProxyConfig>,
) -> std::io::Result<()> {
    // ── Fase 1: negociar el startup (declinar TLS/GSS hasta recibir StartupMessage)
    let startup_raw = negotiate_startup(&mut client).await?;

    // ── Fase 2: conectar upstream y reenviar el StartupMessage
    let upstream = TcpStream::connect((config.upstream_host.as_str(), config.upstream_port)).await?;
    let (server_read, mut server_write) = upstream.into_split();
    server_write.write_all(&startup_raw).await?;
    server_write.flush().await?;

    // ── Fase 3: split del cliente; el write half se comparte (relay + errores)
    let (mut client_read, client_write) = client.into_split();
    let client_write = Arc::new(Mutex::new(client_write));

    // Relay server→cliente (auth, datos, notices) sin interceptar.
    let relay_handle = tokio::spawn(relay_server_to_client(server_read, client_write.clone()));

    // ── Fase 4: loop de intercepción cliente→server
    let result = intercept_client_to_server(
        &mut client_read,
        &mut server_write,
        &client_write,
        &config,
    )
    .await;

    relay_handle.abort();
    result
}

/// Declina TLS/GSS y devuelve los bytes crudos del StartupMessage real.
async fn negotiate_startup(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    loop {
        match read_startup_packet(client).await? {
            StartupPacket::SslRequest | StartupPacket::GssRequest => {
                // Declinamos el cifrado a nivel de proxy ('N'). En un despliegue
                // con TLS, aquí se haría la terminación TLS. El tráfico
                // proxy↔upstream va por la red interna confiable.
                client.write_all(b"N").await?;
                client.flush().await?;
            }
            StartupPacket::Startup { raw, params } => {
                tracing::debug!(
                    user = ?params.user,
                    database = ?params.database,
                    "StartupMessage recibido"
                );
                return Ok(raw);
            }
        }
    }
}

/// Relaya bytes del servidor al cliente sin interceptar.
async fn relay_server_to_client(
    mut server_read: OwnedReadHalf,
    client_write: Arc<Mutex<OwnedWriteHalf>>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match server_read.read(&mut buf).await {
            Ok(0) => break, // upstream cerró
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

/// Loop principal: lee mensajes del cliente, intercepta Query/Parse, reenvía el resto.
async fn intercept_client_to_server(
    client_read: &mut OwnedReadHalf,
    server_write: &mut OwnedWriteHalf,
    client_write: &Arc<Mutex<OwnedWriteHalf>>,
    config: &PgProxyConfig,
) -> std::io::Result<()> {
    // En el protocolo extendido, si bloqueamos en Parse debemos tragar los
    // mensajes siguientes hasta el Sync ('S') y entonces enviar ReadyForQuery.
    let mut skip_until_sync = false;

    loop {
        let msg = match read_message(client_read).await? {
            Some(m) => m,
            None => break, // cliente cerró
        };

        if skip_until_sync {
            if msg.tag == b'S' {
                // Sync: cerramos la secuencia extendida abortada.
                send_to_client(client_write, &build_ready_for_query()).await?;
                skip_until_sync = false;
            }
            continue; // tragar Bind/Describe/Execute/Flush
        }

        match msg.tag {
            // Simple Query
            b'Q' => {
                if let Some(sql) = extract_simple_query(&msg) {
                    // Read the current ruleset lock-free (syncer may swap it).
                    let rules = config.ruleset.load();
                    let decision = evaluate(&sql, Dialect::Postgres, &rules);
                    report_telemetry(config, &sql, &decision);
                    if let TcpDecision::Block { rule_code, ast_node_path, suggested_safe_query } = decision {
                        log_block(&sql, &rule_code, &ast_node_path);
                        send_block_simple(client_write, &rule_code, &ast_node_path, suggested_safe_query.as_deref())
                            .await?;
                        continue;
                    }
                }
                forward(server_write, &msg.encode()).await?;
            }

            // Parse (protocolo extendido)
            b'P' => {
                if let Some(sql) = extract_parse_query(&msg) {
                    let rules = config.ruleset.load();
                    let decision = evaluate(&sql, Dialect::Postgres, &rules);
                    report_telemetry(config, &sql, &decision);
                    if let TcpDecision::Block { rule_code, ast_node_path, .. } = decision {
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

            // Resto (Bind, Execute, Sync, PasswordMessage, etc.): reenviar tal cual.
            _ => {
                forward(server_write, &msg.encode()).await?;
            }
        }
    }

    Ok(())
}

/// Envía un bloque en el protocolo simple: ErrorResponse + ReadyForQuery.
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
    let base = format!("Vetro bloqueó esta query [{rule_code}] — nodo AST: {ast_node_path}");
    match suggestion {
        Some(s) => format!("{base}. Sugerencia: {s}"),
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
        "Query BLOQUEADA en proxy TCP"
    );
}

/// Push a telemetry event for an evaluation. Non-blocking and best-effort: if no
/// sink is configured this is a no-op, and the queue never blocks the SQL path.
fn report_telemetry(config: &PgProxyConfig, sql: &str, decision: &TcpDecision) {
    let Some(sink) = &config.telemetry else { return };

    let (status, rule_code, ast_node_path) = match decision {
        TcpDecision::Allow => ("ALLOWED".to_string(), None, None),
        TcpDecision::Block { rule_code, ast_node_path, .. } => {
            let status = if rule_code == "VETRO-PARSE-ERROR" { "PARSE_ERROR" } else { "BLOCKED" };
            (status.to_string(), Some(rule_code.clone()), Some(ast_node_path.clone()))
        }
    };

    let event = crate::telemetry::TelemetryEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        database_id: sink.database_id.clone(),
        query_text: sql.to_string(),
        dialect: "postgres".to_string(),
        status,
        rule_code,
        ast_node_path,
        severity: None,
        latency_ms: None,
        client_ip: None,
        occurred_at: chrono::Utc::now().to_rfc3339(),
    };
    sink.queue.push(event);
}
