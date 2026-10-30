// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! PostgreSQL TCP proxy session handler.
//!
//! Terminates the PostgreSQL wire protocol transparently: the client (Prisma,
//! SQLAlchemy, psql, ...) connects believing it talks to Postgres. The proxy:
//!   1. Negotiates the startup phase (declines TLS/GSS, forwards StartupMessage;
//!      a CancelRequest is forwarded on its own, see `tcp::cancel`).
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
    /// Hot-swappable kill-switch blocks (VERICTO-105, since 4.18.0), shared with
    /// the rule syncer. `None` while no block is active.
    pub kill_switch: crate::tcp::kill_switch::SharedKillSwitch,
    /// Hot-swappable telemetry query mode (raw | sanitized) shared with the syncer.
    pub telemetry_mode: crate::tcp::rules_sync::SharedTelemetryMode,
    /// Optional telemetry sink: when set, each evaluation is reported. The
    /// database_id identifies which connected database this proxy fronts.
    pub telemetry: Option<TelemetrySink>,
    /// Largest query this proxy will evaluate, already clamped to what the wire
    /// protocol can deliver. Resolved once at startup — see `tcp::query_limit`.
    pub max_query_bytes: usize,
    /// Statements of at most this many bytes are evaluated on the session's own
    /// task, larger ones on the blocking pool; 0 sends every statement to the pool
    /// (`VERICTO_INLINE_EVAL_MAX_BYTES`, since 4.19.0; see `tcp::query_limit`).
    pub inline_eval_max_bytes: usize,
    /// A session remembers the decisions of trivial statements
    /// (`VERICTO_TRIVIAL_FAST_PATH`, since 4.19.0, default on; see `tcp::fast_path`).
    pub trivial_fast_path: bool,
    /// Business policy rules (`VERICTO_POLICY_RULES`, default off): the mode,
    /// the synced principals and compiled policies, the listener (since 4.15.0).
    pub policy_rules: crate::tcp::policy_rules::PolicyRulesRuntime,
    /// The `BackendKeyData` relayed to each open Postgres session: a
    /// `CancelRequest` is forwarded only for one of them (4.16.1).
    pub cancel_keys: Arc<crate::tcp::cancel::CancelRegistry>,
}

/// Where the TCP proxy pushes evaluation telemetry (non-blocking).
#[derive(Clone)]
pub struct TelemetrySink {
    pub queue: Arc<dyn crate::telemetry::EventQueue>,
    pub database_id: String,
    /// The event builder in front of `queue` (4.19.0,
    /// `VERICTO_TELEMETRY_BUILD_QUEUE`): sanitized events are built on its
    /// thread rather than on the query path. `None` builds every event on the
    /// query path, as up to 4.18.0.
    pub deferred: Option<Arc<crate::telemetry::builder::DeferredQueue>>,
}

impl TelemetrySink {
    /// The builder to hand an event to, if any. Sanitized events go to it: their
    /// query text is normalized again, which is most of what an event costs
    /// (6 to 15% of a statement). Raw events are built here, where they cost less
    /// than the hand-over, unless the builder still holds events, which they
    /// would overtake.
    fn builder_for(
        &self,
        mode: crate::tcp::rules_sync::TelemetryQueryMode,
    ) -> Option<&crate::telemetry::builder::DeferredQueue> {
        let deferred = self.deferred.as_deref()?;
        (mode == crate::tcp::rules_sync::TelemetryQueryMode::Sanitized || deferred.pending() > 0)
            .then_some(deferred)
    }
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
        match negotiate_startup(client, config.client_tls_acceptor.as_ref()).await? {
            Negotiated::Session {
                read,
                write,
                raw,
                params,
            } => (read, write, raw, params),
            // A CancelRequest is a connection of its own: forwarded (or not),
            // then closed without an answer.
            Negotiated::Cancel(key) => {
                return crate::tcp::cancel::handle_cancel_request(&config, key).await;
            }
        };
    let session_user = startup.user;

    // Policy rules on (4.15.0): the `vericto.*` settings and `application_name`
    // are taken out of the StartupMessage; the `vericto.*` ones never reach the
    // database. A setting the proxy cannot accept refuses the connection. Off:
    // the StartupMessage is forwarded exactly as it came.
    let (startup_raw, declared) = if config.policy_rules.mode.is_on() {
        match startup_context(&startup_raw) {
            Ok(v) => v,
            Err(message) => {
                client_write
                    .write_all(&crate::tcp::codec::build_error_response(
                        crate::tcp::codec::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                        &message,
                    ))
                    .await?;
                client_write.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "StartupMessage vericto.* setting refused",
                ));
            }
        }
    } else {
        (startup_raw, Default::default())
    };

    // `search_path` (and the identity settings) set by the StartupMessage are
    // the `SET` the engine denies under an allowlist: evaluated as that `SET`,
    // and a blocked one refuses the connection before it reaches the database.
    let refused = {
        let config = Arc::clone(&config);
        let user = session_user.clone();
        let settings = startup.access_settings;
        // As for statements (4.19.0): on this task when the `SET`s it evaluates are
        // small, which includes the usual case of none at all.
        let bytes = settings.iter().map(|(n, v)| n.len() + v.len() + 12).sum();
        crate::tcp::session::run_evaluation(config.inline_eval_max_bytes, bytes, move || {
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

    // The relay follows the ReadyForQuery status, so the replies the proxy
    // writes itself (a refused statement, a consumed `SET vericto.*`) carry the
    // real transaction state: with policy rules on since 4.15.0, in every mode
    // since 4.16.1. It also registers the session's BackendKeyData for cancels.
    let tx_state = Arc::new(crate::tcp::tx_state::ServerTxState::new());

    // PostgreSQL's response coordinator orders pipelined backend replies and
    // local replacements. The relay below is the sole in-session client writer.
    let responses = crate::tcp::pg_response::PgResponseCoordinator::new();

    // Relay server→client (auth, data, notices), framing every backend message.
    let relay_handle = tokio::spawn(relay_server_to_client(
        server_read,
        client_write.clone(),
        relay_wrote.clone(),
        tx_state.clone(),
        Some(config.cancel_keys.clone()),
        responses.clone(),
        Some(format!("{}:{}", config.upstream_host, config.upstream_port)),
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
        r = intercept_client_to_server(
            &mut client_read,
            &mut server_write,
            &client_write,
            &config,
            crate::tcp::session::SessionStart {
                user: session_user,
                declared,
                tx_state: Some(tx_state),
                pg_responses: Some(responses),
                ..Default::default()
            },
        ) => {
            // Client ended or a block/forward error unwound the loop: stop the relay.
            relay_handle.abort();
            r
        }
        relay_result = &mut relay_handle => {
            // Upstream closed/errored: the relay ended. If it never delivered a
            // byte to the client (the upstream died during the connection phase,
            // e.g. mid-auth), the client is still waiting for a startup reply, so
            // send a native ErrorResponse before closing. If bytes were already
            // relayed, the stream is mid-session and injecting one would corrupt
            // it — fall back to a plain close.
            let relay_error = match relay_result {
                Ok(Ok(())) => None,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "PostgreSQL server relay failed; closing the session");
                    Some(e)
                }
                Err(e) => {
                    let error = std::io::Error::other(format!("PostgreSQL server relay task failed: {e}"));
                    tracing::error!(error = %error, "PostgreSQL server relay task failed");
                    Some(error)
                }
            };
            if !relay_wrote.load(std::sync::atomic::Ordering::Relaxed) {
                let mut w = client_write.lock().await;
                let send = async {
                    w.write_all(&crate::tcp::codec::build_error_response(
                        crate::tcp::codec::SQLSTATE_CONNECTION_FAILURE,
                        "Vericto: the database connection was lost",
                    ))
                    .await?;
                    w.flush().await
                }
                .await;
                if let Err(e) = send {
                    tracing::debug!(error = %e, "could not send PostgreSQL connection-loss response");
                }
            }
            match relay_error {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    };

    result
}

/// The StartupMessage to forward and what the session declared in it, with
/// policy rules on; `Err` with the client message when a `vericto.*` setting is
/// not one the proxy accepts. A message that cannot be read as pairs is
/// forwarded as it came (the server refuses it) with nothing declared.
pub(crate) fn startup_context(
    raw: &[u8],
) -> Result<(Vec<u8>, crate::tcp::policy_rules::SessionDeclared), String> {
    use crate::tcp::policy_rules::{SESSION_CONTEXT_RULE_CODE, SessionDeclared, strip_startup};
    let Some(ctx) = strip_startup(raw) else {
        return Ok((raw.to_vec(), SessionDeclared::default()));
    };
    let mut declared = SessionDeclared {
        application_name: ctx.application_name,
        ..Default::default()
    };
    for (name, value) in &ctx.settings {
        declared.set_from_startup(name, value).map_err(|reason| {
            crate::tcp::protocol::postgres::block_message(
                SESSION_CONTEXT_RULE_CODE,
                &format!("{reason} (StartupMessage {name})"),
                None,
            )
        })?;
    }
    Ok((ctx.raw, declared))
}

/// What the startup phase of a client connection turned out to be.
enum Negotiated {
    /// A session: the client transport halves, the raw StartupMessage bytes and
    /// its parameters.
    Session {
        read: ClientRead,
        write: ClientWrite,
        raw: Vec<u8>,
        params: StartupParams,
    },
    /// A CancelRequest for the session holding this key.
    Cancel(crate::tcp::cancel::BackendKey),
}

/// Negotiates the startup phase and returns the client transport halves, the
/// raw StartupMessage bytes and its parameters, or the key of a CancelRequest.
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
///
/// A `CancelRequest` is taken before that requirement, in plaintext or after
/// TLS: libpq's `PQcancel` never negotiates TLS for it, and the packet opens
/// no session (see `tcp::cancel`). Up to 4.16.0 it was read as a
/// StartupMessage, so with `require` it was refused and the query ran on.
async fn negotiate_startup(
    mut client: TcpStream,
    acceptor: Option<&tokio_rustls::TlsAcceptor>,
) -> std::io::Result<Negotiated> {
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
                    return Ok(match read_startup_message(&mut read).await? {
                        AfterTls::Startup(raw, params) => Negotiated::Session {
                            read,
                            write,
                            raw,
                            params,
                        },
                        AfterTls::Cancel(key) => Negotiated::Cancel(key),
                    });
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
            StartupPacket::CancelRequest(key) => return Ok(Negotiated::Cancel(key)),
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
                return Ok(Negotiated::Session {
                    read: Box::new(read),
                    write: Box::new(write),
                    raw,
                    params,
                });
            }
        }
    }
}

/// The packet a client sends after the TLS handshake.
enum AfterTls {
    Startup(Vec<u8>, StartupParams),
    Cancel(crate::tcp::cancel::BackendKey),
}

/// Reads a single startup packet expecting the StartupMessage (used after a TLS
/// handshake, where the next message must be the StartupMessage, or a
/// CancelRequest from a client that encrypts it, such as libpq 17's
/// `PQcancelCreate`).
async fn read_startup_message<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<AfterTls> {
    match read_startup_packet(reader).await? {
        StartupPacket::Startup { raw, params } => {
            tracing::debug!(
                user = ?params.user,
                database = ?params.database,
                "StartupMessage received (over TLS)"
            );
            Ok(AfterTls::Startup(raw, params))
        }
        StartupPacket::CancelRequest(key) => Ok(AfterTls::Cancel(key)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected StartupMessage after TLS handshake",
        )),
    }
}

/// Bytes of upstream data the relay buffers. A backend message that fits is
/// handled whole from this buffer; a larger one (a big DataRow or CopyData) is
/// streamed through it in bounded chunks.
const RELAY_BUFFER: usize = 64 * 1024;

/// Relays the server's messages to the client, in order, applying the local
/// replies the response coordinator planned at their positions.
///
/// `wrote_any` is flipped to `true` the first time a byte is successfully
/// written to the client. `run_session` reads it when the relay ends to decide
/// whether it is still safe to inject a native `ErrorResponse`: once server
/// bytes have reached the client (auth/rows in flight), injecting one would
/// corrupt the protocol stream, so it must fall back to a plain close.
///
/// `tx_state` receives the status of every ReadyForQuery. With `cancel_keys`,
/// the session's BackendKeyData is registered there before it reaches the
/// client, and stays registered until the relay ends (the session closes).
///
/// With `upstream_target` (host:port), the `server_version` ParameterStatus of
/// the startup phase is reported to `tcp::upstream_version` (4.20.0), which
/// warns once per target when it is newer than the parser. Startup only: no
/// statement pays for it, and nothing it finds changes what is relayed.
///
/// How (4.17.2): each upstream read is framed by the messages' length
/// prefixes. The messages the buffer holds whole are passed to the coordinator
/// in one batch (one lock), then written to the client with one write and one
/// flush, so one database read is one TLS record and one send again, as up to
/// 4.17.0 (4.17.1 wrote and flushed every message on its own). When no local
/// reply is planned for them, which is the usual case, the bytes go out as
/// read, straight from the buffer. The complete messages are always written
/// before the relay waits for more upstream bytes, so a message the server
/// has not finished sending never holds back the ones before it.
pub(crate) async fn relay_server_to_client(
    mut server_read: crate::tcp::upstream::UpstreamRead,
    client_write: Arc<Mutex<ClientWrite>>,
    wrote_any: Arc<std::sync::atomic::AtomicBool>,
    tx_state: Arc<crate::tcp::tx_state::ServerTxState>,
    mut cancel_keys: Option<Arc<crate::tcp::cancel::CancelRegistry>>,
    responses: crate::tcp::pg_response::PgResponseCoordinator,
    upstream_target: Option<String>,
) -> std::io::Result<()> {
    use crate::tcp::pg_response::BackendDisposition;

    let mut _registration = None;
    let mut startup = !responses.startup_complete()?;
    // This relay is the sole in-session producer of PostgreSQL client bytes.
    // Hold the writer for the session; startup/connection-loss writers run
    // only before it starts or after it returns.
    let mut client_writer = client_write.lock().await;
    // Upstream bytes not yet relayed are `buf[start..end]`.
    let mut buf = vec![0u8; RELAY_BUFFER];
    let (mut start, mut end) = (0usize, 0usize);
    // The client bytes of a batch in which a local reply replaces, precedes or
    // suppresses a server message. Empty and unused on the usual path.
    let mut altered: Vec<u8> = Vec::new();
    loop {
        // ── 1. The messages buffered whole, in one coordinator pass.
        let mut pos = start;
        let mut is_altered = false;
        let mut failure = None;
        // The header of the next message when it cannot be buffered whole.
        let mut oversized = None;
        // The walk stopped with whole messages still buffered (startup ended).
        let mut more_buffered = false;
        {
            let mut batch = None;
            while end - pos >= 5 {
                let header = [
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                    buf[pos + 4],
                ];
                let tag = header[0];
                let len = match backend_length(&header, startup) {
                    Ok(len) => len,
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                };
                let total = 1 + len;
                if total > end - pos {
                    if total > RELAY_BUFFER {
                        oversized = Some(header);
                    }
                    break;
                }
                let message = pos..pos + total;
                let body = &buf[pos + 5..pos + total];
                let ready = (tag == b'Z').then(|| body[0]);
                // Tracking precedes exposure to the client: the client's next
                // message sees the status, and a cancel finds its key.
                if let Some(status) = ready {
                    tx_state.set_pg_status(status);
                }
                if startup
                    && tag == b'K'
                    && let Some(key) = crate::tcp::cancel::BackendKey::parse(body)
                    && let Some(registry) = cancel_keys.take()
                {
                    _registration = Some(registry.register(key));
                }
                if startup
                    && tag == b'S'
                    && let Some(target) = upstream_target.as_deref()
                    && let Some(version) =
                        crate::tcp::upstream_version::server_version_parameter(body)
                {
                    crate::tcp::upstream_version::global().observe_postgres(target, version);
                }
                let disposition = if startup {
                    BackendDisposition::Forward
                } else {
                    let batch = match batch.as_mut() {
                        Some(batch) => batch,
                        None => match responses.backend_batch() {
                            Ok(opened) => batch.insert(opened),
                            Err(e) => {
                                failure = Some(e);
                                break;
                            }
                        },
                    };
                    match batch.message(tag, ready) {
                        Ok(disposition) => disposition,
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                };
                if !matches!(disposition, BackendDisposition::Forward) && !is_altered {
                    // From here on the batch is assembled: what was forwarded
                    // so far, then each message's client bytes.
                    altered.clear();
                    altered.extend_from_slice(&buf[start..pos]);
                    is_altered = true;
                }
                match disposition {
                    BackendDisposition::Forward => {
                        if is_altered {
                            altered.extend_from_slice(&buf[message.clone()]);
                        }
                    }
                    BackendDisposition::Suppress => {}
                    // Replacements are emitted where the backend message was,
                    // after it has been read whole.
                    BackendDisposition::Replace(bytes) => altered.extend_from_slice(&bytes),
                    // Simple cycles: the replacement, then the server's actual
                    // ReadyForQuery, preserving I/T/E. `ready` is always set
                    // here (only a ReadyForQuery gets this disposition); the
                    // check keeps malformed traffic from manufacturing a frame.
                    BackendDisposition::BeforeForward(bytes) => {
                        if ready.is_none() {
                            failure = Some(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "simple replacement did not end at ReadyForQuery",
                            ));
                            break;
                        }
                        altered.extend_from_slice(&bytes);
                        altered.extend_from_slice(&buf[message.clone()]);
                    }
                }
                pos = message.end;
                if startup && tag == b'Z' {
                    // The session's frontend registers plans from here on.
                    startup = false;
                    if let Err(e) = responses.complete_startup() {
                        failure = Some(e);
                    }
                    more_buffered = true;
                    break;
                }
            }
            // `batch` drops here: the coordinator is unlocked before any await.
        }

        // ── 2. One write and one flush for the batch.
        let out: &[u8] = if is_altered {
            &altered
        } else {
            &buf[start..pos]
        };
        if !out.is_empty() {
            client_writer.write_all(out).await?;
            client_writer.flush().await?;
            wrote_any.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if is_altered && altered.capacity() > RELAY_BUFFER {
            // A rare, large local reply: do not keep its allocation.
            altered = Vec::new();
        }
        start = pos;
        if let Some(e) = failure {
            return Err(e);
        }

        // ── 3. A message larger than the buffer is streamed through it.
        if let Some(header) = oversized {
            let wrote = relay_oversized(
                &mut server_read,
                &mut **client_writer,
                &responses,
                startup,
                header,
                &mut buf,
                start,
                end,
            )
            .await?;
            if wrote {
                wrote_any.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            (start, end) = (0, 0);
            continue;
        }
        if more_buffered {
            continue;
        }

        // ── 4. Read more: keep the partial message at the front.
        if start == end {
            (start, end) = (0, 0);
        } else if start > 0 {
            buf.copy_within(start..end, 0);
            end -= start;
            start = 0;
        }
        let n = server_read.read(&mut buf[end..]).await?;
        if n == 0 {
            if start == end {
                return Ok(());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "PostgreSQL server closed the connection inside a message",
            ));
        }
        end += n;
    }
}

/// The body length (after the 4 length bytes, plus them) of a backend message
/// header, i.e. the bytes after its tag; validated as PostgreSQL defines it.
fn backend_length(header: &[u8; 5], startup: bool) -> std::io::Result<usize> {
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL backend message length: {len}"),
        ));
    }
    if header[0] == b'Z' && len != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL ReadyForQuery length: {len}"),
        ));
    }
    // BackendKeyData is retained until its cancel key is registered, so its
    // size is bounded.
    if startup
        && header[0] == b'K'
        && !(8..=4 + crate::tcp::cancel::MAX_SECRET_LEN).contains(&(len as usize - 4))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL BackendKeyData length: {len}"),
        ));
    }
    Ok(len as usize)
}

/// Streams one backend message larger than [`RELAY_BUFFER`] (a big DataRow or
/// CopyData): its disposition is taken from the header, then its body goes to
/// the client chunk by chunk as it arrives (or is read and dropped when a
/// local reply replaces it). `buf[start..end]` holds its header and the first
/// body bytes. The client writer is held throughout, so nothing can appear
/// between the fragments of the message. Returns whether bytes reached the
/// client.
#[allow(clippy::too_many_arguments)]
async fn relay_oversized(
    server_read: &mut crate::tcp::upstream::UpstreamRead,
    client_writer: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    responses: &crate::tcp::pg_response::PgResponseCoordinator,
    startup: bool,
    header: [u8; 5],
    buf: &mut [u8],
    start: usize,
    end: usize,
) -> std::io::Result<bool> {
    use crate::tcp::pg_response::BackendDisposition;
    let tag = header[0];
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    // Neither a ReadyForQuery nor a BackendKeyData can be this large (their
    // lengths were validated), so no status or key is tracked here, and the
    // plan of a streamed message never completes at ReadyForQuery.
    let disposition = if startup {
        BackendDisposition::Forward
    } else {
        responses.disposition(tag)?
    };
    let stream_to_client = matches!(disposition, BackendDisposition::Forward);
    let buffered = &buf[start + 5..end];
    let mut remaining = len - 4 - buffered.len();
    if stream_to_client {
        client_writer.write_all(&header).await?;
        client_writer.write_all(buffered).await?;
    }
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let n = server_read.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "PostgreSQL server closed the connection inside a message",
            ));
        }
        if stream_to_client {
            client_writer.write_all(&buf[..n]).await?;
        }
        remaining -= n;
    }
    match disposition {
        BackendDisposition::Forward => {}
        BackendDisposition::Suppress => return Ok(false),
        BackendDisposition::Replace(bytes) => client_writer.write_all(&bytes).await?,
        BackendDisposition::BeforeForward(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "simple replacement did not end at ReadyForQuery",
            ));
        }
    }
    client_writer.flush().await?;
    Ok(true)
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
    start: crate::tcp::session::SessionStart,
) -> std::io::Result<()> {
    let proto = crate::tcp::protocol::postgres::PostgresProtocol;
    crate::tcp::session::intercept_client_to_server(
        &proto,
        client_read,
        server_write,
        client_write,
        config,
        start,
    )
    .await
}

pub(crate) fn log_block(sql: &str, dialect: Dialect, rule_code: &str, ast_node_path: &str) {
    tracing::info!(
        rule_code,
        ast_node_path,
        query_preview = %log_preview(sql, dialect),
        "Query BLOCKED at TCP proxy"
    );
}

/// The start of a statement for a log line, with its literals replaced as in
/// sanitized telemetry, whatever the workspace's reporting mode. Logs are read
/// by whoever operates the host and are often shipped elsewhere, and a query's
/// values (emails, tokens, the very data a mask hides) do not belong in them;
/// the statement's shape is what an operator needs to recognise it.
pub(crate) fn log_preview(sql: &str, dialect: Dialect) -> String {
    sanitize_for(sql, dialect).chars().take(80).collect()
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
    dialect.as_str()
}

/// Who issued a query, for its telemetry event: the session's database user and,
/// when an agent-access policy applied, its mode.
#[derive(Debug, Clone, Default)]
pub struct EventIdentity {
    pub db_user: Option<String>,
    pub access_mode: Option<vericto_engine::AccessMode>,
    /// The session's principal and declared context, only with
    /// `VERICTO_POLICY_RULES` on (since 4.15.0).
    pub policy: Option<Arc<crate::tcp::policy_rules::PolicyTelemetry>>,
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
        chrono::Utc::now(),
    )
}

/// Builds a telemetry event from an evaluation decision. Pure (no I/O) so it can
/// be unit-tested.
///
/// In sanitized `mode` every SQL text that leaves is normalized first: the
/// query, the rewritten query of a mask or a `rewrite_limit` bound, and a
/// VERICTO-085 or `rewrite_limit` suggestion (which under `monitor_mode`, or
/// policy rules `observe`, is the would-be rewrite). Sanitizing happens before the
/// size cut, because a cut statement no longer parses and would only ever be
/// reported as redacted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_event(
    database_id: &str,
    sql: &str,
    dialect: Dialect,
    decision: &TcpDecision,
    latency_us: u128,
    mode: crate::tcp::rules_sync::TelemetryQueryMode,
    identity: &EventIdentity,
    occurred_at: chrono::DateTime<chrono::Utc>,
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
            let suggestion = v.suggested_safe_query.as_deref().and_then(|s| {
                // A `rewrite_limit` finding (engine 4.5.0) carries the bounded
                // statement, the client's text with its literals, as its
                // suggestion: treated like a VERICTO-085 one. Only policy findings
                // have a `Policy > ` path, and `rewrite_limit` is the only policy
                // action that suggests anything. Looked at only for a finding
                // with a suggestion.
                let rewrite =
                    v.rule_code == SENSITIVE_RULE_CODE || v.ast_node_path.starts_with("Policy > ");
                if v.rule_code == vericto_engine::ACCESS_RULE_CODE {
                    // Engine 4.6.0 names the denied references in it.
                    Some(redaction.suggestion(s))
                } else if rewrite && Some(s) == rewritten {
                    // A successful mask or LIMIT bound repeats the rewritten SQL
                    // here; the event already carries it in `rewritten_query`.
                    None
                } else if rewrite && sanitized {
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
        occurred_at: occurred_at.to_rfc3339(),
        rewritten_query,
        sensitive_columns,
        db_user: identity.db_user.clone(),
        access_policy_mode: identity.access_mode.map(|m| match m {
            vericto_engine::AccessMode::Observe => "observe".to_string(),
            vericto_engine::AccessMode::Enforce => "enforce".to_string(),
        }),
        access_denied: redaction.payload(),
        principal_id: policy_field(identity, |p| &p.principal_id),
        principal_type: policy_field(identity, |p| &p.principal_type),
        principal_trust: policy_field(identity, |p| &p.principal_trust),
        principal_via: policy_field(identity, |p| &p.principal_via),
        application_name: policy_field(identity, |p| &p.application_name),
        policy_bundle_version: policy_field(identity, |p| &p.policy_bundle_version),
        ticket_id: policy_field(identity, |p| &p.ticket_id),
        session_tenant: policy_field(identity, |p| &p.session_tenant),
        kill_switch_id: None,
        ..Default::default()
    }
}

/// One policy field of an event's identity; `None` with policy rules off.
fn policy_field(
    identity: &EventIdentity,
    field: impl Fn(&crate::tcp::policy_rules::PolicyTelemetry) -> &Option<String>,
) -> Option<String> {
    identity.policy.as_deref().and_then(|p| field(p).clone())
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

    /// A VERICTO-087 suggestion (engine 4.6.0+), which names the denied
    /// references: unchanged, or built again by the engine from the redacted
    /// names, as [`Self::path`] is.
    fn suggestion(&self, original: &str) -> String {
        match &self.redacted {
            None => original.to_string(),
            Some(list) => vericto_engine::access_suggested_fix(list)
                .unwrap_or_else(|| "<suggestion redacted>".to_string()),
        }
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
    use sqlparser::tokenizer::Token;
    let tokens = crate::tcp::protocol::mysql::mysql_tokens(sql).ok()?;
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
    // The mode and the time are those of the statement, wherever it is built.
    let mode = **config.telemetry_mode.load();
    let occurred_at = chrono::Utc::now();
    if let Some(builder) = sink.builder_for(mode) {
        let (database_id, sql) = (sink.database_id.clone(), sql.to_string());
        let (decision, identity) = (decision.clone(), identity.clone());
        builder.submit(Box::new(move || {
            build_event(
                &database_id,
                &sql,
                dialect,
                &decision,
                latency_us,
                mode,
                &identity,
                occurred_at,
            )
        }));
    } else {
        sink.queue.push(build_event(
            &sink.database_id,
            sql,
            dialect,
            decision,
            latency_us,
            mode,
            identity,
            occurred_at,
        ));
    }
}

/// The decision of a statement the kill switch refused: VERICTO-105, critical,
/// block, with the block's message as the only violation's text.
pub(crate) fn kill_switch_decision(block: &crate::tcp::kill_switch::KillBlock) -> TcpDecision {
    use crate::tcp::kill_switch::KILL_SWITCH_RULE_CODE;
    let ast_node_path = block.ast_node_path();
    TcpDecision::Block {
        rule_code: KILL_SWITCH_RULE_CODE.to_string(),
        ast_node_path: ast_node_path.clone(),
        suggested_safe_query: None,
        severity: vericto_engine::Severity::Critical,
        violations: vec![vericto_engine::ReportedViolation {
            rule_id: KILL_SWITCH_RULE_CODE.to_string(),
            rule_code: KILL_SWITCH_RULE_CODE.to_string(),
            severity: vericto_engine::Severity::Critical,
            action: EnforcementAction::Block,
            ast_node_path,
            estimated_rows_affected: None,
            suggested_safe_query: None,
        }],
        sensitive_columns: Vec::new(),
        access_denied: Vec::new(),
    }
}

/// [`report_telemetry`] for a statement the kill switch refused: the event also
/// names the block (`kill_switch_id`).
pub(crate) fn report_kill_switch(
    config: &PgProxyConfig,
    sql: &str,
    dialect: Dialect,
    block: &crate::tcp::kill_switch::KillBlock,
    identity: &EventIdentity,
) {
    let Some(sink) = &config.telemetry else {
        return;
    };
    let mode = **config.telemetry_mode.load();
    let occurred_at = chrono::Utc::now();
    let build = {
        let (database_id, sql) = (sink.database_id.clone(), sql.to_string());
        let (decision, identity) = (kill_switch_decision(block), identity.clone());
        let block_id = block.block_id.clone();
        move || {
            let mut event = build_event(
                &database_id,
                &sql,
                dialect,
                &decision,
                0,
                mode,
                &identity,
                occurred_at,
            );
            event.kill_switch_id = Some(block_id);
            event
        }
    };
    match sink.builder_for(mode) {
        Some(builder) => builder.submit(Box::new(build)),
        None => sink.queue.push(build()),
    }
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
    use sqlparser::tokenizer::{Token, Whitespace};
    let tokens = crate::tcp::protocol::mysql::mysql_tokens(sql).ok()?;
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
            | Token::QuoteDelimitedStringLiteral(_)
            | Token::NationalQuoteDelimitedStringLiteral(_)
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

    /// The measurement behind `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`' default
    /// (`docs/CONFIGURATION.md`, "Disk spool size"): the average spool line of a
    /// pgbench-style mix (the staging benchmark's traffic) plus a few application
    /// statements that break rules, evaluated with the built-in ruleset and
    /// serialized exactly as the spool writes them (one JSON object and a newline
    /// per event). Run with `--nocapture` to see the figure.
    #[test]
    fn the_default_spool_bound_covers_minutes_of_an_api_outage() {
        let workload = [
            "BEGIN;",
            "UPDATE pgbench_accounts SET abalance = abalance + -3122 WHERE aid = 4187363;",
            "SELECT abalance FROM pgbench_accounts WHERE aid = 4187363;",
            "UPDATE pgbench_tellers SET tbalance = tbalance + -3122 WHERE tid = 87;",
            "UPDATE pgbench_branches SET bbalance = bbalance + -3122 WHERE bid = 9;",
            "INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (87, 9, 4187363, -3122, CURRENT_TIMESTAMP);",
            "END;",
            "SELECT id, email, created_at FROM users WHERE id = 48211 LIMIT 1",
            "SELECT o.id, o.total, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.created_at > now() - interval '1 day' ORDER BY o.created_at DESC LIMIT 50",
            "SELECT * FROM orders",
            "DELETE FROM sessions",
        ];
        let rules = crate::tcp::evaluator::default_ruleset();
        let policy = vericto_engine::EnforcementPolicy::default();
        let identity = EventIdentity {
            db_user: Some("app_rw".to_string()),
            access_mode: None,
            policy: None,
        };
        let database_id = uuid::Uuid::new_v4().to_string();
        let mut total = 0usize;
        for sql in workload {
            let decision = crate::tcp::evaluator::evaluate(sql, Dialect::Postgres, &rules, &policy);
            let mut event = build_event(
                &database_id,
                sql,
                Dialect::Postgres,
                &decision,
                412,
                crate::tcp::rules_sync::TelemetryQueryMode::Raw,
                &identity,
                chrono::Utc::now(),
            );
            event.event_id = uuid::Uuid::new_v4().to_string();
            total += serde_json::to_vec(&event).unwrap().len() + 1;
        }
        let average = total / workload.len();
        let events_per_sec = 1_500;
        let minutes = crate::telemetry::queue::DEFAULT_SPOOL_MAX_BYTES as usize
            / (average * events_per_sec)
            / 60;
        println!(
            "average spool line: {average} bytes; default bound: {minutes} min at {events_per_sec} events/s"
        );
        assert!(
            (250..2_000).contains(&average),
            "average event of {average} bytes: re-check the docs/CONFIGURATION.md arithmetic"
        );
        assert!(
            minutes >= 15,
            "the default spool bound covers only {minutes} min at {events_per_sec} events/s"
        );
    }

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
            chrono::Utc::now(),
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
            chrono::Utc::now(),
        );
        assert_eq!(ev.query_text, "SELECT card FROM customers WHERE name = ?");
        assert_eq!(
            ev.rewritten_query.as_deref(),
            Some("SELECT CONCAT(?, RIGHT(`card`, ?)) AS `card` FROM customers WHERE name = ?")
        );
    }

    /// Log previews never carry a literal, in either dialect.
    #[test]
    fn log_preview_has_no_literals() {
        let pg = log_preview(
            "UPDATE users SET email = 'alice@acme.com' WHERE id = 42",
            Dialect::Postgres,
        );
        assert!(!pg.contains("alice@acme.com") && !pg.contains("42"), "{pg}");
        assert!(pg.starts_with("UPDATE users SET email"), "{pg}");
        let my = log_preview(
            "DELETE FROM t WHERE token = \"s3cr3t\" OR 1",
            Dialect::Mysql,
        );
        assert!(!my.contains("s3cr3t"), "{my}");
        assert!(
            log_preview(&"x".repeat(500), Dialect::Mysql)
                .chars()
                .count()
                <= 80
        );
    }

    /// Sanitized events go to the builder; raw ones are built on the query path
    /// unless the builder still holds events, which a raw one must not overtake;
    /// without a builder everything is built on the query path.
    #[test]
    fn only_sanitized_events_or_those_behind_pending_ones_are_deferred() {
        use crate::tcp::rules_sync::TelemetryQueryMode::{Raw, Sanitized};
        use crate::telemetry::builder::DeferredQueue;
        use std::sync::{Barrier, mpsc};
        let below = Arc::new(crate::telemetry::queue::MemoryQueue::new(10));
        let deferred = Arc::new(DeferredQueue::new(below.clone(), 4).unwrap());
        let mut sink = TelemetrySink {
            queue: deferred.clone(),
            database_id: "db".into(),
            deferred: Some(deferred.clone()),
        };
        assert!(sink.builder_for(Sanitized).is_some());
        assert!(sink.builder_for(Raw).is_none(), "nothing pending");

        let (started_tx, started_rx) = mpsc::channel();
        let gate = Arc::new(Barrier::new(2));
        let held = Arc::clone(&gate);
        deferred.submit(Box::new(move || {
            started_tx.send(()).unwrap();
            held.wait();
            let allowed = TcpDecision::Forward {
                observation: None,
                violations: Vec::new(),
                rewritten_query: None,
                sensitive_columns: Vec::new(),
                access_denied: Vec::new(),
            };
            build_telemetry_event("db", "SELECT 1", Dialect::Postgres, &allowed, 1)
        }));
        started_rx.recv().unwrap();
        assert!(sink.builder_for(Raw).is_some(), "behind a pending event");
        gate.wait();
        assert!(crate::telemetry::EventQueue::flush(
            &*deferred,
            std::time::Duration::from_secs(5)
        ));
        assert!(sink.builder_for(Raw).is_none());

        sink.deferred = None;
        assert!(sink.builder_for(Sanitized).is_none());
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
            kill_switch: Default::default(),
            telemetry_mode: Arc::new(ArcSwap::from_pointee(
                crate::tcp::rules_sync::TelemetryQueryMode::default(),
            )),
            telemetry: None,
            max_query_bytes: crate::tcp::query_limit::DEFAULT_MAX_QUERY_BYTES,
            inline_eval_max_bytes: crate::tcp::query_limit::DEFAULT_INLINE_EVAL_MAX_BYTES,
            trivial_fast_path: true,
            policy_rules: Default::default(),
            cancel_keys: Default::default(),
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
