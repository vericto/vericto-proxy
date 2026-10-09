//! Protocol-agnostic session logic for the multi-dialect proxy.
//!
//! The client→server interception loop is identical across wire protocols once
//! framing/classification/block-bytes are abstracted behind `WireProtocol`:
//!   read message → classify → (if SQL) evaluate with the protocol's dialect →
//!   on Block, send the native rejection and (protocol-permitting) swallow the
//!   rest of the sequence → on a mask, forward the engine's rewritten SQL in
//!   place of the original (never the original) → otherwise forward upstream
//!   unchanged.
//!
//! Evaluation, telemetry and enforcement are shared here (no per-protocol
//! duplication). Startup negotiation and upstream connect differ per protocol
//! and remain in each protocol's session entrypoint (see the migration note in
//! `postgres.rs` / `docs/multi-dialect-wire-protocol-design.md`).

use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use vericto_engine::{AccessMode, AccessPolicy, AccessPolicyMap, EnforcementPolicy};

use crate::tcp::client_tls::{ClientRead, ClientWrite};
use crate::tcp::codec::build_ready_for_query;
use crate::tcp::evaluator::{
    SENSITIVE_RULE_CODE, TcpDecision, access_command_decision, evaluate_message,
};
use crate::tcp::postgres::{EventIdentity, PgProxyConfig};
use crate::tcp::protocol::{
    AccessControl, BlockContext, Classified, QueryKind, RawClientMessage, WireProtocol,
};

/// Who the session is, for the agent-access allowlists (VERICTO-087), and the
/// policy its statements are evaluated with.
///
/// The user is the one the session authenticated as: the Postgres StartupMessage
/// `user`, the MySQL HandshakeResponse username. Nothing the client sends later
/// changes it: `SET ROLE` / `SET SESSION AUTHORIZATION` are SQL, which the engine
/// denies under a policy, and the protocol commands that change the user or the
/// default database are refused here (see [`AccessControl`]).
///
/// The policy is resolved again for every statement from the live sync state, so
/// a rules sync that adds, changes or removes this user's policy applies from the
/// session's next statement. The resolution is cached against the two snapshots it
/// was built from (`Arc::ptr_eq`): between syncs a statement pays two atomic loads
/// and no allocation; a session whose user has no policy uses the shared policy
/// itself, exactly as before.
pub(crate) struct SessionAccess {
    user: Option<String>,
    cached: Option<(
        Arc<EnforcementPolicy>,
        Arc<AccessPolicyMap>,
        Arc<EnforcementPolicy>,
    )>,
}

impl SessionAccess {
    pub(crate) fn new(user: Option<String>) -> Self {
        Self { user, cached: None }
    }

    /// The policy for this session's next evaluation.
    fn policy(&mut self, config: &PgProxyConfig) -> Arc<EnforcementPolicy> {
        let base = config.policy.load_full();
        let map = config.agent_access.load_full();
        if let Some((b, m, effective)) = &self.cached
            && Arc::ptr_eq(b, &base)
            && Arc::ptr_eq(m, &map)
        {
            return Arc::clone(effective);
        }
        let effective = match select_policy(&map, self.user.as_deref()) {
            None => Arc::clone(&base),
            Some(access) => Arc::new(EnforcementPolicy {
                access_policy: Some(access),
                ..(*base).clone()
            }),
        };
        self.cached = Some((base, map, Arc::clone(&effective)));
        effective
    }

    /// The session user's policy in `map`, as [`select_policy`] picks it.
    fn policy_in(&self, map: &AccessPolicyMap) -> Option<AccessPolicy> {
        select_policy(map, self.user.as_deref())
    }

    /// The session became `user` (an allowed MySQL COM_CHANGE_USER).
    fn set_user(&mut self, user: Option<String>) {
        self.user = user;
        self.cached = None;
    }

    /// Identity fields of a telemetry event evaluated under `policy`.
    fn identity(&self, policy: &EnforcementPolicy) -> EventIdentity {
        EventIdentity {
            db_user: self.user.clone(),
            access_mode: policy.access_policy.as_ref().map(|p| p.mode),
        }
    }
}

/// The policy of a session of `user`: `AccessPolicyMap::for_user` (exact key,
/// else `"*"`, else none). A session whose user could not be read gets a
/// deny-everything enforce policy as soon as any user has one: it might be
/// one of them, and the proxy cannot show it is not.
fn select_policy(map: &AccessPolicyMap, user: Option<&str>) -> Option<AccessPolicy> {
    match user {
        Some(u) => map.for_user(u).cloned(),
        None if map.0.is_empty() => None,
        None => Some(AccessPolicy::default()),
    }
}

/// The strictest of the modes of the policies involved: `Enforce` wins.
fn strictest_mode<'a>(policies: impl IntoIterator<Item = &'a AccessPolicy>) -> Option<AccessMode> {
    policies.into_iter().map(|p| p.mode).reduce(|a, b| {
        if a == AccessMode::Enforce || b == AccessMode::Enforce {
            AccessMode::Enforce
        } else {
            AccessMode::Observe
        }
    })
}

/// Runs the generic client→server interception loop for any wire protocol.
///
/// `proto` supplies framing/classification/block bytes; everything else
/// (evaluation, telemetry, enforcement, forwarding) is shared. Preserves the
/// Postgres extended-protocol behavior: on a blocked Parse, follow-up messages
/// are swallowed until the protocol's end-of-sequence marker.
pub async fn intercept_client_to_server(
    proto: &dyn WireProtocol,
    client_read: &mut ClientRead,
    server_write: &mut crate::tcp::upstream::UpstreamWrite,
    client_write: &Arc<Mutex<ClientWrite>>,
    // `Arc` rather than `&PgProxyConfig`: evaluation and telemetry run on the
    // blocking pool, which needs an owned handle.
    config: &Arc<PgProxyConfig>,
    // The database user the session authenticated as (None when it could not
    // be read). Selects the session's agent-access policy.
    session_user: Option<String>,
) -> std::io::Result<()> {
    let mut access = SessionAccess::new(session_user);

    // When we block in an extended/prepared sequence, swallow follow-ups until
    // the end-of-sequence marker (Postgres: Sync 'S'). Only the Postgres path
    // sets this; MySQL never requests it.
    let mut skip_until_sync = false;

    // For protocols that negotiate auth on this same stream (MySQL), stay in
    // pass-through until the command phase begins. Postgres intercepts from the
    // first message (auth happens before this loop).
    let mut in_command_phase = proto.intercepts_from_start();

    loop {
        let msg = match proto.read_client_message(client_read).await? {
            Some(m) => m,
            None => break, // client closed
        };

        // Pass auth/negotiation packets through untouched until the command
        // phase starts, so they are never misclassified as SQL.
        if !in_command_phase {
            if proto.is_command_phase_start(&msg) {
                in_command_phase = true;
                // fall through: this first command-phase message IS classified.
            } else {
                forward(server_write, &msg.encode()).await?;
                continue;
            }
        }

        if skip_until_sync {
            if is_postgres_sync(&msg) {
                send_to_client(client_write, &build_ready_for_query()).await?;
                skip_until_sync = false;
            }
            continue; // swallow the aborted extended sequence
        }

        match proto.classify(&msg) {
            Classified::Terminate => {
                forward(server_write, &msg.encode()).await?;
                break;
            }
            Classified::PassThrough => {
                // A protocol command outside SQL that reaches identity, name
                // resolution or data the statement analysis never sees. Only
                // refused when the session is under an allowlist (or, for a user
                // change, when either user is).
                let refused = match proto.access_control(&msg) {
                    AccessControl::Allowed => None,
                    AccessControl::Restricted { label, kind } => {
                        let policy = access.policy(config);
                        policy.access_policy.as_ref().map(|p| {
                            let decision =
                                access_command_decision(&label, p.mode, policy.monitor_mode);
                            (label, kind, decision, access.identity(&policy))
                        })
                    }
                    AccessControl::ChangeUser { user } => {
                        let policy = access.policy(config);
                        let map = config.agent_access.load();
                        let target = select_policy(&map, user.as_deref());
                        let current = access.policy_in(&map);
                        let refused =
                            strictest_mode(current.iter().chain(target.iter())).map(|mode| {
                                let label = "COM_CHANGE_USER".to_string();
                                let decision =
                                    access_command_decision(&label, mode, policy.monitor_mode);
                                (label, QueryKind::Simple, decision, access.identity(&policy))
                            });
                        // Forwarded (no policy involved, or observe): the session
                        // is now the target user, for every later statement.
                        if !matches!(refused, Some((_, _, TcpDecision::Block { .. }, _))) {
                            access.set_user(user);
                        }
                        refused
                    }
                };
                if let Some((label, kind, decision, identity)) = refused {
                    crate::tcp::postgres::report_telemetry(
                        config,
                        &label,
                        proto.dialect(),
                        &decision,
                        0,
                        &identity,
                    );
                    if let TcpDecision::Block {
                        rule_code,
                        ast_node_path,
                        ..
                    } = &decision
                    {
                        crate::tcp::postgres::log_block(&label, rule_code, ast_node_path);
                        let block = proto.build_block_response(&BlockContext {
                            rule_code,
                            ast_node_path,
                            suggested_safe_query: None,
                            kind,
                            client_seq: message_seq(&msg),
                        });
                        send_to_client(client_write, &block.bytes).await?;
                        if block.skip_until_sync {
                            skip_until_sync = true;
                        }
                        continue; // NOT forwarded upstream
                    }
                }
                forward(server_write, &msg.encode()).await?;
            }
            Classified::Query { sql, kind } => {
                // Read the active ruleset/policy lock-free (syncer may swap them).
                // `load_full` (not `load`) because both cross into the blocking
                // pool below, which needs owned handles rather than guards. The
                // policy is this session's: the workspace policy plus its user's
                // allowlist, resolved again for every statement.
                let rules = config.ruleset.load_full();
                let policy = access.policy(config);
                let identity = access.identity(&policy);

                // Admission guard, before any parse. Evaluation cost is linear in
                // input size, so an oversized statement is refused rather than
                // paid for — and refusing here also skips the telemetry sanitize
                // pass, which parses again.
                if sql.len() > config.max_query_bytes {
                    let oversized = crate::tcp::query_limit::oversized_decision(
                        sql.len(),
                        config.max_query_bytes,
                        policy.monitor_mode,
                    );
                    crate::tcp::postgres::report_telemetry(
                        config,
                        &crate::tcp::query_limit::oversize_marker(sql.len()),
                        proto.dialect(),
                        &oversized,
                        0,
                        &identity,
                    );
                    if let TcpDecision::Block {
                        rule_code,
                        ast_node_path,
                        suggested_safe_query,
                        ..
                    } = &oversized
                    {
                        tracing::warn!(
                            bytes = sql.len(),
                            limit = config.max_query_bytes,
                            "Query exceeds VERICTO_MAX_QUERY_BYTES; rejected without evaluation"
                        );
                        let block = proto.build_block_response(&BlockContext {
                            rule_code,
                            ast_node_path,
                            suggested_safe_query: suggested_safe_query.as_deref(),
                            kind,
                            client_seq: message_seq(&msg),
                        });
                        send_to_client(client_write, &block.bytes).await?;
                        if block.skip_until_sync {
                            skip_until_sync = true;
                        }
                        continue; // query NOT forwarded upstream
                    }
                    // monitor_mode: the workspace has opted out of blocking, and
                    // `monitor_mode` is documented as never increasing blocking,
                    // so the query is forwarded. It is forwarded *unevaluated*:
                    // nothing could be enforced on the result, so paying seconds
                    // of CPU for an unactionable finding buys nothing.
                    tracing::warn!(
                        bytes = sql.len(),
                        limit = config.max_query_bytes,
                        "Query exceeds VERICTO_MAX_QUERY_BYTES; forwarded unevaluated (monitor_mode)"
                    );
                    forward(server_write, &msg.encode()).await?;
                    continue;
                }

                // Evaluation is CPU-bound and synchronous, and so is the sanitize
                // pass inside `report_telemetry`. Both run on the blocking pool:
                // on the async reactor they stall the worker thread, freezing every
                // other connection scheduled on it — a per-connection cost turning
                // into a multi-tenant one. Measured hop cost is ~7 µs, negligible
                // next to a database round trip.
                let eval_start = Instant::now();
                let (decision, eval_us) = {
                    let sql = sql.clone();
                    let dialect = proto.dialect();
                    let config = Arc::clone(config);
                    tokio::task::spawn_blocking(move || {
                        let decision = evaluate_message(&sql, dialect, kind, &rules, &policy);
                        let eval_us = eval_start.elapsed().as_micros();
                        // Telemetry before any forwarding (R5.7).
                        crate::tcp::postgres::report_telemetry(
                            &config, &sql, dialect, &decision, eval_us, &identity,
                        );
                        (decision, eval_us)
                    })
                    .await
                    .expect("evaluation task panicked")
                };
                let _ = eval_us;

                if let TcpDecision::Block {
                    rule_code,
                    ast_node_path,
                    suggested_safe_query,
                    ..
                } = &decision
                {
                    crate::tcp::postgres::log_block(&sql, rule_code, ast_node_path);
                    let block = proto.build_block_response(&BlockContext {
                        rule_code,
                        ast_node_path,
                        suggested_safe_query: suggested_safe_query.as_deref(),
                        kind,
                        client_seq: message_seq(&msg),
                    });
                    send_to_client(client_write, &block.bytes).await?;
                    if block.skip_until_sync {
                        skip_until_sync = true;
                    }
                    continue; // query NOT forwarded upstream
                }

                // Masked → forward the rewritten SQL in the same message (same
                // statement name and parameter types on a Parse). Never the
                // original: if this protocol cannot carry the rewrite, block.
                if let TcpDecision::Forward {
                    rewritten_query: Some(rewritten),
                    ..
                } = &decision
                {
                    if let Some(masked) = proto.with_query(&msg, rewritten) {
                        tracing::info!(
                            query_preview = %sql.chars().take(80).collect::<String>(),
                            "Query MASKED at TCP proxy; forwarding the rewritten SQL"
                        );
                        forward(server_write, &masked.encode()).await?;
                        continue;
                    }
                    // Rare: `evaluate` already refuses a rewrite for a dialect
                    // without one, and a Postgres query message always carries it.
                    // A MySQL packet cannot when the rewrite would not fit one
                    // packet, or a COM_QUERY's attributes prefix binds values the
                    // proxy cannot frame. The telemetry event above then says
                    // FLAGGED; the block still wins.
                    let ast_node_path = "SensitiveColumn > mask not enforceable by the proxy: \
                                         this wire protocol cannot carry the rewritten query";
                    tracing::error!(ast_node_path, "blocking a masked query");
                    crate::tcp::postgres::log_block(&sql, SENSITIVE_RULE_CODE, ast_node_path);
                    let block = proto.build_block_response(&BlockContext {
                        rule_code: SENSITIVE_RULE_CODE,
                        ast_node_path,
                        suggested_safe_query: None,
                        kind,
                        client_seq: message_seq(&msg),
                    });
                    send_to_client(client_write, &block.bytes).await?;
                    if block.skip_until_sync {
                        skip_until_sync = true;
                    }
                    continue;
                }

                // Allowed / flagged / monitored → forward unchanged.
                forward(server_write, &msg.encode()).await?;
            }
        }
    }
    Ok(())
}

/// Handles one MySQL client connection end to end.
///
/// MySQL is server-first: the real server sends the Initial Handshake, the
/// client replies with auth, then the command phase begins. The proxy connects
/// upstream first (no client-side startup negotiation, unlike Postgres), then
/// the server→client relay carries the handshake and the interception loop
/// passes auth packets through (gated by `is_command_phase_start`) before
/// intercepting queries. Client-side TLS is not offered in Phase 1 (trusted
/// network); upstream TLS for MySQL is a follow-up.
pub async fn handle_mysql_connection(client: tokio::net::TcpStream, config: Arc<PgProxyConfig>) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if let Err(e) = run_mysql_session(client, config).await {
        tracing::debug!(peer = %peer, error = %e, "MySQL TCP session ended");
    }
}

async fn run_mysql_session(
    client: tokio::net::TcpStream,
    config: Arc<PgProxyConfig>,
) -> std::io::Result<()> {
    use crate::tcp::codec_mysql::{self as mc, AuthPhase};
    use tokio::io::AsyncWriteExt;

    let proto = crate::tcp::protocol::mysql::MysqlProtocol;
    let upstream_tls = config.upstream_tls != crate::tcp::upstream::UpstreamTlsMode::Disable;
    let client_tls_enabled = config.client_tls_acceptor.is_some();

    // Connect upstream (raw TCP; MySQL server speaks first).
    let mut tcp =
        tokio::net::TcpStream::connect((config.upstream_host.as_str(), config.upstream_port))
            .await?;
    let _ = tcp.set_nodelay(true);

    // ── Connection phase, driven as a strict sequential state machine ─────────
    // The MySQL connection phase is NOT complete at the HandshakeResponse: the
    // auth plugin may require several client↔server exchanges, ending only when
    // the server sends OK or ERR (protocol docs; matches ProxySQL/MaxScale). We
    // pump packets in order — no concurrent relay — until OK, then hand off to
    // the command-phase relay+intercept.
    //
    // TLS coherence: caching_sha2/native_password derive the scramble from the
    // "is this a secure connection" state, so BOTH hops must share it. When
    // client TLS is on we advertise CLIENT_SSL to the client (so it wraps its
    // side in TLS) and also do TLS upstream — both secure. Mixing one plaintext
    // + one TLS breaks auth (see docs/mysql-tls-state-of-the-art.md).

    // 1. Server Initial Handshake (seq 0). If we terminate client TLS, advertise
    //    CLIENT_SSL to the client so it initiates its SSL Request.
    let handshake = mc::read_packet(&mut tcp).await?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "no MySQL handshake from upstream",
        )
    })?;
    let server_caps = mc::read_server_capabilities(&handshake.payload).unwrap_or(0);
    if upstream_tls && server_caps & mc::CLIENT_SSL == 0 {
        return Err(std::io::Error::other(
            "UPSTREAM_MYSQL TLS requested but the server does not advertise CLIENT_SSL",
        ));
    }

    // 2. Client TLS is negotiated on the whole stream BEFORE splitting: send the
    //    handshake, read the client's SSL Request, terminate TLS, then split the
    //    resulting TLS stream. Without client TLS we split immediately.
    let (mut client_read, mut client_write_direct): (ClientRead, ClientWrite) =
        if client_tls_enabled {
            use tokio::io::AsyncWriteExt as _;
            let mut client = client;
            // Forward the handshake to the client over plaintext.
            client.write_all(&handshake.encode()).await?;
            client.flush().await?;
            // Client replies with an SSL Request (seq 1, 32-byte truncated response).
            let ssl_req = mc::read_packet(&mut client).await?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed before SSL Request",
                )
            })?;
            let caps = mc::read_client_capabilities(&ssl_req.payload).unwrap_or(0);
            if caps & mc::CLIENT_SSL == 0 {
                return Err(std::io::Error::other(
                    "PROXY_TLS_MODE=require but the MySQL client did not request TLS (add --ssl-mode=REQUIRED)",
                ));
            }
            // Terminate TLS as the server on the client hop.
            crate::tcp::client_tls::accept_tls(config.client_tls_acceptor.as_ref().unwrap(), client)
                .await?
        } else {
            let (r, w) = tokio::io::split(client);
            let mut cw: ClientWrite = Box::new(w);
            cw.write_all(&handshake.encode()).await?;
            cw.flush().await?;
            (Box::new(r) as ClientRead, cw)
        };

    // The real HandshakeResponse: over TLS (seq 2) when client TLS is on, else
    // straight after the handshake (seq 1).
    let client_resp = mc::read_packet(&mut client_read).await?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed during handshake",
        )
    })?;
    // The user the server authenticates: the session's identity for the
    // agent-access allowlists.
    let session_user = mc::read_handshake_username(&client_resp.payload);

    // 3. Forward the HandshakeResponse to the server, upgrading to TLS first when
    //    upstream TLS is enabled (SSL Request → TLS → response with CLIENT_SSL).
    let (server_read, mut server_write): (
        crate::tcp::upstream::UpstreamRead,
        crate::tcp::upstream::UpstreamWrite,
    ) = if upstream_tls {
        // SSL Request (seq 1) = byte-exact 32-byte prefix of the client's
        // response with CLIENT_SSL forced on, then TLS handshake.
        let ssl_req = mc::build_ssl_request_from_response(1, &client_resp.payload);
        tcp.write_all(&ssl_req).await?;
        tcp.flush().await?;
        let (sr, mut sw) = crate::tcp::upstream::upgrade_to_tls_client(
            tcp,
            &config.upstream_host,
            config.upstream_tls,
        )
        .await?;
        // HandshakeResponse over TLS with CLIENT_SSL set, re-sequenced to 2.
        let payload = mc::set_client_ssl_flag(&client_resp.payload, true);
        sw.write_all(&mc::MySqlPacket { seq: 2, payload }.encode())
            .await?;
        sw.flush().await?;
        (sr, sw)
    } else {
        let (r, w) = tcp.into_split();
        let mut sw: crate::tcp::upstream::UpstreamWrite = Box::new(w);
        // Plaintext upstream: forward the response as-is (strip CLIENT_SSL if
        // the client had negotiated it with us, since the server side is plain).
        let payload = mc::set_client_ssl_flag(&client_resp.payload, false);
        sw.write_all(
            &mc::MySqlPacket {
                seq: client_resp.seq,
                payload,
            }
            .encode(),
        )
        .await?;
        sw.flush().await?;
        (Box::new(r) as crate::tcp::upstream::UpstreamRead, sw)
    };

    // 4. Auth exchange loop: pump server↔client packets in order until OK/ERR.
    let mut server_read = server_read;
    loop {
        let srv_pkt = match mc::read_packet(&mut server_read).await? {
            Some(p) => p,
            None => return Ok(()), // upstream closed mid-auth
        };
        client_write_direct.write_all(&srv_pkt.encode()).await?;
        client_write_direct.flush().await?;
        match mc::classify_auth_packet(&srv_pkt.payload) {
            AuthPhase::Ok => break,          // authenticated → command phase
            AuthPhase::Err => return Ok(()), // auth failed; client already notified
            // The server's next packet (the OK after caching_sha2's fast-auth
            // success) is already on its way; the client has nothing to send.
            AuthPhase::ServerContinues => {}
            AuthPhase::More => {
                // Server wants more auth data; relay the client's next packet.
                let cli_pkt = match mc::read_packet(&mut client_read).await? {
                    Some(p) => p,
                    None => return Ok(()),
                };
                server_write.write_all(&cli_pkt.encode()).await?;
                server_write.flush().await?;
            }
        }
    }

    // ── Command phase: now the concurrent relay + interception model applies ──
    let client_write = Arc::new(Mutex::new(client_write_direct));
    let relay_handle = tokio::spawn(relay_upstream_to_client(server_read, client_write.clone()));

    let result = intercept_client_to_server(
        &proto,
        &mut client_read,
        &mut server_write,
        &client_write,
        &config,
        session_user,
    )
    .await;

    relay_handle.abort();
    result
}

/// Relays bytes from the upstream to the client without intercepting. Generic
/// over any boxed upstream read half (shared by the MySQL session).
async fn relay_upstream_to_client(
    mut server_read: crate::tcp::upstream::UpstreamRead,
    client_write: Arc<Mutex<ClientWrite>>,
) {
    use tokio::io::AsyncReadExt;
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

/// Sequence id needed to build a correctly-numbered reply (MySQL). Postgres has
/// no per-message sequence, so it returns 0 (ignored by the pg block builder).
fn message_seq(msg: &RawClientMessage) -> u8 {
    match msg {
        RawClientMessage::Mysql(p) => p.seq,
        RawClientMessage::Postgres(_) => 0,
    }
}

/// True for a Postgres Sync ('S') message — the extended-protocol resume point.
fn is_postgres_sync(msg: &RawClientMessage) -> bool {
    matches!(msg, RawClientMessage::Postgres(m) if m.tag == b'S')
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
