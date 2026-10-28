// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Protocol-agnostic session logic for the multi-dialect proxy.
//!
//! The client→server interception loop is identical across wire protocols once
//! framing/classification/block-bytes are abstracted behind `WireProtocol`:
//!   read message → classify → (if SQL) evaluate with the protocol's dialect →
//!   on Block, send the native rejection and (protocol-permitting) swallow the
//!   rest of the sequence → on a mask or a `rewrite_limit` bound, forward the
//!   engine's rewritten SQL in place of the original (never the original) →
//!   otherwise forward upstream unchanged.
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
use crate::tcp::codec::PgMessage;
use crate::tcp::evaluator::{
    PolicyEval, TcpDecision, access_command_decision, evaluate_message, evaluate_message_with,
    rewrite_not_enforceable,
};
use crate::tcp::postgres::{EventIdentity, PgProxyConfig};
use crate::tcp::protocol::mysql::UseTarget;
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
/// default database are refused here under a policy (see [`AccessControl`]).
///
/// On MySQL the session also tracks its current database, the schema
/// unqualified names resolve to (`AccessPolicy::default_schema`, engine 3.8.1):
/// the one named in the HandshakeResponse, then each forwarded COM_INIT_DB,
/// `USE` or COM_CHANGE_USER. It wins over the synced policy's `default_schema`
/// (the dashboard's setting), which applies only while the session names none.
/// On Postgres the policy's `default_schema` is used as synced (absent: the
/// engine's `public`); `search_path` cannot move it, as `SET search_path` and
/// the StartupMessage's `search_path` are denied under a policy.
///
/// The policy is resolved again for every statement from the live sync state, so
/// a rules sync that adds, changes or removes this user's policy applies from the
/// session's next statement. The resolution is cached against the two snapshots it
/// was built from (`Arc::ptr_eq`): between syncs a statement pays two atomic loads
/// and no allocation; a session whose user has no policy uses the shared policy
/// itself, exactly as before.
pub(crate) struct SessionAccess {
    user: Option<String>,
    database: CurrentDatabase,
    /// The session's principal and declared context for telemetry, with policy
    /// rules on (refreshed by the loop before each message); `None` when off.
    policy_telemetry: Option<Arc<crate::tcp::policy_rules::PolicyTelemetry>>,
    cached: Option<(
        Arc<EnforcementPolicy>,
        Arc<AccessPolicyMap>,
        Arc<EnforcementPolicy>,
    )>,
}

impl SessionAccess {
    pub(crate) fn new(user: Option<String>, database: CurrentDatabase) -> Self {
        Self {
            user,
            database,
            policy_telemetry: None,
            cached: None,
        }
    }

    /// The policy for this session's next evaluation.
    fn policy(&mut self, config: &PgProxyConfig) -> Arc<EnforcementPolicy> {
        let base = config.policy.load_full();
        let map = config.agent_access.load_full();
        Arc::clone(self.policy_from(&base, &map))
    }

    /// [`Self::policy`] from snapshots the caller already holds (the
    /// prepared-statement check reads them from per-session caches).
    fn policy_from(
        &mut self,
        base: &Arc<EnforcementPolicy>,
        map: &Arc<AccessPolicyMap>,
    ) -> &Arc<EnforcementPolicy> {
        let hit = self
            .cached
            .as_ref()
            .is_some_and(|(b, m, _)| Arc::ptr_eq(b, base) && Arc::ptr_eq(m, map));
        if !hit {
            let effective = match select_policy(map, self.user.as_deref()) {
                None => Arc::clone(base),
                Some(mut access) => Arc::new(EnforcementPolicy {
                    access_policy: Some({
                        self.database.apply(&mut access);
                        access
                    }),
                    ..(**base).clone()
                }),
            };
            self.cached = Some((Arc::clone(base), Arc::clone(map), effective));
        }
        &self.cached.as_ref().expect("set above").2
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

    /// The session's current database moved (MySQL: a forwarded COM_INIT_DB,
    /// `USE` or COM_CHANGE_USER).
    fn set_database(&mut self, database: CurrentDatabase) {
        if self.database != database {
            self.database = database;
            self.cached = None;
        }
    }

    /// Identity fields of a telemetry event evaluated under `policy`.
    fn identity(&self, policy: &EnforcementPolicy) -> EventIdentity {
        EventIdentity {
            db_user: self.user.clone(),
            access_mode: policy.access_policy.as_ref().map(|p| p.mode),
            policy: self.policy_telemetry.clone(),
        }
    }
}

/// Per-session caches of the synced snapshots ([`arc_swap::Cache`]): reading
/// one costs a pointer compare until a sync swaps it.
struct SnapshotInputs<'a> {
    rules: arc_swap::Cache<
        &'a arc_swap::ArcSwap<Vec<vericto_engine::Rule>>,
        Arc<Vec<vericto_engine::Rule>>,
    >,
    policy: arc_swap::Cache<&'a arc_swap::ArcSwap<EnforcementPolicy>, Arc<EnforcementPolicy>>,
    access: arc_swap::Cache<&'a arc_swap::ArcSwap<AccessPolicyMap>, Arc<AccessPolicyMap>>,
}

/// What the session's entrypoint learnt at the handshake, before the
/// interception loop starts.
#[derive(Clone, Default)]
pub struct SessionStart {
    /// The database user the session authenticated as (None when it could not
    /// be read). Selects the session's agent-access policy.
    pub user: Option<String>,
    /// MySQL: the session's current database from the HandshakeResponse.
    /// Always [`CurrentDatabase::FromPolicy`] on Postgres, whose `database` is
    /// not a schema.
    pub database: CurrentDatabase,
    /// MySQL: the client capability flags of the HandshakeResponse (the layout
    /// of a later COM_CHANGE_USER depends on them). 0 on Postgres.
    pub client_caps: u32,
    /// What the session declared at startup (`vericto.ticket`, `vericto.tenant`,
    /// `application_name` / `program_name`). Read only with policy rules on.
    pub declared: crate::tcp::policy_rules::SessionDeclared,
    /// The transaction state the server last reported, kept by the PostgreSQL
    /// relay in every mode since 4.16.1. On MySQL it is present only when the
    /// policy path needs server status for a locally consumed statement.
    pub tx_state: Option<Arc<crate::tcp::tx_state::ServerTxState>>,
    /// PostgreSQL only: ordered response plans and prepared-statement state.
    /// `None` on MySQL, whose existing command/response path is unchanged.
    pub pg_responses: Option<crate::tcp::pg_response::PgResponseCoordinator>,
}

/// The schema unqualified names resolve to in a session, as the proxy knows it.
/// Only MySQL sessions move it; it is the engine's `default_schema`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CurrentDatabase {
    /// The session named none (or Postgres): the synced policy's
    /// `default_schema` applies, absent = the engine default.
    #[default]
    FromPolicy,
    /// The session's current database, named in the handshake or by a later
    /// COM_INIT_DB / `USE` / COM_CHANGE_USER. Wins over the policy's value.
    Named(String),
    /// The session moved to a database the proxy could not read: no default
    /// schema, so only unqualified names match entries without a schema (the
    /// engine's stricter reading), never the policy's value.
    Unknown,
}

impl CurrentDatabase {
    /// From a database read off the wire: `Some(None)` names none, `None` is
    /// unreadable.
    pub(crate) fn from_wire(database: Option<Option<String>>) -> Self {
        match database {
            Some(Some(db)) => CurrentDatabase::Named(db),
            Some(None) => CurrentDatabase::FromPolicy,
            None => CurrentDatabase::Unknown,
        }
    }

    /// Sets `policy.default_schema` for this session.
    fn apply(&self, policy: &mut AccessPolicy) {
        match self {
            CurrentDatabase::FromPolicy => {}
            CurrentDatabase::Named(db) => policy.default_schema = Some(db.clone()),
            CurrentDatabase::Unknown => policy.default_schema = None,
        }
    }
}

/// Postgres: the startup settings that change who the session is or where
/// names resolve (`search_path`, `role`, `session_authorization`, sent as
/// StartupMessage parameters or in `options`), evaluated exactly as the `SET`
/// the client could send after connecting, under the session user's policy:
/// denied under an enforced allowlist, flagged under observe or monitor mode
/// (and forwarded). Evaluated only when the session has an allowlist or the
/// database has sensitive-column tags; otherwise nothing changes. Each one is
/// reported like the statement it stands for. Returns the block message of
/// the first one blocked: the connection is then refused before it reaches
/// the database. Runs on the blocking pool (it evaluates).
pub(crate) fn startup_settings_block(
    config: &PgProxyConfig,
    user: Option<&str>,
    settings: &[(String, String)],
) -> Option<String> {
    if settings.is_empty() {
        return None;
    }
    let mut access = SessionAccess::new(user.map(str::to_string), CurrentDatabase::FromPolicy);
    let policy = access.policy(config);
    if policy.access_policy.is_none() && policy.sensitive_columns.is_empty() {
        return None;
    }
    let rules = config.ruleset.load_full();
    let identity = access.identity(&policy);
    let dialect = vericto_engine::Dialect::Postgres;
    for (name, value) in settings {
        let sql = format!("SET {name} = '{}'", value.replace('\'', "''"));
        let start = Instant::now();
        let decision = evaluate_message(&sql, dialect, QueryKind::Simple, &rules, &policy);
        crate::tcp::postgres::report_telemetry(
            config,
            &sql,
            dialect,
            &decision,
            start.elapsed().as_micros(),
            &identity,
        );
        if let TcpDecision::Block {
            rule_code,
            ast_node_path,
            ..
        } = &decision
        {
            crate::tcp::postgres::log_block(&sql, dialect, rule_code, ast_node_path);
            return Some(crate::tcp::protocol::postgres::block_message(
                rule_code,
                &format!("{ast_node_path} (StartupMessage {name})"),
                None,
            ));
        }
    }
    None
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
    // Who the session is and, on MySQL, its current database.
    start: SessionStart,
) -> std::io::Result<()> {
    let client_caps = start.client_caps;
    let tx_state = start.tx_state;
    let pg_responses = start.pg_responses;
    // What a consumed `SET vericto.*` reports when no relay tracks the state.
    let untracked = crate::tcp::tx_state::ServerTxState::new();
    let mut access = SessionAccess::new(start.user, start.database);
    // Policy rules (4.15.0): `None` with VERICTO_POLICY_RULES=off; the
    // protocol ordering and prepared-statement tracking remain active.
    let policy_mode = config.policy_rules.mode;
    let mut session_policy = policy_mode
        .is_on()
        .then(|| crate::tcp::policy_rules::SessionPolicy::new(start.declared));

    // When we block in an extended/prepared sequence, swallow follow-ups until
    // the end-of-sequence marker (Postgres: Sync 'S'). Only the Postgres path
    // sets this; MySQL never requests it.
    let mut skip_until_sync = false;
    // PostgreSQL with the response coordinator: after the kill switch refused a
    // message of an extended sequence, the server skips the rest of it until
    // Sync (the refusal reached it as an invalid Parse), so the rest is dropped
    // here: one refusal, one event, per sequence.
    let mut kill_switch_until_sync = false;

    // For protocols that negotiate auth on this same stream (MySQL), stay in
    // pass-through until the command phase begins. Postgres intercepts from the
    // first message (auth happens before this loop).
    let mut in_command_phase = proto.intercepts_from_start();

    // The sync snapshots a Bind/Execute compares a prepared statement against.
    let mut snapshot_inputs = SnapshotInputs {
        rules: arc_swap::Cache::new(&*config.ruleset),
        policy: arc_swap::Cache::new(&*config.policy),
        access: arc_swap::Cache::new(&*config.agent_access),
    };

    // PostgreSQL with ordered responses (4.17.3): the client is read through a
    // buffer, and the frontend messages framed from it go upstream together
    // (see [`UpstreamSender`]). Their plans are registered in order as each
    // one is handled, before its bytes leave, as before.
    let coalesce = pg_responses.is_some() && proto.client_read_buffer() > 0;
    // Capacity 1 buffers nothing: `BufReader` passes every read of at least
    // its capacity straight to the socket (0 is not a valid capacity). MySQL
    // reads through the buffer too (4.19.0), without coalescing.
    let mut client_read = tokio::io::BufReader::with_capacity(
        if coalesce || proto.buffers_client_reads() {
            proto.client_read_buffer().max(1)
        } else {
            1
        },
        client_read,
    );
    let mut upstream = UpstreamSender::new(server_write, coalesce);
    // The decisions of trivial statements this session sent (4.19.0).
    let mut verdicts = crate::tcp::fast_path::Verdicts::default();
    // Every frontend message is read into this one (PostgreSQL reuses its
    // buffer from message to message).
    let mut msg = RawClientMessage::Postgres(PgMessage {
        tag: 0,
        body: Vec::new(),
    });

    loop {
        // Nothing is held upstream while the loop waits for the client: what
        // is pending goes out as soon as the client's buffered bytes hold no
        // further whole message.
        if !proto.has_buffered_message(client_read.buffer()) {
            upstream.flush().await?;
        }
        // A message already buffered is framed here, without the boxed future
        // of the trait's async read (4.20.0).
        if !proto.take_buffered_message(&mut client_read, &mut msg)
            && !proto
                .read_client_message_into(&mut client_read, &mut msg)
                .await?
        {
            break; // client closed
        }

        // Pass auth/negotiation packets through untouched until the command
        // phase starts, so they are never misclassified as SQL.
        if !in_command_phase {
            if proto.is_command_phase_start(&msg) {
                in_command_phase = true;
                // fall through: this first command-phase message IS classified.
            } else {
                forward_client_message(&mut upstream, &msg, pg_responses.as_ref(), None).await?;
                continue;
            }
        }

        if skip_until_sync {
            if is_postgres_sync(&msg) {
                send_to_client(client_write, &proto.build_sync_reply(tx_state.as_deref())).await?;
                skip_until_sync = false;
            }
            continue; // swallow the aborted extended sequence
        }

        // MySQL, policy rules on: the relay reads the response to this command
        // for its status flags (sequence id 0 starts a command).
        if let (Some(tx), RawClientMessage::Mysql(p)) = (tx_state.as_deref(), &msg)
            && p.seq == 0
            && let Some(&command) = p.payload.first()
        {
            tx.note_mysql_command(command);
        }

        // The session's principal against the bundle in force: resolved again
        // only when a sync swapped the bundle, the user changed or a `SET
        // vericto.*` declared something; otherwise two pointer compares.
        let policy_ctx = session_policy.as_mut().map(|sp| {
            let bundle = config.policy_rules.bundle.load_full();
            let (ctx, telemetry) =
                sp.context(access.user.as_deref(), &bundle, &config.policy_rules);
            access.policy_telemetry = Some(telemetry);
            (bundle, ctx)
        });

        // The kill switch (VERICTO-105, 4.18.0): the session's agent is blocked,
        // so every statement is refused before anything is parsed or evaluated,
        // in every mode. Plumbing (Sync, Describe, ping…) costs one match; any
        // other message one atomic load and an `is_none` while no block is
        // active, and with blocks one hash lookup by the session user.
        if kill_switch_until_sync {
            if is_postgres_sync(&msg) {
                kill_switch_until_sync = false;
            } else if proto.kill_switch_scope(&msg).is_some() {
                continue;
            }
        }
        let refused = proto.kill_switch_scope(&msg).and_then(|kind| {
            config
                .kill_switch
                .load()
                .as_ref()
                .and_then(|ks| ks.for_user(access.user.as_deref()).cloned())
                .map(|block| (kind, block))
        });
        if let Some((kind, block)) = refused {
            let text = match proto.classify(&msg) {
                Classified::Query { sql, .. } => sql,
                _ => kill_switch_label(&msg),
            };
            let policy = access.policy(config);
            crate::tcp::postgres::report_kill_switch(
                config,
                &text,
                proto.dialect(),
                &block,
                &access.identity(&policy),
            );
            let ast_node_path = block.ast_node_path();
            tracing::info!(
                rule_code = crate::tcp::kill_switch::KILL_SWITCH_RULE_CODE,
                block_id = %block.block_id,
                target_type = %block.target_type,
                query_preview = %crate::tcp::postgres::log_preview(&text, proto.dialect()),
                "Statement refused by the kill switch"
            );
            let reply = proto.build_block_response(&BlockContext {
                rule_code: crate::tcp::kill_switch::KILL_SWITCH_RULE_CODE,
                ast_node_path: &ast_node_path,
                suggested_safe_query: None,
                message: Some(&block.message),
                kind,
                client_seq: message_seq(&msg),
                tx: tx_state.as_deref(),
            });
            let extended = reply.skip_until_sync;
            if local_block(
                proto,
                &msg,
                &mut upstream,
                client_write,
                pg_responses.as_ref(),
                reply,
            )
            .await?
            {
                skip_until_sync = true;
            } else if extended && pg_responses.is_some() {
                kill_switch_until_sync = true;
            }
            continue; // NOT forwarded upstream
        }

        // A prepared statement can outlive the rules, effective access policy,
        // business-policy bundle or session context under which Parse was
        // accepted. Bind and Execute re-evaluate only when one of those Arc
        // snapshots changed. MySQL keeps its existing prepare-time behavior.
        if let (Some(pg), RawClientMessage::Postgres(message)) = (pg_responses.as_ref(), &msg)
            && matches!(message.tag, b'B' | b'E')
        {
            // Read through per-session caches: between syncs this is a pointer
            // compare per snapshot, not an `ArcSwap` load.
            let stale = {
                let rules = snapshot_inputs.rules.load();
                let policy = access
                    .policy_from(snapshot_inputs.policy.load(), snapshot_inputs.access.load());
                let current = crate::tcp::pg_response::SnapshotRef {
                    rules: policy_ctx
                        .as_ref()
                        .and_then(|(bundle, _)| bundle.rules.as_ref())
                        .unwrap_or(rules),
                    policy,
                    bundle: policy_ctx.as_ref().map(|(bundle, _)| bundle),
                    context: policy_ctx.as_ref().map(|(_, ctx)| ctx),
                };
                // An Execute is evaluated again when a business policy in force
                // may read the time of execution (4.17.3: only then; see
                // `PolicyRules::reads_time`). Otherwise the verdict reached under
                // the same snapshots stands: a changed snapshot (rules, effective
                // access policy, bundle, session context) is what re-evaluates.
                let time_dependent_execution =
                    message.tag == b'E' && current.bundle.is_some_and(|bundle| bundle.reads_time);
                // The usual case: every statement and portal held was evaluated
                // under the current snapshot, known without a lookup.
                let fresh = !time_dependent_execution
                    && pg
                        .prepared()
                        .lock()
                        .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?
                        .all_evaluated_under(current);
                (!fresh).then(|| current.to_owned())
            };
            let refused = match stale {
                None => None,
                Some(current) => {
                    // A request the server can already answer is not held back
                    // while this one is evaluated.
                    upstream.flush_answerable().await?;
                    let policy = Arc::clone(&current.policy);
                    // The telemetry identity (a copy of the user name) only when
                    // a statement is evaluated again.
                    refresh_prepared(pg, message, current, policy_mode, config, || {
                        access.identity(&policy)
                    })
                    .await?
                }
            };
            if let Some(decision) = refused {
                let TcpDecision::Block {
                    rule_code,
                    ast_node_path,
                    suggested_safe_query,
                    ..
                } = &decision
                else {
                    unreachable!("prepared refresh only returns a block")
                };
                crate::tcp::postgres::log_block(
                    "<prepared statement>",
                    proto.dialect(),
                    rule_code,
                    ast_node_path,
                );
                let block = proto.build_block_response(&BlockContext {
                    rule_code,
                    ast_node_path,
                    suggested_safe_query: suggested_safe_query.as_deref(),
                    message: None,
                    kind: QueryKind::Prepared,
                    client_seq: message_seq(&msg),
                    tx: tx_state.as_deref(),
                });
                local_block(
                    proto,
                    &msg,
                    &mut upstream,
                    client_write,
                    pg_responses.as_ref(),
                    block,
                )
                .await?;
                continue;
            }
        }

        match proto.classify(&msg) {
            Classified::Terminate => {
                forward_client_message(&mut upstream, &msg, pg_responses.as_ref(), None).await?;
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
                        // MySQL changes the database with the user: the
                        // packet's, under the session's capability flags.
                        if !matches!(refused, Some((_, _, TcpDecision::Block { .. }, _)))
                            && let RawClientMessage::Mysql(p) = &msg
                        {
                            access.set_database(CurrentDatabase::from_wire(
                                crate::tcp::codec_mysql::read_change_user_database(
                                    &p.payload,
                                    client_caps,
                                ),
                            ));
                        }
                        refused
                    }
                    AccessControl::ChangeDatabase { database } => {
                        // `USE` in protocol form: refused as `USE` is (the engine
                        // denies it under a policy), labelled COM_INIT_DB.
                        let policy = access.policy(config);
                        let label = "COM_INIT_DB".to_string();
                        let refused = policy.access_policy.as_ref().map(|p| {
                            let decision =
                                access_command_decision(&label, p.mode, policy.monitor_mode);
                            (label, QueryKind::Simple, decision, access.identity(&policy))
                        });
                        // Forwarded (no policy, observe, monitor_mode): unqualified
                        // names resolve to the new database from the next statement.
                        if !matches!(refused, Some((_, _, TcpDecision::Block { .. }, _))) {
                            access.set_database(match database {
                                Some(db) => CurrentDatabase::Named(db),
                                None => CurrentDatabase::Unknown,
                            });
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
                        crate::tcp::postgres::log_block(
                            &label,
                            proto.dialect(),
                            rule_code,
                            ast_node_path,
                        );
                        let block = proto.build_block_response(&BlockContext {
                            rule_code,
                            ast_node_path,
                            suggested_safe_query: None,
                            message: None,
                            kind,
                            client_seq: message_seq(&msg),
                            tx: tx_state.as_deref(),
                        });
                        if local_block(
                            proto,
                            &msg,
                            &mut upstream,
                            client_write,
                            pg_responses.as_ref(),
                            block,
                        )
                        .await?
                        {
                            skip_until_sync = true;
                        }
                        continue; // NOT forwarded upstream
                    }
                }
                forward_client_message(&mut upstream, &msg, pg_responses.as_ref(), None).await?;
            }
            Classified::Query { sql, kind } => {
                // `SET vericto.ticket` / `vericto.tenant`: consumed by the proxy,
                // set once, never forwarded (policy rules on only).
                if let Some(sp) = session_policy.as_mut() {
                    use crate::tcp::policy_rules::{
                        ContextStatement, SESSION_CONTEXT_RULE_CODE, intercept_context_statement,
                    };
                    // In a failed transaction block (Postgres `E`) the server would
                    // refuse the statement with 25P02: so does the proxy, and the
                    // value is not taken. Other statements go to the server, which
                    // answers 25P02 itself.
                    if let Some(reply) = tx_state
                        .as_deref()
                        .and_then(|tx| proto.build_in_failed_transaction(kind, tx))
                    {
                        let mut probe = sp.declared.clone();
                        if !matches!(
                            intercept_context_statement(
                                &sql,
                                kind == QueryKind::Prepared,
                                &mut probe
                            ),
                            ContextStatement::NotContext
                        ) {
                            if local_failed_transaction(
                                &msg,
                                &mut upstream,
                                client_write,
                                pg_responses.as_ref(),
                                reply,
                            )
                            .await?
                            {
                                skip_until_sync = true;
                            }
                            continue; // NOT forwarded upstream
                        }
                    }
                    let mut proposed = sp.declared.clone();
                    match intercept_context_statement(
                        &sql,
                        kind == QueryKind::Prepared,
                        &mut proposed,
                    ) {
                        ContextStatement::NotContext => {}
                        ContextStatement::Consumed => {
                            tracing::debug!("SET vericto.* consumed by the proxy");
                            let tx = tx_state.as_deref().unwrap_or(&untracked);
                            if local_set_ok(
                                proto,
                                &msg,
                                &mut upstream,
                                client_write,
                                pg_responses.as_ref(),
                                tx,
                            )
                            .await?
                            {
                                sp.declared = proposed;
                            }
                            continue; // NOT forwarded upstream
                        }
                        ContextStatement::Blocked(reason) => {
                            let ast_node_path = format!("SessionContext > {reason}");
                            let decision = TcpDecision::Block {
                                rule_code: SESSION_CONTEXT_RULE_CODE.to_string(),
                                ast_node_path: ast_node_path.clone(),
                                suggested_safe_query: None,
                                severity: vericto_engine::Severity::High,
                                violations: Vec::new(),
                                sensitive_columns: Vec::new(),
                                access_denied: Vec::new(),
                            };
                            let policy = access.policy(config);
                            crate::tcp::postgres::report_telemetry(
                                config,
                                &sql,
                                proto.dialect(),
                                &decision,
                                0,
                                &access.identity(&policy),
                            );
                            crate::tcp::postgres::log_block(
                                &sql,
                                proto.dialect(),
                                SESSION_CONTEXT_RULE_CODE,
                                &ast_node_path,
                            );
                            let block = proto.build_block_response(&BlockContext {
                                rule_code: SESSION_CONTEXT_RULE_CODE,
                                ast_node_path: &ast_node_path,
                                suggested_safe_query: None,
                                message: None,
                                kind,
                                client_seq: message_seq(&msg),
                                tx: tx_state.as_deref(),
                            });
                            if local_block(
                                proto,
                                &msg,
                                &mut upstream,
                                client_write,
                                pg_responses.as_ref(),
                                block,
                            )
                            .await?
                            {
                                skip_until_sync = true;
                            }
                            continue; // NOT forwarded upstream
                        }
                    }
                }

                // Read the active ruleset/policy lock-free (syncer may swap them).
                // `load_full` (not `load`) because both cross into the blocking
                // pool below, which needs owned handles rather than guards. The
                // policy is this session's: the workspace policy plus its user's
                // allowlist, resolved again for every statement.
                let rules = config.ruleset.load_full();
                let policy = access.policy(config);
                let identity = access.identity(&policy);
                // The snapshots a Parse is tracked under, for its Bind and
                // Execute (built for a Parse only).
                let snapshot = pg_responses
                    .as_ref()
                    .filter(|_| kind == QueryKind::Prepared)
                    .map(|_| crate::tcp::pg_response::EvalSnapshot {
                        rules: policy_ctx
                            .as_ref()
                            .and_then(|(bundle, _)| bundle.rules.clone())
                            .unwrap_or_else(|| Arc::clone(&rules)),
                        policy: Arc::clone(&policy),
                        bundle: policy_ctx.as_ref().map(|(bundle, _)| Arc::clone(bundle)),
                        context: policy_ctx.as_ref().map(|(_, ctx)| Arc::clone(ctx)),
                    });

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
                            message: None,
                            kind,
                            client_seq: message_seq(&msg),
                            tx: tx_state.as_deref(),
                        });
                        if local_block(
                            proto,
                            &msg,
                            &mut upstream,
                            client_write,
                            pg_responses.as_ref(),
                            block,
                        )
                        .await?
                        {
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
                    let action = stage_parse_action(
                        pg_responses.as_ref(),
                        &msg,
                        &sql,
                        &sql,
                        snapshot.clone(),
                    )?;
                    forward_client_message(&mut upstream, &msg, pg_responses.as_ref(), action)
                        .await?;
                    continue;
                }

                // Evaluation is CPU-bound and synchronous, and so is the sanitize
                // pass inside `report_telemetry`. A statement of at most
                // `VERICTO_INLINE_EVAL_MAX_BYTES` is evaluated on this task (4.19.0):
                // tens of microseconds, less than the two thread hand-offs of the
                // blocking pool cost. A larger one runs on the blocking pool, where
                // its parse cannot stall the other connections of this worker.
                upstream.flush_answerable().await?;
                let eval_start = Instant::now();
                // A trivial statement this session already sent, under the same
                // snapshots: the decision the full evaluation reached for it then
                // (`fast_path`; never under business policy rules).
                let remembered_here = config.trivial_fast_path && policy_ctx.is_none();
                let remembered = if remembered_here {
                    verdicts.get(&sql, kind, &rules, &policy).cloned()
                } else {
                    None
                };
                let snapshots = remembered_here.then(|| (Arc::clone(&rules), Arc::clone(&policy)));
                let (decision, eval_us) = if let Some(decision) = remembered {
                    let eval_us = eval_start.elapsed().as_micros();
                    crate::tcp::postgres::report_telemetry(
                        config,
                        &sql,
                        proto.dialect(),
                        &decision,
                        eval_us,
                        &identity,
                    );
                    (decision, eval_us)
                } else {
                    let sql = sql.clone();
                    let dialect = proto.dialect();
                    let config = Arc::clone(config);
                    run_evaluation(config.inline_eval_max_bytes, sql.len(), move || {
                        let decision = match &policy_ctx {
                            // Policy rules on: the rules the bundle's policies were
                            // compiled from (the same ruleset once a sync ran).
                            Some((bundle, ctx)) => {
                                let ctx = crate::tcp::policy_rules::at_now(ctx);
                                let rules = bundle.rules.as_ref().unwrap_or(&rules);
                                evaluate_message_with(
                                    &sql,
                                    dialect,
                                    kind,
                                    rules,
                                    &policy,
                                    Some(&PolicyEval {
                                        mode: policy_mode,
                                        policies: &bundle.policies,
                                        ctx: &ctx,
                                    }),
                                )
                            }
                            None => evaluate_message(&sql, dialect, kind, &rules, &policy),
                        };
                        let eval_us = eval_start.elapsed().as_micros();
                        // Telemetry before any forwarding (R5.7): enqueued in memory,
                        // persisted by the background writer, so it costs no I/O here.
                        crate::tcp::postgres::report_telemetry(
                            &config, &sql, dialect, &decision, eval_us, &identity,
                        );
                        (decision, eval_us)
                    })
                    .await
                    .expect("evaluation task panicked")
                };
                let _ = eval_us;
                if let Some((rules, policy)) = &snapshots {
                    verdicts.keep(&sql, kind, rules, policy, &decision);
                }

                if let TcpDecision::Block {
                    rule_code,
                    ast_node_path,
                    suggested_safe_query,
                    ..
                } = &decision
                {
                    crate::tcp::postgres::log_block(
                        &sql,
                        proto.dialect(),
                        rule_code,
                        ast_node_path,
                    );
                    let block = proto.build_block_response(&BlockContext {
                        rule_code,
                        ast_node_path,
                        suggested_safe_query: suggested_safe_query.as_deref(),
                        message: None,
                        kind,
                        client_seq: message_seq(&msg),
                        tx: tx_state.as_deref(),
                    });
                    if local_block(
                        proto,
                        &msg,
                        &mut upstream,
                        client_write,
                        pg_responses.as_ref(),
                        block,
                    )
                    .await?
                    {
                        skip_until_sync = true;
                    }
                    continue; // query NOT forwarded upstream
                }

                // Not blocked: a MySQL `USE` in it moves the session's current
                // database for the next statements, as COM_INIT_DB does.
                if proto.dialect() == vericto_engine::Dialect::Mysql && kind == QueryKind::Simple {
                    match crate::tcp::protocol::mysql::sql_use_target(&sql) {
                        Some(UseTarget::Database(db)) => {
                            access.set_database(CurrentDatabase::Named(db))
                        }
                        Some(UseTarget::Unknown) => access.set_database(CurrentDatabase::Unknown),
                        None => {}
                    }
                }

                // Masked, or bounded by a `rewrite_limit` policy (4.17.0) →
                // forward the rewritten SQL in the same message (same statement
                // name and parameter types on a Parse). Never the original: if
                // this protocol cannot carry the rewrite, block.
                if let TcpDecision::Forward {
                    rewritten_query: Some(rewritten),
                    violations,
                    sensitive_columns,
                    access_denied,
                    ..
                } = &decision
                {
                    if let Some(rewritten_msg) = proto.with_query(&msg, rewritten) {
                        let masked = sensitive_columns
                            .iter()
                            .any(|c| c.policy == vericto_engine::SensitivePolicy::Mask);
                        tracing::info!(
                            query_preview = %crate::tcp::postgres::log_preview(&sql, proto.dialect()),
                            "{}",
                            if masked {
                                "Query MASKED at TCP proxy; forwarding the rewritten SQL"
                            } else {
                                "Query BOUNDED (LIMIT) at TCP proxy; forwarding the rewritten SQL"
                            }
                        );
                        let action = stage_parse_action(
                            pg_responses.as_ref(),
                            &msg,
                            &sql,
                            rewritten,
                            snapshot.clone(),
                        )?;
                        forward_client_message(
                            &mut upstream,
                            &rewritten_msg,
                            pg_responses.as_ref(),
                            action,
                        )
                        .await?;
                        continue;
                    }
                    // Rare: `evaluate` already refuses a rewrite for a dialect
                    // without one, and a Postgres query message always carries it.
                    // A MySQL packet cannot when the rewrite would not fit one
                    // packet, or a COM_QUERY's attributes prefix binds values the
                    // proxy cannot frame. The telemetry event above then says
                    // FLAGGED; the block still wins.
                    let TcpDecision::Block {
                        rule_code,
                        ast_node_path,
                        ..
                    } = rewrite_not_enforceable(
                        "this wire protocol cannot carry the rewritten query",
                        Some(rewritten),
                        violations.clone(),
                        sensitive_columns.clone(),
                        access_denied.clone(),
                    )
                    else {
                        unreachable!("rewrite_not_enforceable always blocks")
                    };
                    tracing::error!(ast_node_path, "blocking a rewritten query");
                    crate::tcp::postgres::log_block(
                        &sql,
                        proto.dialect(),
                        &rule_code,
                        &ast_node_path,
                    );
                    let block = proto.build_block_response(&BlockContext {
                        rule_code: &rule_code,
                        ast_node_path: &ast_node_path,
                        suggested_safe_query: None,
                        message: None,
                        kind,
                        client_seq: message_seq(&msg),
                        tx: tx_state.as_deref(),
                    });
                    if local_block(
                        proto,
                        &msg,
                        &mut upstream,
                        client_write,
                        pg_responses.as_ref(),
                        block,
                    )
                    .await?
                    {
                        skip_until_sync = true;
                    }
                    continue;
                }

                // Allowed / flagged / monitored → forward unchanged.
                let action = stage_parse_action(pg_responses.as_ref(), &msg, &sql, &sql, snapshot)?;
                forward_client_message(&mut upstream, &msg, pg_responses.as_ref(), action).await?;
            }
        }
    }
    // A Terminate (or what preceded the client's close) is not held back.
    upstream.flush().await
}

/// Handles one MySQL client connection end to end.
///
/// MySQL is server-first: the real server sends the Initial Handshake, the
/// client replies with auth, then the command phase begins. The proxy connects
/// upstream first (no client-side startup negotiation, unlike Postgres), then
/// the server→client relay carries the handshake and the interception loop
/// passes auth packets through (gated by `is_command_phase_start`) before
/// intercepting queries. TLS, when configured, covers both hops (see the TLS
/// coherence note in `run_mysql_session`); the upstream hop verifies against
/// `UPSTREAM_SSLROOTCERT` and presents `UPSTREAM_SSLCERT`, as on Postgres.
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
    // Recorded for the heartbeat (4.20.0) and logged at debug once per upstream.
    if let Some(version) = mc::read_server_version(&handshake.payload) {
        crate::tcp::upstream_version::global().observe_mysql(
            &format!("{}:{}", config.upstream_host, config.upstream_port),
            version,
        );
    }
    let server_caps = mc::read_server_capabilities(&handshake.payload).unwrap_or(0);
    if upstream_tls && server_caps & mc::CLIENT_SSL == 0 {
        return Err(std::io::Error::other(
            "UPSTREAM_MYSQL TLS requested but the server does not advertise CLIENT_SSL",
        ));
    }

    // The greeting the client sees offers only what this proxy can carry.
    // - Compression, never: after the OK both ends would switch to compressed
    //   framing, which the command loop does not decode. A client that asked for
    //   it hung on its first command, with nothing evaluated.
    // - CLIENT_SSL, only when the proxy terminates client TLS. Without that, a
    //   client in the default `ssl-mode=PREFERRED` answered with an SSL Request
    //   and a TLS handshake the proxy cannot complete, and failed to connect
    //   ("SSL connection error: wrong version number") instead of falling back to
    //   plaintext, as it does against a server without TLS.
    let not_carried = mc::COMPRESSION_CAPABILITIES
        | if client_tls_enabled {
            0
        } else {
            mc::CLIENT_SSL
        };
    let greeting = mc::MySqlPacket {
        seq: handshake.seq,
        payload: mc::clear_server_capabilities(&handshake.payload, not_carried),
    };

    // 2. Client TLS is negotiated on the whole stream BEFORE splitting: send the
    //    handshake, read the client's SSL Request, terminate TLS, then split the
    //    resulting TLS stream. Without client TLS we split immediately.
    let (mut client_read, mut client_write_direct): (ClientRead, ClientWrite) =
        if client_tls_enabled {
            use tokio::io::AsyncWriteExt as _;
            let mut client = client;
            // Forward the handshake to the client over plaintext.
            client.write_all(&greeting.encode()).await?;
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
                // Answered the way MySQL answers under require_secure_transport,
                // so the client reports why instead of "Lost connection".
                let err = mc::build_err_packet(
                    ssl_req.seq.wrapping_add(1),
                    mc::ER_SECURE_TRANSPORT_REQUIRED,
                    "HY000",
                    "Connections using insecure transport are prohibited: this proxy \
                     requires TLS (PROXY_TLS_MODE=require). Connect with --ssl-mode=REQUIRED.",
                );
                client.write_all(&err).await?;
                client.flush().await?;
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
            cw.write_all(&greeting.encode()).await?;
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
    // agent-access allowlists. The database it names is the session's first
    // current database, which wins over the policy's `default_schema`.
    let mut session = SessionStart {
        user: mc::read_handshake_username(&client_resp.payload),
        database: CurrentDatabase::from_wire(mc::read_handshake_database(&client_resp.payload)),
        client_caps: mc::read_client_capabilities(&client_resp.payload).unwrap_or(0),
        declared: Default::default(),
        // Policy rules on (4.15.0): the relay follows the server status flags.
        tx_state: config
            .policy_rules
            .mode
            .is_on()
            .then(|| Arc::new(crate::tcp::tx_state::ServerTxState::new())),
        pg_responses: None,
    };
    // Policy rules on (4.15.0): `program_name` and the `vericto.*` connect
    // attributes are read; the `vericto.*` ones are taken out of the response.
    // One the proxy cannot accept refuses the connection. Off: untouched.
    let client_resp = if config.policy_rules.mode.is_on() {
        match mysql_handshake_context(&client_resp.payload) {
            Ok((payload, declared)) => {
                session.declared = declared;
                mc::MySqlPacket {
                    seq: client_resp.seq,
                    payload: payload.unwrap_or(client_resp.payload),
                }
            }
            Err(message) => {
                let err = mc::build_err_packet(
                    client_resp.seq.wrapping_add(1),
                    mc::VERICTO_BLOCK_ERR_CODE,
                    "42000",
                    &message,
                );
                client_write_direct.write_all(&err).await?;
                client_write_direct.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "MySQL connect attribute vericto.* refused",
                ));
            }
        }
    } else {
        client_resp
    };
    // The server enables compression only if the response asks for it. A client
    // that ignored the greeting and asked anyway does not get it either: its
    // compressed commands then fail at the server instead of passing the proxy
    // unread.
    let client_resp = mc::MySqlPacket {
        seq: client_resp.seq,
        payload: mc::clear_client_capabilities(&client_resp.payload, mc::COMPRESSION_CAPABILITIES),
    };

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
            config.upstream_ca_path.as_deref(),
            config.upstream_client_cert.as_deref(),
            config.upstream_client_key.as_deref(),
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
            AuthPhase::Ok => {
                // The status flags the session starts with (autocommit, …).
                if let (Some(tx), Some(flags)) = (
                    session.tx_state.as_deref(),
                    crate::tcp::tx_state::ok_status(&srv_pkt.payload),
                ) {
                    tx.set_mysql_flags(flags);
                }
                break; // authenticated → command phase
            }
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
    let relay_tracker = session.tx_state.clone().map(|state| {
        (
            crate::tcp::tx_state::MySqlTxTracker::new(session.client_caps),
            state,
        )
    });
    let relay_handle = tokio::spawn(relay_upstream_to_client(
        server_read,
        client_write.clone(),
        relay_tracker,
    ));

    let result = intercept_client_to_server(
        &proto,
        &mut client_read,
        &mut server_write,
        &client_write,
        &config,
        session,
    )
    .await;

    relay_handle.abort();
    result
}

/// MySQL, policy rules on: what a HandshakeResponse declares in its connect
/// attributes (`program_name`, `vericto.ticket`, `vericto.tenant`), and the
/// response without the `vericto.*` ones (`None`: forward it unchanged). `Err`
/// with the client message for a `vericto.*` attribute the proxy cannot accept.
pub(crate) fn mysql_handshake_context(
    payload: &[u8],
) -> Result<(Option<Vec<u8>>, crate::tcp::policy_rules::SessionDeclared), String> {
    use crate::tcp::policy_rules::{
        MAX_APPLICATION_NAME_CHARS, SESSION_CONTEXT_RULE_CODE, SessionDeclared,
    };
    let mut declared = SessionDeclared::default();
    let Some((_, attrs)) = crate::tcp::codec_mysql::read_connect_attrs(payload) else {
        return Ok((None, declared));
    };
    let is_context = |k: &str| k.to_ascii_lowercase().starts_with("vericto.");
    for (key, value) in &attrs {
        if key == "program_name" {
            declared.application_name =
                Some(value.chars().take(MAX_APPLICATION_NAME_CHARS).collect());
        } else if is_context(key) {
            declared.set_from_startup(key, value).map_err(|reason| {
                crate::tcp::protocol::mysql::block_message(
                    SESSION_CONTEXT_RULE_CODE,
                    &format!("{reason} (connect attribute {key})"),
                    None,
                )
            })?;
        }
    }
    let stripped = attrs
        .iter()
        .any(|(k, _)| is_context(k))
        .then(|| crate::tcp::codec_mysql::without_connect_attrs(payload, is_context))
        .flatten();
    Ok((stripped, declared))
}

/// Relays bytes from the upstream to the client without intercepting. Generic
/// over any boxed upstream read half (shared by the MySQL session).
pub(crate) async fn relay_upstream_to_client(
    mut server_read: crate::tcp::upstream::UpstreamRead,
    client_write: Arc<Mutex<ClientWrite>>,
    // Policy rules on: follows the server status flags (see `tx_state`).
    mut tracker: Option<(
        crate::tcp::tx_state::MySqlTxTracker,
        Arc<crate::tcp::tx_state::ServerTxState>,
    )>,
) {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match server_read.read(&mut buf).await {
            Ok(0) => break, // upstream closed
            Ok(n) => {
                if let Some((t, state)) = tracker.as_mut() {
                    t.feed(&buf[..n], state);
                }
                let mut writer = client_write.lock().await;
                if writer.write_all(&buf[..n]).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// What a kill-switch refusal of a message without readable SQL is reported as.
fn kill_switch_label(msg: &RawClientMessage) -> String {
    match msg {
        RawClientMessage::Postgres(m) => match m.tag {
            b'B' => "Bind (prepared statement)".to_string(),
            b'E' => "Execute (prepared statement)".to_string(),
            b'F' => "FunctionCall".to_string(),
            b'Q' => "Query (unreadable SQL)".to_string(),
            b'P' => "Parse (unreadable SQL)".to_string(),
            t => format!("protocol message {:?}", t as char),
        },
        RawClientMessage::Mysql(p) => match p.command_tag() {
            Some(0x17) => "COM_STMT_EXECUTE (prepared statement)".to_string(),
            Some(0x1c) => "COM_STMT_FETCH (prepared statement)".to_string(),
            Some(0x02) => "COM_INIT_DB".to_string(),
            Some(0x04) => "COM_FIELD_LIST".to_string(),
            Some(0x11) => "COM_CHANGE_USER".to_string(),
            Some(t) => format!("command 0x{t:02x}"),
            None => "empty command".to_string(),
        },
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

async fn local_block(
    _proto: &dyn WireProtocol,
    original: &RawClientMessage,
    upstream: &mut UpstreamSender<'_>,
    client_write: &Arc<Mutex<ClientWrite>>,
    pg: Option<&crate::tcp::pg_response::PgResponseCoordinator>,
    block: crate::tcp::protocol::BlockResponse,
) -> std::io::Result<bool> {
    if let Some(pg) = pg {
        if matches!(original, RawClientMessage::Postgres(message) if message.tag == b'F') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "blocked PostgreSQL FunctionCall closes the session because no side-effect-free ordered response fence exists",
            ));
        }
        let replacement = if block.skip_until_sync {
            block.bytes
        } else {
            postgres_before_ready(block.bytes)?
        };
        if block.skip_until_sync {
            let full = pg.register_now(
                crate::tcp::pg_response::PlanKind::Parse,
                Some(replacement),
                false,
                None,
            )?;
            queue_plan(upstream, pg, full).await?;
            upstream
                .send_pg(&crate::tcp::pg_response::invalid_parse())
                .await?;
        } else {
            let full = pg.register_now(
                crate::tcp::pg_response::PlanKind::Simple,
                Some(replacement),
                false,
                Some(crate::tcp::pg_response::PreparedAction::SimpleQuery),
            )?;
            queue_plan(upstream, pg, full).await?;
            upstream.send_pg(&postgres_marker_query()).await?;
        }
        return Ok(false);
    }
    let _ = original;
    send_to_client(client_write, &block.bytes).await?;
    Ok(block.skip_until_sync)
}

/// A consumed simple SET is ordered by a harmless upstream cycle. If an
/// earlier pipelined statement put the transaction into failed state, the
/// marker's native 25P02 is preserved and the synthetic CommandComplete is not
/// emitted.
async fn local_set_ok(
    proto: &dyn WireProtocol,
    msg: &RawClientMessage,
    upstream: &mut UpstreamSender<'_>,
    client_write: &Arc<Mutex<ClientWrite>>,
    pg: Option<&crate::tcp::pg_response::PgResponseCoordinator>,
    tx: &crate::tcp::tx_state::ServerTxState,
) -> std::io::Result<bool> {
    let bytes = proto.build_set_ok(message_seq(msg), tx);
    if let Some(pg) = pg {
        let (full, completion) = pg.register_simple_with_completion_now(
            postgres_before_ready(bytes)?,
            true,
            Some(crate::tcp::pg_response::PreparedAction::SimpleQuery),
        )?;
        queue_plan(upstream, pg, full).await?;
        upstream.send_pg(&postgres_marker_query()).await?;
        // The marker's response is awaited: it must reach the server first.
        upstream.flush().await?;
        completion.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "PostgreSQL SET response plan was abandoned",
            )
        })
    } else {
        send_to_client(client_write, &bytes).await?;
        Ok(true)
    }
}

async fn local_failed_transaction(
    msg: &RawClientMessage,
    upstream: &mut UpstreamSender<'_>,
    client_write: &Arc<Mutex<ClientWrite>>,
    pg: Option<&crate::tcp::pg_response::PgResponseCoordinator>,
    reply: crate::tcp::protocol::BlockResponse,
) -> std::io::Result<bool> {
    if let Some(pg) = pg {
        if reply.skip_until_sync {
            // PostgreSQL itself supplies 25P02 and enters native extended
            // skip-until-Sync state; no local replacement is needed.
            let full =
                pg.register_now(crate::tcp::pg_response::PlanKind::Parse, None, false, None)?;
            queue_plan(upstream, pg, full).await?;
            upstream
                .send_pg(&crate::tcp::pg_response::invalid_parse())
                .await?;
        } else {
            let full = pg.register_now(
                crate::tcp::pg_response::PlanKind::Simple,
                Some(Vec::new()),
                true,
                Some(crate::tcp::pg_response::PreparedAction::SimpleQuery),
            )?;
            queue_plan(upstream, pg, full).await?;
            upstream.send_pg(&postgres_marker_query()).await?;
        }
        Ok(false)
    } else {
        send_to_client(client_write, &reply.bytes).await?;
        let _ = msg;
        Ok(reply.skip_until_sync)
    }
}

/// Queues a plan the response queue had no room for. The frontend messages
/// held for the database go out first: the relay frees room only as their
/// responses arrive.
async fn queue_plan(
    upstream: &mut UpstreamSender<'_>,
    pg: &crate::tcp::pg_response::PgResponseCoordinator,
    full: Option<crate::tcp::pg_response::PendingPlan>,
) -> std::io::Result<()> {
    if let Some(plan) = full {
        upstream.flush().await?;
        pg.register_when_room(plan).await?;
    }
    Ok(())
}

fn postgres_marker_query() -> PgMessage {
    PgMessage {
        tag: b'Q',
        body: b"SELECT 1 /* vericto ordered response marker */\0".to_vec(),
    }
}

fn postgres_before_ready(mut bytes: Vec<u8>) -> std::io::Result<Vec<u8>> {
    const READY_LEN: usize = 6;
    if bytes.len() < READY_LEN
        || bytes[bytes.len() - READY_LEN..bytes.len() - 1] != [b'Z', 0, 0, 0, 5]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PostgreSQL simple synthetic response lacks ReadyForQuery",
        ));
    }
    bytes.truncate(bytes.len() - READY_LEN);
    Ok(bytes)
}

async fn send_to_client(
    client_write: &Arc<Mutex<ClientWrite>>,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut writer = client_write.lock().await;
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn refresh_prepared(
    pg: &crate::tcp::pg_response::PgResponseCoordinator,
    message: &PgMessage,
    current: crate::tcp::pg_response::EvalSnapshot,
    mode: crate::tcp::policy_rules::PolicyRulesMode,
    config: &Arc<PgProxyConfig>,
    identity: impl FnOnce() -> EventIdentity,
) -> std::io::Result<Option<TcpDecision>> {
    enum Target {
        Statement(Vec<u8>, crate::tcp::pg_response::PreparedStatement),
        Portal(Vec<u8>, crate::tcp::pg_response::PreparedStatement),
    }
    // An Execute is evaluated again when a business policy in force may read
    // the time of execution; otherwise only a changed snapshot (rules,
    // effective access policy, bundle, session context) is.
    let time_dependent_execution = message.tag == b'E'
        && current
            .bundle
            .as_ref()
            .is_some_and(|bundle| bundle.reads_time);
    let target = {
        let state = pg
            .prepared()
            .lock()
            .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?;
        let stale = |prepared: &crate::tcp::pg_response::PreparedStatement| {
            time_dependent_execution || !prepared.snapshot.same_as(&current)
        };
        match message.tag {
            b'B' => crate::tcp::pg_response::bind_names(message).and_then(|(_, statement)| {
                state
                    .statement_ref(statement)
                    .filter(|prepared| stale(prepared))
                    .map(|prepared| Target::Statement(statement.to_vec(), prepared.clone()))
            }),
            b'E' => crate::tcp::pg_response::execute_portal(message).and_then(|portal| {
                state
                    .statement_for_portal_ref(portal)
                    .filter(|prepared| stale(prepared))
                    .map(|prepared| Target::Portal(portal.to_vec(), prepared.clone()))
            }),
            _ => None,
        }
    };
    let Some(target) = target else {
        return Ok(None);
    };
    let prepared = match &target {
        Target::Statement(_, prepared) | Target::Portal(_, prepared) => prepared.clone(),
    };
    let identity = identity();

    let original = prepared.original_sql.clone();
    let evaluated_sql = original.clone();
    let config_for_task = Arc::clone(config);
    let snapshot = current.clone();
    let decision = run_evaluation(config.inline_eval_max_bytes, original.len(), move || {
        let start = Instant::now();
        let decision = match (&snapshot.bundle, &snapshot.context) {
            (Some(bundle), Some(ctx)) => {
                let ctx = crate::tcp::policy_rules::at_now(ctx);
                evaluate_message_with(
                    &evaluated_sql,
                    vericto_engine::Dialect::Postgres,
                    QueryKind::Prepared,
                    &snapshot.rules,
                    &snapshot.policy,
                    Some(&PolicyEval {
                        mode,
                        policies: &bundle.policies,
                        ctx: &ctx,
                    }),
                )
            }
            _ => evaluate_message(
                &evaluated_sql,
                vericto_engine::Dialect::Postgres,
                QueryKind::Prepared,
                &snapshot.rules,
                &snapshot.policy,
            ),
        };
        let desired = match &decision {
            TcpDecision::Forward {
                rewritten_query: Some(sql),
                ..
            } => sql.as_str(),
            TcpDecision::Forward { .. } => evaluated_sql.as_ref(),
            TcpDecision::Block { .. } => "",
        };
        let decision = if matches!(decision, TcpDecision::Forward { .. })
            && desired != prepared.upstream_sql.as_ref()
        {
            TcpDecision::Block {
                rule_code: "VERICTO-PREPARED-STALE".to_string(),
                ast_node_path: "PreparedStatement > required SQL rewrite changed; close and re-prepare the statement"
                    .to_string(),
                suggested_safe_query: None,
                severity: vericto_engine::Severity::High,
                violations: Vec::new(),
                sensitive_columns: Vec::new(),
                access_denied: Vec::new(),
            }
        } else {
            decision
        };
        crate::tcp::postgres::report_telemetry(
            &config_for_task,
            &evaluated_sql,
            vericto_engine::Dialect::Postgres,
            &decision,
            start.elapsed().as_micros(),
            &identity,
        );
        decision
    })
    .await
    .map_err(|e| std::io::Error::other(format!("prepared evaluation task failed: {e}")))?;

    if matches!(decision, TcpDecision::Forward { .. }) {
        let mut state = pg
            .prepared()
            .lock()
            .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?;
        match target {
            Target::Statement(name, _) => state.update_snapshot(&name, current),
            Target::Portal(portal, _) => state.update_portal_snapshot(&portal, current),
        }
        Ok(None)
    } else {
        Ok(Some(decision))
    }
}

/// Runs an evaluation (`work`) of a statement of `sql_len` bytes: on the calling
/// task when the statement is at most `inline_eval_max_bytes`
/// (`PgProxyConfig::inline_eval_max_bytes`), on the blocking pool otherwise
/// (always with `VERICTO_INLINE_EVAL_MAX_BYTES=0`, the behaviour up to 4.18.0).
/// `Err` only when the pool's task panicked.
pub(crate) async fn run_evaluation<T, F>(
    inline_eval_max_bytes: usize,
    sql_len: usize,
    work: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if evaluates_inline(inline_eval_max_bytes, sql_len) {
        Ok(work())
    } else {
        tokio::task::spawn_blocking(work).await
    }
}

/// Whether a statement of `sql_len` bytes is evaluated on the session's own task.
fn evaluates_inline(inline_eval_max_bytes: usize, sql_len: usize) -> bool {
    sql_len <= inline_eval_max_bytes && inline_eval_max_bytes > 0
}

fn stage_parse_action(
    pg: Option<&crate::tcp::pg_response::PgResponseCoordinator>,
    msg: &RawClientMessage,
    original_sql: &str,
    upstream_sql: &str,
    snapshot: Option<crate::tcp::pg_response::EvalSnapshot>,
) -> std::io::Result<Option<crate::tcp::pg_response::PreparedAction>> {
    let (Some(pg), RawClientMessage::Postgres(message), Some(snapshot)) = (pg, msg, snapshot)
    else {
        return Ok(None);
    };
    if message.tag != b'P' {
        return Ok(None);
    }
    let name = crate::tcp::pg_response::parse_name(message).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed PostgreSQL Parse message",
        )
    })?;
    let mut state = pg
        .prepared()
        .lock()
        .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?;
    // The SQL is shared with the statement it replaces when it is the same
    // text (a driver preparing the unnamed statement again for every
    // execution), and between the original and the upstream text when it
    // goes upstream as written: no copy then, and the retained-SQL bound
    // counts it once.
    let previous = state.statement_ref(name);
    let original_sql: Arc<str> = match previous {
        Some(previous) if *previous.original_sql == *original_sql => {
            Arc::clone(&previous.original_sql)
        }
        _ => Arc::from(original_sql),
    };
    let upstream_sql = if upstream_sql == &*original_sql {
        Arc::clone(&original_sql)
    } else {
        match previous {
            Some(previous) if *previous.upstream_sql == *upstream_sql => {
                Arc::clone(&previous.upstream_sql)
            }
            _ => Arc::from(upstream_sql),
        }
    };
    let id = state.stage_parse(
        name,
        crate::tcp::pg_response::PreparedStatement::new(original_sql, upstream_sql, snapshot),
    )?;
    Ok(Some(crate::tcp::pg_response::PreparedAction::CommitParse(
        id,
    )))
}

async fn forward_client_message(
    upstream: &mut UpstreamSender<'_>,
    msg: &RawClientMessage,
    pg: Option<&crate::tcp::pg_response::PgResponseCoordinator>,
    action: Option<crate::tcp::pg_response::PreparedAction>,
) -> std::io::Result<()> {
    if let (Some(pg), RawClientMessage::Postgres(message)) = (pg, msg) {
        let action = if action.is_some() {
            action
        } else {
            match message.tag {
                b'Q' => Some(crate::tcp::pg_response::PreparedAction::SimpleQuery),
                b'B' => {
                    let (portal, statement) = crate::tcp::pg_response::bind_names(message)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "malformed PostgreSQL Bind message",
                            )
                        })?;
                    let id = pg
                        .prepared()
                        .lock()
                        .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?
                        .stage_bind(portal, statement)?;
                    Some(crate::tcp::pg_response::PreparedAction::CommitBind(id))
                }
                b'C' => crate::tcp::pg_response::close_target(message),
                _ => None,
            }
        };
        let full = pg.register_message(message, action)?;
        queue_plan(upstream, pg, full).await?;
    }
    upstream.send(msg).await
}

/// Bytes the frontend holds for the database before it writes them (4.17.3):
/// past this, what is pending goes out, and a message this large goes out on
/// its own.
const COALESCE_LIMIT: usize = 16 * 1024;

/// The frontend's writes to the database.
///
/// On PostgreSQL (4.17.3) the frontend messages framed from one client read
/// are coalesced: each is appended to `pending`, in order, once its response
/// plan is registered, and `pending` is written with one write and one flush
/// when the loop is about to wait: for the client (its buffered bytes hold no
/// further whole message), for room in the response queue, for a response it
/// awaits, or for an evaluation while it holds a message the server answers on
/// its own; and when it reaches [`COALESCE_LIMIT`]. A larger message goes out
/// on its own, after what was pending. Up to 4.17.2 every message was one
/// write and one flush (about 5 sends per extended-protocol transaction).
///
/// Elsewhere (MySQL, or PostgreSQL without the ordered response coordinator)
/// every message is written and flushed as it comes, as before.
pub(crate) struct UpstreamSender<'a> {
    inner: &'a mut crate::tcp::upstream::UpstreamWrite,
    pending: Vec<u8>,
    coalesce: bool,
    /// `pending` holds a message the server answers without waiting for more:
    /// Sync, Flush, a simple Query, a FunctionCall, CopyDone or CopyFail.
    answerable: bool,
}

impl<'a> UpstreamSender<'a> {
    pub(crate) fn new(inner: &'a mut crate::tcp::upstream::UpstreamWrite, coalesce: bool) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            coalesce,
            answerable: false,
        }
    }

    /// Sends (or, coalescing, queues) one frontend message.
    pub(crate) async fn send(&mut self, msg: &RawClientMessage) -> std::io::Result<()> {
        match msg {
            RawClientMessage::Postgres(message) if self.coalesce => self.send_pg(message).await,
            // One write and one flush per message, from the sender's own buffer
            // (4.19.0: no allocation per message). Nothing is pending here: a
            // sender that does not coalesce never holds bytes.
            _ => {
                msg.encode_into(&mut self.pending);
                let written = self.inner.write_all(&self.pending).await;
                self.pending.clear();
                if self.pending.capacity() > 2 * COALESCE_LIMIT {
                    self.pending = Vec::new();
                }
                written?;
                self.inner.flush().await
            }
        }
    }

    /// [`Self::send`] for a PostgreSQL message.
    pub(crate) async fn send_pg(&mut self, message: &PgMessage) -> std::io::Result<()> {
        if !self.coalesce {
            self.inner.write_all(&message.encode()).await?;
            return self.inner.flush().await;
        }
        let size = message.encoded_len();
        if self.pending.len() + size > COALESCE_LIMIT {
            self.flush().await?;
        }
        if size > COALESCE_LIMIT {
            // Large (COPY data, a big Bind): straight from its buffer.
            let len = (message.body.len() + 4) as i32;
            let mut header = [0u8; 5];
            header[0] = message.tag;
            header[1..].copy_from_slice(&len.to_be_bytes());
            self.inner.write_all(&header).await?;
            self.inner.write_all(&message.body).await?;
            return self.inner.flush().await;
        }
        message.encode_into(&mut self.pending);
        self.answerable |= matches!(message.tag, b'S' | b'H' | b'Q' | b'F' | b'c' | b'f');
        Ok(())
    }

    /// Writes what is pending, with one write and one flush.
    pub(crate) async fn flush(&mut self) -> std::io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let written = self.inner.write_all(&self.pending).await;
        self.pending.clear();
        self.answerable = false;
        if self.pending.capacity() > 2 * COALESCE_LIMIT {
            self.pending = Vec::new();
        }
        written?;
        self.inner.flush().await
    }

    /// [`Self::flush`] when what is pending could already be answered.
    pub(crate) async fn flush_answerable(&mut self) -> std::io::Result<()> {
        if self.answerable {
            self.flush().await
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> &[u8] {
        &self.pending
    }
}
