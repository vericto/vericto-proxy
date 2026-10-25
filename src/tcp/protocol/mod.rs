// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Wire-protocol strategy for the multi-dialect TCP proxy.
//!
//! The proxy is a *server* of a database wire protocol. The protocol is fixed by
//! whatever the connecting client speaks — it is chosen per deployment (Option
//! A), one protocol per proxy instance, derived from the fronted database's
//! dialect. This trait abstracts the three protocol-specific concerns; the rest
//! of the session (connect upstream, relay server→client, the interception
//! loop, evaluation, telemetry, enforcement) is generic and lives in
//! `session.rs`.
//!
//! Design note (why the trait is shaped this way): making the trait own the
//! socket types would force object-safety gymnastics over `Box<dyn AsyncRead>`.
//! Instead the generic session owns the streams and calls small, mostly-pure
//! trait methods:
//!   - `dialect()`            → which engine parser to use
//!   - `read_client_message`  → frame one client message (protocol-specific I/O)
//!   - `classify`             → is it SQL? forward-as-is? terminate?
//!   - `build_block_response` → native rejection bytes + protocol resume state
//!
//! Startup negotiation differs enough per protocol (Postgres: client speaks
//! first with SSLRequest/StartupMessage; MySQL: server speaks first) that it is
//! handled by protocol-specific session entrypoints rather than a single trait
//! method — see `session.rs` and each `protocol/*.rs`.

use vericto_engine::parser::Dialect;

pub mod mysql;
pub mod postgres;

/// A framed client message, opaque to the generic session. Each protocol
/// carries whatever it needs to re-encode the message for forwarding.
pub enum RawClientMessage {
    /// PostgreSQL message (tag + body).
    Postgres(crate::tcp::codec::PgMessage),
    /// MySQL packet (seq + payload).
    Mysql(crate::tcp::codec_mysql::MySqlPacket),
}

impl RawClientMessage {
    /// The complete on-wire bytes to forward upstream unchanged.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RawClientMessage::Postgres(m) => m.encode(),
            RawClientMessage::Mysql(m) => m.encode(),
        }
    }
}

/// How a query arrived — needed to build the correct block response and resume
/// the protocol state afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    /// Simple/immediate query (pg 'Q', mysql COM_QUERY).
    Simple,
    /// Prepared/parse phase (pg 'P', mysql COM_STMT_PREPARE).
    Prepared,
}

/// Classification of a client message by the active protocol.
pub enum Classified {
    /// Carries SQL to evaluate.
    Query { sql: String, kind: QueryKind },
    /// Not a query — forward the raw bytes upstream unchanged.
    PassThrough,
    /// Client terminated the session (pg 'X', mysql COM_QUIT).
    Terminate,
}

/// What an agent-access allowlist (VERICTO-087) makes of a client message that
/// carries no SQL the engine evaluates. Consulted only for messages classified
/// [`Classified::PassThrough`].
pub enum AccessControl {
    /// Statement plumbing (bind/execute/close/sync, ping, copy data, auth
    /// continuation…): forwarded under any policy.
    Allowed,
    /// A command the statement analysis cannot see into and that reaches
    /// identity, name resolution or data (MySQL COM_FIELD_LIST;
    /// Postgres FunctionCall; a query message whose SQL cannot be read; any
    /// command not known to be plumbing). Refused under a policy, like the SQL
    /// it stands for (`SHOW COLUMNS`, `set_config(…)`); deny by default.
    Restricted { label: String, kind: QueryKind },
    /// MySQL COM_CHANGE_USER: the session re-authenticates as `user` (None when
    /// it cannot be read). Refused when the current or the target user has a
    /// policy; otherwise the session becomes that user.
    ChangeUser { user: Option<String> },
    /// MySQL COM_INIT_DB, the protocol form of `USE <db>`: refused under a
    /// policy as `USE` is (labelled `COM_INIT_DB`); when it is forwarded, the
    /// session's current database becomes `database` (None when the name
    /// cannot be read), which unqualified names resolve to from then on.
    ChangeDatabase { database: Option<String> },
}

/// Context for building a native block response.
pub struct BlockContext<'a> {
    pub rule_code: &'a str,
    pub ast_node_path: &'a str,
    pub suggested_safe_query: Option<&'a str>,
    /// The client's error text in full, in place of the wording built from the
    /// rule, path and suggestion: the kill switch's message (VERICTO-105), which
    /// the control plane writes and every path returns verbatim.
    pub message: Option<&'a str>,
    pub kind: QueryKind,
    /// Sequence id of the blocked message (MySQL needs command_seq + 1 for the
    /// reply; Postgres ignores this).
    pub client_seq: u8,
    /// The transaction state the server last reported: the Postgres reply's
    /// ReadyForQuery carries it. Always `Some` on Postgres since 4.16.1 (up to
    /// 4.16.0 only with policy rules on; off, ReadyForQuery said idle). MySQL:
    /// `Some` with policy rules on; its refusal (an ERR_Packet) carries no
    /// status either way. `None`: ReadyForQuery says idle.
    pub tx: Option<&'a crate::tcp::tx_state::ServerTxState>,
}

/// Bytes to send to the client to reject a query, plus whether the protocol
/// must now swallow follow-up messages until an end-of-sequence marker (the
/// Postgres extended-protocol skip-until-Sync case). MySQL leaves this false.
pub struct BlockResponse {
    pub bytes: Vec<u8>,
    pub skip_until_sync: bool,
}

/// A database wire protocol the proxy can speak. One implementation per engine
/// (postgres, mysql, …), selected at deploy time behind `Arc<dyn WireProtocol>`.
#[async_trait::async_trait]
pub trait WireProtocol: Send + Sync {
    /// Which engine dialect to evaluate queries with under this protocol.
    fn dialect(&self) -> Dialect;

    /// Human-readable name for logs/telemetry ("postgres" | "mysql").
    /// Used by the protocol-selecting startup path (Phase 1 MySQL wiring).
    #[allow(dead_code)]
    fn name(&self) -> &'static str;

    /// Reads and frames the next client message. Returns None on clean EOF.
    /// This is the only protocol-specific *read* in the interception loop.
    async fn read_client_message(
        &self,
        client_read: &mut crate::tcp::client_tls::ClientReader<'_>,
    ) -> std::io::Result<Option<RawClientMessage>>;

    /// [`Self::read_client_message`] into `slot`, which a protocol may reuse
    /// (PostgreSQL keeps the message buffer from one message to the next).
    /// `false` on clean EOF.
    async fn read_client_message_into(
        &self,
        client_read: &mut crate::tcp::client_tls::ClientReader<'_>,
        slot: &mut RawClientMessage,
    ) -> std::io::Result<bool> {
        match self.read_client_message(client_read).await? {
            Some(message) => {
                *slot = message;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// The bytes the interception loop reads the client through before they
    /// are framed (4.17.3): PostgreSQL buffers, so the messages of one client
    /// read go upstream in one write; 0 reads the socket directly (MySQL).
    /// Only used with PostgreSQL's ordered response coordinator.
    fn client_read_buffer(&self) -> usize {
        0
    }

    /// Whether `buffered` (the client bytes read but not yet framed) holds a
    /// whole message, so the next read needs no I/O. While it does, frontend
    /// messages are coalesced upstream; when it does not, the loop sends what
    /// it holds before it waits for the client.
    fn has_buffered_message(&self, _buffered: &[u8]) -> bool {
        false
    }

    /// Classifies a framed message: query (with SQL), pass-through, or terminate.
    fn classify(&self, msg: &RawClientMessage) -> Classified;

    /// Whether the interception loop should classify messages from the very
    /// first one. Postgres: true (startup/auth is negotiated before this loop).
    /// MySQL: false — the client→server side must pass auth packets through
    /// untouched until the command phase begins (auth packets are NOT commands
    /// and could otherwise be misread as SQL). Default: true.
    fn intercepts_from_start(&self) -> bool {
        true
    }

    /// In `intercepts_from_start() == false` protocols, returns true when this
    /// message marks the start of the command phase (MySQL: a client packet with
    /// sequence id 0 — every command restarts the sequence at 0, while auth
    /// packets never do). Unused when interception starts immediately.
    fn is_command_phase_start(&self, _msg: &RawClientMessage) -> bool {
        true
    }

    /// Builds the native rejection response for a blocked query.
    fn build_block_response(&self, ctx: &BlockContext) -> BlockResponse;

    /// What the server answers to a successful `SET` sent as a simple query:
    /// the proxy's reply to a `SET vericto.*` it consumed (policy rules on),
    /// carrying the transaction state the server last reported (`tx`).
    /// `client_seq` as in [`BlockContext`].
    fn build_set_ok(&self, client_seq: u8, tx: &crate::tcp::tx_state::ServerTxState) -> Vec<u8>;

    /// What the server answers to a statement sent while the session is in a
    /// failed transaction block, when this protocol has one (Postgres `E`:
    /// 25P02, and the extended sequence is skipped until Sync). `None` when the
    /// session is not in one, or the protocol has no such state (MySQL: an
    /// error never leaves the transaction unusable). Policy rules on only.
    fn build_in_failed_transaction(
        &self,
        _kind: QueryKind,
        _tx: &crate::tcp::tx_state::ServerTxState,
    ) -> Option<BlockResponse> {
        None
    }

    /// The ReadyForQuery the proxy sends when it ends a skipped extended
    /// sequence at Sync (Postgres only). `tx` as in [`BlockContext`].
    fn build_sync_reply(&self, tx: Option<&crate::tcp::tx_state::ServerTxState>) -> Vec<u8> {
        let status = tx.map_or(crate::tcp::tx_state::PG_IDLE, |t| t.pg_status());
        crate::tcp::codec::build_ready_for_query_with(status)
    }

    /// The same query message carrying `sql` instead (a mask rewrite), with
    /// everything else about it unchanged. `None` when this protocol cannot
    /// carry a rewrite: the session then blocks, because the only other thing it
    /// could forward is the unmasked original. Default: `None`.
    fn with_query(&self, _msg: &RawClientMessage, _sql: &str) -> Option<RawClientMessage> {
        None
    }

    /// Whether an active kill switch (VERICTO-105) refuses this client message,
    /// and with which reply shape: every message that runs a statement or reaches
    /// the server beyond protocol plumbing, read or not, SQL or not. `None`:
    /// forwarded (plumbing that runs nothing by itself, authentication,
    /// Terminate). Default: refuse nothing.
    fn kill_switch_scope(&self, _msg: &RawClientMessage) -> Option<QueryKind> {
        None
    }

    /// What an agent-access allowlist makes of a message that carries no SQL
    /// (see [`AccessControl`]). Default: [`AccessControl::Allowed`].
    fn access_control(&self, _msg: &RawClientMessage) -> AccessControl {
        AccessControl::Allowed
    }
}

// Protocol selection lives in `main.rs` (it picks the listener — run_pg_proxy vs
// run_mysql_proxy — from VERICTO_WIRE_PROTOCOL). The `WireProtocol` impls are
// instantiated directly by each session entrypoint.
