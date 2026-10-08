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

/// Context for building a native block response.
pub struct BlockContext<'a> {
    pub rule_code: &'a str,
    pub ast_node_path: &'a str,
    pub suggested_safe_query: Option<&'a str>,
    pub kind: QueryKind,
    /// Sequence id of the blocked message (MySQL needs command_seq + 1 for the
    /// reply; Postgres ignores this).
    pub client_seq: u8,
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
        client_read: &mut crate::tcp::client_tls::ClientRead,
    ) -> std::io::Result<Option<RawClientMessage>>;

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

    /// The same query message carrying `sql` instead (a mask rewrite), with
    /// everything else about it unchanged. `None` when this protocol cannot
    /// carry a rewrite: the session then blocks, because the only other thing it
    /// could forward is the unmasked original. Default: `None`.
    fn with_query(&self, _msg: &RawClientMessage, _sql: &str) -> Option<RawClientMessage> {
        None
    }
}

// Protocol selection lives in `main.rs` (it picks the listener — run_pg_proxy vs
// run_mysql_proxy — from VERICTO_WIRE_PROTOCOL). The `WireProtocol` impls are
// instantiated directly by each session entrypoint.
