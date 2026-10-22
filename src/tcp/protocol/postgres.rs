// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! PostgreSQL implementation of the `WireProtocol` strategy.
//!
//! Wraps the existing Postgres codec (`crate::tcp::codec`) behind the generic
//! trait WITHOUT changing its behavior — same 'Q'/'P' extraction, same
//! ErrorResponse, same extended-protocol skip-until-Sync. The session loop that
//! used to live in `postgres.rs` now lives generically in `session.rs`; this
//! module supplies only the Postgres-specific framing and block bytes.

use vericto_engine::parser::Dialect;

use crate::tcp::codec::{
    SQLSTATE_INSUFFICIENT_PRIVILEGE, build_error_response, build_ready_for_query,
    extract_parse_query, extract_simple_query, read_message, with_replaced_query,
};
use crate::tcp::protocol::{
    AccessControl, BlockContext, BlockResponse, Classified, QueryKind, RawClientMessage,
    WireProtocol,
};

pub struct PostgresProtocol;

#[async_trait::async_trait]
impl WireProtocol for PostgresProtocol {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn read_client_message(
        &self,
        client_read: &mut crate::tcp::client_tls::ClientRead,
    ) -> std::io::Result<Option<RawClientMessage>> {
        Ok(read_message(client_read)
            .await?
            .map(RawClientMessage::Postgres))
    }

    fn classify(&self, msg: &RawClientMessage) -> Classified {
        let RawClientMessage::Postgres(m) = msg else {
            return Classified::PassThrough;
        };
        match m.tag {
            b'Q' => match extract_simple_query(m) {
                Some(sql) => Classified::Query {
                    sql,
                    kind: QueryKind::Simple,
                },
                None => Classified::PassThrough,
            },
            b'P' => match extract_parse_query(m) {
                Some(sql) => Classified::Query {
                    sql,
                    kind: QueryKind::Prepared,
                },
                None => Classified::PassThrough,
            },
            b'X' => Classified::Terminate,
            _ => Classified::PassThrough,
        }
    }

    fn with_query(&self, msg: &RawClientMessage, sql: &str) -> Option<RawClientMessage> {
        let RawClientMessage::Postgres(m) = msg else {
            return None;
        };
        with_replaced_query(m, sql).map(RawClientMessage::Postgres)
    }

    /// Under an allowlist, only the extended-protocol plumbing of a statement
    /// already evaluated at its Parse, COPY data, authentication messages and
    /// Terminate pass. A FunctionCall (`'F'`) calls a function by OID with no
    /// SQL to analyse, e.g. `set_config('role', …)`, which as SQL the engine
    /// denies; a Query or Parse whose SQL cannot be read is not evaluated; any
    /// other message is unknown. All refused: deny by default.
    fn access_control(&self, msg: &RawClientMessage) -> AccessControl {
        let RawClientMessage::Postgres(m) = msg else {
            return AccessControl::Allowed;
        };
        let (label, kind) = match m.tag {
            // Bind, Execute, Describe, Close, Sync, Flush; CopyData/Done/Fail;
            // PasswordMessage / SASL / GSS responses; Terminate.
            b'B' | b'E' | b'D' | b'C' | b'S' | b'H' | b'd' | b'c' | b'f' | b'p' | b'X' => {
                return AccessControl::Allowed;
            }
            b'F' => ("FunctionCall".to_string(), QueryKind::Simple),
            b'Q' => ("Query (unreadable SQL)".to_string(), QueryKind::Simple),
            b'P' => ("Parse (unreadable SQL)".to_string(), QueryKind::Prepared),
            t => (
                format!("protocol message {:?}", t as char),
                QueryKind::Simple,
            ),
        };
        AccessControl::Restricted { label, kind }
    }

    /// CommandComplete `SET` + ReadyForQuery with the transaction status the
    /// server last reported (`I`, or `T` inside a transaction block).
    fn build_set_ok(&self, _client_seq: u8, tx: &crate::tcp::tx_state::ServerTxState) -> Vec<u8> {
        let mut bytes = crate::tcp::codec::PgMessage {
            tag: b'C',
            body: b"SET\0".to_vec(),
        }
        .encode();
        bytes.extend_from_slice(&crate::tcp::codec::build_ready_for_query_with(
            tx.pg_status(),
        ));
        bytes
    }

    /// In a failed transaction block (`E`) the server rejects every command but
    /// the end of the block with 25P02; the proxy answers the same way for what
    /// it would otherwise answer itself, and keeps the state `E`.
    fn build_in_failed_transaction(
        &self,
        kind: QueryKind,
        tx: &crate::tcp::tx_state::ServerTxState,
    ) -> Option<BlockResponse> {
        let status = tx.pg_status();
        if status != crate::tcp::tx_state::PG_FAILED_TRANSACTION {
            return None;
        }
        let mut bytes = build_error_response(
            crate::tcp::codec::SQLSTATE_IN_FAILED_SQL_TRANSACTION,
            "current transaction is aborted, commands ignored until end of transaction block",
        );
        let skip_until_sync = kind == QueryKind::Prepared;
        if !skip_until_sync {
            bytes.extend_from_slice(&crate::tcp::codec::build_ready_for_query_with(status));
        }
        Some(BlockResponse {
            bytes,
            skip_until_sync,
        })
    }

    fn build_block_response(&self, ctx: &BlockContext) -> BlockResponse {
        let err = build_error_response(
            SQLSTATE_INSUFFICIENT_PRIVILEGE,
            &block_message(ctx.rule_code, ctx.ast_node_path, ctx.suggested_safe_query),
        );
        match ctx.kind {
            QueryKind::Simple => {
                // Simple protocol: ErrorResponse + ReadyForQuery, no skip.
                let mut bytes = err;
                match ctx.tx {
                    Some(tx) => bytes.extend_from_slice(
                        &crate::tcp::codec::build_ready_for_query_with(tx.pg_status()),
                    ),
                    None => bytes.extend_from_slice(&build_ready_for_query()),
                }
                BlockResponse {
                    bytes,
                    skip_until_sync: false,
                }
            }
            QueryKind::Prepared => {
                // Extended protocol: send ErrorResponse now, then swallow the
                // following Bind/Describe/Execute until Sync ('S'), at which
                // point the session sends ReadyForQuery. Preserves prior behavior.
                BlockResponse {
                    bytes: err,
                    skip_until_sync: true,
                }
            }
        }
    }
}

/// Block message shown to the client. Unchanged from the original path.
pub fn block_message(rule_code: &str, ast_node_path: &str, suggestion: Option<&str>) -> String {
    let base = format!("Vericto blocked this query [{rule_code}] — AST node: {ast_node_path}");
    match suggestion {
        Some(s) => format!("{base}. Suggestion: {s}"),
        None => base,
    }
}
