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
    BlockContext, BlockResponse, Classified, QueryKind, RawClientMessage, WireProtocol,
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

    fn build_block_response(&self, ctx: &BlockContext) -> BlockResponse {
        let err = build_error_response(
            SQLSTATE_INSUFFICIENT_PRIVILEGE,
            &block_message(ctx.rule_code, ctx.ast_node_path, ctx.suggested_safe_query),
        );
        match ctx.kind {
            QueryKind::Simple => {
                // Simple protocol: ErrorResponse + ReadyForQuery, no skip.
                let mut bytes = err;
                bytes.extend_from_slice(&build_ready_for_query());
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
