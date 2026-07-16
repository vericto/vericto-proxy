//! MySQL implementation of the `WireProtocol` strategy (Phase 1).
//!
//! Framing lives in `codec_mysql`. This module maps MySQL packets onto the
//! generic session's classification and block-response contract. Auth is not
//! reimplemented — the session relays the upstream handshake and passes auth
//! packets through (classified as PassThrough), so caching_sha2_password /
//! mysql_native_password work untouched.

use vericto_engine::parser::Dialect;

use crate::tcp::codec_mysql::{
    build_err_packet, read_packet, MySqlPacket, COM_QUIT, VERICTO_BLOCK_ERR_CODE,
    VERICTO_BLOCK_SQLSTATE,
};
use crate::tcp::protocol::{
    BlockContext, BlockResponse, Classified, QueryKind, RawClientMessage, WireProtocol,
};

pub struct MysqlProtocol;

#[async_trait::async_trait]
impl WireProtocol for MysqlProtocol {
    fn dialect(&self) -> Dialect {
        Dialect::Mysql
    }

    fn name(&self) -> &'static str {
        "mysql"
    }

    async fn read_client_message(
        &self,
        client_read: &mut crate::tcp::client_tls::ClientRead,
    ) -> std::io::Result<Option<RawClientMessage>> {
        Ok(read_packet(client_read).await?.map(RawClientMessage::Mysql))
    }

    fn classify(&self, msg: &RawClientMessage) -> Classified {
        let RawClientMessage::Mysql(pkt) = msg else {
            // A protocol mismatch is a programming error; forward defensively.
            return Classified::PassThrough;
        };
        match pkt.command_tag() {
            Some(COM_QUIT) => Classified::Terminate,
            _ => match pkt.extract_sql() {
                Some(sql) => Classified::Query {
                    sql,
                    // COM_QUERY and COM_STMT_PREPARE both surface as SQL; the
                    // distinction (Simple vs Prepared) drives the reply sequence
                    // id but not the framing, so map both to their kind.
                    kind: prepared_or_simple(pkt),
                },
                None => Classified::PassThrough,
            },
        }
    }

    fn intercepts_from_start(&self) -> bool {
        // MySQL negotiates auth on the same client→server stream this loop reads,
        // so we must pass auth packets through until the command phase starts.
        false
    }

    fn is_command_phase_start(&self, msg: &RawClientMessage) -> bool {
        // The command phase begins when the client sends a packet with sequence
        // id 0: every command resets seq to 0, whereas the auth exchange uses
        // increasing sequence ids (client auth response is seq 1, etc.).
        matches!(msg, RawClientMessage::Mysql(p) if p.seq == 0)
    }

    fn build_block_response(&self, ctx: &BlockContext) -> BlockResponse {
        let message = block_message(ctx.rule_code, ctx.ast_node_path, ctx.suggested_safe_query);
        // The reply to a command packet uses sequence id command_seq + 1.
        let reply_seq = ctx.client_seq.wrapping_add(1);
        BlockResponse {
            bytes: build_err_packet(
                reply_seq,
                VERICTO_BLOCK_ERR_CODE,
                VERICTO_BLOCK_SQLSTATE,
                &message,
            ),
            // MySQL has no extended skip-until-Sync equivalent: the single
            // ERR_Packet completes the command; the client issues the next one.
            skip_until_sync: false,
        }
    }
}

fn prepared_or_simple(pkt: &MySqlPacket) -> QueryKind {
    use crate::tcp::codec_mysql::COM_STMT_PREPARE;
    match pkt.command_tag() {
        Some(COM_STMT_PREPARE) => QueryKind::Prepared,
        _ => QueryKind::Simple,
    }
}

/// Block message shown to the client (same wording as the Postgres path).
fn block_message(rule_code: &str, ast_node_path: &str, suggestion: Option<&str>) -> String {
    let base = format!("Vericto blocked this query [{rule_code}] — AST node: {ast_node_path}");
    match suggestion {
        Some(s) => format!("{base}. Suggestion: {s}"),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::codec_mysql::{COM_QUERY, COM_STMT_PREPARE};

    fn pkt(tag: u8, body: &str) -> RawClientMessage {
        let mut payload = vec![tag];
        payload.extend_from_slice(body.as_bytes());
        RawClientMessage::Mysql(MySqlPacket { seq: 0, payload })
    }

    #[test]
    fn classifies_com_query_as_query() {
        let p = MysqlProtocol;
        match p.classify(&pkt(COM_QUERY, "DELETE FROM users")) {
            Classified::Query { sql, kind } => {
                assert_eq!(sql, "DELETE FROM users");
                assert_eq!(kind, QueryKind::Simple);
            }
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn classifies_prepare_as_prepared_query() {
        let p = MysqlProtocol;
        match p.classify(&pkt(COM_STMT_PREPARE, "UPDATE t SET x=1")) {
            Classified::Query { kind, .. } => assert_eq!(kind, QueryKind::Prepared),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn classifies_quit_as_terminate() {
        let p = MysqlProtocol;
        let quit = RawClientMessage::Mysql(MySqlPacket {
            seq: 0,
            payload: vec![COM_QUIT],
        });
        assert!(matches!(p.classify(&quit), Classified::Terminate));
    }

    #[test]
    fn classifies_ping_as_passthrough() {
        let p = MysqlProtocol;
        let ping = RawClientMessage::Mysql(MySqlPacket {
            seq: 0,
            payload: vec![0x0e],
        });
        assert!(matches!(p.classify(&ping), Classified::PassThrough));
    }

    #[test]
    fn block_response_targets_reply_sequence() {
        let p = MysqlProtocol;
        let ctx = BlockContext {
            rule_code: "VERICTO-001",
            ast_node_path: "DeleteStmt",
            suggested_safe_query: None,
            kind: QueryKind::Simple,
            client_seq: 0,
        };
        let resp = p.build_block_response(&ctx);
        assert!(!resp.skip_until_sync);
        // reply seq must be command_seq + 1 = 1
        assert_eq!(resp.bytes[3], 1);
        assert_eq!(resp.bytes[4], 0xFF); // ERR packet
    }
}
