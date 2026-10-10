//! MySQL implementation of the `WireProtocol` strategy (Phase 1).
//!
//! Framing lives in `codec_mysql`. This module maps MySQL packets onto the
//! generic session's classification and block-response contract. Auth is not
//! reimplemented — the session relays the upstream handshake and passes auth
//! packets through (classified as PassThrough), so caching_sha2_password /
//! mysql_native_password work untouched.

use vericto_engine::parser::Dialect;

use crate::tcp::codec_mysql::{
    COM_QUIT, MySqlPacket, VERICTO_BLOCK_ERR_CODE, VERICTO_BLOCK_SQLSTATE, build_err_packet,
    read_change_user_name, read_init_db_name, read_packet,
};
use crate::tcp::protocol::{
    AccessControl, BlockContext, BlockResponse, Classified, QueryKind, RawClientMessage,
    WireProtocol,
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
        // Only a packet with sequence id 0 starts a command. The others belong to
        // the command in progress — the auth exchange of a COM_CHANGE_USER, the
        // file of a LOAD DATA LOCAL INFILE — and their first byte is data, not a
        // command tag: read as one, a 0x01 there was a COM_QUIT that ended the
        // session, and a 0x03 was "SQL" to evaluate. Forwarding them as they are
        // is safe because the server never runs one as a command: MySQL answers a
        // command whose sequence id is not 0 with ERROR 1156 ("Got packets out of
        // order") and does not execute it. `access_control` draws the same line.
        if pkt.seq != 0 {
            return Classified::PassThrough;
        }
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

    /// A mask rewrite goes in the same command (COM_QUERY or COM_STMT_PREPARE),
    /// same sequence id. A COM_STMT_PREPARE needs nothing else: the proxy keeps
    /// no statement map, the server assigns the id of the rewritten statement in
    /// its COM_STMT_PREPARE_OK (relayed unchanged), and the client's
    /// COM_STMT_EXECUTE / COM_STMT_SEND_LONG_DATA name that id and bind the same
    /// `?` parameters (checked by `evaluator::evaluate_message`).
    fn with_query(&self, msg: &RawClientMessage, sql: &str) -> Option<RawClientMessage> {
        let RawClientMessage::Mysql(p) = msg else {
            return None;
        };
        p.with_sql(sql).map(RawClientMessage::Mysql)
    }

    /// Under an allowlist, only commands known to be plumbing pass: ping,
    /// statistics, the COM_STMT_* follow-ups of a statement evaluated at its
    /// COM_STMT_PREPARE, COM_SET_OPTION and COM_RESET_CONNECTION (the user
    /// stays). COM_INIT_DB is `USE` (it moves where unqualified names resolve:
    /// refused like `USE`, and tracked when forwarded), COM_FIELD_LIST is `SHOW COLUMNS`, the replication and process commands
    /// reach server state; they and any unknown command are refused, deny by
    /// default. Only command packets (sequence id 0) are commands: packets
    /// inside a command (auth continuation, LOCAL INFILE data) pass.
    fn access_control(&self, msg: &RawClientMessage) -> AccessControl {
        let RawClientMessage::Mysql(p) = msg else {
            return AccessControl::Allowed;
        };
        if p.seq != 0 {
            return AccessControl::Allowed;
        }
        let (label, kind) = match p.command_tag() {
            // PING, STATISTICS, STMT_EXECUTE, STMT_SEND_LONG_DATA, STMT_CLOSE,
            // STMT_RESET, SET_OPTION, STMT_FETCH, RESET_CONNECTION; QUIT.
            Some(0x0e | 0x09 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b | 0x1c | 0x1f | 0x01) => {
                return AccessControl::Allowed;
            }
            Some(0x11) => {
                return AccessControl::ChangeUser {
                    user: read_change_user_name(&p.payload),
                };
            }
            Some(0x02) => {
                return AccessControl::ChangeDatabase {
                    database: read_init_db_name(&p.payload),
                };
            }
            Some(0x04) => ("COM_FIELD_LIST", QueryKind::Simple),
            Some(0x03) => ("COM_QUERY (unreadable SQL)", QueryKind::Simple),
            Some(0x16) => ("COM_STMT_PREPARE (unreadable SQL)", QueryKind::Prepared),
            Some(0x0a) => ("COM_PROCESS_INFO", QueryKind::Simple),
            Some(0x0c) => ("COM_PROCESS_KILL", QueryKind::Simple),
            Some(0x0d) => ("COM_DEBUG", QueryKind::Simple),
            Some(0x12) => ("COM_BINLOG_DUMP", QueryKind::Simple),
            Some(0x15) => ("COM_REGISTER_SLAVE", QueryKind::Simple),
            Some(0x1e) => ("COM_BINLOG_DUMP_GTID", QueryKind::Simple),
            Some(t) => {
                return AccessControl::Restricted {
                    label: format!("command 0x{t:02x}"),
                    kind: QueryKind::Simple,
                };
            }
            None => ("empty command", QueryKind::Simple),
        };
        AccessControl::Restricted {
            label: label.to_string(),
            kind,
        }
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

    /// A packet inside a command (sequence id != 0) is data, whatever its first
    /// byte: not a COM_QUIT, not SQL to evaluate.
    #[test]
    fn a_packet_inside_a_command_is_passed_through() {
        let p = MysqlProtocol;
        let inside = |seq: u8, payload: &[u8]| {
            RawClientMessage::Mysql(MySqlPacket {
                seq,
                payload: payload.to_vec(),
            })
        };
        for (seq, payload) in [
            (2u8, &b"\x014,starts-with-0x01\n"[..]), // LOCAL INFILE data
            (2, &[0x01; 32][..]),                    // COM_CHANGE_USER scramble
            (2, &b"\x03DROP TABLE t"[..]),           // looks like a COM_QUERY
            (3, &b"\x16DELETE FROM t"[..]),          // looks like a COM_STMT_PREPARE
            (255, &[][..]),                          // end of a LOCAL INFILE file
        ] {
            assert!(
                matches!(p.classify(&inside(seq, payload)), Classified::PassThrough),
                "seq {seq}, {payload:?}"
            );
        }
        // The same bytes with sequence id 0 are commands.
        assert!(matches!(
            p.classify(&inside(0, b"\x01")),
            Classified::Terminate
        ));
        assert!(matches!(
            p.classify(&inside(0, b"\x03DROP TABLE t")),
            Classified::Query { .. }
        ));
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

    /// A mask rewrite travels in the same command: COM_QUERY stays COM_QUERY,
    /// COM_STMT_PREPARE stays COM_STMT_PREPARE, same sequence id.
    #[test]
    fn with_query_carries_the_rewrite_in_the_same_command() {
        let p = MysqlProtocol;
        for tag in [COM_QUERY, COM_STMT_PREPARE] {
            let Some(RawClientMessage::Mysql(m)) = p.with_query(
                &pkt(tag, "SELECT email FROM t"),
                "SELECT 'x' AS email FROM t",
            ) else {
                panic!("MySQL carries a rewrite");
            };
            assert_eq!(m.seq, 0);
            assert_eq!(m.payload[0], tag);
            assert_eq!(
                m.extract_sql().as_deref(),
                Some("SELECT 'x' AS email FROM t")
            );
        }
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

/// Where a `USE` in a COM_QUERY moves the session's current database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UseTarget {
    /// `USE db` (backticks or not): the session's current database is `db`.
    Database(String),
    /// A `USE` the proxy cannot read for certain (a versioned comment that may
    /// hold one, an unusual form, text the tokenizer rejects): the current
    /// database is unknown from here on.
    Unknown,
}

/// The current database after the statements of a forwarded COM_QUERY: the
/// last `USE` in it, or `None` when it has none. Only the statement start
/// counts (`USE INDEX` in a `SELECT` is not a `USE`). Conservative where it
/// cannot be sure: a `/*! … */` comment mentioning `use`, or text the
/// tokenizer rejects that does, makes the database unknown.
pub(crate) fn sql_use_target(sql: &str) -> Option<UseTarget> {
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::keywords::Keyword;
    use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

    let mentions_use = |s: &str| s.to_ascii_lowercase().contains("use");
    let Ok(tokens) = Tokenizer::new(&MySqlDialect {}, sql).tokenize() else {
        return mentions_use(sql).then_some(UseTarget::Unknown);
    };
    let mut target = None;
    let mut statement: Vec<&Token> = Vec::new();
    let close = |statement: &mut Vec<&Token>, target: &mut Option<UseTarget>| {
        if let Some(Token::Word(w)) = statement.first()
            && w.keyword == Keyword::USE
            && w.quote_style.is_none()
        {
            *target = Some(match statement.as_slice() {
                [_, Token::Word(db)] if db.quote_style.is_none_or(|q| q == '`') => {
                    UseTarget::Database(db.value.clone())
                }
                _ => UseTarget::Unknown,
            });
        }
        statement.clear();
    };
    for t in &tokens {
        match t {
            Token::Whitespace(Whitespace::MultiLineComment(c))
                if c.starts_with('!') && mentions_use(c) =>
            {
                target = Some(UseTarget::Unknown);
            }
            Token::Whitespace(_) | Token::EOF => {}
            Token::SemiColon => close(&mut statement, &mut target),
            t => statement.push(t),
        }
    }
    close(&mut statement, &mut target);
    target
}

#[cfg(test)]
mod use_tests {
    use super::{UseTarget, sql_use_target};

    #[test]
    fn use_statements_move_the_current_database() {
        let db = |s: &str| Some(UseTarget::Database(s.to_string()));
        assert_eq!(sql_use_target("USE shop"), db("shop"));
        assert_eq!(sql_use_target("use `Shop` ;"), db("Shop"));
        assert_eq!(sql_use_target("/* hi */ USE a; SELECT 1; USE b"), db("b"));
        assert_eq!(sql_use_target("SELECT * FROM t USE INDEX (i)"), None);
        assert_eq!(sql_use_target("SELECT 'use x'"), None);
        assert_eq!(sql_use_target("SELECT 1"), None);
        assert_eq!(sql_use_target("USE a.b"), Some(UseTarget::Unknown));
        assert_eq!(
            sql_use_target("/*!50000 USE x */"),
            Some(UseTarget::Unknown)
        );
        assert_eq!(
            sql_use_target("USE 'unterminated"),
            Some(UseTarget::Unknown)
        );
    }
}
