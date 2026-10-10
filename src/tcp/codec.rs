//! PostgreSQL wire-protocol codec (pgwire v3).
//!
//! Handles message framing in both phases:
//! - **Startup** (no type byte): `[Int32 len][Int32 code/version][payload]`
//! - **Regular** (with type byte): `[Byte1 tag][Int32 len][payload]`
//!
//! Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html

use tokio::io::{AsyncRead, AsyncReadExt};

/// `SSLRequest` magic code (80877103).
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
/// `GSSENCRequest` magic code (80877104).
pub const GSS_REQUEST_CODE: i32 = 80_877_104;

/// SQLSTATE returned when blocking a query (insufficient_privilege).
pub const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// SQLSTATE returned when the upstream database is unreachable
/// (connection_failure, class 08). Sent to the client as a native
/// `ErrorResponse` during the connection phase so the driver surfaces a typed
/// error instead of a bare closed socket.
pub const SQLSTATE_CONNECTION_FAILURE: &str = "08006";

/// SQLSTATE returned when `PROXY_TLS_MODE=require` and the client starts in
/// plaintext (invalid_authorization_specification). The same code PostgreSQL
/// itself answers when `pg_hba.conf` only has `hostssl` entries.
pub const SQLSTATE_INVALID_AUTHORIZATION: &str = "28000";

/// Maximum accepted message size (anti-DoS defense). 64MB.
const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// Result of reading the client's startup message.
#[derive(Debug)]
pub enum StartupPacket {
    /// The client requests TLS. The proxy answers 'S' (terminate TLS) when
    /// client TLS is enabled, otherwise 'N' (decline).
    SslRequest,
    /// The client requests GSSAPI encryption. We respond declining ('N').
    GssRequest,
    /// The real `StartupMessage`. Contains the complete bytes (len + body) to
    /// forward to the upstream unmodified.
    Startup { raw: Vec<u8>, params: StartupParams },
}

/// Relevant parameters extracted from the StartupMessage.
#[derive(Debug, Default, Clone)]
pub struct StartupParams {
    pub user: Option<String>,
    pub database: Option<String>,
    /// The run-time settings the StartupMessage sets that an agent-access
    /// allowlist depends on ([`ACCESS_STARTUP_SETTINGS`]), as `(name, value)`
    /// in the order the server applies them: the `options` switches
    /// (`-c name=value`, `--name=value`), then the parameters sent directly.
    /// Names lower-cased, `-` read as `_`, as the server reads them.
    pub access_settings: Vec<(String, String)>,
}

/// Settings a StartupMessage can set that change who the session is or where
/// unqualified names resolve: the engine denies their `SET` form under an
/// agent-access policy (`SET search_path`, `SET ROLE`,
/// `SET SESSION AUTHORIZATION`), so the proxy evaluates them as that `SET`
/// before the session starts (see `session::startup_settings_block`).
pub const ACCESS_STARTUP_SETTINGS: &[&str] = &["search_path", "role", "session_authorization"];

/// A regular-protocol message (with tag).
#[derive(Debug, Clone)]
pub struct PgMessage {
    pub tag: u8,
    /// Payload without the tag or the 4 length bytes.
    pub body: Vec<u8>,
}

impl PgMessage {
    /// Rebuilds the complete message bytes (tag + len + body) for forwarding.
    pub fn encode(&self) -> Vec<u8> {
        let len = (self.body.len() + 4) as i32;
        let mut out = Vec::with_capacity(self.body.len() + 5);
        out.push(self.tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Reads the client's startup packet (startup phase, no type byte).
pub async fn read_startup_packet<R>(reader: &mut R) -> std::io::Result<StartupPacket>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf);

    if len < 8 || (len as usize) > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid startup length: {len}"),
        ));
    }

    let body_len = (len - 4) as usize;
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;

    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    match code {
        SSL_REQUEST_CODE => Ok(StartupPacket::SslRequest),
        GSS_REQUEST_CODE => Ok(StartupPacket::GssRequest),
        _ => {
            // The real StartupMessage. Rebuild the original bytes for forwarding.
            let mut raw = Vec::with_capacity(body_len + 4);
            raw.extend_from_slice(&len_buf);
            raw.extend_from_slice(&body);
            let params = parse_startup_params(&body[4..]);
            Ok(StartupPacket::Startup { raw, params })
        }
    }
}

/// Parses the StartupMessage key/value pairs (after the 4 version bytes).
fn parse_startup_params(body: &[u8]) -> StartupParams {
    let mut params = StartupParams::default();
    let mut direct = Vec::new();
    let mut options = Vec::new();
    // Pairs of NUL-terminated strings, ended by an empty name. An empty value
    // is a value (not skipped), or every later pair would be read shifted.
    let mut parts = body.split(|&b| b == 0);
    while let Some(key) = parts.next() {
        if key.is_empty() {
            break;
        }
        let Some(val) = parts.next() else { break };
        let val = String::from_utf8_lossy(val).into_owned();
        match std::str::from_utf8(key) {
            Ok("user") => params.user = Some(val),
            Ok("database") => params.database = Some(val),
            Ok("options") => options.extend(options_settings(&val)),
            _ => direct.push((guc_name(&String::from_utf8_lossy(key)), val)),
        }
    }
    params.access_settings = options
        .into_iter()
        .chain(direct)
        .filter(|(name, _)| ACCESS_STARTUP_SETTINGS.contains(&name.as_str()))
        .collect();
    params
}

/// A setting name as the server reads it: case-insensitive, `-` as `_`.
fn guc_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// The `name=value` settings of a StartupMessage `options` string: words split
/// on unescaped whitespace (`\` escapes the next character), `-c name=value`,
/// `-cname=value` and `--name=value`, as the server's `pg_split_opts` and
/// command-line parser read them. Other switches carry no setting.
fn options_settings(options: &str) -> Vec<(String, String)> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = options.chars();
    while let Some(c) = chars.next() {
        if c.is_ascii_whitespace() {
            if in_word {
                words.push(std::mem::take(&mut word));
                in_word = false;
            }
            continue;
        }
        in_word = true;
        if c == '\\' {
            if let Some(next) = chars.next() {
                word.push(next);
            }
        } else {
            word.push(c);
        }
    }
    if in_word {
        words.push(word);
    }
    let mut out = Vec::new();
    let mut words = words.into_iter();
    while let Some(w) = words.next() {
        let setting = if w == "-c" {
            words.next()
        } else if let Some(rest) = w.strip_prefix("--") {
            Some(rest.to_string())
        } else {
            w.strip_prefix("-c").map(str::to_string)
        };
        if let Some((name, value)) = setting.as_deref().and_then(|s| s.split_once('=')) {
            out.push((guc_name(name), value.to_string()));
        }
    }
    out
}

/// Reads a regular-protocol message (with tag). Returns `None` on clean EOF.
pub async fn read_message<R>(reader: &mut R) -> std::io::Result<Option<PgMessage>>
where
    R: AsyncRead + Unpin,
{
    let mut tag = [0u8; 1];
    match reader.read_exact(&mut tag).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf);

    if len < 4 || (len as usize) > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid message length: {len}"),
        ));
    }

    let body_len = (len - 4) as usize;
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;

    Ok(Some(PgMessage { tag: tag[0], body }))
}

/// Extracts the SQL from a Simple Query message ('Q'): payload = cstring.
pub fn extract_simple_query(msg: &PgMessage) -> Option<String> {
    cstring_at(&msg.body, 0).map(|(s, _)| s)
}

/// Extracts the SQL from a Parse message ('P'): [cstring stmt][cstring query][...].
pub fn extract_parse_query(msg: &PgMessage) -> Option<String> {
    // First cstring: statement name (may be empty).
    let (_, after_name) = cstring_at(&msg.body, 0)?;
    // Second cstring: the SQL.
    cstring_at(&msg.body, after_name).map(|(s, _)| s)
}

/// The same Simple Query ('Q') or Parse ('P') message carrying `sql` instead of
/// its original SQL. For a Parse the statement name and everything after the
/// query (the parameter type OIDs) are kept byte for byte, so the client's
/// later Bind/Describe/Execute still address the statement it prepared.
///
/// `None` when `msg` is neither, is malformed, or `sql` cannot travel as a
/// cstring (an embedded NUL would end it early and send a truncated query).
pub fn with_replaced_query(msg: &PgMessage, sql: &str) -> Option<PgMessage> {
    if sql.as_bytes().contains(&0) {
        return None;
    }
    let mut body = Vec::with_capacity(msg.body.len() + sql.len());
    let rest = match msg.tag {
        b'Q' => {
            cstring_at(&msg.body, 0)?;
            &[][..]
        }
        b'P' => {
            let (_, after_name) = cstring_at(&msg.body, 0)?;
            let (_, after_query) = cstring_at(&msg.body, after_name)?;
            body.extend_from_slice(&msg.body[..after_name]);
            &msg.body[after_query..]
        }
        _ => return None,
    };
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    body.extend_from_slice(rest);
    Some(PgMessage { tag: msg.tag, body })
}

/// Reads a cstring (NUL-terminated) from `offset`. Returns (string, next_offset).
fn cstring_at(buf: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset > buf.len() {
        return None;
    }
    let end = buf[offset..].iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&buf[offset..offset + end])
        .ok()?
        .to_string();
    Some((s, offset + end + 1))
}

/// Builds a backend `ErrorResponse` ('E') message.
pub fn build_error_response(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    // Fields: type (1 byte) + value (cstring). Terminated by a 0 byte.
    let push_field = |body: &mut Vec<u8>, field: u8, value: &str| {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    };
    push_field(&mut body, b'S', "ERROR"); // Severity (localizable)
    push_field(&mut body, b'V', "ERROR"); // Severity (non-localizable)
    push_field(&mut body, b'C', sqlstate); // SQLSTATE
    push_field(&mut body, b'M', message); // Message
    body.push(0); // Field terminator

    let len = (body.len() + 4) as i32;
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(b'E');
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Builds a `ReadyForQuery` ('Z') message with status 'I' (idle).
pub fn build_ready_for_query() -> Vec<u8> {
    // tag 'Z' + len(5) + status 'I'
    vec![b'Z', 0, 0, 0, 5, b'I']
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup_body(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut b = Vec::new();
        for (k, v) in pairs {
            b.extend_from_slice(k.as_bytes());
            b.push(0);
            b.extend_from_slice(v.as_bytes());
            b.push(0);
        }
        b.push(0);
        b
    }

    /// `search_path`, `role` and `session_authorization` set at startup, sent
    /// directly or through `options`, are what an allowlist must see.
    #[test]
    fn startup_settings_that_move_names_or_identity_are_collected() {
        let p = parse_startup_params(&startup_body(&[
            ("user", "agent"),
            ("database", "shop"),
            ("application_name", ""),
            (
                "options",
                r"-c search_path=secret,public --ROLE=admin -cstatement_timeout=5 -c search\ path=x",
            ),
            ("Search_Path", "audit"),
            ("session-authorization", "postgres"),
            ("DateStyle", "ISO"),
        ]));
        assert_eq!(p.user.as_deref(), Some("agent"));
        assert_eq!(p.database.as_deref(), Some("shop"));
        let got: Vec<(&str, &str)> = p
            .access_settings
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("search_path", "secret,public"),
                ("role", "admin"),
                ("search_path", "audit"),
                ("session_authorization", "postgres"),
            ]
        );
        // An escaped space is part of the value.
        let p = parse_startup_params(&startup_body(&[("options", r"-csearch_path=a\ b")]));
        assert_eq!(
            p.access_settings,
            vec![("search_path".into(), "a b".into())]
        );
        // Nothing relevant: nothing collected (and an empty value does not shift
        // the pairs after it).
        let p = parse_startup_params(&startup_body(&[
            ("application_name", ""),
            ("user", "app"),
            ("options", "-c statement_timeout=0"),
        ]));
        assert_eq!(p.user.as_deref(), Some("app"));
        assert!(p.access_settings.is_empty());
    }

    fn simple_query_msg(sql: &str) -> PgMessage {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        PgMessage { tag: b'Q', body }
    }

    fn parse_msg(stmt_name: &str, sql: &str) -> PgMessage {
        let mut body = Vec::new();
        body.extend_from_slice(stmt_name.as_bytes());
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i16.to_be_bytes()); // 0 param types
        PgMessage { tag: b'P', body }
    }

    #[test]
    fn extract_simple_query_works() {
        let msg = simple_query_msg("DELETE FROM users");
        assert_eq!(
            extract_simple_query(&msg).as_deref(),
            Some("DELETE FROM users")
        );
    }

    #[test]
    fn extract_parse_query_works() {
        let msg = parse_msg("stmt1", "UPDATE products SET price = 0");
        assert_eq!(
            extract_parse_query(&msg).as_deref(),
            Some("UPDATE products SET price = 0")
        );
    }

    #[test]
    fn extract_parse_query_unnamed_statement() {
        let msg = parse_msg("", "SELECT 1");
        assert_eq!(extract_parse_query(&msg).as_deref(), Some("SELECT 1"));
    }

    #[test]
    fn replaced_simple_query_carries_only_the_new_sql() {
        let msg =
            with_replaced_query(&simple_query_msg("SELECT email FROM t"), "SELECT 'x'").unwrap();
        assert_eq!(msg.tag, b'Q');
        assert_eq!(msg.body, b"SELECT 'x'\0");
    }

    #[test]
    fn replaced_parse_keeps_the_name_and_the_parameter_types() {
        let mut original = parse_msg("stmt_9", "SELECT card FROM t WHERE id = $1");
        // Replace the "0 types" tail with two explicit OIDs.
        original.body.truncate(original.body.len() - 2);
        original.body.extend_from_slice(&2i16.to_be_bytes());
        original.body.extend_from_slice(&23i32.to_be_bytes());
        original.body.extend_from_slice(&25i32.to_be_bytes());
        let tail = original.body[original.body.len() - 10..].to_vec();

        let msg =
            with_replaced_query(&original, "SELECT 'x' AS card FROM t WHERE id = $1").unwrap();
        assert_eq!(msg.tag, b'P');
        assert_eq!(
            extract_parse_query(&msg).as_deref(),
            Some("SELECT 'x' AS card FROM t WHERE id = $1")
        );
        assert!(msg.body.starts_with(b"stmt_9\0"));
        assert_eq!(&msg.body[msg.body.len() - 10..], &tail[..]);
    }

    #[test]
    fn replaced_query_refuses_a_nul_and_other_messages() {
        assert!(with_replaced_query(&simple_query_msg("SELECT 1"), "SELECT 1\0; DROP").is_none());
        let sync = PgMessage {
            tag: b'S',
            body: Vec::new(),
        };
        assert!(with_replaced_query(&sync, "SELECT 1").is_none());
    }

    #[test]
    fn encode_roundtrip_length() {
        let msg = simple_query_msg("SELECT 1");
        let encoded = msg.encode();
        assert_eq!(encoded[0], b'Q');
        let len = i32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
        assert_eq!(len as usize, msg.body.len() + 4);
    }

    #[test]
    fn error_response_has_sqlstate() {
        let err = build_error_response(SQLSTATE_INSUFFICIENT_PRIVILEGE, "blocked");
        assert_eq!(err[0], b'E');
        // SQLSTATE 42501 must be present in the payload.
        let payload = &err[5..];
        let as_str = String::from_utf8_lossy(payload);
        assert!(as_str.contains("42501"));
        assert!(as_str.contains("blocked"));
    }

    #[test]
    fn ready_for_query_is_idle() {
        let z = build_ready_for_query();
        assert_eq!(z, vec![b'Z', 0, 0, 0, 5, b'I']);
    }
}
