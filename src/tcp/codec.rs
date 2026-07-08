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
}

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
    let mut parts = body.split(|&b| b == 0).filter(|s| !s.is_empty());
    while let (Some(key), Some(val)) = (parts.next(), parts.next()) {
        match std::str::from_utf8(key) {
            Ok("user") => params.user = std::str::from_utf8(val).ok().map(String::from),
            Ok("database") => params.database = std::str::from_utf8(val).ok().map(String::from),
            _ => {}
        }
    }
    params
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
