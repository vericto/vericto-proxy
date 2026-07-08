//! MySQL wire-protocol framing for the multi-dialect proxy (Phase 1).
//!
//! Scope: only what the proxy needs to intercept and evaluate SQL — packet
//! framing, command classification (COM_QUERY / COM_STMT_PREPARE), and building
//! a native ERR_Packet to reject a blocked query. Authentication is NOT
//! reimplemented: the proxy relays the upstream's handshake and passes auth
//! packets through (see protocol/mysql.rs), so we never touch
//! caching_sha2_password / mysql_native_password.
//!
//! MySQL packet layout (classic protocol):
//!   [3 bytes payload length, little-endian][1 byte sequence id][payload...]
//! In the command phase the first payload byte is the command tag; for
//! COM_QUERY (0x03) and COM_STMT_PREPARE (0x16) the remaining bytes are the SQL
//! text (UTF-8). Reference:
//! https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html

use tokio::io::{AsyncRead, AsyncReadExt};

/// Max accepted MySQL packet payload (anti-DoS). MySQL's protocol max for a
/// single packet is 16 MB (0xFFFFFF); larger logical payloads are split. We do
/// not reassemble split packets for evaluation — a single 16 MB packet already
/// far exceeds any real query, so we cap reads at one packet.
pub const MYSQL_MAX_PACKET_LEN: usize = 0xFF_FF_FF; // 16 MiB - 1

/// Command tags we care about (first payload byte in the command phase).
pub const COM_QUERY: u8 = 0x03;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_QUIT: u8 = 0x01;

/// CLIENT_SSL capability flag (bit 11). Present in the 4-byte client capability
/// flags at the start of both the SSL Request packet and the HandshakeResponse.
pub const CLIENT_SSL: u32 = 0x0000_0800;

/// Generic-response header bytes for a server→client packet during the
/// connection (auth) phase. (EOF 0xFE is treated as "more" by classification,
/// not called out separately.)
pub const OK_HEADER: u8 = 0x00;
pub const ERR_HEADER: u8 = 0xFF;

/// Outcome of a server→client packet during the auth exchange, classified by
/// its first payload byte. The proxy transports auth packets in order without
/// understanding their contents; it only needs to know when the exchange ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPhase {
    /// OK_Packet — authentication succeeded; the connection phase is complete.
    Ok,
    /// ERR_Packet — authentication failed; forward to the client and close.
    Err,
    /// AuthSwitchRequest / AuthMoreData (or an OK/EOF-lookalike escaped by the
    /// plugin) — more exchanges follow; keep pumping.
    More,
}

/// Classifies a server→client connection-phase packet by its first byte.
/// Note: a real OK_Packet begins with 0x00, but auth plugins may send 0x01
/// (AuthMoreData) or 0xFE (AuthSwitchRequest); we treat only 0x00 as OK and
/// 0xFF as ERR, everything else as "more". An empty payload is treated as More
/// (defensive — never end the loop on a malformed packet).
pub fn classify_auth_packet(payload: &[u8]) -> AuthPhase {
    match payload.first().copied() {
        Some(OK_HEADER) => AuthPhase::Ok,
        Some(ERR_HEADER) => AuthPhase::Err,
        _ => AuthPhase::More,
    }
}

/// Reads the 4-byte little-endian client capability flags from the start of a
/// HandshakeResponse / SSLRequest payload. Returns None if the payload is too
/// short. (The protocol_41 client capabilities are the first 4 bytes.)
pub fn read_client_capabilities(payload: &[u8]) -> Option<u32> {
    let b = payload.get(0..4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads the server capability flags from an Initial Handshake (protocol v10)
/// packet payload. The server splits its capabilities across two fields; this
/// reconstructs the full 32-bit value. Returns None if the packet is malformed.
///
/// Layout (v10): protocol_version(1) + server_version(NUL-terminated string) +
/// thread_id(4) + auth_plugin_data_part_1(8) + filler(1) +
/// capability_flags_lower(2) + [ character_set(1) + status_flags(2) +
/// capability_flags_upper(2) + ... ].
pub fn read_server_capabilities(payload: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    // protocol_version
    let _proto = *payload.get(i)?;
    i += 1;
    // server_version: NUL-terminated
    let nul = payload.get(i..)?.iter().position(|&b| b == 0)?;
    i += nul + 1;
    // thread_id(4) + auth_plugin_data_part_1(8) + filler(1) = 13
    i += 13;
    // capability_flags_lower (2 bytes)
    let lo = payload.get(i..i + 2)?;
    let lower = u16::from_le_bytes([lo[0], lo[1]]) as u32;
    i += 2;
    // If the packet ends here (very old servers), only the lower half exists.
    // Otherwise: character_set(1) + status_flags(2) = 3, then upper caps (2).
    let upper = match payload.get(i + 3..i + 5) {
        Some(hi) => u16::from_le_bytes([hi[0], hi[1]]) as u32,
        None => 0,
    };
    Some((upper << 16) | lower)
}

/// Builds the SSL Request packet the proxy sends to the upstream to initiate
/// TLS. The SSL Request MUST be a byte-exact prefix of the client's
/// HandshakeResponse41 header (capability flags + max_packet_size + charset +
/// 23-byte filler = 32 bytes), so the server sees the same negotiated
/// parameters before and after TLS. We therefore derive it from the client's
/// actual HandshakeResponse payload rather than inventing values — only forcing
/// the CLIENT_SSL capability bit on. `seq` must be the server-handshake seq + 1
/// (i.e. 1). Falls back to a minimal 32-byte request if the response is short.
pub fn build_ssl_request_from_response(seq: u8, client_response: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 32];
    let take = client_response.len().min(32);
    header[..take].copy_from_slice(&client_response[..take]);
    // Force CLIENT_SSL on in the capability flags (first 4 bytes, LE).
    let caps = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) | CLIENT_SSL;
    header[0..4].copy_from_slice(&caps.to_le_bytes());
    MySqlPacket {
        seq,
        payload: header.to_vec(),
    }
    .encode()
}

/// Returns a copy of a HandshakeResponse payload with the CLIENT_SSL capability
/// bit forced ON (when `on`) or OFF (when `off`). Used to reconcile the client's
/// declared capabilities with the TLS decision the proxy made on the upstream
/// hop. No-op if the payload is too short to hold the flags.
pub fn set_client_ssl_flag(payload: &[u8], on: bool) -> Vec<u8> {
    let mut out = payload.to_vec();
    if let Some(caps) = read_client_capabilities(payload) {
        let new = if on {
            caps | CLIENT_SSL
        } else {
            caps & !CLIENT_SSL
        };
        out[0..4].copy_from_slice(&new.to_le_bytes());
    }
    out
}

/// A framed MySQL packet as read off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlPacket {
    /// Sequence id from the header (must be preserved when forwarding).
    pub seq: u8,
    /// Raw payload (command tag byte + body).
    pub payload: Vec<u8>,
}

impl MySqlPacket {
    /// Reassembles the complete on-wire bytes (header + payload) for forwarding.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len();
        let mut out = Vec::with_capacity(4 + len);
        // 3-byte little-endian length.
        out.push((len & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(self.seq);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Command tag (first payload byte), or None for an empty payload.
    pub fn command_tag(&self) -> Option<u8> {
        self.payload.first().copied()
    }

    /// If this packet carries SQL (COM_QUERY / COM_STMT_PREPARE), return it as a
    /// UTF-8 string. Returns None for other commands or invalid UTF-8 (we don't
    /// block on undecodable bytes — evaluation only applies to real SQL text).
    ///
    /// COM_QUERY on modern clients (MySQL 8.0.23+ negotiating
    /// CLIENT_QUERY_ATTRIBUTES) prefixes the SQL with two length-encoded ints —
    /// `parameter_count` and `parameter_set_count` — plus the encoded params
    /// when count > 0. We skip that prefix so the extracted text is the bare
    /// SQL. COM_STMT_PREPARE has no such prefix.
    pub fn extract_sql(&self) -> Option<String> {
        match self.command_tag()? {
            COM_QUERY => {
                let body = &self.payload[1..];
                let sql_bytes = strip_query_attributes(body);
                std::str::from_utf8(sql_bytes).ok().map(|s| s.to_string())
            }
            COM_STMT_PREPARE => std::str::from_utf8(&self.payload[1..])
                .ok()
                .map(|s| s.to_string()),
            _ => None,
        }
    }
}

/// Reads a MySQL length-encoded integer. Returns (value, bytes_consumed).
/// Handles the 1-byte (<251), 0xFC (2-byte), 0xFD (3-byte), 0xFE (8-byte) forms.
fn read_lenenc(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first {
        0x00..=0xFA => Some((first as u64, 1)),
        0xFC => {
            let b = buf.get(1..3)?;
            Some((u16::from_le_bytes([b[0], b[1]]) as u64, 3))
        }
        0xFD => {
            let b = buf.get(1..4)?;
            Some((
                (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16),
                4,
            ))
        }
        0xFE => {
            let b = buf.get(1..9)?;
            let mut v = 0u64;
            for (i, byte) in b.iter().enumerate() {
                v |= (*byte as u64) << (8 * i);
            }
            Some((v, 9))
        }
        // 0xFB (NULL) / 0xFF are not valid here.
        _ => None,
    }
}

/// Strips the optional CLIENT_QUERY_ATTRIBUTES prefix from a COM_QUERY body.
/// If the body doesn't look like the attributes form, it's returned unchanged
/// (older clients send the raw query right after the command tag).
fn strip_query_attributes(body: &[u8]) -> &[u8] {
    // Heuristic: the attributes form begins with parameter_count (lenenc) then
    // parameter_set_count (lenenc, always 1). A raw query instead begins with a
    // SQL keyword byte (a letter / whitespace), never a bare 0x00/0x01 control
    // byte. So only attempt to strip when the first byte is a plausible lenenc
    // control value that is NOT a printable SQL start.
    let Some(&first) = body.first() else {
        return body;
    };
    if first.is_ascii_alphabetic() || first == b'(' || first == b' ' || first == b'/' {
        // Looks like SQL already (SELECT, DELETE, (, comment, …) — no prefix.
        return body;
    }
    // Parse: parameter_count (lenenc), parameter_set_count (lenenc).
    let Some((param_count, n1)) = read_lenenc(body) else {
        return body;
    };
    let Some((_param_set_count, n2)) = read_lenenc(&body[n1..]) else {
        return body;
    };
    // With bound params a null-bitmap + params follow, which we don't skip
    // (Vetro evaluates SQL text, not bound values). For the overwhelming common
    // case (0 params) the SQL starts right after the two ints.
    if param_count != 0 {
        return body;
    }
    match body.get(n1 + n2..) {
        Some(sql) if !sql.is_empty() => sql,
        _ => body,
    }
}

/// Reads exactly one MySQL packet from the client. Returns None on clean EOF
/// (client closed before a new packet). Enforces the packet-length cap.
pub async fn read_packet<R>(reader: &mut R) -> std::io::Result<Option<MySqlPacket>>
where
    R: AsyncRead + Unpin,
{
    // Header: 3-byte LE length + 1-byte sequence id.
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        // Clean EOF before any header byte → client closed.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let seq = header[3];

    if len > MYSQL_MAX_PACKET_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("MySQL packet length {len} exceeds cap"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(MySqlPacket { seq, payload }))
}

/// Builds a native ERR_Packet to reject a blocked query. The client driver
/// surfaces this as a normal SQL error (not a dropped connection).
///
/// ERR_Packet (with protocol_41 capabilities, which every modern driver sets):
///   0xFF                       header
///   [2 bytes] error_code (LE)  we use 1045-style? no — use a generic code
///   '#'                        sql_state marker
///   [5 bytes] sql_state        ASCII
///   [N bytes] error_message    UTF-8, rest of packet
///
/// `seq` must be the sequence id following the command packet (command seq + 1),
/// so the client accepts it as the response to its query.
pub fn build_err_packet(seq: u8, error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9 + message.len());
    payload.push(0xFF);
    payload.push((error_code & 0xFF) as u8);
    payload.push(((error_code >> 8) & 0xFF) as u8);
    payload.push(b'#');
    // sql_state is exactly 5 ASCII chars; pad/truncate defensively.
    let mut state = sql_state.as_bytes().to_vec();
    state.resize(5, b'0');
    payload.extend_from_slice(&state[..5]);
    payload.extend_from_slice(message.as_bytes());

    MySqlPacket { seq, payload }.encode()
}

/// MySQL error code + SQLSTATE for a Vetro block. 1142 = ER_TABLEACCESS_DENIED
/// ("command denied") with SQLSTATE 42000 (syntax/access) — the closest native
/// analogue to Postgres' insufficient_privilege (42501), so drivers classify it
/// as an authorization/permission error rather than a connection fault.
pub const VETRO_BLOCK_ERR_CODE: u16 = 1142;
pub const VETRO_BLOCK_SQLSTATE: &str = "42000";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrips_header_and_payload() {
        let pkt = MySqlPacket {
            seq: 7,
            payload: vec![COM_QUERY, b'S', b'E', b'L'],
        };
        let bytes = pkt.encode();
        // len = 4 payload bytes → [4,0,0], seq=7
        assert_eq!(&bytes[..4], &[4, 0, 0, 7]);
        assert_eq!(&bytes[4..], &[COM_QUERY, b'S', b'E', b'L']);
    }

    #[test]
    fn extract_sql_from_com_query() {
        let mut payload = vec![COM_QUERY];
        payload.extend_from_slice(b"DELETE FROM users");
        let pkt = MySqlPacket { seq: 0, payload };
        assert_eq!(pkt.extract_sql().as_deref(), Some("DELETE FROM users"));
    }

    #[test]
    fn extract_sql_strips_query_attributes_prefix() {
        // MySQL 8.0.23+ COM_QUERY with CLIENT_QUERY_ATTRIBUTES, 0 params:
        // [0x03][param_count=0x00][param_set_count=0x01][SQL]
        let mut payload = vec![COM_QUERY, 0x00, 0x01];
        payload.extend_from_slice(b"DELETE FROM users");
        let pkt = MySqlPacket { seq: 0, payload };
        assert_eq!(pkt.extract_sql().as_deref(), Some("DELETE FROM users"));
    }

    #[test]
    fn extract_sql_from_com_stmt_prepare() {
        let mut payload = vec![COM_STMT_PREPARE];
        payload.extend_from_slice(b"UPDATE t SET x=1");
        let pkt = MySqlPacket { seq: 0, payload };
        assert_eq!(pkt.extract_sql().as_deref(), Some("UPDATE t SET x=1"));
    }

    #[test]
    fn extract_sql_none_for_other_commands() {
        let pkt = MySqlPacket {
            seq: 0,
            payload: vec![COM_QUIT],
        };
        assert_eq!(pkt.extract_sql(), None);
        // ping (0x0e), etc.
        let ping = MySqlPacket {
            seq: 0,
            payload: vec![0x0e],
        };
        assert_eq!(ping.extract_sql(), None);
    }

    #[test]
    fn extract_sql_none_for_empty_payload() {
        let pkt = MySqlPacket {
            seq: 0,
            payload: vec![],
        };
        assert_eq!(pkt.command_tag(), None);
        assert_eq!(pkt.extract_sql(), None);
    }

    #[test]
    fn err_packet_has_expected_shape() {
        let bytes = build_err_packet(1, VETRO_BLOCK_ERR_CODE, VETRO_BLOCK_SQLSTATE, "blocked");
        // header: len (3) + seq
        let len = (bytes[0] as usize) | ((bytes[1] as usize) << 8) | ((bytes[2] as usize) << 16);
        assert_eq!(len, bytes.len() - 4);
        assert_eq!(bytes[3], 1); // seq
        assert_eq!(bytes[4], 0xFF); // ERR header
                                    // error code 1142 = 0x0476 → little-endian bytes 0x76, 0x04
        assert_eq!(bytes[5], 0x76);
        assert_eq!(bytes[6], 0x04);
        assert_eq!(bytes[7], b'#');
        assert_eq!(&bytes[8..13], b"42000");
        assert_eq!(&bytes[13..], b"blocked");
    }

    #[tokio::test]
    async fn read_packet_parses_header_and_payload() {
        // A COM_QUERY "SELECT 1": payload = [0x03] + "SELECT 1"
        let mut payload = vec![COM_QUERY];
        payload.extend_from_slice(b"SELECT 1");
        let wire = MySqlPacket {
            seq: 0,
            payload: payload.clone(),
        }
        .encode();

        let mut cursor = std::io::Cursor::new(wire);
        let pkt = read_packet(&mut cursor).await.unwrap().unwrap();
        assert_eq!(pkt.seq, 0);
        assert_eq!(pkt.extract_sql().as_deref(), Some("SELECT 1"));
    }

    #[tokio::test]
    async fn read_packet_returns_none_on_clean_eof() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_packet(&mut cursor).await.unwrap().is_none());
    }

    #[test]
    fn ssl_request_is_32_byte_prefix_of_response_with_ssl_on() {
        // A client HandshakeResponse: caps (no SSL) + max_packet + charset(0xFF) + filler + username…
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x000F_A285u32.to_le_bytes()); // caps, no SSL
        resp.extend_from_slice(&(MYSQL_MAX_PACKET_LEN as u32).to_le_bytes());
        resp.push(0xFF); // charset
        resp.extend_from_slice(&[0u8; 23]); // filler
        resp.extend_from_slice(b"appuser\0"); // username + more (ignored by SSL req)

        let bytes = build_ssl_request_from_response(1, &resp);
        assert_eq!(bytes.len(), 4 + 32); // header + exactly 32-byte payload
        assert_eq!(bytes[3], 1); // seq
        let caps = read_client_capabilities(&bytes[4..]).unwrap();
        assert!(caps & CLIENT_SSL != 0, "CLIENT_SSL must be forced on");
        // The rest of the 32-byte prefix must match the client's response byte-for-byte.
        assert_eq!(bytes[4 + 4..4 + 32], resp[4..32]); // max_packet + charset + filler unchanged
        assert_eq!(bytes[4 + 8], 0xFF); // charset preserved
    }

    #[test]
    fn set_client_ssl_flag_toggles_bit() {
        // capabilities without SSL
        let mut payload = 0x0000_A285u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 28]); // rest of a response
        assert_eq!(read_client_capabilities(&payload).unwrap() & CLIENT_SSL, 0);

        let on = set_client_ssl_flag(&payload, true);
        assert!(read_client_capabilities(&on).unwrap() & CLIENT_SSL != 0);

        let off = set_client_ssl_flag(&on, false);
        assert_eq!(read_client_capabilities(&off).unwrap() & CLIENT_SSL, 0);
    }

    #[test]
    fn classify_auth_packet_detects_ok_err_more() {
        assert_eq!(classify_auth_packet(&[OK_HEADER, 0, 0]), AuthPhase::Ok);
        assert_eq!(
            classify_auth_packet(&[ERR_HEADER, 0x15, 0x04]),
            AuthPhase::Err
        );
        // AuthSwitchRequest (0xFE) and AuthMoreData (0x01) → More
        assert_eq!(classify_auth_packet(&[0xFE]), AuthPhase::More);
        assert_eq!(classify_auth_packet(&[0x01, 0x03]), AuthPhase::More);
        // Empty payload is defensively treated as More (never end on malformed).
        assert_eq!(classify_auth_packet(&[]), AuthPhase::More);
    }

    #[test]
    fn read_server_capabilities_parses_v10_handshake() {
        // Minimal v10 handshake: proto=10, "8.0.0\0", thread_id(4),
        // auth1(8), filler(1), cap_lower(2)=0xA685, charset(1), status(2),
        // cap_upper(2)=0x000F, ...
        let mut p = vec![10u8];
        p.extend_from_slice(b"8.0.0\0");
        p.extend_from_slice(&[1, 0, 0, 0]); // thread_id
        p.extend_from_slice(&[0u8; 8]); // auth part 1
        p.push(0); // filler
        p.extend_from_slice(&0xAE85u16.to_le_bytes()); // cap lower (bit 11 / CLIENT_SSL set)
        p.push(0xFF); // charset
        p.extend_from_slice(&0x0002u16.to_le_bytes()); // status
        p.extend_from_slice(&0x000Fu16.to_le_bytes()); // cap upper
        p.extend_from_slice(&[0u8; 20]); // remainder
        let caps = read_server_capabilities(&p).unwrap();
        assert_eq!(caps, (0x000F << 16) | 0xAE85);
        assert!(caps & CLIENT_SSL != 0); // 0xAE85 has bit 11 (0x800) set
    }
}
