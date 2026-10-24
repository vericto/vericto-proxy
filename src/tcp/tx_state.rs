// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The transaction state the server last reported, read off the
//! server→client relay so that the replies the proxy writes itself (a consumed
//! `SET vericto.*`, a refused statement) carry the session's real state
//! instead of "idle".
//!
//! - **Postgres:** the status byte of the last `ReadyForQuery` ('Z'): `I`
//!   idle, `T` in a transaction block, `E` in a failed transaction block.
//! - **MySQL:** the status flags of the last OK / EOF packet
//!   (`SERVER_STATUS_IN_TRANS`, `SERVER_STATUS_AUTOCOMMIT`, …).
//!
//! Postgres: always built (since 4.16.1; up to 4.16.0 only with
//! VERICTO_POLICY_RULES on, so a statement the proxy refused with the flag off
//! was answered with `I` even inside a transaction block). MySQL: only built
//! with policy rules on, the only time the proxy writes a reply that carries
//! status flags (the OK of a consumed `SET vericto.*`); its refusals are ERR
//! packets, which carry none. The trackers never change a byte of either stream.
//! The PostgreSQL relay
//! frames complete backend messages and feeds the tracker before exposing each
//! relevant byte; BackendKeyData is retained until its cancel key is registered.
//! The ordered response coordinator, rather than a timing assumption about the
//! client, positions PostgreSQL replies written by the proxy itself.

use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};

/// `ReadyForQuery` status: idle.
pub const PG_IDLE: u8 = b'I';
/// `ReadyForQuery` status: in a transaction block.
#[cfg(test)]
pub const PG_IN_TRANSACTION: u8 = b'T';
/// `ReadyForQuery` status: in a failed transaction block.
pub const PG_FAILED_TRANSACTION: u8 = b'E';

/// MySQL `SERVER_STATUS_IN_TRANS`.
#[cfg(test)]
pub const MYSQL_STATUS_IN_TRANS: u16 = 0x0001;
/// MySQL `SERVER_STATUS_AUTOCOMMIT`.
pub const MYSQL_STATUS_AUTOCOMMIT: u16 = 0x0002;
/// MySQL `SERVER_MORE_RESULTS_EXISTS`.
const MYSQL_MORE_RESULTS: u16 = 0x0008;
/// MySQL `CLIENT_DEPRECATE_EOF`.
pub const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;

/// The state shared by the client-side loop (reads it) and the relay (writes it).
#[derive(Debug)]
pub struct ServerTxState {
    pg_status: AtomicU8,
    mysql_flags: AtomicU16,
    /// MySQL: the command byte of the last command forwarded, and a generation
    /// counter so the relay knows a new response begins.
    mysql_command: AtomicU8,
    mysql_generation: AtomicU32,
}

impl Default for ServerTxState {
    fn default() -> Self {
        ServerTxState {
            pg_status: AtomicU8::new(PG_IDLE),
            mysql_flags: AtomicU16::new(MYSQL_STATUS_AUTOCOMMIT),
            mysql_command: AtomicU8::new(0),
            mysql_generation: AtomicU32::new(0),
        }
    }
}

impl ServerTxState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The last `ReadyForQuery` status (idle until the server sent one).
    pub fn pg_status(&self) -> u8 {
        self.pg_status.load(Ordering::Acquire)
    }

    pub fn set_pg_status(&self, status: u8) {
        self.pg_status.store(status, Ordering::Release);
    }

    /// The last MySQL status flags (autocommit until the server sent some).
    pub fn mysql_flags(&self) -> u16 {
        self.mysql_flags.load(Ordering::Acquire)
    }

    pub fn set_mysql_flags(&self, flags: u16) {
        self.mysql_flags.store(flags, Ordering::Release);
    }

    /// Called by the client loop just before it forwards a MySQL command
    /// packet (sequence id 0): its response is the next thing the server sends.
    pub fn note_mysql_command(&self, command: u8) {
        self.mysql_command.store(command, Ordering::Release);
        self.mysql_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn mysql_command(&self) -> (u32, u8) {
        let generation = self.mysql_generation.load(Ordering::Acquire);
        (generation, self.mysql_command.load(Ordering::Acquire))
    }
}

/// Postgres: frames the server→client stream and records every
/// `ReadyForQuery` status. Every backend message after the StartupMessage is
/// `tag(1) + length(4, itself included) + body`, so framing from the first byte
/// of the relay is exact.
///
/// Until the first `ReadyForQuery` (the startup phase) it also keeps the body
/// of the `BackendKeyData` ('K'), the key a `CancelRequest` for this session
/// presents (see `tcp::cancel`).
#[derive(Debug, Default)]
pub struct PgTxTracker {
    header: [u8; 5],
    header_len: usize,
    /// Body bytes still to skip of the current message.
    remaining: usize,
    /// The current message is a ReadyForQuery whose status byte is next.
    in_ready: bool,
    /// A ReadyForQuery has been seen: the startup phase is over.
    started: bool,
    /// The body of the BackendKeyData being read, during the startup phase.
    key_body: Option<Vec<u8>>,
    /// The BackendKeyData once read, until taken.
    backend_key: Option<crate::tcp::cancel::BackendKey>,
}

impl PgTxTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The session's `BackendKeyData`, once the server has sent it (taken once).
    pub fn take_backend_key(&mut self) -> Option<crate::tcp::cancel::BackendKey> {
        self.backend_key.take()
    }

    pub fn feed(&mut self, mut bytes: &[u8], state: &ServerTxState) {
        while !bytes.is_empty() {
            if self.started && self.remaining == 0 && self.header_len == 0 {
                bytes = Self::skip_whole_messages(bytes, state);
                if bytes.is_empty() {
                    return;
                }
            }
            if self.remaining > 0 {
                if self.in_ready {
                    state.set_pg_status(bytes[0]);
                    self.in_ready = false;
                    self.started = true;
                }
                let n = self.remaining.min(bytes.len());
                if let Some(body) = self.key_body.as_mut() {
                    body.extend_from_slice(&bytes[..n]);
                    if self.remaining == n {
                        self.backend_key = crate::tcp::cancel::BackendKey::parse(body);
                        self.key_body = None;
                    }
                }
                self.remaining -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (5 - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + n].copy_from_slice(&bytes[..n]);
            self.header_len += n;
            bytes = &bytes[n..];
            if self.header_len == 5 {
                self.header_len = 0;
                let len = u32::from_be_bytes([
                    self.header[1],
                    self.header[2],
                    self.header[3],
                    self.header[4],
                ]) as usize;
                self.remaining = len.saturating_sub(4);
                self.in_ready = self.header[0] == b'Z' && self.remaining == 1;
                if !self.started
                    && self.header[0] == b'K'
                    && (8..=4 + crate::tcp::cancel::MAX_SECRET_LEN).contains(&self.remaining)
                {
                    self.key_body = Some(Vec::with_capacity(self.remaining));
                }
            }
        }
    }

    /// The relay's usual case after the startup phase: walks the messages that
    /// lie whole in `bytes` in place (one header read each, no copy) and records
    /// the last ReadyForQuery status among them. Returns the tail that starts
    /// with a message this chunk does not hold whole, for the byte-wise path.
    fn skip_whole_messages<'a>(bytes: &'a [u8], state: &ServerTxState) -> &'a [u8] {
        let mut pos = 0;
        let mut status = None;
        while let Some(header) = bytes.get(pos..pos + 5) {
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let end = pos + 1 + len.max(4);
            if end > bytes.len() {
                break;
            }
            if header[0] == b'Z' && len == 5 {
                status = Some(bytes[pos + 5]);
            }
            pos = end;
        }
        if let Some(s) = status {
            state.set_pg_status(s);
        }
        &bytes[pos..]
    }
}

/// MySQL: frames the server→client stream (command phase) and records the
/// status flags of every OK / EOF packet, following the response to the
/// command the client loop last noted ([`ServerTxState::note_mysql_command`]).
/// A command whose response it does not model is skipped until the next one:
/// the state then keeps the last value it knew.
#[derive(Debug)]
pub struct MySqlTxTracker {
    deprecate_eof: bool,
    header: [u8; 4],
    header_len: usize,
    /// Payload length and sequence id of the packet being read.
    payload_len: usize,
    remaining: usize,
    prefix: Vec<u8>,
    /// The packet just finished had the maximum length: the next one continues it.
    continuation: bool,
    generation: u32,
    command: u8,
    phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The first packet of a response (or of the next result of a multi-result).
    Start,
    /// Column definitions still to come, then (without DEPRECATE_EOF) an EOF.
    Columns(u64),
    ColumnsEof,
    Rows,
    /// COM_STMT_PREPARE: parameter definitions, then column definitions.
    PrepareParams(u64, u64),
    PrepareParamsEof(u64),
    PrepareColumns(u64),
    PrepareColumnsEof,
    /// COM_CHANGE_USER: auth packets until the OK.
    ChangeUser,
    /// Nothing more is expected, or the response is not modelled.
    Done,
}

const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_PROCESS_KILL: u8 = 0x0c;
const COM_PING: u8 = 0x0e;
const COM_CHANGE_USER: u8 = 0x11;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_RESET: u8 = 0x1a;
const COM_SET_OPTION: u8 = 0x1b;
const COM_RESET_CONNECTION: u8 = 0x1f;

/// Enough of a packet to read the OK / EOF / prepare-OK fields.
const PREFIX: usize = 32;
const MAX_PAYLOAD: usize = 0x00ff_ffff;

impl MySqlTxTracker {
    /// `client_caps`: the HandshakeResponse capability flags (DEPRECATE_EOF is
    /// in effect when the client asks for it; every server since 5.7.5 grants it).
    pub fn new(client_caps: u32) -> Self {
        MySqlTxTracker {
            deprecate_eof: client_caps & CLIENT_DEPRECATE_EOF != 0,
            header: [0; 4],
            header_len: 0,
            payload_len: 0,
            remaining: 0,
            prefix: Vec::with_capacity(PREFIX),
            continuation: false,
            generation: 0,
            command: 0,
            phase: Phase::Done,
        }
    }

    pub fn feed(&mut self, mut bytes: &[u8], state: &ServerTxState) {
        while !bytes.is_empty() {
            if self.header_len < 4 {
                let n = (4 - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + n].copy_from_slice(&bytes[..n]);
                self.header_len += n;
                bytes = &bytes[n..];
                if self.header_len < 4 {
                    return;
                }
                self.payload_len =
                    u32::from_le_bytes([self.header[0], self.header[1], self.header[2], 0])
                        as usize;
                self.remaining = self.payload_len;
                self.prefix.clear();
                if self.remaining == 0 {
                    self.finish_packet(state);
                }
                continue;
            }
            let n = self.remaining.min(bytes.len());
            let want = PREFIX.saturating_sub(self.prefix.len()).min(n);
            self.prefix.extend_from_slice(&bytes[..want]);
            self.remaining -= n;
            bytes = &bytes[n..];
            if self.remaining == 0 {
                self.finish_packet(state);
            }
        }
    }

    fn finish_packet(&mut self, state: &ServerTxState) {
        self.header_len = 0;
        let continues = self.continuation;
        self.continuation = self.payload_len == MAX_PAYLOAD;
        if continues {
            return; // the tail of a packet of 16 MiB or more
        }
        let (generation, command) = state.mysql_command();
        if generation != self.generation {
            self.generation = generation;
            self.command = command;
            self.phase = match command {
                COM_CHANGE_USER => Phase::ChangeUser,
                COM_QUERY | COM_STMT_EXECUTE | COM_STMT_PREPARE | COM_INIT_DB | COM_PING
                | COM_PROCESS_KILL | COM_STMT_RESET | COM_SET_OPTION | COM_RESET_CONNECTION => {
                    Phase::Start
                }
                _ => Phase::Done,
            };
        }
        let p = std::mem::take(&mut self.prefix);
        self.step(&p, state);
        self.prefix = p;
    }

    fn is_eof(&self, p: &[u8]) -> bool {
        p.first() == Some(&0xfe) && self.payload_len < 9
    }

    /// The end of a result set: EOF, or with DEPRECATE_EOF an OK with a 0xFE header.
    fn is_terminator(&self, p: &[u8]) -> bool {
        p.first() == Some(&0xfe)
            && if self.deprecate_eof {
                self.payload_len < MAX_PAYLOAD
            } else {
                self.payload_len < 9
            }
    }

    fn step(&mut self, p: &[u8], state: &ServerTxState) {
        let first = p.first().copied();
        self.phase = match self.phase {
            Phase::Done => Phase::Done,
            Phase::ChangeUser => match first {
                Some(0x00) => {
                    record(ok_status(p), state);
                    Phase::Done
                }
                Some(0xff) => Phase::Done,
                _ => Phase::ChangeUser,
            },
            Phase::Start => match (self.command, first) {
                (_, None) | (_, Some(0xff)) => Phase::Done,
                (COM_STMT_PREPARE, Some(0x00)) => {
                    let cols = u16_at(p, 5).unwrap_or(0) as u64;
                    let params = u16_at(p, 7).unwrap_or(0) as u64;
                    self.prepare_next(params, cols)
                }
                (COM_STMT_PREPARE, _) => Phase::Done,
                (_, Some(0x00)) => self.after_status(ok_status(p), state),
                (_, Some(0xfe)) if self.is_eof(p) => self.after_status(eof_status(p), state),
                (COM_QUERY | COM_STMT_EXECUTE, Some(0xfb)) => Phase::Start, // LOCAL INFILE
                (COM_QUERY | COM_STMT_EXECUTE, Some(_)) => match read_lenenc(p) {
                    Some(n) if n > 0 => Phase::Columns(n),
                    _ => Phase::Done,
                },
                _ => Phase::Done,
            },
            Phase::Columns(n) => {
                if n > 1 {
                    Phase::Columns(n - 1)
                } else if self.deprecate_eof {
                    Phase::Rows
                } else {
                    Phase::ColumnsEof
                }
            }
            Phase::ColumnsEof => {
                if self.is_eof(p) {
                    record(eof_status(p), state);
                }
                Phase::Rows
            }
            Phase::Rows => match first {
                Some(0xff) => Phase::Done,
                Some(0xfe) if self.is_terminator(p) => {
                    let status = if self.deprecate_eof {
                        ok_status(p)
                    } else {
                        eof_status(p)
                    };
                    self.after_status(status, state)
                }
                _ => Phase::Rows,
            },
            Phase::PrepareParams(n, cols) => {
                if n > 1 {
                    Phase::PrepareParams(n - 1, cols)
                } else if self.deprecate_eof {
                    self.prepare_next(0, cols)
                } else {
                    Phase::PrepareParamsEof(cols)
                }
            }
            Phase::PrepareParamsEof(cols) => {
                if self.is_eof(p) {
                    record(eof_status(p), state);
                }
                self.prepare_next(0, cols)
            }
            Phase::PrepareColumns(n) => {
                if n > 1 {
                    Phase::PrepareColumns(n - 1)
                } else if self.deprecate_eof {
                    Phase::Done
                } else {
                    Phase::PrepareColumnsEof
                }
            }
            Phase::PrepareColumnsEof => {
                if self.is_eof(p) {
                    record(eof_status(p), state);
                }
                Phase::Done
            }
        };
    }

    fn prepare_next(&self, params: u64, cols: u64) -> Phase {
        if params > 0 {
            Phase::PrepareParams(params, cols)
        } else if cols > 0 {
            Phase::PrepareColumns(cols)
        } else {
            Phase::Done
        }
    }

    /// Records `status` and stays at a response start while more results follow.
    fn after_status(&self, status: Option<u16>, state: &ServerTxState) -> Phase {
        record(status, state);
        match status {
            Some(s) if s & MYSQL_MORE_RESULTS != 0 => Phase::Start,
            _ => Phase::Done,
        }
    }
}

fn record(status: Option<u16>, state: &ServerTxState) {
    if let Some(s) = status {
        state.set_mysql_flags(s);
    }
}

fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*p.get(at)?, *p.get(at + 1)?]))
}

/// Status flags of an OK packet: header, affected rows, last insert id, status.
pub fn ok_status(p: &[u8]) -> Option<u16> {
    let mut at = 1;
    for _ in 0..2 {
        at += lenenc_width(p.get(at..)?)?;
    }
    u16_at(p, at)
}

/// Status flags of an EOF packet: header, warnings, status.
fn eof_status(p: &[u8]) -> Option<u16> {
    u16_at(p, 3)
}

fn lenenc_width(b: &[u8]) -> Option<usize> {
    Some(match *b.first()? {
        0..=0xfa => 1,
        0xfc => 3,
        0xfd => 4,
        0xfe => 9,
        _ => return None,
    })
}

fn read_lenenc(b: &[u8]) -> Option<u64> {
    let width = lenenc_width(b)?;
    if width == 1 {
        return Some(b[0] as u64);
    }
    let bytes = b.get(1..width)?;
    Some(
        bytes
            .iter()
            .enumerate()
            .fold(0u64, |v, (i, byte)| v | ((*byte as u64) << (8 * i))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn pg_tracks_ready_for_query_across_any_chunking() {
        let mut stream = pg(b'C', b"BEGIN\0");
        stream.extend(pg(b'Z', b"T"));
        stream.extend(pg(b'D', &[0, 1, 0, 0, 0, 1, b'Z']));
        stream.extend(pg(b'E', b"SERROR\0\0"));
        stream.extend(pg(b'Z', b"E"));
        for chunk in 1..stream.len() {
            let state = ServerTxState::new();
            let mut t = PgTxTracker::new();
            let mut seen = Vec::new();
            for c in stream.chunks(chunk) {
                t.feed(c, &state);
                seen.push(state.pg_status());
            }
            assert_eq!(state.pg_status(), PG_FAILED_TRANSACTION, "chunk {chunk}");
            assert!(
                seen.contains(&PG_IN_TRANSACTION) || chunk > 12,
                "chunk {chunk}"
            );
        }
    }

    /// After the startup the relay walks whole messages in place: the same
    /// statuses as the byte-wise path, whatever the chunking.
    #[test]
    fn pg_tracks_ready_for_query_after_the_startup_across_any_chunking() {
        let mut stream = pg(b'K', &[0, 0, 0, 7, 1, 2, 3, 4]);
        stream.extend(pg(b'Z', b"I"));
        let mut ends = Vec::new();
        for (tag, status) in [("BEGIN", b'T'), ("SELECT 1", b'T'), ("ERROR", b'E')] {
            stream.extend(pg(b'T', b"\x00\x01a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00"));
            // A DataRow whose value looks like a ReadyForQuery.
            stream.extend(pg(b'D', &[0, 1, 0, 0, 0, 6, b'Z', 0, 0, 0, 5, b'X']));
            stream.extend(pg(b'C', format!("{tag}\0").as_bytes()));
            stream.extend(pg(b'Z', &[status]));
            ends.push((stream.len(), status));
        }
        stream.extend(pg(b'N', b"SNOTICE\x00\x00"));
        stream.extend(pg(b'Z', b"I"));
        ends.push((stream.len(), b'I'));
        for chunk in 1..=stream.len() {
            let state = ServerTxState::new();
            let mut t = PgTxTracker::new();
            let mut fed = 0;
            for c in stream.chunks(chunk) {
                t.feed(c, &state);
                fed += c.len();
                // At a ReadyForQuery boundary the state is that one's status.
                if let Some((_, status)) = ends.iter().find(|(end, _)| *end == fed) {
                    assert_eq!(state.pg_status(), *status, "chunk {chunk} at {fed}");
                }
            }
            assert_eq!(state.pg_status(), b'I', "chunk {chunk}");
            assert_eq!(
                t.take_backend_key().map(|k| k.pid),
                Some(7),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn pg_reads_the_backend_key_data_of_the_startup_across_any_chunking() {
        let mut stream = pg(b'R', &[0, 0, 0, 0]);
        stream.extend(pg(b'S', b"TimeZone\0UTC\0"));
        stream.extend(pg(b'K', &[0, 0, 0x10, 0x92, 0xde, 0xad, 0xbe, 0xef]));
        stream.extend(pg(b'Z', b"I"));
        // After the startup a 'K' is not a key (the server sends none).
        stream.extend(pg(b'K', &[0, 0, 0, 1, 1, 1, 1, 1]));
        for chunk in 1..stream.len() {
            let state = ServerTxState::new();
            let mut t = PgTxTracker::new();
            let mut keys = Vec::new();
            for c in stream.chunks(chunk) {
                t.feed(c, &state);
                keys.extend(t.take_backend_key());
            }
            assert_eq!(keys.len(), 1, "chunk {chunk}");
            assert_eq!(keys[0].pid, 0x1092, "chunk {chunk}");
            assert_eq!(
                &keys[0].secret[..],
                &[0xde, 0xad, 0xbe, 0xef],
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn pg_a_data_row_with_z_bytes_is_not_read_as_ready_for_query() {
        let state = ServerTxState::new();
        let mut t = PgTxTracker::new();
        t.feed(&pg(b'D', b"Z\0\0\0\x05T"), &state);
        assert_eq!(state.pg_status(), PG_IDLE);
    }

    fn my(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut out = len.to_le_bytes()[..3].to_vec();
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    fn ok(status: u16) -> Vec<u8> {
        let mut p = vec![0x00, 0x00, 0x00];
        p.extend_from_slice(&status.to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        p
    }

    #[test]
    fn mysql_ok_after_a_query_sets_the_flags() {
        let state = ServerTxState::new();
        let mut t = MySqlTxTracker::new(CLIENT_DEPRECATE_EOF);
        state.note_mysql_command(COM_QUERY);
        t.feed(&my(1, &ok(MYSQL_STATUS_IN_TRANS)), &state);
        assert_eq!(state.mysql_flags(), MYSQL_STATUS_IN_TRANS);
    }

    #[test]
    fn mysql_result_set_terminator_sets_the_flags_and_rows_are_skipped() {
        for deprecate in [true, false] {
            let caps = if deprecate { CLIENT_DEPRECATE_EOF } else { 0 };
            let state = ServerTxState::new();
            let mut t = MySqlTxTracker::new(caps);
            state.note_mysql_command(COM_QUERY);
            let mut s = my(1, &[0x01]); // one column
            s.extend(my(
                2,
                b"\x03def\x00\x00\x00\x01a\x00\x0c\x3f\x00\x0b\x00\x00\x00\x03\x00\x00\x00\x00\x00",
            ));
            let mut seq = 3;
            if !deprecate {
                s.extend(my(seq, &[0xfe, 0, 0, 0x02, 0x00]));
                seq += 1;
            }
            // A row whose only value is the empty string: first byte 0x00.
            s.extend(my(seq, &[0x00]));
            seq += 1;
            let status = MYSQL_STATUS_IN_TRANS;
            if deprecate {
                let mut p = vec![0xfe, 0x00, 0x00];
                p.extend_from_slice(&status.to_le_bytes());
                p.extend_from_slice(&[0, 0]);
                s.extend(my(seq, &p));
            } else {
                let mut p = vec![0xfe, 0, 0];
                p.extend_from_slice(&status.to_le_bytes());
                s.extend(my(seq, &p));
            }
            for c in s.chunks(3) {
                t.feed(c, &state);
            }
            assert_eq!(state.mysql_flags(), status, "deprecate_eof {deprecate}");
        }
    }

    #[test]
    fn mysql_prepare_ok_is_not_read_as_a_status() {
        let state = ServerTxState::new();
        let mut t = MySqlTxTracker::new(CLIENT_DEPRECATE_EOF);
        state.note_mysql_command(COM_STMT_PREPARE);
        // stmt id 1, 0 columns, 1 param: bytes 5..9 would read as flags 0xffff otherwise.
        t.feed(&my(1, &[0x00, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]), &state);
        t.feed(
            &my(
                2,
                b"\x03def\x00\x00\x00\x01?\x00\x0c\x3f\x00\x00\x00\x00\x00\xfd\x80\x00\x00\x00\x00",
            ),
            &state,
        );
        assert_eq!(state.mysql_flags(), MYSQL_STATUS_AUTOCOMMIT);
    }

    #[test]
    fn mysql_multi_results_keep_reading_until_the_last_ok() {
        let state = ServerTxState::new();
        let mut t = MySqlTxTracker::new(CLIENT_DEPRECATE_EOF);
        state.note_mysql_command(COM_QUERY);
        t.feed(
            &my(1, &ok(MYSQL_STATUS_AUTOCOMMIT | MYSQL_MORE_RESULTS)),
            &state,
        );
        t.feed(&my(2, &ok(MYSQL_STATUS_IN_TRANS)), &state);
        assert_eq!(state.mysql_flags(), MYSQL_STATUS_IN_TRANS);
    }

    #[test]
    fn mysql_an_unmodelled_command_keeps_the_last_flags() {
        let state = ServerTxState::new();
        let mut t = MySqlTxTracker::new(CLIENT_DEPRECATE_EOF);
        state.note_mysql_command(COM_QUERY);
        t.feed(&my(1, &ok(MYSQL_STATUS_IN_TRANS)), &state);
        state.note_mysql_command(0x09); // COM_STATISTICS: a plain string
        t.feed(&my(1, b"\x00Uptime: 1"), &state);
        assert_eq!(state.mysql_flags(), MYSQL_STATUS_IN_TRANS);
    }
}
