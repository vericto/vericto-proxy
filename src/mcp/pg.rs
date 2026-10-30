// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The PostgreSQL client of `vericto-proxy mcp` (design "MCP execution modes"
//! §5.3): the proxy's own `connect_upstream` (TCP, the SSL negotiation, rustls)
//! and the message encoders and SCRAM-SHA-256 client of `postgres-protocol`.
//! Not `tokio-postgres`: it sends statements of its own (type lookups in
//! `pg_type`) that would reach the database without passing the evaluator.
//! Every byte this module writes is a startup or authentication message, a
//! control statement (`control.rs`) or the statement `execute_once` hands it.
//!
//! The agent's statement goes through the extended protocol only: one unnamed
//! `Parse` (which the server refuses for more than one command), `Bind` with
//! text-format parameters, `Describe` portal, `Execute` with a row limit and
//! `Sync`. The simple `Query` message, which runs several statements, carries
//! control statements only.
//!
//! Rows are read as they arrive and bounded while they are read (rows, bytes,
//! bytes per cell), so a call never holds more than its byte cap plus one row.

use std::io;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use postgres_protocol::authentication::sasl;
use postgres_protocol::message::frontend;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::mcp::config::DatabaseTarget;
use crate::tcp::cancel::BackendKey;
use crate::tcp::upstream::{UpstreamRead, UpstreamTlsMode, UpstreamWrite, connect_upstream};

/// Largest backend message other than a `DataRow` accepted (a `RowDescription`
/// of the maximum 1,664 columns is about 140 KB).
const MAX_CONTROL_MESSAGE: usize = 1024 * 1024;

/// Why a connection could not be opened. `message` never contains the host,
/// the user or the password (design §6.5, `DATABASE_UNAVAILABLE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    /// `dns` | `tcp` | `tls` | `auth` | `startup` | `protocol`.
    pub step: &'static str,
    pub sqlstate: Option<String>,
    pub message: String,
}

impl ConnectError {
    fn new(step: &'static str, message: impl Into<String>) -> Self {
        Self {
            step,
            sqlstate: None,
            message: message.into(),
        }
    }
}

/// An `ErrorResponse`, field by field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbError {
    pub severity: String,
    pub sqlstate: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<String>,
    pub where_: Option<String>,
}

fn parse_error_fields(body: &[u8]) -> DbError {
    let mut e = DbError::default();
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let code = body[i];
        i += 1;
        let end = body[i..]
            .iter()
            .position(|&b| b == 0)
            .map_or(body.len(), |p| i + p);
        let value = String::from_utf8_lossy(&body[i..end]).into_owned();
        i = end + 1;
        match code {
            b'V' => e.severity = value,
            b'S' if e.severity.is_empty() => e.severity = value,
            b'C' => e.sqlstate = value,
            b'M' => e.message = value,
            b'D' => e.detail = Some(value),
            b'H' => e.hint = Some(value),
            b'P' => e.position = Some(value),
            b'W' => e.where_ = Some(value),
            _ => {}
        }
    }
    e
}

/// One result column (`RowDescription`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub type_oid: u32,
}

/// One value as the server sent it in text format, possibly cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// The bytes kept (at most the cell cap, fewer when the row hit the byte cap).
    pub bytes: Vec<u8>,
    /// The value's full length on the wire.
    pub full_len: usize,
}

impl Cell {
    pub fn truncated(&self) -> bool {
        self.bytes.len() < self.full_len
    }
}

/// Bounds of one read.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    /// Rows to keep; the statement is executed with one more, to learn
    /// whether there are more without reading them.
    pub max_rows: u32,
    pub max_cell_bytes: usize,
    /// Raw bytes of values kept, all rows together (the serialized cap is
    /// applied exactly when the result is built).
    pub max_result_bytes: usize,
}

/// What an extended-protocol run returned.
#[derive(Debug, Default)]
pub struct RunOutcome {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Option<Cell>>>,
    /// More rows exist than were kept: `max_rows` reached.
    pub more_rows: bool,
    /// Rows were dropped at the byte cap.
    pub byte_capped: bool,
    pub command_tag: Option<String>,
    pub error: Option<DbError>,
    /// From the first message sent to `ReadyForQuery`.
    pub db_time: Duration,
}

/// Why a run did not produce an outcome.
#[derive(Debug)]
pub enum RunError {
    /// The control batch failed (the statement was not sent).
    Control(DbError),
    /// The connection broke or the server broke the protocol.
    Io(io::Error),
}

impl From<io::Error> for RunError {
    fn from(e: io::Error) -> Self {
        RunError::Io(e)
    }
}

/// Where to send a `CancelRequest` for a running statement.
#[derive(Clone)]
pub struct CancelHandle {
    target: DatabaseTarget,
    key: BackendKey,
}

impl CancelHandle {
    /// Sends the `CancelRequest` on a new connection (TLS negotiated as for
    /// the session). Best effort: errors are logged, never surfaced.
    pub async fn cancel(&self) {
        let t = &self.target;
        let result = async {
            let (_r, mut w) = connect_upstream(
                &t.host,
                t.port,
                t.tls,
                t.ca_path.as_deref(),
                t.client_cert.as_deref(),
                t.client_key.as_deref(),
            )
            .await?;
            w.write_all(&self.key.cancel_request()).await?;
            w.flush().await
        };
        if let Err(e) = tokio::time::timeout(Duration::from_secs(5), result)
            .await
            .unwrap_or_else(|_| Err(io::Error::other("timed out")))
        {
            tracing::warn!(error_kind = ?e.kind(), "Could not send the CancelRequest to the database");
        }
    }
}

/// One open, authenticated connection.
pub struct PgConn {
    r: BufReader<UpstreamRead>,
    w: UpstreamWrite,
    key: Option<BackendKey>,
    target: DatabaseTarget,
    pub server_version: Option<String>,
    pub last_used: Instant,
    /// The transaction status of the last `ReadyForQuery`.
    pub status: u8,
    /// Something went wrong mid-protocol: never reused.
    pub broken: bool,
}

/// Connects and authenticates (design §5.3: SCRAM-SHA-256; MD5 only when
/// allowed; a cleartext password only over TLS or to loopback; `cert` through
/// the mutual-TLS pair).
pub async fn connect(target: &DatabaseTarget, allow_md5: bool) -> Result<PgConn, ConnectError> {
    // DNS first, so a failure names its step.
    if tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map(|mut a| a.next().is_none())
        .unwrap_or(true)
    {
        return Err(ConnectError::new(
            "dns",
            "could not resolve the database host",
        ));
    }
    let (r, w) = connect_upstream(
        &target.host,
        target.port,
        target.tls,
        target.ca_path.as_deref(),
        target.client_cert.as_deref(),
        target.client_key.as_deref(),
    )
    .await
    .map_err(|e| connect_io_error(e, target.tls))?;
    let mut conn = PgConn {
        r: BufReader::with_capacity(16 * 1024, r),
        w,
        key: None,
        target: target.clone(),
        server_version: None,
        last_used: Instant::now(),
        status: b'I',
        broken: false,
    };
    conn.startup(allow_md5).await?;
    Ok(conn)
}

/// A connect error, without anything that names the host (rustls messages
/// can quote the certificate's names).
fn connect_io_error(e: io::Error, tls: UpstreamTlsMode) -> ConnectError {
    let text = e.to_string();
    if tls != UpstreamTlsMode::Disable && text.contains("declined TLS") {
        return ConnectError::new("tls", "the database does not accept TLS connections");
    }
    match e.kind() {
        io::ErrorKind::ConnectionRefused => ConnectError::new("tcp", "connection refused"),
        io::ErrorKind::TimedOut => ConnectError::new("tcp", "connection timed out"),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            if text.contains("upstream") || text.contains("reading") =>
        {
            ConnectError::new(
                "tls",
                "a TLS file (UPSTREAM_SSLROOTCERT, UPSTREAM_SSLCERT or UPSTREAM_SSLKEY) cannot be read",
            )
        }
        _ if tls != UpstreamTlsMode::Disable
            && (text.contains("certificate") || text.contains("Certificate")) =>
        {
            ConnectError::new(
                "tls",
                "the database certificate did not verify (check sslmode and UPSTREAM_SSLROOTCERT)",
            )
        }
        _ if tls != UpstreamTlsMode::Disable => {
            ConnectError::new("tls", format!("the TLS handshake failed ({:?})", e.kind()))
        }
        kind => ConnectError::new("tcp", format!("could not connect ({kind:?})")),
    }
}

/// One backend message header.
struct Header {
    tag: u8,
    len: usize,
}

impl PgConn {
    pub fn cancel_handle(&self) -> Option<CancelHandle> {
        self.key.as_ref().map(|key| CancelHandle {
            target: self.target.clone(),
            key: key.clone(),
        })
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.w.write_all(buf).await?;
        self.w.flush().await
    }

    async fn header(&mut self) -> io::Result<Header> {
        let mut h = [0u8; 5];
        self.r.read_exact(&mut h).await?;
        let len = i32::from_be_bytes([h[1], h[2], h[3], h[4]]);
        if len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid backend message length",
            ));
        }
        Ok(Header {
            tag: h[0],
            len: len as usize - 4,
        })
    }

    async fn body(&mut self, h: &Header) -> io::Result<Vec<u8>> {
        if h.len > MAX_CONTROL_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("backend message '{}' too large", h.tag as char),
            ));
        }
        let mut b = vec![0u8; h.len];
        self.r.read_exact(&mut b).await?;
        Ok(b)
    }

    async fn message(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let h = self.header().await?;
        let b = self.body(&h).await?;
        Ok((h.tag, b))
    }

    async fn startup(&mut self, allow_md5: bool) -> Result<(), ConnectError> {
        let mut buf = BytesMut::new();
        let params = [
            ("user", self.target.user.as_str()),
            ("database", self.target.dbname.as_str()),
            ("client_encoding", "UTF8"),
            ("application_name", "vericto-proxy-mcp"),
        ];
        frontend::startup_message(params.iter().copied(), &mut buf)
            .map_err(|_| ConnectError::new("startup", "the user or database name is not valid"))?;
        let io = |e: io::Error| {
            ConnectError::new("startup", format!("connection lost ({:?})", e.kind()))
        };
        self.write(&buf).await.map_err(io)?;

        let tls = self.target.tls != UpstreamTlsMode::Disable;
        let mut scram: Option<sasl::ScramSha256> = None;
        let password = self.target.password.clone();
        loop {
            let (tag, body) = self.message().await.map_err(io)?;
            match tag {
                b'R' => {
                    if body.len() < 4 {
                        return Err(ConnectError::new(
                            "protocol",
                            "short authentication message",
                        ));
                    }
                    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let data = &body[4..];
                    let mut out = BytesMut::new();
                    match code {
                        0 => continue, // AuthenticationOk
                        3 => {
                            if !tls && !self.target.is_loopback() {
                                return Err(ConnectError::new(
                                    "auth",
                                    "the database asked for a cleartext password over a connection without TLS; refused",
                                ));
                            }
                            frontend::password_message(password.expose().as_bytes(), &mut out)
                                .map_err(|_| {
                                    ConnectError::new("auth", "the password is not valid")
                                })?;
                        }
                        5 => {
                            if !allow_md5 {
                                return Err(ConnectError::new(
                                    "auth",
                                    "the database asked for MD5 password authentication, which is refused \
                                     (use SCRAM-SHA-256, or set VERICTO_MCP_ALLOW_MD5=true)",
                                ));
                            }
                            if data.len() < 4 {
                                return Err(ConnectError::new("protocol", "short MD5 salt"));
                            }
                            let salt = [data[0], data[1], data[2], data[3]];
                            let hash = postgres_protocol::authentication::md5_hash(
                                self.target.user.as_bytes(),
                                password.expose().as_bytes(),
                                salt,
                            );
                            frontend::password_message(hash.as_bytes(), &mut out).map_err(
                                |_| ConnectError::new("auth", "the password is not valid"),
                            )?;
                        }
                        10 => {
                            let mechanisms: Vec<&[u8]> =
                                data.split(|&b| b == 0).filter(|m| !m.is_empty()).collect();
                            if !mechanisms.contains(&sasl::SCRAM_SHA_256.as_bytes()) {
                                return Err(ConnectError::new(
                                    "auth",
                                    "the database offers no SASL mechanism this client supports (SCRAM-SHA-256)",
                                ));
                            }
                            let binding = if tls {
                                sasl::ChannelBinding::unrequested()
                            } else {
                                sasl::ChannelBinding::unsupported()
                            };
                            let s = sasl::ScramSha256::new(password.expose().as_bytes(), binding);
                            frontend::sasl_initial_response(
                                sasl::SCRAM_SHA_256,
                                s.message(),
                                &mut out,
                            )
                            .map_err(|_| ConnectError::new("auth", "SCRAM failed"))?;
                            scram = Some(s);
                        }
                        11 => {
                            let s = scram.as_mut().ok_or_else(|| {
                                ConnectError::new("protocol", "unexpected SASL continue")
                            })?;
                            s.update(data).map_err(|_| {
                                ConnectError::new("auth", "the SCRAM exchange failed")
                            })?;
                            frontend::sasl_response(s.message(), &mut out)
                                .map_err(|_| ConnectError::new("auth", "SCRAM failed"))?;
                        }
                        12 => {
                            let s = scram.as_mut().ok_or_else(|| {
                                ConnectError::new("protocol", "unexpected SASL final")
                            })?;
                            s.finish(data).map_err(|_| {
                                ConnectError::new(
                                    "auth",
                                    "the server's SCRAM signature did not verify",
                                )
                            })?;
                            continue;
                        }
                        other => {
                            return Err(ConnectError::new(
                                "auth",
                                format!(
                                    "the database asked for an authentication method this client does not support (code {other})"
                                ),
                            ));
                        }
                    }
                    self.write(&out).await.map_err(io)?;
                }
                b'E' => {
                    let e = parse_error_fields(&body);
                    let step = if e.sqlstate.starts_with("28") {
                        "auth"
                    } else {
                        "startup"
                    };
                    // The message of an auth failure names the user; only the
                    // class is kept.
                    let message = match e.sqlstate.as_str() {
                        "28P01" => "password authentication failed".to_string(),
                        "28000" => {
                            "the role is not allowed to log in from here (pg_hba)".to_string()
                        }
                        "3D000" => "the database does not exist".to_string(),
                        "53300" => "too many connections".to_string(),
                        "57P03" => "the database is starting up or shutting down".to_string(),
                        s => format!("the database refused the connection (SQLSTATE {s})"),
                    };
                    return Err(ConnectError {
                        step,
                        sqlstate: Some(e.sqlstate),
                        message,
                    });
                }
                b'S' => {
                    let mut parts = body.split(|&b| b == 0);
                    let name = parts.next().unwrap_or_default();
                    let value = parts.next().unwrap_or_default();
                    match name {
                        b"server_version" => {
                            self.server_version = Some(String::from_utf8_lossy(value).into_owned());
                            crate::tcp::upstream_version::global().observe_postgres(
                                &format!("{}:{}", self.target.host, self.target.port),
                                value,
                            );
                        }
                        b"client_encoding" if !value.eq_ignore_ascii_case(b"UTF8") => {
                            return Err(ConnectError::new(
                                "startup",
                                "the server did not accept client_encoding UTF8",
                            ));
                        }
                        _ => {}
                    }
                }
                b'K' => self.key = BackendKey::parse(&body),
                b'Z' => {
                    self.status = body.first().copied().unwrap_or(b'I');
                    return Ok(());
                }
                b'N' | b'v' => {}
                other => {
                    return Err(ConnectError::new(
                        "protocol",
                        format!("unexpected message '{}' during startup", other as char),
                    ));
                }
            }
        }
    }

    /// Runs a control batch (simple query) and returns the transaction status
    /// it ended in, or the first error.
    pub async fn control(&mut self, text: &str) -> Result<u8, RunError> {
        let mut buf = BytesMut::new();
        frontend::query(text, &mut buf)?;
        self.write(&buf).await?;
        let mut error = None;
        loop {
            let (tag, body) = self.message().await?;
            match tag {
                b'C' | b'N' | b'S' | b'I' | b'T' | b'D' | b'A' => {}
                b'E' => error = Some(parse_error_fields(&body)),
                b'Z' => {
                    self.status = body.first().copied().unwrap_or(b'?');
                    return match error {
                        Some(e) => Err(RunError::Control(e)),
                        None => Ok(self.status),
                    };
                }
                other => {
                    self.broken = true;
                    return Err(RunError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected message '{}'", other as char),
                    )));
                }
            }
        }
    }

    /// Sends `sql` exactly (one unnamed Parse) with `params` bound as text,
    /// executes it with `limits.max_rows + 1` rows, and reads the result
    /// within `limits`. Pipelines `then` (a control statement) after the
    /// `Sync` and reads its answer too, so the call ends in one round trip.
    pub async fn run(
        &mut self,
        sql: &str,
        params: &[Option<String>],
        limits: ReadLimits,
        then: &str,
    ) -> Result<RunOutcome, RunError> {
        let mut buf = BytesMut::new();
        // Parameter types are left to the server (0 = unspecified), as a
        // driver that sends text values does.
        frontend::parse("", sql, std::iter::empty(), &mut buf)?;
        frontend::bind(
            "",
            "",
            std::iter::empty::<i16>(), // no codes: every parameter in text format
            params,
            |p, out| match p {
                None => Ok(postgres_protocol::IsNull::Yes),
                Some(v) => {
                    out.extend_from_slice(v.as_bytes());
                    Ok(postgres_protocol::IsNull::No)
                }
            },
            std::iter::empty::<i16>(), // no codes: every result column in text format
            &mut buf,
        )
        .map_err(|e| match e {
            frontend::BindError::Conversion(e) => io::Error::other(e),
            frontend::BindError::Serialization(e) => e,
        })?;
        frontend::describe(b'P', "", &mut buf)?;
        let execute_rows = limits.max_rows.saturating_add(1).min(i32::MAX as u32) as i32;
        frontend::execute("", execute_rows, &mut buf)?;
        frontend::sync(&mut buf);
        frontend::query(then, &mut buf)?;

        let started = Instant::now();
        self.write(&buf).await?;
        let mut out = RunOutcome::default();
        let mut used = 0usize;
        let mut first_z = true;
        loop {
            let h = self.header().await?;
            match h.tag {
                b'D' => {
                    let row = self.data_row(&h, limits, used, out.rows.is_empty()).await?;
                    if out.more_rows || out.byte_capped {
                        continue;
                    }
                    if out.rows.len() as u32 >= limits.max_rows {
                        out.more_rows = true;
                        continue;
                    }
                    match row {
                        Some((cells, size)) => {
                            used += size;
                            out.rows.push(cells);
                        }
                        None => out.byte_capped = true,
                    }
                }
                b'T' => {
                    let body = self.body(&h).await?;
                    out.columns = parse_row_description(&body)?;
                }
                b'C' => {
                    let body = self.body(&h).await?;
                    if first_z {
                        out.command_tag = Some(
                            String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body))
                                .into_owned(),
                        );
                    }
                }
                b's' => {
                    self.body(&h).await?;
                    out.more_rows = true;
                }
                b'E' => {
                    let body = self.body(&h).await?;
                    let e = parse_error_fields(&body);
                    if first_z {
                        out.error.get_or_insert(e);
                    } else {
                        // The pipelined control statement failed: the
                        // connection is in an unknown state.
                        self.broken = true;
                    }
                }
                b'Z' => {
                    let body = self.body(&h).await?;
                    self.status = body.first().copied().unwrap_or(b'?');
                    if first_z {
                        out.db_time = started.elapsed();
                        first_z = false;
                    } else {
                        return Ok(out);
                    }
                }
                b'1' | b'2' | b'n' | b'I' | b'N' | b'A' | b't' => {
                    self.body(&h).await?;
                }
                b'S' => {
                    let body = self.body(&h).await?;
                    let mut parts = body.split(|&b| b == 0);
                    if parts.next() == Some(b"client_encoding".as_slice())
                        && parts
                            .next()
                            .is_some_and(|v| !v.eq_ignore_ascii_case(b"UTF8"))
                    {
                        // Nothing the agent can send changes it; if it changed
                        // anyway, this connection is not reused.
                        self.broken = true;
                    }
                }
                other => {
                    self.broken = true;
                    return Err(RunError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected message '{}'", other as char),
                    )));
                }
            }
        }
    }

    /// Reads one `DataRow` without holding more than the caps: every cell cut
    /// at the cell cap, and the row's cells cut to what is left of the byte cap
    /// when it is the first row (a first row is returned cut, never dropped).
    /// `None` (row dropped, the rest of it discarded) when a later row does
    /// not fit the byte cap.
    async fn data_row(
        &mut self,
        h: &Header,
        limits: ReadLimits,
        used: usize,
        first: bool,
    ) -> io::Result<Option<(Vec<Option<Cell>>, usize)>> {
        let mut remaining_msg = h.len;
        let mut take = |n: usize| -> io::Result<()> {
            if n > remaining_msg {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed DataRow",
                ));
            }
            remaining_msg -= n;
            Ok(())
        };
        take(2)?;
        let mut n = [0u8; 2];
        self.r.read_exact(&mut n).await?;
        let count = u16::from_be_bytes(n) as usize;
        let mut cells = Vec::with_capacity(count.min(1664));
        let mut size = 0usize;
        let mut fits = true;
        for _ in 0..count {
            take(4)?;
            let mut l = [0u8; 4];
            self.r.read_exact(&mut l).await?;
            let len = i32::from_be_bytes(l);
            if len < 0 {
                cells.push(None);
                size += 4; // `null`
                continue;
            }
            let len = len as usize;
            take(len)?;
            let budget_left = limits.max_result_bytes.saturating_sub(used + size);
            let keep = if fits {
                if first {
                    len.min(limits.max_cell_bytes).min(budget_left)
                } else {
                    len.min(limits.max_cell_bytes)
                }
            } else {
                0
            };
            let mut bytes = vec![0u8; keep];
            self.r.read_exact(&mut bytes).await?;
            discard(&mut self.r, len - keep).await?;
            size += keep + 2;
            if !first && used + size > limits.max_result_bytes {
                fits = false;
            }
            cells.push(Some(Cell {
                bytes,
                full_len: len,
            }));
        }
        if remaining_msg > 0 {
            discard(&mut self.r, remaining_msg).await?;
        }
        Ok(fits.then_some((cells, size)))
    }
}

async fn discard<R: AsyncRead + Unpin>(r: &mut R, mut n: usize) -> io::Result<()> {
    let mut sink = [0u8; 8192];
    while n > 0 {
        let k = n.min(sink.len());
        r.read_exact(&mut sink[..k]).await?;
        n -= k;
    }
    Ok(())
}

fn parse_row_description(body: &[u8]) -> io::Result<Vec<Column>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed RowDescription");
    if body.len() < 2 {
        return Err(bad());
    }
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut i = 2;
    let mut cols = Vec::with_capacity(count);
    for _ in 0..count {
        let end = body[i..].iter().position(|&b| b == 0).ok_or_else(bad)? + i;
        let name = String::from_utf8_lossy(&body[i..end]).into_owned();
        i = end + 1;
        if body.len() < i + 18 {
            return Err(bad());
        }
        let type_oid = u32::from_be_bytes([body[i + 6], body[i + 7], body[i + 8], body[i + 9]]);
        i += 18;
        cols.push(Column { name, type_oid });
    }
    Ok(cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_fields_are_read_by_code() {
        let mut b = Vec::new();
        for (c, v) in [
            (b'S', "ERROR"),
            (b'V', "ERROR"),
            (b'C', "22P02"),
            (
                b'M',
                "invalid input syntax for type integer: \"123-45-6789\"",
            ),
            (b'D', "detail"),
            (b'W', "SQL function"),
        ] {
            b.push(c);
            b.extend_from_slice(v.as_bytes());
            b.push(0);
        }
        b.push(0);
        let e = parse_error_fields(&b);
        assert_eq!(e.sqlstate, "22P02");
        assert_eq!(e.severity, "ERROR");
        assert!(e.message.contains("123-45-6789"));
        assert_eq!(e.detail.as_deref(), Some("detail"));
        assert_eq!(e.where_.as_deref(), Some("SQL function"));
    }

    #[test]
    fn connect_errors_never_name_the_host() {
        let e = connect_io_error(
            io::Error::other(
                "invalid peer certificate: NotValidForName for db.secret-host.internal",
            ),
            UpstreamTlsMode::VerifyFull,
        );
        assert_eq!(e.step, "tls");
        assert!(!e.message.contains("secret-host"), "{}", e.message);
    }
}
