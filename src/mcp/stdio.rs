// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The stdio transport (design "MCP execution modes" §5.4): newline-delimited
//! JSON-RPC on stdin/stdout. **stdout carries protocol messages only**: logs go
//! to stderr (`main.rs` sets that up before anything else runs in `mcp` mode).
//! Requests run concurrently; each answer is written as one line. The process
//! ends when stdin closes, after the calls in flight have answered.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::mcp::runtime::Runtime;
use crate::mcp::server::{self, Peer};

/// Calls of one stdio client answered concurrently.
const MAX_IN_FLIGHT: usize = 64;

/// Serves one client on `input`/`output` until `input` closes.
pub async fn serve<R, W>(rt: Arc<Runtime>, input: R, output: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // A line holds one statement JSON-escaped (at most 6 bytes per byte for
    // control characters) plus the envelope.
    let max_line = rt
        .cfg
        .max_query_bytes
        .saturating_mul(6)
        .saturating_add(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut out = output;
        while let Some(line) = rx.recv().await {
            if out.write_all(line.as_bytes()).await.is_err()
                || out.write_all(b"\n").await.is_err()
                || out.flush().await.is_err()
            {
                break;
            }
        }
    });
    let peer = Arc::new(Peer::stdio());
    let mut reader = BufReader::with_capacity(64 * 1024, input);
    let mut tasks = tokio::task::JoinSet::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line(&mut reader, &mut line, max_line).await {
            Ok(Line::Eof) => break,
            Ok(Line::TooLong) => {
                let _ = tx.send(
                    server::error_response(
                        serde_json::Value::Null,
                        server::PARSE_ERROR,
                        "message too large",
                    )
                    .to_string(),
                );
                continue;
            }
            Ok(Line::Data) => {}
            Err(e) => {
                tracing::warn!(error_kind = ?e.kind(), "stdin read failed; stopping");
                break;
            }
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let msg: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                let _ = tx.send(
                    server::error_response(
                        serde_json::Value::Null,
                        server::PARSE_ERROR,
                        "invalid JSON",
                    )
                    .to_string(),
                );
                continue;
            }
        };
        let (rt, peer, tx) = (Arc::clone(&rt), Arc::clone(&peer), tx.clone());
        // `initialize` is handled in line, so the clientInfo it declares is
        // known to every call after it.
        let is_init = msg.get("method").and_then(serde_json::Value::as_str) == Some("initialize");
        if is_init {
            if let Some(resp) = server::handle(&rt, &peer, msg).await {
                let _ = tx.send(resp.to_string());
            }
            continue;
        }
        // At most this many calls in flight; reading waits for one to end.
        while tasks.len() >= MAX_IN_FLIGHT {
            let _ = tasks.join_next().await;
        }
        tasks.spawn(async move {
            if let Some(resp) = server::handle(&rt, &peer, msg).await {
                let _ = tx.send(resp.to_string());
            }
        });
        while tasks.try_join_next().is_some() {}
    }
    // stdin closed: let the calls in flight answer (each is bounded by its
    // statement timeout), then stop.
    let grace = Duration::from_millis(u64::from(rt.cfg.limits.statement_timeout_cap_ms) + 15_000);
    let _ = tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
    drop(tx);
    let _ = writer.await;
}

enum Line {
    Data,
    TooLong,
    Eof,
}

/// One line into `buf`, without its newline; a line over `max` is skipped.
async fn read_line<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Line> {
    let mut too_long = false;
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() && !too_long {
                Line::Eof
            } else if too_long {
                Line::TooLong
            } else {
                Line::Data
            });
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (&available[..i], Some(i + 1)),
            None => (available, None),
        };
        if !too_long {
            if buf.len() + chunk.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let consumed = done.unwrap_or(available.len());
        r.consume(consumed);
        if done.is_some() {
            return Ok(if too_long { Line::TooLong } else { Line::Data });
        }
    }
}
