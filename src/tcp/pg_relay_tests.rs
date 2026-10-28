// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The PostgreSQL backend relay of 4.17.2 (`postgres::relay_server_to_client`),
//! driven directly: a scripted upstream on one side of an in-memory pipe, a
//! client on the other, the response coordinator in between.
//!
//! - **One write per upstream read:** the messages one read holds whole reach
//!   the client in one write and one flush (4.17.1 wrote and flushed each
//!   message: one TLS record, `sendmsg` and TCP segment per message).
//! - **Bytes as read:** with no local reply planned, the client receives the
//!   server's bytes unchanged, whatever the upstream chunking, including
//!   messages around and above the relay buffer and long DataRow / COPY OUT
//!   streams; the ReadyForQuery status and the BackendKeyData are tracked
//!   before the bytes are exposed.
//! - **Local replies in place:** a local rejection planned in the middle of
//!   pipelined groups replaces exactly its own response, at every chunking.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;

use crate::tcp::cancel::CancelRegistry;
use crate::tcp::client_tls::ClientWrite;
use crate::tcp::pg_response::{PgResponseCoordinator, PlanKind};
use crate::tcp::tx_state::{PG_FAILED_TRANSACTION, PG_IDLE, PG_IN_TRANSACTION, ServerTxState};

/// The relay's buffer size (`postgres::RELAY_BUFFER`).
const BUFFER: usize = 64 * 1024;

fn pg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A message whose whole frame (tag + length + body) is `total` bytes, its body
/// a pattern that shows any reordering or interleaving.
fn sized(tag: u8, total: usize, seed: u8) -> Vec<u8> {
    let body: Vec<u8> = (0..total - 5)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect();
    pg(tag, &body)
}

/// Counts the client writes and flushes the relay makes.
struct Counting {
    inner: DuplexStream,
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(_))) {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(poll, Poll::Ready(Ok(()))) {
            self.flushes.fetch_add(1, Ordering::SeqCst);
        }
        poll
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Relay {
    /// What the server sends.
    upstream: DuplexStream,
    /// What the client receives.
    client: DuplexStream,
    responses: PgResponseCoordinator,
    tx: Arc<ServerTxState>,
    keys: Arc<CancelRegistry>,
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// A relay in the startup phase (`after_startup` false) or after it.
fn relay(after_startup: bool) -> Relay {
    let (upstream, relay_upstream) = tokio::io::duplex(1 << 22);
    let (relay_client, client) = tokio::io::duplex(1 << 24);
    let writes = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let client_write: ClientWrite = Box::new(Counting {
        inner: relay_client,
        writes: writes.clone(),
        flushes: flushes.clone(),
    });
    let responses = PgResponseCoordinator::new();
    if after_startup {
        responses.complete_startup().unwrap();
    }
    let tx = Arc::new(ServerTxState::new());
    let keys = Arc::new(CancelRegistry::default());
    let task = tokio::spawn(crate::tcp::postgres::relay_server_to_client(
        Box::new(relay_upstream),
        Arc::new(Mutex::new(client_write)),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        tx.clone(),
        Some(keys.clone()),
        responses.clone(),
        None,
    ));
    Relay {
        upstream,
        client,
        responses,
        tx,
        keys,
        writes,
        flushes,
        task,
    }
}

impl Relay {
    async fn plan(&self, kind: PlanKind, n: usize) {
        for _ in 0..n {
            self.responses
                .register(kind, None, false, None)
                .await
                .unwrap();
        }
    }

    /// Sends `bytes` in pieces of the widths given (cycled), yielding between
    /// them so that the relay sees them as separate reads.
    async fn send_split(&mut self, bytes: &[u8], widths: &[usize]) {
        let mut offset = 0;
        let mut i = 0;
        while offset < bytes.len() {
            let width = widths[i % widths.len()].max(1);
            let end = bytes.len().min(offset + width);
            self.upstream.write_all(&bytes[offset..end]).await.unwrap();
            self.upstream.flush().await.unwrap();
            offset = end;
            i += 1;
            tokio::task::yield_now().await;
        }
    }

    async fn receive(&mut self, n: usize) -> Vec<u8> {
        let mut got = vec![0u8; n];
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            self.client.read_exact(&mut got),
        )
        .await
        .expect("the client receives the relayed bytes")
        .unwrap();
        got
    }

    /// Closes the upstream and returns the relay's result.
    async fn end(self) -> std::io::Result<()> {
        drop(self.upstream);
        tokio::time::timeout(std::time::Duration::from_secs(10), self.task)
            .await
            .expect("the relay ends with the upstream")
            .unwrap()
    }
}

fn startup() -> Vec<u8> {
    let mut s = pg(b'R', &[0, 0, 0, 0]);
    s.extend(pg(b'S', b"TimeZone\0UTC\0"));
    s.extend(pg(b'K', &[0, 0, 0x10, 0x92, 0xde, 0xad, 0xbe, 0xef]));
    s.extend(pg(b'Z', b"I"));
    s
}

/// Three simple-protocol replies (BEGIN; a row whose value looks like a
/// ReadyForQuery; an error), a notice and a COMMIT, with their statuses.
fn simple_replies() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend(pg(b'C', b"BEGIN\0"));
    s.extend(pg(b'Z', &[PG_IN_TRANSACTION]));
    s.extend(pg(
        b'T',
        b"\x00\x01a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00",
    ));
    s.extend(pg(b'D', &[0, 1, 0, 0, 0, 6, b'Z', 0, 0, 0, 5, b'X']));
    s.extend(pg(b'C', b"SELECT 1\0"));
    s.extend(pg(b'Z', &[PG_IN_TRANSACTION]));
    s.extend(pg(b'E', b"SERROR\0C22012\0Mdivision by zero\0\0"));
    s.extend(pg(b'Z', &[PG_FAILED_TRANSACTION]));
    s.extend(pg(b'N', b"SNOTICE\0\0"));
    s.extend(pg(b'C', b"ROLLBACK\0"));
    s.extend(pg(b'Z', &[PG_IDLE]));
    s
}

/// The messages of one upstream read reach the client in one write and one
/// flush: the 4.17.1 regression (a write and a flush per message) cannot
/// come back unnoticed.
#[tokio::test]
async fn one_upstream_read_is_one_client_write_and_one_flush() {
    let mut r = relay(true);
    // An extended select: Parse, Bind, Describe, Execute, Sync.
    for kind in [
        PlanKind::Parse,
        PlanKind::Bind,
        PlanKind::Describe,
        PlanKind::Execute,
        PlanKind::Sync,
    ] {
        r.plan(kind, 1).await;
    }
    let mut reply = pg(b'1', b"");
    reply.extend(pg(b'2', b""));
    reply.extend(pg(
        b'T',
        b"\x00\x01a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00",
    ));
    reply.extend(pg(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
    reply.extend(pg(b'C', b"SELECT 1\0"));
    reply.extend(pg(b'Z', b"I"));
    r.upstream.write_all(&reply).await.unwrap();
    assert_eq!(r.receive(reply.len()).await, reply);
    assert_eq!(r.writes.load(Ordering::SeqCst), 1, "one write");
    assert_eq!(r.flushes.load(Ordering::SeqCst), 1, "one flush");
    assert!(!r.responses.has_plans().unwrap(), "every plan completed");
    r.end().await.unwrap();
}

/// The startup and the replies after it reach the client byte for byte at
/// every chunking of the upstream stream, from one byte at a time to all at
/// once. The status of the last ReadyForQuery and the startup's key are
/// tracked; a DataRow whose value looks like a ReadyForQuery is not one.
#[tokio::test]
async fn bytes_are_relayed_unchanged_at_every_upstream_chunking() {
    let mut stream = startup();
    let replies = simple_replies();
    stream.extend(&replies);
    for width in 1..=stream.len() {
        let mut r = relay(false);
        r.plan(PlanKind::Simple, 4).await;
        r.send_split(&stream, &[width]).await;
        assert_eq!(r.receive(stream.len()).await, stream, "width {width}");
        assert_eq!(r.tx.pg_status(), PG_IDLE, "width {width}");
        assert_eq!(r.keys.len(), 1, "the startup key is registered");
        assert!(!r.responses.has_plans().unwrap(), "width {width}");
        let keys = r.keys.clone();
        r.end().await.unwrap();
        assert_eq!(keys.len(), 0, "the key leaves with the session");
    }
}

/// The status a ReadyForQuery carries is set before the client receives it.
#[tokio::test]
async fn ready_for_query_status_is_tracked_before_the_client_sees_it() {
    let mut r = relay(true);
    r.plan(PlanKind::Simple, 1).await;
    let mut reply = pg(b'C', b"BEGIN\0");
    reply.extend(pg(b'Z', &[PG_IN_TRANSACTION]));
    r.upstream.write_all(&reply).await.unwrap();
    r.receive(reply.len()).await;
    assert_eq!(r.tx.pg_status(), PG_IN_TRANSACTION);
    r.end().await.unwrap();
}

/// A long result: many small DataRows and rows just under, at, and just over
/// the relay buffer, and several times larger, fragmented around the buffer
/// size. Every byte arrives in order and the plan completes at the end.
#[tokio::test]
async fn large_data_row_streams_and_rows_around_the_buffer_size() {
    let mut stream = pg(
        b'T',
        b"\x00\x01a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\xff\xff\xff\xff\xff\xff\x00\x00",
    );
    for i in 0..3000usize {
        stream.extend(sized(b'D', 11 + i % 300, i as u8));
    }
    for (i, total) in [
        BUFFER - 1,
        BUFFER,
        BUFFER + 1,
        BUFFER + 4,
        BUFFER + 5,
        BUFFER + 6,
        3 * BUFFER + 17,
        5,
        BUFFER / 2,
        2 * BUFFER,
    ]
    .into_iter()
    .enumerate()
    {
        stream.extend(sized(b'D', total.max(5), i as u8));
    }
    stream.extend(pg(b'C', b"SELECT 3010\0"));
    stream.extend(pg(b'Z', b"I"));
    for widths in [
        &[usize::MAX][..],
        &[BUFFER - 1, BUFFER, BUFFER + 1][..],
        &[1, 4, 5, 6, 4093, BUFFER - 5, 7][..],
        &[3, BUFFER + 5, 2][..],
        &[16 * 1024 - 1, 16 * 1024 + 1][..],
    ] {
        let mut r = relay(true);
        r.plan(PlanKind::Simple, 1).await;
        let sender = {
            let stream = stream.clone();
            let widths = widths.to_vec();
            let mut upstream = std::mem::replace(&mut r.upstream, tokio::io::duplex(1).0);
            tokio::spawn(async move {
                let mut offset = 0;
                let mut i = 0;
                while offset < stream.len() {
                    let end = stream
                        .len()
                        .min(offset.saturating_add(widths[i % widths.len()]));
                    upstream.write_all(&stream[offset..end]).await.unwrap();
                    upstream.flush().await.unwrap();
                    offset = end;
                    i += 1;
                    tokio::task::yield_now().await;
                }
                upstream
            })
        };
        let got = r.receive(stream.len()).await;
        assert!(got == stream, "widths {widths:?}");
        r.upstream = sender.await.unwrap();
        assert!(!r.responses.has_plans().unwrap(), "widths {widths:?}");
        r.end().await.unwrap();
    }
}

/// COPY OUT: CopyOutResponse, CopyData rows (one larger than the buffer),
/// CopyDone, CommandComplete, ReadyForQuery, then a pipelined simple
/// statement the proxy refused locally (its marker cycle answered by the
/// server): the COPY bytes go out unchanged, and the local reply takes the
/// marker's place before the server's ReadyForQuery.
#[tokio::test]
async fn copy_out_then_a_local_reply_in_order_at_every_chunking() {
    let mut copy = pg(b'H', &[0, 0, 1, 0, 0]);
    for i in 0..500usize {
        copy.extend(pg(b'd', format!("{i}\trow {i}\n").as_bytes()));
    }
    copy.extend(sized(b'd', BUFFER + 100, 9));
    copy.extend(pg(b'c', b""));
    copy.extend(pg(b'C', b"COPY 501\0"));
    copy.extend(pg(b'Z', b"I"));
    let marker = {
        let mut m = pg(b'I', b"");
        m.extend(pg(b'Z', b"I"));
        m
    };
    let refusal = crate::tcp::codec::build_error_response("42501", "Vericto: refused");
    let mut stream = copy.clone();
    stream.extend(&marker);
    let mut expected = copy.clone();
    expected.extend(&refusal);
    expected.extend(pg(b'Z', b"I"));
    for widths in [
        &[usize::MAX][..],
        &[1][..],
        &[7, BUFFER, 3][..],
        &[copy.len() - 1, 1, 1][..],
    ] {
        let mut r = relay(true);
        r.plan(PlanKind::Simple, 1).await;
        r.responses
            .register(PlanKind::Simple, Some(refusal.clone()), false, None)
            .await
            .unwrap();
        if widths == [1] {
            // One byte at a time is slow for 70 KiB: only the first part.
            let head = copy.len() - BUFFER - 200;
            r.send_split(&stream[..head], &[1]).await;
            r.send_split(&stream[head..], &[4096]).await;
        } else {
            r.send_split(&stream, widths).await;
        }
        assert!(
            r.receive(expected.len()).await == expected,
            "widths {widths:?}"
        );
        assert!(!r.responses.has_plans().unwrap());
        r.end().await.unwrap();
    }
}

/// Three pipelined extended groups; the middle one was refused locally (its
/// Parse replaced by an invalid one, so the server answers with an error and
/// skips to Sync). The client receives group 1, the local refusal in place of
/// the server's error, the server's ReadyForQuery, then group 3, at every
/// chunking of the upstream stream.
#[tokio::test]
async fn pipelined_groups_with_a_local_block_in_the_middle_at_every_chunking() {
    let refusal = crate::tcp::codec::build_error_response("42501", "Vericto: refused");
    let group = |rows: usize| {
        let mut g = pg(b'1', b"");
        g.extend(pg(b'2', b""));
        for i in 0..rows {
            g.extend(sized(b'D', 40, i as u8));
        }
        g.extend(pg(b'C', b"SELECT 1\0"));
        g.extend(pg(b'Z', b"I"));
        g
    };
    let server_error = crate::tcp::codec::build_error_response("42601", "syntax error");
    let mut stream = group(3);
    stream.extend(&server_error);
    stream.extend(pg(b'Z', b"I"));
    stream.extend(group(2));
    let mut expected = group(3);
    expected.extend(&refusal);
    expected.extend(pg(b'Z', b"I"));
    expected.extend(group(2));
    for width in 1..=stream.len() {
        let mut r = relay(true);
        for kind in [
            PlanKind::Parse,
            PlanKind::Bind,
            PlanKind::Execute,
            PlanKind::Sync,
        ] {
            r.plan(kind, 1).await;
        }
        r.responses
            .register(PlanKind::Parse, Some(refusal.clone()), false, None)
            .await
            .unwrap();
        for kind in [PlanKind::Bind, PlanKind::Execute, PlanKind::Sync] {
            r.plan(kind, 1).await;
        }
        for kind in [
            PlanKind::Parse,
            PlanKind::Bind,
            PlanKind::Execute,
            PlanKind::Sync,
        ] {
            r.plan(kind, 1).await;
        }
        r.send_split(&stream, &[width]).await;
        assert_eq!(r.receive(expected.len()).await, expected, "width {width}");
        assert!(!r.responses.has_plans().unwrap(), "width {width}");
        r.end().await.unwrap();
    }
}

/// A server that stops inside a message: the messages before it are already
/// with the client (the relay never holds complete messages back waiting for
/// the rest of a partial one).
#[tokio::test]
async fn complete_messages_are_not_held_back_by_a_partial_one() {
    let mut r = relay(true);
    r.plan(PlanKind::Simple, 2).await;
    let mut first = pg(b'C', b"SELECT 1\0");
    first.extend(pg(b'Z', b"I"));
    let second = sized(b'D', 5000, 1);
    let mut partial = first.clone();
    partial.extend_from_slice(&second[..100]);
    r.upstream.write_all(&partial).await.unwrap();
    assert_eq!(r.receive(first.len()).await, first);
    // The rest arrives later and completes the row.
    r.upstream.write_all(&second[100..]).await.unwrap();
    assert_eq!(r.receive(second.len()).await, second);
    let mut tail = pg(b'C', b"SELECT 1\0");
    tail.extend(pg(b'Z', b"I"));
    r.upstream.write_all(&tail).await.unwrap();
    assert_eq!(r.receive(tail.len()).await, tail);
    r.end().await.unwrap();
}

/// A connection that ends inside a message is an error, not a clean end; one
/// that ends between messages is a clean end.
#[tokio::test]
async fn an_upstream_end_inside_a_message_is_an_error() {
    let mut r = relay(true);
    r.plan(PlanKind::Simple, 1).await;
    r.upstream
        .write_all(&sized(b'D', 300, 0)[..120])
        .await
        .unwrap();
    let error = r.end().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);

    let mut r = relay(true);
    r.plan(PlanKind::Simple, 1).await;
    r.upstream
        .write_all(&sized(b'D', BUFFER * 2, 0)[..BUFFER + 3])
        .await
        .unwrap();
    let error = r.end().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);

    let r = relay(true);
    r.end().await.unwrap();
}

/// Malformed backend framing closes the session; the complete messages
/// before it still reach the client.
#[tokio::test]
async fn malformed_backend_framing_fails_closed_after_the_good_messages() {
    for bad in [
        vec![b'D', 0, 0, 0, 3],
        vec![b'Z', 0, 0, 0, 6, b'I', b'I'],
        vec![b'D', 0x80, 0, 0, 0],
    ] {
        let mut r = relay(true);
        r.plan(PlanKind::Simple, 2).await;
        let mut good = pg(b'C', b"SELECT 1\0");
        good.extend(pg(b'Z', b"I"));
        let mut stream = good.clone();
        stream.extend(&bad);
        r.upstream.write_all(&stream).await.unwrap();
        assert_eq!(r.receive(good.len()).await, good);
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), r.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData,
            "{bad:?}"
        );
    }
}

/// A backend message with no plan (the server answering something the
/// frontend never sent) fails closed, as in 4.17.1.
#[tokio::test]
async fn a_backend_message_without_a_plan_fails_closed() {
    let mut r = relay(true);
    r.upstream
        .write_all(&pg(b'C', b"SELECT 1\0"))
        .await
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), r.task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    let _ = r.client.read(&mut [0u8; 1]).await;
}

/// The response queue is bounded: with every slot taken, the frontend waits
/// for the relay to complete a plan instead of dropping one.
#[tokio::test]
async fn a_full_response_queue_waits_for_the_relay() {
    let mut r = relay(true);
    r.plan(PlanKind::Simple, 4096).await;
    let responses = r.responses.clone();
    let waiting = tokio::spawn(async move {
        responses
            .register(PlanKind::Simple, None, false, None)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!waiting.is_finished(), "no slot while the queue is full");
    let mut reply = pg(b'C', b"SELECT 1\0");
    reply.extend(pg(b'Z', b"I"));
    r.upstream.write_all(&reply).await.unwrap();
    r.receive(reply.len()).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .expect("a completed plan frees a slot")
        .unwrap();
    r.end().await.unwrap();
}
