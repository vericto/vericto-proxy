// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! 4.17.3: the frontend messages framed from one client read go to the
//! database in one write and one flush ([`crate::tcp::session::UpstreamSender`]),
//! driven through the interception loop with an upstream that records every
//! write and flush. Up to 4.17.2 each message was a write and a flush of its
//! own (about 5 per extended-protocol transaction).
//!
//! The ordering guarantees of 4.17.1 (#89) are checked end to end in
//! `fake_pg_tests` (pipelined groups with a refusal in the middle, Flush, a
//! full response queue) and `pg_relay_tests`.

use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;

use super::sensitive_tests::{pg_parse, pg_query, pg_sync};
use crate::tcp::client_tls::{ClientRead, ClientWrite};
use crate::tcp::codec::PgMessage;
use crate::tcp::postgres::PgProxyConfig;
use crate::tcp::session::UpstreamSender;

/// Refused by the built-in ruleset under the default policy.
const DANGEROUS: &str = "DELETE FROM users";

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    PgMessage {
        tag,
        body: body.to_vec(),
    }
    .encode()
}

fn bind() -> Vec<u8> {
    msg(b'B', b"\0\0\0\0\0\0\0")
}

fn describe() -> Vec<u8> {
    msg(b'D', b"P\0")
}

fn execute() -> Vec<u8> {
    msg(b'E', b"\0\0\0\0\0")
}

/// One extended-protocol transaction as pgbench and libpq send it.
fn extended(sql: &str) -> Vec<u8> {
    let mut b = pg_parse("", sql, &[]);
    b.extend(bind());
    b.extend(describe());
    b.extend(execute());
    b.extend(pg_sync());
    b
}

/// What the database side received: every write, and the writes grouped by
/// the flush that ended them.
#[derive(Default)]
struct Recorded {
    writes: Vec<Vec<u8>>,
    flushed: Vec<Vec<u8>>,
    unflushed: Vec<u8>,
}

#[derive(Clone, Default)]
struct Recorder(Arc<StdMutex<Recorded>>);

impl Recorder {
    fn flushed(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().flushed.clone()
    }

    fn writes(&self) -> usize {
        self.0.lock().unwrap().writes.len()
    }

    /// Waits until `n` flushes were recorded.
    async fn until_flushes(&self, n: usize) -> Vec<Vec<u8>> {
        super::sensitive_tests::timeout(async {
            loop {
                let flushed = self.flushed();
                if flushed.len() >= n {
                    return flushed;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut r = self.0.lock().unwrap();
        r.writes.push(buf.to_vec());
        r.unflushed.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut r = self.0.lock().unwrap();
        let group = std::mem::take(&mut r.unflushed);
        r.flushed.push(group);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn config() -> Arc<PgProxyConfig> {
    super::sensitive_tests::config_with(
        ("unused", 0),
        vericto_engine::EnforcementPolicy::default(),
        crate::tcp::rules_sync::TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    )
    .0
}

/// The PostgreSQL interception loop with the ordered response coordinator
/// (as `run_session` wires it, after startup), its database side recorded.
/// No relay runs: nothing here needs a response.
fn session() -> (DuplexStream, Recorder) {
    let cfg = config();
    let recorder = Recorder::default();
    let (client, proxy_client_side) = tokio::io::duplex(1 << 20);
    let (cr, cw) = tokio::io::split(proxy_client_side);
    let mut client_read: ClientRead = Box::new(cr);
    let client_write: Arc<Mutex<ClientWrite>> = Arc::new(Mutex::new(Box::new(cw)));
    let mut server_write: crate::tcp::upstream::UpstreamWrite = Box::new(recorder.clone());
    let responses = crate::tcp::pg_response::PgResponseCoordinator::new();
    responses.complete_startup().unwrap();
    tokio::spawn(async move {
        crate::tcp::session::intercept_client_to_server(
            &crate::tcp::protocol::postgres::PostgresProtocol,
            &mut client_read,
            &mut server_write,
            &client_write,
            &cfg,
            crate::tcp::session::SessionStart {
                tx_state: Some(Arc::new(crate::tcp::tx_state::ServerTxState::new())),
                pg_responses: Some(responses),
                ..Default::default()
            },
        )
        .await
    });
    (client, recorder)
}

/// Would fail on 4.17.2: five writes and five flushes.
#[tokio::test]
async fn an_extended_transaction_is_one_upstream_write_and_flush() {
    let (mut client, db) = session();
    let tx = extended("SELECT 1");
    client.write_all(&tx).await.unwrap();
    let flushed = db.until_flushes(1).await;
    assert_eq!(flushed, vec![tx]);
    assert_eq!(db.writes(), 1);

    // The next transaction, its own client read: its own write.
    let tx2 = extended("SELECT 2");
    client.write_all(&tx2).await.unwrap();
    assert_eq!(db.until_flushes(2).await[1], tx2);
    assert_eq!(db.writes(), 2);
}

/// A refused Parse in the middle of three pipelined groups is replaced at
/// its position (by a Parse the server refuses, whose error the relay swaps
/// for the refusal). A group the server could answer is sent before the
/// next statement is evaluated, so the coalescing never delays a response
/// behind an evaluation.
#[tokio::test]
async fn pipelined_groups_with_a_refusal_in_the_middle_go_up_in_order() {
    let (mut client, db) = session();
    let mut bytes = extended("SELECT 1");
    bytes.extend(extended(DANGEROUS));
    bytes.extend(extended("SELECT 2"));
    client.write_all(&bytes).await.unwrap();

    let mut refused = crate::tcp::pg_response::invalid_parse().encode();
    refused.extend(bind());
    refused.extend(describe());
    refused.extend(execute());
    refused.extend(pg_sync());
    let flushed = db.until_flushes(3).await;
    assert_eq!(
        flushed,
        vec![extended("SELECT 1"), refused, extended("SELECT 2")]
    );
    assert!(
        !flushed
            .concat()
            .windows(DANGEROUS.len())
            .any(|w| w == DANGEROUS.as_bytes())
    );
}

/// A Flush asks for the responses so far: it is not held back waiting for
/// more client bytes.
#[tokio::test]
async fn a_flush_goes_up_without_waiting_for_more() {
    let (mut client, db) = session();
    let mut bytes = pg_parse("s1", "SELECT 1", &[]);
    bytes.extend(bind());
    bytes.extend(execute());
    bytes.extend(msg(b'H', b""));
    client.write_all(&bytes).await.unwrap();
    assert_eq!(db.until_flushes(1).await, vec![bytes]);
    client.write_all(&pg_sync()).await.unwrap();
    assert_eq!(db.until_flushes(2).await[1], pg_sync());
}

/// A client message cut by the client read: what was framed goes out before
/// the loop waits for the rest.
#[tokio::test]
async fn a_partial_message_does_not_hold_back_the_ones_before_it() {
    let (mut client, db) = session();
    let first = extended("SELECT 1");
    let second = extended("SELECT 2");
    let mut bytes = first.clone();
    bytes.extend_from_slice(&second[..7]);
    client.write_all(&bytes).await.unwrap();
    assert_eq!(db.until_flushes(1).await, vec![first]);
    client.write_all(&second[7..]).await.unwrap();
    assert_eq!(db.until_flushes(2).await[1], second);
}

/// COPY IN: CopyData is coalesced, a message larger than the coalescing
/// bound goes out on its own after what was pending, bytes in order.
#[tokio::test]
async fn copy_in_data_is_coalesced_and_a_large_message_streamed_in_order() {
    let (mut client, db) = session();
    let copy = pg_query("COPY t FROM STDIN");
    client.write_all(&copy).await.unwrap();
    db.until_flushes(1).await;

    let mut data = Vec::new();
    for i in 0..200 {
        data.extend(msg(b'd', format!("{i}\trow {i}\n").as_bytes()));
    }
    let large = msg(b'd', &vec![b'x'; 100_000]);
    data.extend(&large);
    for i in 0..20 {
        data.extend(msg(b'd', format!("{i}\ttail\n").as_bytes()));
    }
    data.extend(msg(b'c', b""));
    client.write_all(&data).await.unwrap();

    let recorded = super::sensitive_tests::timeout(async {
        loop {
            let flushed = db.flushed();
            if flushed.concat().len() == copy.len() + data.len() {
                return flushed;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert_eq!(
        recorded.concat(),
        [copy, data].concat(),
        "same bytes, in order"
    );
    // 222 messages: a handful of flushes, not one per message.
    assert!(recorded.len() <= 8, "{} flushes", recorded.len());
    // The large message is a flush of its own, nothing else in it.
    assert!(recorded.contains(&large));
}

/// A refused simple Query in a pipelined client read: the marker query
/// takes its place, after the statement before it.
#[tokio::test]
async fn a_refused_simple_query_keeps_its_position() {
    let (mut client, db) = session();
    let mut bytes = pg_query("SELECT 1");
    bytes.extend(pg_query(DANGEROUS));
    bytes.extend(pg_query("SELECT 2"));
    client.write_all(&bytes).await.unwrap();
    let flushed = db.until_flushes(3).await;
    let marker = pg_query("SELECT 1 /* vericto ordered response marker */");
    assert_eq!(
        flushed,
        vec![pg_query("SELECT 1"), marker, pg_query("SELECT 2")]
    );
}

#[tokio::test]
async fn the_sender_bounds_what_it_holds() {
    let recorder = Recorder::default();
    let mut inner: crate::tcp::upstream::UpstreamWrite = Box::new(recorder.clone());
    let mut sender = UpstreamSender::new(&mut inner, true);
    let small = PgMessage {
        tag: b'd',
        body: vec![b'a'; 1000],
    };
    for _ in 0..16 {
        sender.send_pg(&small).await.unwrap();
    }
    // 16 x 1005 bytes fit in the 16 KiB bound: nothing written yet.
    assert_eq!(sender.pending().len(), 16 * 1005);
    assert_eq!(recorder.writes(), 0);
    // One more does not: what is pending goes first.
    sender.send_pg(&small).await.unwrap();
    assert_eq!(recorder.flushed().len(), 1);
    assert_eq!(sender.pending().len(), 1005);
    // CopyData is not answerable on its own: no flush before an evaluation.
    sender.flush_answerable().await.unwrap();
    assert_eq!(recorder.flushed().len(), 1);
    let sync = PgMessage {
        tag: b'S',
        body: Vec::new(),
    };
    sender.send_pg(&sync).await.unwrap();
    sender.flush_answerable().await.unwrap();
    assert_eq!(recorder.flushed().len(), 2);
    assert!(sender.pending().is_empty());
    // Nothing pending: flush writes nothing.
    sender.flush().await.unwrap();
    assert_eq!(recorder.flushed().len(), 2);

    // Not coalescing (MySQL; PostgreSQL without the coordinator): a write and
    // a flush per message, as before.
    let recorder = Recorder::default();
    let mut inner: crate::tcp::upstream::UpstreamWrite = Box::new(recorder.clone());
    let mut sender = UpstreamSender::new(&mut inner, false);
    sender.send_pg(&small).await.unwrap();
    sender.send_pg(&sync).await.unwrap();
    assert_eq!(recorder.flushed().len(), 2);
    assert!(sender.pending().is_empty());
}
