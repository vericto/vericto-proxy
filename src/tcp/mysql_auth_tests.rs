//! The MySQL connection phase through the proxy, packet by packet.
//!
//! The proxy relays the auth exchange without understanding the plugins, so the
//! only thing it decides is whose turn it is: after each server packet, either the
//! client answers or the server keeps talking. Getting that wrong does not fail
//! loudly, it deadlocks: both ends wait for each other.
//!
//! Two layers, like `sensitive_tests`:
//!
//! * **Scripted** (always run): a fake MySQL server plays a fixed exchange
//!   against a scripted client, through a real proxy on localhost. Each exchange
//!   is one the real protocol produces (caching_sha2_password fast and full
//!   auth, AuthSwitchRequest, a failed login), and every read is bounded, so a
//!   wrong turn shows up as a timeout. After a successful login the client runs a
//!   blocked and an allowed query, to prove the command phase is the intercepting
//!   one.
//! * **Real MySQL** (run when `VERICTO_TEST_MYSQL_URL` is set): many logins as one
//!   user. With caching_sha2_password, the default on MySQL 8.0 and 8.4, only the
//!   first login does the full exchange; the server caches the account's hash and
//!   answers every later one with fast auth.

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use vericto_engine::EnforcementPolicy;

use super::sensitive_tests::{config_with, spawn_mysql_proxy, timeout, with_real_mysql};
use crate::tcp::codec_mysql::{self as mc, MySqlPacket};
use crate::tcp::rules_sync::TelemetryQueryMode;

/// One packet of a connection-phase exchange, in order. The sequence id of
/// packet `i` is `i`, as on the wire: the server's handshake is 0 and both
/// directions share the counter until the OK.
enum Step {
    Server(Vec<u8>),
    Client(Vec<u8>),
}

const OK: [u8; 7] = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];

/// Server capabilities of the scripted handshake: everything a MySQL 8.4 with TLS
/// offers, including CLIENT_SSL (0x0800), CLIENT_COMPRESS (0x0020) and
/// CLIENT_ZSTD_COMPRESSION_ALGORITHM (0x0400_0000).
const SERVER_CAPS: u32 = 0xdfff_ffff;
/// Where the two capability halves sit in [`handshake`]: after the version
/// string, thread id (4), auth data part 1 (8) and filler (1); the upper half
/// after character set (1) and status (2).
const CAPS_LOWER_AT: usize = 1 + b"8.4.0-scripted\0".len() + 13;
const CAPS_UPPER_AT: usize = CAPS_LOWER_AT + 5;
/// What the proxy may not let a session negotiate when it does not terminate
/// client TLS: compression, and TLS itself. Spelled out here, not taken from
/// `codec_mysql`, so the tests check the values rather than restate them.
const NOT_CARRIED_PLAIN: u32 = 0x0400_0000 | 0x0000_0020 | 0x0000_0800;
const COMPRESSION: u32 = 0x0400_0000 | 0x0000_0020;

/// Protocol v10 handshake announcing caching_sha2_password.
fn handshake() -> Vec<u8> {
    let mut p = vec![0x0a];
    p.extend_from_slice(b"8.4.0-scripted\0");
    p.extend_from_slice(&7u32.to_le_bytes()); // thread id
    p.extend_from_slice(b"scramble"); // auth-plugin-data, part 1
    p.push(0); // filler
    p.extend_from_slice(&(SERVER_CAPS as u16).to_le_bytes()); // capabilities, lower
    p.push(0xff); // character set
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // status
    p.extend_from_slice(&((SERVER_CAPS >> 16) as u16).to_le_bytes()); // capabilities, upper
    p.push(21); // auth-plugin-data length
    p.extend_from_slice(&[0; 10]); // reserved
    p.extend_from_slice(b"-part-two-12\0"); // auth-plugin-data, part 2
    p.extend_from_slice(b"caching_sha2_password\0");
    p
}

/// HandshakeResponse41 for user `app`, without CLIENT_SSL, so the proxy forwards
/// it byte for byte.
fn handshake_response() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x000a_a20fu32.to_le_bytes()); // capabilities (no CLIENT_SSL)
    p.extend_from_slice(&(1u32 << 24).to_le_bytes()); // max packet size
    p.push(0xff); // character set
    p.extend_from_slice(&[0; 23]); // filler
    p.extend_from_slice(b"app\0");
    p.push(32);
    p.extend_from_slice(&[0x5a; 32]); // scrambled password
    p.extend_from_slice(b"caching_sha2_password\0");
    p
}

/// The capabilities of a handshake payload laid out like [`handshake`].
fn greeting_caps(payload: &[u8]) -> u32 {
    let lo = u16::from_le_bytes([payload[CAPS_LOWER_AT], payload[CAPS_LOWER_AT + 1]]) as u32;
    let hi = u16::from_le_bytes([payload[CAPS_UPPER_AT], payload[CAPS_UPPER_AT + 1]]) as u32;
    (hi << 16) | lo
}

/// The handshake as the client should receive it through a plaintext proxy:
/// the same bytes with [`NOT_CARRIED_PLAIN`] cleared.
fn greeting_as_relayed(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    let caps = greeting_caps(payload) & !NOT_CARRIED_PLAIN;
    out[CAPS_LOWER_AT..CAPS_LOWER_AT + 2].copy_from_slice(&(caps as u16).to_le_bytes());
    out[CAPS_UPPER_AT..CAPS_UPPER_AT + 2].copy_from_slice(&((caps >> 16) as u16).to_le_bytes());
    out
}

/// A HandshakeResponse as the server should receive it: compression cleared.
fn response_as_relayed(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    let caps = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) & !COMPRESSION;
    out[0..4].copy_from_slice(&caps.to_le_bytes());
    out
}

fn err_1045() -> Vec<u8> {
    let mut p = vec![0xff];
    p.extend_from_slice(&1045u16.to_le_bytes());
    p.extend_from_slice(b"#28000Access denied for user 'app'@'localhost'");
    p
}

async fn send(stream: &mut TcpStream, seq: usize, payload: &[u8]) {
    let packet = MySqlPacket {
        seq: seq as u8,
        payload: payload.to_vec(),
    };
    stream.write_all(&packet.encode()).await.unwrap();
    stream.flush().await.unwrap();
}

/// Reads one packet, or panics with `what` after 5 s: a deadlock reads as a
/// timeout here instead of hanging the suite.
async fn recv(stream: &mut TcpStream, what: &str) -> Option<MySqlPacket> {
    tokio::time::timeout(std::time::Duration::from_secs(5), mc::read_packet(stream))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap()
}

/// What the fake server saw in the command phase.
#[derive(Debug, PartialEq)]
enum Upstream {
    /// The login failed; the proxy closed the connection without a command.
    Closed,
    /// The SQL of the one command that reached the server.
    Query(String),
}

/// Plays `script` between a scripted client and a fake MySQL server, through a
/// proxy that enforces the default ruleset. Every packet must arrive as sent,
/// except the two the proxy edits on purpose: the handshake (seq 0) reaches the
/// client as [`greeting_as_relayed`], and the HandshakeResponse (seq 1) reaches
/// the server as [`response_as_relayed`]. Returns what the client received for
/// its commands: after a successful login, a `DELETE` with no `WHERE` (expected:
/// blocked by the proxy) and a `SELECT 1` (expected: answered by the server);
/// and what the server received.
async fn play(script: Vec<Step>) -> (Vec<MySqlPacket>, Upstream) {
    let db = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_port = db.local_addr().unwrap().port();
    let ok_at_end = matches!(script.last(), Some(Step::Server(p)) if p.first() == Some(&0x00));

    // The fake server plays the script from its side.
    let server_script: Vec<(bool, Vec<u8>)> = script
        .iter()
        .map(|s| match s {
            Step::Server(p) => (true, p.clone()),
            Step::Client(p) => (false, p.clone()),
        })
        .collect();
    let server = tokio::spawn(async move {
        let (mut s, _) = db.accept().await.unwrap();
        for (seq, (from_server, payload)) in server_script.into_iter().enumerate() {
            if from_server {
                send(&mut s, seq, &payload).await;
            } else {
                let got = recv(&mut s, "the client's auth packet at the server").await;
                let got = got.expect("proxy closed before relaying the client's packet");
                let want = if seq == 1 {
                    response_as_relayed(&payload)
                } else {
                    payload
                };
                assert_eq!((got.seq as usize, got.payload), (seq, want));
            }
        }
        match recv(&mut s, "a command at the server").await {
            None => Upstream::Closed,
            Some(cmd) => {
                // Answer it with an OK, as for a query that ran.
                send(&mut s, 1, &OK).await;
                Upstream::Query(String::from_utf8_lossy(&cmd.payload[1..]).into_owned())
            }
        }
    });

    let (cfg, _) = config_with(
        ("127.0.0.1", db_port),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let proxy_port = spawn_mysql_proxy(cfg).await;
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

    for (seq, step) in script.iter().enumerate() {
        match step {
            Step::Server(p) => {
                let got = recv(&mut c, "the server's auth packet at the client").await;
                let got = got.expect("proxy closed before relaying the server's packet");
                let want = if seq == 0 {
                    greeting_as_relayed(p)
                } else {
                    p.clone()
                };
                assert_eq!((got.seq as usize, got.payload), (seq, want));
            }
            Step::Client(p) => send(&mut c, seq, p).await,
        }
    }

    let mut replies = Vec::new();
    if ok_at_end {
        for sql in ["DELETE FROM t", "SELECT 1"] {
            let mut cmd = vec![mc::COM_QUERY];
            cmd.extend_from_slice(sql.as_bytes());
            send(&mut c, 0, &cmd).await;
            let reply = recv(&mut c, &format!("the reply to {sql}")).await;
            replies.push(reply.expect("proxy closed in the command phase"));
        }
    } else {
        assert!(
            recv(&mut c, "the proxy to close after a failed login")
                .await
                .is_none(),
            "nothing may follow an auth ERR"
        );
    }
    drop(c);
    (replies, timeout(server).await.unwrap())
}

/// After a successful login: the `DELETE` is blocked by the proxy with ERROR
/// 1142 and never reaches the server; the `SELECT 1` does.
fn assert_command_phase(replies: &[MySqlPacket], upstream: Upstream) {
    assert_eq!(replies.len(), 2);
    assert_eq!(
        replies[0].payload[0], 0xff,
        "DELETE without WHERE is an ERR"
    );
    let code = u16::from_le_bytes([replies[0].payload[1], replies[0].payload[2]]);
    assert_eq!(code, 1142);
    assert_eq!(replies[1].payload, OK, "SELECT 1 is answered by the server");
    assert_eq!(upstream, Upstream::Query("SELECT 1".to_string()));
}

/// caching_sha2_password fast auth: the account's hash is in the server's cache,
/// so the server sends AuthMoreData 0x03 and then the OK, with nothing from the
/// client in between. This is every login after the first one for a user on a
/// default MySQL 8.0 / 8.4; waiting for the client after the 0x03 deadlocked it.
#[tokio::test]
async fn caching_sha2_fast_auth_reaches_the_command_phase() {
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(vec![0x01, 0x03]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// caching_sha2_password full auth over TLS (the account is not cached yet):
/// AuthMoreData 0x04, then the client sends the password, which TLS protects,
/// and the server answers OK.
#[tokio::test]
async fn caching_sha2_full_auth_waits_for_the_client() {
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(vec![0x01, 0x04]),
        Step::Client(b"secret\0".to_vec()),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// caching_sha2_password full auth in plaintext: the client asks for the
/// server's RSA public key (0x02), receives it as AuthMoreData, and sends the
/// encrypted password. Every server packet here waits for the client.
#[tokio::test]
async fn caching_sha2_full_auth_with_the_rsa_key_exchange() {
    let mut key = vec![0x01];
    key.extend_from_slice(
        b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEF\n-----END PUBLIC KEY-----\n",
    );
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(vec![0x01, 0x04]),
        Step::Client(vec![0x02]),
        Step::Server(key),
        Step::Client(vec![0xa5; 256]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// AuthSwitchRequest to caching_sha2_password (a client that started with
/// mysql_native_password), answered with the new scramble, then fast auth.
#[tokio::test]
async fn auth_switch_then_caching_sha2_fast_auth() {
    let mut switch = vec![0xfe];
    switch.extend_from_slice(b"caching_sha2_password\0");
    switch.extend_from_slice(b"new-scramble-20bytes\0");
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(switch),
        Step::Client(vec![0x3c; 32]),
        Step::Server(vec![0x01, 0x03]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// AuthSwitchRequest to mysql_native_password: the client answers and the
/// server says OK. (A mysql_native_password account seen from an 8.x client.)
#[tokio::test]
async fn auth_switch_to_native_password() {
    let mut switch = vec![0xfe];
    switch.extend_from_slice(b"mysql_native_password\0");
    switch.extend_from_slice(b"new-scramble-20bytes\0");
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(switch),
        Step::Client(vec![0x3c; 20]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// Multi-factor authentication (MySQL 8.0.27+): the first factor ends in fast
/// auth, and the server follows the 0x03 with AuthNextFactor (0x02) instead of
/// the OK. The client answers that one, and the second factor ends in fast auth
/// too. The proxy must read the server twice after each 0x03 and the client in
/// between.
#[tokio::test]
async fn multi_factor_with_fast_auth_on_both_factors() {
    let mut next_factor = vec![0x02];
    next_factor.extend_from_slice(b"caching_sha2_password\0");
    next_factor.extend_from_slice(b"second-factor-salt20\0");
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(vec![0x01, 0x03]),
        Step::Server(next_factor),
        Step::Client(vec![0x7e; 32]),
        Step::Server(vec![0x01, 0x03]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// An account with an empty password: the client sends an empty auth response
/// and the server answers OK right away, with no AuthMoreData at all.
#[tokio::test]
async fn empty_password_is_ok_straight_after_the_response() {
    let mut response = handshake_response();
    let at = response
        .iter()
        .position(|&b| b == 32)
        .expect("auth length byte");
    response.splice(at..at + 33, [0u8]); // auth-response length 0, no data
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(response),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// A wrong password: the ERR reaches the client and the proxy closes both ends
/// without starting the command phase.
#[tokio::test]
async fn failed_login_is_relayed_and_closed() {
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(handshake_response()),
        Step::Server(vec![0x01, 0x04]),
        Step::Client(b"wrong\0".to_vec()),
        Step::Server(err_1045()),
    ])
    .await;
    assert!(replies.is_empty());
    assert_eq!(upstream, Upstream::Closed);
}

// ── Real MySQL ───────────────────────────────────────────────────────────────

/// Many logins as one user, in a row and at the same time. Against a
/// caching_sha2_password account every login after the first is a fast-auth
/// login, which is the exchange that used to hang.
#[tokio::test]
async fn real_mysql_repeated_logins_as_one_user() {
    use mysql_async::prelude::Queryable;
    with_real_mysql(|opts| async move {
        let login = |opts: mysql_async::Opts| async move {
            let mut c = timeout(mysql_async::Conn::new(opts)).await.unwrap();
            let one: Option<i64> = c.query_first("SELECT 1").await.unwrap();
            assert_eq!(one, Some(1));
            c.disconnect().await.unwrap();
        };
        for _ in 0..10 {
            login(opts.clone()).await;
        }
        let parallel: Vec<_> = (0..10).map(|_| tokio::spawn(login(opts.clone()))).collect();
        for task in parallel {
            task.await.unwrap();
        }
    })
    .await;
}

// ── What the greeting offers ─────────────────────────────────────────────────

/// A TLS acceptor that never gets to present a certificate: enough to put the
/// proxy in `PROXY_TLS_MODE=require` for tests that end before the handshake.
fn tls_required_acceptor() -> tokio_rustls::TlsAcceptor {
    use tokio_rustls::rustls;

    #[derive(Debug)]
    struct NoCertificate;
    impl rustls::server::ResolvesServerCert for NoCertificate {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(NoCertificate));
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

/// A proxy in front of a fake server that sends [`handshake`] and then expects
/// nothing; returns the port, and the server task, which reports whether the
/// proxy closed its connection.
async fn proxy_in_front_of_a_greeting(
    client_tls: bool,
) -> (u16, tokio::task::JoinHandle<Option<MySqlPacket>>) {
    let db = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_port = db.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut s, _) = db.accept().await.unwrap();
        send(&mut s, 0, &handshake()).await;
        recv(&mut s, "the proxy to close or relay").await
    });
    let (cfg, _) = config_with(
        ("127.0.0.1", db_port),
        EnforcementPolicy::default(),
        TelemetryQueryMode::Raw,
        crate::tcp::evaluator::default_ruleset(),
        crate::tcp::upstream::UpstreamTlsMode::Disable,
    );
    let cfg = if client_tls {
        let mut cfg = std::sync::Arc::into_inner(cfg).expect("unshared config");
        cfg.client_tls_acceptor = Some(tls_required_acceptor());
        std::sync::Arc::new(cfg)
    } else {
        cfg
    };
    (spawn_mysql_proxy(cfg).await, server)
}

/// Without client TLS the client is offered neither TLS nor compression, and
/// every other capability and byte of the greeting is the server's. A client in
/// the default `ssl-mode=PREFERRED` then stays in plaintext instead of starting a
/// TLS handshake the proxy cannot answer, and no client switches to compressed
/// framing the proxy cannot read.
#[tokio::test]
async fn plaintext_greeting_offers_neither_tls_nor_compression() {
    let (port, _server) = proxy_in_front_of_a_greeting(false).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let got = recv(&mut c, "the greeting").await.unwrap();
    assert_eq!(got.seq, 0);
    assert_eq!(
        greeting_caps(&got.payload),
        SERVER_CAPS & !NOT_CARRIED_PLAIN
    );
    assert_eq!(got.payload, greeting_as_relayed(&handshake()));
}

/// With client TLS the greeting keeps CLIENT_SSL, and still offers no
/// compression.
#[tokio::test]
async fn tls_greeting_keeps_tls_and_drops_compression() {
    let (port, _server) = proxy_in_front_of_a_greeting(true).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let got = recv(&mut c, "the greeting").await.unwrap();
    assert_eq!(greeting_caps(&got.payload), SERVER_CAPS & !COMPRESSION);
}

/// A client that asks for compression anyway does not get it: the server
/// receives the response with both compression bits cleared, so it never
/// switches to compressed framing.
#[tokio::test]
async fn compression_requested_anyway_is_not_forwarded() {
    let mut response = handshake_response();
    let caps = u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
    response[0..4].copy_from_slice(&(caps | COMPRESSION).to_le_bytes());
    // `play` checks the server receives `response_as_relayed(response)`.
    let (replies, upstream) = play(vec![
        Step::Server(handshake()),
        Step::Client(response),
        Step::Server(vec![0x01, 0x03]),
        Step::Server(OK.to_vec()),
    ])
    .await;
    assert_command_phase(&replies, upstream);
}

/// `PROXY_TLS_MODE=require` and a client that answers the greeting without
/// asking for TLS: it gets the error MySQL itself sends under
/// `require_secure_transport` (3159, HY000), then the connection closes, and the
/// server never receives the client's credentials.
#[tokio::test]
async fn tls_required_refuses_a_plaintext_login_with_err_3159() {
    let (port, server) = proxy_in_front_of_a_greeting(true).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    recv(&mut c, "the greeting").await.unwrap();
    send(&mut c, 1, &handshake_response()).await;
    let err = recv(&mut c, "the refusal")
        .await
        .expect("an ERR, not a close");
    assert_eq!(err.seq, 2);
    assert_eq!(err.payload[0], 0xff);
    assert_eq!(u16::from_le_bytes([err.payload[1], err.payload[2]]), 3159);
    assert_eq!(&err.payload[3..9], b"#HY000");
    let message = String::from_utf8_lossy(&err.payload[9..]);
    assert!(message.contains("PROXY_TLS_MODE=require"), "{message}");
    assert!(recv(&mut c, "the close").await.is_none());
    assert!(
        timeout(server).await.unwrap().is_none(),
        "the server must not receive the plaintext response"
    );
}
