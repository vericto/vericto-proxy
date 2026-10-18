//! Upstream connection establishment, with optional TLS to the real database.
//!
//! The proxy→database hop is the one that typically crosses an untrusted /
//! remote network (e.g. a managed RDS instance). When `UPSTREAM_SSLMODE` is
//! `require` or `verify-full`, the proxy performs the PostgreSQL SSL negotiation
//! (an `SSLRequest` followed by a rustls handshake) and tunnels the rest of the
//! session through TLS.
//!
//! The app→proxy hop is intentionally NOT terminated here: the proxy is meant to
//! be deployed inside the same trusted boundary as the application (sidecar /
//! same private subnet), so that hop does not require encryption. Terminating
//! client-side TLS is a separate, optional capability.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Boxed upstream read half (plaintext TCP or TLS).
pub type UpstreamRead = Box<dyn AsyncRead + Send + Unpin>;
/// Boxed upstream write half (plaintext TCP or TLS).
pub type UpstreamWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// TLS mode for the proxy→database connection. Mirrors libpq `sslmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamTlsMode {
    /// Plaintext (default): the trusted-network deployment assumption.
    #[default]
    Disable,
    /// Encrypt, but do not verify the server certificate (libpq `require`).
    Require,
    /// Encrypt and verify the certificate chain + hostname (libpq `verify-full`).
    VerifyFull,
}

impl UpstreamTlsMode {
    /// Parses the `UPSTREAM_SSLMODE` token. Unknown/empty → `Disable`.
    pub fn from_env_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "require" => UpstreamTlsMode::Require,
            "verify-full" | "verify_full" | "verifyfull" => UpstreamTlsMode::VerifyFull,
            _ => UpstreamTlsMode::Disable,
        }
    }
}

/// PostgreSQL `SSLRequest`: Int32 length = 8, Int32 code = 80877103 (0x04D2162F).
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

/// Connects to the upstream database, optionally upgrading to TLS, and returns
/// the (read, write) halves ready for the StartupMessage and relaying.
///
/// When `client_cert_path`/`client_key_path` are set (and TLS is enabled), the
/// proxy presents that certificate to the database for mutual TLS — covering
/// the `cert` authentication method (the proxy authenticates as a single
/// service identity). It is ignored when `mode` is `Disable`.
pub async fn connect_upstream(
    host: &str,
    port: u16,
    mode: UpstreamTlsMode,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> io::Result<(UpstreamRead, UpstreamWrite)> {
    let mut tcp = TcpStream::connect((host, port)).await?;
    // Disable Nagle to avoid the Nagle + delayed-ACK ~40ms stall on small msgs.
    let _ = tcp.set_nodelay(true);

    if mode == UpstreamTlsMode::Disable {
        let (r, w) = tcp.into_split();
        return Ok((Box::new(r), Box::new(w)));
    }

    // PostgreSQL SSL negotiation: send SSLRequest, read the 1-byte reply.
    // 'S' → proceed with TLS; 'N' → server does not support TLS.
    tcp.write_all(&SSL_REQUEST).await?;
    tcp.flush().await?;
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await?;
    if reply[0] != b'S' {
        return Err(io::Error::other(format!(
            "upstream declined TLS (replied '{}') but UPSTREAM_SSLMODE requires it",
            reply[0] as char
        )));
    }

    let client_auth = load_client_auth(client_cert_path, client_key_path)?;
    let config = build_client_config(mode, ca_path, client_auth)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid upstream hostname for TLS",
        )
    })?;
    let tls = connector.connect(server_name, tcp).await?;
    let (r, w) = tokio::io::split(tls);
    Ok((Box::new(r), Box::new(w)))
}

/// Upgrades an already-connected TCP stream to a client-side TLS session.
///
/// Unlike `connect_upstream` (which owns the Postgres SSL negotiation), this is
/// for protocols where TLS is initiated mid-handshake AFTER the proxy has
/// exchanged some plaintext bytes — MySQL, whose SSL Request is a truncated
/// login packet sent over the already-open TCP connection before TLS begins.
/// The MySQL-specific packet exchange stays in the session; this only performs
/// the rustls client handshake and returns the boxed halves.
pub async fn upgrade_to_tls_client(
    tcp: TcpStream,
    host: &str,
    mode: UpstreamTlsMode,
) -> io::Result<(UpstreamRead, UpstreamWrite)> {
    let config = build_client_config(mode, None, None)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid upstream hostname for TLS",
        )
    })?;
    let tls = connector.connect(server_name, tcp).await?;
    let (r, w) = tokio::io::split(tls);
    Ok((Box::new(r), Box::new(w)))
}

/// Optional client certificate chain + private key for upstream mutual TLS.
type ClientAuth = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Loads the optional client certificate + key used for upstream mutual TLS.
/// Returns `None` when neither is configured; errors if only one is set.
fn load_client_auth(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> io::Result<Option<ClientAuth>> {
    match (cert_path, key_path) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let pem = std::fs::read(cert).map_err(|e| {
                io::Error::new(e.kind(), format!("reading upstream cert {cert}: {e}"))
            })?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
                .collect::<Result<_, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if certs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("no certificates found in upstream cert {cert}"),
                ));
            }
            let key_pem = std::fs::read(key).map_err(|e| {
                io::Error::new(e.kind(), format!("reading upstream key {key}: {e}"))
            })?;
            let key_der = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| match e {
                pem::Error::NoItemsFound => io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("no private key found in upstream key {key}"),
                ),
                other => io::Error::new(io::ErrorKind::InvalidData, other),
            })?;
            Ok(Some((certs, key_der)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream mutual TLS requires both UPSTREAM_SSLCERT and UPSTREAM_SSLKEY",
        )),
    }
}

/// Builds the rustls client config for the requested mode, optionally with a
/// client certificate for mutual TLS.
fn build_client_config(
    mode: UpstreamTlsMode,
    ca_path: Option<&str>,
    client_auth: Option<ClientAuth>,
) -> io::Result<ClientConfig> {
    // Both arms converge on the `WantsClientCert` builder state, so the
    // client-auth choice is applied once below.
    let builder = match mode {
        UpstreamTlsMode::VerifyFull => {
            let mut roots = RootCertStore::empty();
            if let Some(path) = ca_path {
                let pem = std::fs::read(path)?;
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    let cert = cert.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    roots
                        .add(cert)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                }
            } else {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            ClientConfig::builder().with_root_certificates(roots)
        }
        UpstreamTlsMode::Require => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertVerification)),
        UpstreamTlsMode::Disable => unreachable!("Disable handled before TLS config"),
    };

    match client_auth {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// Certificate verifier that accepts any server certificate. Used only for
/// `require` mode, which provides encryption-in-transit without authenticating
/// the server (matching libpq `sslmode=require` semantics). For authentication,
/// use `verify-full`.
mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertVerification;

    impl ServerCertVerifier for NoCertVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                ED25519,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssl_request_encodes_length_and_code() {
        assert_eq!(
            i32::from_be_bytes([
                SSL_REQUEST[0],
                SSL_REQUEST[1],
                SSL_REQUEST[2],
                SSL_REQUEST[3]
            ]),
            8
        );
        assert_eq!(
            i32::from_be_bytes([
                SSL_REQUEST[4],
                SSL_REQUEST[5],
                SSL_REQUEST[6],
                SSL_REQUEST[7]
            ]),
            80_877_103
        );
    }

    #[test]
    fn tls_mode_parses_from_env() {
        assert_eq!(
            UpstreamTlsMode::from_env_str("require"),
            UpstreamTlsMode::Require
        );
        assert_eq!(
            UpstreamTlsMode::from_env_str("VERIFY-FULL"),
            UpstreamTlsMode::VerifyFull
        );
        assert_eq!(
            UpstreamTlsMode::from_env_str("verify_full"),
            UpstreamTlsMode::VerifyFull
        );
        assert_eq!(
            UpstreamTlsMode::from_env_str("disable"),
            UpstreamTlsMode::Disable
        );
        assert_eq!(UpstreamTlsMode::from_env_str(""), UpstreamTlsMode::Disable);
        assert_eq!(
            UpstreamTlsMode::from_env_str("bogus"),
            UpstreamTlsMode::Disable
        );
        assert_eq!(UpstreamTlsMode::default(), UpstreamTlsMode::Disable);
    }

    use tokio::net::TcpListener;

    /// A syntactically valid PEM block whose DER is meaningless: enough to reach
    /// the parsing branches without shipping real key material in the tests.
    const FAKE_CERT: &str = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n";
    const FAKE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n";

    fn install_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    /// A scratch file holding `body`, removed when the guard drops.
    struct TempPem(std::path::PathBuf);
    impl TempPem {
        fn new(body: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vericto-upstream-test-{}.pem",
                uuid::Uuid::new_v4()
            ));
            std::fs::write(&path, body).unwrap();
            Self(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A one-connection fake database: runs `serve` on the accepted socket and
    /// returns what it produced.
    async fn fake_db<F, Fut, T>(serve: F) -> (u16, tokio::task::JoinHandle<T>)
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send,
        T: Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            serve(socket).await
        });
        (port, task)
    }

    async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(5), f)
            .await
            .expect("timed out")
    }

    /// The default deployment: plaintext, no SSLRequest, bytes relayed both ways.
    #[tokio::test]
    async fn disable_mode_relays_plaintext_without_an_ssl_request() {
        let (port, db) = fake_db(|mut s| async move {
            let mut got = [0u8; 5];
            s.read_exact(&mut got).await.unwrap();
            s.write_all(b"world").await.unwrap();
            got
        })
        .await;
        let (mut r, mut w) = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::Disable,
            None,
            None,
            None,
        ))
        .await
        .expect("plaintext connect");
        w.write_all(b"hello").await.unwrap();
        w.flush().await.unwrap();
        let mut back = [0u8; 5];
        within(r.read_exact(&mut back)).await.unwrap();
        assert_eq!(&back, b"world");
        assert_eq!(&within(db).await.unwrap(), b"hello", "no SSLRequest first");
    }

    #[tokio::test]
    async fn an_unreachable_database_is_an_error() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let err = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::Disable,
            None,
            None,
            None,
        ))
        .await
        .err()
        .expect("nothing listens there");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    /// UPSTREAM_SSLMODE=require against a server without TLS: the proxy refuses
    /// to fall back to plaintext, after sending exactly the 8-byte SSLRequest.
    #[tokio::test]
    async fn a_server_that_declines_tls_is_refused_not_downgraded() {
        let (port, db) = fake_db(|mut s| async move {
            let mut req = [0u8; 8];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(b"N").await.unwrap();
            req
        })
        .await;
        let err = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::Require,
            None,
            None,
            None,
        ))
        .await
        .err()
        .expect("must not downgrade");
        assert!(err.to_string().contains("declined TLS"), "{err}");
        assert!(err.to_string().contains("'N'"), "{err}");
        assert_eq!(within(db).await.unwrap(), SSL_REQUEST);
    }

    #[tokio::test]
    async fn a_server_that_closes_before_answering_the_ssl_request_is_an_error() {
        let (port, _db) = fake_db(|mut s| async move {
            let mut req = [0u8; 8];
            s.read_exact(&mut req).await.unwrap();
        })
        .await;
        let err = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::VerifyFull,
            None,
            None,
            None,
        ))
        .await
        .err()
        .expect("no reply");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A server that accepts the SSLRequest but then does not speak TLS fails
    /// the handshake: the session never proceeds unencrypted.
    #[tokio::test]
    async fn a_broken_tls_handshake_is_an_error() {
        install_provider();
        let (port, _db) = fake_db(|mut s| async move {
            let mut req = [0u8; 8];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(b"S").await.unwrap();
            // Read the ClientHello, answer with garbage that is not a TLS record.
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"this is not TLS at all\r\n").await;
        })
        .await;
        let res = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::Require,
            None,
            None,
            None,
        ))
        .await;
        assert!(res.is_err(), "a garbled handshake must fail");
    }

    /// Mutual TLS needs both halves; one alone is a configuration error raised
    /// before any TLS byte is sent.
    #[tokio::test]
    async fn a_client_cert_without_its_key_is_refused() {
        let (port, _db) = fake_db(|mut s| async move {
            let mut req = [0u8; 8];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(b"S").await.unwrap();
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest).await;
            rest
        })
        .await;
        let err = within(connect_upstream(
            "127.0.0.1",
            port,
            UpstreamTlsMode::Require,
            None,
            Some("/etc/vericto/client.pem"),
            None,
        ))
        .await
        .err()
        .expect("half a key pair");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("UPSTREAM_SSLKEY"), "{err}");
    }

    #[test]
    fn client_auth_is_optional_but_both_halves_go_together() {
        assert!(load_client_auth(None, None).unwrap().is_none());
        let err = load_client_auth(None, Some("/k.pem")).expect_err("key alone");
        assert!(err.to_string().contains("UPSTREAM_SSLCERT"), "{err}");
    }

    /// File errors name the file (a path is not a secret) so the operator can fix it.
    #[test]
    fn unreadable_or_empty_client_auth_files_say_which_and_why() {
        let err = load_client_auth(Some("/nonexistent/c.pem"), Some("/nonexistent/k.pem"))
            .expect_err("missing cert");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("/nonexistent/c.pem"), "{err}");

        let cert = TempPem::new(FAKE_CERT);
        let err = load_client_auth(Some(cert.path()), Some("/nonexistent/k.pem"))
            .expect_err("missing key");
        assert!(err.to_string().contains("/nonexistent/k.pem"), "{err}");

        let empty = TempPem::new("no PEM here\n");
        let err = load_client_auth(Some(empty.path()), Some(empty.path()))
            .expect_err("no certificate in the file");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("no certificates found"), "{err}");

        // A certificate where the key belongs: a real, easy swap of the two vars.
        let err = load_client_auth(Some(cert.path()), Some(cert.path()))
            .expect_err("a certificate is not a key");
        assert!(err.to_string().contains("no private key found"), "{err}");

        let key = TempPem::new(FAKE_KEY);
        let (certs, _key) = load_client_auth(Some(cert.path()), Some(key.path()))
            .unwrap()
            .expect("both halves parsed");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn client_configs_build_for_each_mode() {
        install_provider();
        // verify-full without a CA bundle trusts the public web PKI roots.
        assert!(build_client_config(UpstreamTlsMode::VerifyFull, None, None).is_ok());
        assert!(build_client_config(UpstreamTlsMode::Require, None, None).is_ok());

        let err = build_client_config(
            UpstreamTlsMode::VerifyFull,
            Some("/nonexistent/ca.pem"),
            None,
        )
        .expect_err("missing CA bundle");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // A CA bundle whose certificate does not parse is refused, not skipped:
        // skipping it would silently verify against nothing.
        let ca = TempPem::new(FAKE_CERT);
        let err = build_client_config(UpstreamTlsMode::VerifyFull, Some(ca.path()), None)
            .expect_err("unparseable CA");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A CA file with no certificate at all builds a config with an empty
        // trust store: it fails closed (no server certificate verifies), but only
        // at the first handshake, not at startup.
        let empty = TempPem::new("");
        assert!(build_client_config(UpstreamTlsMode::VerifyFull, Some(empty.path()), None).is_ok());

        // A client key that does not parse is refused when the config is built.
        let cert = TempPem::new(FAKE_CERT);
        let key = TempPem::new(FAKE_KEY);
        let auth = load_client_auth(Some(cert.path()), Some(key.path())).unwrap();
        let err =
            build_client_config(UpstreamTlsMode::Require, None, auth).expect_err("meaningless key");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The `require` verifier accepts any certificate (libpq `sslmode=require`)
    /// and offers the usual signature schemes.
    #[test]
    fn require_mode_verifier_accepts_any_certificate() {
        use tokio_rustls::rustls::client::danger::ServerCertVerifier;
        use tokio_rustls::rustls::pki_types::UnixTime;
        let v = danger::NoCertVerification;
        let cert = CertificateDer::from(vec![1, 2, 3]);
        let name = ServerName::try_from("db.internal").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        let schemes = v.supported_verify_schemes();
        assert!(schemes.contains(&tokio_rustls::rustls::SignatureScheme::ED25519));
        assert!(schemes.contains(&tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256));
    }

    /// MySQL upgrades an open socket mid-handshake; a peer that hangs up instead
    /// of answering the ClientHello is an error, never a plaintext session.
    #[tokio::test]
    async fn upgrading_a_socket_whose_peer_hangs_up_is_an_error() {
        install_provider();
        let (port, _db) = fake_db(|s| async move { drop(s) }).await;
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let res = within(upgrade_to_tls_client(
            tcp,
            "127.0.0.1",
            UpstreamTlsMode::Require,
        ))
        .await;
        assert!(res.is_err());
    }
}
