// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Upstream connection establishment, with optional TLS to the real database.
//!
//! The proxy→database hop is the one that typically crosses an untrusted /
//! remote network (e.g. a managed RDS instance). When `UPSTREAM_SSLMODE` is
//! `require`, `verify-ca` or `verify-full`, the proxy performs the PostgreSQL SSL
//! negotiation (an `SSLRequest` followed by a rustls handshake) and tunnels the
//! rest of the session through TLS. MySQL upgrades mid-handshake through
//! [`upgrade_to_tls_client`], with the same verification and client certificate.
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

/// TLS mode for the proxy→database connection. Mirrors libpq `sslmode`, minus
/// the two modes that may connect in plaintext (`allow`, `prefer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamTlsMode {
    /// Plaintext (default): the trusted-network deployment assumption.
    #[default]
    Disable,
    /// Encrypt, but do not verify the server certificate (libpq `require`).
    Require,
    /// Encrypt and verify the certificate chain against `UPSTREAM_SSLROOTCERT`,
    /// but not the hostname (libpq `verify-ca`).
    VerifyCa,
    /// Encrypt and verify the certificate chain + hostname (libpq `verify-full`).
    VerifyFull,
}

impl UpstreamTlsMode {
    /// Parses `UPSTREAM_SSLMODE`, in any case and with surrounding whitespace
    /// ignored. Unset or empty is `disable`, the documented default.
    ///
    /// Any other value is an error, so a typo or an unsupported libpq mode stops
    /// the proxy at startup. Up to 4.12.2 it silently meant `disable`, which sent
    /// the database hop in plaintext.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let Some(v) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(UpstreamTlsMode::Disable);
        };
        match v.to_ascii_lowercase().as_str() {
            "disable" => Ok(UpstreamTlsMode::Disable),
            "require" => Ok(UpstreamTlsMode::Require),
            "verify-ca" | "verify_ca" | "verifyca" => Ok(UpstreamTlsMode::VerifyCa),
            "verify-full" | "verify_full" | "verifyfull" => Ok(UpstreamTlsMode::VerifyFull),
            "prefer" | "allow" => Err(format!(
                "UPSTREAM_SSLMODE={v:?} is not supported: libpq's `prefer` and `allow` \
                 connect in plaintext when the server does not offer TLS, and this proxy \
                 never falls back to plaintext. Use `require`, `verify-ca` or `verify-full` \
                 to encrypt the database hop, or `disable` (the default) for plaintext"
            )),
            _ => Err(format!(
                "UPSTREAM_SSLMODE={v:?} is not supported: use `disable` (the default), \
                 `require`, `verify-ca` (needs UPSTREAM_SSLROOTCERT) or `verify-full`"
            )),
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
///
/// It verifies and authenticates exactly as [`connect_upstream`] does: the CA
/// bundle (`UPSTREAM_SSLROOTCERT`) and the mutual-TLS pair (`UPSTREAM_SSLCERT`
/// / `UPSTREAM_SSLKEY`) apply to MySQL too. Up to 4.12.2 both were ignored here.
pub async fn upgrade_to_tls_client(
    tcp: TcpStream,
    host: &str,
    mode: UpstreamTlsMode,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> io::Result<(UpstreamRead, UpstreamWrite)> {
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

/// Loads the upstream TLS material once, exactly as [`connect_upstream`] does for
/// every connection, so that a missing or unreadable CA bundle, one without a
/// certificate, half a mutual-TLS pair, or a client certificate or key that does
/// not parse fails the proxy at startup instead of every connection.
///
/// `Disable` reads nothing: the files are not used in that mode.
pub fn validate_upstream_tls(
    mode: UpstreamTlsMode,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> io::Result<()> {
    if mode == UpstreamTlsMode::Disable {
        return Ok(());
    }
    let client_auth = load_client_auth(client_cert_path, client_key_path)?;
    build_client_config(mode, ca_path, client_auth).map(drop)
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
    // Every arm converges on the `WantsClientCert` builder state, so the
    // client-auth choice is applied once below.
    let builder = match mode {
        UpstreamTlsMode::VerifyFull => {
            let roots = match ca_path {
                Some(path) => load_ca_bundle(path)?,
                None => {
                    let mut roots = RootCertStore::empty();
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    roots
                }
            };
            ClientConfig::builder().with_root_certificates(roots)
        }
        UpstreamTlsMode::VerifyCa => {
            // Without a bundle, verify-ca would accept any publicly trusted
            // certificate issued for any name, which authenticates nothing.
            // libpq refuses verify-ca without a root certificate too.
            let path = ca_path.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UPSTREAM_SSLMODE=verify-ca requires UPSTREAM_SSLROOTCERT \
                     (the CA bundle that issued the database certificate)",
                )
            })?;
            let verifier = danger::ChainOnlyVerification::new(load_ca_bundle(path)?);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
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

/// Reads the `UPSTREAM_SSLROOTCERT` bundle into a trust store. A file that
/// cannot be read, holds a certificate that does not parse, or holds no
/// certificate at all is an error naming the variable and the path.
fn load_ca_bundle(path: &str) -> io::Result<RootCertStore> {
    let invalid = |e: &dyn std::fmt::Display| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UPSTREAM_SSLROOTCERT {path}: {e}"),
        )
    };
    let pem = std::fs::read(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("reading UPSTREAM_SSLROOTCERT {path}: {e}"),
        )
    })?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|e| invalid(&e))?;
        roots.add(cert).map_err(|e| invalid(&e))?;
    }
    // An empty trust store would verify no server at all: refuse it here rather
    // than let every handshake fail.
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in UPSTREAM_SSLROOTCERT {path}"),
        ));
    }
    Ok(roots)
}

/// Custom server-certificate verifiers.
///
/// `NoCertVerification` accepts any server certificate. Used only for `require`
/// mode, which provides encryption-in-transit without authenticating the server
/// (matching libpq `sslmode=require` semantics).
///
/// `ChainOnlyVerification` is `verify-ca`: the certificate must chain to the
/// configured CA bundle, be within its validity period and carry valid
/// signatures, but the name it was issued for is not compared with
/// `UPSTREAM_HOST` (libpq `sslmode=verify-ca`). For both, use `verify-full`.
mod danger {
    use std::sync::Arc;

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::client::verify_server_cert_signed_by_trust_anchor;
    use tokio_rustls::rustls::crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::server::ParsedCertificate;
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

    #[derive(Debug)]
    pub struct ChainOnlyVerification {
        roots: Arc<RootCertStore>,
        algorithms: WebPkiSupportedAlgorithms,
    }

    impl ChainOnlyVerification {
        /// Verifies against `roots` with the signature algorithms of the
        /// process-default crypto provider (ring, installed by `main`), the one
        /// `ClientConfig::builder()` uses for `verify-full`.
        pub fn new(roots: RootCertStore) -> Self {
            let algorithms = CryptoProvider::get_default()
                .map(|p| p.signature_verification_algorithms)
                .unwrap_or_else(|| {
                    tokio_rustls::rustls::crypto::ring::default_provider()
                        .signature_verification_algorithms
                });
            Self {
                roots: Arc::new(roots),
                algorithms,
            }
        }
    }

    impl ServerCertVerifier for ChainOnlyVerification {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // The same chain check verify-full runs (WebPkiServerVerifier), minus
            // its final step, the server-name comparison.
            let cert = ParsedCertificate::try_from(end_entity)?;
            verify_server_cert_signed_by_trust_anchor(
                &cert,
                &self.roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(message, cert, dss, &self.algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(message, cert, dss, &self.algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algorithms.supported_schemes()
        }
    }

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

/// A real self-signed CA certificate (P-256, valid to 2126) for the tests of the
/// CA-bundle paths. Public material only: its private key was discarded when it
/// was made.
#[cfg(test)]
pub(crate) const TEST_CA_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBXTCCAQKgAwIBAgIJAJdPKbgINA48MAoGCCqGSM49BAMCMCAxHjAcBgNVBAMM
FXZlcmljdG8tcHJveHkgdGVzdCBDQTAgFw0yNjEwMTgxNDUxMzhaGA8yMTI2MDky
NDE0NTEzOFowIDEeMBwGA1UEAwwVdmVyaWN0by1wcm94eSB0ZXN0IENBMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE0I6tKlB+c4RfpGe9rBPuLLscbjxB0f54Rspp
U7owxypSi1D+iSEHdVgOZWEC8OoynzLfJNGrYDhomsYOp3DESKMjMCEwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDSQAwRgIhALtA
TotCZD3smB3uTGweITE7Il0dx2Q83QfowDasHcjrAiEAw69sVopqr/ZrT/QIBfAt
lePoXdsR2KkNAfC6Nz6Bdes=
-----END CERTIFICATE-----
";

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

    /// Every accepted spelling, in any case and with surrounding whitespace;
    /// unset or empty keeps the documented default, `disable`.
    #[test]
    fn tls_mode_parses_case_insensitively_and_unset_is_disable() {
        use UpstreamTlsMode::*;
        for (raw, want) in [
            (None, Disable),
            (Some(""), Disable),
            (Some("   "), Disable),
            (Some("disable"), Disable),
            (Some(" DISABLE "), Disable),
            (Some("require"), Require),
            (Some("Require\n"), Require),
            (Some("verify-ca"), VerifyCa),
            (Some(" VERIFY_CA"), VerifyCa),
            (Some("verifyca"), VerifyCa),
            (Some("verify-full"), VerifyFull),
            (Some("VERIFY-FULL"), VerifyFull),
            (Some("verify_full"), VerifyFull),
            (Some("\tVerifyFull "), VerifyFull),
        ] {
            assert_eq!(UpstreamTlsMode::parse(raw), Ok(want), "{raw:?}");
        }
        assert_eq!(UpstreamTlsMode::default(), Disable);
    }

    /// A value the proxy does not recognise used to mean plaintext. It is now an
    /// error naming the variable, the value and every accepted value.
    #[test]
    fn an_unknown_upstream_tls_mode_is_an_error_not_plaintext() {
        for raw in [
            "bogus",
            "required",
            "verify",
            "verify-fulll",
            "true",
            "on",
            "ssl",
        ] {
            let err = UpstreamTlsMode::parse(Some(raw)).expect_err(raw);
            assert!(err.contains("UPSTREAM_SSLMODE"), "{err}");
            assert!(err.contains(&format!("{raw:?}")), "{err}");
            for accepted in ["`disable`", "`require`", "`verify-ca`", "`verify-full`"] {
                assert!(err.contains(accepted), "{accepted} missing: {err}");
            }
        }
    }

    /// libpq's `prefer` and `allow` connect in plaintext when the server does not
    /// offer TLS. A firewall proxy must not do that, so they are refused with
    /// that reason rather than mapped to `require` or to `disable`.
    #[test]
    fn prefer_and_allow_are_refused_because_they_fall_back_to_plaintext() {
        for raw in ["prefer", "allow", " PREFER ", "Allow"] {
            let err = UpstreamTlsMode::parse(Some(raw)).expect_err(raw);
            assert!(err.contains("UPSTREAM_SSLMODE"), "{err}");
            assert!(err.contains("plaintext"), "{err}");
            assert!(err.contains("`verify-ca`"), "{err}");
        }
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

        // A CA file with no certificate at all is refused when the config is
        // built (at startup, through validate_upstream_tls), not left to build an
        // empty trust store that fails every handshake.
        for body in ["", "no PEM here\n", FAKE_KEY] {
            let empty = TempPem::new(body);
            let err = build_client_config(UpstreamTlsMode::VerifyFull, Some(empty.path()), None)
                .expect_err("a CA bundle without a certificate");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(
                err.to_string()
                    .contains("no certificates found in UPSTREAM_SSLROOTCERT"),
                "{err}"
            );
            assert!(err.to_string().contains(empty.path()), "{err}");
        }

        // A real CA certificate builds a verify-full config.
        let ca = TempPem::new(TEST_CA_CERT);
        assert!(build_client_config(UpstreamTlsMode::VerifyFull, Some(ca.path()), None).is_ok());

        // A client key that does not parse is refused when the config is built.
        let cert = TempPem::new(FAKE_CERT);
        let key = TempPem::new(FAKE_KEY);
        let auth = load_client_auth(Some(cert.path()), Some(key.path())).unwrap();
        let err =
            build_client_config(UpstreamTlsMode::Require, None, auth).expect_err("meaningless key");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The startup check loads what each connection will load, and reads nothing
    /// in `disable` mode, where the files are unused.
    #[test]
    fn validate_upstream_tls_checks_the_material_each_mode_uses() {
        install_provider();
        let missing = Some("/nonexistent/vericto/x.pem");
        validate_upstream_tls(UpstreamTlsMode::Disable, missing, missing, None)
            .expect("disable reads no file");
        validate_upstream_tls(UpstreamTlsMode::VerifyFull, None, None, None)
            .expect("verify-full on the public roots");
        validate_upstream_tls(UpstreamTlsMode::Require, None, None, None).expect("require");

        let ca = TempPem::new(TEST_CA_CERT);
        validate_upstream_tls(UpstreamTlsMode::VerifyFull, Some(ca.path()), None, None)
            .expect("a CA bundle with a certificate");

        let empty = TempPem::new("");
        let err =
            validate_upstream_tls(UpstreamTlsMode::VerifyFull, Some(empty.path()), None, None)
                .expect_err("an empty CA bundle");
        assert!(
            err.to_string()
                .contains("no certificates found in UPSTREAM_SSLROOTCERT"),
            "{err}"
        );

        let err = validate_upstream_tls(UpstreamTlsMode::VerifyFull, missing, None, None)
            .expect_err("a missing CA bundle");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string()
                .contains("UPSTREAM_SSLROOTCERT /nonexistent/vericto/x.pem"),
            "{err}"
        );

        for mode in [UpstreamTlsMode::Require, UpstreamTlsMode::VerifyFull] {
            let err = validate_upstream_tls(mode, None, missing, None).expect_err("half a pair");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("UPSTREAM_SSLKEY"), "{err}");

            let err =
                validate_upstream_tls(mode, None, missing, missing).expect_err("missing files");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
            assert!(
                err.to_string().contains("/nonexistent/vericto/x.pem"),
                "{err}"
            );

            let cert = TempPem::new(FAKE_CERT);
            let key = TempPem::new(FAKE_KEY);
            let err = validate_upstream_tls(mode, None, Some(cert.path()), Some(key.path()))
                .expect_err("a client key that does not parse");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
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
            None,
            None,
            None,
        ))
        .await;
        assert!(res.is_err());
    }

    // ── Real handshakes against a private CA ─────────────────────────────────

    use super::test_pki::{Leaf, TestCa, server_config};
    use tokio_rustls::rustls::ServerConfig;

    /// Which upstream path a handshake test drives.
    #[derive(Clone, Copy, Debug)]
    enum Path {
        /// `connect_upstream`: SSLRequest, then TLS.
        Postgres,
        /// `upgrade_to_tls_client`: TLS on an open socket (MySQL's SSL Request
        /// is the session's job).
        Mysql,
    }

    /// The material one handshake uses, by path.
    struct Material<'a> {
        ca: Option<&'a str>,
        cert: Option<&'a str>,
        key: Option<&'a str>,
    }

    const NO_FILES: Material<'static> = Material {
        ca: None,
        cert: None,
        key: None,
    };

    /// A one-connection TLS database on 127.0.0.1 presenting `server`. Resolves
    /// to the client certificates it was shown, or to the handshake error.
    async fn tls_db(
        path: Path,
        server: Arc<ServerConfig>,
    ) -> (
        u16,
        tokio::task::JoinHandle<io::Result<Option<Vec<CertificateDer<'static>>>>>,
    ) {
        fake_db(move |mut s| async move {
            if let Path::Postgres = path {
                let mut req = [0u8; 8];
                s.read_exact(&mut req).await?;
                s.write_all(b"S").await?;
            }
            let mut tls = tokio_rustls::TlsAcceptor::from(server).accept(s).await?;
            // One byte each way: the handshake is complete on both sides,
            // client certificate included, before either end returns.
            let mut b = [0u8; 1];
            tls.read_exact(&mut b).await?;
            tls.write_all(b"!").await?;
            tls.flush().await?;
            Ok(tls
                .get_ref()
                .1
                .peer_certificates()
                .map(|c| c.iter().map(|c| c.clone().into_owned()).collect()))
        })
        .await
    }

    /// Runs one handshake through `path` with `mode` and `files`, against a
    /// database presenting `leaf` (and requiring a client certificate signed by
    /// `client_ca`, if given). Returns the client's result and the server's.
    async fn handshake(
        path: Path,
        mode: UpstreamTlsMode,
        host: &str,
        files: Material<'_>,
        leaf: &Leaf,
        client_ca: Option<&TestCa>,
    ) -> (
        io::Result<()>,
        io::Result<Option<Vec<CertificateDer<'static>>>>,
    ) {
        install_provider();
        let (port, db) = tls_db(path, server_config(leaf, client_ca)).await;
        let client = async {
            let (mut r, mut w) = match path {
                Path::Postgres => {
                    connect_upstream(host, port, mode, files.ca, files.cert, files.key).await?
                }
                Path::Mysql => {
                    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
                    upgrade_to_tls_client(tcp, host, mode, files.ca, files.cert, files.key).await?
                }
            };
            w.write_all(b"?").await?;
            w.flush().await?;
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await?;
            Ok(())
        };
        let client = within(client).await;
        let server = within(db).await.unwrap();
        (client, server)
    }

    /// The bug this release fixes on MySQL, and the behaviour Postgres already
    /// had: verify-full trusts the CA in UPSTREAM_SSLROOTCERT, so a database
    /// whose certificate a private CA issued is accepted.
    #[tokio::test]
    async fn verify_full_trusts_the_private_ca_in_upstream_sslrootcert() {
        let ca = TestCa::new("vericto test private CA");
        let ca_file = TempPem::new(&ca.pem());
        let leaf = ca.issue(&["localhost", "127.0.0.1"]);
        for path in [Path::Postgres, Path::Mysql] {
            let files = Material {
                ca: Some(ca_file.path()),
                ..NO_FILES
            };
            let (client, server) = handshake(
                path,
                UpstreamTlsMode::VerifyFull,
                "127.0.0.1",
                files,
                &leaf,
                None,
            )
            .await;
            client.unwrap_or_else(|e| panic!("{path:?}: {e}"));
            server.unwrap_or_else(|e| panic!("{path:?}: {e}"));
        }
    }

    /// Without UPSTREAM_SSLROOTCERT, verify-full trusts the public web roots
    /// only, so the same private-CA database is refused (fail closed), and a
    /// bundle holding another CA is refused too, on both paths.
    #[tokio::test]
    async fn verify_full_refuses_a_ca_it_was_not_given() {
        let ca = TestCa::new("vericto test private CA");
        let other = TestCa::new("someone else's CA");
        let other_file = TempPem::new(&other.pem());
        let leaf = ca.issue(&["127.0.0.1"]);
        for path in [Path::Postgres, Path::Mysql] {
            for ca_path in [None, Some(other_file.path())] {
                let files = Material {
                    ca: ca_path,
                    ..NO_FILES
                };
                let (client, _) = handshake(
                    path,
                    UpstreamTlsMode::VerifyFull,
                    "127.0.0.1",
                    files,
                    &leaf,
                    None,
                )
                .await;
                let err = client.expect_err("an unknown issuer must be refused");
                assert!(
                    err.to_string().contains("UnknownIssuer"),
                    "{path:?} {ca_path:?}: {err}"
                );
            }
        }
    }

    /// verify-ca (libpq semantics): the chain must lead to the configured CA,
    /// the name in the certificate is not checked. verify-full, given the same
    /// certificate for another name, refuses it.
    #[tokio::test]
    async fn verify_ca_checks_the_chain_but_not_the_hostname() {
        let ca = TestCa::new("vericto test private CA");
        let ca_file = TempPem::new(&ca.pem());
        let leaf = ca.issue(&["db-primary.internal"]);
        for path in [Path::Postgres, Path::Mysql] {
            let files = || Material {
                ca: Some(ca_file.path()),
                ..NO_FILES
            };
            let (client, server) = handshake(
                path,
                UpstreamTlsMode::VerifyCa,
                "127.0.0.1",
                files(),
                &leaf,
                None,
            )
            .await;
            client.unwrap_or_else(|e| panic!("{path:?} verify-ca: {e}"));
            server.unwrap_or_else(|e| panic!("{path:?} verify-ca: {e}"));

            let (client, _) = handshake(
                path,
                UpstreamTlsMode::VerifyFull,
                "127.0.0.1",
                files(),
                &leaf,
                None,
            )
            .await;
            let err = client.expect_err("verify-full checks the name");
            assert!(
                err.to_string().contains("not valid for name"),
                "{path:?}: {err}"
            );
        }
    }

    /// verify-ca still verifies the chain: a certificate from another CA, or a
    /// self-signed one, is refused even though the name is not checked.
    #[tokio::test]
    async fn verify_ca_refuses_a_certificate_from_another_ca() {
        let ca = TestCa::new("vericto test private CA");
        let ca_file = TempPem::new(&ca.pem());
        let rogue = TestCa::new("rogue CA").issue(&["127.0.0.1"]);
        for path in [Path::Postgres, Path::Mysql] {
            let files = Material {
                ca: Some(ca_file.path()),
                ..NO_FILES
            };
            let (client, _) = handshake(
                path,
                UpstreamTlsMode::VerifyCa,
                "127.0.0.1",
                files,
                &rogue,
                None,
            )
            .await;
            let err = client.expect_err("another CA's certificate");
            assert!(err.to_string().contains("UnknownIssuer"), "{path:?}: {err}");
        }
    }

    /// verify-ca without a CA bundle would accept any publicly trusted
    /// certificate for any name, which authenticates nothing. Like libpq, it
    /// needs a root certificate: refused when the config is built, so at startup.
    #[test]
    fn verify_ca_requires_upstream_sslrootcert() {
        install_provider();
        let err = validate_upstream_tls(UpstreamTlsMode::VerifyCa, None, None, None)
            .expect_err("verify-ca without a CA bundle");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("UPSTREAM_SSLROOTCERT"), "{err}");
        assert!(err.to_string().contains("verify-ca"), "{err}");

        let empty = TempPem::new("");
        let err = validate_upstream_tls(UpstreamTlsMode::VerifyCa, Some(empty.path()), None, None)
            .expect_err("an empty CA bundle");
        assert!(
            err.to_string()
                .contains("no certificates found in UPSTREAM_SSLROOTCERT"),
            "{err}"
        );

        let ca = TempPem::new(TEST_CA_CERT);
        validate_upstream_tls(UpstreamTlsMode::VerifyCa, Some(ca.path()), None, None)
            .expect("a CA bundle with a certificate");
    }

    /// The MySQL path presents UPSTREAM_SSLCERT / UPSTREAM_SSLKEY for mutual
    /// TLS, as the Postgres path does; a server that requires a client
    /// certificate refuses a handshake without one.
    #[tokio::test]
    async fn both_paths_present_the_client_certificate_for_mutual_tls() {
        let ca = TestCa::new("vericto test private CA");
        let ca_file = TempPem::new(&ca.pem());
        let leaf = ca.issue(&["127.0.0.1"]);
        let client_leaf = ca.issue(&["vericto-proxy"]);
        let cert_file = TempPem::new(&client_leaf.cert_pem);
        let key_file = TempPem::new(&client_leaf.key_pem);
        for path in [Path::Postgres, Path::Mysql] {
            let files = Material {
                ca: Some(ca_file.path()),
                cert: Some(cert_file.path()),
                key: Some(key_file.path()),
            };
            let (client, server) = handshake(
                path,
                UpstreamTlsMode::VerifyFull,
                "127.0.0.1",
                files,
                &leaf,
                Some(&ca),
            )
            .await;
            client.unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let shown = server
                .unwrap_or_else(|e| panic!("{path:?}: {e}"))
                .expect("a client certificate");
            assert_eq!(shown, vec![client_leaf.cert.clone()], "{path:?}");

            let files = Material {
                ca: Some(ca_file.path()),
                ..NO_FILES
            };
            let (_, server) = handshake(
                path,
                UpstreamTlsMode::VerifyFull,
                "127.0.0.1",
                files,
                &leaf,
                Some(&ca),
            )
            .await;
            assert!(server.is_err(), "{path:?}: no client certificate");
        }
    }
}

/// Throwaway PKI for the handshake tests: a private CA and the certificates it
/// issues, generated per run with rcgen, so no private key is ever committed.
#[cfg(test)]
pub(crate) mod test_pki {
    use std::sync::Arc;

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};

    /// A self-signed CA, valid for the test run.
    pub(crate) struct TestCa {
        issuer: CertifiedIssuer<'static, KeyPair>,
    }

    /// A certificate a [`TestCa`] issued, with its private key.
    pub(crate) struct Leaf {
        pub(crate) cert: CertificateDer<'static>,
        pub(crate) cert_pem: String,
        pub(crate) key_pem: String,
        key_der: Vec<u8>,
    }

    impl TestCa {
        pub(crate) fn new(common_name: &str) -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let issuer =
                CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
            Self { issuer }
        }

        /// The CA certificate, PEM: what UPSTREAM_SSLROOTCERT holds.
        pub(crate) fn pem(&self) -> String {
            self.issuer.pem()
        }

        /// Issues a certificate for `names` (DNS names or IP addresses).
        pub(crate) fn issue(&self, names: &[&str]) -> Leaf {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            let params = CertificateParams::new(names).unwrap();
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &self.issuer).unwrap();
            Leaf {
                cert: cert.der().clone(),
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
                key_der: key.serialize_der(),
            }
        }

        fn roots(&self) -> RootCertStore {
            let mut roots = RootCertStore::empty();
            roots.add(self.issuer.der().clone()).unwrap();
            roots
        }
    }

    impl Leaf {
        fn key(&self) -> PrivateKeyDer<'static> {
            PrivatePkcs8KeyDer::from(self.key_der.clone()).into()
        }
    }

    /// A server presenting `leaf`, requiring a client certificate issued by
    /// `client_ca` when one is given.
    pub(crate) fn server_config(leaf: &Leaf, client_ca: Option<&TestCa>) -> Arc<ServerConfig> {
        let builder = ServerConfig::builder();
        let builder = match client_ca {
            Some(ca) => builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(ca.roots()))
                    .build()
                    .unwrap(),
            ),
            None => builder.with_no_client_auth(),
        };
        Arc::new(
            builder
                .with_single_cert(vec![leaf.cert.clone()], leaf.key())
                .unwrap(),
        )
    }
}
