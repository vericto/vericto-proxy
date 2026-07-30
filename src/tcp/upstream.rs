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
            let mut rd: &[u8] = &pem;
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
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
            let mut krd: &[u8] = &key_pem;
            let key_der = rustls_pemfile::private_key(&mut krd)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("no private key found in upstream key {key}"),
                )
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
                let mut rd: &[u8] = &pem;
                for cert in rustls_pemfile::certs(&mut rd) {
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
}
