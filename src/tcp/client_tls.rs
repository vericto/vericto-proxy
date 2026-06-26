//! Optional server-side TLS for the client → proxy hop.
//!
//! By default the proxy declines client TLS (answers `'N'` to the PostgreSQL
//! `SSLRequest`) and relies on being deployed inside the same trusted boundary
//! as the application (sidecar / private subnet), so that hop does not need
//! encryption. When the client → proxy hop must cross an untrusted network — or
//! a driver enforces `sslmode=require` — set `PROXY_TLS_MODE=require` with a
//! server certificate and key; the proxy then answers `'S'` and terminates TLS
//! as the server.
//!
//! Scope: server-side TLS only (the client authenticates the proxy). Mutual TLS
//! (client-certificate auth AT the proxy) is intentionally out of scope; the
//! related capability — the proxy presenting its own client certificate to the
//! upstream database — lives in `upstream.rs`.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Boxed client read half (plaintext TCP or TLS).
pub type ClientRead = Box<dyn AsyncRead + Send + Unpin>;
/// Boxed client write half (plaintext TCP or TLS).
pub type ClientWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// TLS mode for the client → proxy hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientTlsMode {
    /// Decline client TLS (default; trusted-network deployment).
    #[default]
    Disable,
    /// Terminate TLS as the server (encrypt the client → proxy hop).
    Require,
}

impl ClientTlsMode {
    /// Parses the `PROXY_TLS_MODE` token. Unknown/empty → `Disable`.
    pub fn from_env_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "require" => ClientTlsMode::Require,
            _ => ClientTlsMode::Disable,
        }
    }
}

/// Loads the server certificate chain and private key (PEM) and builds a rustls
/// `TlsAcceptor`. Fails fast with a descriptive error so a misconfiguration is
/// caught at startup rather than on the first connection.
pub fn build_acceptor(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Reads a PEM certificate chain from disk.
fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("reading TLS cert {path}: {e}")))?;
    let mut rd: &[u8] = &pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {path}"),
        ));
    }
    Ok(certs)
}

/// Reads a PEM private key from disk (PKCS#8, PKCS#1, or SEC1).
fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("reading TLS key {path}: {e}")))?;
    let mut rd: &[u8] = &pem;
    rustls_pemfile::private_key(&mut rd)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no private key found in {path}"),
        )
    })
}

/// Performs the server-side TLS handshake on an accepted client socket and
/// returns the boxed (read, write) halves.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
) -> io::Result<(ClientRead, ClientWrite)> {
    let tls = acceptor.accept(tcp).await?;
    let (r, w) = tokio::io::split(tls);
    Ok((Box::new(r), Box::new(w)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_mode_parses_from_env() {
        assert_eq!(
            ClientTlsMode::from_env_str("require"),
            ClientTlsMode::Require
        );
        assert_eq!(
            ClientTlsMode::from_env_str("REQUIRE"),
            ClientTlsMode::Require
        );
        assert_eq!(
            ClientTlsMode::from_env_str("disable"),
            ClientTlsMode::Disable
        );
        assert_eq!(ClientTlsMode::from_env_str(""), ClientTlsMode::Disable);
        assert_eq!(ClientTlsMode::from_env_str("bogus"), ClientTlsMode::Disable);
        assert_eq!(ClientTlsMode::default(), ClientTlsMode::Disable);
    }

    #[test]
    fn build_acceptor_errors_on_missing_cert() {
        let err = match build_acceptor("/nonexistent/server.crt", "/nonexistent/server.key") {
            Ok(_) => panic!("missing cert must error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn load_certs_errors_on_pem_without_certificate() {
        let dir = std::env::temp_dir();
        let path = dir.join("vetro_test_empty_cert.pem");
        std::fs::write(&path, b"not a pem certificate\n").unwrap();
        let res = load_certs(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        let err = res.expect_err("PEM without a certificate must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
