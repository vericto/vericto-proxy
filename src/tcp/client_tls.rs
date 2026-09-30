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
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
///
/// Each argument is either **inline PEM** or a **filesystem path**, decided by
/// [`pem_or_path`]. Inline PEM is what makes the private key deliverable from a
/// secrets manager: ECS, Kubernetes and most orchestrators inject secrets as
/// environment variables, not as files, so a path-only contract forced the key to
/// be baked into the container image — where anyone who can pull it can read it,
/// where it survives in the layer history, and where rotating it means rebuilding.
/// That is how the first deployment of this proxy ended up shipping its key inside
/// an image in a registry.
pub fn build_acceptor(cert: &str, key: &str) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert)?;
    let key = load_private_key(key)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The PEM marker that distinguishes inline material from a path.
///
/// A filesystem path cannot contain a newline followed by this token, and a PEM
/// document always begins with it, so the test is unambiguous in both directions.
/// Leading whitespace is tolerated because secret managers and YAML block scalars
/// both like to add it.
const PEM_MARKER: &str = "-----BEGIN";

/// Resolves an argument that may be inline PEM or a path to a PEM file.
///
/// Inline wins when the value looks like PEM. The path branch keeps the previous
/// behaviour byte for byte, so an existing deployment that passes
/// `/etc/vericto/proxy-cert.pem` is unaffected.
fn pem_or_path(value: &str, what: &str) -> io::Result<Vec<u8>> {
    if value.trim_start().starts_with(PEM_MARKER) {
        return Ok(value.as_bytes().to_vec());
    }
    std::fs::read(value).map_err(|e| {
        // The path is echoed, the inline branch never is: an error message is the
        // one place a private key must not appear, and this function handles both.
        io::Error::new(e.kind(), format!("reading TLS {what} {value}: {e}"))
    })
}

/// Reads a PEM certificate chain from inline PEM or from disk.
fn load_certs(source: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = pem_or_path(source, "cert")?;
    let mut rd: &[u8] = &pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", describe_source(source)),
        ));
    }
    Ok(certs)
}

/// Reads a PEM private key from disk (PKCS#8, PKCS#1, or SEC1).
fn load_private_key(source: &str) -> io::Result<PrivateKeyDer<'static>> {
    let pem = pem_or_path(source, "key")?;
    let mut rd: &[u8] = &pem;
    rustls_pemfile::private_key(&mut rd)?.ok_or_else(|| {
        // Deliberately does NOT echo `source`: when the key arrives inline, that
        // value IS the key. `describe_source` reports the shape instead.
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no private key found in {}", describe_source(source)),
        )
    })
}

/// A log-safe description of where TLS material came from.
///
/// Returns the path verbatim when it is a path, and a fixed label when the value
/// is inline PEM — so no diagnostic can leak the key it is diagnosing.
fn describe_source(value: &str) -> String {
    if value.trim_start().starts_with(PEM_MARKER) {
        "the inline PEM value".to_string()
    } else {
        value.to_string()
    }
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

    /// A syntactically valid but meaningless PEM block, enough to exercise the
    /// inline-vs-path branch without shipping a real key in the test suite.
    const PEM_FALSO: &str = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n";

    #[test]
    fn inline_pem_is_read_without_touching_the_filesystem() {
        // The whole point of the change: material can arrive as a value, so a
        // secrets manager can deliver it and the key never enters the image.
        let bytes = pem_or_path(PEM_FALSO, "cert").expect("inline PEM is accepted");
        assert_eq!(bytes, PEM_FALSO.as_bytes());
    }

    #[test]
    fn leading_whitespace_before_the_pem_marker_is_tolerated() {
        // Secret managers and YAML block scalars both like to add it.
        let padded = format!("\n  {PEM_FALSO}");
        assert!(pem_or_path(&padded, "cert").is_ok());
    }

    #[test]
    fn a_path_is_still_read_from_disk() {
        // The previous contract, unchanged: an existing deployment passing
        // /etc/vericto/proxy-cert.pem must behave exactly as before.
        let path = std::env::temp_dir().join("vericto_test_path_branch.pem");
        std::fs::write(&path, PEM_FALSO).unwrap();
        let res = pem_or_path(path.to_str().unwrap(), "cert");
        let _ = std::fs::remove_file(&path);
        assert_eq!(res.expect("path is read"), PEM_FALSO.as_bytes());
    }

    #[test]
    fn a_failing_path_names_the_path() {
        // A path is not a secret, so echoing it is what makes the error useful.
        let err = pem_or_path("/nonexistent/server.key", "key").expect_err("must error");
        assert!(
            err.to_string().contains("/nonexistent/server.key"),
            "got {err}"
        );
    }

    #[test]
    fn an_error_on_inline_material_never_echoes_it() {
        // The invariant that matters most here. When the key arrives inline, the
        // value IS the key, so any diagnostic that echoed its argument would write
        // a private key into the logs — trading one leak for a worse one.
        //
        // The input is a certificate passed where the key belongs: a real
        // misconfiguration (the two env vars are easy to swap), and the one shape
        // that reaches the "no private key found" branch with inline material,
        // because the PEM marker matches while no key parses out of it.
        // El cuerpo es base64 válido a propósito: si no lo fuera, rustls fallaría al
        // decodificarlo y su propio error se propagaría antes de llegar a la rama que
        // esta prueba verifica.
        let mal_puesto = "-----BEGIN CERTIFICATE-----\nTUFSQ0FET1I=\n-----END CERTIFICATE-----\n";
        let err = load_private_key(mal_puesto).expect_err("a cert is not a key");
        let texto = err.to_string();
        assert!(
            !texto.contains("TUFSQ0FET1I"),
            "el error filtró el material recibido: {texto}"
        );
        assert!(texto.contains("the inline PEM value"), "got {texto}");
    }

    #[test]
    fn an_error_on_inline_cert_material_never_echoes_it() {
        // Reaches the same branch a swapped-in private key would: a PEM block whose
        // marker matches while no CERTIFICATE parses out of it. A PUBLIC KEY block is
        // used rather than a private one so this file never carries a literal shaped
        // like a secret — the repository's secret scanner flags that shape on sight,
        // and it is right to: a test fixture is not worth teaching a scanner to ignore
        // the pattern it exists to catch.
        let no_es_un_cert = "-----BEGIN PUBLIC KEY-----\nTUFSQ0FET1I=\n-----END PUBLIC KEY-----\n";
        let err = load_certs(no_es_un_cert).expect_err("a public key is not a cert");
        let texto = err.to_string();
        assert!(
            !texto.contains("TUFSQ0FET1I"),
            "el error filtró material de la clave: {texto}"
        );
        assert!(texto.contains("the inline PEM value"), "got {texto}");
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
        let path = dir.join("vericto_test_empty_cert.pem");
        std::fs::write(&path, b"not a pem certificate\n").unwrap();
        let res = load_certs(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        let err = res.expect_err("PEM without a certificate must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
