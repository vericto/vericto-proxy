// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Boxed client read half (plaintext TCP or TLS).
pub type ClientRead = Box<dyn AsyncRead + Send + Unpin>;
/// Boxed client write half (plaintext TCP or TLS).
pub type ClientWrite = Box<dyn AsyncWrite + Send + Unpin>;
/// The client read half as the interception loop reads it (4.17.3): through
/// a buffer on PostgreSQL, so the frontend messages of one client read are
/// framed without further reads and forwarded upstream together; with no
/// buffer (capacity 0, every read goes straight to the socket) on MySQL.
pub type ClientReader<'a> = tokio::io::BufReader<&'a mut ClientRead>;

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
    /// Parses `PROXY_TLS_MODE`, in any case and with surrounding whitespace
    /// ignored. Unset or empty is `disable`, the documented default.
    ///
    /// Any other value is an error. Up to 4.12.2 it silently meant `disable`, so
    /// a typo such as `required` left the client hop in plaintext.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(ClientTlsMode::Disable),
            Some(v) if v.eq_ignore_ascii_case("disable") => Ok(ClientTlsMode::Disable),
            Some(v) if v.eq_ignore_ascii_case("require") => Ok(ClientTlsMode::Require),
            Some(v) => Err(format!(
                "PROXY_TLS_MODE={v:?} is not supported: use `disable` (the default) or \
                 `require` (terminate client TLS with PROXY_TLS_CERT and PROXY_TLS_KEY)"
            )),
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
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
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
    PrivateKeyDer::from_pem_slice(&pem).map_err(|e| match e {
        // Deliberately does NOT echo `source`: when the key arrives inline, that
        // value IS the key. `describe_source` reports the shape instead.
        pem::Error::NoItemsFound => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no private key found in {}", describe_source(source)),
        ),
        other => io::Error::new(io::ErrorKind::InvalidData, other),
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
    fn tls_mode_parses_case_insensitively_and_unset_is_disable() {
        for (raw, want) in [
            (None, ClientTlsMode::Disable),
            (Some(""), ClientTlsMode::Disable),
            (Some("  "), ClientTlsMode::Disable),
            (Some("disable"), ClientTlsMode::Disable),
            (Some(" Disable\n"), ClientTlsMode::Disable),
            (Some("require"), ClientTlsMode::Require),
            (Some("REQUIRE"), ClientTlsMode::Require),
            (Some(" Require "), ClientTlsMode::Require),
        ] {
            assert_eq!(ClientTlsMode::parse(raw), Ok(want), "{raw:?}");
        }
        assert_eq!(ClientTlsMode::default(), ClientTlsMode::Disable);
    }

    /// An unknown value used to decline client TLS silently; it is now an error
    /// naming the variable, the value and the accepted values.
    #[test]
    fn an_unknown_client_tls_mode_is_an_error() {
        for raw in ["bogus", "required", "on", "true", "verify-full", "prefer"] {
            let err = ClientTlsMode::parse(Some(raw)).expect_err(raw);
            assert!(err.contains("PROXY_TLS_MODE"), "{err}");
            assert!(err.contains(&format!("{raw:?}")), "{err}");
            assert!(
                err.contains("`disable`") && err.contains("`require`"),
                "{err}"
            );
        }
    }

    /// A syntactically valid but meaningless PEM block, enough to exercise the
    /// inline-vs-path branch without shipping a real key in the test suite.
    const PEM_FALSO: &str = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n";

    /// The three private-key encodings the docs promise (PKCS#8, PKCS#1, SEC1) are
    /// still told apart after moving from rustls-pemfile to the pki-types parser,
    /// which picks the variant from the PEM label the same way.
    #[test]
    fn every_documented_private_key_encoding_is_recognised() {
        let pem = |label: &str| format!("-----BEGIN {label}-----\nZm9v\n-----END {label}-----\n");
        assert!(matches!(
            load_private_key(&pem("PRIVATE KEY")),
            Ok(PrivateKeyDer::Pkcs8(_))
        ));
        assert!(matches!(
            load_private_key(&pem("RSA PRIVATE KEY")),
            Ok(PrivateKeyDer::Pkcs1(_))
        ));
        assert!(matches!(
            load_private_key(&pem("EC PRIVATE KEY")),
            Ok(PrivateKeyDer::Sec1(_))
        ));
    }

    #[test]
    fn a_key_file_without_a_key_says_so_without_echoing_it() {
        // A certificate where the key should be: the old `Ok(None)` branch, now
        // `NoItemsFound`. Same message, and the inline value is never repeated.
        let err = load_private_key(PEM_FALSO).expect_err("a certificate is not a key");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("no private key found"));
        assert!(!err.to_string().contains("Zm9v"));
    }

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
        // The body is deliberately valid base64: if it were not, rustls would fail to
        // decode it and surface its own error before reaching the branch this test
        // covers.
        let cert_where_key_belongs =
            "-----BEGIN CERTIFICATE-----\nTUFSQ0FET1I=\n-----END CERTIFICATE-----\n";
        let err = load_private_key(cert_where_key_belongs).expect_err("a cert is not a key");
        let message = err.to_string();
        assert!(
            !message.contains("TUFSQ0FET1I"),
            "el error filtró el material recibido: {message}"
        );
        assert!(message.contains("the inline PEM value"), "got {message}");
    }

    #[test]
    fn an_error_on_inline_cert_material_never_echoes_it() {
        // Reaches the same branch a swapped-in private key would: a PEM block whose
        // marker matches while no CERTIFICATE parses out of it. A PUBLIC KEY block is
        // used rather than a private one so this file never carries a literal shaped
        // like a secret — the repository's secret scanner flags that shape on sight,
        // and it is right to: a test fixture is not worth teaching a scanner to ignore
        // the pattern it exists to catch.
        let key_where_cert_belongs =
            "-----BEGIN PUBLIC KEY-----\nTUFSQ0FET1I=\n-----END PUBLIC KEY-----\n";
        let err = load_certs(key_where_cert_belongs).expect_err("a public key is not a cert");
        let message = err.to_string();
        assert!(
            !message.contains("TUFSQ0FET1I"),
            "the error leaked key material: {message}"
        );
        assert!(message.contains("the inline PEM value"), "got {message}");
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

    /// A rustls client that trusts only `cert` (so a handshake that succeeds
    /// was signed with its key), keeping its sessions when `resume`.
    fn client_config(
        cert: &CertificateDer<'static>,
        resume: bool,
    ) -> Arc<tokio_rustls::rustls::ClientConfig> {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if !resume {
            config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
        }
        Arc::new(config)
    }

    /// One TLS handshake with the proxy's acceptor; how it went, client side.
    async fn handshake(
        acceptor: &TlsAcceptor,
        config: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> tokio_rustls::rustls::HandshakeKind {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = accept_tls(&acceptor, tcp).await.unwrap();
            let mut byte = [0u8; 1];
            r.read_exact(&mut byte).await.unwrap();
            w.write_all(&byte).await.unwrap();
            w.flush().await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("proxy.test").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .unwrap();
        tls.write_all(b"x").await.unwrap();
        let mut echo = [0u8; 1];
        // Reading also takes in the session tickets the server sent.
        tls.read_exact(&mut echo).await.unwrap();
        server.await.unwrap();
        tls.get_ref().1.handshake_kind().unwrap()
    }

    /// An ECDSA P-256 certificate, its key inline as PKCS#8 (what rcgen, `openssl
    /// genpkey` and most CAs give), terminates client TLS, and a client that
    /// offers the session it got resumes it on its next connection: the
    /// listener keeps a session cache (rustls' default of 256 sessions) and
    /// hands out TLS 1.3 tickets that refer to it. A client that does not offer
    /// a session gets a full handshake.
    #[tokio::test]
    async fn ecdsa_p256_certificates_terminate_tls_and_sessions_resume() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["proxy.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let acceptor =
            build_acceptor(&cert.pem(), &key.serialize_pem()).expect("ECDSA P-256 accepted");
        use tokio_rustls::rustls::HandshakeKind::{Full, Resumed};

        let resuming = client_config(cert.der(), true);
        assert_eq!(handshake(&acceptor, resuming.clone()).await, Full);
        assert_eq!(handshake(&acceptor, resuming.clone()).await, Resumed);
        assert_eq!(handshake(&acceptor, resuming).await, Resumed);

        let fresh = client_config(cert.der(), false);
        assert_eq!(handshake(&acceptor, fresh.clone()).await, Full);
        assert_eq!(handshake(&acceptor, fresh).await, Full);
    }
}
