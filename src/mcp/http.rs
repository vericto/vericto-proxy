// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The Streamable HTTP transport (design "MCP execution modes" §5.4),
//! stateless like the hosted `/mcp`: one `POST /mcp` per JSON-RPC message,
//! answered with `application/json` (or `202 Accepted` for a notification); no
//! server-initiated stream, so `GET` and `DELETE` are `405`.
//!
//! In order, before any tool runs:
//!
//! 1. **Host and Origin** are validated (`VERICTO_MCP_ALLOWED_HOSTS`,
//!    `VERICTO_MCP_ALLOWED_ORIGINS`) before authentication: a local HTTP MCP
//!    server a browser can reach is the DNS-rebinding case the MCP
//!    specification warns about.
//! 2. **Bearer authentication** is mandatory, also on loopback (§11.2).
//! 3. The body is bounded (`VERICTO_MAX_QUERY_BYTES` plus 64 KiB).
//!
//! It listens on `127.0.0.1:8808` by default; any other address needs TLS
//! (`PROXY_TLS_MODE=require`) or `VERICTO_MCP_ALLOW_PLAINTEXT_HTTP=true`
//! behind a TLS-terminating sidecar.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::mcp::config::is_loopback_host;
use crate::mcp::identity;
use crate::mcp::runtime::Runtime;
use crate::mcp::server::{self, Peer};

/// The path the MCP endpoint answers on.
pub const PATH: &str = "/mcp";

/// Who may reach the endpoint, by Host and Origin.
#[derive(Debug, Clone)]
pub struct Guard {
    hosts: Vec<String>,
    origins: Vec<String>,
    loopback_listener: bool,
}

impl Guard {
    pub fn new(listen: SocketAddr, hosts: &[String], origins: &[String]) -> Self {
        let mut allowed: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if !listen.ip().is_unspecified() && !listen.ip().is_loopback() {
            allowed.push(listen.ip().to_string());
        }
        allowed.extend(hosts.iter().map(|h| strip_port(h).to_ascii_lowercase()));
        Self {
            hosts: allowed,
            origins: origins
                .iter()
                .map(|o| o.trim_end_matches('/').to_ascii_lowercase())
                .collect(),
            loopback_listener: listen.ip().is_loopback(),
        }
    }

    /// `Err(reason)` when the request must be refused with 403.
    pub fn check(&self, host: Option<&str>, origin: Option<&str>) -> Result<(), &'static str> {
        let Some(host) = host else {
            return Err("missing Host header");
        };
        let name = strip_port(host).to_ascii_lowercase();
        if !self.hosts.contains(&name) {
            return Err("Host not allowed (VERICTO_MCP_ALLOWED_HOSTS)");
        }
        if let Some(origin) = origin {
            let o = origin.trim_end_matches('/').to_ascii_lowercase();
            let listed = self.origins.contains(&o);
            let local = self.origins.is_empty()
                && self.loopback_listener
                && origin_host(&o).is_some_and(is_loopback_host);
            if !listed && !local {
                return Err("Origin not allowed (VERICTO_MCP_ALLOWED_ORIGINS)");
            }
        }
        Ok(())
    }
}

/// `host[:port]` or `[v6][:port]` without the port.
fn strip_port(h: &str) -> &str {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) && !name.contains(':') => {
            name
        }
        _ => h,
    }
}

fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.split_once("://")?.1;
    Some(strip_port(rest.split('/').next().unwrap_or(rest)))
}

fn reply(
    status: StatusCode,
    body: impl Into<Bytes>,
    content_type: &'static str,
) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}

fn plain(status: StatusCode, msg: &'static str) -> Response<Full<Bytes>> {
    reply(status, msg, "text/plain; charset=utf-8")
}

/// One request.
pub async fn handle(
    rt: Arc<Runtime>,
    guard: Arc<Guard>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != PATH {
        return Ok(plain(
            StatusCode::NOT_FOUND,
            "not found: the MCP endpoint is /mcp",
        ));
    }
    let headers = req.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()));
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Err(why) = guard.check(host.as_deref(), origin) {
        tracing::warn!(reason = why, "MCP request refused before authentication");
        return Ok(plain(StatusCode::FORBIDDEN, why));
    }
    if req.method() != Method::POST {
        let mut r = plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "this server is stateless: POST JSON-RPC messages to /mcp",
        );
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return Ok(r);
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let who = token.and_then(|t| identity::authenticate(t, &rt.http_identities()));
    let Some(who) = who else {
        let mut r = plain(StatusCode::UNAUTHORIZED, "a valid bearer token is required");
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"vericto-proxy mcp\", error=\"invalid_token\""),
        );
        return Ok(r);
    };
    if let Some(v) = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        && !server::PROTOCOL_VERSIONS.contains(&v.trim())
    {
        return Ok(plain(
            StatusCode::BAD_REQUEST,
            "unsupported MCP-Protocol-Version",
        ));
    }
    let json_body = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json_body {
        return Ok(plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ));
    }
    // The statement JSON-escaped (a quote or a backslash doubles) plus the
    // envelope.
    let limit = rt
        .cfg
        .max_query_bytes
        .saturating_mul(2)
        .saturating_add(64 * 1024);
    let body = match Limited::new(req.into_body(), limit).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return Ok(plain(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large",
            ));
        }
    };
    let msg: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let e = server::error_response(
                serde_json::Value::Null,
                server::PARSE_ERROR,
                "invalid JSON",
            );
            return Ok(reply(
                StatusCode::BAD_REQUEST,
                e.to_string(),
                "application/json",
            ));
        }
    };
    let peer = Peer::http(who);
    Ok(match server::handle(&rt, &peer, msg).await {
        None => {
            let mut r = Response::new(Full::new(Bytes::new()));
            *r.status_mut() = StatusCode::ACCEPTED;
            r
        }
        Some(v) => reply(StatusCode::OK, v.to_string(), "application/json"),
    })
}

/// Accepts connections until the process stops.
pub async fn serve(
    rt: Arc<Runtime>,
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
) -> std::io::Result<()> {
    let guard = Arc::new(Guard::new(
        listener.local_addr()?,
        &rt.cfg.allowed_hosts,
        &rt.cfg.allowed_origins,
    ));
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let (rt, guard, tls) = (Arc::clone(&rt), Arc::clone(&guard), tls.clone());
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                handle(Arc::clone(&rt), Arc::clone(&guard), req)
            });
            // A client that never finishes its headers is cut off (slowloris).
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            let result = match tls {
                Some(acceptor) => {
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
                    {
                        Ok(Ok(stream)) => {
                            builder
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                        }
                        _ => return,
                    }
                }
                None => builder.serve_connection(TokioIo::new(tcp), service).await,
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "MCP HTTP connection ended");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_origin_guard_against_rebinding() {
        let g = Guard::new("127.0.0.1:8808".parse().unwrap(), &[], &[]);
        assert!(g.check(Some("127.0.0.1:8808"), None).is_ok());
        assert!(g.check(Some("localhost:8808"), None).is_ok());
        assert!(g.check(Some("[::1]:8808"), None).is_ok());
        assert!(g.check(Some("attacker.example:8808"), None).is_err());
        assert!(g.check(None, None).is_err());
        assert!(
            g.check(Some("localhost:8808"), Some("http://localhost:6274"))
                .is_ok()
        );
        assert!(
            g.check(Some("localhost:8808"), Some("https://evil.example"))
                .is_err()
        );
        let g = Guard::new(
            "0.0.0.0:8808".parse().unwrap(),
            &["vericto-mcp.internal".to_string()],
            &["https://tools.internal".to_string()],
        );
        assert!(g.check(Some("vericto-mcp.internal:8808"), None).is_ok());
        assert!(g.check(Some("other.internal"), None).is_err());
        assert!(
            g.check(
                Some("vericto-mcp.internal"),
                Some("https://tools.internal/")
            )
            .is_ok()
        );
        assert!(
            g.check(Some("vericto-mcp.internal"), Some("http://localhost:3000"))
                .is_err()
        );
    }
}
