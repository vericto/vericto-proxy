//! Proxy TCP transparente del protocolo de wire de PostgreSQL.
//!
//! Permite que cualquier driver/ORM se conecte a Vetro como si fuera Postgres
//! (solo cambia el host del connection string), sin modificar el código de la
//! aplicación. Cada query pasa por el motor de evaluación AST antes de llegar a
//! la base de datos real.

pub mod codec;
pub mod evaluator;
pub mod postgres;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::rules::sync::SharedRuleset;
use crate::tcp::postgres::{handle_connection, PgProxyConfig, TelemetrySink};

/// Configuración de arranque del proxy TCP, resuelta desde entorno.
pub struct TcpProxyOptions {
    pub listen_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Database this proxy fronts, used to tag telemetry. Optional.
    pub database_id: Option<String>,
}

impl TcpProxyOptions {
    /// Lee la configuración del proxy TCP desde variables de entorno.
    /// Devuelve `None` si no está configurado el upstream (proxy TCP deshabilitado).
    pub fn from_env() -> Option<Self> {
        let upstream_host = std::env::var("UPSTREAM_PG_HOST").ok()?;
        let listen_port = std::env::var("PROXY_PG_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5433);
        let upstream_port = std::env::var("UPSTREAM_PG_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5432);
        Some(Self {
            listen_port,
            upstream_host,
            upstream_port,
            database_id: std::env::var("VETRO_DATABASE_ID").ok(),
        })
    }
}

/// Arranca el listener del proxy TCP de Postgres. Corre indefinidamente.
///
/// `ruleset` es compartido y recargable por el syncer; `telemetry` es opcional
/// (None deshabilita el reporte, p.ej. en modo dev/air-gapped).
pub async fn run_pg_proxy(
    opts: TcpProxyOptions,
    ruleset: SharedRuleset,
    telemetry: Option<TelemetrySink>,
) -> std::io::Result<()> {
    let config = Arc::new(PgProxyConfig {
        upstream_host: opts.upstream_host.clone(),
        upstream_port: opts.upstream_port,
        ruleset,
        telemetry,
    });

    let addr = format!("0.0.0.0:{}", opts.listen_port);
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!(
        listen = %addr,
        upstream = %format!("{}:{}", opts.upstream_host, opts.upstream_port),
        "Proxy TCP de PostgreSQL escuchando"
    );

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                // Desactiva el algoritmo de Nagle para minimizar latencia.
                let _ = socket.set_nodelay(true);
                let config = config.clone();
                tokio::spawn(handle_connection(socket, config));
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error aceptando conexión TCP");
            }
        }
    }
}
