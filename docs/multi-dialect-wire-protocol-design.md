# Diseño — Soporte multi-dialecto en el proxy TCP (wire protocol strategy)

> Estado: **Fase 1 (MySQL) implementada y verificada e2e, incl. TLS de ambos hops**
> Creado: 2026-07-06 · Actualizado: 2026-07-07
> Repo: `vetro-proxy`
> Fase 1: **MySQL** (✅ plaintext + ✅ TLS) · Fases siguientes: SQL Server (TDS), Oracle (TNS)
>
> ## Estado TLS de MySQL (verificado en contenedores)
>
> - ✅ **Ambos hops TLS** (cliente→proxy y proxy→MySQL): el modo de producción.
>   Cliente con `--ssl-mode=REQUIRED` → proxy (termina TLS con su cert) → MySQL con
>   `require_secure_transport=ON`. `caching_sha2_password` (root) autentica porque
>   **ambos hops comparten el contexto "conexión segura"**. Enforcement verificado
>   sobre el doble TLS: DELETE/UPDATE sin WHERE y DROP bloqueados (VETRO-001/010),
>   queries seguras pasan.
> - ✅ **Ambos hops plaintext** (red confiable / sidecar): sin cambios, sigue OK.
> - ❌ **Un solo hop TLS** (cliente plaintext + upstream TLS, o viceversa): NO
>   soportado **por diseño del protocolo MySQL**, no por una limitación nuestra —
>   el scramble de auth depende del estado "seguro", que debe coincidir en ambos
>   lados (ver `docs/mysql-tls-state-of-the-art.md`). El proxy exige coherencia:
>   `PROXY_TLS_MODE=require` ⇒ `UPSTREAM_MYSQL_SSLMODE=require`.
>
> Env vars: `PROXY_TLS_MODE=require` + `PROXY_TLS_CERT`/`PROXY_TLS_KEY` (client hop);
> `UPSTREAM_MYSQL_SSLMODE=require|verify-full` + `UPSTREAM_MYSQL_SSLROOTCERT` (upstream).

> Decisiones tomadas: (1) Opción A — un proxy por dialecto, protocolo elegido en
> despliegue vía config del `database_id`. (2) Diseñar el trait pensando en los 3,
> implementar solo MySQL en fase 1.

## Contexto y corrección de una premisa

Hoy `vetro-proxy` es un **servidor del wire-protocol de PostgreSQL**: negocia el
`StartupMessage`/`SSLRequest`, extrae el SQL de los mensajes `'Q'` (simple) y `'P'`
(extended), evalúa con `vetro-engine` (hardcodeado a `Dialect::Postgres` en
`postgres.rs:235,266`) y, al bloquear, responde un `ErrorResponse` **nativo de
Postgres**.

**Premisa a corregir:** "dialecto" (lo que parsea el engine) **no es lo mismo** que
"wire protocol" (los bytes que el cliente habla con el servidor). El engine ya parsea
4 dialectos (`Dialect::{Postgres, Mysql, Oracle, MsSql}`, `parser_for()`), pero el
proxy solo habla el protocolo de red de Postgres. MySQL, SQL Server (TDS) y Oracle
(TNS) tienen **protocolos de red completamente distintos** (handshake, framing de
mensajes, formato de error, auth). No se puede "elegir el dialecto por config" y que
el mismo listener hable los cuatro: el protocolo lo impone el cliente que se conecta.

Por eso el strategy va sobre **el protocolo de red del servidor**, no sobre el
dialecto de parsing. El dialecto del engine se **deriva** del protocolo activo.

## Decisión de arquitectura (Opción A)

**Un proxy por base de datos, con su wire protocol elegido en despliegue.** Encaja con
el modelo actual: cada instancia de proxy ya fronts una sola BD (`VETRO_DATABASE_ID`,
`UPSTREAM_*`). El protocolo se selecciona al arrancar; el listener habla exactamente
un protocolo. Sin auto-detección (frágil en el hot path) y sin multiplexar protocolos
en un mismo puerto.

### Selección del protocolo

Fuente del dialecto, por orden de prioridad:

1. **Env explícito** `VETRO_WIRE_PROTOCOL=postgres|mysql` (autoridad del despliegue).
2. **Config del `database_id`** vía `GET /sync/rules` → `proxy_config.dialect`
   (el dashboard ya conoce el dialecto de la BD; se propaga al proxy).
3. **Default** `postgres` (retrocompatibilidad — comportamiento actual intacto).

> Nota de arranque: como el protocolo debe conocerse **antes** de aceptar conexiones
> y el sync es asíncrono, el env (1) es la vía primaria para producción. La config del
> sync (2) sirve para validar/derivar y para no duplicar la verdad; si el env no está,
> el proxy puede hacer un primer sync bloqueante para resolver el dialecto antes de
> `bind()`. El dialecto **no** se hot-swappea en runtime (cambiar el protocolo de un
> listener vivo no tiene sentido: rompería las conexiones abiertas).

## El trait `WireProtocol`

Abstrae exactamente los 3 puntos que hoy son específicos de Postgres; **la lógica de
sesión (fases 1–4 en `postgres.rs::run_session`) es genérica y se conserva**: negociar
startup → conectar upstream → relay server→client → interceptar client→server.

```rust
// src/tcp/protocol/mod.rs (NUEVO)

use vetro_engine::parser::Dialect;

/// SQL extraído de un mensaje del cliente, listo para evaluar.
pub struct ExtractedQuery {
    pub sql: String,
    /// Contexto que el protocolo necesita para construir el bloqueo correcto
    /// (p. ej. en Postgres extended, distinguir 'Q' de 'P' para el skip-until-Sync).
    pub kind: QueryKind,
}

pub enum QueryKind { Simple, Prepared }

/// Qué hacer tras interceptar un mensaje del cliente.
pub enum ClientMessage {
    /// Trae SQL a evaluar (con su tipo).
    Query(ExtractedQuery),
    /// Reenviar tal cual (auth, bind, execute, ping, etc.).
    PassThrough,
    /// El cliente cerró / terminó la sesión.
    Terminate,
}

/// Estrategia de wire protocol. Una impl por motor (postgres, mysql, ...).
/// Objeto-seguro: se elige en runtime y vive detrás de `Arc<dyn WireProtocol>`.
#[async_trait::async_trait]
pub trait WireProtocol: Send + Sync {
    /// Dialecto del engine que corresponde a este protocolo.
    fn dialect(&self) -> Dialect;

    /// Negocia la fase de arranque con el cliente (declina/termina TLS, lee el
    /// handshake) y devuelve los bytes de arranque a reenviar al upstream.
    /// Equivale a `negotiate_startup` de postgres.rs, por protocolo.
    async fn negotiate_startup(
        &self,
        client: ClientStream,
        tls: Option<&tokio_rustls::TlsAcceptor>,
    ) -> std::io::Result<StartupOutcome>;

    /// Lee el siguiente mensaje del cliente y lo clasifica. Encapsula el framing
    /// del protocolo (tags 'Q'/'P' en pg; COM_QUERY en mysql; etc.).
    async fn read_client_message(
        &self,
        client_read: &mut ClientRead,
    ) -> std::io::Result<Option<RawMessage>>;

    /// Clasifica un mensaje ya leído: ¿trae SQL?, ¿se reenvía?, ¿termina?
    fn classify(&self, msg: &RawMessage) -> ClientMessage;

    /// Construye la respuesta de BLOQUEO nativa del protocolo (ErrorResponse en
    /// pg; ERR_Packet en mysql; TDS error token en sqlserver). Incluye reanudar
    /// el estado del protocolo si aplica (p. ej. ReadyForQuery / skip-until-Sync).
    fn build_block_response(&self, ctx: &BlockContext) -> BlockResponse;
}
```

`BlockContext` lleva `rule_code`, `ast_node_path`, `suggested_safe_query`, `kind`.
`BlockResponse` lleva los bytes a enviar + si hay que entrar en modo "swallow hasta
fin de secuencia" (el equivalente al `skip_until_sync` de Postgres extended).

### Qué se conserva y qué se abstrae

| Pieza actual (`postgres.rs`) | Destino |
|---|---|
| `run_session` (fases 1–4) | **Genérico** → `src/tcp/session.rs`, parametrizado por `Arc<dyn WireProtocol>` |
| `relay_server_to_client` | **Genérico** (bytes opacos server→client) |
| `negotiate_startup` (pg) | `impl WireProtocol for PostgresProtocol::negotiate_startup` |
| `intercept_client_to_server` | **Genérico**: bucle que llama `read_client_message` + `classify` + `evaluate(dialect())` + `build_block_response` |
| `extract_simple_query` / `extract_parse_query` | dentro de `PostgresProtocol::classify` |
| `build_error_response` + `skip_until_sync` | `PostgresProtocol::build_block_response` |
| `evaluate(&sql, Dialect::Postgres, …)` | `evaluate(&sql, proto.dialect(), …)` |

El resultado: la lógica de evaluación, telemetría (`report_telemetry`) y enforcement
**no se duplica** — vive una sola vez en `session.rs`; cada protocolo solo aporta
framing + bloqueo nativo.

## Estructura de archivos propuesta

```
src/tcp/
  mod.rs            # run_proxy(opts, proto, ...) — elige el listener por protocolo
  session.rs        # NUEVO: run_session genérico (fases 1-4) sobre dyn WireProtocol
  protocol/
    mod.rs          # NUEVO: trait WireProtocol + tipos (ExtractedQuery, ClientMessage…)
    postgres.rs     # MOVER aquí la impl actual (codec pg + negotiate + classify + block)
    mysql.rs        # NUEVO (fase 1)
    # sqlserver.rs  # fase 3 (TDS)
    # oracle.rs     # fase 4 (TNS) — evaluar ROI antes
  codec.rs          # framing pg (se mantiene, usado por protocol/postgres.rs)
  codec_mysql.rs    # NUEVO (fase 1): framing MySQL (handshake, COM_QUERY, ERR_Packet)
  evaluator.rs      # sin cambios (ya recibe Dialect como parámetro)
  upstream.rs       # generalizar TLS/puerto (hoy asume pg; ver notas)
```

## Fase 1 — MySQL: alcance concreto

MySQL es el candidato correcto para primero: protocolo **abierto y documentado**,
drivers ubicuos, alta demanda. Lo que hay que implementar en `protocol/mysql.rs` +
`codec_mysql.rs`:

1. **Handshake inicial**: el servidor MySQL habla primero (al revés que Postgres).
   El proxy debe enviar el `Initial Handshake Packet` (o reenviar el del upstream) y
   manejar la respuesta de auth del cliente. Decisión: **relay del handshake del
   upstream** (el proxy conecta upstream primero, reenvía su handshake al cliente, y
   hace passthrough de la auth) para no reimplementar `caching_sha2_password`.
2. **Framing**: paquetes MySQL = `[3 bytes length][1 byte seq][payload]`. El primer
   byte del payload en fase de comando indica el tipo; `0x03` = `COM_QUERY` → el resto
   es el SQL. Eso es el análogo de `extract_simple_query`.
3. **Prepared statements**: `COM_STMT_PREPARE` (`0x16`) trae SQL → evaluar. El análogo
   del `'P'` de Postgres. Definir el equivalente al skip-until-Sync (descartar hasta
   fin de la secuencia de ejecución del stmt bloqueado).
4. **Respuesta de bloqueo**: `ERR_Packet` nativo (`0xFF` + código de error + SQLSTATE +
   mensaje). Reusar el mensaje de bloqueo (`rule_code`, `ast_node_path`, sugerencia).
5. **Dialecto**: `MySqlProtocol::dialect() -> Dialect::Mysql`.
6. **Upstream**: `UPSTREAM_MYSQL_HOST/PORT`, TLS MySQL (distinto del `SSLRequest` de pg).
7. **Tests** en `vetro-regression`: replicar `multi-dialect.spec.ts` conectando un
   driver MySQL real contra el proxy en modo mysql (block DELETE sin WHERE, DROP, etc.).

## Cambios fuera del proxy

- **Backend (`vetro-fmw`)**: `GET /sync/rules` debe incluir `proxy_config.dialect`
  derivado del dialecto de la BD (`databases.dialect` ya existe en el schema). Añadir
  el campo al `SyncResponse`/`ProxyConfig` de `rules_sync.rs`.
- **Despliegue/infra**: el proxy de una BD MySQL se lanza con `VETRO_WIRE_PROTOCOL=mysql`
  + `UPSTREAM_MYSQL_HOST/PORT`. En AWS, es una task/servicio por BD (ya es el modelo).
- **Docs**: README del proxy + guía de despliegue: nueva env var y el mapa dialecto→puerto.

## Fases siguientes (no fase 1)

- **Fase 2 — SQL Server (TDS)**: protocolo documentado (MS-TDS) pero complejo (prelogin,
  TDS7 login, tokens). Esfuerzo alto. Implementar solo `protocol/sqlserver.rs` +
  `codec_tds.rs`; el trait ya lo soporta.
- **Fase 3 — Oracle (TNS)**: protocolo **propietario y cerrado**, muy complejo. Antes de
  implementar, **evaluar ROI**: puede convenir cubrir Oracle solo por el endpoint HTTP
  de `vetro-eval` (evaluación sin proxy TCP) hasta que la demanda justifique reimplementar
  TNS. Dejar el trait listo, no forzar la implementación.

## Riesgos / consideraciones

1. **El handshake de cada protocolo es la parte cara y frágil.** El diseño de "relay del
   handshake del upstream + passthrough de auth" minimiza el riesgo (no reimplementamos
   auth), pero hay que validar bien con drivers reales (Prisma/mysql2/JDBC).
2. **No romper Postgres.** El refactor mueve `postgres.rs` a `protocol/postgres.rs` sin
   cambiar su comportamiento; la suite `vetro-regression` (412 casos) es la red de
   seguridad. Correrla antes/después del refactor y exigir verde.
3. **`upstream.rs` asume Postgres TLS.** Generalizar el connect/TLS por protocolo (MySQL
   negocia TLS distinto). Aislarlo detrás del trait o de un `upstream_mysql.rs`.
4. **Verificación:** este diseño se escribió sin toolchain de Rust disponible en el
   entorno (`cargo`/`rustc` ausentes, sin red para el git-dep del engine). La
   implementación debe compilarse y pasar `cargo clippy` + la suite de regresión en un
   entorno con Rust.

## Estado de implementación (fase 1)

Escrito y entregado (aditivo, no toca el path Postgres vivo):

- ✅ `Cargo.toml` — dependencia `async-trait`.
- ✅ `src/tcp/codec_mysql.rs` — framing MySQL (read_packet, MySqlPacket, extract_sql
  para COM_QUERY/COM_STMT_PREPARE, build_err_packet) **con tests unitarios**.
- ✅ `src/tcp/protocol/mod.rs` — trait `WireProtocol` + tipos + `select_protocol()`.
- ✅ `src/tcp/protocol/postgres.rs` — impl Postgres (envuelve el codec actual, mismo
  comportamiento incl. skip-until-Sync).
- ✅ `src/tcp/protocol/mysql.rs` — impl MySQL **con tests unitarios**.
- ✅ `src/tcp/session.rs` — bucle de intercepción **genérico** sobre `dyn WireProtocol`.
- ✅ `postgres.rs` — `report_telemetry`/`log_block` pasados a `pub(crate)` para reuso.
- ✅ `tcp/mod.rs` — módulos nuevos declarados.

- ✅ **Rewiring del path Postgres vivo** — `postgres.rs::intercept_client_to_server`
  ahora delega en `session::intercept_client_to_server` con `PostgresProtocol`. Código
  muerto (helpers inline viejos) eliminado.

**Verificado en contenedor `rust:1.88`** (con el engine real clonado vía credenciales
de GitHub; `libclang` + `protoc` instalados para las deps de `pg_query`/prost):

- `cargo build` → **0 warnings, 0 errores**.
- `cargo test` → **46/46 pasan** (13 nuevos MySQL + regresión Postgres intacta).
- `cargo clippy -- -D warnings` → **limpio** (calidad estricta).

- ✅ **Handshake MySQL (server-first)** — `session::run_mysql_session`: conecta upstream
  primero, relay del Initial Handshake al cliente, passthrough de auth vía el gate
  `is_command_phase_start` (primer paquete cliente con `seq == 0` = inicio de fase de
  comando). `run_mysql_proxy` + `handle_mysql_connection` en `tcp/mod.rs`.
- ✅ **`main.rs`** — elige `run_mysql_proxy` vs `run_pg_proxy` por `VETRO_WIRE_PROTOCOL`.
- ✅ **`TcpProxyOptions`** — vars `UPSTREAM_MYSQL_HOST/PORT`, `PROXY_MYSQL_LISTEN_PORT`
  (defaults 3306 / 3307).
- ✅ **CLIENT_QUERY_ATTRIBUTES** — `extract_sql` salta el prefijo lenenc
  `parameter_count`/`parameter_set_count` que MySQL 8.0.23+ antepone al SQL en COM_QUERY
  (sin esto el SQL llegaba con bytes de control `\x00\x01` y el parser no lo reconocía).

**Verificado E2E contra MySQL 8 real** (contenedor `rust:1.88` + `mysql:8.0` en red
Docker; proxy en modo mysql fronteando la base):

- `cargo build` → **0 warnings**; `cargo test` → **47/47**; `cargo clippy -- -D warnings` → limpio.
- `SELECT` (segura) → pasa transparente y devuelve datos reales.
- `DELETE FROM users` (sin WHERE) → **bloqueada** con `ERROR 1142 (42000): Vetro blocked
  this query [VETRO-001] …` — el driver la ve como error SQL nativo; las filas quedan
  intactas.
- `UPDATE … SET …` (sin WHERE) → bloqueada (`VETRO-030`).
- `UPDATE … WHERE id=1` (segura) → pasa y el cambio se aplica → confirma discriminación
  por AST, no bloqueo indiscriminado.

**Limitación conocida de fase 1 (documentar para despliegue):**

- **TLS cliente→proxy no soportado en MySQL.** Igual que el modelo de Postgres del proxy
  (red confiable), el proxy declina/no ofrece TLS del lado cliente. Un cliente MySQL con
  `--ssl-mode=PREFERRED` (default) manda un SSL Request y el handshake TLS haría que el
  framing MySQL vea bytes cifrados. **En fase 1 el cliente debe conectar con
  `ssl-mode=DISABLED`** (despliegue sidecar / subred privada, como Postgres). TLS
  cliente para MySQL es una mejora posterior (declinar el SSL Request como hace el path
  Postgres, o terminar TLS del lado cliente).
- **Upstream TLS MySQL** no implementado (plaintext al upstream) — mejora posterior.

**Pendiente (no bloquea la fase 1 funcional):**

1. **Backend** — `proxy_config.dialect` en `/sync/rules` (independiente del Rust; TS).
2. **E2E en `vetro-regression`** — portar el escenario probado manualmente a
   `tests/proxy/multi-dialect.spec.ts` con un servicio MySQL en el compose.
3. **TLS cliente/upstream MySQL** (ver limitaciones arriba).

## Criterio de aceptación (fase 1 — MySQL)

- Un proxy lanzado con `VETRO_WIRE_PROTOCOL=mysql` acepta conexiones de un driver MySQL
  real y reenvía queries seguras a un MySQL upstream, transparente para la app.
- Una query destructiva (DELETE sin WHERE, DROP, TRUNCATE, UPDATE sin WHERE) es
  bloqueada con un `ERR_Packet` nativo de MySQL — el driver la reporta como error, no
  como crash de conexión.
- La evaluación usa `Dialect::Mysql` en el engine.
- El proxy Postgres sigue funcionando idéntico (regresión verde, 412 casos).
- Telemetría y sync de reglas funcionan igual en ambos protocolos.
