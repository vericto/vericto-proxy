# Vericto Proxy

> Transparent SQL TCP proxy — deterministic SQL firewall in the wire path.

[![CI](https://github.com/donkan168/vericto-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/donkan168/vericto-proxy/actions/workflows/ci.yml)
[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vericto-proxy` is the **customer-facing TCP wire-protocol proxy**. It intercepts
every query on the database wire protocol, evaluates it with the
[vericto-engine](https://github.com/donkan168/vericto-engine) AST parser, and either
forwards it to the real database or blocks it — all in <2ms.

One proxy instance fronts one database and speaks exactly one wire protocol,
chosen at deploy time with `VERICTO_WIRE_PROTOCOL`:

| `VERICTO_WIRE_PROTOCOL` | Databases | Block response |
|-----------------------|-----------|----------------|
| `postgres` (default)  | PostgreSQL | native `ErrorResponse` `SQLSTATE 42501` |
| `mysql`               | MySQL      | native `ERR_Packet` `ERROR 1142` |

Everything else — configuration, evaluation, telemetry — is **the same across
engines**. Only the value above and (optionally) the default ports change.

No AI, no stochastic heuristics — the same input always produces the same result.

> **Other dialects** (Oracle, SQL Server): evaluate via the HTTP API
> ([vericto-eval](https://github.com/donkan168/vericto-eval)); there is no wire
> proxy for them.

---

## Architecture position

```
Your app / ORM
     │
     │  SQL wire protocol (proxy listen port, default 5433)
     ▼
 vericto-proxy   ──── vericto-engine (lib) ────►  ALLOWED / BLOCKED
     │
     │  (if ALLOWED) forwards query
     ▼
 Real database upstream
```

Point your `DATABASE_URL` host at `vericto-proxy` instead of your real database.
No code changes required — your ORM/driver is unaware of the proxy.

---

## What it blocks

- `DELETE` / `UPDATE` without `WHERE`
- `DROP TABLE`, `DROP SCHEMA`, `TRUNCATE`
- OR-tautology SQL injection (`WHERE id = $1 OR 1=1`)
- `ALTER TABLE DROP COLUMN` / `RENAME`
- `INSERT` without explicit column list
- `SELECT *` without `WHERE`, `SELECT` without `LIMIT`
- … [full rule list →](https://vericto.com/rules)

A blocked query is returned as a **native error** for the active protocol (see
the table above), so no special handling is needed in your application.

---

## Configuration

All variables are **dialect-agnostic** — the same names apply to every engine.

### Required

| Variable       | Description                                             |
|----------------|---------------------------------------------------------|
| `UPSTREAM_HOST`| Hostname of the real database to proxy to               |

### Ports

| Variable            | Default | Description                                   |
|---------------------|---------|-----------------------------------------------|
| `UPSTREAM_PORT`     | protocol default¹ | Port of the upstream database        |
| `PROXY_LISTEN_PORT` | protocol default¹ | Port the proxy listens on            |

¹ Defaults follow `VERICTO_WIRE_PROTOCOL`: **Postgres** `5432` upstream / `5433`
listen; **MySQL** `3306` upstream / `3307` listen.

### Control-plane link (telemetry + rule sync)

Recommended for production. When `VERICTO_API_URL`, `VERICTO_API_KEY` **and**
`VERICTO_DATABASE_ID` are set, the proxy reports every decision and polls the
active ruleset. Without the link it still protects using the built-in ruleset
(dev / air-gapped), but reports nothing.

> **All three are needed for telemetry.** Without `VERICTO_DATABASE_ID` no events
> are emitted at all (there is nothing to attribute them to) — even if the API
> URL and key are set. It is also the key the control-plane uses to correlate
> telemetry and resolve per-database rules.

| Variable                          | Default | Description                                      |
|-----------------------------------|---------|--------------------------------------------------|
| `VERICTO_API_URL`                   | —       | e.g. `https://api.vericto.com`                     |
| `VERICTO_API_KEY`                   | —       | Workspace API key (`vtro_...`)                   |
| `VERICTO_DATABASE_ID`               | —       | UUID of the database record; enables + correlates telemetry |
| `VERICTO_RULES_SYNC_INTERVAL_SECS`  | `300`   | How often to poll `/sync/rules` (min 30)         |
| `VERICTO_TELEMETRY_BUFFER`          | `memory`| `memory` or `disk` (survives restarts)           |
| `VERICTO_TELEMETRY_DISK_PATH`       | `/var/lib/vericto/spool` | Spool dir when buffer=disk        |
| `VERICTO_TELEMETRY_MEMORY_CAPACITY` | `10000` | Max events in the memory ring buffer             |
| `VERICTO_TELEMETRY_BATCH_SIZE`      | `100`   | Max events per POST `/ingest/events`             |
| `VERICTO_TELEMETRY_FLUSH_SECS`      | `5`     | How often the reporter flushes                   |

### TLS (optional)

Encrypts each hop independently. `UPSTREAM_SSLMODE` covers the proxy→database
hop; `PROXY_TLS_MODE` covers the client→proxy hop.

| Variable             | Values / Default | Description                              |
|----------------------|------------------|------------------------------------------|
| `UPSTREAM_SSLMODE`   | `disable` (def) \| `require` \| `verify-full` | TLS to the database |
| `UPSTREAM_SSLROOTCERT`| —               | CA bundle (PEM) for `verify-full`        |
| `UPSTREAM_SSLCERT` / `UPSTREAM_SSLKEY` | —  | Client cert for upstream mutual TLS (Postgres) |
| `PROXY_TLS_MODE`     | `disable` (def) \| `require` | Terminate client-side TLS     |
| `PROXY_TLS_CERT` / `PROXY_TLS_KEY` | —  | Server cert/key presented to clients     |

> **MySQL TLS caveat:** TLS must be on **both** hops or neither — never one. The
> proxy participates in the handshake, and MySQL derives its auth scramble from
> the "secure connection" state, so a plaintext hop paired with a TLS hop breaks
> authentication by protocol design. Set `PROXY_TLS_MODE=require` **and**
> `UPSTREAM_SSLMODE=require` together (or leave both off). See
> [engine-specific notes](#engine-specific-notes).

### Observability

| Variable        | Default | Description                                   |
|-----------------|---------|-----------------------------------------------|
| `RUST_LOG`      | `info`  | Log level (`info`, `debug`, `trace`)          |
| `RUST_BACKTRACE`| `0`     | Set to `1` to enable backtraces on panic      |

---

## Engine-specific notes

Only two things differ per engine; everything above is shared.

- **`VERICTO_WIRE_PROTOCOL`** selects the protocol and the default ports (see
  [Ports](#ports)).
- **Block response** is native to each protocol: Postgres `ErrorResponse`
  (`SQLSTATE 42501`), MySQL `ERR_Packet` (`ERROR 1142`). Either way the driver
  sees a normal SQL error and the connection stays open.

### MySQL details

- The proxy speaks the MySQL classic protocol: it extracts SQL from `COM_QUERY`
  and `COM_STMT_PREPARE` (including the `CLIENT_QUERY_ATTRIBUTES` prefix MySQL
  8.0.23+ prepends) and evaluates it with the engine's `Mysql` dialect.
- **TLS is both-hops-or-neither** (see the TLS caveat above). For a trusted
  network (sidecar / private subnet) leave both plaintext — the default. When
  running the client plaintext, connect it with `--ssl-mode=DISABLED`.

---

## Quick start

```bash
# Postgres (default). Requires a local Postgres on 5432.
UPSTREAM_HOST=localhost cargo run

# MySQL. Requires a local MySQL on 3306.
VERICTO_WIRE_PROTOCOL=mysql UPSTREAM_HOST=localhost cargo run

# With the control-plane link (telemetry + rule sync)
UPSTREAM_HOST=localhost \
VERICTO_API_URL=https://api.vericto.com \
VERICTO_API_KEY=vtro_... \
VERICTO_DATABASE_ID=your-db-uuid \
cargo run

# Tests
cargo test
cargo clippy -- -D warnings
cargo fmt
```

---

## Docker

```bash
docker build -t vericto/proxy:local .

# Postgres
docker run --rm -e UPSTREAM_HOST=host.docker.internal -p 5433:5433 vericto/proxy:local

# MySQL
docker run --rm \
  -e VERICTO_WIRE_PROTOCOL=mysql \
  -e UPSTREAM_HOST=host.docker.internal \
  -p 3307:3307 \
  vericto/proxy:local
```

In `docker-compose.yml` (vericto-fmw monorepo):

```yaml
proxy:
  image: ${VERICTO_PROXY_IMAGE:-vericto/proxy:local}
  ports:
    - "5433:5433"
  environment:
    UPSTREAM_HOST: postgres
    UPSTREAM_PORT: "5432"
    PROXY_LISTEN_PORT: "5433"
    # For MySQL: VERICTO_WIRE_PROTOCOL: "mysql" + the matching ports.
    # Optional — uncomment for telemetry + rule sync (all three together):
    # VERICTO_API_URL: "http://api:4000"
    # VERICTO_API_KEY: "${VERICTO_API_KEY}"
    # VERICTO_DATABASE_ID: "${VERICTO_DATABASE_ID}"
```

---

## Connection strings

| | Connection string |
|-|-------------------|
| **Postgres via proxy** | `postgres://user:pass@localhost:5433/mydb` |
| **MySQL via proxy**    | `mysql://user:pass@localhost:3307/mydb` |

Same credentials as a direct connection — only the host/port change.

---

## Contributing

Rules, dialect improvements, and parser fixes are the highest-value community
contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Elastic License 2.0 — source-available, no managed-service resale.
For a commercial license contact [hola@vericto.com](mailto:hola@vericto.com).
