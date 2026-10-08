# Vericto Proxy

> Transparent SQL TCP proxy — deterministic SQL firewall in the wire path.

[![CI](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml)
[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vericto-proxy` is the **customer-facing TCP wire-protocol proxy**. It intercepts
every query on the database wire protocol, evaluates it with the
[vericto-engine](https://github.com/vericto/vericto-engine) AST parser, and either
forwards it to the real database or blocks it.

One proxy instance fronts one database and speaks exactly one wire protocol,
chosen at deploy time with `VERICTO_WIRE_PROTOCOL`:

| `VERICTO_WIRE_PROTOCOL` | Databases | Block response |
|-----------------------|-----------|----------------|
| `postgres` (default)  | PostgreSQL | native `ErrorResponse` `SQLSTATE 42501` |
| `mysql`               | MySQL      | native `ERR_Packet` `ERROR 1142` |

Everything else — configuration, evaluation, telemetry — is **the same across
engines**. Only the value above and (optionally) the default ports change.

No AI, no stochastic heuristics — the same input always produces the same result.

> **Other dialects** (Oracle, SQL Server): evaluate via the
> [HTTP API](https://vericto.com/integration-guide#http-setup); there is no wire
> proxy for them.

---

## Try it with Docker

All you need is Docker: no account, no API key, no build. This starts a throwaway
Postgres, puts the proxy in front of it with the built-in ruleset, and sends a few
queries through it with the `psql` that ships in the Postgres image. The password
`demo` is only for this disposable database.

```bash
docker network create vericto-demo
docker run -d --name vericto-demo-db --network vericto-demo \
  -e POSTGRES_PASSWORD=demo postgres:17
docker run -d --name vericto-demo-proxy --network vericto-demo \
  -e UPSTREAM_HOST=vericto-demo-db ghcr.io/vericto/vericto-proxy:4.5.1
until docker exec vericto-demo-db pg_isready -q -h localhost -U postgres; do sleep 1; done

docker run --rm --network vericto-demo postgres:17 \
  psql postgresql://postgres:demo@vericto-demo-proxy:5433/postgres \
  -c "CREATE TABLE users (id int PRIMARY KEY, email text)" \
  -c "INSERT INTO users VALUES (1, 'ana@example.com'), (42, 'bo@example.com')" \
  -c "DELETE FROM users" \
  -c "DELETE FROM users WHERE id = 42" \
  -c "SELECT id, email FROM users"
```

The `DELETE` without a `WHERE` never reaches the database; the one with a `WHERE`
does:

```text
CREATE TABLE
INSERT 0 2
ERROR:  Vericto blocked this query [VERICTO-001] — AST node: DeleteStmt > WhereClause = NULL. Suggestion: DELETE FROM users WHERE id = $1
DELETE 1
 id |      email
----+-----------------
  1 | ana@example.com
(1 row)
```

`docker logs vericto-demo-proxy` shows the decision. To put the proxy in front of
your own database, see [Docker](#docker) and
[Connection strings](#connection-strings). Clean up with:

```bash
docker rm -f vericto-demo-db vericto-demo-proxy && docker network rm vericto-demo
```

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

With the built-in ruleset, these never reach the database:

- `DELETE` / `UPDATE` without `WHERE`
- `DROP TABLE`, `DROP SCHEMA`, `TRUNCATE`
- OR-tautology SQL injection (`WHERE id = $1 OR 1=1`)
- `ALTER TABLE DROP COLUMN` / `RENAME`
- … [full rule list →](https://vericto.com/rules-reference)

Lower-severity findings — `SELECT *` without `WHERE`, `SELECT` without `LIMIT`,
`INSERT` without an explicit column list — are forwarded and recorded rather than
blocked. With the control-plane link on, the workspace policy decides the action
for each severity.

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

If the control plane is unreachable, the proxy keeps enforcing the last ruleset and
policy it synced. With `VERICTO_TELEMETRY_BUFFER=disk` it also keeps a copy of them on
disk (`<spool dir>/.rules-cache`), so a restart during the outage resumes with the
workspace's custom rules and policy instead of only the built-in ruleset. Set
`VERICTO_RULES_CACHE_PATH` to put the copy elsewhere (or enable it with the memory
buffer), or to an empty value to turn it off.

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
| `VERICTO_RULES_CACHE_PATH`          | `<spool dir>/.rules-cache` with buffer=disk, else off | Last-good ruleset kept for restarts; empty = off |
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
| `PROXY_TLS_MODE`     | `disable` (def) \| `require` | Terminate client-side TLS. With `require`, a client that does not request TLS is refused (Postgres: SQLSTATE 28000) |
| `PROXY_TLS_CERT` / `PROXY_TLS_KEY` | —  | Server cert/key presented to clients. Either a **path** to a PEM file or the **PEM contents inline** — inline lets a secrets manager deliver the key, so it never has to be baked into the image |

> **MySQL TLS caveat:** TLS must be on **both** hops or neither — never one. The
> proxy participates in the handshake, and MySQL derives its auth scramble from
> the "secure connection" state, so a plaintext hop paired with a TLS hop breaks
> authentication by protocol design. Set `PROXY_TLS_MODE=require` **and**
> `UPSTREAM_SSLMODE=require` together (or leave both off). See
> [engine-specific notes](#engine-specific-notes).

### Query size limit

| Variable                  | Default              | Description                                   |
|---------------------------|----------------------|-----------------------------------------------|
| `VERICTO_MAX_QUERY_BYTES` | `10485760` (10 MiB)  | Largest statement the proxy evaluates         |

Evaluation runs before the query reaches the database, and its cost grows with the
statement's size. On the measurements in `src/tcp/query_limit.rs` it takes about
22 ms for 64 KB and 3.8 s for 10 MB. A statement over the limit is refused before it
is parsed, with the same native error as a blocked query and the code
`VERICTO-QUERY-TOO-LARGE`. In `monitor_mode` it is forwarded unevaluated instead.

A value larger than the wire protocol can carry is clamped, with a warning: 64 MiB for
PostgreSQL, 16 MiB − 1 byte for MySQL. A value that is not a positive integer falls
back to the default, also with a warning.

### Health check (optional)

| Variable               | Default | Description                                   |
|------------------------|---------|-----------------------------------------------|
| `VERICTO_HEALTHZ_PORT` | — (off) | TCP port for load-balancer health checks      |

The listener accepts each connection and closes it without exchanging any bytes, so
a probe is a plain TCP connect. It is separate from the traffic port and never
contacts the database: a database outage does not take the proxy out of rotation.

It opens only once warm-up is done: at startup without the control-plane link, or
after the first rule-sync attempt (successful or not) with it. Until then probes get
connection refused. The image's `HEALTHCHECK` probes this port when it is set. A
value that is not a valid port number is ignored, and the listener stays off.

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

## Run from source

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

Release images are published at `ghcr.io/vericto/vericto-proxy` for `linux/amd64`
and `linux/arm64`, and pull without credentials.

```bash
# Postgres. On Linux, add --add-host=host.docker.internal:host-gateway
docker run --rm -e UPSTREAM_HOST=host.docker.internal -p 5433:5433 \
  ghcr.io/vericto/vericto-proxy:4.5.1

# MySQL
docker run --rm \
  -e VERICTO_WIRE_PROTOCOL=mysql \
  -e UPSTREAM_HOST=host.docker.internal \
  -p 3307:3307 \
  ghcr.io/vericto/vericto-proxy:4.5.1
```

To build the image from this checkout instead:

```bash
docker build -t vericto/proxy:local .
```

With Docker Compose:

```yaml
proxy:
  image: ${VERICTO_PROXY_IMAGE:-ghcr.io/vericto/vericto-proxy:4.5.1}
  ports:
    - "5433:5433"
  environment:
    UPSTREAM_HOST: postgres
    UPSTREAM_PORT: "5432"
    PROXY_LISTEN_PORT: "5433"
    # For MySQL: VERICTO_WIRE_PROTOCOL: "mysql" + the matching ports.
    # Optional — uncomment for telemetry + rule sync (all three together):
    # VERICTO_API_URL: "https://api.vericto.com"
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

Wire-protocol, TLS, telemetry and deployment fixes belong here; rules and
parser changes belong in [vericto-engine](https://github.com/vericto/vericto-engine).
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Vericto S.A.S. Licensed under the Elastic License 2.0 — see
[LICENSE](LICENSE). Source-available, no managed-service resale.
For a commercial license contact [enterprise@vericto.com](mailto:enterprise@vericto.com).

The Docker image carries `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES` (the
licenses of every dependency compiled into the binary) in
`/usr/share/doc/vericto-proxy/`:

```bash
docker run --rm --entrypoint cat ghcr.io/vericto/vericto-proxy:latest \
  /usr/share/doc/vericto-proxy/THIRD_PARTY_LICENSES
```
