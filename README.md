# Vetro Proxy

> Transparent PostgreSQL TCP proxy — deterministic SQL firewall in the wire path.

[![CI](https://github.com/donkan168/vetro-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/donkan168/vetro-proxy/actions/workflows/ci.yml)
[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vetro-proxy` is the **customer-facing TCP wire-protocol proxy**. It intercepts
every query via the PostgreSQL wire protocol, evaluates it with the
[vetro-engine](https://github.com/donkan168/vetro-engine) AST parser, and either
forwards it to the real database or blocks it — all in <2ms.

No AI, no stochastic heuristics — the same input always produces the same result.

> **For HTTP evaluation** (CI/CD dry-runs, dashboard): use
> [vetro-eval](https://github.com/donkan168/vetro-eval) instead.

---

## Architecture position

```
Your app / ORM
     │
     │  PostgreSQL wire protocol (port 5433)
     ▼
 vetro-proxy   ──── vetro-engine (lib) ────►  ALLOWED / BLOCKED
     │
     │  (if ALLOWED) forwards query
     ▼
 PostgreSQL upstream
```

Point your `DATABASE_URL` host at `vetro-proxy` instead of your real database.
No code changes required — your ORM/driver is unaware of the proxy.

---

## What it blocks

- `DELETE` / `UPDATE` without `WHERE`
- `DROP TABLE`, `DROP SCHEMA`, `TRUNCATE`
- OR-tautology SQL injection (`WHERE id = $1 OR 1=1`)
- `ALTER TABLE DROP COLUMN` / `RENAME`
- `INSERT` without explicit column list
- `SELECT *` without `WHERE`, `SELECT` without `LIMIT`
- … [full rule list →](https://vetro.dev/rules)

Blocked queries return a native PostgreSQL error `SQLSTATE 42501`
(insufficient_privilege) — no special handling needed in your application.

---

## Environment variables

### Required

| Variable           | Description                                            |
|--------------------|--------------------------------------------------------|
| `UPSTREAM_PG_HOST` | Hostname of the real PostgreSQL database to proxy to  |

### Optional — TCP proxy

| Variable              | Default | Description                                     |
|-----------------------|---------|------------------------------------------------|
| `PROXY_PG_LISTEN_PORT`| `5433`  | Port the TCP proxy listens on                  |
| `UPSTREAM_PG_PORT`    | `5432`  | Port of the upstream PostgreSQL database       |

### Optional — control-plane link (telemetry + rule sync)

When `VETRO_API_URL` and `VETRO_API_KEY` are set, the proxy reports blocked
queries to the Vetro API and polls the active ruleset every 5 minutes.
Without them the proxy runs with the built-in default ruleset only (suitable
for dev / air-gapped deployments).

| Variable                          | Default | Description                                      |
|-----------------------------------|---------|--------------------------------------------------|
| `VETRO_API_URL`                   | —       | e.g. `https://api.vetro.dev`                     |
| `VETRO_API_KEY`                   | —       | Workspace API key (`vtro_...`)                   |
| `VETRO_DATABASE_ID`               | —       | UUID of the database record in the Vetro platform|
| `VETRO_RULES_SYNC_INTERVAL_SECS`  | `300`   | How often to poll `/sync/rules` (seconds)        |
| `VETRO_TELEMETRY_BUFFER`          | `memory`| `memory` or `disk` (survives restarts)           |
| `VETRO_TELEMETRY_DISK_PATH`       | `/var/lib/vetro/spool` | Spool dir when `buffer_mode=disk`  |
| `VETRO_TELEMETRY_MEMORY_CAPACITY` | `10000` | Max events in memory ring buffer                 |
| `VETRO_TELEMETRY_BATCH_SIZE`      | `100`   | Max events per POST `/ingest/events`             |
| `VETRO_TELEMETRY_FLUSH_SECS`      | `5`     | How often the reporter flushes (seconds)         |

### Observability

| Variable        | Default | Description                                   |
|-----------------|---------|-----------------------------------------------|
| `RUST_LOG`      | `info`  | Log level (`info`, `debug`, `trace`)          |
| `RUST_BACKTRACE`| `0`     | Set to `1` to enable backtraces on panic      |

---

## Quick start

```bash
# Run locally (requires a local Postgres on 5432)
UPSTREAM_PG_HOST=localhost cargo run

# With control-plane link
UPSTREAM_PG_HOST=localhost \
VETRO_API_URL=https://api.vetro.dev \
VETRO_API_KEY=vtro_... \
VETRO_DATABASE_ID=your-db-uuid \
cargo run

# Tests
cargo test
cargo clippy -- -D warnings
cargo fmt
```

---

## Docker

```bash
docker build -t vetro/proxy:local .
docker run --rm \
  -e UPSTREAM_PG_HOST=host.docker.internal \
  -p 5433:5433 \
  vetro/proxy:local
```

In `docker-compose.yml` (vetro-fmw monorepo):

```yaml
proxy:
  image: ${VETRO_PROXY_IMAGE:-ghcr.io/donkan168/vetro-proxy:1.0.0}
  ports:
    - "5433:5433"
  environment:
    PROXY_PG_LISTEN_PORT: "5433"
    UPSTREAM_PG_HOST: postgres
    UPSTREAM_PG_PORT: "5432"
    # Optional — uncomment for telemetry + rule sync:
    # VETRO_API_URL: "http://api:4000"
    # VETRO_API_KEY: "${VETRO_API_KEY}"
    # VETRO_DATABASE_ID: "${VETRO_DATABASE_ID}"
```

To build and run a local image:

```bash
docker build -t vetro/proxy:local .
VETRO_PROXY_IMAGE=vetro/proxy:local docker compose up -d proxy
```

---

## Connection strings

| | Connection string |
|-|-------------------|
| **Via proxy (protected)** | `postgres://postgres:postgres@localhost:5433/vetro_dev` |
| **Direct (unprotected)**  | `postgres://postgres:postgres@localhost:54322/vetro_dev` |

---

## Contributing

Rules, dialect improvements, and parser fixes are the highest-value community
contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Elastic License 2.0 — source-available, no managed-service resale.
For a commercial license contact [hola@vetro.dev](mailto:hola@vetro.dev).
