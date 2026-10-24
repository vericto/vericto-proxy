# Vericto Proxy

> Stops destructive SQL before it reaches your database, whether it comes from AI
> agents, scripts or people, with no code changes.

[![CI](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue.svg)](LICENSING.md)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Docker Hub](https://img.shields.io/docker/v/vericto/vericto-proxy?sort=semver&label=docker%20hub)](https://hub.docker.com/r/vericto/vericto-proxy)

AI agents, scripts and people all run SQL against production with real credentials.
Nobody reads each statement before it runs, and a database role decides what a user
may touch, not whether this particular statement should run. One `DELETE` without a
`WHERE` empties a table. A `SELECT` of the wrong columns copies emails or card
numbers to wherever the result goes.

`vericto-proxy` sits between your clients and the database, on the database's own
wire protocol. It parses every query with the
[vericto-engine](https://github.com/vericto/vericto-engine) AST parser, checks it
against your rules, and either forwards it to the real database or blocks it with a
normal SQL error. Your application only changes the host and port in its connection
string.

> **License.** Source-available under the
> [FSL-1.1-ALv2](LICENSING.md). You can self-host it and use it for free, including
> in production at a for-profit company. What it does not allow is a Competing Use:
> making it available to others in a commercial product or service that substitutes
> for it or offers substantially similar functionality, such as a SQL firewall
> service built on it. Each release also becomes Apache-2.0 two years after Vericto
> makes it available. [LICENSING.md](LICENSING.md) answers the common questions.

One proxy instance fronts one database and speaks exactly one wire protocol,
chosen at deploy time with `VERICTO_WIRE_PROTOCOL`:

| `VERICTO_WIRE_PROTOCOL` | Databases | Block response |
|-----------------------|-----------|----------------|
| `postgres` (default)  | PostgreSQL | native `ErrorResponse` `SQLSTATE 42501` |
| `mysql`               | MySQL      | native `ERR_Packet` `ERROR 1142` |

Everything else — configuration, evaluation, telemetry — is **the same across
engines**. Only the value above and (optionally) the default ports change.

No AI, no stochastic heuristics — the same input always produces the same result.

> **Other dialects** (Oracle, SQL Server, Snowflake, SQLite): evaluate via the
> [HTTP API](https://vericto.com/integration-guide#http-setup), the CLI or MCP;
> there is no wire proxy for them. Snowflake has no TCP wire protocol at all, so
> `VERICTO_WIRE_PROTOCOL=snowflake` stops the proxy at startup with an error.
> SQLite is a library linked into the application, with no wire protocol either:
> its SQL is checked in the application, before it runs.

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
  -e UPSTREAM_HOST=vericto-demo-db vericto/vericto-proxy:4.17.1
until docker exec vericto-demo-db pg_isready -q -h localhost -U postgres; do sleep 1; done

docker run --rm --network vericto-demo postgres:17 \
  psql postgresql://postgres:demo@vericto-demo-proxy:5433/postgres \
  -c "CREATE TABLE users (id int PRIMARY KEY, email text)" \
  -c "INSERT INTO users VALUES (1, 'ana@example.com'), (42, 'bo@example.com')" \
  -c "DELETE FROM users" \
  -c "DELETE FROM users WHERE id = 42" \
  -c "SELECT id, email FROM users"
```

The image comes from Docker Hub; `ghcr.io/vericto/vericto-proxy:4.17.1` serves the
same digest (see [Docker](#docker)).

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

For assertion-based coverage of the article's extended protocol, pipelines,
prepared-policy refresh, TLS/SCRAM, cancellation, COPY and PostgreSQL 18 cases,
run [`examples/postgres-wire-article/run.sh`](examples/postgres-wire-article/README.md).

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

**Bounded reads (4.17.0).** To cap what an agent reads instead of only flagging
it, a business policy with `action: { rewrite_limit: n }` (the LIMIT cap template
in rewrite mode) makes the proxy forward the statement with `LIMIT n` added, or a
larger `LIMIT` lowered, on Postgres and MySQL, simple and prepared statements. It
needs `VERICTO_POLICY_RULES=enforce`; see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#business-policy-rules-preview-off-by-default).

A blocked query is returned as a **native error** for the active protocol (see
the table above), so no special handling is needed in your application.

**PostgreSQL pipelines and prepared statements (4.17.1).** Local block and
session-context replies are ordered at the exact position of their upstream
response cycle, after every earlier pipelined result. Backend messages are framed,
so even a large row or COPY message is never split by a synthetic reply. Named and
unnamed prepared SQL is checked again at Bind and Execute after a rules, policy,
principal or session-context refresh; active time-dependent business policies are checked on
every Execute. If a mask or `rewrite_limit` would now require different SQL, the
proxy returns `VERICTO-PREPARED-STALE` and the client must close and prepare the
statement again. Portals retain the plan they bound even after their source
statement is closed or replaced. PostgreSQL COPY BOTH/replication is rejected by
closing the session rather than risk response mis-ordering. A FunctionCall denied
by an agent-access policy also closes, because a Query-based ordering marker would
change unnamed-statement state. MySQL behavior is unchanged in this patch: a MySQL
prepared statement is still checked when prepared, not refreshed when it is later
executed.

---

## Sensitive columns

Columns can be tagged as sensitive per database in the Vericto dashboard (Team and
Enterprise plans). The tags reach the proxy with the ruleset (`/sync/rules`, so the
control-plane link and `VERICTO_DATABASE_ID` are required) and are enforced on the
wire, before the database sees the query. When a query reads several tagged columns
the strictest policy wins (`block` > `mask` > `flag`). **The proxy enforces:** unlike
the Validation API or the CLI, which only advise, what the proxy decides is what the
database receives.

| Policy  | Postgres | MySQL |
|---------|----------|-------|
| `block` | The query never reaches the database: `ErrorResponse`, SQLSTATE 42501 | Never reaches the database: `ERR_Packet`, ERROR 1142 |
| `flag`  | Forwarded as sent, recorded as FLAGGED | Same |
| `mask`  | The proxy forwards a **rewritten** query in which the column is masked (`full`, `last4`, `email` or `hash`) under its own name, and never the original. The client receives masked values. | Same: the proxy forwards the rewritten query in the same `COM_QUERY` or `COM_STMT_PREPARE`, and never the original. |

If a rewrite does not hold together, the proxy blocks with `VERICTO-085` rather than
forward the original. `SELECT *` over a table with a masked or blocked column is
blocked; list the columns. The full behaviour (both protocols, prepared statements,
fail-safe cases, parse errors, telemetry, known limits) is in
[docs/SENSITIVE_COLUMNS.md](docs/SENSITIVE_COLUMNS.md).

---

## Agent access

An allowlist per database user (Team and Enterprise plans), set in the Vericto
dashboard: which tables and columns that user may read, and which it may write.
Everything else is denied (`VERICTO-087`). The policies reach the proxy with the
ruleset (`/sync/rules`, so the control-plane link and `VERICTO_DATABASE_ID` are
required), keyed by database user, with an optional `"*"` default for every user
not listed.

The identity of a session is the database user it authenticated as, so give each
agent its own database user and a policy for that user. Under a policy, every
reference counts (`WHERE`, `JOIN`, subqueries, `RETURNING`, not only what the query
returns), DDL is always denied, and the identity cannot be changed from inside the
session (`SET ROLE`, `USE`, `COM_CHANGE_USER` and the like are denied). A policy in
`observe` mode records what it would deny and forwards the query.

The full behaviour (name resolution, writes and locks, policy changes on open
sessions, telemetry, known limits) is in [docs/AGENT_ACCESS.md](docs/AGENT_ACCESS.md).

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

### Everything else

The rest is optional and documented in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md):

- **[Control-plane link](docs/CONFIGURATION.md#control-plane-link-telemetry--rule-sync)**
  (`VERICTO_API_URL`, `VERICTO_API_KEY`, `VERICTO_DATABASE_ID`, all three
  together): reports decisions to the Vericto API and syncs the workspace's rules
  and policy. Without it the proxy still protects with the built-in ruleset, and
  reports nothing. Also covers the telemetry buffer,
  [over the monthly quota](docs/CONFIGURATION.md#over-the-monthly-quota),
  [disk spool size](docs/CONFIGURATION.md#disk-spool-size) and
  [several proxies on one volume](docs/CONFIGURATION.md#several-proxies-on-one-volume).
- **[TLS](docs/CONFIGURATION.md#tls-optional)** on each hop, client→proxy and
  proxy→database. On MySQL, TLS must be on both hops or neither.
- **[Query size limit](docs/CONFIGURATION.md#query-size-limit)**
  (`VERICTO_MAX_QUERY_BYTES`, 10 MiB by default).
- **[Business policy rules](docs/CONFIGURATION.md#business-policy-rules-preview-off-by-default)**
  (`VERICTO_POLICY_RULES`, `off` by default): a preview, off unless you turn it
  on; with it off the proxy skips principal-aware policy evaluation. PostgreSQL
  response ordering and prepared-statement tracking remain active. With it on, the proxy
  applies only sync bundles whose Ed25519 signature verifies
  ([`VERICTO_BUNDLE_SIGNING_KEYS`](docs/CONFIGURATION.md#business-policy-rules-preview-off-by-default)
  for a control plane other than Vericto's).
- **[Health check](docs/CONFIGURATION.md#health-check-optional)** for load
  balancers (`VERICTO_HEALTHZ_PORT`).
- **[Observability](docs/CONFIGURATION.md#observability)**: logs, and
  [metrics](docs/CONFIGURATION.md#metrics) as Prometheus or CloudWatch EMF.
- **[CPU sizing](docs/CONFIGURATION.md#cpu-sizing)**: capacity per vCPU, when to
  scale out (CPU at 50–60% of the task's reservation), and `VERICTO_WORKER_THREADS`
  (by default sized from the container's CPU limit, 1 worker on a 0.5 vCPU task).
- **[Engine-specific notes](docs/CONFIGURATION.md#engine-specific-notes)**,
  including [MySQL details](docs/CONFIGURATION.md#mysql-details) (TLS, protocol
  compression).

To run from source and run the tests, see
[CONTRIBUTING.md](CONTRIBUTING.md#run-from-source).

---

## Docker

Release images are published on Docker Hub as
[`vericto/vericto-proxy`](https://hub.docker.com/r/vericto/vericto-proxy) (from
4.14.1 on) and at `ghcr.io/vericto/vericto-proxy`, for `linux/amd64` and
`linux/arm64`, and pull without credentials. The release workflow copies the
multi-arch index it pushed to GHCR, so both registries serve the same digest under
the same tags (`<version>`, `<major>.<minor>`, `<major>` and `latest`): pull from
whichever your environment allows.

```bash
# Postgres. On Linux, add --add-host=host.docker.internal:host-gateway
docker run --rm -e UPSTREAM_HOST=host.docker.internal -p 5433:5433 \
  vericto/vericto-proxy:4.17.1

# MySQL
docker run --rm \
  -e VERICTO_WIRE_PROTOCOL=mysql \
  -e UPSTREAM_HOST=host.docker.internal \
  -p 3307:3307 \
  vericto/vericto-proxy:4.17.1

# The same image from GHCR
docker pull ghcr.io/vericto/vericto-proxy:4.17.1
```

Images released from now on carry a build provenance attestation (Sigstore,
GitHub Actions) that ties their digest to this repository, the release workflow
and the commit. Verify one before you deploy it, and deploy by digest:

```bash
gh attestation verify oci://ghcr.io/vericto/vericto-proxy:<version> --repo vericto/vericto-proxy

# Docker Hub (4.14.1 and later): the same digest, attested under its Docker Hub name
gh attestation verify oci://docker.io/vericto/vericto-proxy:<version> --repo vericto/vericto-proxy
```

Each platform image (4.15.2 and later) also carries a signed SPDX SBOM attestation,
made for the platform manifest's digest (`docker buildx imagetools inspect` lists
both):

```bash
gh attestation verify oci://ghcr.io/vericto/vericto-proxy@<platform digest> \
  --repo vericto/vericto-proxy --predicate-type https://spdx.dev/Document/v2.3
```

The runtime base is [Chainguard `glibc-dynamic`](https://images.chainguard.dev/directory/image/glibc-dynamic/overview)
(4.15.2 and later; `debian:bookworm-slim` before): glibc, libgcc and the CA bundle,
**no shell and no package manager**. The proxy runs as `65532:65532` (`nonroot`; it
was `1001:1001` up to 4.15.1, so `chown` a volume an older image wrote, or pass
`--user 1001:1001`). Health checks call the binary instead of a shell, in exec form:
`["CMD", "/usr/local/bin/vericto-proxy", "healthcheck"]` (Docker Compose
`healthcheck.test`, ECS `healthCheck.command`). It connects to the healthz listener
(`VERICTO_HEALTHZ_PORT`) and exits 0 when that succeeds or the port is not set,
1 otherwise. A `CMD-SHELL` check, `bash -c`, `curl` or `wget` fails in this image.

To build the image from this checkout instead:

```bash
docker build -t vericto/proxy:local .
```

With Docker Compose:

```yaml
proxy:
  image: ${VERICTO_PROXY_IMAGE:-vericto/vericto-proxy:4.17.1}
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

Copyright 2026 Vericto S.A.S. Source-available under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(SPDX `FSL-1.1-ALv2`) since 4.14.0: use, modify and redistribute it for any
purpose other than a Competing Use, and each version becomes Apache-2.0 two
years after it is released. Versions 4.13.0 and earlier remain under the
Elastic License 2.0. [LICENSING.md](LICENSING.md) answers the common questions,
including how the embedded vericto-engine is licensed; see also
[NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md).
For a commercial license contact [enterprise@vericto.com](mailto:enterprise@vericto.com).

The Docker image carries `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES` (the
licenses of every dependency compiled into the binary) in
`/usr/share/doc/vericto-proxy/`, and the label
`org.opencontainers.image.licenses=FSL-1.1-ALv2`:

```bash
# The image has no shell or `cat` (4.15.2 and later), so copy the file out:
id=$(docker create ghcr.io/vericto/vericto-proxy:latest)
docker cp "$id":/usr/share/doc/vericto-proxy/THIRD_PARTY_LICENSES - | tar -xO
docker rm "$id" >/dev/null
```
