# Vericto Proxy

> Stops destructive SQL before it reaches your database, whether it comes from AI
> agents, scripts or people, with no code changes.

[![CI](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/vericto/vericto-proxy/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSING.md)
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

> **License.** Open source under the [AGPL-3.0-only](LICENSING.md), or under a
> commercial license from Vericto S.A.S. You can self-host it and use it for free,
> including in production at a for-profit company. Distributing it, or offering a
> modified version over a network, requires providing the source under the AGPL;
> anyone who cannot do that can ask for the commercial license. Versions up to
> 4.23.0 keep the license they were released with.
> [LICENSING.md](LICENSING.md) answers the common questions.

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
  -e UPSTREAM_HOST=vericto-demo-db vericto/vericto-proxy:5.0.1
until docker exec vericto-demo-db pg_isready -q -h localhost -U postgres; do sleep 1; done

docker run --rm --network vericto-demo postgres:17 \
  psql postgresql://postgres:demo@vericto-demo-proxy:5433/postgres \
  -c "CREATE TABLE users (id int PRIMARY KEY, email text)" \
  -c "INSERT INTO users VALUES (1, 'ana@example.com'), (42, 'bo@example.com')" \
  -c "DELETE FROM users" \
  -c "DELETE FROM users WHERE id = 42" \
  -c "SELECT id, email FROM users"
```

The image comes from Docker Hub; `ghcr.io/vericto/vericto-proxy:5.0.1` serves the
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

## Install the native binary

Every release from 5.0.1 on attaches prebuilt `vericto-proxy` binaries to its
[GitHub Release](https://github.com/vericto/vericto-proxy/releases), so neither
Docker nor a Rust toolchain is needed: the same binary runs the TCP proxy and
`vericto-proxy mcp`.

| Platform | Archive |
|---|---|
| Linux x86_64 (glibc 2.35 or later) | `vericto-proxy-x86_64-unknown-linux-gnu.tar.xz` |
| Linux aarch64 (glibc 2.35 or later) | `vericto-proxy-aarch64-unknown-linux-gnu.tar.xz` |
| macOS Apple silicon | `vericto-proxy-aarch64-apple-darwin.tar.xz` |
| macOS Intel | `vericto-proxy-x86_64-apple-darwin.tar.xz` |
| Windows x86_64 | `vericto-proxy-x86_64-pc-windows-msvc.zip` |

On Linux and macOS the installer script picks the archive for the machine, checks
its SHA-256 and puts `vericto-proxy` in `$CARGO_HOME/bin` (`~/.cargo/bin` by
default), adding that directory to `PATH` in your shell profile if needed:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/vericto/vericto-proxy/releases/download/v5.0.1/vericto-proxy-installer.sh | sh
vericto-proxy mcp --version
```

Or download an archive yourself. Each one has a `.sha256` file next to it (and
`sha256.sum` lists them all), and a build provenance attestation (Sigstore,
GitHub Actions) that ties it to this repository, the release workflow and the
commit:

```bash
v=5.0.1 t=x86_64-unknown-linux-gnu
base=https://github.com/vericto/vericto-proxy/releases/download/v$v
curl -fL -O "$base/vericto-proxy-$t.tar.xz" -O "$base/vericto-proxy-$t.tar.xz.sha256"
shasum -a 256 -c "vericto-proxy-$t.tar.xz.sha256"
gh attestation verify "vericto-proxy-$t.tar.xz" --repo vericto/vericto-proxy
tar -xJf "vericto-proxy-$t.tar.xz"   # vericto-proxy-$t/vericto-proxy
```

On Windows, check the `.zip` with `Get-FileHash -Algorithm SHA256` against its
`.sha256` file (or `gh attestation verify`) and unpack it with `Expand-Archive`.
There is no PowerShell installer yet. Each archive also carries `LICENSE`,
`NOTICE` and `THIRD_PARTY_LICENSES`.

The binaries are the plain release build; the container image adds
profile-guided optimization, which runs a statement in fewer instructions
([PGO](docs/PERFORMANCE.md#profile-guided-optimization-pgo)). To build from
source instead, see [CONTRIBUTING.md](CONTRIBUTING.md#run-from-source).

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

**PostgreSQL pipelines and prepared statements (4.17.3).** Local block and
session-context replies are ordered at the exact position of their upstream
response cycle, after every earlier pipelined result. Backend messages are framed,
so even a large row or COPY message is never split by a synthetic reply. Named and
unnamed prepared SQL is checked again at Bind and Execute after a rules, policy,
principal or session-context refresh; business policies that may read the time
(`time.*`) are checked on every Execute, the others keep the verdict reached under the
same rules, policy, bundle and session context (see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md)). If a mask or `rewrite_limit` would now require different SQL, the
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

**Kill switch (4.18.0).** When an owner or admin blocks an agent (or every agent of
the workspace) from the dashboard's Incident response panel, the proxy refuses every
statement of that database user from its next rule sync with `VERICTO-105` and the
kill-switch message the Runtime API returns, before anything is evaluated and in
every mode: `SELECT 1`, `SET` and `BEGIN` included, and statements prepared before
the block. Lifting the block restores the session at the following sync. See
[docs/AGENT_ACCESS.md](docs/AGENT_ACCESS.md#kill-switch-vericto-105).

---

## MCP: an agent runs SQL through Vericto (Proxy mode)

`vericto-proxy mcp` (4.21.0) is an MCP server for AI agents: Claude Code, Cursor,
Codex or any MCP client gets an `execute_sql` tool and **no database credential**.
Each statement is evaluated first, and the server runs exactly what it evaluated (or
the policy's rewrite of it) on PostgreSQL, read-only, in a transaction that always rolls
back, with row, size and time caps. `describe_schema`, a local `check_sql` and `whoami`
come with it. Over stdio for a developer's machine, or Streamable HTTP for a team.

**Try it without an account.** With no control plane configured it runs locally on the
built-in ruleset (the rules the TCP proxy runs standalone) and reports nothing:

```bash
claude mcp add vericto-db -- \
  docker run -i --rm --user "$(id -u):$(id -g)" \
    -v ~/.config/vericto/shop.url:/run/secrets/db.url:ro \
    vericto/vericto-proxy:5.0.1 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
```

Without Docker, with the [native binary](#install-the-native-binary):

```bash
claude mcp add vericto-db -- ~/.cargo/bin/vericto-proxy \
  mcp --database-url-file ~/.config/vericto/shop.url
```

**Connect to Vericto** for custom rules, business policies, sensitive-column masking,
audit and the dashboard: add `-e VERICTO_API_KEY=vtro_... -e VERICTO_DATABASE_ID=<id>`
(and pass both into the container). A configured control plane is never replaced by the
built-in rules: until its first signed bundle is in force the server answers
`NOT_READY`.

What is checked is what runs, **provided the agent has no other credential for the
database**: the server warns when its environment exposes one. Setup for each client
(with or without an account), the HTTP mode, the limits and the security notes are in
[docs/MCP.md](docs/MCP.md).

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
- **[Query admission limits](docs/CONFIGURATION.md#query-size-limit)**:
  `VERICTO_MAX_QUERY_BYTES` (1 MiB by default on TCP; MCP stays at 64 KiB) and a
  linear pre-parse guard against expressions with more than 10,000 binary operators
  (`VERICTO_MAX_BINARY_OPERATORS`).
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
`linux/arm64`, and pull without credentials. The image workflow (`docker.yml`)
copies the multi-arch index it pushed to GHCR, so both registries serve the same
digest under the same tags (`<version>`, `<major>.<minor>`, `<major>` and
`latest`): pull from whichever your environment allows.

```bash
# Postgres. On Linux, add --add-host=host.docker.internal:host-gateway
docker run --rm -e UPSTREAM_HOST=host.docker.internal -p 5433:5433 \
  vericto/vericto-proxy:5.0.1

# MySQL
docker run --rm \
  -e VERICTO_WIRE_PROTOCOL=mysql \
  -e UPSTREAM_HOST=host.docker.internal \
  -p 3307:3307 \
  vericto/vericto-proxy:5.0.1

# The same image from GHCR
docker pull ghcr.io/vericto/vericto-proxy:5.0.1
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
  image: ${VERICTO_PROXY_IMAGE:-vericto/vericto-proxy:5.0.1}
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

Copyright 2026 Vericto S.A.S. and contributors.

vericto-proxy 5.0.0 and later is open source under the
[GNU Affero General Public License, version 3 only](LICENSE)
(`AGPL-3.0-only`). Vericto S.A.S. also offers separate commercial licenses.
The AGPL permits commercial use and competition subject to its conditions; it
is not a non-compete license.

Versions 4.14.0 through 4.23.0 remain under FSL-1.1-ALv2, including its future
Apache-2.0 grant. Versions 4.13.0 and earlier remain under Elastic License 2.0.
[LICENSING.md](LICENSING.md) explains the options and embedded engine, and
[LICENSE_HISTORY.md](LICENSE_HISTORY.md) identifies the release boundaries.
See also [NOTICE](NOTICE), [TRADEMARKS.md](TRADEMARKS.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

The Docker image carries `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES` (the
licenses of dependencies compiled into the binary) and `RUNTIME_BASE_LICENSES`
(the pinned base-image packages and their license texts) in
`/usr/share/doc/vericto-proxy/`. Package SPDX documents remain under
`/var/lib/db/sbom`, and the image label is
`org.opencontainers.image.licenses=AGPL-3.0-only`. Each native release archive
(5.0.1 and later) carries `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES` next to
the binary. To read the image's copy:

```bash
# The image has no shell or `cat` (4.15.2 and later), so copy the file out:
id=$(docker create ghcr.io/vericto/vericto-proxy:latest)
docker cp "$id":/usr/share/doc/vericto-proxy/THIRD_PARTY_LICENSES - | tar -xO
docker rm "$id" >/dev/null
```
