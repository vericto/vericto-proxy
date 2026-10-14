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

> **Other dialects** (Oracle, SQL Server, Snowflake): evaluate via the
> [HTTP API](https://vericto.com/integration-guide#http-setup), the CLI or MCP;
> there is no wire proxy for them. Snowflake has no TCP wire protocol at all, so
> `VERICTO_WIRE_PROTOCOL=snowflake` stops the proxy at startup with an error.

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

## Sensitive columns

Columns can be tagged as sensitive per database in the Vericto dashboard (Team and
Enterprise plans). The tags reach the proxy with the ruleset (`/sync/rules`, so the
control-plane link and `VERICTO_DATABASE_ID` are required) and are enforced on the
wire, before the database sees the query. Each tag has a policy; when a query reads
several tagged columns the strictest wins (`block` > `mask` > `flag`). A column read
is a projection: what the query returns, or copies into another table. A column used
only in `WHERE`, `JOIN`, `GROUP BY` or `ORDER BY` is not a read.

**The proxy enforces.** Unlike the Validation API or the CLI, which only advise,
what the proxy decides is what the database receives:

| Policy  | Postgres | MySQL |
|---------|----------|-------|
| `block` | The query never reaches the database: `ErrorResponse`, SQLSTATE 42501 | Never reaches the database: `ERR_Packet`, ERROR 1142 |
| `flag`  | Forwarded as sent, recorded as FLAGGED | Same |
| `mask`  | The proxy forwards a **rewritten** query in which the column is masked (`full`, `last4`, `email` or `hash`) under its own name, and never the original. The client receives masked values. | Same: the proxy forwards the rewritten query in the same `COM_QUERY` or `COM_STMT_PREPARE`, and never the original. |

What holds under `mask`:

- Both protocols of each database are rewritten. Postgres: a simple `Query` and the
  extended protocol's `Parse`; on a `Parse` the statement name and the parameter types
  are kept, and `$n` placeholders survive, so the client's `Bind`/`Execute` run
  unchanged. MySQL: `COM_QUERY` (keeping the `CLIENT_QUERY_ATTRIBUTES` prefix) and
  `COM_STMT_PREPARE`. The `?` placeholders survive in the same order, so the
  parameter count the server returns in `COM_STMT_PREPARE_OK` is the one the client
  expects, and `COM_STMT_EXECUTE` / `COM_STMT_SEND_LONG_DATA` pass through untouched.
  The proxy keeps no statement map: the client executes the id the server gave the
  rewritten statement.
- The MySQL masks use only functions present in MySQL 5.7 and 8.0, Aurora MySQL and
  MariaDB, and give the same values as on Postgres (`a***@example.io`, `****4242`).
  The rewrite is printed from the parsed statement, so comments and formatting are
  not kept (string literals are). A query the engine cannot reproduce faithfully
  (optimizer hints `/*+ … */`, `SQL_CALC_FOUND_ROWS` and the other SELECT modifiers,
  bit literals) is blocked rather than rewritten. Rule evaluation on MySQL follows
  MySQL's own reading of comments and string escapes; text the engine cannot read
  with certainty is blocked by `VERICTO-086`, tags or not.
- A masked column becomes `text` (a string on MySQL). A computed expression over it
  (`lower(email)`, `substring(card, 1, 4)`) is masked `full`, whatever the style.
- `SELECT *`, `t.*`, whole-row references (`row_to_json(t)`) and `COPY t TO` over a
  table with a masked or blocked column are blocked; list the columns. So are copies
  of a masked column into another table (`INSERT … SELECT`, `CREATE TABLE AS`), since
  masking them would change stored data.
- **Fail-safe:** if anything about the rewrite does not hold together (no rewritten
  query for a masked read, an empty rewrite or one with a NUL, a rewrite for a dialect
  without one, a rewrite that drops a `$n` or changes the number of `?` the client
  will bind), the proxy blocks with `VERICTO-085` and a message saying why (MySQL:
  ERROR 1142). It never forwards the original instead.
- `monitor_mode` never changes what runs: a would-be block or mask is forwarded as sent
  and recorded, as for every other rule.

With any `block` or `mask` tag configured, a query the engine cannot parse is
**blocked**, whatever the workspace's parse-error policy says: a query that cannot be
read cannot be shown not to read the column. With no tags, or only `flag` tags,
parse errors behave as before.

Every read of a tagged column is reported with rule code `VERICTO-085`, the tagged
columns it touched and, for a mask, the rewritten query next to the original (both
sanitized in sanitized telemetry mode: Postgres text with libpg_query, MySQL text with
the MySQL lexer, every literal and comment replaced). The two share the per-event query budget, so a
masked event is no larger than any other.

Known limits come from the engine, which works from the SQL alone: a view, function or
partition over a tagged table is not covered unless it is tagged too. See the
[engine documentation](https://github.com/vericto/vericto-engine#sensitive-columns-vericto-085).

---

## Agent access

An allowlist per database user (Team and Enterprise plans), set in the Vericto
dashboard: which tables and columns that user may read, and which it may write.
Everything else is denied (`VERICTO-087`). The policies reach the proxy with the
ruleset (`/sync/rules`, so the control-plane link and `VERICTO_DATABASE_ID` are
required), keyed by database user, with an optional `"*"` default for every user
not listed.

**The TCP proxy enforces per database user.** The identity of a session is the
user it authenticated as: the Postgres StartupMessage `user`, the MySQL
HandshakeResponse username. A database with a policy for user X applies it only to
sessions as X; a user with no policy (and no `"*"`) is not restricted, exactly as
before. To give an agent a dedicated proxy instance, give it its own database user
and a policy for that user.

| Outcome | Postgres | MySQL |
|---------|----------|-------|
| Allowed | Forwarded as sent | Same |
| Denied, policy `enforce` | Never reaches the database: `ErrorResponse`, SQLSTATE 42501, `[VERICTO-087]` and what was denied | Never reaches the database: `ERR_Packet`, ERROR 1142 |
| Denied, policy `observe` | Forwarded as sent, recorded as FLAGGED | Same |

- **Every reference counts**, not only what the query returns: `WHERE`, `JOIN`,
  `GROUP BY`, `ORDER BY`, subqueries, CTEs, `RETURNING`. `*` needs every column of
  the table granted. A write needs `read_write` on its target; DDL is always denied.
  Catalogue schemas (`information_schema`, `pg_catalog`, `mysql`, …) are denied
  unless listed. Both protocols of each database are covered: a Postgres simple
  `Query` and the extended protocol's `Parse` (the sequence is then discarded up to
  `Sync`), MySQL `COM_QUERY` and `COM_STMT_PREPARE`.
- **The identity cannot be changed from inside the session.** Under a policy,
  `SET ROLE`, `SET SESSION AUTHORIZATION`, `SET search_path`, `set_config('role', …)`
  and `USE` are denied by the engine, and so are the protocol commands that do the
  same outside SQL: a Postgres `FunctionCall` message, MySQL `COM_INIT_DB`,
  `COM_FIELD_LIST` and the replication/process commands, and any command the proxy
  does not know (deny by default). MySQL `COM_CHANGE_USER` is refused when the
  current or the target user has a policy. On Postgres, `search_path`, `role` and
  `session_authorization` set by the StartupMessage (as parameters or in
  `options`, e.g. `PGOPTIONS='-c search_path=…'`) are evaluated as the `SET` they
  are: under an enforced policy the connection is refused with 42501 before it
  reaches the database; under `observe` it is flagged.
- **Unqualified names resolve to the default schema** (vericto-engine 3.8.1). An
  entry without a schema is the table in the default schema only; a table of the
  same name in another schema needs an entry naming it. The default is the
  database's setting in the dashboard (`default_schema` in `/sync/rules`), else
  `public` on Postgres. On MySQL it is the session's current database: the one
  named at login, then each forwarded `COM_INIT_DB` or `USE` (allowed without a
  policy or under `observe`), which wins over the dashboard's setting; a name
  qualified with it (Prisma's `` `db`.`User` ``) matches entries without a schema.
  Postgres names compare as Postgres does (quoted names exactly, unquoted ones
  folded to lower case); MySQL table and database names compare exactly.
- **Writes and locks.** `DELETE` needs a `read_write` entry for the table, whatever
  its column list, and is reported as the table. `SELECT … FOR UPDATE` /
  `FOR SHARE` need `read_write` on each locked table.
- **Policy changes apply to open sessions.** The policy is selected again for every
  statement, so a sync that adds, changes or removes it takes effect on each
  session's next statement, without reconnecting. The last-good policies are kept in
  the rules cache with the rest of the bundle.
- Session statements drivers send on connect (transaction control, `SET NAMES`,
  time zone, timeouts, Rails' `sql_mode` setup) are allowed; other `SET` statements
  are denied under a policy. Under `enforce`, a query the engine cannot parse is
  blocked.
- **With sensitive columns:** a `block` tag still wins; a column that is allowed and
  tagged `mask` comes back masked; a column that is not allowed is denied whether or
  not it is tagged.
- `monitor_mode` turns a would-be block into a flag, as for every rule.

Every event carries the session's `db_user`; under a policy also its mode
(`access_policy_mode`) and what was denied (`access_denied`: schema, table, column
and whether it needed read, write or ddl). Names only: in sanitized telemetry mode,
a MySQL name the query did not spell as an identifier (a `"…"` string the engine
also reads as a possible column) is reported as `?`.

Known limits come from the engine, which works from the SQL alone: a view or
function over a table is not resolved to it (grant the view itself), and an
unqualified column in a multi-table query must be allowed in every table it could
belong to (qualify it). See the
[engine documentation](https://github.com/vericto/vericto-engine#agent-access-allowlists-vericto-087).

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
| `VERICTO_API_URL`                   | —       | e.g. `https://api.vericto.com`. Must be `https://` (the API key travels with every request); `http://` only for a loopback host |
| `VERICTO_ALLOW_INSECURE_API_URL`    | `false` | `true` accepts an `http://` API URL on any host: development stacks only |
| `VERICTO_API_KEY`                   | —       | Workspace API key (`vtro_...`)                   |
| `VERICTO_DATABASE_ID`               | —       | UUID of the database record; enables + correlates telemetry |
| `VERICTO_RULES_SYNC_INTERVAL_SECS`  | `300`   | How often to poll `/sync/rules` (min 30)         |
| `VERICTO_TELEMETRY_BUFFER`          | `memory`| `memory` or `disk` (survives restarts)           |
| `VERICTO_TELEMETRY_DISK_PATH`       | `/var/lib/vericto/spool` | Spool dir when buffer=disk        |
| `VERICTO_TELEMETRY_SPOOL_SUBDIR`    | — (off) | buffer=disk, several proxies on one volume: spool to `<spool dir>/tasks/<name>/`, `<name>` = `task` (ECS task id, else hostname), `hostname`, or a fixed name. See [Several proxies on one volume](#several-proxies-on-one-volume) |
| `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` | `600` | With `VERICTO_TELEMETRY_SPOOL_SUBDIR`: a proxy's directory whose lease is this old is adopted by a live one (min 120) |
| `VERICTO_RULES_CACHE_PATH`          | `<spool dir>/.rules-cache` with buffer=disk, else off | Last-good ruleset kept for restarts; empty = off |
| `VERICTO_TELEMETRY_MEMORY_CAPACITY` | `10000` | Max undelivered events in the memory ring buffer (oldest dropped past it). With buffer=disk it also bounds the spool's event count when set, as it did up to 4.11 |
| `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` | `1073741824` (1 GiB) | buffer=disk: most bytes of spool files kept on disk; past it the oldest are dropped and counted (min 1 MiB). See [Disk spool size](#disk-spool-size) |
| `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS` | — (bytes only) | buffer=disk: optional event bound on top of the byte bound; unset, `VERICTO_TELEMETRY_MEMORY_CAPACITY` applies if set |
| `VERICTO_TELEMETRY_BATCH_SIZE`      | `500`   | Max events per POST `/ingest/events` (at most 500, the API's limit); this many pending events trigger a send |
| `VERICTO_TELEMETRY_FLUSH_SECS`      | `5`     | Longest the oldest pending event waits before a partial batch is sent (whichever comes first with the batch size) |
| `VERICTO_TELEMETRY_MAX_IN_FLIGHT`   | `4`     | POSTs outstanding at once (1–64)                 |
| `VERICTO_TELEMETRY_GZIP`            | `true`  | gzip request bodies (`Content-Encoding: gzip`); turned off automatically if the API refuses them |
| `VERICTO_TELEMETRY_RETRY_BASE_MS`   | `1000`  | First wait after a retryable delivery failure; doubles per consecutive failure |
| `VERICTO_TELEMETRY_RETRY_MAX_SECS`  | `60`    | Longest wait between delivery retries            |
| `VERICTO_TELEMETRY_QUEUE_CAPACITY`  | `2048`  | buffer=disk: events queued in memory for the spool writer; past it new events are dropped and counted, queries never wait |
| `VERICTO_TELEMETRY_SPOOL_FLUSH_MS`  | `50`    | buffer=disk: longest an event waits before its batch is written and fsynced |
| `VERICTO_TELEMETRY_SPOOL_BATCH_MAX` | `1000`  | buffer=disk: most events per spool file (one write and fsync) |
| `VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS` | `5000` | On SIGTERM/SIGINT: time allowed to write queued events to the spool and deliver what it can before exiting |

Telemetry never holds a statement back. The query path only places the event in
memory; with `buffer=disk` a background writer persists events to the spool in
batches (one file per batch, fsynced), so a slow or network volume such as EFS
adds no latency to queries. An event reaches the disk at most
`VERICTO_TELEMETRY_SPOOL_FLUSH_MS` after its statement ran; a crash (not a
SIGTERM) inside that window loses those events. The proxy logs
`Telemetry pipeline stats` every minute while there is activity: queue depth,
spooled events, dropped events and the batch write time, and the delivery side:
events delivered, requests, retries, events refused permanently, requests in
flight and the last and longest request time.

Delivery (since 4.11.0) sends a batch as soon as `VERICTO_TELEMETRY_BATCH_SIZE`
events are pending, or when the oldest has waited `VERICTO_TELEMETRY_FLUSH_SECS`,
with up to `VERICTO_TELEMETRY_MAX_IN_FLIGHT` requests outstanding. An event leaves
the buffer only when the request that carried it is answered 2xx, whatever order the
answers arrive in; a retryable failure (network, 5xx, 429, 401/403) keeps the batch
for a later attempt with exponential backoff, a 413 splits the batch, and a
payload the API refuses (400, 415, 422) is dropped and logged at `error`.

Since 4.12.0 every rule sync (`GET /api/v1/sync/rules`, every
`VERICTO_RULES_SYNC_INTERVAL_SECS`) also sends the pipeline's counters in the
`X-Vericto-Telemetry-Stats` header, as compact JSON: events enqueued and
delivered, events dropped by cause (`dropped_queue_full`, `evicted_oldest`,
`dropped_permanent`, `write_failures`, and `dropped_quota`, see below), the events
and bytes buffered right now, and whether telemetry is paused for the quota
(`quota_paused`, `quota_resets_at`). The totals are since the process started, under a random `instance_id`
drawn at startup, so the Vericto API can tell new drops from a restart and show
them in the dashboard. No query text, user name or address is in it. An API that
does not know the header ignores it. The header also says how far behind delivery
is: `oldest_undelivered_age_s` (seconds since the oldest event still waiting was
recorded, 0 when none waits), `last_delivery_at` (the last 2xx, `null` before the
first) and `spool_max_bytes` (the spool's bound, 0 with the memory buffer). The
same figures are in [Metrics](#metrics).

#### Over the monthly quota

On a plan with a hard monthly query limit the API refuses telemetry past it. Since
4.12.0, when `/ingest/events` answers 429 with `code: "QUOTA_EXCEEDED"` and the
reset time (`error.resets_at` or `Retry-After`), or a rule sync says
`telemetry_quota: "exceeded"`, the proxy **pauses telemetry**: it keeps evaluating
and enforcing every query exactly as before, but sends and retries nothing, and new
events are not buffered (counted as `dropped_quota`, so the spool does not fill
with events the API would refuse). Events buffered before the pause wait. It
resumes when a rule sync says `telemetry_quota: "ok"` (after an upgrade, or in the
new month), at the latest one `VERICTO_RULES_SYNC_INTERVAL_SECS` later, or when the
reset time passes. The log has one WARN when it pauses and one INFO when it
resumes. Any other 429 keeps the retries with backoff.

#### Disk spool size

Up to 4.11 the spool held at most 10,000 events (`VERICTO_TELEMETRY_MEMORY_CAPACITY`),
under 7 seconds of an API outage at 1,500 statements per second. Since 4.12.0 it
is bounded by bytes, `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`, default 1 GiB:

- **Event size.** The test `the_default_spool_bound_covers_minutes_of_an_api_outage`
  (`src/tcp/postgres.rs`) evaluates a pgbench-style mix (the staging benchmark's
  traffic) plus statements that break rules, with the built-in ruleset, and
  measures the spool lines exactly as written: **417 bytes per event on average**.
- **Outage covered.** 1 GiB / (417 B × 1,500 events/s) ≈ **28 minutes** of API
  outage before the oldest events are dropped; ~12 minutes if events average
  1 KiB (long statements, several violations). At lower traffic, proportionally
  more.
- **Storage.** 1 GiB is 5% of the 20 GiB of ephemeral storage a Fargate task gets
  by default, and on EFS (elastic, no size to provision) it is about 1 GiB-month
  of standard storage at most. Writing at the rate above is ~0.6 MiB/s.
- **Files.** The spool also keeps at most 100,000 segment files, which bounds the
  proxy's in-memory index (~200 bytes per file) and the directory it lists at
  startup when traffic is so low that every file carries a single event.

Raise the bound for longer outages if the volume has room; lower it on a small
volume. A deployment that set `VERICTO_TELEMETRY_MEMORY_CAPACITY` keeps that
event bound on the spool as well, so set `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS` (or
remove the variable) to let the spool grow to the byte bound. Spool files are
named `seg-<seq>-<count>-<bytes>.jsonl` since 4.12.0; 4.12 reads the files of
earlier versions, but an earlier version ignores 4.12's (they stay on disk,
undelivered), so let the spool drain before a downgrade.

#### Several proxies on one volume

A disk spool belongs to one process: it names its files from its own counter,
bounds them by its own `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`, and deletes each one
when the API acknowledges it. Replicas that mount one volume at the same path (an
ECS service with one EFS access point) must not share the directory: each would
send the others' events too, count them against its own bound and evict them.
Set `VERICTO_TELEMETRY_SPOOL_SUBDIR=task` (or `hostname`, or a name per replica):

- Each proxy spools to `<spool dir>/tasks/<name>/` and holds a lease there,
  `.lease`, rewritten every 30 seconds and released on a clean shutdown.
- At startup and every minute a proxy adopts the directories of the others whose
  lease is released or older than `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` (default
  10 minutes): it renames each one into its own `adopted/` directory and delivers
  its events first, within its own byte bound. A task that is stopped or replaced
  therefore leaves nothing behind for good. The rename is the claim: it is atomic
  on a local filesystem and on NFSv4 (EFS), so when two proxies race for the same
  directory exactly one gets it, and nobody reads a directory it did not rename.
- Spool files at the top of the shared directory (written before the setting was
  turned on) are claimed the same way, one file at a time.
- The rules cache stays at `<spool dir>/.rules-cache`, shared: every replica syncs
  the same rules and writes the file atomically under its own temporary name.

A proxy that is alive but cannot write its lease for the whole orphan window (its
volume unreachable for ten minutes) can have its directory adopted under it: it
logs an error and continues in a fresh directory, and the adopter delivers what was
moved. The API deduplicates events by id, so a batch in flight at that moment that
is sent twice is stored once. Before a downgrade to a version without the setting,
let the spool drain: older versions do not read `tasks/`.

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
| `VERICTO_HEALTHZ_ADDR` | `0.0.0.0` | Address the health-check listener binds (an IP; an invalid value stops the proxy at startup). The image's `HEALTHCHECK` probes `127.0.0.1`: with another address, probe that one instead |

The listener accepts each connection and closes it without exchanging any bytes, so
a probe is a plain TCP connect. (Since 4.12.0 it closes when the peer does, or after
2 seconds of silence, and answers an HTTP request: `GET /metrics` when enabled, a 404
otherwise.) It is separate from the traffic port and never
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
| `VERICTO_METRICS_PROMETHEUS` | `false` | Serve `GET /metrics` (Prometheus text) on the health-check listener; needs `VERICTO_HEALTHZ_PORT` |
| `VERICTO_METRICS_EMF` | `false` | Write the metrics as one CloudWatch Embedded Metric Format line on stdout per interval |
| `VERICTO_METRICS_EMF_NAMESPACE` | `Vericto/Proxy` | CloudWatch namespace of the EMF line |
| `VERICTO_METRICS_EMF_INTERVAL_SECS` | `60` | Seconds between EMF lines (10–3600) |
| `VERICTO_METRICS_PROXY_NAME` | `vericto-proxy` | The EMF `ProxyName` dimension |
| `VERICTO_METRICS_EMF_TASK_DIMENSION` | `true` | Also publish under `[ProxyName, TaskId]` (ECS task id, else hostname) |

#### Metrics

Since 4.12.0 the telemetry pipeline is also visible locally, in two opt-in forms with
the same figures. All names start with `vericto_proxy_`:

| Metric | Type | Meaning |
|--------|------|---------|
| `vericto_proxy_telemetry_oldest_undelivered_age_seconds` | gauge | Age of the oldest event not yet delivered; 0 when none waits |
| `vericto_proxy_telemetry_seconds_since_last_delivery` | gauge | Seconds without a successful delivery while events wait; 0 when none waits |
| `vericto_proxy_telemetry_last_delivery_timestamp_seconds` | gauge | Unix time of the last 2xx (Prometheus only; 0 before the first) |
| `vericto_proxy_telemetry_spool_bytes` / `_spool_events` | gauge | What is buffered now |
| `vericto_proxy_telemetry_spool_capacity_bytes` / `_spool_used_percent` | gauge | The spool's bound and how full it is (0 with the memory buffer) |
| `vericto_proxy_telemetry_enqueued_total` / `_delivered_total` | counter | Events accepted and delivered since the process started |
| `vericto_proxy_telemetry_dropped_total{cause}` | counter | Dropped events; `cause` is `queue_full`, `evicted`, `permanent`, `write_failure` or `quota` (not recorded while over the monthly quota) |
| `vericto_proxy_telemetry_quota_paused` | gauge | 1 while telemetry is paused for the monthly quota |
| `vericto_proxy_telemetry_requests_in_flight` | gauge | Telemetry requests outstanding |
| `vericto_proxy_info{version,buffer}` / `vericto_proxy_telemetry_enabled` | gauge | Build and buffer; whether the control-plane link is on |

- **Prometheus**: `VERICTO_METRICS_PROMETHEUS=true` serves `GET /metrics` on the
  health-check listener (`VERICTO_HEALTHZ_PORT`), never on the database port.
- **CloudWatch EMF**: `VERICTO_METRICS_EMF=true` writes one JSON line per
  `VERICTO_METRICS_EMF_INTERVAL_SECS` to stdout; with the `awslogs` log driver
  CloudWatch Logs turns it into metrics in `VERICTO_METRICS_EMF_NAMESPACE`, under the
  dimension sets `[ProxyName]` and `[ProxyName, TaskId]`. Alarm on `[ProxyName]` with
  the `Maximum` statistic (the worst task): task ids change with every deployment.
  Counters are sent as what happened during the interval: `vericto_proxy_telemetry_delivered`,
  `_dropped_queue_full`, `_dropped_evicted`, `_dropped_permanent`,
  `_dropped_write_failure`, `_dropped_quota`, and `_dropped_loss` (every cause but
  the quota). Each `TaskId` series is a custom metric; set
  `VERICTO_METRICS_EMF_TASK_DIMENSION=false` to publish only `[ProxyName]`.

What they never carry: query text, database user names, client addresses, or
workspace, database or API-key ids. The only labels are `cause` (five fixed values),
`version` and `buffer` (one value each per process), so the number of series is
fixed whatever the traffic. The figures are not secret, but they say how busy the
database is: bind the health-check listener to a private address
(`VERICTO_HEALTHZ_ADDR`), keep its port reachable only from the load balancer and
your monitoring, and never expose it to the internet.

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
  network (sidecar / private subnet) leave both plaintext — the default. A
  plaintext proxy does not offer TLS in its greeting, so a client in the default
  `ssl-mode=PREFERRED` connects in plaintext, as it would to a server without
  TLS; one that requires TLS is refused by the client itself. With
  `PROXY_TLS_MODE=require`, a client that does not ask for TLS gets
  `ERROR 3159 (HY000)`, as from a server with `require_secure_transport`.
- **No protocol compression.** The proxy reads each command as a plain packet,
  so it clears `CLIENT_COMPRESS` and zstd from the greeting and from the
  client's response, and clients see what a server with
  `protocol_compression_algorithms=uncompressed` offers: one that prefers
  compression (`--compress`, a list that includes `uncompressed`, mysql2
  `compress: true`) runs uncompressed; one that allows only `zlib` or `zstd` is
  refused at connect with `ERROR 2066`.

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

# Also run the sensitive-column tests against a real Postgres (each creates and
# drops its own database; without the variable they are skipped)
VERICTO_TEST_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres cargo test sensitive_tests

# ... and a real MySQL (5.7 or 8.0), over COM_QUERY and prepared statements
VERICTO_TEST_MYSQL_URL=mysql://root:secret@127.0.0.1:3306 cargo test sensitive_tests
# The agent-access tests (access_tests) use the same variables; they also create
# and drop their own roles / users, so the admin URL needs that privilege.
# for a MySQL that requires TLS, both hops use it: add
#   VERICTO_TEST_MYSQL_SSLMODE=require \
#   VERICTO_TEST_MYSQL_TLS_CERT=proxy-cert.pem VERICTO_TEST_MYSQL_TLS_KEY=proxy-key.pem
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

Images released from now on carry a build provenance attestation (Sigstore,
GitHub Actions) that ties their digest to this repository, the release workflow
and the commit. Verify one before you deploy it, and deploy by digest:

```bash
gh attestation verify oci://ghcr.io/vericto/vericto-proxy:<version> --repo vericto/vericto-proxy
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
