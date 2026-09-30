# Changelog

All notable changes to vericto-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Reports every rule a query violated, not only the reported winner.** This is
  the follow-up 4.3.2 left explicitly pending: adopting engine v3.5.0 added
  `EvaluationOutcome::violations` and that entry said consuming it needed the
  backend's `query_event_violations` table first. That table now exists and the
  API's `/ingest/events` schema accepts a `violations[]` array, so the gap closes
  here.

  The evidence gap was measured, not assumed. On a live local stack a
  `SELECT * FROM t` violates both VERICTO-050 (no LIMIT) and VERICTO-051 (star
  without WHERE) — the engine says so and `engine.rs` documents the tie-break — and
  only VERICTO-050 reached the database. For a product whose deliverable is the
  record of what a query broke, recording one of two findings is a silent loss.
  Verified after the change: the same query now stores both rows, each with its own
  resolved action, and a query blocked by VERICTO-003 also records VERICTO-090
  alongside it.

  `TcpDecision::Forward` and `::Block` now carry the set, and `build_telemetry_event`
  maps it. The decision is still derived from the winner alone, so reporting more
  cannot change whether a query is blocked — which is what makes the field safe to
  add to the hot path. Entry 0 is taken from the engine's own ordering rather than
  re-derived here, because re-deriving it could disagree with the decision the proxy
  already acted on.

  `rule_id` is deliberately NOT reported. The API types it as a UUID, while inside
  this proxy a rule's identity IS its code (`rules_sync` sets
  `rule_id: code.to_string()`, because that is what the control plane's sync
  endpoint keys the ruleset by). Sending it would put a non-UUID in a UUID field,
  and since the API parses the whole request body at once, that single field would
  reject the ENTIRE batch with a 400 — losing every event in it, not just this
  violation. The API resolves the code server-side, which is the only side holding
  the catalogue.

  Capped at 8 violations per event (`MAX_REPORTED_VIOLATIONS`). The binding
  constraint is the API's 1 MiB body limit for the whole batch, the same one
  `MAX_REPORTED_QUERY_BYTES` is sized against: at the default `batch_size` of 100
  the query text already accounts for ~800 KiB, leaving roughly 2.2 KiB per event
  for everything else, and a serialized violation runs ~150–250 bytes. Truncation
  keeps the head of the engine-ordered list, so the entry dropped is always the
  least severe and never the rule that decided the query's fate. An ALLOWED event
  omits the field entirely (`skip_serializing_if`), so the events that dominate real
  traffic do not grow by a single byte.

## [4.3.2] — 2026-08-10

### Changed

- **Adopts `vericto-engine` v3.5.0** (from v3.4.0). No code change and no
  behaviour change on the wire: v3.5.0 only *adds* `EvaluationOutcome::violations`,
  and every field this proxy reads keeps the same value for the same input.
  The pin is moved now rather than later so the two first-party hosts do not drift
  again — `vericto-eval` adopted v3.5.0 in 2.1.5, and leaving this one behind is
  how the stack ended up three releases out of step before.
  This proxy does not consume the new field yet. It could: reporting every
  violation in telemetry instead of only the winner is exactly the evidence gap
  v3.5.0 closes. But `TelemetryEvent` and the API's `/ingest/events` schema carry
  one rule per event, so that needs the backend's `query_event_violations` table
  first. Deliberately left for its own change rather than half-done here.
  Checked the two invariants this component cares about: `pg_query` still resolves
  to a single copy in the lock file (so the statically-linked `libpg_query` is not
  duplicated), and `default_ruleset()` still mirrors the engine catalogue.

## [4.3.1] — 2026-08-09

### Changed

- **Adopts `vericto-engine` v3.4.0** (from v3.2.4, three behaviour releases back).
  No code change here, but the proxy links the engine in-process, so what it
  blocks on the wire changes with it:
  - **Constant-only tautologies count as always-true** (engine 3.3.0). A statement
    whose only `WHERE` is `1 IN (1,2)`, `1 BETWEEN 0 AND 2` or `'x' LIKE '%'` is
    now refused with the native protocol error instead of being forwarded. This is
    the one change that rejects traffic the proxy previously passed, which is why
    the rollout puts workspaces into a timed observe window first — while that
    window is active the control plane sends `monitor_mode`, so these degrade to
    FLAG and are reported rather than blocked.
  - **A bounded set operation is no longer reported as unbounded** (engine 3.3.1).
    `SELECT … UNION SELECT … LIMIT 10` stops tripping VERICTO-050 on PostgreSQL,
    matching what the other dialects already did.
  - **A custom rule's `func_name:` predicate reaches any function** (engine 3.4.0),
    so a workspace rule naming `pg_read_file` or `dblink` fires where it silently
    did nothing before. VERICTO-070 still only fires on the sleep family.
  - `ParsedQuery::statements` is longer for queries containing ordinary functions,
    since every call is now recorded. Evaluation is linear in that count and the
    rule predicates short-circuit on `kind`; the wire path is unaffected in shape.
  `pg_query` still resolves to a single copy in the lock file, so the
  statically-linked `libpg_query` is not duplicated — the invariant the manifest
  calls out next to that dependency.

## [4.3.0] — 2026-08-08

Read before rolling out: this release **can reject queries that previously
reached the database**. Minor rather than patch for that reason.

### Added

- **`VERICTO_MAX_QUERY_BYTES` — an admission limit on the size of a query the
  proxy will evaluate.** Default **10 MiB**. A statement over the limit is
  refused with rule code `VERICTO-QUERY-TOO-LARGE` before being parsed, so a
  refused query costs neither the evaluation parse nor the telemetry sanitize
  pass.

  Why a limit at all: evaluation runs inline before the query reaches the
  database, and its cost is linear in input size. Measured on `pg_query` 6.2 with
  a wide `INSERT … VALUES` — the shape `MAX_AST_DEPTH` does not bound, since it
  limits nesting depth and not breadth:

  | size | evaluate | + sanitize | total |
  | --- | --- | --- | --- |
  | 64 KB | 20 ms | 1.7 ms | 22 ms |
  | 1 MB | 335 ms | 28 ms | 363 ms |
  | 4 MB | 1313 ms | 122 ms | 1435 ms |
  | 10 MB | 3440 ms | 382 ms | 3822 ms |

  About 0.35 ms/KB. Postgres framing accepts 64 MiB, which extrapolates to some
  23 s for a single statement. The default caps that at about 3.8 s.

  The default errs high on purpose. The statements that legitimately get large are
  batch inserts and long `IN` lists — 100 000 UUIDs is roughly 3.8 MB, a 5 000-row
  insert across 20 columns roughly 2 MB — and rejecting a customer's ETL is a
  worse outcome than evaluating it slowly.

  **The maximum is per wire protocol**, anchored to the codec's own framing cap
  rather than to a number of our choosing: 64 MiB on Postgres, 16 MiB − 1 on
  MySQL, whose protocol caps a packet there and which this proxy does not
  reassemble across packets. A configured value above the cap is clamped with a
  warning, since beyond it the codec already refuses the message. An unparseable
  or zero value falls back to the default, also with a warning.

  **`monitor_mode` is honoured**: a workspace in dry-run forwards the query
  unevaluated instead of rejecting it. The engine documents `monitor_mode` as
  forcing every blocking action to a non-blocking one and holds it under a
  property test asserting it never *increases* blocking — a size rejection there
  would be the one thing that blocks in a dry-run deployment. It is forwarded
  *unevaluated* because nothing could be enforced on the result, so paying seconds
  of CPU for an unactionable finding buys nothing.

  Refusal is deliberately not fail-open. Forwarding an unevaluated query would
  create a rule bypass that does not exist today: padding a statement past the
  limit would carry it to the database unexamined.

### Changed

- **CI now runs on pull requests that do not target `main`, and can be triggered
  manually.** The `pull_request` trigger filtered on `branches: [main]`, so a
  stacked PR — one based on another open branch — reported no checks at all and
  could be merged unverified; found by this release's own stacked PR, which came up
  with zero checks. And with no `workflow_dispatch`, re-running CI on a branch
  required pushing a commit — the hole we fell into during the GitHub Actions
  outage on 2026-08-06, when runs sat orphaned in `queued` and could be neither
  cancelled nor re-run. `push` is still restricted to `main`.
- **Evaluation and telemetry reporting now run on the blocking pool.** Both are
  CPU-bound and synchronous; on the async reactor they stall the worker thread and
  freeze every other connection scheduled on it, turning a per-connection cost
  into a multi-tenant one. The measured hop cost is ~7 µs (9.9 µs inline versus
  16.9 µs offloaded for a small query), negligible next to a database round trip,
  so the offload is unconditional rather than gated on size.
  Telemetry moves with evaluation because `sanitize_query` calls
  `pg_query::normalize`, which parses again — leaving it behind would keep about
  11% of the cost on the reactor.

## [4.2.2] — 2026-08-08

### Fixed

- **A single large query could stall all telemetry delivery.** `query_text` was
  reported in full, so any query over the API's ingest limits produced a batch the
  API refuses: 400 when a field exceeds the schema's 65 536, 413 when the batch
  exceeds the 1 MiB body limit. The reporter treated every non-2xx as retryable
  and `nack`ed the batch, which re-buffers at the *front* of the queue, then broke
  out of the drain loop. The rejected batch therefore sat at the head being
  re-sent once per flush tick, blocking every event behind it until the ring
  buffer churned past it.
  Two changes, either of which alone would leave a gap:
  - `query_text` is now truncated to 8 KiB when the event is built, with a visible
    marker. Applied at build time rather than at send time because the queue holds
    up to `memory_capacity` (10 000) events and the disk spool writes each one to
    a file — an unbounded field is a memory and disk problem before it is an HTTP
    one. The cut lands on a UTF-8 character boundary, since SQL carries arbitrary
    UTF-8 in identifiers, literals and comments.
  - The reporter now distinguishes permanent from retryable failures. 400, 413 and
    422 are properties of the bytes, so the batch is dropped (logged at `error`
    with the status and event count) instead of retried forever. Everything else
    still retries, including 401/403: a rotated or mistyped API key is an operator
    misconfiguration that is fixable without redeploying, so discarding telemetry
    over it would turn a recoverable mistake into silent data loss.

  The 8 KiB figure is derived, not picked: at the default `batch_size` of 100, the
  schema's own 65 536 would produce a ~6.5 MiB body, six times the API's limit.
  8 KiB keeps a full default batch near 800 KiB with room for the rest of each
  event and for JSON escaping. A compile-time assertion pins the arithmetic, so
  raising the limit past what the batch budget allows fails the build.

## [4.2.1] — 2026-08-08

### Changed

- **`vericto-engine` v3.2.3 → v3.2.4.** Equal-severity ties are now broken on the
  rule code instead of on the order the ruleset happens to arrive in. Previously
  the first matching rule in the synced slice won, and the control plane serves
  its ruleset from a query with no `ORDER BY`, so the same query could be reported
  under different codes between runs.
  **Nothing changes about what this proxy blocks.** Tied rules share a severity,
  so the resolved action is identical either way — a query that was blocked stays
  blocked, and one that passed still passes. What changes is the `rule_code`,
  `rule_id` and `ast_node_path` attached to the finding and to the native error
  returned to the client, which now stay stable across rule syncs.
  Unlike 4.2.0, this release is safe to deploy without auditing workloads.

## [4.2.0] — 2026-08-06

Read before rolling out: this release **blocks traffic it previously allowed**.
Minor rather than patch for that reason, even though no API or config changed.

### Changed

- **`vericto-engine` v3.2.1 → v3.2.3. VERICTO-070 now fires on `pg_sleep_until`
  for MySQL, Oracle and MS SQL**, and this proxy's default ruleset sets that rule
  to `Block` (`tcp/evaluator.rs`), so those queries are now **rejected at the
  wire** where they previously passed through.
  The engine kept its sleep-function list in two walkers and only the PostgreSQL
  one carried that name, so a time-based blind-injection probe using
  `pg_sleep_until` was blocked on PostgreSQL and silently forwarded on every other
  dialect. Closing that gap is the point of the release — but `pg_sleep_until` is
  a PostgreSQL function, so on a MySQL, Oracle or MS SQL upstream it would not
  have executed anyway. If a legitimate workload sends that identifier to a
  non-PostgreSQL database, it will now be refused.
  The rest of v3.2.2 and all of v3.2.3 are internal to the engine: a corrected
  dependency snippet in its docs with a guard test, removal of its unused
  `anyhow`/`tokio-test` dependencies, and removal of its CI cache step. No
  config, env-var, or wire-protocol change here.

## [4.1.0] — 2026-08-06

First release since 4.0.1. The versions 4.0.2 and 4.0.3 were bumped in
`Cargo.toml` but never tagged, so no image was ever published for them and they
are not releases; their contents ship here. Everything below is the accumulated
delta over 4.0.1.

### Added

- **Dedicated TCP health-check listener with a readiness gate**
  (`tcp/healthz.rs`), opt-in via `VERICTO_HEALTHZ_PORT` and disabled by default.
  Kept separate from the wire-protocol traffic port because MySQL's handshake is
  server-first: the proxy must connect upstream the moment it accepts, so a TCP
  probe on the traffic port would open and immediately discard a real database
  connection on every check. The `healthz` port answers probes without touching
  the upstream, and behaves identically for Postgres and MySQL.
  Readiness is gated by *not binding* the port until warm-up completes, because
  a TCP check succeeds as soon as the port is listening — before user space ever
  calls `accept()` — so declining to accept would not read as unhealthy. During
  warm-up probes get connection-refused; afterwards the port binds and accepts.
  Readiness flips after the first rule-sync *attempt*, whether it succeeded or
  failed, so a control-plane outage never pulls the proxy out of rotation. The
  check deliberately never probes the upstream database, so a database blip
  cannot cascade into every instance being pulled from rotation.

### Fixed

- **Adopt `vericto-engine v3.2.0`** (git dependency bumped from `v3.1.1`),
  picking up the VERICTO-010 false-positive fix: `DROP POLICY`, `DROP TRIGGER`,
  `DROP FUNCTION`, `DROP VIEW`, and `DROP SEQUENCE` are no longer flagged as a
  critical `DROP TABLE` at runtime. Schema/DDL detection now matches only
  `DROP TABLE`/`DROP DATABASE` (VERICTO-010); `DROP INDEX`/`DROP SCHEMA` keep
  their own rules (013 / 012).

  The runtime proxy keeps the full workspace policy (it does not set the new
  `schema_migration_cap`), so a genuine `DROP TABLE`/`DROP DATABASE` against a
  live database still blocks — only the mis-classified non-table drops stop
  firing.
- **Telemetry reported `dialect: "postgres"` for every evaluation**, including
  from a proxy fronting MySQL, because `build_telemetry_event` hardcoded the
  label. Rule evaluation itself was already dialect-correct — the session has
  always passed `proto.dialect()` into `evaluate()` — so only the reported label
  was wrong, and the control plane stores the dialect as reported. The dialect is
  now threaded from that same source of truth through `report_telemetry` into
  `build_telemetry_event`. Any MySQL evaluation recorded before this fix is
  mislabelled at rest in the control plane.
- **Adopt `vericto-engine v3.2.1`** (git dependency bumped from `v3.2.0`),
  picking up the VERICTO-040 false-positive fix. The engine flagged any
  `INSERT … SELECT` without checking whether the source was filtered, so
  `INSERT INTO t SELECT … WHERE id = $1` was reported — and **rejected at the
  wire, since this proxy's default ruleset sets VERICTO-040 to Block**. That
  made parameterised backfills fail against a live connection. The rule now
  fires only when the source has no effective `WHERE` and no row limit;
  `WHERE 1=1` bounds nothing and still fires.

### Changed

- **`pg_query` 5.1 → 6.2**, bumped in the same commit as the engine tag above
  and not separately. Both crates statically link `libpg_query`, so a
  major-version split between them would compile and link two copies of it.
  The engine moved to `pg_query` 6.2 in v3.2.1, so this line has to follow.
  Vendored PostgreSQL goes 16.1 → 17.7. The only call site here is
  `pg_query::normalize` in `tcp/postgres.rs`, whose signature is unchanged.
- **Custom-rule predicate `where_always_true` now matches more queries.** It
  previously only matched an always-true *OR branch* (`WHERE id = 5 OR 1=1`);
  it now also matches a WHERE that is trivially true as a whole (`WHERE 1=1`,
  `WHERE true`). A custom rule using that predicate may start blocking traffic
  it previously let through. Nothing that matched before stops matching.

## [4.0.1] — 2026-07-29

Maintenance release: no API, config, or behaviour changes.

### Changed

- **Adopt `vericto-engine v3.1.1`** (git dependency bumped from `v3.0.0`). Brings
  the full custom-rule predicate schema (nested `condition:` block, `FuncCall`
  node type, 8 predicates) into the in-process evaluation path. The proxy passes
  `ast_condition_yaml` straight through, so no code changes were needed.
- **Migrated to Rust edition 2024** (`edition = "2021"` → `"2024"`). Toolchain is
  already pinned to 1.88, which supports it; no source changes were required.
- Updated repository URL and README links from `donkan168/…` to `vericto/…` to
  reflect the repository transfer.

## [4.0.0] — 2026-07-16

Rebrand from **Vetro** to **Vericto**. Breaking release: environment variables,
the crate/container image, rule codes, and the contact domain were renamed, and
the service now targets the rebranded engine.

### Changed (breaking)

- **Environment variables renamed** `VETRO_*` → `VERICTO_*` (e.g.
  `VETRO_API_KEY` → `VERICTO_API_KEY`, `VETRO_DATABASE_ID`,
  `VETRO_WIRE_PROTOCOL`, `VETRO_TELEMETRY_*`, …). Deployments and the control
  plane that set these must migrate.
- **Renamed** crate and container image `vetro-proxy` → `vericto-proxy`.
- **Adopt `vericto-engine v3.0.0`** (git dependency updated to the renamed
  `vericto-engine` repository at tag `v3.0.0`); imports updated to
  `vericto_engine::…`.
- **Rule codes** referenced in code, tests and docs renamed `VETRO-NNN` →
  `VERICTO-NNN` to match the engine.
- **Contact domain** updated `vetro.dev` → `vericto.com`.

### Notes

- No change to the TCP wire-proxy behaviour; only naming and identifiers.
- Historical entries below were rewritten to the `vericto-*` / `VERICTO-*`
  names for readability; they were originally published under `vetro-*`.

## [3.0.0] — 2026-07-08

### Changed (breaking)

- **Dialect-agnostic environment variables.** The upstream/listen configuration
  is no longer prefixed per engine. Rename in every deployment:
  - `UPSTREAM_PG_HOST` / `UPSTREAM_MYSQL_HOST` → `UPSTREAM_HOST`
  - `UPSTREAM_PG_PORT` / `UPSTREAM_MYSQL_PORT` → `UPSTREAM_PORT`
  - `PROXY_PG_LISTEN_PORT` / `PROXY_MYSQL_LISTEN_PORT` → `PROXY_LISTEN_PORT`
  - `UPSTREAM_PG_SSLMODE` / `UPSTREAM_MYSQL_SSLMODE` → `UPSTREAM_SSLMODE`
  - `UPSTREAM_PG_SSLROOTCERT` → `UPSTREAM_SSLROOTCERT`
  - `UPSTREAM_PG_SSLCERT` / `UPSTREAM_PG_SSLKEY` → `UPSTREAM_SSLCERT` / `UPSTREAM_SSLKEY`

  The wire protocol is still selected by `VERICTO_WIRE_PROTOCOL` (`postgres` |
  `mysql`), which now only changes the DEFAULT ports (Postgres 5432/5433, MySQL
  3306/3307) when they are not set explicitly. There is no backward-compatible
  fallback — the old names are ignored.

### Fixed

- **Upstream-failure resilience.** If the upstream ended while the intercept
  loop was blocked reading from the client (e.g. the database dies mid-auth),
  the session used to leak a hung client connection. The relay and intercept are
  now joined so either end tears down the other. During the connection phase the
  proxy also answers a native `ErrorResponse` (`SQLSTATE 08006`) instead of a
  bare closed socket; once bytes are already flowing it falls back to a clean
  close to avoid corrupting the stream.
- **Docker image build.** The production `Dockerfile` produced a stub binary
  (missing `Cargo.toml`/lockfile in the builder stage) and failed the private
  git-dependency fetch (token treated as username, missing
  `CARGO_NET_GIT_FETCH_WITH_CLI`). It now builds the real binary.

## [2.3.0] — 2026-07-07

### Added

- Multi-dialect wire-protocol support via a runtime `WireProtocol` strategy: the
  active protocol is selected at deploy time with `VERICTO_WIRE_PROTOCOL`
  (`postgres` | `mysql`; defaults to `postgres`, so existing deployments are
  unchanged). The session loop — evaluation, telemetry, enforcement — is now
  shared, protocol-agnostic code; each protocol supplies only its framing,
  classification, and native block response.
- **MySQL wire protocol (Phase 1)**: transparent proxy for the MySQL classic
  protocol. Extracts SQL from `COM_QUERY` and `COM_STMT_PREPARE` (including the
  `CLIENT_QUERY_ATTRIBUTES` prefix added by MySQL 8.0.23+), evaluates it with
  `Dialect::Mysql`, and blocks destructive statements with a native `ERR_Packet`
  (`ERROR 1142 … [VERICTO-xxx]`) so the driver sees a SQL error, not a broken
  connection. Configured with `UPSTREAM_MYSQL_HOST`/`PORT` and
  `PROXY_MYSQL_LISTEN_PORT` (default 3307).
- **MySQL TLS on both hops** (client→proxy and proxy→MySQL): the proxy
  participates in the connection-phase handshake as a strict sequential auth
  state machine (matching ProxySQL/MaxScale), terminating client-side TLS and
  re-establishing TLS to the upstream. Both hops must share the "secure
  connection" state or the `caching_sha2_password` scramble mismatches, so
  single-hop TLS is unsupported by design. Enabled with `PROXY_TLS_MODE`/
  `PROXY_TLS_CERT`/`PROXY_TLS_KEY` (client hop) and `UPSTREAM_MYSQL_SSLMODE`
  (upstream hop).
- Surface the dashboard-configured database `dialect` in `/sync/rules`; the
  proxy logs a warning when the deployed `VERICTO_WIRE_PROTOCOL` does not match it.

### Fixed

- CI could not fetch the private `vericto-engine` git dependency on any branch that
  changed `Cargo.lock`: the credential rewrite treated the token as a username
  (headless password prompt) and `~/.cargo/git` was cached with a stale,
  unauthenticated checkout. Use `x-access-token:<token>` and drop `~/.cargo/git`
  from the cache.

## [2.2.0] — 2026-06-27

### Changed

- Bump `vericto-engine` to `v2.1.0`, which closes the rule-coverage gaps
  ENG-001…ENG-010 (8 new rules, plus fixes to LIMIT handling, nested-SELECT
  detection, sleep detection, tautology depth, and DROP DATABASE/SCHEMA).

### Added

- Register the 8 new engine rules in the built-in `default_ruleset()` (and its
  verbatim R13 mirror test): `VERICTO-080`/`VERICTO-081` (Critical — COPY PROGRAM,
  DO block) and `VERICTO-017`/`018`/`019`/`082`/`083`/`084` (High — ALTER TABLE
  DROP CONSTRAINT / ALTER COLUMN TYPE / DISABLE TRIGGER, GRANT/REVOKE, MERGE,
  CREATE TABLE AS). The catalogue now carries 28 rules.

## [1.0.0] — 2025-06

### Added

- Deterministic SQL firewall engine using AST parsing (no AI, no heuristics).
- PostgreSQL parsing via `pg_query` (libpg_query) — full-fidelity protobuf AST,
  including destructive statements nested in data-modifying CTEs.
- MySQL, Oracle, and SQL Server parsing via `sqlparser-rs`.
- 20 built-in rules (VERICTO-001 through VERICTO-090) covering DELETE/UPDATE without
  WHERE, DROP, TRUNCATE, ALTER TABLE, dangerous function calls, and OR-tautology
  SQL injection.
- Custom rules defined as YAML AST conditions.
- HTTP evaluation endpoint (`POST /evaluate`) for CI/CD dry-runs.
- Transparent PostgreSQL TCP wire-protocol proxy (simple + extended protocol);
  destructive queries are blocked with a native `SQLSTATE 42501`.
- Fail-closed behavior: unparseable queries are blocked by default.
- Per-workspace ruleset cache with TTL-based invalidation.
- Optional control-plane link: ruleset hot-sync and telemetry reporting.
- `/health` and `/metrics` (p50/p99 latency) endpoints.

[Unreleased]: https://github.com/donkan168/vericto-proxy/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/donkan168/vericto-proxy/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/donkan168/vericto-proxy/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/donkan168/vericto-proxy/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/donkan168/vericto-proxy/compare/v1.0.0...v2.2.0
[1.0.0]: https://github.com/donkan168/vericto-proxy/releases/tag/v1.0.0
