# Changelog

All notable changes to vetro-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

  The wire protocol is still selected by `VETRO_WIRE_PROTOCOL` (`postgres` |
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
  active protocol is selected at deploy time with `VETRO_WIRE_PROTOCOL`
  (`postgres` | `mysql`; defaults to `postgres`, so existing deployments are
  unchanged). The session loop — evaluation, telemetry, enforcement — is now
  shared, protocol-agnostic code; each protocol supplies only its framing,
  classification, and native block response.
- **MySQL wire protocol (Phase 1)**: transparent proxy for the MySQL classic
  protocol. Extracts SQL from `COM_QUERY` and `COM_STMT_PREPARE` (including the
  `CLIENT_QUERY_ATTRIBUTES` prefix added by MySQL 8.0.23+), evaluates it with
  `Dialect::Mysql`, and blocks destructive statements with a native `ERR_Packet`
  (`ERROR 1142 … [VETRO-xxx]`) so the driver sees a SQL error, not a broken
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
  proxy logs a warning when the deployed `VETRO_WIRE_PROTOCOL` does not match it.

### Fixed

- CI could not fetch the private `vetro-engine` git dependency on any branch that
  changed `Cargo.lock`: the credential rewrite treated the token as a username
  (headless password prompt) and `~/.cargo/git` was cached with a stale,
  unauthenticated checkout. Use `x-access-token:<token>` and drop `~/.cargo/git`
  from the cache.

## [2.2.0] — 2026-06-27

### Changed

- Bump `vetro-engine` to `v2.1.0`, which closes the rule-coverage gaps
  ENG-001…ENG-010 (8 new rules, plus fixes to LIMIT handling, nested-SELECT
  detection, sleep detection, tautology depth, and DROP DATABASE/SCHEMA).

### Added

- Register the 8 new engine rules in the built-in `default_ruleset()` (and its
  verbatim R13 mirror test): `VETRO-080`/`VETRO-081` (Critical — COPY PROGRAM,
  DO block) and `VETRO-017`/`018`/`019`/`082`/`083`/`084` (High — ALTER TABLE
  DROP CONSTRAINT / ALTER COLUMN TYPE / DISABLE TRIGGER, GRANT/REVOKE, MERGE,
  CREATE TABLE AS). The catalogue now carries 28 rules.

## [1.0.0] — 2025-06

### Added

- Deterministic SQL firewall engine using AST parsing (no AI, no heuristics).
- PostgreSQL parsing via `pg_query` (libpg_query) — full-fidelity protobuf AST,
  including destructive statements nested in data-modifying CTEs.
- MySQL, Oracle, and SQL Server parsing via `sqlparser-rs`.
- 20 built-in rules (VETRO-001 through VETRO-090) covering DELETE/UPDATE without
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

[Unreleased]: https://github.com/donkan168/vetro-proxy/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/donkan168/vetro-proxy/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/donkan168/vetro-proxy/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/donkan168/vetro-proxy/compare/v1.0.0...v2.2.0
[1.0.0]: https://github.com/donkan168/vetro-proxy/releases/tag/v1.0.0
