# Changelog

All notable changes to vetro-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/donkan168/vetro-proxy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/donkan168/vetro-proxy/releases/tag/v1.0.0
