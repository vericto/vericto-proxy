# Vetro Proxy

> Deterministic SQL firewall — parse before it burns.

Vetro Proxy is the open core of [Vetro](https://vetro.dev): a deterministic SQL
security engine that parses every query into its Abstract Syntax Tree (AST) and
decides whether it is safe or destructive. No AI, no stochastic heuristics — the
same input always produces the same result.

This repository contains the **AST evaluation engine and rule set**. The hosted
platform (dashboard, audit trail, notifications, multi-tenancy, billing) is a
separate commercial product.

## Why deterministic?

LLM-based or heuristic SQL guards drift: the same query can be allowed today and
blocked tomorrow. Vetro evaluates a formal AST condition. A query either matches
a rule or it does not — auditable, reproducible, and fast (<2ms p99).

## What it does

- Parses SQL into an AST (`pg_query` for PostgreSQL, `sqlparser-rs` for MySQL,
  Oracle, and SQL Server).
- Evaluates a normalized AST against a deterministic rule set.
- Blocks destructive statements: `DELETE`/`UPDATE` without `WHERE`, `DROP`,
  `TRUNCATE`, OR-tautology SQL injection (`OR 1=1`), and more.
- Fails closed: a query that does not parse is blocked by default.

## Two modes

1. **HTTP evaluation endpoint** (`POST /evaluate`) — evaluate a query against a
   rule set without a database connection. Used for CI/CD dry-runs.
2. **Transparent PostgreSQL TCP proxy** — terminates the Postgres wire protocol.
   Point your driver at Vetro instead of your database; destructive queries are
   blocked with a native `SQLSTATE 42501` before they reach the database.

## Quick start

```bash
cargo run                 # starts on :5434 (PROXY_EVAL_PORT)
cargo test                # unit tests for parsers and rules
cargo clippy -- -D warnings
cargo fmt
```

Evaluate a query:

```bash
curl -X POST http://localhost:5434/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "DELETE FROM users",
    "dialect": "postgres",
    "workspace_id": "00000000-0000-0000-0000-000000000000",
    "rules": [
      { "rule_id": "r1", "code": "VETRO-001", "severity": "critical",
        "rule_type": "standard", "ast_condition_yaml": null }
    ]
  }'
```

## Supported dialects

| Dialect    | Parser              | HTTP eval | TCP proxy |
|------------|---------------------|-----------|-----------|
| PostgreSQL | pg_query            | ✅        | ✅        |
| MySQL      | sqlparser-rs        | ✅        | roadmap   |
| Oracle     | sqlparser-rs        | ✅        | n/a (OCI) |
| SQL Server | sqlparser-rs (TSQL) | ✅        | roadmap   |

## Built-in rules

| Code | Detection | Severity |
|------|-----------|----------|
| VETRO-001 | DELETE without WHERE | critical |
| VETRO-003 | DELETE with always-true WHERE (`1=1`) | critical |
| VETRO-010 | DROP TABLE / DATABASE | critical |
| VETRO-011 | TRUNCATE TABLE | critical |
| VETRO-012 | DROP SCHEMA | critical |
| VETRO-030 | UPDATE without WHERE (primary tables) | critical |
| VETRO-042 | UPDATE without WHERE | critical |
| VETRO-090 | OR tautology in WHERE (SQL injection — `OR 1=1`) | critical |
| VETRO-002 | DELETE with LIMIT 0 (MySQL) | high |
| VETRO-013 | DROP INDEX without IF EXISTS | high |
| VETRO-015 | ALTER TABLE DROP COLUMN | high |
| VETRO-016 | ALTER TABLE RENAME | high |
| VETRO-031 | UPDATE nested in CTE without WHERE | high |
| VETRO-033 | DELETE nested in subquery/CTE without WHERE | high |
| VETRO-040 | INSERT INTO … SELECT without filter | high |
| VETRO-070 | SLEEP() / PG_SLEEP() | high |
| VETRO-050 | SELECT without LIMIT | medium |
| VETRO-051 | SELECT * without WHERE | medium |
| VETRO-060 | INSERT without explicit columns | medium |
| VETRO-061 | INSERT batch > 10k rows | medium |

Custom rules are defined as YAML AST conditions (`node_type`, `condition`) and
evaluated against the same normalized AST. See [CONTRIBUTING.md](CONTRIBUTING.md)
to propose a new rule.

## Contributing

We actively welcome new rules, dialect improvements, and parser fixes — this is
exactly where community knowledge adds the most value. See
[CONTRIBUTING.md](CONTRIBUTING.md) and our [security policy](SECURITY.md).

## License

Vetro Proxy is source-available under the [Elastic License 2.0](LICENSE). You
may freely use, modify, and redistribute it. You may **not** offer it to third
parties as a hosted or managed service. For a commercial managed-service
license, contact hola@vetro.dev.
