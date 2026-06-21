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

## Contributing

We actively welcome new rules, dialect improvements, and parser fixes — this is
exactly where community knowledge adds the most value. See
[CONTRIBUTING.md](CONTRIBUTING.md) and our [security policy](SECURITY.md).

## License

Vetro Proxy is source-available under the [Elastic License 2.0](LICENSE). You
may freely use, modify, and redistribute it. You may **not** offer it to third
parties as a hosted or managed service. For a commercial managed-service
license, contact hola@vetro.dev.
