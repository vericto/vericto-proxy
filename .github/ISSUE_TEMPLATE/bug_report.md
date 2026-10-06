---
name: Bug report
about: Something the proxy gets wrong on the wire, with TLS, telemetry, rule sync or its configuration
title: "[BUG] "
labels: bug
---

<!--
Security vulnerabilities: do not open an issue. Report them privately, see
https://github.com/vericto/vericto-proxy/security/policy

Rules and SQL parsing live in vericto-engine. If a specific statement got the wrong
verdict, you can report it here or in vericto-engine; we move issues to the right
repository.
-->

**What happened**
A clear description of what went wrong, and what you expected instead.

**Wire protocol**
- [ ] PostgreSQL
- [ ] MySQL

**Client**
Driver or ORM and its version (for example `psycopg 3.2`, `pgx v5`, `mysql2 3.11`).

**Proxy**
- Version or image tag (for example `ghcr.io/vericto/vericto-proxy:4.5.1`):
- Deployment (Docker, Kubernetes, ECS, binary):
- Configuration: the `UPSTREAM_*`, `PROXY_*` and `VERICTO_*` variables you set.
  Remove API keys, passwords and certificates before pasting.

**Steps to reproduce**
1.
2.

**SQL statement (if a query was blocked or allowed when it should not have been)**
```sql
-- the exact statement
```

**Logs**
Proxy output around the failure, ideally with `RUST_LOG=debug`. Remove anything sensitive.
```
paste relevant output here
```
