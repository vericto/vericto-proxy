# Security Policy

Vericto Proxy is a security product. We take vulnerabilities seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report it privately, by either channel:

- Email **security@vericto.com**.
- Open a private report on GitHub:
  [Report a vulnerability](https://github.com/vericto/vericto-proxy/security/advisories/new)
  (Security tab → "Report a vulnerability"). Only the maintainers can see it.

Include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal SQL payload or AST input is ideal).
- The affected version or commit.
- Any suggested remediation.

You will receive an acknowledgement within **48 hours** and a status update
within **5 business days**.

## Scope

High-priority issues for this proxy include:

- **Evasion** — a destructive query that bypasses a rule that should block it
  (e.g. a `DELETE` without `WHERE` that is incorrectly allowed), including SQL
  that reaches the database without being evaluated.
- **Denial of service** — input that causes excessive CPU/memory (deeply nested
  ASTs, pathological queries, oversized messages). The proxy refuses to evaluate
  a statement larger than `VERICTO_MAX_QUERY_BYTES` (10 MiB by default), and the
  engine refuses statements nested more than 200 levels and stops walking an AST
  deeper than 50 levels; bypasses of any of these are in scope.
- **Fail-open behavior** — any path where an unparseable or malformed query is
  allowed instead of blocked when the policy says to block it.

Issues in rule evaluation itself can be reported here or to
[vericto-engine](https://github.com/vericto/vericto-engine/security); we route
them to the right repository.

## Disclosure process

1. Report received and acknowledged (within 48h).
2. We confirm and assess severity.
3. We develop and test a fix.
4. We release the fix and credit you (unless you prefer to remain anonymous).
5. Public disclosure after users have had reasonable time to update.

## Supported versions

Security fixes are applied to the latest released version. Older versions are
patched at the maintainers' discretion.

Thank you for helping keep Vericto and its users safe.
