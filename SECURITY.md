# Security Policy

Vericto Proxy is a security product. We take vulnerabilities seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@vericto.com** with:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal SQL payload or AST input is ideal).
- The affected version or commit.
- Any suggested remediation.

You will receive an acknowledgement within **48 hours** and a status update
within **5 business days**.

## Scope

High-priority issues for this engine include:

- **Evasion** — a destructive query that bypasses a rule that should block it
  (e.g. a `DELETE` without `WHERE` that is incorrectly allowed).
- **Parser denial of service** — input that causes excessive CPU/memory
  (deeply nested ASTs, pathological queries). The engine enforces a 64KB query
  limit and 50-level AST depth limit as defenses; bypasses of these are in scope.
- **Fail-open behavior** — any path where an unparseable or malformed query is
  allowed instead of blocked.

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
