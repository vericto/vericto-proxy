# Contributing to Vericto Proxy

Thanks for your interest in improving Vericto Proxy. This guide covers the
open-source AST engine in this repository. Contributions are accepted under the
project's [Elastic License 2.0](LICENSE).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be
respectful, constructive, and technically precise.

## Ways to contribute

- **New rules** — add detection for a destructive or risky SQL pattern.
- **Dialect support** — improve PostgreSQL, MySQL, Oracle, or SQL Server parsing.
- **Parser fixes** — handle AST edge cases (nested CTEs, subqueries, etc.).
- **Performance** — the engine targets <2ms p99; benchmarks are welcome.
- **Docs** — clarify rule semantics or the YAML condition schema.

## Getting started

```bash
git clone https://github.com/<you>/vericto-proxy.git
cd vericto-proxy
cargo build
cargo test
```

Requires Rust 1.88+ (the `pg_query` binding needs `libclang` and `protoc` — see
the Dockerfile for the exact system dependencies).

## Development workflow

1. Fork the repo and create a branch: `feat/my-rule` or `fix/mysql-delete`.
2. Make your change with tests.
3. Run the full check suite before opening a PR:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
4. Open a PR using the template. Keep PRs focused and under ~500 lines.

## Adding a new rule

1. Implement the evaluator in `src/rules/evaluator.rs`.
2. Register it with a `VERICTO-XXX` code and a severity (`critical`/`high`/`medium`).
3. Add unit tests in the same module covering:
   - A query that **must** be blocked (positive case).
   - A safe variant that **must** be allowed (regression guard against false positives).
4. Document the rule in `README.md` and the rule table.

> A rule that produces false positives is worse than no rule. Always include a
> "must be allowed" test alongside the "must be blocked" test.

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(rules): add MERGE statement detection for SQL Server
fix(parser): handle nested CTE in DELETE for postgres
perf(engine): cache compiled YAML conditions per ruleset
test(rules): add false-positive guards for VERICTO-051
```

Scopes for this repo: `engine`, `parser`, `rules`, `tcp`, `cli`, `docs`.

**Write in English** — commit subjects and bodies, code comments, test names, identifiers,
`CHANGELOG.md` entries and pull request descriptions. The codebase is source-available
under Elastic-2.0 and read by people who do not share a first language with its authors,
so a single language keeps it reviewable. Part of this repository's early history is in
Spanish; those commits are left as they are rather than rewritten, and everything from
here forward is English.

## Pull request acceptance criteria

- ✅ CI passes (`fmt`, `clippy -D warnings`, `cargo test`).
- ✅ New rules include both a blocked-case and an allowed-case test.
- ✅ At least one maintainer review.
- ✅ No new `unwrap()`/`expect()` on runtime paths — handle errors explicitly.
- ✅ Public functions documented with `///`.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Developer Certificate of Origin

By contributing, you certify that your contribution complies with the
[DCO](https://developercertificate.org/). Sign your commits with `git commit -s`.
