# Contributing to Vericto Proxy

Thanks for your interest in improving Vericto Proxy. This guide covers the TCP
wire-protocol proxy in this repository, which is source-available under the
[Elastic License 2.0](LICENSE). Contributions are accepted under the same license.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be
respectful, constructive, and technically precise.

## What belongs here

The proxy sits on the database wire protocol and calls
[vericto-engine](https://github.com/vericto/vericto-engine) in-process to decide
each query. Contributions that fit here:

- **Wire protocol** — PostgreSQL and MySQL message handling (`src/tcp/`).
- **TLS** — the client→proxy and proxy→database hops.
- **Telemetry and rule sync** — the control-plane link (`src/telemetry/`,
  `src/tcp/rules_sync.rs`).
- **Configuration, Docker image and deployment docs.**
- **Performance** — latency added on the query path; include measurements.

Contributions that belong in vericto-engine: new rules, rule evaluation, and SQL
parsing for any dialect.

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

Rules are implemented and tested in
[vericto-engine](https://github.com/vericto/vericto-engine) — see its
CONTRIBUTING guide. Once a rule ships in an engine release, the proxy picks it up
in two steps:

1. Bump the `vericto-engine` tag in `Cargo.toml`, keeping `pg_query` on the same
   major version as the engine (the comment there explains why).
2. If the rule should be part of the built-in ruleset used without the
   control-plane link, add its code, severity and default action to
   `default_ruleset()` in `src/tcp/evaluator.rs`, and to the table its tests check.

> A rule that produces false positives is worse than no rule. Always include a
> "must be allowed" test alongside the "must be blocked" test.

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(tcp): add MySQL wire protocol with TLS on both hops
fix(telemetry): stop one large query from stalling all delivery
feat(rules-sync): keep the last-good ruleset on disk across restarts
fix(tcp): disable Nagle on upstream socket to remove ~40ms latency
```

Scopes for this repo: `tcp`, `telemetry`, `rules-sync`, `config`, `healthz`,
`docker`, `deps`, `docs`.

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
