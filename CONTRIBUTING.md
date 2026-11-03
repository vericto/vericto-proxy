# Contributing to Vericto Proxy

Thanks for your interest in improving Vericto Proxy. This guide covers the TCP
wire-protocol proxy in this repository, which is open source under the
[GNU Affero General Public License, version 3 only](LICENSE)
(AGPL-3.0-only) and also available under a commercial license (see
[LICENSING.md](LICENSING.md)). Contributions are accepted under the Vericto
[Contributor License Agreement](#license-and-contributor-license-agreement).

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

## Run from source

```bash
# Postgres (default). Requires a local Postgres on 5432.
UPSTREAM_HOST=localhost cargo run

# MySQL. Requires a local MySQL on 3306.
VERICTO_WIRE_PROTOCOL=mysql UPSTREAM_HOST=localhost cargo run

# With the control-plane link (telemetry + rule sync)
UPSTREAM_HOST=localhost \
VERICTO_API_URL=https://api.vericto.com \
VERICTO_API_KEY=vtro_... \
VERICTO_DATABASE_ID=your-db-uuid \
cargo run

# Tests
cargo test
cargo clippy -- -D warnings
cargo fmt

# Also run the sensitive-column tests against a real Postgres (each creates and
# drops its own database; without the variable they are skipped)
VERICTO_TEST_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres cargo test sensitive_tests

# ... and a real MySQL (5.7 or 8.0), over COM_QUERY and prepared statements
VERICTO_TEST_MYSQL_URL=mysql://root:secret@127.0.0.1:3306 cargo test sensitive_tests
# The agent-access tests (access_tests) use the same variables; they also create
# and drop their own roles / users, so the admin URL needs that privilege.
# for a MySQL that requires TLS, both hops use it: add
#   VERICTO_TEST_MYSQL_SSLMODE=require \
#   VERICTO_TEST_MYSQL_TLS_CERT=proxy-cert.pem VERICTO_TEST_MYSQL_TLS_KEY=proxy-key.pem
```

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
   major version as the engine (the comment there explains why). If `pg_query`
   changes version, update `third-party/pg_query-bundled.txt` too: it holds the
   licenses of the C code that crate compiles in, and the image build stops when
   its version line does not match `Cargo.lock`. The same goes for
   `third-party/mimalloc-bundled.txt` and the `libmimalloc-sys` crate (the C
   allocator it compiles in).
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
`CHANGELOG.md` entries and pull request descriptions. The codebase is open source
under AGPL-3.0-only and read by people who do not share a first language with its authors,
so a single language keeps it reviewable. Part of this repository's early history is in
Spanish; those commits are left as they are rather than rewritten, and everything from
here forward is English.

## Pull request acceptance criteria

- ✅ CI passes (`fmt`, `clippy -D warnings`, `cargo test`).
- ✅ The performance gate passes: no workload of the corpus costs more than 3%
  more instructions per statement than the base, and every statement is answered
  as before ([docs/PERFORMANCE.md](docs/PERFORMANCE.md#ci-performance-gate)).
- ✅ The Contributor License Agreement is signed.
- ✅ New rules include both a blocked-case and an allowed-case test.
- ✅ At least one maintainer review.
- ✅ No new `unwrap()`/`expect()` on runtime paths — handle errors explicitly.
- ✅ Public functions documented with `///`.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License and Contributor License Agreement

vericto-proxy 5.0.0 and later is open source under the
[GNU Affero General Public License, version 3 only](LICENSE)
(`AGPL-3.0-only`). Vericto S.A.S. also offers separate commercial licenses.
Older releases keep their original terms; see [LICENSING.md](LICENSING.md) and
[LICENSE_HISTORY.md](LICENSE_HISTORY.md).

Before a pull request can be merged, every human commit author must sign the
Vericto Individual Contributor License Agreement, version 1.1
([CLA index](CLA.md), permanent text [legal/cla/1.1.md](legal/cla/1.1.md)). The
agreement lets Vericto distribute accepted contributions under the project's
public license and under separate commercial licenses while the contributor
keeps copyright.

Read the agreement and post this exact pull-request comment:

```
I have read the CLA Document and I hereby sign the CLA
```

The CLA workflow records your GitHub username and numeric account ID,
repository ID, pull-request number, comment ID, comment timestamp, CLA version
and SHA-256 document hash in `signatures/v1.1/cla.json` on the
`cla-signatures` branch. The data and retention are described in
[CLA_PRIVACY_NOTICE.md](CLA_PRIVACY_NOTICE.md). If the check does not rerun,
comment `recheck`. A commit whose email is not linked to a GitHub account
cannot be matched to a signer. Closed pull requests are locked to preserve the
signature comment.

If an employer, client or other person may own rights in your contribution,
obtain written authorization and send it to
[legal@vericto.com](mailto:legal@vericto.com) before submitting.

## Copyright and SPDX headers

A contributor keeps copyright under CLA 1.1. A new source file must identify
its actual copyright holder, followed by the project license:

```text
// SPDX-FileCopyrightText: 2026 Your Name or Organization
// SPDX-License-Identifier: AGPL-3.0-only
```

Use `Vericto S.A.S.` only when Vericto owns that file through employment,
contract or written assignment. Preserve existing copyright and license
notices. Do not replace another contributor's notice with Vericto's name.

## Third-party and AI-assisted material

Do not copy code or documentation from an issue, comment, website or other
source unless the pull request identifies the source and Vericto has rights to
include it. Ideas and facts are different from copyrightable text or code.

Read [AI_POLICY.md](AI_POLICY.md). If an AI or code-generation tool assisted
the pull request, disclose it in the description using:

```text
Created with: <tool name>; assistance: <what it produced>
```

You remain responsible for understanding, testing and licensing the submitted
material. Do not name an AI system in a `Co-authored-by` trailer.
