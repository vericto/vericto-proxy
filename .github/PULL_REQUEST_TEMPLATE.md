## What does this PR change?

<!-- A clear, concise description of the change. -->

## Why?

<!-- Context: a wire-protocol bug, a driver or TLS incompatibility, a telemetry or rule-sync issue, a deployment need. Rule and parser changes belong in vericto-engine. -->

## Type of change

- [ ] Wire protocol (PostgreSQL / MySQL)
- [ ] TLS
- [ ] Telemetry or rule sync
- [ ] Configuration
- [ ] Docker image or deployment
- [ ] Performance
- [ ] Documentation
- [ ] Dependencies
- [ ] Licensing / legal metadata

## Tests

- [ ] Added or updated tests that cover the change
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --all` passes

## Checklist

- [ ] No `unwrap()` / `expect()` on runtime paths
- [ ] Public functions documented with `///`
- [ ] Commits follow Conventional Commits
- [ ] New or changed environment variables documented in `README.md` and `.env.example`
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] I have signed the Vericto Contributor License Agreement 1.1 (`legal/cla/1.1.md`) on my first pull request by commenting `I have read the CLA Document and I hereby sign the CLA`; comment `recheck` if the `CLA` check does not rerun
- [ ] I disclosed third-party and AI-assisted material as required by `CONTRIBUTING.md` and `AI_POLICY.md`
