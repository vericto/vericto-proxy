## What does this PR change?

<!-- A clear, concise description of the change. -->

## Why?

<!-- Context: a missed destructive pattern, a parser bug, a new dialect, perf. -->

## Type of change

- [ ] New rule
- [ ] Parser / dialect fix
- [ ] Performance improvement
- [ ] Bug fix
- [ ] Documentation

## Tests

- [ ] Added a "must be blocked" test (positive case)
- [ ] Added a "must be allowed" test (false-positive guard)
- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo fmt --check` passes

## Checklist

- [ ] No `unwrap()` / `expect()` on runtime paths
- [ ] Public functions documented with `///`
- [ ] Commits follow Conventional Commits and are signed (`git commit -s`)
- [ ] Rule documented in `README.md` (if adding a rule)
