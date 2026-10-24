# PostgreSQL wire-protocol article reproducer

This directory is a public, self-contained, assertion-based companion to **“What a PostgreSQL proxy must get right: libpg_query, Parse/Bind/Sync, and ReadyForQuery.”** It starts disposable PostgreSQL 17 and 18 servers plus four proxy topologies, drives the PostgreSQL v3 protocol with a Python 3 standard-library client, and fails when observed messages, SQLSTATEs, transaction states, row counts, or copied bytes differ from the expected behavior.

No Vericto account or API key is used. The only runtime secrets are a random PostgreSQL password and one-day self-signed private keys under `.run/`; keys are created mode `0600` and removed during normal cleanup.

## Prerequisites and quick start

- macOS or Linux
- Docker Engine/Desktop and Docker Compose v2 (`docker compose`)
- Python 3.10+ standard library
- Enough disk/CPU to build the proxy and run seven small containers

From this directory:

```bash
./run.sh
```

The wire harness needs no Rust installation. To reproduce the article's exact
`libpg_query` tree shapes, rule paths and 1,000-run determinism check from this
public checkout, run this optional source companion with Rust 1.88:

```bash
cargo test article_
```

`BUILD_LOCAL=1` is the default. It builds the current repository checkout as a randomly named, run-scoped image. A warm build normally takes 1–5 minutes and the assertions about 10–30 seconds; a cold multi-stage Rust build can take 10–25 minutes depending on network and CPU. PostgreSQL and the certificate-generator image are pinned by multi-architecture digest.

To test a published release, provide a digest-pinned image:

```bash
BUILD_LOCAL=0 \
VERICTO_IMAGE='ghcr.io/vericto/vericto-proxy@sha256:<64-hex-digest>' \
./run.sh
```

Unpinned overrides are rejected. `ALLOW_UNPINNED=1` is an explicit, discouraged escape hatch. The PostgreSQL defaults can be overridden with `POSTGRES17_IMAGE` and `POSTGRES18_IMAGE`, subject to the same check.

Run selected cases by exact name, substring, glob, or a comma-separated environment filter:

```bash
./run.sh simple-block-allow pipeline-ordering
CASE_FILTER='tls-*,cancel-*' ./run.sh
./run.sh --list
```

`run.sh` prints human progress and writes JSON Lines to `artifacts/results-<random-project>.jsonl`. Every selected case has a `PASS` or `FAIL` record; the last line is a run summary.

## Isolation and cleanup

Each run uses a cryptographically random Compose project name, named volumes and local image. Cleanup calls `docker compose down --volumes --remove-orphans` only for that project, removes only that run's locally built image, and deletes only that run's `.run` directory. It never prunes Docker or searches/removes unrelated resources.

```bash
KEEP=1 ./run.sh                    # always preserve this run
KEEP_ON_FAIL=1 ./run.sh            # preserve only when an assertion fails
```

When retained, the final `[KEEP]` line prints the project and secret directory. Remove it explicitly after investigation:

```bash
docker compose -f compose.yaml -p <printed-project> down --volumes --remove-orphans
rm -rf .run/<printed-project>
docker image rm <printed-project>-proxy:local   # local-build mode only
```

The trap preserves the harness exit status. `artifacts/` survives cleanup so CI can collect JSONL; both runtime directories are gitignored.

## Coverage and evidence boundary

“External” means a real containerized PostgreSQL server and the public proxy process were exercised over TCP. “Source suite” means the behavior is covered by focused Rust tests in this checkout but is not claimed as external evidence by this Docker harness.

| Behavior | Harness case | Evidence | Assertion |
|---|---|---|---|
| libpg_query 17.7 tree shapes, rule paths and 1,000-run determinism | `cargo test article_` | Public source suite | tree version `170007`, DELETE/WHERE nodes, stacked count, exact rule codes and paths |
| Simple block/allow; blocked rows unchanged | `simple-block-allow` | External, PG17 | `42501` / `VERICTO-001`, counts 2 then 1 |
| Stacked statements are admitted all-or-nothing | `stacked-all-or-nothing` | External, PG17 | no `DataRow`; table unchanged |
| Data-modifying CTE traversal | `data-modifying-cte` | External, PG17 | `42501` / `VERICTO-001`; rows unchanged |
| `OR 1=1` tautology | `or-tautology` | External, PG17 | `42501` / `VERICTO-090` |
| Extended error timing and recovery | `extended-timing-recovery` | External, raw pgwire | `ErrorResponse` arrives before `Sync`; Bind/Execute produce no reply; `ReadyForQuery(I)` after Sync; next query works |
| Earlier extended work plus later local block | `extended-pipeline-rollback` | External, raw pgwire + PG17 | ordered `ParseComplete/BindComplete/CommandComplete`, replacement error, server `ReadyForQuery`; earlier write rolls back |
| Bind-value blind spot | `bind-value-blind-spot` | External, raw pgwire | `$1 = 0` is allowed at Parse and deletes all three rows |
| `ReadyForQuery` I/T/E | `ready-for-query-states` | External, PG17 | exact status sequence `I,T,T,E,E,I` |
| Slow query then local block ordering | `pipeline-ordering` | External, raw pipelined `Query` | complete first response cycle before blocked cycle |
| Three pipelined queries, middle blocked | `pipeline-ordering` | External, raw pipelined `Query` | rows `1`, block, rows `2`, each in its own ordered cycle |
| Backend frame larger than 16 KiB | `large-backend-frame` | External, raw pgwire | one complete 40,007-byte-ish `DataRow` body and exact 40,000-byte value |
| PostgreSQL 18 `VIRTUAL` parser-version skew | `pg18-virtual-version-skew` | External, PG18 | statement passes the PG17 parser's flagged parse error and PG18 produces value 18 |
| Distinct/shared-cert TLS + SCRAM channel binding | `tls-channel-binding` | External, PG17 TLS | six-cell matrix: distinct `require/prefer` fail, distinct `disable` succeeds, all shared modes succeed |
| Cancel through TLS-required proxy | `cancel-under-tls` | External, PG17 TLS | active query is polled, plaintext `CancelRequest` yields `57014`, session returns idle |
| `COPY ... PROGRAM` | `copy-behaviors` | External, PG17 | `42501` / `VERICTO-080` |
| `COPY FROM` and `COPY TO` server files | `copy-behaviors` | External, PG17 | FROM is forwarded/flagged and inserts; TO writes bytes verified with `pg_read_file` |
| `COPY FROM STDIN` / `TO STDOUT` | `copy-behaviors` | External, raw pgwire | CopyIn/CopyOut responses and exact CSV payload |
| Prepared statement refresh after policy/rules changes | `prepared-refresh` | External, signed ephemeral control plane + PG17 | statement parses under allow bundle, deny bundle syncs, later Bind/Execute returns `42501` / `VERICTO-087` |

### Additional prepared-refresh source tests

The external `prepared-refresh` case generates an ephemeral Ed25519 key, signs an allow and deny bundle, runs a local HTTP control plane, prepares a statement under the allow bundle, waits for the proxy to sync the deny bundle and verifies that the later Bind/Execute is blocked. The following focused Rust tests add coverage for Bind-time refresh, Execute-time refresh, portal lifetime, time-dependent policies and changed rewrites:

```bash
# Run from the repository root; requires the Rust toolchain and fetched Cargo dependencies.
cargo test tcp::fake_pg_tests::prepared_statement_is_rechecked_after_an_access_policy_swap -- --exact
cargo test tcp::fake_pg_tests::execute_rechecks_a_portal_after_an_access_policy_swap -- --exact
cargo test tcp::fake_pg_tests::portal_keeps_the_old_unnamed_statement_after_it_is_replaced -- --exact
cargo test tcp::fake_pg_tests::execute_rechecks_time_dependent_policies_without_an_arc_swap -- --exact
cargo test tcp::fake_pg_tests::a_changed_prepared_rewrite_requires_reprepare -- --exact
```

These tests exercise the in-process state transitions that the external control-plane case cannot force individually.

## Deliberate limits

- The signed control-plane fixture implements only the `/api/v1/sync/rules` contract needed by this test. Its Ed25519 private key is generated for one run and deleted; it is not a production control plane.
- It does not prove network isolation around a real production database; these databases are disposable project-scoped containers.
- The large-frame case proves the client receives one valid, intact backend frame despite the proxy's 16 KiB internal relay chunks. TCP itself may segment bytes arbitrarily, so the test does not assert packet boundaries.
- `COPY FROM '/tmp/...'` is expected to be forwarded while producing a non-blocking built-in finding. Without an API key there is no remote telemetry assertion; forwarding and resulting rows are asserted externally.
- The TLS certificates are intentionally short-lived and self-signed. Hostname/CA verification is outside the article's channel-binding experiment.

## Files

- `run.sh`: prerequisite checks, pin policy, random project lifecycle, cert generation, filtering, cleanup
- `compose.yaml`: PG17/PG18 and plaintext/distinct-cert/shared-cert proxy topologies
- `pgwire_repro.py`: PostgreSQL v3 framing, SCRAM/PLUS, assertions, JSONL reporting
- `mock_control_plane.py`: minimal signed rule-sync fixture for the external prepared-refresh case
- `.gitignore`: excludes ephemeral secrets and result artifacts
