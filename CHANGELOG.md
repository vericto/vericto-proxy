# Changelog

All notable changes to vericto-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.20.0] - 2026-10-27

**The proxy says when the database is a newer PostgreSQL than its parser.** The
engine reads PostgreSQL with the PostgreSQL 17 parser; a PostgreSQL 18 database
accepts syntax that parser cannot read, which the proxy handles as a parse error.
The proxy now compares the `server_version` the database reports with the parser's
version and, when the database is newer, logs one warning per upstream and shows
it on `/metrics` and in the rule-sync heartbeat. Observability only: every
statement is answered exactly as in 4.19.0, and nothing runs per statement.

### Added

- **A warning when the database is a newer PostgreSQL than the parser**
  (`src/tcp/upstream_version.rs`). The engine parses PostgreSQL with libpg_query,
  the grammar of one major version (17 with `pg_query` 6.x); a newer database
  accepts syntax it cannot read, and such a statement is a parse error
  (`VERICTO-PARSE-ERROR`: refused when parse errors fail closed, forwarded and
  flagged under the fail-open default). The proxy now reads the `server_version`
  the database sends at startup and, when its major is newer than the parser's
  (read from `pg_query` itself, not a constant), logs one warning per upstream
  `host:port` for the life of the process, under `alert="upstream_newer_than_parser"`
  with `server_version`, `server_major` and `parser_major`; again only for a still
  newer major. Equal and older versions, and a `server_version` that cannot be
  read, are logged at `debug`. The same state is in `/metrics`
  (`vericto_proxy_upstream_newer_than_parser`,
  `vericto_proxy_upstream_server_major_version`, `vericto_proxy_parser_major_version`)
  and in the rule-sync heartbeat (`X-Vericto-Telemetry-Stats`, new field
  `upstream`; `v` stays 1), so the dashboard can show it. MySQL: the greeting's
  server version is recorded there too and logged at `debug`, with no comparison
  (`sqlparser` has no grammar per server version). Observability only: no verdict
  and no relayed byte changes, the check runs once per connection during startup
  and never per statement, and the table holds at most 16 upstreams. No new
  setting. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#sql-parser-version-and-database-version).

## [4.19.0] - 2026-10-26

**Less CPU per statement, with nothing answered differently.** A statement is
evaluated on its connection's task instead of being handed to the blocking pool
and back, the trivial statements of every transaction (`BEGIN`, `COMMIT`,
`SELECT 1`…) reuse the decision their session's full evaluation reached for them,
sanitized telemetry is built off the query path, the allocator is mimalloc, MySQL
reads a command in one system call, the database hop keeps one TLS configuration
(and resumes MySQL sessions), and the published images are built with
profile-guided optimization. Every change keeps verdicts, forwarded bytes and
telemetry as they were (the per-change tests say how), and a new CI gate fails a
pull request that costs more than 3% more instructions per statement on any of
15 workloads, or answers any statement of its corpus differently. Measured
against 4.18.0 with that gate (callgrind, linux/arm64, one worker, same corpus):

| workload | PostgreSQL | MySQL |
|---|---:|---:|
| `trivial` (`BEGIN`, `SELECT 1`, `COMMIT`) | -87.5% | -82.0% |
| TPC-B transaction, text / extended protocol | -13.5% / -13.3% | -27.8% (text) |
| TPC-B, prepared statements | +0.3% | -63.7% |
| 2,000-row result | -3.2% | -19.3% |
| a connection per statement | -12.9% | -17.0% |
| policy mix, control plane on, sanitized telemetry | -15.5% | -28.8% |
| `trivial` with the control plane on | -12.8% | -19.3% |

With the release images' profile-guided optimization on top: -89.2% / -16.0% /
-16.1% / -15.4% / -8.6% / -15.8% / -18.5% / -17.7% on PostgreSQL and -84.5% /
-37.2% / -69.4% / -27.6% / -22.2% / -39.6% / -25.8% on MySQL, in the same order.
System calls per statement: 9.9 -> 6.0 (PostgreSQL), 12.0 -> 6.0 (MySQL). Every
statement of the corpus is answered exactly as 4.18.0 answers it (equal outcome
digests on all 15 workloads). Instruction counts leave out the kernel, memory
stalls and contention: the CPU per transaction on the EC2 bench is the release
criterion.

### Performance

- **Statements up to 1 KiB are evaluated on the connection's task, not on the
  blocking pool** (`VERICTO_INLINE_EVAL_MAX_BYTES`, default 1024; `0` = every
  statement on the pool, as up to 4.18.0). The pool cost two thread hand-offs per
  statement: system calls per statement 9.9 -> 6.0 on PostgreSQL and 12.0 -> 8.0 on
  MySQL (`strace -f -c`), user-space instructions -2.5% to -7.9% (callgrind gate),
  and proxy CPU per transaction -26% (pgbench select-only, extended, 8 clients, one
  worker; -33% with 1 client) and -41% (sysbench point select, MySQL text) in
  interleaved local runs. Verdicts, forwarded bytes and telemetry are the same
  either way (`inline_and_pool_evaluation_give_the_same_outcome`). The check of the
  StartupMessage's settings takes the same way, so a connection no longer hands
  its start-up to the pool either (futex calls per PostgreSQL connection 6 -> 4).
- **Trivial statements reuse their session's earlier decision**
  (`VERICTO_TRIVIAL_FAST_PATH`, default `on`; `src/tcp/fast_path.rs`). `BEGIN`,
  `COMMIT`, `ROLLBACK`, `END`, `START TRANSACTION`, `SELECT 1`, `SET autocommit=0/1`
  and `SET NAMES utf8mb4` (after trimming ASCII whitespace and one trailing `;`,
  any ASCII case) are evaluated in full the first time a session sends them; the
  same bytes, sent the same way, under the same ruleset and effective policy
  (the same `Arc`s, held so they cannot be reused) then get that decision without a
  parse. Never under business policy rules. A cache of the engine's own answer
  (evaluation is a pure function of the statement, the rules and the policy), not
  a table of verdicts: `fast_path_tests` sends every entry and thirty near misses
  (comments, `BEGIN; DROP …`, whitespace, case, Unicode look-alikes, `SET ROLE`,
  `SET SESSION AUTHORIZATION`…) twice through a session with and one without it,
  under the built-in rules, monitor mode, parse errors blocked, sensitive columns,
  an enforced allowlist and a custom rule against SELECT, raw and sanitized
  telemetry, simple query, Parse, COM_QUERY and COM_STMT_PREPARE, and requires the
  same bytes, answers and events (but `latency_ms`); a ruleset or policy swap is
  answered from the new one. Callgrind: -86.3% instructions per statement on
  `pg trivial`, -78.3% on `mysql trivial`, -8.1% / -8.4% on `pg oltp_extended` /
  `oltp_simple`, -11.1% on `mysql oltp_text`, -57.2% on `mysql oltp_prepared`
  (BEGIN and COMMIT as text), +1% on `connect` (the first `SELECT 1` of each
  session is kept).
- **Sanitized telemetry events are built off the query path**
  (`VERICTO_TELEMETRY_BUILD_QUEUE`, default 4096 waiting events; `0` = on the query
  path, as up to 4.18.0). The second normalization of the query text (libpg_query /
  the MySQL tokenizer), the violation mapping and the event id now run on the
  `vericto-telemetry-build` thread, which collects events for up to 25 ms at a time
  so that handing one over costs the query path a lock and no system call. Bounded:
  a full queue drops the event and counts it in `dropped_queue_full`; the query path
  never waits. Same event content and order (`deferred_events_equal_the_query_path_ones_in_sanitized_mode`,
  the event time is taken on the query path), and the shutdown flush waits for the
  events still being built. Callgrind, one worker, sanitized mode, with the 4.19.0
  allocator (mimalloc, below): query-path
  instructions per statement -11.3% (`pg trivial_cp`), -9.9% (`pg policy_mix`),
  -7.2% (`mysql trivial_cp`), -14.2% (`mysql policy_mix`); the whole process
  +0.6% to +1.8%. Raw-mode events stay on the query path (deferring them saved less
  than the hand-over costs). Export batches were already gzip-compressed
  (`VERICTO_TELEMETRY_GZIP`).
- **mimalloc is the global allocator** (the default `mimalloc` cargo feature;
  `--no-default-features` keeps the system allocator). Callgrind gate against
  glibc's malloc: -2.1% to -3.3% instructions per statement on the PostgreSQL OLTP
  and large-result workloads, -10.8% / -14.9% on `pg trivial_cp` / `pg policy_mix`,
  -6.7% to -28.2% on every MySQL workload. jemalloc measured the same within a
  point and was not taken (needs `make`; bundles BSD-2-Clause sources the license
  policy does not list). Peak RSS about 7 MB higher (17 to 18 MB under 8 to 64
  connections). Cargo.lock: `mimalloc` 0.1.52 and `libmimalloc-sys` 0.1.49 (MIT).
- **MySQL: the client is read through a 16 KiB buffer, into one reused packet
  buffer** (`codec_mysql::read_packet_into`), as PostgreSQL is since 4.17.3. A
  command cost two reads of the socket (header, then payload) and one allocation;
  it now costs one read and none. Each packet is still forwarded and flushed on its
  own (nothing is coalesced upstream), now from the sender's reused buffer instead
  of a new `Vec` per packet. System calls per statement 8.0 -> 6.0
  (`strace -f -c`, COM_QUERY and COM_STMT_EXECUTE), instructions -0.2% to -5.2% on
  the MySQL workloads of the gate.
- **The database hop reuses one TLS client configuration**, rebuilt only when
  `UPSTREAM_SSLROOTCERT`, `UPSTREAM_SSLCERT` or `UPSTREAM_SSLKEY` changes (inode,
  size and modification time are checked per connection, so a rotated file applies
  from the next connection, as before). Up to 4.18.0 each connection read the
  files and built a configuration of its own, which also discarded rustls' session
  cache: no connection could resume the TLS session of an earlier one. Callgrind,
  one connection per statement: -14.8% of the proxy's connection cost with
  `UPSTREAM_SSLMODE=require`, -8.7% with `verify-full` (PostgreSQL 17, which
  disables resumption), -9.3% with TLS on both MySQL hops, where every connection
  after the first now resumes (MySQL 8.0.46 `Ssl_session_cache_hits` 0 -> 63 of 63).
- **The published images are built with profile-guided optimization**
  (`release.yml`, `perf/pgo-train.sh`, docs/PERFORMANCE.md "PGO"). Each
  architecture's runner trains a profile on the performance gate's corpus
  (PostgreSQL 17 and MySQL 8.0 service containers) and the image build uses it
  for every Rust crate (`--build-context pgo=…`; without it `docker build .` is the
  plain build, as before). Callgrind gate, image binaries with and without the
  profile (linux/arm64): -3.0% to -15.8% instructions per statement on PostgreSQL,
  -6.5% to -15.4% on MySQL; trained without four of the workloads, those four
  still gain -0.5% to -10.5%. Release build time per architecture: plus one
  instrumented build and about a minute of training, and the dependency layer is
  rebuilt each release. Code generation stays generic: the images run on any
  x86_64 / aarch64 CPU. `lto = "fat"` was measured and not taken (-0.75% median,
  2.5 times the crate's build time).

### Added

- **CI performance gate** (`.github/workflows/perf-gate.yml`, `perf/callgrind-gate.sh`,
  `examples/perf_gate.rs`, docs/PERFORMANCE.md): every pull request measures the
  user-space instructions per statement of its head and its base under callgrind, on
  15 workloads of both dialects (trivial, OLTP over every protocol, a 2,000-row
  result, a connection per statement, a policy-heavy mix with masks, an allowlist,
  a business policy and sanitized telemetry), and fails when one grows by more than 3%
  (`PERF_GATE_THRESHOLD_PCT`) or when any statement of the corpus is answered
  differently. Repeated runs agree within 0.3%; on 4.17.0 -> 4.17.1 the gate reports
  the #89 regression (+4.3% to +1,683% on the PostgreSQL workloads).
- **ECDSA P-256 certificates are documented as the preferred kind** for
  `PROXY_TLS_CERT` (docs/CONFIGURATION.md, "Certificates, resumption and TLS cost"):
  a full handshake costs the proxy about 0.1 ms of CPU with one, 0.7 to 1.2 ms with
  RSA-2048. They already worked (PKCS#8 or SEC1 keys); a test now terminates TLS
  with one end to end and checks that a client that offers its session back
  resumes it (the listener's 256-session cache and TLS 1.3 tickets, unchanged).
  docs/PERFORMANCE.md has the TLS measurements, why the crypto provider stays
  `ring` (aws-lc-rs measured: no gain on ECDSA or bulk, slower RSA on arm64), and a
  design note on kernel TLS (not implemented).
- **`TARGET_CPU` Docker build argument** (opt-in, empty by default): CPU-specific
  code generation for an image of one's own (e.g. `neoverse-v1` for Graviton3). The
  published images do not use it.

### Security

- **Runtime image base `cgr.dev/chainguard/glibc-dynamic:latest` pinned to its
  current digest** (`sha256:5bb932663cff…`, from `2827063c9efb…`, the Dependabot
  bump merged in #92), in the Dockerfile and Dockerfile.local.

## [4.18.0] - 2026-10-25

**The kill switch is VERICTO-105 on the wire, for every statement.** Up to 4.17.x a
dashboard "Block all statements" reached the proxy only as a deny-all agent-access
allowlist for the blocked database user: refusals were reported as VERICTO-087, and
statements that read no table (`SELECT 1`, `SET`, `BEGIN`) still passed. 4.18.0 reads
the new `kill_switch` field of `/sync/rules` and refuses every statement of a blocked
user (or of every user, under the workspace switch) with the control plane's
kill-switch message. Requires 4.17.3 to be tagged first (this release is built on it;
4.17.1 and 4.17.2 were not released).

### Added

- **`kill_switch` in the sync bundle** (`{"workspace": {block_id, target_type,
  message}, "db_users": {"<user>": {…}}}`, present only while a block is active;
  part of the signed body). Applied with the rest of each sync, restored from the
  rules cache after a restart, cleared by the first sync without it. A malformed
  entry is skipped and logged (`alert=kill_switch_malformed`) and never turns the
  bundle away: its deny-all allowlist still blocks that user as VERICTO-087.
- **Every statement of a blocked session is refused before anything else**, in
  every mode (`monitor_mode`, observe windows and `VERICTO_POLICY_RULES` included):
  Postgres `Query`, `Parse`, and `Bind`/`Execute` of a statement prepared before the
  block, through the ordered response coordinator; MySQL `COM_QUERY`,
  `COM_STMT_PREPARE`, `COM_STMT_EXECUTE`/`COM_STMT_FETCH`, `COM_INIT_DB`,
  `COM_FIELD_LIST` and `COM_CHANGE_USER` (no way out to another user). The error is
  a normal one (Postgres 42501, MySQL 1142) whose text is the block's message.
  Protocol plumbing (Sync, Describe, Close, ping, statement close/reset, quit)
  passes. A user's own block wins over the workspace switch. The check comes before
  every verdict: an Execute that keeps its statement's time-free business-policy
  verdict (4.17.3) is refused by a block like any other.
- **Telemetry `kill_switch_id`**: each refusal is a BLOCKED event with VERICTO-105,
  severity critical, path `KillSwitch > <target>`, the one violation, and the block
  id, which the control plane links to the block; one event per statement.
- `docs/AGENT_ACCESS.md` "Kill switch (VERICTO-105)"; README.

### Changed

- **vericto-engine v4.5.0 -> v4.6.0** (git tag): every VERICTO-087 finding carries a
  deterministic suggestion (what is not in the identity's allowlist, and that an
  admin must grant it in Dashboard > Agent access), so the proxy's 087 error now
  ends with `. Suggestion: …`. Nothing else changes in the engine's decisions or
  paths. In sanitized telemetry, when a MySQL name is redacted from `access_denied`,
  the suggestion is rebuilt from the redacted names
  (`vericto_engine::access_suggested_fix`), so a double-quoted literal never leaves
  in it. Cargo.lock: only the engine entry and this crate's version change.

### Performance

- Plumbing messages (Sync, Describe, ping…) pay one match; any other message one
  atomic load and an `is_none` while no block is active, and one hash lookup by the
  session user while blocks are. Callgrind, pgbench select-only `-M extended`, one
  session, one worker, linux/arm64 release builds, marginal user-space instructions
  per statement over 4,000 statements, 2 runs each: 4.17.1 227,669 / 227,760, 4.18.0
  227,706 / 228,955 (no block; no control plane); with a control plane, 211,365 /
  211,336 without a block and 212,237 / 212,340 with another user blocked (+0.4%).
  On 4.17.3 (pgbench `-n -S -c 1`, TLS on both legs, no control plane, 2 runs):
  extended 206,486 / 205,909 -> 207,020 / 206,393 (+0.3%), prepared 20,371 /
  20,356 -> 20,799 / 20,796 (+2.1%: the kill-switch check on the Parse, Bind and
  Execute messages).

## [4.17.3] - 2026-10-25

**PostgreSQL: 4.17.1's ordering and prepared-statement guarantees at 4.17.0's
cost or less, and business policies re-evaluate an Execute only when they read
the time.** This is the first release of the work of 4.17.1 (PR #89) and
4.17.2; neither was tagged or released. 4.17.1 (merge 77ff155) failed its EC2
release gate on 2026-10-24: +14 to +38% CPU per transaction against 4.17.0 and
a quota tail at the 0.5 vCPU Fargate shape, because its relay wrote and flushed
the client stream once per backend message. 4.17.2 (patch 0066, not merged)
removed most of that, but its gate on 2026-10-25 still measured +1.5 to +7.3%
CPU per transaction against 4.17.0 in the PostgreSQL cells (criterion: at most
+3%), a tail on one core at 90% of S, and, with business policies on, +54%
(extended) and about 3.5x (prepared) CPU per transaction from evaluating every
Execute again. 4.17.3 is 4.17.2 plus the three changes below. Everything the
4.17.1 and 4.17.2 notes describe ships first in this release.

### Changed

- **Frontend messages go to the database in one write per client read.** Up to
  4.17.2 every frontend message was its own write and flush upstream (about 5
  per extended-protocol transaction: Parse, Bind, Describe, Execute, Sync; with
  TLS each one a record and a `sendmsg`). The client is now read through a
  16 KiB buffer, and the messages framed from one client read are appended in
  order to one upstream buffer, each after its response plan is registered,
  as before. That buffer is written with one write and one flush when the
  session is about to wait: for the client (no further whole message is
  buffered), for room in the response queue, for the response a consumed
  `SET vericto.*` awaits, or for an evaluation while it holds a message the
  server answers on its own (Sync, Flush, a simple Query, a FunctionCall,
  CopyDone, CopyFail), so the coalescing never delays an earlier response
  behind a later statement's evaluation. It is also written at 16 KiB; a
  larger message (COPY data, a big Bind) goes out on its own after what was
  pending, straight from its buffer. A locally refused message keeps its exact
  position (its marker query or invalid Parse takes its place in the same
  buffer), a Flush is never held back waiting for more client bytes, and COPY
  IN data is forwarded in order. MySQL, and PostgreSQL without the ordered
  response coordinator, still write and flush every message as it comes.
- **Business policies: an Execute is evaluated again only when a policy in
  force may read the time.** 4.17.1 and 4.17.2 evaluated every Execute again
  while any business policy was active. From 4.17.3 the bundle records, when it
  is compiled, whether any of its business policies may read the time of the
  statement (`time.now`, `time.hour`, `time.minute`, `time.weekday`,
  `time.date`, `time.tz`). This comes from the engine's analysis of each
  compiled policy (`vericto_engine::policy::check_policy`: the fields its
  compiled CEL reads), not from the policy's text, and it is conservative: a
  policy is time-free only when it compiles and every field it reads is a
  statement, principal, session, ticket or database field; any other field,
  including one a later engine adds, and a policy that does not compile count
  as reading the time. With such a policy in the bundle every Execute is
  evaluated again, as before. Otherwise an Execute keeps the verdict its
  statement or portal was evaluated to under the same snapshots: the rules,
  the session's effective access policy (allowlist and sensitive-column masks
  included), the business-policy bundle and the session context, compared as
  the same `Arc`s. Any change to one of them (a sync with a new bundle, an
  allowlist or mask change, a `SET vericto.*`, a different principal) still
  forces the evaluation at the next Bind or Execute, with the same
  `VERICTO-PREPARED-STALE` handling when a mask or `rewrite_limit` would now
  require different SQL. No verdict depends on Bind parameters: the engine
  evaluates a statement's SQL text, never its parameter values (a `LIMIT $1`
  is unknown to a policy, which its `on_unknown` decides at Parse), so a
  verdict reused across Executes with different parameters is the one each of
  them would get.

### Performance

- **Compact Parse/Bind bookkeeping.** A prepared statement is shared by its
  pending Parse, the statement table and every portal bound from it (one
  reference count; a Bind used to copy six handles). Statement and portal
  names up to 30 bytes, which covers the names drivers generate, are kept
  inline, so tracking one allocates nothing. The retained-SQL bound is kept as
  entries come and go (a Parse used to sum it over every entry), and a Parse
  of the same text as the statement it replaces (a driver preparing the
  unnamed statement for every execution) shares that SQL instead of copying
  it. Each frontend message is read into one reused buffer and framed from the
  client read buffer without further reads; the snapshot a Parse is tracked
  under is built for a Parse only.
- **Callgrind** (user-space instructions per transaction, `pgbench -n -S -c
  1`, `VERICTO_WORKER_THREADS=1`, TLS on both legs, PostgreSQL 17, release
  builds in rust:1.88-slim-bookworm linux/arm64, marginal = (Ir@6000 -
  Ir@2000)/4000, 3 runs, spread under 0.7%): extended 4.16.2 214.1k, 4.17.0
  213.6k, 4.17.2 217.8k, 4.17.3 206.2k (-3.5% against 4.17.0); prepared 26.36k,
  26.35k, 29.15k, 20.35k (-22.8%); simple 200.0k, 200.3k, 201.1k, 200.6k
  (+0.1%). `strace -c` per transaction: `writev` 6 -> 2 (extended, 16
  connections) and 5 -> 2 (prepared); simple unchanged (2).
- **EC2 release gate** (2026-10-25: the 4.17.2 gate's suites with 4.17.2 added
  as a target, c7g hosts, latest AL2023; 0.5 vCPU, TLS on both legs, policies
  off, 4-5 paired repetitions per cell). CPU per transaction against 4.17.0:
  extended -14 to -18% (every rate, one core and the 0.5 vCPU Fargate shape),
  prepared -32 to -33%, simple +0.0 to +2.2% (intervals include 0), MySQL +0.4
  to +2.0%. p99 below the knee: extended 0.06 to 0.20 ms lower, prepared 0.02 to
  0.03 ms lower, simple within +0.05 ms. At the Fargate shape the added p99 over
  a direct connection is +0.36 ms at 80% of S and +0.41 ms at 90% (4.17.0: +0.46
  and +1.75 ms; 4.16.2: +0.45 and +0.59 ms). On one core at 90% of S the p99 is
  1.4 ms (4.17.0 26.4 ms, 4.16.2 25.5 ms, 4.17.2 48.7 ms): the knee moved past
  90%. Closed-loop TPS against 4.17.0: extended +5 to +23%, prepared +57 to
  +61%, simple and MySQL within noise. MySQL at 90% of S on one core, a cell at
  its quota knee: p99 9.2 ms against 6.1 ms for 4.17.0 (interval includes 0;
  4.17.2: 7.8 ms), no collapse.
- **Business policies on** (same gate, one business policy on `select` of
  `public.pgbench_accounts`): with a time-free policy (`deny_if:
  stmt.has_where == false`), CPU per transaction is 13% (extended) and 30 to
  32% (prepared) below 4.17.0 with policies on, and 44% and 80% below 4.17.2
  (closed loop at 16 connections: 6,160 and 29,487 TPS against 5,052 and
  18,685 for 4.17.0 and 3,160 and 4,651 for 4.17.2). With the time-dependent
  policy (`in_window(time.now, ...)`), every Execute is still evaluated again:
  +28% (extended) and about 2.8x (prepared) against 4.17.0, 15 to 17% below
  4.17.2.

### Tests

- `src/tcp/pg_coalesce_tests.rs` drives the interception loop with an upstream
  that records every write and flush: an extended transaction is one write and
  one flush (five on 4.17.2); three pipelined groups with a refused Parse in
  the middle reach the database in order with the invalid Parse at its
  position; a refused simple Query keeps its position; a Flush goes up without
  more client bytes; a message cut by the client read does not hold back the
  ones before it; COPY IN data is coalesced, and a 100 KB CopyData goes out on
  its own, bytes in order; the sender's 16 KiB bound and the per-message path
  without coalescing.
- Through the real entrypoint against a scripted PostgreSQL: a time-free policy
  is evaluated at Parse and not at the three Executes after it (it was at each
  on 4.17.2); a time-dependent one is evaluated at every Execute; a bundle swap
  makes the next Bind evaluate the statement again, once, and a new bundle
  whose time-free policy refuses it refuses the next Bind; a `SET
  vericto.tenant` that a time-free policy reads makes the next Bind refuse the
  statement; a `LIMIT $1` statement executed with three different parameters
  keeps its Parse verdict; more Syncs in one client write than the response
  queue holds; pipelined groups with a refusal in the middle and a group ended
  by Flush, every response in order. A unit test checks which policies count
  as reading the time.
- The randomized prepared-state test also checks the incremental retained-SQL
  bound against a recount.

## [4.17.2] - 2026-10-25

_Not released: superseded by 4.17.3 (see above)._

**PostgreSQL relay performance: 4.17.1's guarantees, most of its cost removed.** 4.17.1
(merge 77ff155, PR #89) was never tagged or released: its EC2 release gate
(2026-10-24, policies off, 0.5 vCPU, TLS on both legs) found that it regressed
every PostgreSQL cell against 4.16.2 and 4.17.0: +10 to +21 µs of CPU per
transaction (+14% simple, +20% extended, +38% prepared), p99 +0.07 to +0.23 ms
below the knee, 12 to 32% less closed-loop throughput, and a quota tail at 80% of
S (extended at the 0.5 vCPU Fargate shape: added p99 +16.3 ms against +0.46 ms,
collapse at 90%). Its new backend relay wrote and flushed the client stream once
per backend message, where 4.17.0 did it once per upstream read: with TLS on the
client leg every message became its own TLS record, `sendmsg` and TCP segment
(proxy-to-client bytes per transaction went from about 180 to 380-476), and the
response coordinator added a lock round trip per message. 4.17.2 is 4.17.1 with
that cost removed; its fixes (pipeline ordering, prepared-statement refresh at
Bind/Execute, the COPY and FunctionCall fail-safes) are unchanged and ship first
in 4.17.3. The 4.17.1 notes below describe them. What remained over 4.17.0
(see Performance) was the bookkeeping those fixes need, which 4.17.3 reduces.

### Fixed

- **One client write per upstream read.** The relay frames each upstream read by
  the backend messages' length prefixes. The messages the read holds whole are
  written to the client with one write and one flush, so one database read is
  one TLS record and one send again, as up to 4.17.0. When no local reply is
  planned for them (the usual case) the bytes go out exactly as read, straight
  from the relay's buffer; a batch with a local reply is assembled in order in a
  side buffer. Complete messages are always written before the relay waits for
  more upstream bytes, so a backend message the server has not finished sending
  never holds back the ones before it. A message larger than the 64 KiB buffer
  (a big DataRow or CopyData) is still streamed through it, its disposition taken
  from the header and the client writer held until its last byte.
- **The coordinator is consulted once per upstream read.** The messages of a
  read are matched to their response plans under one lock (and the
  prepared-statement state under one more, only when a completed plan changes
  it), instead of one or two locks per message. A plan with no local reply that
  does not end in an extended-protocol error completes on an inline path. Plans
  are smaller (a local reply is boxed), and the frontend registers a plan without
  an `.await` unless the bounded queue is full: the slot count is now the queue
  length checked under the lock the push takes anyway (no semaphore permit per
  message), with the same backpressure.
- **Bind/Execute need no lookup while nothing is stale.** The prepared state
  counts, against the session's current snapshot (rules, effective access policy,
  business-policy bundle, session context), how many statements, portals and
  candidates were evaluated under another one. While that count is 0 a Bind or
  Execute is known fresh with a pointer compare; the snapshot is read through
  per-session `arc_swap` caches, and the telemetry identity is built only when a
  statement is evaluated again. While business policies are active every Execute
  is still evaluated again, as in 4.17.1 (4.17.3 narrows this to policies that
  may read the time).
- **Fewer allocations per statement.** A Parse whose SQL goes upstream unchanged
  keeps one copy of it (4.17.1 kept two); the retained-SQL bound uses an
  allocation-free upper bound and builds the exact (shared-aware) count only near
  the limit (4.17.1 built a hash set on every Parse). The unnamed statement and
  portal, which most drivers use, are kept outside the hash maps, and pending
  Parse/Bind candidates are a FIFO acknowledged from its front.

### Performance

- **EC2 release gate** (2026-10-25: the 4.17.1 gate's suites, c7g hosts, latest
  AL2023; 0.5 vCPU, TLS on both legs, policies off, 4-5 paired repetitions per
  cell). Against 4.17.0, CPU per transaction: extended +1.5 to +3.9%, simple +3.6
  to +7.3%, prepared +5.1% (4.17.1: +14 to +38%); p99 within ±0.02 ms of 4.17.0 up
  to 70% of S and at most +0.07 ms at 80%; closed-loop TPS -3 to -7% (4.17.1: -12
  to -32%); proxy-to-client bytes per transaction as 4.17.0 (172-185 B; 4.17.1:
  381-476 B). At the 0.5 vCPU Fargate shape (a 0.5 quota over two cores) the added
  p99 over a direct connection is +0.44 ms at 80% of S and +0.56 ms at 90%
  (4.16.2: +0.42 and +0.49 ms; 4.17.1: +16.3 ms and a collapse). On one core, at
  90% of S the extra CPU brings the knee closer: p99 23.8 ms (4.16.2 2.4 ms,
  4.17.0 6.0 ms). Against 4.16.2 the CPU per transaction is +2 to +8% (in the
  extended protocol 4.17.0 itself measures +2 to +4% over 4.16.2 in the same
  session). MySQL, whose path 4.17.2 does not change, is within noise on latency
  and TPS.
- **Callgrind** (user-space instructions per transaction, `pgbench -n -S -c 1`,
  `VERICTO_WORKER_THREADS=1`, TLS on both legs, PostgreSQL 17, release builds in
  rust:1.88-slim-bookworm linux/arm64, marginal = (Ir@6000 - Ir@2000)/4000, 3
  runs, spread under 0.7%): extended 4.16.2 214.0k, 4.17.0 213.9k, 4.17.1
  249.7k, 4.17.2 217.9k (+1.9% vs 4.17.0); prepared 26.35k, 26.35k, 54.4k,
  29.15k (+10.6%: the prepared-statement bookkeeping of 4.17.1); simple 200.4k,
  200.1k, 218.3k, 201.4k (+0.6%).
- **Business policies on** (`VERICTO_POLICY_RULES=enforce`, one business policy
  that reads `time.now`): as in 4.17.1, every Execute is evaluated again while
  business policies are active, which 4.17.0 did not do. On the same hosts, CPU
  per transaction against 4.17.0 with policies on: extended +63 µs (+54%; the
  Parse and the Execute of each statement are both evaluated), prepared +84 µs
  (about 3.5x; 4.17.0 evaluated a prepared statement only at Parse). Policies off,
  no Execute is evaluated again unless a rules, policy or context swap made a
  statement stale.

### Tests

- `src/tcp/pg_relay_tests.rs` drives the relay directly: one upstream read is
  one client write and one flush; the startup and later replies reach the client
  unchanged at every upstream chunking (1 byte to all at once), with the
  ReadyForQuery status and BackendKeyData tracked before exposure; DataRow
  streams with rows just under, at and over the 64 KiB buffer and several times
  larger, fragmented around the buffer size; COPY OUT followed by a local reply;
  three pipelined extended groups with a local refusal in the middle at every
  chunking; complete messages not held back by a partial one; truncated and
  malformed framing failing closed after the good messages; a message without a
  plan; a full response queue waiting for the relay.
- Scripted PostgreSQL sessions through the real entrypoint, plaintext and with
  TLS on both legs (`PROXY_TLS_MODE=require`, `UPSTREAM_SSLMODE=require`): a
  2,004-row result with rows around and over the buffer, COPY OUT, and pipelined
  groups with a refusal in the middle, the upstream writing in pieces around the
  buffer size. A real-PostgreSQL test (`VERICTO_TEST_PG_URL`) checks rows of 64
  KiB and 300 KB by the simple and extended protocol and 64 prepared statements
  pipelined by the driver.
- A randomized test checks the incremental stale count against a recount after
  20,000 stages, commits, aborts, closes, refreshes and transaction ends.
- The byte-wise backend tracker (`PgTxTracker`) is gone with the relay that used
  it; its chunking tests are replaced by the relay's.

## [4.17.1] - 2026-10-24

_Not released: superseded by 4.17.2, itself superseded by 4.17.3 (see above)._

**PostgreSQL pipelined replies are ordered, and prepared statements follow live
policy refreshes.** In 4.17.0 the client-reading task wrote a local block directly
through the same mutex as a relay that copied arbitrary 16 KiB chunks. If a slow
allowed Query was followed without waiting by a locally blocked Query, the client
could receive the later `ErrorResponse`/`ReadyForQuery` before the earlier rows;
the same write could land between the header and body fragments of one large
backend message. Separately, PostgreSQL SQL was evaluated only at Parse, so an
already prepared named statement continued under an older ruleset, access policy
or business-policy context at later Bind/Execute.

### Fixed

- **Ordered PostgreSQL response coordinator.** The frontend registers a bounded
  response plan before forwarding each message; the backend relay is the only
  producer of in-session client bytes. It frames backend messages and holds their
  output position while streaming large bodies, so a local response cannot split
  a DataRow/COPY message. Async Notice, Notification and ParameterStatus messages
  remain visible and do not complete a plan. Plans cover simple Query and the
  extended Parse, Bind, Describe (including ParameterDescription), Execute, Close
  and Sync response shapes; Flush and COPY continuation messages add no artificial
  response or round trip. A bounded queue backpressures the frontend rather than
  silently evicting an association. The frontend `Sync`, not the later backend
  `ReadyForQuery`, ends plan suppression after an extended error, so messages
  pipelined immediately after that `Sync` keep their response plans.
- **Local simple replies use an upstream marker cycle.** A blocked Query or
  consumed `SET vericto.*` sends a harmless fixed Query upstream, suppresses that
  cycle and emits the intended local messages immediately before the server's
  actual ReadyForQuery. Earlier pipelined results therefore finish first and the
  status remains the server's `I`, `T` or `E`. A marker rejected in a failed
  transaction preserves PostgreSQL's native 25P02 for a consumed SET.
- **Local extended errors use PostgreSQL's own recovery.** A blocked Parse, or a
  stale Bind/Execute rejected after refresh, sends an intentionally invalid Parse
  upstream. Its ErrorResponse is replaced at that ordered position with Vericto's
  SQLSTATE 42501; follow-ups and Sync are still forwarded, PostgreSQL performs its
  native skip-until-Sync; PostgreSQL, not the proxy, supplies ReadyForQuery and
  transaction-failure semantics. If an earlier backend ErrorResponse already put
  the sequence into that state, queued later local replacements are discarded up
  to the real Sync plan, so the earlier error wins.
- **Prepared SQL refresh.** Named and unnamed statements retain original SQL, the
  SQL actually prepared upstream and Arc snapshots of their rules, effective
  policy, policy bundle and session context. Bind re-evaluates when a snapshot
  changes. Execute does the same and, while business policies are active,
  re-evaluates on every call so a policy that reads `time.now` cannot preserve a
  Parse-time allow after its window closes. A newly blocking decision is enforced;
  if a refreshed mask or `rewrite_limit` would add, remove or change the upstream
  SQL, the proxy returns `VERICTO-PREPARED-STALE` with a close-and-re-prepare
  instruction rather than execute the old server-side text. Parse/Bind state
  commits only on ParseComplete/BindComplete, errors abandon uncertain candidates,
  CloseComplete commits cleanup, and transaction end clears portals while named
  statements survive. A portal owns the prepared plan it bound, so closing or
  replacing the source statement does not change it, as on PostgreSQL. Names,
  reachable retained SQL and statement/portal counts are bounded; exceeding a
  bound closes the affected session safely.
- **COPY and FunctionCall fail-safes.** COPY IN and COPY OUT stay attached to
  their Query/Execute plan through final completion. COPY BOTH, including
  streaming replication, is explicitly unsupported by this finite response
  coordinator and closes the session instead of risking byte interleaving or a
  false support claim. A FunctionCall denied by an agent-access policy also
  closes the session: using a simple Query as its ordering marker would destroy
  PostgreSQL's unnamed prepared statement, a side effect the original message
  did not have.

### Performance

- A local regression smoke test (`pgbench -S -M extended`, 8 clients, 2
  workers, PostgreSQL 17, Docker Desktop on Apple Silicon) alternated four
  8-second runs per version: 4.17.1 averaged 26.3k TPS versus 26.7k for 4.17.0
  (within 1.4%, with individual runs visibly noisy). This is not a publishable
  benchmark; it checks that complete backend framing did not introduce an
  obvious hot-path regression. The reproducible EC2 benchmark remains the
  release-performance source.

### Compatibility

- MySQL framing, local replies and prepared-statement behavior are unchanged.
  MySQL prepared SQL is still evaluated when prepared and is not re-evaluated on
  a later execute after a hot swap.
- The backend transaction tracker and cancel-key registration still process bytes
  before those bytes are exposed to the client. A clean upstream EOF closes the
  session as before; malformed/truncated framing and coordinator mismatches are
  surfaced and close safely.

### Tests

- Scripted PostgreSQL sessions cover a slow allowed Query followed by a local
  block, three pipelined simple Queries with the middle blocked, a 32 KiB backend
  message fragmented at several boundaries around 16 KiB, multiple extended
  groups with Flush before Sync, a later blocked Parse after an earlier successful
  group, an earlier backend error suppressing a queued local rejection, and a
  valid message pipelined immediately after its recovery Sync.
- Prepared tests cover policy Arc replacement after Parse, unchanged snapshots,
  time-dependent policies changing without an Arc swap, changed rewrites requiring
  re-prepare, portals surviving source statement close/replacement, named/unnamed
  state, backend-acknowledged Parse/Bind/Close lifecycle, transaction-end cleanup,
  reachable-SQL memory accounting and state bounds. A denied FunctionCall closes
  without running a Query marker.
- `src/tcp/article_claims_tests.rs` pins the article's libpg_query 17.7 tree
  shapes, exact rule codes/paths, documented COPY/version-skew limits and the
  1,000-run determinism example.
- `examples/postgres-wire-article` is the public Docker companion: 15 external
  assertion cases cover PostgreSQL 17/18, simple and extended pipelines,
  prepared refresh through an ephemeral Ed25519-signed control plane,
  TLS/SCRAM, cancellation, COPY and large backend frames.

## [4.17.0] — 2026-10-24

**Bounded reads on the wire: `rewrite_limit` business policies are enforced.**
vericto-engine 4.5.0 added `action: { rewrite_limit: n }`, a business policy that
bounds the rows a principal's `SELECT` returns (the dashboard's LIMIT cap template
in rewrite mode): the engine returns the bounded statement as `rewritten_query`.
Up to 4.16.2 the proxy, on engine 4.4.0, could not run that policy, and its
consistency check refused any rewrite that was not a VERICTO-085 mask ("a rewritten
query was returned but no masked column was read"), so a bound would have blocked
the very reads it was meant to cap. The control plane therefore withheld these
policies from every proxy, and an agent's unbounded `SELECT` through the proxy was
only flagged (VERICTO-050). With 4.17.0 and `VERICTO_POLICY_RULES=enforce` the
database receives the bounded statement instead of the client's. Nothing changes
with policy rules `off` (the default) or without a `rewrite_limit` policy.

### Added

- **`rewrite_limit` under `enforce`.** The bounded statement is forwarded in place
  of the client's in the same message: Postgres simple query and `Parse` (same
  statement name and parameter types), MySQL `COM_QUERY` and `COM_STMT_PREPARE`.
  The engine adds `LIMIT n` to the outer query of a top-level `SELECT`, lowers a
  larger literal `LIMIT` / `FETCH FIRST` / MySQL `LIMIT a, m` (`OFFSET` kept), leaves
  a smaller one alone, and turns a Postgres `LIMIT $k` into
  `LIMIT LEAST($k::bigint, n)`, which keeps the parameter's number and type. Writes,
  `SELECT 1`, aggregate-only projections and `EXPLAIN` are untouched. A MySQL
  `LIMIT ?` is forwarded as sent and the policy's `on_unknown` decides (default
  `flag`): its value is only known at execution. Applied on top of a mask when both
  apply. `observe` and `monitor_mode` forward the original and report the would-be
  text as the finding's suggestion.
- **The sync announces the feature**: `X-Vericto-Policy-Language: cel/1, rewrite_limit`
  (comma-separated, so a control plane that only knows `cel/1` still reads it). The
  value is checked against the engine's `POLICY_LANGUAGE` and `POLICY_FEATURES` by a
  test, so a later engine feature cannot go unannounced.

### Changed

- **vericto-engine v4.4.0 → v4.5.0** (git tag). `evaluate()` is unchanged for every
  input and without a `rewrite_limit` policy `evaluate_with_context()` runs the 4.4.0
  code plus one emptiness check (engine CHANGELOG [4.5.0]).
- **Rewrite consistency** (`src/tcp/evaluator.rs`): a rewrite is accounted for by a
  masked column or by a `rewrite_limit` policy hit with outcome `rewritten`. Policy
  hits only exist on the policy path, so with policy rules off a rewrite without a
  mask is refused exactly as before; the hits are only looked at when a rewrite came
  back without a mask. The other checks stay (an empty rewrite or one with a NUL, a
  dialect without a rewrite, a prepared statement whose parameters would change).
- A bound the proxy cannot enforce (the engine's "failure blocks", e.g.
  `FETCH … WITH TIES`; a rewrite that would change the client's bind parameters; a
  MySQL packet that cannot carry it) is blocked under the policy's code, with
  `LIMIT rewrite not enforceable by the proxy: <reason>`; a mask still blocks as
  VERICTO-085. Never the unbounded original.
- **Telemetry.** A bounded statement is reported like a mask: the client's text in
  `query_text`, the bounded one in `rewritten_query`, the policy's finding with
  action `monitor` and no repeated suggestion. In `sanitized` mode a `rewrite_limit`
  suggestion (the would-be text under `observe` / `monitor_mode`) is normalized like
  a VERICTO-085 one, so no literal of the client's statement leaves. The log line
  says `Query BOUNDED (LIMIT)` instead of `Query MASKED`.

### Documentation

- `docs/CONFIGURATION.md` (business policy rules): the announcement and a "Bounded
  reads" entry; README: where bounded reads come from and the image tags.

### Tests

- `src/tcp/rewrite_limit_tests.rs`: Postgres simple query and `Parse` (name, types,
  `LIMIT $2`), MySQL `COM_QUERY` and `COM_STMT_PREPARE` (`LIMIT a, m`, `LIMIT ?`),
  larger and smaller `LIMIT`, writes and aggregates untouched, other principals,
  `off`, `observe`, `monitor_mode`, sanitized telemetry, "failure blocks"; and
  against a real Postgres 17 and MySQL 8.0 (`VERICTO_TEST_PG_URL` /
  `VERICTO_TEST_MYSQL_URL`): the client gets `n` rows on both protocols of each,
  `OFFSET` is kept, a smaller `LIMIT` and a bound `LIMIT $1` work, writes and
  `count(*)` see every row. Evaluator unit tests for the consistency rule and the
  block attribution.

### Performance

- The always-on path is unchanged: callgrind, pgbench select-only (extended
  protocol) through one session, policy rules off, no control plane, 1 worker,
  release builds on rust 1.88 (bookworm), linux/arm64, Postgres 17, 2 repetitions:
  200,518 / 200,505 user-space instructions per statement for 4.16.2 against
  200,490 / 200,504 for 4.17.0 (4,000 statements; within 0.02%).

## [4.16.2] — 2026-10-24

**Async workers sized from the CPU limit, not the CPU count.** Up to 4.16.1 the
proxy started tokio's default of one worker per CPU it could run on. On ECS Fargate
that is the host's vCPUs, not the task's: the CPU quota of a task is set on the
task's cgroup, above the container's, and the container sees neither the quota nor
its throttling (measured 2026-10-23, platform 1.4.0, ARM64, 0.5 vCPU tasks: 1 or 2
CPUs visible depending on the host, `cpu.cfs_quota_us` = -1, while two busy threads
got 0.50 vCPU). With 2 workers on a 0.5 vCPU quota the proxy needed about 25% more
CPU per statement (103–106 against 81–83 µs for PostgreSQL pgbench select-only,
extended protocol, TLS on both hops), reached the quota at a lower rate and was then
throttled for the rest of each 100 ms CFS period, a stall for every connection at
once: an added p99 of 39 ms at 4,826 statements/s and a collapse (p50 above 60 ms) at
5,429/s, against 0.40 and 0.49 ms with 1 worker on the same budget (vericto-bench
results/bench-2026-11-proxy-tail, 3 paired repetitions per cell). On one core with a
visible quota (Docker `--cpus`) nothing changes: std already gave 1 worker there.

### Changed

- **Worker threads** (`src/runtime_sizing.rs`): `VERICTO_WORKER_THREADS` when set,
  else `TOKIO_WORKER_THREADS` (as before), else the CPU limit rounded up, at most the
  CPUs available and at least 1. The limit is the lower of the cgroup quota visible
  to the process (v2 `cpu.max`, v1 `cpu.cfs_quota_us`, the process's cgroup and its
  visible ancestors) and the ECS task's `Limits.CPU` (task metadata v4, read once at
  startup with a 2-second timeout, only when `ECS_CONTAINER_METADATA_URI_V4` is set).
  Rounding up, not down as std does: 1.5 vCPU gets 2 workers. A malformed
  `VERICTO_WORKER_THREADS` (not 1–1024) stops the proxy at startup. One startup line,
  `"Runtime sizing"`, logs the choice and where it came from.
- `vericto-proxy healthcheck` no longer starts a runtime.
- The evaluation pool keeps tokio's default bound: a cap of 4 threads made no
  measurable difference at 0.5 vCPU up to 90% of the published saturation rate, and a
  low cap would let a few large statements hold every evaluation thread.

### Documentation

- `docs/CONFIGURATION.md`, new section "CPU sizing": CPU per statement, where the
  latency knee of a CPU quota is, scaling out at 50–60% of the task's CPU
  reservation, why Fargate shows no throttling inside the container, 1 vCPU tasks
  for bursty loads. README points to it.

### Performance

- The statement path is unchanged: callgrind, 2,000 pgbench select-only statements
  (extended protocol) through one session, linux/arm64, release images, 2
  repetitions: 196,510 / 196,771 user-space instructions per statement for 4.15.3,
  197,358 / 196,888 for 4.16.2 (4.16.0 and 4.16.1 included; means within 0.25%).

## [4.16.1] — 2026-10-24

**Two Postgres wire-protocol fixes.** Nothing changes in configuration, telemetry or
`/metrics`; MySQL is unchanged.

### Fixed

- **A cancel request works with `PROXY_TLS_MODE=require`.** A client cancels a running
  query by sending a `CancelRequest` (code 80877102) on a new connection, and libpq's
  `PQcancel` (psql's Ctrl+C, most drivers) sends it in plaintext. The proxy read it as
  a StartupMessage, so with `require` it answered 28000 and the query ran on. The
  proxy now takes a `CancelRequest` before the TLS requirement applies, in plaintext
  or after TLS (libpq 17's `PQcancelCreate` encrypts it), and forwards it to the
  database on a new connection, over `UPSTREAM_SSLMODE` like any other, never
  answering it, as the server does not.
  - **Only for a session of this proxy.** The proxy still relays the server's
    `BackendKeyData` to the client unchanged, and now records the key of each open
    session (`src/tcp/cancel.rs`): a `CancelRequest` is forwarded only when its
    process id and secret (compared in constant time) are those of a session that
    is open on the same proxy process. A wrong secret, a wrong pid, a closed
    session's key: dropped, nothing reaches the database. Up to 4.16.0, with
    `disable`, any packet with that code was forwarded as it came.
  - With more than one proxy replica behind a load balancer, a cancel works when it
    reaches the replica that holds the session (for example, source-IP affinity).
- **The ReadyForQuery of a statement the proxy refuses reports the real
  transaction status with `VERICTO_POLICY_RULES=off`** (the default). It always said
  `I` (idle), also inside a transaction block (`T`) or a failed one (`E`), in the
  simple protocol and at the `Sync` that ends a refused extended sequence; a
  driver that tracks the status (libpq's `PQtransactionStatus`, connection pools
  that check it before reuse) then took an open transaction for an idle
  connection. Since the statement never reaches the database, the status is the
  server's last one: the relay now follows it with the tracker that policy rules
  on already used (4.15.0), in every mode. The client-side loop does no new work
  per statement, and the tracker now walks the messages a read holds whole in
  place (one header read each, no copy, no allocation, no lock), so the relay
  costs what it did: on a fixed replay of 2,000 Postgres statements through one
  session (callgrind, user-space instructions, linux/arm64, 3 runs each),
  233,055 per statement for 4.16.0 and 233,047 for 4.16.1.
  - **MySQL needs no change:** its counterpart is the status flags of an OK / EOF
    packet (`SERVER_STATUS_IN_TRANS`, `SERVER_STATUS_AUTOCOMMIT`), and the proxy's
    refusal is an `ERR_Packet`, which carries none, so the client keeps the flags of
    the server's last OK, still true because the statement never ran. Checked
    against MySQL 8.0 (inside `BEGIN`, after an error, with autocommit off).

### Tests

- `src/tcp/fake_pg_tests.rs` drives the real session entrypoint against a scripted
  Postgres: a plaintext cancel under `require` is forwarded byte for byte, also one
  sent over TLS; a wrong secret, pid or length is ignored; a cancel while no query
  runs is forwarded and the session runs on; a closed session's key is ignored; a
  refusal reports `I` idle, `T` inside `BEGIN`, `E` after an error, in the simple
  and the extended protocol; the MySQL refusal is the same `ERR_Packet` in each
  state. `real_pg_client_cancel_through_the_proxy` (with `VERICTO_TEST_PG_URL`)
  cancels a running statement with tokio-postgres's cancel token: 57014.

## [4.16.0] — 2026-10-23

**Security: with business policy rules on, the proxy applies only signed sync
bundles.** With `VERICTO_POLICY_RULES=off` (the default) nothing changes: no header
is read, nothing is hashed, the rules cache is read and written as in 4.15.3, and
`/metrics` carries no new series. The per-statement path is untouched in every mode.

Up to 4.15.3 the proxy trusted any `/sync/rules` body that reached it over TLS with
its API key, and any rules cache it found on its volume. With business policies the
bundle decides more than which standard rules run: a policy can block, flag or
exempt statements per principal. Whoever could alter the bundle in transit (a
TLS-intercepting middlebox with a trusted certificate) or at rest (write access to
the shared spool volume that holds the rules cache) could therefore loosen or
replace the workspace's policies on every proxy that reads it. Since vericto-fmw M3
the control plane signs the body it sends to a proxy announcing `cel/1`
(`X-Vericto-Bundle-Signature`, Ed25519 over a domain-separated SHA-256 digest of the
exact body). 4.16.0 verifies that signature.

### Added

- **Bundle signature verification** (`src/tcp/bundle_signature.rs`), with policy
  rules on. A response is applied only when its signature verifies with a trusted
  key; otherwise it is not applied, not cached, and its ETag is not adopted (the
  next poll asks for a full body again), and the last good bundle stays in effect.
  The rules cache stores the signature with the body and is verified on load. With
  no good bundle at all (a first start, a refused cache) the built-in ruleset stays
  in effect, without the workspace's rules or policies, and readiness is not held
  back: the same fail-safe as an unreachable control plane. Refusing traffic
  instead would turn a key mix-up into an outage; applying the unverified bundle
  would defeat the check.
- **Pinned public keys.** The binary embeds the public key each Vericto API
  publishes (`https://api.vericto.com`: `vericto-production-2026`;
  `https://api-staging.vericto.com`: `vericto-staging-2026`), selected by
  `VERICTO_API_URL`. `VERICTO_BUNDLE_SIGNING_KEYS` (JSON) or
  `VERICTO_BUNDLE_SIGNING_KEYS_FILE` replace them, for another control plane or a
  rotation ahead of a release. A malformed override, or both set, fails startup
  rather than silently trusting the embedded keys. Any other API address with no
  override trusts no key: every bundle is refused, with a warning at startup. An
  unknown control plane is never trusted by default.
- **Rotation.** Several keys can be trusted at once and the header's `key-id`
  picks one. The order is: the new public key reaches the proxies first, then the
  control plane switches its active key, then the old key is dropped. Switching the
  control plane first leaves proxies on their last good bundle (stale, never open)
  until they hold the new key.
- **Observability.** Each refusal logs `alert=bundle_signature_rejected` with
  `reason` (`missing`, `malformed`, `unsupported_scheme`, `digest_mismatch`,
  `unknown_key_id`, `bad_signature`, `no_trusted_key`), `key_id` and `source`
  (`sync` or `cache`). `/metrics` adds `vericto_proxy_bundle_signature_verified`,
  `vericto_proxy_bundle_signature_accepted_total` and
  `vericto_proxy_bundle_signature_rejected_total{reason}`, only with policy rules on.

### Upgrading

- **Upgrade the control plane first.** vericto-fmw before the M3 follow-up signs
  bundles only with its own `POLICY_RULES_ENABLED` on; a 4.16.0 proxy with
  `VERICTO_POLICY_RULES` on would then refuse every bundle and stay on the built-in
  ruleset. Vericto's hosted API is upgraded before this release is published.
- **The first restart with the flag on waits for a sync.** A rules cache written by
  4.15.x has no signature, so with the flag on 4.16.0 ignores it at startup and
  runs the built-in ruleset until its first sync. With the control plane reachable
  that is the first poll.
- A cache written by 4.16.0 still loads on 4.15.x (the new field is ignored), so a
  rollback keeps its last good rules.

### Security

- `cargo update` within the declared ranges (compatible versions only), so fixes
  published since 4.15.3 are in: among others `tokio-util` 0.7.20, `webpki-roots`
  1.0.11 and `zeroize` 1.9.1. `cargo deny check` and `cargo audit --deny warnings`
  pass on the result. No code change from it.

## [4.15.3] — 2026-10-23

**Performance: less CPU per statement on the always-on path.** No behaviour change:
same verdicts, same bytes to the database and the client, same telemetry content.

The M2 release gate measured 4.15.0 with `VERICTO_POLICY_RULES=off` at +3.6% proxy
CPU per transaction against 4.14.3 on MySQL (oltp_read_only, 0.5 vCPU). With the flag
off, 4.15.0 runs the same number of instructions per statement as 4.14.3 (within
0.2%; the policy paths take none), so the difference is code layout and cache
behaviour of the larger binary, not extra work. This release takes work out of the
per-statement path instead:

### Security

- `ctutils` 0.4.3 → 0.4.5 in `Cargo.lock` (RUSTSEC-2026-0385: non-constant-time mask generation and `u128`
  comparisons). A transitive dependency; no code change.
- `tokio` 1.53.2 → 1.54.1 in `Cargo.lock` (RUSTSEC-2026-0386: `AsyncFd::new` and related constructors violate
  I/O safety). No code change.

### Changed

- **Telemetry batches are serialized straight from the events.** The request body
  of `POST /ingest/events` used to be built as a `serde_json::Value` first, which
  copied every field of every event (one event per statement) into a map and a
  string of its own before writing it out. It is now written directly. The body is
  the same JSON document; only the order of the keys inside an event changes (the
  declaration order instead of alphabetical), which JSON does not give any meaning.
- **A flagged statement's rule code and AST path are moved, not copied,** into the
  decision the session acts on.
- Together, on a fixed MySQL oltp_read_only replay (16 statements per transaction):
  **-10.4% user-space instructions per transaction** against 4.14.3, 4.15.0 and 4.15.1
  (3.35 M against 3.73 M, callgrind), with the same system calls.

## [4.15.2] — 2026-10-22

**Security: the runtime image moves to Chainguard `glibc-dynamic`, with no shell.**
The proxy's behaviour, configuration and wire traffic are 4.15.1's. What changes is
the image around the binary, and with it how a container health check is written
and which user the process runs as (see Upgrading).

### Security

- **Runtime base image: `cgr.dev/chainguard/glibc-dynamic:latest@sha256:00696e56…b0e85212`**
  (Wolfi: glibc 2.44, libgcc and libstdc++ 16.2.0, the CA bundle; 7 packages), from
  `debian:bookworm-slim@sha256:7ff6ba31…78efe3f8`. The binary links only libc, libm
  and libgcc_s, all provided by the base (checked with the image's own
  `ld.so --list`), and TLS is rustls with the compiled-in webpki-roots store, so
  `libssl3` and `ca-certificates` are no longer installed. Scanned on 2026-10-22 with
  Trivy 0.76.1 and Grype 0.121.0, both platforms: **0 findings of any severity**
  (4.15.1: 1 Critical, 12 High unique CVEs with Trivy, 1 Critical, 20 High with
  Grype, none of them with a Debian 12 fix). This closes the residual util-linux,
  zlib, glibc, OpenSSL and perl-base findings listed under 4.15.1.
- **The image has no shell, package manager or coreutils**, which removes them as
  tools for anyone who gets code execution in the container.
- **Container scan gate in CI and before release.** `ci.yml` builds the image on
  every pull request and push and scans it with Grype (pinned by digest);
  `release.yml` scans each platform image **before it is pushed**. Both fail on a
  Critical or High finding that has a fix available. A weekly workflow
  (`image-scan.yml`) rebuilds main and scans it and the released `latest` image.
- **SBOM.** Each released platform image carries a Sigstore-signed SPDX SBOM
  attestation (Syft) for its platform digest, also uploaded as a workflow artifact:
  `gh attestation verify oci://ghcr.io/vericto/vericto-proxy@<platform digest> --repo vericto/vericto-proxy --predicate-type https://spdx.dev/Document/v2.3`.
- **Dependabot (docker) runs weekly** (it was monthly), so the digest pin follows
  what cgr.dev serves: only `latest` is free, and Chainguard does not promise to keep
  old digests.

### Added

- **`vericto-proxy healthcheck`**: the container health check as a subcommand,
  since the image has no shell. It connects to the healthz listener
  (`VERICTO_HEALTHZ_PORT`, on `127.0.0.1` or the address `VERICTO_HEALTHZ_ADDR`
  names), closes, and exits 0 on success, 1 on failure or on a port that is not a
  number, and 0 when the port is unset (the listener is optional). It never
  contacts the database. The image's `HEALTHCHECK` uses it in exec form.

### Upgrading

- **Health checks must call the binary**, in exec form:
  `["CMD", "/usr/local/bin/vericto-proxy", "healthcheck"]` (Docker Compose
  `healthcheck.test`, ECS `healthCheck.command`, Kubernetes `exec` probes). A
  `CMD-SHELL` check, `bash -c '... /dev/tcp/...'`, `curl` or `wget` fails in this
  image and marks the container unhealthy. NLB/ALB TCP target-group checks are
  unaffected. **Change the check and the image together:** up to 4.15.1 the binary
  ignores its arguments, so `vericto-proxy healthcheck` against an older image starts
  a second proxy, which fails to bind the ports already in use and exits 1.
- **The process runs as `65532:65532`** (Chainguard's `nonroot`), not `1001:1001`. A
  host or named volume written by an older image (for example a disk telemetry spool)
  needs `chown -R 65532:65532`, or run the container with `--user 1001:1001`. An EFS
  access point with a `PosixUser` enforces its own uid and is not affected.
- **`docker exec <container> sh` and ECS Exec shells no longer work.** Copy files out
  with `docker cp`; `/metrics` and the EMF line report the telemetry spool.

## [4.15.1] — 2026-10-22

**Security: the runtime image moves to the current `debian:bookworm-slim`.** No code
change; the binary, the configuration and the behaviour are exactly 4.15.0's.

### Security

- **Runtime base image bumped** to `debian:bookworm-slim@sha256:7ff6ba31…78efe3f8`
  (Debian 12.15 with the `perl-base 5.36.0-7+deb12u4` security update), from
  `sha256:7c7b2c96…6ccc587`. Amazon ECR scanning of the 4.15.0 image reported 26
  findings (5 Critical, 13 High) in four base packages; the 5 Critical and all the
  `perl-base` findings (8 CVEs, among them CVE-2026-42496, CVE-2026-13221,
  CVE-2026-8376, CVE-2026-12087 and CVE-2026-57433) are fixed by this base.
- **Still open, no Debian 12 fix published yet:** `util-linux 2.38.1-5+deb12u3`
  (5 High, 1 Medium), `zlib 1.2.13.dfsg-1` (CVE-2026-85091, High) and
  `glibc 2.36-9+deb12u14` (1 Medium, 2 Low). Dependabot (docker) moves the digest
  again when Debian ships them. Debian 13 (trixie) was evaluated and not adopted: it
  still reports High findings in glibc and zlib and is a major base change.

## [4.15.0] — 2026-10-21

**Business policy rules, behind `VERICTO_POLICY_RULES` (default `off`).** With the
flag off the proxy behaves exactly as 4.14.3: same rule-sync request, same bytes to
the database, same verdicts, same telemetry. This is a preview for the business
policy rules milestone M2; nothing turns it on by itself.

### Added

- **`VERICTO_POLICY_RULES=off|observe|enforce`**, any case; unset or empty is `off`,
  and any other value fails startup (as `VERICTO_TELEMETRY_BUFFER` does), so a typo
  can neither leave enforcement off nor turn it on silently.
- **Policy bundle compiled at sync.** With the flag on, every `GET /sync/rules`
  carries `X-Vericto-Policy-Language: cel/1`, and each applied response (the rules
  cache included) is compiled once with the engine's `PolicySet::compile` into an
  `ArcSwap`, together with the very rules it was compiled from and the response's
  `version` (reported as `policy_bundle_version`). A policy that does not compile
  is logged and fails closed in its scope (engine behaviour).
- **Principals.** The `principals` section of `/sync/rules` (identify: `db_user`,
  `db_user_pattern` with medium trust, `application_name`, `listener` with weak
  trust; `narrow`; `attrs`; `{db_user}` templates) is resolved once per session,
  and again only when a sync swaps the bundle or a MySQL COM_CHANGE_USER changes the
  user. The strongest identifying signal wins; narrowing must also match and never
  raises trust; two principals at the same top trust are ambiguous and the session
  is `unknown` with `weak` trust, as is a session nothing matches. A malformed
  section, or entry, is ignored with a warning and never fails the sync.
- **Session signals.** Postgres `application_name` (StartupMessage parameter or
  `-c application_name=` in `options`), MySQL `program_name` (connect attributes),
  and the listener (the address the proxy binds). No client address is captured:
  `session.client_ip` is left unset.
- **Session context: `vericto.ticket` and `vericto.tenant`.** From the Postgres
  StartupMessage (`-c vericto.ticket=…` / `--vericto.ticket=…` in `options`, or a
  `vericto.*` parameter), from MySQL connect attributes, or from `SET [SESSION]
  vericto.ticket {= | TO} '…'` sent on its own as a simple query. The proxy consumes
  them and never forwards them: the StartupMessage and the HandshakeResponse reach
  the database without them, and a `SET` is answered by the proxy (CommandComplete
  `SET` + ReadyForQuery, or an OK_Packet) carrying the session's real transaction
  state: the relay follows the last ReadyForQuery status (`I`, `T`, `E`) and the
  last MySQL OK/EOF status flags (`SERVER_STATUS_IN_TRANS`, autocommit), so the
  proxy's own replies (a consumed `SET`, a refusal, the Sync that ends a refused
  extended sequence) report what the server reported last. In a failed
  Postgres transaction block (`E`) a `SET vericto.*`, simple or extended, gets
  25P02 as the server would answer it, and its value is not taken. MySQL has no
  failed-transaction state, so it has no equivalent. Each key is set once per session: a
  second `SET`, a `RESET`, `SET … TO DEFAULT` or a `set_config` of a key already
  set, any other `vericto.*` name, `SET LOCAL`, and a `SET vericto.*` sent as a
  prepared statement or among other statements, are blocked with
  `VERICTO-SESSION-CONTEXT` (and reported). A startup setting the proxy cannot
  accept refuses the connection before it reaches the database. Values are 1 to
  128 characters without control characters.
- **Evaluation with context.** With the flag on, each statement is evaluated with
  the engine's `evaluate_with_context` (mode `proxy`, the principal, `db.id`, the
  time in UTC, the ticket, the tenant, `application_name` and the listener).
  `enforce`: the policies decide with the rest of the rules, including the engine's
  block of a statement it cannot read when an enforced blocking policy may apply.
  `observe`: the verdict is the one `evaluate()` gives; what the policies found is
  added to the event, every block lowered to a flag, so a statement only a policy
  would have blocked is forwarded and reported `FLAGGED`. In `observe` a bundle
  with policies costs a second evaluation per statement. An empty policy set costs
  nothing over 4.14.3 in either mode (the engine short-cuts it).
- **Telemetry fields**, only with the flag on: `principal_id`, `principal_type`,
  `principal_trust`, `principal_via`, `application_name`, `policy_bundle_version`,
  `ticket_id` and `session_tenant`. No client address.
- `docs/CONFIGURATION.md` ("Business policy rules"), `.env.example` and the README
  document the flag.

### Security

- **rustls-webpki 0.103.15 → 0.103.16** (RUSTSEC-2026-0382, certificate verification
  may accept distrusted intermediates) and **webpki-roots 1.0.8 → 1.0.10**
  (RUSTSEC-2026-0381, bundled roots allowed distrusted emSign intermediates). Both
  advisories were published on 2026-10-19 and also affect 4.14.3, whose CI
  supply-chain job now fails on them. Lockfile only: these are the TLS
  verification of the upstream (`UPSTREAM_SSLMODE=verify-*`) and control-plane hops.

### Changed

- **vericto-engine 4.3.0 → 4.4.0** (business policies, CEL in custom rules). Its
  `evaluate()` keeps the 4.3.0 contract, so with the flag off no verdict changes.
  `pg_query` 6.2 and `sqlparser` 0.63 stay aligned with the engine. The engine adds
  `regex`, already in the lockfile.
- README: the quickstart and Docker examples use `vericto/vericto-proxy:4.15.0`.

### Not yet verified

- The BENCH quick suite (features off within the 95% interval of 4.14.3) has not
  been run for this release: the proxy repository has no local benchmark.

## [4.14.3] — 2026-10-19

**The default log level is now `info`, as documented.** No other behaviour change.

### Fixed

- Without `RUST_LOG`, the proxy logged at `info,vericto_proxy=debug` (one or more
  debug lines per statement), while `docs/CONFIGURATION.md` documents `info`. The
  default is now `info`. The Docker image already set `RUST_LOG=info`, so containers
  that do not override it log exactly as before; binaries run without `RUST_LOG`,
  and deployments that copied `RUST_LOG=info,vericto_proxy=debug` from
  `.env.example`, are the ones that change. `.env.example` now says `RUST_LOG=info`
  and shows how to turn the debug lines back on.
- The evaluation-cost comment in `src/tcp/query_limit.rs` said "roughly 0.35 ms/KB".
  It now gives the measured end-to-end slope with its conditions (about 0.23 ms/KB
  of SQL on PostgreSQL and 0.18 ms/KB on MySQL at 0.25 vCPU, proxy 4.12.0) next to
  the original table, and the 64 MiB extrapolation that follows from both (15 to
  22 s instead of 23 s). Comment only.
- README: the quickstart and Docker examples use `vericto/vericto-proxy:4.14.3`.

## [4.14.2] — 2026-10-19

**Documentation only; no code change.** The proxy behaves exactly as 4.14.1 did.

### Changed

- README: the opening now says what the proxy is for and the problem it solves,
  states the license (FSL-1.1-ALv2, Apache-2.0 two years after each release) near
  the top, and the quickstart and Docker examples use `vericto/vericto-proxy:4.14.2`
  from Docker Hub (GHCR serves the same digest) instead of
  `ghcr.io/vericto/vericto-proxy:4.5.1`.
- README shortened. The advanced configuration (control-plane link, monthly quota,
  disk spool size, several proxies on one volume, TLS, query size limit, health
  check, observability and metrics, engine-specific and MySQL notes) moved, unchanged,
  to `docs/CONFIGURATION.md`; the full sensitive-column and agent-access references
  to `docs/SENSITIVE_COLUMNS.md` and `docs/AGENT_ACCESS.md`, with a summary left in
  the README; "Run from source" to `CONTRIBUTING.md`. Comments and `.env.example`
  that pointed to the README's "Disk spool size" now point to `docs/CONFIGURATION.md`.

## [4.14.1] — 2026-10-19

**The image is now also on Docker Hub, and no code change.** The proxy behaves
exactly as 4.14.0 did.

### Added

- **Docker Hub: `vericto/vericto-proxy`.** The release workflow now also
  publishes the image to [Docker Hub](https://hub.docker.com/r/vericto/vericto-proxy),
  next to `ghcr.io/vericto/vericto-proxy`, which keeps working as before. It does
  not build twice: it copies the multi-arch index it pushed to GHCR, by digest,
  and checks that Docker Hub serves the same digest, under the same tags
  (`<version>`, `<major>.<minor>`, `<major>`, `latest`). The Docker Hub copy has
  its own build provenance attestation, verifiable with
  `gh attestation verify oci://docker.io/vericto/vericto-proxy:<version> --repo vericto/vericto-proxy`.
  The Docker Hub token lives in a `dockerhub` GitHub environment that only
  release tags (`v*.*.*`) can use, read by a separate job; without it the
  workflow publishes to GHCR only and says so in a notice.
- README: Docker Hub badge, `docker pull` / `docker run` examples and the
  verification command for the Docker Hub name.

## [4.14.0] — 2026-10-18

**A new license, and no code change.** From this version on, vericto-proxy is
licensed under the Functional Source License, Version 1.1, ALv2 Future License
(SPDX `FSL-1.1-ALv2`) instead of the Elastic License 2.0. **All previously
released versions, 4.13.0 and earlier, remain under the Elastic License 2.0.**
The proxy behaves exactly as 4.13.0 did. It moves to vericto-engine v4.3.0,
which has the same code as v4.2.0 under the same new license.

### Changed

- **License: FSL-1.1-ALv2, which becomes Apache-2.0 after two years.** `LICENSE`
  is the FSL-1.1-ALv2 text from fsl.software, unmodified, with
  "Copyright 2026 Vericto S.A.S." in its notice. It lets you use, copy, modify
  and redistribute the proxy for any purpose other than a Competing Use: a
  commercial product or service that substitutes for the proxy, or for a
  Vericto product that uses it, or that offers substantially similar
  functionality. Running the proxy in front of your own databases, including in
  production at a company, is a permitted purpose. Each version is also
  licensed under the Apache License 2.0 from the second anniversary of the date
  it is made available, irrevocably. Compared with the Elastic License 2.0, the
  FSL also covers self-managed competing products (ELv2 only restricted hosted
  and managed services) and drops the license-key clause.
- **vericto-engine v4.3.0** (from v4.2.0): the engine's own relicensing
  release, FSL-1.1-ALv2, with no code change. The whole binary, engine
  included, is now under one license, so `NOTICE`, `deny.toml` and
  `third-party/about.toml` need no exception for an Elastic-2.0 engine.
- `Cargo.toml` and `Cargo.lock` declare `license = "FSL-1.1-ALv2"` (the SPDX
  identifier) and version 4.14.0. The image label is
  `org.opencontainers.image.licenses=FSL-1.1-ALv2` (`release.yml`).
- `NOTICE` states the copyright, the license, the Apache-2.0 future license,
  that versions up to 4.13.0 stay under the Elastic License 2.0, and where the
  third-party notices are.
- **New `LICENSING.md`**: which versions are under which license, and a short
  FAQ (what is allowed, what a Competing Use is, when a version becomes
  Apache-2.0, commercial licenses). **New `TRADEMARKS.md`**: the license grants
  no right to the Vericto name or logo, and what you may do without asking.
- `THIRD_PARTY_LICENSES` in the image: `third-party/about.toml` no longer
  accepts `Elastic-2.0` for any crate. It accepts `FSL-1.1-ALv2` for
  vericto-proxy and vericto-engine only, and the file's header explains it.
  `deny.toml` does the same with `exceptions`, so a third-party dependency
  under a source-available license still fails `cargo deny check`.
- Every Rust source file and `third-party/build-notices.sh` start with
  `SPDX-FileCopyrightText` and `SPDX-License-Identifier` lines (the REUSE
  convention).
- README (badge and License section), CONTRIBUTING and the Dockerfile comments
  name the new license. CONTRIBUTING explains that CLA 1.0, which names the
  Elastic License 2.0, also covers later and other licenses.

## [4.13.0] — 2026-10-18

A security update of the bundled PostgreSQL parser and vericto-engine v4.2.0
(from v4.1.3). **This release can block statements that 4.12.3 let through**
(see "Changed"). No wire-protocol or configuration changes.

### Security

- **pg_query 6.2.1 (libpg_query 17-6.2.5), from 6.2.0 (libpg_query 17-6.2.2).**
  It fixes [GHSA-6ggm-xmc9-8ffg](https://github.com/pganalyze/libpg_query/security/advisories/GHSA-6ggm-xmc9-8ffg)
  (High, CVSS 3.1 8.1; CWE-125, CWE-170, CWE-787): `pg_query_normalize()` could
  read and write heap memory out of bounds on specially crafted query text.
  The advisory is published by pganalyze in the libpg_query repository; it has
  no CVE and no RustSec entry, so `cargo audit` does not report it. Parsing,
  fingerprinting and deparsing are not affected.
  - **The proxy is affected.** For PostgreSQL traffic it passes the client's SQL
    to `pg_query::normalize` to strip literals from sanitized telemetry, from
    VERICTO-085 suggestions in sanitized mode, and from the query preview in
    every block log line, whatever the reporting mode. A client that can send
    SQL through the proxy could reach the bug. MySQL text is normalized with
    the proxy's own tokenizer and was not affected.
  - 6.2.1 also hardens the deparser that the engine uses for mask rewrites
    (strict checks for unexpected pointer values, parentheses kept around
    subscripted array constructors).
  - `third-party/pg_query-bundled.txt` names the new versions; the license
    texts did not change.

### Changed

- **vericto-engine v4.2.0.** What changes for traffic through the proxy:
  - **The decision is the strongest action across all violations.** When the
    workspace policy softens a severity (for example Critical to Flag), 4.1.3
    could let the softened violation decide for the whole statement and
    forward a script that also held a violation that blocks. With 4.2.0 such a
    script is blocked: `DROP TABLE a; INSERT INTO archive SELECT * FROM accounts`
    under a policy that maps Critical to Flag now blocks with VERICTO-040
    instead of being forwarded as a Flag. Nothing that 4.12.3 blocked is
    allowed now, and a statement whose violations all resolve to the same
    action gets the same decision and the same reported rule as before.
  - When the sensitive-column code shares an action with a rule, the reported
    winner can change (VERICTO-085 now ranks by severity like any rule); the
    decision and the forwarded rewrite do not.
- **The built-in ruleset is the engine's standard ruleset.** The proxy used to
  keep its own copy of the 42 built-in rules for use before its first rule
  sync and whenever a sync fails; it now uses `vericto_engine::standard_rules()`.
  The codes, severities and default actions are the same; a test still pins
  them.

### CI

- **The CLA check runs in GitHub Actions** instead of cla-assistant.io, whose
  webhook failed on every delivery on 2026-10-17 and 2026-10-18 and left pull
  requests without a status. `.github/workflows/cla.yml` (CLA Assistant Lite,
  pinned by commit SHA) reports the `CLA` check. The agreement is unchanged
  (ICLA v1.0, now also in `CLA.md`). Contributors sign it by commenting
  `I have read the CLA Document and I hereby sign the CLA` on their pull
  request, and `recheck` reruns the check. Signatures are kept on the
  `cla-signatures` branch. The workflow never checks out pull request code.
  No code change.

## [4.12.3] — 2026-10-18

Requires vericto-engine v4.1.3 (from v4.1.1): fewer false positives, short
`last4` values no longer shown, and `-1 < 0`-style tautologies now caught on
MySQL. Two upstream TLS fixes: a TLS mode the proxy does not recognise no
longer turns TLS off, and the MySQL path honours the CA bundle and client
certificate. No wire-protocol changes.

### Changed

- **vericto-engine v4.1.3** (4.1.2 and 4.1.3). What changes for traffic
  through the proxy:
  - **`last4` masks no longer return short values in clear.** A value of 8
    characters or fewer under a `last4` tag is now returned as `'[redacted]'`,
    like `full`; longer values keep `'****'` and their last four characters.
    Up to 4.1.1, `'1234'` came back as `'****1234'`. Only the rewritten SQL
    changes: which queries are allowed, flagged or blocked does not.
  - **Fewer false positives on tautology rules** (VERICTO-003, -030, -040,
    -042, -090). A comparison with `NULL` (`WHERE NULL = NULL`,
    `WHERE NOT (NULL = 1)`), a string comparison a collation can decide either
    way (`NOT ('a' < 'b')`, `'a' <> 'A'`), literals of different kinds
    (`NOT (1 = '1')`) and bind parameters compared by their text (`? = ?`) are
    no longer reported as always true, so such a `DELETE` or `UPDATE` is no
    longer blocked. Real tautologies (`'a' = 'a'`, `1 = 1`, `' OR 'a'='a`)
    still are.
  - **`-1 < 0` is now detected on MySQL.** Negative literals were decided only
    on PostgreSQL, so `DELETE … WHERE -1 < 0` (VERICTO-003) and `… OR -1 < 0`
    (VERICTO-090) passed the MySQL proxy. They are now blocked there, as they
    already were on Postgres. This is the one change that can block a query
    4.12.2 allowed.
  - Snowflake `ORDER BY ALL` is read correctly. Snowflake has no wire protocol
    for this proxy, so it does not reach the proxy.
  - No API used by the proxy changed. 4.1.3 makes the engine's constant
    comparison three-valued (`parser::mod`'s `Truth`, replacing
    `is_always_true` / `is_always_false`), but all of it is crate-private and
    the proxy never called it.
- **`rcgen` joins the dev-dependencies**, to generate throwaway CAs and
  certificates for the new TLS handshake tests. It is not in the binary, and
  no private key is committed.

### Fixed

- **An unknown `UPSTREAM_SSLMODE` or `PROXY_TLS_MODE` no longer disables TLS.**
  Up to 4.12.2, any value the proxy did not recognise (`verify-ca`, `prefer`,
  `required`, a typo) silently meant `disable`, so traffic on that hop went out
  in plaintext. Both variables are now read in any case with surrounding
  whitespace ignored, and any other value stops the proxy at startup with an
  error naming the variable and the accepted values, as 4.12.2 did for
  `VERICTO_TELEMETRY_BUFFER`. Unset or empty is still `disable` for both.
- **`UPSTREAM_SSLMODE=verify-ca` is supported**, with libpq's meaning: the
  database certificate must chain to the CA in `UPSTREAM_SSLROOTCERT` and be
  valid, but its name is not compared with `UPSTREAM_HOST`. It is common in
  libpq configurations, where the database is reached through an address its
  certificate does not name (an IP, a load balancer, a tunnel). Like libpq,
  it needs `UPSTREAM_SSLROOTCERT`: against the public web roots, a chain check
  without a name check would accept any publicly trusted certificate and
  authenticate nothing.
- **`prefer` and `allow` are refused, not mapped to another mode.** In libpq
  both connect in plaintext when the server does not offer TLS. A firewall
  proxy must not fall back to plaintext on its own, and mapping them to
  `require` would silently change what the operator wrote, so the error says
  why and lists `require`, `verify-ca` and `verify-full`.
- **The MySQL upstream path honours `UPSTREAM_SSLROOTCERT`.** It verified
  against the public web roots only, so with `verify-full` a MySQL server whose
  certificate a private CA issued failed every handshake. It now uses the same
  CA bundle as Postgres, and presents `UPSTREAM_SSLCERT` / `UPSTREAM_SSLKEY`
  for mutual TLS (MySQL `REQUIRE X509`) when they are set. The MySQL proxy
  also loads this material at startup, as the Postgres proxy has since 4.12.2:
  a missing, empty or unparseable file, or half a pair, stops it before it
  listens.

### Upgrade notes

- **Behaviour change: an unsupported TLS mode now fails startup.** A
  deployment with an `UPSTREAM_SSLMODE` other than `disable`, `require`,
  `verify-ca` or `verify-full`, or a `PROXY_TLS_MODE` other than `disable` or
  `require`, ran in plaintext on that hop and now exits with, for example,
  `UPSTREAM_SSLMODE="prefer" is not supported: …`. Check both values before
  upgrading. A deployment with `verify-ca` used to run in plaintext: it now
  encrypts and verifies, and needs `UPSTREAM_SSLROOTCERT`.
- **Behaviour change on MySQL with upstream TLS.** `UPSTREAM_SSLROOTCERT`,
  `UPSTREAM_SSLCERT` and `UPSTREAM_SSLKEY` were ignored on MySQL and are now
  used, and checked at startup. A MySQL deployment that sets them to a file
  that is missing or does not parse now exits at startup, and one with
  `verify-full` whose bundle does not hold the CA of a publicly trusted server
  certificate now fails the handshake: remove the variable, or point it at the
  right CA.
- **The engine's MySQL tautology fix can block queries that passed before**
  (`WHERE -1 < 0` and the like). Run the new version under `monitor_mode`
  first if your application issues such statements.

### Tests

- New tests for both fixes, written first and failing on 4.12.2: every
  accepted spelling of both TLS modes, unknown values and `prefer`/`allow` as
  startup errors, real handshakes against a private CA on the Postgres and
  MySQL paths (`verify-full` with the bundle, refused without it or with
  another CA; `verify-ca` accepting another name but not another CA;
  mutual TLS on both paths), a full MySQL connection phase through the proxy
  to a private-CA server, and the startup checks of the MySQL proxy.

## [4.12.2] — 2026-10-18

Two configuration mistakes that used to pass silently now stop the proxy at
startup with an error naming the variable. No wire-protocol changes;
enforcement is unchanged.

### Fixed

- **`VERICTO_TELEMETRY_BUFFER` is case-insensitive and trimmed.** Up to 4.12.1
  only the exact value `disk` selected the disk spool: `DISK`, `Disk` or
  ` disk` silently selected the in-memory buffer, so telemetry was not durable
  across restarts and the rules cache stayed off, with nothing in the log.
  `disk` and `memory` are now accepted in any case, with surrounding whitespace
  ignored; unset or empty is still `memory`.
- **An upstream CA bundle without a certificate fails at startup.** With
  `UPSTREAM_SSLMODE=verify-full`, an `UPSTREAM_SSLROOTCERT` file holding no
  certificate built an empty trust store: every connection failed closed at
  the TLS handshake, but the proxy started and reported ready. The Postgres
  proxy now loads its upstream TLS material once at startup, as it already did
  for `PROXY_TLS_MODE=require` without a certificate or key: a missing,
  unreadable or empty CA bundle, half of an `UPSTREAM_SSLCERT` /
  `UPSTREAM_SSLKEY` pair, or a client certificate or key that does not parse
  stops it before it listens. Errors name the variable and the file path.
  The files are still read again for each connection, as before.

### Upgrade notes

- **Behaviour change: an invalid value now fails startup.** A
  `VERICTO_TELEMETRY_BUFFER` other than `memory` or `disk` (for example
  `disc`) exits with `VERICTO_TELEMETRY_BUFFER="disc" is not supported`, like
  an unusable `VERICTO_TELEMETRY_SPOOL_SUBDIR`; it used to run on the memory
  buffer. Only read when the control-plane link is configured.
- **Behaviour change: an empty CA bundle fails startup.** A deployment with
  `UPSTREAM_SSLMODE=require` or `verify-full` whose CA bundle or mutual-TLS
  files are missing, empty or unparseable used to start and fail every
  connection; it now exits at startup. With `UPSTREAM_SSLMODE=disable` the
  files are not read. A `DISK` (upper case) deployment now gets the disk
  spool and the rules cache it asked for: make sure the spool volume is
  mounted.

### Documentation

- The `Cargo.toml` comment on the `vericto-engine` dependency called the engine
  an "open-core" library. It is under the Elastic License 2.0, which is
  source-available, not open source; the comment now says so. No code or
  dependency change.

### Tests

- Unit-test line coverage from 85.8% to 91.3% (cargo-llvm-cov; production lines
  only, without the in-file test modules: 76.7% to 85.5%). New tests cover the
  everyday query path on both protocols (allowed query forwarded byte for byte,
  dangerous one answered by the proxy and never forwarded, the extended-protocol
  sequence swallowed until Sync), Terminate / COM_QUIT, malformed Postgres
  frames, the `VERICTO_MAX_QUERY_BYTES` boundary (inclusive at the limit, refused
  one byte over, forwarded unevaluated under `monitor_mode`), the upstream TLS
  negotiation (a server that declines TLS is refused, never downgraded; broken
  handshakes; mutual-TLS file errors), MySQL connection-phase failures (no
  greeting, upstream TLS required but not offered, upstream gone mid-auth), a
  failed first rule sync (5xx, 401, unparseable body, unreachable API: the
  built-in ruleset stays, nothing is cached, the proxy still gets ready), every
  configuration variable and its clamping, and spool-directory adoption without
  a lease.
- Testability seams with no behaviour change: `ControlPlaneConfig`,
  `TcpProxyOptions` and `VERICTO_MAX_QUERY_BYTES` are read through a lookup
  function (the process environment in production), and the ECS task id through
  a function that takes the metadata endpoint, so tests never mutate the
  process environment.

## [4.12.1] — 2026-10-15

Requires vericto-engine v4.1.1 (from v4.0.0). No wire-protocol changes, and
nothing changes for Postgres or MySQL traffic: every verdict of the engine,
proxy and eval SQL (3,654 statements, Postgres and MySQL, under seven
policies) is the same with v4.0.0 and v4.1.1. The telemetry pipeline is
unchanged.

### Changed

- **vericto-engine v4.1.1.** The engine adds the SQLite dialect (4.1.0) and,
  on SQLite only, finds VERICTO-070's `randomblob(N)` / `zeroblob(N)` probe in
  every clause (4.1.1). SQLite is a library linked into the application, with
  no wire protocol for a proxy to front, so none of it is reachable from the
  Postgres or MySQL protocol this proxy serves. The engine now builds
  sqlparser with its `visitor` feature (`sqlparser_derive` joins the lock
  file).
- **The built-in fallback catalogue lists VERICTO-098 to VERICTO-101**, the
  engine's SQLite rules (Critical: 100 extension loading or file functions;
  High: 098 `ATTACH DATABASE`, 099 a `PRAGMA` that turns a safety off, 101
  `VACUUM INTO`), all `block`, so the list stays the engine's whole catalogue.
  They read only what the engine's SQLite parser records and never fire on the
  Postgres or MySQL protocol.
- The README lists SQLite with the dialects checked through the HTTP API, the
  CLI or MCP rather than a proxy.

## [4.12.0] — 2026-10-14

Telemetry loss is visible outside the proxy, the disk spool rides out a longer
API outage, and a workspace over its monthly quota no longer makes the proxy
retry all month. No wire-protocol changes; enforcement is unchanged. Works with
the current Vericto API, which ignores the new header and sends no quota reset
time (so 4.11's retries apply there); the API's matching release stores the
counters, shows them in the dashboard and announces the quota state.

### Added

- **Pipeline counters in every rule sync.** `GET /api/v1/sync/rules` (the
  proxy's heartbeat, every `VERICTO_RULES_SYNC_INTERVAL_SECS`) carries an
  `X-Vericto-Telemetry-Stats` header with compact JSON: `enqueued`, `delivered`,
  `dropped_queue_full`, `evicted_oldest`, `dropped_permanent`, `write_failures`,
  the events (`spooled_events`) and bytes (`spool_bytes`) buffered now,
  `dropped_quota`, `quota_paused` and `quota_resets_at`, the buffer mode and the
  proxy version. Totals are since the process started,
  under a random `instance_id` drawn at startup, so the API tells a restart
  (counters from 0) from new drops. Up to 4.11 these figures were only in the
  proxy's own `Telemetry pipeline stats` log line, so events evicted from a full
  spool were lost without the control plane knowing. The header has no query
  text, user name or address. An API that does not know it ignores it.
- **Telemetry pauses over the monthly quota.** On a 429 whose body says
  `code: "QUOTA_EXCEEDED"` and when the quota resets (`error.resets_at`, or a
  `Retry-After` header), or a rule sync saying `telemetry_quota: "exceeded"`
  with `telemetry_quota_resets_at`, the proxy stops sending and retrying
  telemetry and stops enqueuing new events (counted as `dropped_quota`).
  Queries are evaluated and enforced exactly as before, and events already
  buffered wait. It resumes when a rule sync says `telemetry_quota: "ok"` (an
  upgrade, or the new month) or the reset time passes. One WARN on pausing, one
  INFO on resuming. Up to 4.11 the proxy retried such batches with backoff all
  month while its spool filled and evicted. Any other 429 (a rate limit, or a
  quota 429 without a reset time, as older APIs send) keeps the backoff.
- `Telemetry pipeline stats` also logs `spool_bytes`, `dropped_quota` and
  `quota_paused`.
- **Delivery lag.** The proxy knows how far behind its telemetry is without
  scanning the spool: the write time of the oldest spool segment (its mtime,
  read once, after a restart), the front of the memory ring, and the oldest
  event of each batch in flight. The rule-sync header carries it as
  `oldest_undelivered_age_s` (0 when nothing waits), with `last_delivery_at`
  (the last 2xx) and `spool_max_bytes`. Fields were only added: `v` stays 1.
- **Metrics** (README, "Metrics"), both off by default: `GET /metrics` in the
  Prometheus text format on the health-check listener
  (`VERICTO_METRICS_PROMETHEUS`), never on the database port; and a CloudWatch
  Embedded Metric Format line on stdout every 60 s (`VERICTO_METRICS_EMF`,
  `VERICTO_METRICS_EMF_NAMESPACE` default `Vericto/Proxy`,
  `VERICTO_METRICS_EMF_INTERVAL_SECS`, `VERICTO_METRICS_PROXY_NAME`,
  `VERICTO_METRICS_EMF_TASK_DIMENSION`), dimensions `[ProxyName]` and
  `[ProxyName, TaskId]`. Oldest undelivered age, seconds since the last
  delivery, spool bytes, events, bound and percentage, delivered, dropped by
  cause, quota pause and requests in flight, all named `vericto_proxy_*`. Labels
  are a fixed set (`cause`, `version`, `buffer`); no query text, user, address
  or workspace/database id, ever.
- **`VERICTO_HEALTHZ_ADDR`**: the address the health-check listener binds
  (default `0.0.0.0`, as before).
- **One spool directory per proxy on a shared volume**
  (`VERICTO_TELEMETRY_SPOOL_SUBDIR=task|hostname|<name>`, README "Several
  proxies on one volume"). Each proxy spools to `<spool dir>/tasks/<name>/`
  under a lease it renews every 30 s and releases on shutdown, and adopts, at
  startup and every minute, the directories whose lease is released or older
  than `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` (default 600): an atomic rename
  into its own `adopted/` directory, so exactly one proxy takes each, and their
  events are delivered first. Files at the top of the shared directory are
  claimed one by one the same way. Up to now, replicas mounting one EFS access
  point shared one spool: each sent the others' files too, counted them against
  its own bound and evicted them.

### Changed

- **The disk spool is bounded by bytes:** `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`,
  default 1 GiB (at least 1 MiB). Up to 4.11 it held at most
  `VERICTO_TELEMETRY_MEMORY_CAPACITY` events (10,000), under 7 seconds of an
  API outage at 1,500 statements per second. Measured over a pgbench-style mix,
  a spool line averages 417 bytes, so 1 GiB holds ~28 minutes at 1,500 events
  per second, and it is 5% of Fargate's default 20 GiB of ephemeral storage
  (README, "Disk spool size"). Past the bound the oldest segments are evicted
  and counted (`evicted_oldest`), as before. The memory buffer keeps its event
  bound, `VERICTO_TELEMETRY_MEMORY_CAPACITY` (10,000).
- **An event bound on the spool only when one is configured:**
  `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS`, or `VERICTO_TELEMETRY_MEMORY_CAPACITY`
  when that is set, so a deployment that bounded its spool with it keeps that
  bound. The spool also keeps at most 100,000 segment files, which bounds the
  in-memory index and the startup listing when traffic is so low that each file
  carries one event.
- **Segment files carry their size in the name,**
  `seg-<seq>-<count>-<bytes>.jsonl`, so the index (bytes included) is rebuilt at
  startup from one directory listing. Files written by 4.9.1–4.11 and legacy
  `*.json` files are read as before and measured once with `stat`.

### Fixed

- The rules cache is written under a temporary name unique to each write, so
  replicas sharing the spool volume no longer truncate each other's temporary
  file before its rename.

### Upgrade notes

- Several replicas on one spool volume: set `VERICTO_TELEMETRY_SPOOL_SUBDIR=task`
  (the Vericto Enterprise kit does). The files already in the shared directory
  are claimed and delivered by the upgraded proxies. A version without the
  setting does not read `tasks/`: let the spool drain before downgrading.
- The health-check listener now waits up to 2 s for a request before closing a
  connection that sends nothing; a TCP probe that closes its side is answered
  at once, as before.

- With `VERICTO_TELEMETRY_BUFFER=disk` and no `VERICTO_TELEMETRY_MEMORY_CAPACITY`,
  the spool can now grow to 1 GiB during an outage. Make sure the volume has
  room, or set `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` lower.
- A downgrade to 4.11 or earlier ignores the segments written by 4.12 (they stay
  on disk, undelivered, until 4.12 runs again). Let the spool drain first.

## [4.11.0] — 2026-10-14

Telemetry delivery keeps up with the proxy's traffic. On staging (PostgreSQL
benchmark, 650–1,500 statements per second) 4.9.1 delivered ~114 events per
second: one request of 100 events at a time, each waiting ~700 ms for the API,
so the disk spool filled and evicted ~86% of the events. No wire-protocol
changes and nothing changes on the query path. Pairs with the Vericto API's
bulk, queued ingest; works with an older API too (see gzip below).

### Changed

- **Batches of 500, sent when full or when 5 s old.** A batch goes as soon as
  `VERICTO_TELEMETRY_BATCH_SIZE` events (default now 500, from 100, and capped
  at 500, what `/api/v1/ingest/events` accepts) are pending, or when the oldest
  pending event has waited `VERICTO_TELEMETRY_FLUSH_SECS` (default 5),
  whichever comes first. Before, the reporter woke every 5 s.
- **Up to 4 requests in flight** (`VERICTO_TELEMETRY_MAX_IN_FLIGHT`). The
  queue hands each batch events no other undelivered batch holds, and an event
  leaves the buffer (disk spool or memory) only when the request that carried
  it was answered 2xx, in whatever order the answers arrive; a failed batch is
  offered again without resending the ones around it. After a restart, whatever
  was not acknowledged is sent again (at-least-once, as before).
- **Retries back off exponentially** (`VERICTO_TELEMETRY_RETRY_BASE_MS`, 1 s,
  doubling to `VERICTO_TELEMETRY_RETRY_MAX_SECS`, 60 s) instead of every tick.
- **A 413 splits the batch** in halves until the parts fit, instead of dropping
  it. 415 is now a permanent refusal like 400 and 422.

### Added

- **gzip request bodies** (`Content-Encoding: gzip`, `VERICTO_TELEMETRY_GZIP`,
  on by default). If the API refuses a compressed body (400 or 415) and accepts
  the same events uncompressed, the proxy sends uncompressed from then on, so
  4.11.0 against an API without gzip support loses nothing.
- `Telemetry pipeline stats` also logs delivered events, requests, retries,
  events refused permanently, requests in flight and request times.

### Security

- `rustls` 0.23.45 → 0.23.46 (lockfile only) for RUSTSEC-2026-0346 (`Debug`
  output of client session values exposes TLS secrets), RUSTSEC-2026-0347
  (buffered data sent to the outer server after an ECH rejection),
  RUSTSEC-2026-0348 (Brotli certificate decompression can allocate up to 1 GiB
  before authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello
  can downgrade later connections to classical key exchange). rustls is the TLS
  stack of the proxy's client and server connections and of its requests to the
  Vericto API. The proxy does not configure ECH or enable Brotli certificate
  compression.

### Dependencies

- `flate2` 1 (MIT OR Apache-2.0), already in the lockfile through `mysql_async`,
  now a direct dependency for the gzip bodies.

## [4.10.0] — 2026-10-13

Requires vericto-engine v4.0.0 (from v3.9.0). No wire-protocol changes, and
nothing changes for Postgres or MySQL traffic: the engine's 4.0.0 release
compared every verdict of this repository's SQL with 3.9.0 and none differs.
The 4.9.1 telemetry pipeline is unchanged.

### Changed

- **vericto-engine v4.0.0.** The engine adds the Snowflake dialect and makes its
  growing public types `#[non_exhaustive]`. The proxy builds against it with two
  changes: the telemetry dialect name is `Dialect::as_str()` (the same four
  names as before), and the query-size cap gives every dialect the proxy does
  not serve over the wire the stricter MySQL cap, as it already did for Oracle
  and SQL Server.
- **The built-in fallback catalogue lists VERICTO-091 to VERICTO-097**, the
  engine's Snowflake rules (Critical: 091 stage unload or file transfer, 092
  external stage or integration, 093 share to another account; High: 094
  recovery reduced, 095 warehouse cost, 096 code that runs later, 097 role
  switch), all `block`, so the list stays the engine's whole catalogue. They
  read only what the engine's Snowflake parser records and never fire on the
  Postgres or MySQL protocol.

### Added

- **`VERICTO_WIRE_PROTOCOL=snowflake` is a startup error**, instead of falling
  back to the Postgres protocol. Snowflake has no TCP wire protocol a proxy can
  front (clients reach it over HTTPS): check Snowflake SQL through the HTTP API,
  the CLI or MCP. Other values behave as before.
- A sync whose dashboard dialect is `snowflake` logs a specific warning (no
  proxy can front a Snowflake database) instead of the generic protocol
  mismatch one.

## [4.9.1] — 2026-10-13

Requires vericto-engine v3.9.0 (unchanged). No wire-protocol changes. Telemetry
is now asynchronous: see the behaviour changes below before upgrading a proxy
that runs `VERICTO_TELEMETRY_BUFFER=disk`.

### Performance

- **Telemetry no longer holds statements back with the disk buffer.** Up to
  4.9.0, `VERICTO_TELEMETRY_BUFFER=disk` wrote every statement's event to the
  spool synchronously, after evaluation and before the statement was
  forwarded: create a file, write it, rename it. On a network volume (EFS)
  each of those is a round trip, and the kernel holds the spool directory's
  lock across create, rename and unlink, so all connections queued behind one
  another and behind the reporter's deletes. Throughput through the proxy was
  capped at about 40 statements per second at any concurrency, with the
  proxy's CPU nearly idle (staging session 1: +17.5 ms p50 at concurrency 1,
  +192 ms p50 and about 1 s p99 at concurrency 16). Now the query path only
  places the event in a bounded in-memory channel (`try_send`, no I/O, no
  lock held across I/O) and forwards the statement at once. A background
  writer thread persists the channel's contents in batches: one spool file
  per batch of up to `VERICTO_TELEMETRY_SPOOL_BATCH_MAX` events (default
  1000) or every `VERICTO_TELEMETRY_SPOOL_FLUSH_MS` (default 50 ms), written
  to a temporary name, fsynced, renamed into place and the directory fsynced.
  On a local reproduction with EFS-like latency on the spool (Postgres 17,
  concurrency 16), throughput through the proxy went from 42 to about 4,600
  statements per second (direct: about 5,600, database-bound), the median
  added latency from 343 ms to 0.15 ms, and the p99 added to OLTP statements
  from 790 ms to 1.5 ms. MySQL 8.0 shows the same: 36 to about 2,500
  statements per second, added p50 395 ms to 0.05 ms.
- **No directory listing on the spool after startup.** The spool index
  (segments, event counts, delivery progress) is kept in memory and rebuilt
  from one listing at startup; spool files have monotonic names
  (`seg-<seq>-<count>.jsonl`). 4.9.0 still listed and sorted the whole spool
  for every delivery batch, and for every event once the spool was full,
  holding the lock every connection's `push` needed (at a full 5,000-file
  spool on the reproduction: 113 ms per listing, 271 ms waiting for the lock,
  9 statements per second).
- **Spool reads and deletes are off the async workers.** The reporter read
  and deleted spool files on a tokio worker thread, stalling the sessions
  scheduled on it for the duration of each delivery's deletes (52 to 615 ms
  per 100-event batch on the reproduction). They now run on the blocking pool.
- **The memory buffer no longer logs inside its lock.** When the in-memory
  buffer was full, every event logged a warning while holding the buffer's
  mutex, serialising all connections on stdout. Drops are now counted and
  warned about at most every 10 seconds, outside the lock.

### Changed

- **Durability of the disk buffer.** An event reaches the spool at most
  `VERICTO_TELEMETRY_SPOOL_FLUSH_MS` (plus one write) after its statement,
  instead of before the statement was forwarded. A crash or `SIGKILL` inside
  that window loses those events; a `SIGTERM` does not (see below). What is on
  disk is now fsynced (4.9.0 did not fsync), so it also survives a power loss.
  Delivery stays at least once: a spool file is deleted only once all its
  events are acknowledged, and a partly delivered file is sent again from its
  start after a restart.
- **Backpressure: drop, never block.** When the channel in front of the disk
  writer is full (`VERICTO_TELEMETRY_QUEUE_CAPACITY`, default 2048 events) new
  events are dropped and counted, and a warning is logged at most every 10
  seconds; statements are never held back. There was, and is, no blocking or
  fail-closed telemetry mode.
- **Capacity is counted in events.** `VERICTO_TELEMETRY_MEMORY_CAPACITY`
  (default 10,000) still bounds the disk spool; past it the oldest spool files
  are dropped, a whole file (up to one batch) at a time, counted and warned
  about. The spool holds far fewer files than events: an external watch on the
  file count (such as the benchmark's 5,000-file stop condition) should count
  events or bytes instead.
- **Clean shutdown.** On `SIGTERM` or `SIGINT` the proxy writes what is still
  queued to the spool, delivers what it can, and exits, within
  `VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS` (default 5000). Before, there was no
  handler: as a container's PID 1 without an init (the image runs the binary
  directly) the proxy ignored `SIGTERM` until the runtime sent `SIGKILL` (30 s
  later with `docker stop -t 30`, exit 137); it now exits 0 in about a second.
  With the memory buffer the shutdown delivery is the only chance for buffered
  events.
- **Upgrade.** One-event `*.json` files left by 4.9.0 and earlier are read back
  and delivered first; nothing needs to be drained before upgrading.

### Added

- `Telemetry pipeline stats` log line every minute while there is activity:
  queue depth, spooled events, events enqueued, dropped because the queue was
  full, evicted for capacity, lost to write errors, batches written, last and
  longest batch write time.
- Configuration: `VERICTO_TELEMETRY_QUEUE_CAPACITY`,
  `VERICTO_TELEMETRY_SPOOL_FLUSH_MS`, `VERICTO_TELEMETRY_SPOOL_BATCH_MAX`,
  `VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS` (README, Control plane).

## [4.9.0] — 2026-10-12

Requires vericto-engine v3.9.0. No configuration or wire-protocol changes.

### Security

- **RUSTSEC-2024-0449.** vericto-engine 3.8.1 parsed custom-rule YAML with
  `serde_yaml`, whose `unsafe-libyaml` is unmaintained; since the advisory
  reached the RustSec database, the proxy's own `cargo deny` and `cargo audit`
  fail on it. Engine 3.9.0 uses `serde_norway`, the maintained fork, with the
  same rule syntax and error messages.
- **Two built-in rules cover more statements, with the engine.** `DROP TRIGGER`
  is reported by VERICTO-019 and `COPY … FROM` a server-side file by
  VERICTO-061, on every dialect including PostgreSQL, so a workspace that
  blocks those rules now blocks these statements too.

### Changed

- **sqlparser 0.63, with the engine.** The engine parses MySQL, Oracle and SQL
  Server with sqlparser 0.63 instead of 0.52, and the proxy tokenizes MySQL
  text with the same version. Statements 0.52 could not parse, which the proxy
  forwarded or blocked according to the workspace's parse-error setting (and
  blocked under a `block`/`mask` tag or an enforced allowlist), are now judged
  by the rules: on MySQL, for example, `SET SESSION TRANSACTION …` sent on
  connect by Django, Hibernate and SQLAlchemy is allowed, index hints and
  `WITH ROLLUP` are masked like any query, and data-modifying CTEs are
  evaluated. Statement kinds the engine does not model still resolve as parse
  errors. See the engine's 3.9.0 CHANGELOG for the full list.
- The proxy's MySQL tokenizer keeps a `/*! … */` comment as a comment, as
  before: sqlparser 0.63 splices its content into the statement as code,
  whatever its version number, which would have made `/*!50000 USE x */` move
  the session's current database for certain and put comment text into
  sanitized telemetry. A `USE` in such a comment still makes the current
  database unknown.

### Dependencies

- Routine updates (Dependabot): tokio 1.53.2, tokio-rustls 0.26.6, async-trait
  0.1.92, serde 1.0.229, serde_json 1.0.151 and uuid 1.26.1. tokio-rustls 0.26.6
  propagates a transport error on a TLS stream at the next read (0.26.5, never
  shipped here, could swallow it); no API or MSRV change (Rust 1.88).

### CI

- GitHub Actions updates (Dependabot), still pinned by SHA: actions/cache 6.1.0,
  actions/upload-artifact 7.0.2, actions/download-artifact 8.0.2,
  docker/login-action 4.6.0 and docker/build-push-action 7.4.0. They run on
  Node 24; the release image keeps the same tags, labels and per-arch build
  (no build-time provenance), with the provenance attestation added in 4.8.2.

## [4.8.2] — 2026-10-11

Security release from the 2026-10 review. Requires vericto-engine v3.8.1 (unchanged).
Upgrade note: a proxy pointed at an `http://` control plane (local development only)
now needs `VERICTO_ALLOW_INSECURE_API_URL=true`.

### Security

- **The API key only goes to an `https://` control plane.** The proxy refuses to
  start when `VERICTO_API_URL` is `http://` on a host other than loopback, unless
  `VERICTO_ALLOW_INSECURE_API_URL=true` (development stacks). Requests that carry
  the key follow redirects only within the same origin.
- **The telemetry spool is private to the proxy's user.** With
  `VERICTO_TELEMETRY_BUFFER=disk` the spool directory is `0700` and its files
  `0600` (they were created with the process umask). Enforcing the spool's
  capacity no longer lists the directory for every event.
- **Log lines show queries without their values.** The preview of a blocked or
  masked query in the proxy's log has its literals replaced, as sanitized
  telemetry does, whatever the workspace's reporting mode.
- The release image is published with a build provenance attestation
  (`gh attestation verify`), its build is pinned (base images by digest,
  `--locked`), the crate forbids `unsafe` code, and CI adds cargo-deny,
  cargo-audit, gitleaks and Dependabot, with every action pinned by SHA.

## [4.8.1] — 2026-10-10

Requires vericto-engine v3.8.1. Adopts its dialect-aware name semantics for the
agent access allowlists, table-level `DELETE`, row locks that need write, and
`AccessPolicy::default_schema`; closes the StartupMessage `search_path` gap; and
the MySQL connection fixes below.

### Added

- **`default_schema` from `/sync/rules` reaches the engine.** Each `agent_access`
  policy may carry the database's `default_schema` (the dashboard's setting); the
  proxy passes it to the engine with the policy, so an entry without a schema is
  the table in that schema. Absent: the engine default (`public` on Postgres).
  Entry names arrive in the form fmw sends them (Postgres names that are not
  plain lower case double-quoted) and are compared by the engine.
- **MySQL sessions track their current database.** The database named in the
  HandshakeResponse is the session's default schema and wins over the policy's
  `default_schema`; a forwarded `COM_INIT_DB`, SQL `USE` or `COM_CHANGE_USER`
  moves it for the statements after it. `COM_INIT_DB` is `USE <db>` in protocol
  form: refused under an enforced policy as `USE` is (the database then does not
  move), forwarded and flagged under `observe`, forwarded without a policy, and
  tracked whenever it is forwarded, so a policy synced later in the session
  applies to the database the session is really in. A `USE` the proxy cannot read
  for certain (a `/*! … */` comment, `USE a.b`) leaves no default schema, the
  engine's stricter reading.

### Changed

- **Engine 3.8.1 semantics** under an allowlist: a schema-less entry no longer
  matches the table in every schema; Postgres compares quoted names exactly and
  folds unquoted ones; MySQL compares table and database names exactly; `DELETE`
  needs a `read_write` entry for the table whatever its column list and is
  reported as the table (`AccessPolicy > orders (write)`, column null);
  `SELECT … FOR UPDATE` / `FOR SHARE` need `read_write` on each locked table;
  SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` are denied; the session
  statements drivers send on connect are no longer blocked as parse errors on a
  database with `block`/`mask` tags.

### Fixed

- **A Postgres StartupMessage could set `search_path` (or `role`,
  `session_authorization`) past an allowlist.** `SET search_path` is denied under
  a policy, but the same setting sent at connect, as a startup parameter or in
  `options` (`-c search_path=…`, `--search_path=…`, `PGOPTIONS`), reached the
  server unevaluated and moved where unqualified names resolve. Each such setting
  is now evaluated as the `SET` it is, under the session user's policy, when the
  session has an allowlist or the database has sensitive-column tags: denied under
  `enforce` (the connection is refused with 42501 and never reaches the
  database), flagged under `observe` or `monitor_mode`, reported like the
  statement. Without a policy nothing changes.
- StartupMessage parameters with an empty value no longer shift the pairs after
  them (the parser skipped empty strings, so `application_name=''` made the next
  name read as a value).

- **MySQL logins no longer hang after the first one for a `caching_sha2_password`
  account**, the default on MySQL 8.0 and 8.4, with or without TLS. Once the
  server has the account's hash cached it answers with fast auth: AuthMoreData
  `0x03`, then the OK, with nothing from the client in between. The proxy waited
  for a client packet after every AuthMoreData, so the client waited for an OK the
  proxy never relayed and the login hung until the client gave up. Not affected:
  the first login after a server restart or `FLUSH PRIVILEGES` (full auth), and
  `mysql_native_password` accounts.
- Tests for the connection phase: a fake MySQL server plays the fast-auth,
  full-auth (with and without the RSA key exchange), AuthSwitchRequest,
  multi-factor (AuthNextFactor after fast auth), empty-password and failed-login
  exchanges through the proxy, with every read bounded so a wrong
  turn fails instead of hanging. Against a real MySQL (`VERICTO_TEST_MYSQL_URL`),
  many logins as one user, in a row and at once.
- **MySQL clients in the default `ssl-mode=PREFERRED` connect to a plaintext
  proxy.** The proxy relayed the server's greeting as is, so it offered TLS it
  cannot provide without `PROXY_TLS_MODE`: the client sent an SSL Request and a
  TLS handshake, and failed with `SSL connection error: wrong version number`.
  The greeting now offers TLS only when the proxy terminates it, and a client
  then falls back to plaintext as it does against a server without TLS.
- **MySQL protocol compression is never negotiated.** After the OK, a client that
  asked for zlib or zstd switched to compressed framing, which the proxy does
  not decode: every command hung, and none was evaluated. The proxy clears
  `CLIENT_COMPRESS` and `CLIENT_ZSTD_COMPRESSION_ALGORITHM` from the greeting
  and from the client's response, so clients get what a server with
  `protocol_compression_algorithms=uncompressed` offers: one that prefers
  compression runs uncompressed, one that allows only `zlib` or `zstd` is refused
  at connect (`ERROR 2066`) instead of hanging.
- **`PROXY_TLS_MODE=require` refuses a plaintext MySQL login with an error**:
  `ERROR 3159 (HY000)`, as MySQL does under `require_secure_transport`, instead
  of closing the connection ("Lost connection to MySQL server").
- **A MySQL packet inside a command is no longer read as a new command.** Only a
  packet with sequence id 0 starts one; the packets that continue it carry data.
  The proxy read their first byte as a command tag, so a LOAD DATA LOCAL INFILE
  file starting with `0x01` ended the session as a `COM_QUIT`, and so did about
  one COM_CHANGE_USER in 256 to a `caching_sha2_password` account (its scramble
  starting with `0x01`); file data starting with `0x03` was evaluated as SQL.
  They are forwarded as they are now, which is safe: MySQL answers a command
  whose sequence id is not 0 with `ERROR 1156` and does not run it.

## [4.8.0] — 2026-10-09

Agent access allowlists (`VERICTO-087`), enforced per database user. Requires
vericto-engine v3.8.0. A database without policies is evaluated exactly as before.

### Added

- **`agent_access` in `/sync/rules`**: one allowlist per database user, `"*"`
  optionally the default for users not listed (engine contract §2). Parsed with
  the engine's own types into a hot-swapped map, and kept in the rules cache with
  the rest of the bundle, so a restart during an outage keeps restricting the
  agents. Absent, `null` or `{}` = no user restricted.
- **Per-session identity.** The session's user is the Postgres StartupMessage
  `user` or the MySQL HandshakeResponse username. Each statement is evaluated with
  that user's policy (`AccessPolicyMap::for_user`), selected again per statement:
  a sync that changes it applies to open sessions on their next statement. Two
  sessions of different users on one proxy get their own policies. A session
  whose user cannot be read gets a deny-everything policy while any user has one.
- **Enforcement on both protocols.** A denial under `enforce` is the native
  error (42501 / ERROR 1142) with `[VERICTO-087]` and what was denied, on the
  simple and the extended / prepared paths; under `observe` the query is
  forwarded and flagged. An allowed column tagged `mask` comes back masked.
- **Nothing the client sends mid-session changes the identity.** Besides the SQL
  the engine denies under a policy (`SET ROLE`, `SET SESSION AUTHORIZATION`,
  `USE`, …), the proxy refuses the protocol commands that do the same outside
  SQL: Postgres `FunctionCall`, MySQL `COM_INIT_DB`, `COM_FIELD_LIST`, the
  replication / process commands and any unknown command; a query message whose
  SQL cannot be read. MySQL `COM_CHANGE_USER` is refused when the current or the
  target user has a policy.
- **Telemetry**: `db_user` on every event (when known), `access_policy_mode` and
  `access_denied` (`[{schema, table, column, needed}]`) under a policy. Names are
  cut to 63 bytes and the list to 64 entries, the ingest schema's bounds. In
  sanitized mode a MySQL name the query did not spell as an identifier (a `"…"`
  string the engine also reads as a column) is reported as `?`.
- `VERICTO-087` is in the built-in ruleset (31 rules), like `VERICTO-085`; it
  only acts on a policy.

### Changed

- Parse errors resolve with `effective_parse_error_for(sql, dialect)`: under an
  enforced allowlist they block, except the session statements drivers send on
  connect.
- `ast_node_path` (flat and per violation) is cut to 512 bytes, the ingest
  schema's bound: a long parser message or name no longer rejects the batch.
- The catalogue test finds the engine's README through `cargo metadata` when the
  engine is not a git checkout (a local `[patch]`).

## [4.7.1] — 2026-10-08

### Fixed

- **The built-in ruleset is the engine's whole catalogue again (30 rules, was 28).**
  It is what the proxy enforces at startup, before the first `/sync/rules`, and
  whenever there is no control plane and no rules cache. It lacked the two newest
  engine codes:
  - `VERICTO-085` (read of a sensitive column, High / block, Security). It only
    acts on column tags, which come with `/sync/rules`, so listing it changes no
    decision.
  - `VERICTO-086` (MySQL text the engine and MySQL would read differently, Critical
    / block, Security). The engine already raised it without the list. A proxy with
    no control plane blocks `/*!50000 SELECT id FROM accounts` with ERROR 1142
    `[VERICTO-086]`, and a test now pins that on the built-in path.
- A test compares the built-in ruleset with the catalogue of the engine the proxy
  is built against: same codes, same severities. It reads the engine's README
  from the locked dependency, so a new engine rule fails the build until it is
  added here.

## [4.7.0] — 2026-10-08

MySQL masks. A `mask` tag on MySQL used to block every read of the column with
ERROR 1142; with vericto-engine v3.7.0 the proxy forwards the engine's rewritten
query instead, so a MySQL client receives masked values, as a Postgres one already
did. A database without tags is evaluated exactly as before.

### Added

- **`mask` on MySQL (VERICTO-085, engine v3.7.0).** When the engine returns a
  `rewritten_query`, the proxy sends it in place of the original:
  - `COM_QUERY`: the rewrite replaces the SQL text. The `CLIENT_QUERY_ATTRIBUTES`
    prefix that MySQL 8.0.23+ clients put in front of it is kept, since the server
    parses it first.
  - `COM_STMT_PREPARE`: the rewrite replaces the statement. Its `?` placeholders are
    counted with the MySQL lexer (not inside strings, quoted identifiers or comments)
    before forwarding, so the parameter count the server returns in
    `COM_STMT_PREPARE_OK` is the one the client prepared for. A different count is
    blocked, like a lost `$n` on Postgres.
  - `COM_STMT_EXECUTE` and `COM_STMT_SEND_LONG_DATA` are not touched. The proxy keeps
    no statement map: the server gives the rewritten statement its id, the
    `COM_STMT_PREPARE_OK` reaches the client unchanged, and the client executes that
    id with the values it bound.

  A MySQL mask the engine cannot rewrite (`SELECT *` over a masked column, a copy into
  another table, a query whose text cannot be reproduced faithfully) still blocks with
  ERROR 1142 and the engine's reason. The fail-safe checks are the Postgres ones: an
  empty rewrite, a NUL, a changed `?` count, a rewrite with no masked column, or a
  masked read with no rewrite all block with `VERICTO-085` and a message. A rewrite
  that would not fit one MySQL packet, or a `COM_QUERY` whose attributes bind values,
  cannot be framed and blocks too. `monitor_mode` forwards the original and only
  reports. Telemetry is the Postgres one: `rule_code` `VERICTO-085`, the touched
  columns, and the rewritten query next to the original.

### Fixed

- **Sanitized telemetry normalizes MySQL text with the MySQL lexer.** Every query was
  normalized with libpg_query, whatever its dialect. On MySQL text that leaked and
  lost data:
  - a double-quoted value (`WHERE name = "Alice"`) is a string in MySQL and an
    identifier in Postgres, so it was reported in clear;
  - backtick-quoted identifiers, which every MySQL mask rewrite uses, do not parse in
    Postgres, so the rewritten query would only ever have been reported as
    `<unparseable query redacted>`.

  MySQL queries, rewrites and suggestions now go through the sqlparser MySQL
  tokenizer (the one the engine parses with). Every literal (string, number, hex,
  bit) becomes `?` and every comment a space; keywords, identifiers, operators and
  the client's own `?` are kept. Text that does not tokenize is still redacted.
  Postgres is unchanged.

### Changed

- **vericto-engine v3.7.0** (from v3.6.1): MySQL `mask` rewrites. No type or field
  changes. Engine changes that reach the wire beyond the mask itself:
  - Rule evaluation on MySQL now follows MySQL's own reading of comments and string
    escapes, for every rule and policy, with or without tags. Text the engine cannot
    read with certainty is blocked by the new Security rule `VERICTO-086` ("SQL text
    that MySQL and the engine would read differently"), which the proxy answers like
    any block (ERROR 1142 on MySQL), and only flags under `monitor_mode`. Its message
    carries no query text.
  - More ways of copying a tagged MySQL column into a session variable or another
    row now count as reads of it.
  - On Postgres a computed expression masked `full` (`string_agg(email, ',')`) keeps
    its expression, so an aggregate still returns one row. Values are unchanged.
- **`sqlparser` 0.52** is now a direct dependency. It was already compiled in through
  the engine, so no new code ships: it gives the `?` count and the MySQL sanitizer.
  It stays pinned to the engine's version.

## [4.6.0] — 2026-10-08

Sensitive Column Protection: the proxy enforces the database's column tags on the
wire. It blocks the column, flags it, or on Postgres forwards a rewritten query that
masks it. It needs vericto-engine v3.6.1. A database without tags is evaluated
exactly as before. The release also ships the changes made since 4.5.1 and listed
below: `PROXY_TLS_MODE=require` refuses plaintext Postgres clients, parser messages
reach the control plane, and `rustls-pemfile` is gone.

### Added

- **Sensitive columns are enforced on the wire (VERICTO-085, engine v3.6.1).** A
  database's column tags now arrive in `/sync/rules` as `sensitive_columns`, next to
  `rules` and `policy`, and go into the `EnforcementPolicy` every query is evaluated
  with. They are kept in the live `ArcSwap` snapshot and in the last-good rules cache
  like the rest of the response, so a restart during a control-plane outage keeps
  enforcing them. An API that does not send the field gives exactly the policy the
  proxy built before.

  What a tag does on each protocol:
  - `block`: the query never reaches the database (Postgres `ErrorResponse` 42501,
    MySQL `ERR_Packet` 1142), on the simple and the extended protocol alike.
  - `flag`: forwarded as sent and reported as FLAGGED.
  - `mask` on Postgres: the proxy forwards the engine's **rewritten** query instead of
    the original, so the client receives masked values. A simple `Query` and an
    extended-protocol `Parse` are both rewritten in place. On a `Parse` the statement
    name and the parameter type OIDs are kept byte for byte and the `$n` placeholders
    survive, so the client's `Bind` and `Execute` work unchanged.
  - `mask` on MySQL: **blocked**. The engine has no MySQL rewrite yet, and forwarding
    the value in clear would quietly turn "never in clear" into "tell me afterwards".

  The proxy does not take the rewrite on trust. A masked read with no rewritten query,
  a rewrite for a dialect that has none, an empty one or one with a NUL, or a rewrite
  that drops a `$n` the client is going to bind, is blocked
  with `VERICTO-085` and a message saying why. In each of those cases the only thing
  left to forward is the unmasked original. `monitor_mode` still never changes what
  runs: there, a would-be mask is forwarded as sent and only reported.

  Telemetry carries what the audit needs, in the shape `/ingest/events` validates:
  `rule_code` `VERICTO-085`, `sensitive_columns`
  (`[{schema, table, column, policy}]`, at most 64, the schema's bound), and, for a
  mask, `rewritten_query` next to the original `query_text`. In sanitized mode the
  rewritten query is normalized like the original, and so is a VERICTO-085 suggestion,
  which under `monitor_mode` is the would-be rewrite with the query's literals in it.
  The original and the rewrite share the 8 KiB query budget instead of taking 8 KiB
  each. That budget is what keeps a default batch of 100 events under the API's 1 MiB
  body limit, and two full texts per event would break it at 1.6 MiB. Events and spool
  files without the new fields read and serialize exactly as before.

- **A way to try the proxy with Docker alone.** The README's new "Try it with
  Docker" section starts a throwaway Postgres and the published image, and shows a
  `DELETE` without `WHERE` being blocked and one with `WHERE` going through. It needs
  no account, API key or build.

### Changed

- **With a `block` or `mask` tag configured, a query that does not parse is blocked**,
  whatever the workspace's parse-error policy says. The proxy now branches on the
  engine's `EnforcementPolicy::effective_parse_error()` instead of the raw
  `parse_error` field. Without that, syntax the parser rejects and the database
  accepts would be a way around a tag: MySQL `HANDLER customers READ` and
  `PREPARE s FROM '…'` are two such cases. With no tags, or with only `flag` tags,
  parse errors behave as before.
- **vericto-engine v3.6.1** (from v3.5.3). Version 3.6.1 rather than 3.6.0: in
  3.6.0 a computed mask over a bind parameter (`substring(card, $1, 4)`) dropped the
  `$1`, and the proxy blocked such a Parse. With 3.6.1 the parameter is kept and the
  Parse is forwarded rewritten; the parameter check stays as a safety net.
  Additive: `EnforcementPolicy` gains
  `sensitive_columns` and `EvaluationOutcome` gains `rewritten_query` and
  `sensitive_columns`. With no tags the engine skips the analysis and every decision
  is unchanged.

- **The Docker and Compose examples use the published image**
  `ghcr.io/vericto/vericto-proxy:4.5.1` instead of a locally built
  `vericto/proxy:local`. Building the image yourself is still documented, and the
  `cargo` instructions are now under "Run from source".
- **Contributions need the Vericto Contributor License Agreement** instead of a DCO
  sign-off. `CONTRIBUTING.md` and the pull request template ask contributors to sign
  it before their first pull request is merged, and no longer ask for `git commit -s`.
- **The issue and pull request templates describe the proxy.** They had been copied
  from vericto-engine and asked about dialects the proxy does not serve and about new
  rules. The bug report now asks for the wire protocol, the driver, the proxy version
  and its configuration. Rule proposals and parser problems link to vericto-engine,
  and vulnerabilities to private reporting; the rule-proposal template is gone.

### Security

- **PEM parsing no longer depends on `rustls-pemfile`.** That crate is unmaintained
  (RUSTSEC-2025-0134) and had become a thin wrapper over the parser in
  `rustls-pki-types`, which the proxy already compiled in through `tokio-rustls`. The
  certificate and key loaders for both TLS hops now call it directly, so a dependency
  is gone instead of replaced. Behaviour is unchanged: the three private-key encodings
  (PKCS#8, PKCS#1, SEC1) are still told apart by their PEM label, and a key file with
  no key still fails with the same message, without echoing inline material. New tests
  pin both.
- **`anyhow` 1.0.104**, past the `downcast_mut` unsoundness (RUSTSEC-2026-0190). It
  only reaches the build through `prost-derive`, a proc-macro, so it never ran in the
  proxy; updated so `cargo audit` reports nothing.

With both, `cargo audit` reports no vulnerabilities and no warnings. This closes R4
of the 2026-10-04 vulnerability review.

### Removed

- **`Dockerfile.build`.** It was a stale copy of `Dockerfile.local`. It copied the
  engine from a `vericto-engine-local` directory, documented the production tag as
  `v1.0.0`, and pointed to a helper script outside this repository. `Dockerfile.local`
  covers the same case: building against a local vericto-engine checkout.

### Fixed

- **A rule suggestion longer than 2048 bytes no longer loses a whole telemetry
  batch.** The ingest schema caps `violations[].suggested_safe_query` at 2048, and the
  proxy sent the suggestion uncut. One long suggestion failed validation, the API
  rejected the batch with a 400, and the reporter dropped every event in it as a
  permanent failure. Suggestions are now cut to 2048 bytes and marked. A VERICTO-085
  suggestion that repeats the rewritten query is not sent at all, since the event
  already carries that query.

- **`VERICTO_MAX_QUERY_BYTES` and `VERICTO_HEALTHZ_PORT` are documented.** The proxy
  reads both, but neither `README.md` nor `.env.example` mentioned them. The README now
  gives the size limit's default, clamping and monitor-mode behaviour, and explains when
  the health-check port opens and what a probe checks.
- `Dockerfile.local` no longer points to a helper script that is not in this
  repository.
- **`PROXY_TLS_MODE=require` refuses plaintext PostgreSQL clients.** A client that
  skipped `SSLRequest` and sent its StartupMessage in plaintext (`sslmode=disable`)
  was accepted and relayed to the database unencrypted. It now gets a native
  `ErrorResponse` with SQLSTATE 28000 and the connection closes before any upstream
  connection is opened, as the MySQL path already did. With `PROXY_TLS_MODE=disable`
  nothing changes.
- **Parser messages reach the control plane.** Telemetry sent the parser's message
  as `parse_error`, but `/ingest/events` reads `parse_error_message` and dropped the
  unknown key, so a PARSE_ERROR event never carried its message. The field now goes
  out as `parse_error_message`, cut to the API's 2048-byte cap so a long message
  cannot get the whole batch rejected. Disk-spooled events written by an older build
  still read back.

## [4.5.1] — 2026-10-05

Build, packaging and documentation changes, made as the repository goes public.
Nothing changes in what the proxy blocks or forwards. The only source change is a doc
comment, and the engine update is documentation and CI only. Upgrading needs no
configuration change.

### Changed

- **Builds no longer need a GitHub token.** vericto-engine is public, so CI and the
  release image fetch it anonymously. Nothing reads the `GH_PAT_PRIVATE_REPOS` secret
  any more: the credential-rewrite step in CI, the BuildKit `github_token` secret in
  the release workflow and the three `RUN --mount=type=secret` wrappers in the
  Dockerfile are gone, and so is `CARGO_NET_GIT_FETCH_WITH_CLI`, which only existed so
  cargo would honor that rewrite. `docker build .` works on a fresh clone with no
  secrets.
- **GitHub Actions are pinned to commit SHAs**, with the release in a trailing comment,
  and Dependabot proposes updates to them weekly.
- **Adopts `vericto-engine` v3.5.3** (from v3.5.2), the engine's latest release.
  Upstream it is documentation and CI only: a `NOTICE`, a corrected security policy
  and test names. The library code the proxy compiles is unchanged, with no API,
  behaviour or rule change, so the proxy blocks exactly what it did. `pg_query` stays
  on 6.2, the version the engine uses.

### Added

- **The image ships its license files.** `LICENSE`, `NOTICE` and a generated
  `THIRD_PARTY_LICENSES` are in `/usr/share/doc/vericto-proxy/`; until now the image
  held only the binary. The Elastic License 2.0 requires that anyone who receives
  the software also receives its terms, and the licenses of the dependencies require
  their notices to go with binary copies. `THIRD_PARTY_LICENSES` is written during
  the image build by `cargo-about` 0.9.2 from `Cargo.lock`, so it always matches
  what was compiled. It covers the crates that ship for the image's Linux targets,
  excluding build and dev dependencies. `third-party/pg_query-bundled.txt` adds the
  C code `pg_query` links in, which cargo-about cannot see: libpg_query, the
  PostgreSQL parser sources, protobuf-c and xxHash. A dependency under a license
  that is not in `third-party/about.toml`'s `accepted` list fails the build, and so
  does a `pg_query` version that file does not describe.
- `NOTICE`, naming the licensor (Vericto S.A.S.).
- GitHub private vulnerability reporting as a second channel in `SECURITY.md`.

### Removed

- **Seven dependencies nothing used.** `tower`, `tower-http`, `serde_yaml`,
  `thiserror`, `anyhow` and `once_cell` had no references left in `src/`, and neither
  did the dev-dependency `tokio-test`. `axum`, `tower` and `tower-http` were listed
  under a comment describing an HTTP evaluation endpoint that the proxy no longer
  serves. `axum` moves to `[dev-dependencies]`: its only remaining use is the test
  double for the control-plane API in the rules-sync tests, so it is no longer
  compiled into the release binary.

### Fixed

- **The image's `org.opencontainers.image.licenses` label read `NOASSERTION`.** The
  release workflow declared `Elastic-2.0` (with the title and description labels) in
  the merge job. That job only stitches the per-architecture images into a manifest
  list and never applies labels. So the label came from metadata-action's default,
  GitHub's license detection, which does not recognise ELv2. The three labels now
  sit on the build job's metadata step, the one whose labels reach the image.
- **Documentation that no longer matched the code.**
  - `.env.example` still used the per-engine names removed in 3.0.0
    (`UPSTREAM_PG_HOST`, `PROXY_PG_LISTEN_PORT`, `UPSTREAM_PG_SSLMODE`, …). The proxy
    ignores them, so a deployment configured from that file had no `UPSTREAM_HOST`
    and exited at startup. The file also described an HTTP evaluation endpoint the
    proxy does not have.
  - The README listed `SELECT *` without `WHERE`, `SELECT` without `LIMIT` and
    `INSERT` without a column list as blocked. The built-in ruleset flags or monitors
    them and forwards the query.
  - The README and the crate docs said every query is decided in under 2 ms.
    Evaluation time grows with query size: about 22 ms for a 64 KB `INSERT`, per the
    measurements in `src/tcp/query_limit.rs`.
  - `SECURITY.md` said the engine enforces a 64 KB query limit. The size limit the
    proxy applies is `VERICTO_MAX_QUERY_BYTES` (10 MiB by default); the engine's own
    guards are its 200-level nesting and 50-level AST depth limits.
  - `CONTRIBUTING.md` described this repository as the AST engine and sent rule work
    to files that live in vericto-engine.
  - Links: the rule list points at `vericto.com/rules-reference` (`/rules` returned
    404), the Oracle/SQL Server note at the public HTTP API guide instead of a private
    repository, and the commercial-license contact is `enterprise@vericto.com`.

## [4.5.0] — 2026-10-04

### Added

- **The last-good ruleset survives a restart.** The proxy already kept enforcing the
  last synced ruleset and policy while the control plane was down, but only in memory:
  a restart during the outage came back with the built-in critical rules alone. The
  workspace's custom rules were gone, and so was its policy (severity actions, monitor
  mode, sanitized telemetry), until the control plane returned. A rolling deploy, an
  OOM kill or a node drain during an API incident was enough to trigger it.

  Each accepted `/sync/rules` response is now written to disk, and the syncer loads it
  before its first request. The copy is the response body as received, plus its ETag,
  which goes on that first request: an unchanged ruleset still costs one 304. It is
  written only after the response parsed and was applied, to a temporary file renamed
  into place (a crash mid-write leaves the previous copy), with mode `0600`.

  A copy is only reused by the link that wrote it: it records the API URL, the
  database id and a SHA-256 fingerprint of the API key — never the key. A proxy pointed
  at another workspace or database ignores the old file rather than enforcing someone
  else's rules until its first sync. A missing, corrupt or foreign file is logged and
  ignored; startup never depends on it.

  On by default with `VERICTO_TELEMETRY_BUFFER=disk`, at `<spool dir>/.rules-cache`:
  that buffer already means a durable volume is mounted there, and the image's
  non-root user cannot write anywhere else under `/var/lib`. The name is hidden and has
  no `.json` extension, so the spool never reads it as an event. Off by default with
  the memory buffer, where there may be no writable volume at all.
  `VERICTO_RULES_CACHE_PATH` sets another path, or turns it off when empty.

## [4.4.2] — 2026-10-04

### Security

- **rustls 0.23.40 → 0.23.45 (RUSTSEC-2026-0285).** rustls accepted TLS 1.3
  handshake messages across encryption-level boundaries. The proxy uses rustls for
  the upstream connection to the database (`UPSTREAM_PG_SSLMODE=require` /
  `verify-full`) and for its control-plane calls, so this is a dependency-only
  update with no behaviour change.
- **quinn-proto 0.11.14 → 0.11.19 (RUSTSEC-2026-0185).** Remote memory exhaustion
  from unbounded out-of-order stream reassembly. Listed in `Cargo.lock` but not
  compiled into the proxy (no target pulls in HTTP/3/QUIC); updated so the lockfile
  carries no known advisory.

Found by the 2026-10-04 vulnerability review (`cargo audit`); `cargo audit` now
reports no vulnerabilities, only the existing warnings for `rustls-pemfile`
(unmaintained) and `anyhow` (`downcast_mut` unsoundness, not used).

## [4.4.1] — 2026-10-01

### Fixed

- **`VERICTO_TELEMETRY_BUFFER=disk` never delivered an event that violated no rule,
  and one such event was enough to block the whole spool.** `TelemetryEvent` did not
  round-trip through its own serializer: `violations` carried
  `skip_serializing_if = "Vec::is_empty"` without `serde(default)`, so the key is
  omitted for an ALLOWED event and deserialization then fails with
  `missing field "violations"`. Memory mode never noticed because it never serializes —
  disk mode is the only path that reads back what it wrote.

  The blast radius is much larger than those events, because `DiskQueue::drain_batch`
  skipped an unparseable file *without removing it*. The spool drains oldest-first, so
  the first unreadable event parks at the head of the queue and every later tick
  re-reads it. Once unreadable files fill a whole `drain_batch` window
  (`VERICTO_TELEMETRY_BATCH_SIZE`, default 100) the batch comes back empty and the
  reporter stops on `if batch.events.is_empty() { break }`, so reporting stays silent
  until the file is removed. The deserialize error was discarded rather than logged, and
  restarting did not clear it: the spool is durable by design, so the file outlives the
  process.

  Measured on a staging deployment: 536 events stranded on EFS behind 283 unreadable
  ones, the oldest nine hours old, while the proxy kept evaluating and blocking
  correctly and `rules_sync` kept answering 304 — the data path was unaffected
  throughout, only reporting stopped. Reproduced locally on both wire protocols: the
  previous build delivered the 2 events of 12 that carried a violation and left the
  other 10 in the spool, while this one delivers all 12 and empties it. Swapping the
  image on an already stranded spool drained it with no new traffic, so an existing
  backlog recovers on deploy.

  Three changes: `serde(default)` on `violations`; `drain_batch` now logs and discards
  a file it cannot read, because losing one event is strictly better than losing every
  event behind it; and `push` writes to a temporary name and renames into place, so a
  task dying mid-write cannot leave a truncated file that reintroduces the same wedge
  by another route. Five tests cover the queue, which had none.

- **The image's `HEALTHCHECK` now probes the health port over TCP.** It previously ran
  `curl -fsS "http://localhost:${PROXY_EVAL_PORT}/health"`. The health listener binds
  `VERICTO_HEALTHZ_PORT` and is a plain TCP accept-and-close that exchanges no bytes
  (`src/tcp/healthz.rs`), so an HTTP GET against a different variable could not
  succeed and a container run directly from the image stayed `unhealthy` while the
  proxy served traffic normally.

  Both deployments already probe it correctly and never relied on this directive:
  `docker-compose.yml` defines its own TCP check and ECS uses the NLB target group with
  `HealthCheckProtocol: TCP`. Matching them here makes the image accurate on its own.
  With `VERICTO_HEALTHZ_PORT` unset the container reports healthy, since the listener is
  opt-in and the absence of an optional port is not a failure.

### Removed

- **`PROXY_EVAL_PORT`, `EXPOSE 5434` and the `curl` package from the runtime image.**
  The variable is a leftover from when evaluation was an HTTP call to a sidecar; the
  engine has run in-process since, and the name appears nowhere in the source — the
  proxy never listened on 5434. `curl` was installed solely for the healthcheck that
  no longer needs it, so the runtime image carries one less package.

## [4.4.0] — 2026-09-30

### Added

- **`PROXY_TLS_CERT` and `PROXY_TLS_KEY` now accept inline PEM, not only a path.**
  Anything whose first non-whitespace characters are `-----BEGIN` is read as the
  material itself; everything else is still read from disk, byte for byte as before,
  so an existing deployment passing `/etc/vericto/server.crt` is unaffected.

  This exists to get the private key out of the container image. ECS, Kubernetes and
  most orchestrators inject secrets as **environment variables**, not as files, so a
  path-only contract left one option: bake the key into the image. That is what the
  first deployment of this proxy did — a `-tls` image variant with
  `COPY proxy-key.pem` in it, sitting in a registry. Anyone with pull access could
  read it (two commands: `docker create`, `docker cp`), it survives in the layer
  history after the tag is gone, and rotating it means rebuilding and redeploying.
  With inline PEM the same deployment references a secret ARN and the key never
  reaches an image at all.

  **A failing load never echoes inline material.** When the key arrives inline, the
  value *is* the key, so a diagnostic that printed its argument would write a private
  key into the logs — trading one exposure for a worse one. `describe_source` reports
  the path verbatim when it is a path, and the fixed string `the inline PEM value`
  when it is not. Two tests pin this on the two error branches that can be reached
  with inline material, and both use the realistic trigger: the cert and the key
  swapped between the two variables. The test bodies are valid base64 on purpose —
  with invalid base64, rustls fails at decode and its own error propagates before
  reaching the branch under test, so the test would pass without proving anything.

## [4.3.3] — 2026-09-30

### Changed

- **Adopts `vericto-engine` v3.5.2** (from v3.5.0). No code change here, and no API
  change in the engine — but this one does change what the proxy blocks, which is why
  it gets its own release rather than riding along with the next feature.

  v3.5.2 fixes VERICTO-019 not detecting `ALTER TABLE … DISABLE ROW LEVEL SECURITY`
  on PostgreSQL. The engine's `pg_ast.rs` mapped only the three `DISABLE TRIGGER`
  subtypes, so `AtDisableRowSecurity` fell through and no `StatementInfo` was emitted
  at all — the statement was invisible to the whole evaluator, not merely unmatched by
  one rule. The sqlparser walker had always mapped it, so MySQL, Oracle and SQL Server
  detected what PostgreSQL did not, and PostgreSQL is the only dialect that implements
  RLS.

  Verified against this binary built from this tree, running inline in front of a real
  PostgreSQL: `DISABLE ROW LEVEL SECURITY` is rejected with VERICTO-019 where it
  previously returned ALLOWED with no rule attributed, `DISABLE TRIGGER ALL` still
  blocks, and `ENABLE ROW LEVEL SECURITY`, `ENABLE TRIGGER ALL` and `ADD COLUMN` still
  pass — widening detection must not start refusing the statements that add protection
  or the ordinary ones, because inline a false positive is an outage.

  **Operators should know this before deploying:** a migration running
  `ALTER TABLE … DISABLE ROW LEVEL SECURITY` against a workspace with VERICTO-019
  active goes from passing to blocked. The blast radius is bounded by the rule's class
  — VERICTO-019 is `SchemaMigration`, so a channel passing `schema_migration_cap:
  Some(Flag)` reports instead of blocking — and by the workspace catalogue, which
  decides whether the rule is active at all.

  Checked the two invariants this component cares about, as in 4.3.2: `pg_query` still
  resolves to a single copy in the lock file (6.2.0, so the statically-linked
  `libpg_query` is not duplicated), and `default_ruleset()` still mirrors the engine
  catalogue at 28 codes.

## [4.3.2] — 2026-08-10

### Changed

- **Adopts `vericto-engine` v3.5.0** (from v3.4.0). No code change and no
  behaviour change on the wire: v3.5.0 only *adds* `EvaluationOutcome::violations`,
  and every field this proxy reads keeps the same value for the same input.
  The pin is moved now rather than later so the two first-party hosts do not drift
  again — `vericto-eval` adopted v3.5.0 in 2.1.5, and leaving this one behind is
  how the stack ended up three releases out of step before.
  This proxy does not consume the new field yet. It could: reporting every
  violation in telemetry instead of only the winner is exactly the evidence gap
  v3.5.0 closes. But `TelemetryEvent` and the API's `/ingest/events` schema carry
  one rule per event, so that needs the backend's `query_event_violations` table
  first. Deliberately left for its own change rather than half-done here.
  Checked the two invariants this component cares about: `pg_query` still resolves
  to a single copy in the lock file (so the statically-linked `libpg_query` is not
  duplicated), and `default_ruleset()` still mirrors the engine catalogue.

## [4.3.1] — 2026-08-09

### Changed

- **Adopts `vericto-engine` v3.4.0** (from v3.2.4, three behaviour releases back).
  No code change here, but the proxy links the engine in-process, so what it
  blocks on the wire changes with it:
  - **Constant-only tautologies count as always-true** (engine 3.3.0). A statement
    whose only `WHERE` is `1 IN (1,2)`, `1 BETWEEN 0 AND 2` or `'x' LIKE '%'` is
    now refused with the native protocol error instead of being forwarded. This is
    the one change that rejects traffic the proxy previously passed, which is why
    the rollout puts workspaces into a timed observe window first — while that
    window is active the control plane sends `monitor_mode`, so these degrade to
    FLAG and are reported rather than blocked.
  - **A bounded set operation is no longer reported as unbounded** (engine 3.3.1).
    `SELECT … UNION SELECT … LIMIT 10` stops tripping VERICTO-050 on PostgreSQL,
    matching what the other dialects already did.
  - **A custom rule's `func_name:` predicate reaches any function** (engine 3.4.0),
    so a workspace rule naming `pg_read_file` or `dblink` fires where it silently
    did nothing before. VERICTO-070 still only fires on the sleep family.
  - `ParsedQuery::statements` is longer for queries containing ordinary functions,
    since every call is now recorded. Evaluation is linear in that count and the
    rule predicates short-circuit on `kind`; the wire path is unaffected in shape.
  `pg_query` still resolves to a single copy in the lock file, so the
  statically-linked `libpg_query` is not duplicated — the invariant the manifest
  calls out next to that dependency.

## [4.3.0] — 2026-08-08

Read before rolling out: this release **can reject queries that previously
reached the database**. Minor rather than patch for that reason.

### Added

- **`VERICTO_MAX_QUERY_BYTES` — an admission limit on the size of a query the
  proxy will evaluate.** Default **10 MiB**. A statement over the limit is
  refused with rule code `VERICTO-QUERY-TOO-LARGE` before being parsed, so a
  refused query costs neither the evaluation parse nor the telemetry sanitize
  pass.

  Why a limit at all: evaluation runs inline before the query reaches the
  database, and its cost is linear in input size. Measured on `pg_query` 6.2 with
  a wide `INSERT … VALUES` — the shape `MAX_AST_DEPTH` does not bound, since it
  limits nesting depth and not breadth:

  | size | evaluate | + sanitize | total |
  | --- | --- | --- | --- |
  | 64 KB | 20 ms | 1.7 ms | 22 ms |
  | 1 MB | 335 ms | 28 ms | 363 ms |
  | 4 MB | 1313 ms | 122 ms | 1435 ms |
  | 10 MB | 3440 ms | 382 ms | 3822 ms |

  About 0.35 ms/KB. Postgres framing accepts 64 MiB, which extrapolates to some
  23 s for a single statement. The default caps that at about 3.8 s.

  The default errs high on purpose. The statements that legitimately get large are
  batch inserts and long `IN` lists — 100 000 UUIDs is roughly 3.8 MB, a 5 000-row
  insert across 20 columns roughly 2 MB — and rejecting a customer's ETL is a
  worse outcome than evaluating it slowly.

  **The maximum is per wire protocol**, anchored to the codec's own framing cap
  rather than to a number of our choosing: 64 MiB on Postgres, 16 MiB − 1 on
  MySQL, whose protocol caps a packet there and which this proxy does not
  reassemble across packets. A configured value above the cap is clamped with a
  warning, since beyond it the codec already refuses the message. An unparseable
  or zero value falls back to the default, also with a warning.

  **`monitor_mode` is honoured**: a workspace in dry-run forwards the query
  unevaluated instead of rejecting it. The engine documents `monitor_mode` as
  forcing every blocking action to a non-blocking one and holds it under a
  property test asserting it never *increases* blocking — a size rejection there
  would be the one thing that blocks in a dry-run deployment. It is forwarded
  *unevaluated* because nothing could be enforced on the result, so paying seconds
  of CPU for an unactionable finding buys nothing.

  Refusal is deliberately not fail-open. Forwarding an unevaluated query would
  create a rule bypass that does not exist today: padding a statement past the
  limit would carry it to the database unexamined.

### Changed

- **CI now runs on pull requests that do not target `main`, and can be triggered
  manually.** The `pull_request` trigger filtered on `branches: [main]`, so a
  stacked PR — one based on another open branch — reported no checks at all and
  could be merged unverified; found by this release's own stacked PR, which came up
  with zero checks. And with no `workflow_dispatch`, re-running CI on a branch
  required pushing a commit — the hole we fell into during the GitHub Actions
  outage on 2026-08-06, when runs sat orphaned in `queued` and could be neither
  cancelled nor re-run. `push` is still restricted to `main`.
- **Evaluation and telemetry reporting now run on the blocking pool.** Both are
  CPU-bound and synchronous; on the async reactor they stall the worker thread and
  freeze every other connection scheduled on it, turning a per-connection cost
  into a multi-tenant one. The measured hop cost is ~7 µs (9.9 µs inline versus
  16.9 µs offloaded for a small query), negligible next to a database round trip,
  so the offload is unconditional rather than gated on size.
  Telemetry moves with evaluation because `sanitize_query` calls
  `pg_query::normalize`, which parses again — leaving it behind would keep about
  11% of the cost on the reactor.

## [4.2.2] — 2026-08-08

### Fixed

- **A single large query could stall all telemetry delivery.** `query_text` was
  reported in full, so any query over the API's ingest limits produced a batch the
  API refuses: 400 when a field exceeds the schema's 65 536, 413 when the batch
  exceeds the 1 MiB body limit. The reporter treated every non-2xx as retryable
  and `nack`ed the batch, which re-buffers at the *front* of the queue, then broke
  out of the drain loop. The rejected batch therefore sat at the head being
  re-sent once per flush tick, blocking every event behind it until the ring
  buffer churned past it.
  Two changes, either of which alone would leave a gap:
  - `query_text` is now truncated to 8 KiB when the event is built, with a visible
    marker. Applied at build time rather than at send time because the queue holds
    up to `memory_capacity` (10 000) events and the disk spool writes each one to
    a file — an unbounded field is a memory and disk problem before it is an HTTP
    one. The cut lands on a UTF-8 character boundary, since SQL carries arbitrary
    UTF-8 in identifiers, literals and comments.
  - The reporter now distinguishes permanent from retryable failures. 400, 413 and
    422 are properties of the bytes, so the batch is dropped (logged at `error`
    with the status and event count) instead of retried forever. Everything else
    still retries, including 401/403: a rotated or mistyped API key is an operator
    misconfiguration that is fixable without redeploying, so discarding telemetry
    over it would turn a recoverable mistake into silent data loss.

  The 8 KiB figure is derived, not picked: at the default `batch_size` of 100, the
  schema's own 65 536 would produce a ~6.5 MiB body, six times the API's limit.
  8 KiB keeps a full default batch near 800 KiB with room for the rest of each
  event and for JSON escaping. A compile-time assertion pins the arithmetic, so
  raising the limit past what the batch budget allows fails the build.

## [4.2.1] — 2026-08-08

### Changed

- **`vericto-engine` v3.2.3 → v3.2.4.** Equal-severity ties are now broken on the
  rule code instead of on the order the ruleset happens to arrive in. Previously
  the first matching rule in the synced slice won, and the control plane serves
  its ruleset from a query with no `ORDER BY`, so the same query could be reported
  under different codes between runs.
  **Nothing changes about what this proxy blocks.** Tied rules share a severity,
  so the resolved action is identical either way — a query that was blocked stays
  blocked, and one that passed still passes. What changes is the `rule_code`,
  `rule_id` and `ast_node_path` attached to the finding and to the native error
  returned to the client, which now stay stable across rule syncs.
  Unlike 4.2.0, this release is safe to deploy without auditing workloads.

## [4.2.0] — 2026-08-06

Read before rolling out: this release **blocks traffic it previously allowed**.
Minor rather than patch for that reason, even though no API or config changed.

### Changed

- **`vericto-engine` v3.2.1 → v3.2.3. VERICTO-070 now fires on `pg_sleep_until`
  for MySQL, Oracle and MS SQL**, and this proxy's default ruleset sets that rule
  to `Block` (`tcp/evaluator.rs`), so those queries are now **rejected at the
  wire** where they previously passed through.
  The engine kept its sleep-function list in two walkers and only the PostgreSQL
  one carried that name, so a time-based blind-injection probe using
  `pg_sleep_until` was blocked on PostgreSQL and silently forwarded on every other
  dialect. Closing that gap is the point of the release — but `pg_sleep_until` is
  a PostgreSQL function, so on a MySQL, Oracle or MS SQL upstream it would not
  have executed anyway. If a legitimate workload sends that identifier to a
  non-PostgreSQL database, it will now be refused.
  The rest of v3.2.2 and all of v3.2.3 are internal to the engine: a corrected
  dependency snippet in its docs with a guard test, removal of its unused
  `anyhow`/`tokio-test` dependencies, and removal of its CI cache step. No
  config, env-var, or wire-protocol change here.

## [4.1.0] — 2026-08-06

First release since 4.0.1. The versions 4.0.2 and 4.0.3 were bumped in
`Cargo.toml` but never tagged, so no image was ever published for them and they
are not releases; their contents ship here. Everything below is the accumulated
delta over 4.0.1.

### Added

- **Dedicated TCP health-check listener with a readiness gate**
  (`tcp/healthz.rs`), opt-in via `VERICTO_HEALTHZ_PORT` and disabled by default.
  Kept separate from the wire-protocol traffic port because MySQL's handshake is
  server-first: the proxy must connect upstream the moment it accepts, so a TCP
  probe on the traffic port would open and immediately discard a real database
  connection on every check. The `healthz` port answers probes without touching
  the upstream, and behaves identically for Postgres and MySQL.
  Readiness is gated by *not binding* the port until warm-up completes, because
  a TCP check succeeds as soon as the port is listening — before user space ever
  calls `accept()` — so declining to accept would not read as unhealthy. During
  warm-up probes get connection-refused; afterwards the port binds and accepts.
  Readiness flips after the first rule-sync *attempt*, whether it succeeded or
  failed, so a control-plane outage never pulls the proxy out of rotation. The
  check deliberately never probes the upstream database, so a database blip
  cannot cascade into every instance being pulled from rotation.

### Fixed

- **Adopt `vericto-engine v3.2.0`** (git dependency bumped from `v3.1.1`),
  picking up the VERICTO-010 false-positive fix: `DROP POLICY`, `DROP TRIGGER`,
  `DROP FUNCTION`, `DROP VIEW`, and `DROP SEQUENCE` are no longer flagged as a
  critical `DROP TABLE` at runtime. Schema/DDL detection now matches only
  `DROP TABLE`/`DROP DATABASE` (VERICTO-010); `DROP INDEX`/`DROP SCHEMA` keep
  their own rules (013 / 012).

  The runtime proxy keeps the full workspace policy (it does not set the new
  `schema_migration_cap`), so a genuine `DROP TABLE`/`DROP DATABASE` against a
  live database still blocks — only the mis-classified non-table drops stop
  firing.
- **Telemetry reported `dialect: "postgres"` for every evaluation**, including
  from a proxy fronting MySQL, because `build_telemetry_event` hardcoded the
  label. Rule evaluation itself was already dialect-correct — the session has
  always passed `proto.dialect()` into `evaluate()` — so only the reported label
  was wrong, and the control plane stores the dialect as reported. The dialect is
  now threaded from that same source of truth through `report_telemetry` into
  `build_telemetry_event`. Any MySQL evaluation recorded before this fix is
  mislabelled at rest in the control plane.
- **Adopt `vericto-engine v3.2.1`** (git dependency bumped from `v3.2.0`),
  picking up the VERICTO-040 false-positive fix. The engine flagged any
  `INSERT … SELECT` without checking whether the source was filtered, so
  `INSERT INTO t SELECT … WHERE id = $1` was reported — and **rejected at the
  wire, since this proxy's default ruleset sets VERICTO-040 to Block**. That
  made parameterised backfills fail against a live connection. The rule now
  fires only when the source has no effective `WHERE` and no row limit;
  `WHERE 1=1` bounds nothing and still fires.

### Changed

- **`pg_query` 5.1 → 6.2**, bumped in the same commit as the engine tag above
  and not separately. Both crates statically link `libpg_query`, so a
  major-version split between them would compile and link two copies of it.
  The engine moved to `pg_query` 6.2 in v3.2.1, so this line has to follow.
  Vendored PostgreSQL goes 16.1 → 17.7. The only call site here is
  `pg_query::normalize` in `tcp/postgres.rs`, whose signature is unchanged.
- **Custom-rule predicate `where_always_true` now matches more queries.** It
  previously only matched an always-true *OR branch* (`WHERE id = 5 OR 1=1`);
  it now also matches a WHERE that is trivially true as a whole (`WHERE 1=1`,
  `WHERE true`). A custom rule using that predicate may start blocking traffic
  it previously let through. Nothing that matched before stops matching.

## [4.0.1] — 2026-07-29

Maintenance release: no API, config, or behaviour changes.

### Changed

- **Adopt `vericto-engine v3.1.1`** (git dependency bumped from `v3.0.0`). Brings
  the full custom-rule predicate schema (nested `condition:` block, `FuncCall`
  node type, 8 predicates) into the in-process evaluation path. The proxy passes
  `ast_condition_yaml` straight through, so no code changes were needed.
- **Migrated to Rust edition 2024** (`edition = "2021"` → `"2024"`). Toolchain is
  already pinned to 1.88, which supports it; no source changes were required.
- Updated repository URL and README links to `vericto/…` to reflect the
  repository transfer.

## [4.0.0] — 2026-07-16

Rebrand from **Vetro** to **Vericto**. Breaking release: environment variables,
the crate/container image, rule codes, and the contact domain were renamed, and
the service now targets the rebranded engine.

### Changed (breaking)

- **Environment variables renamed** `VETRO_*` → `VERICTO_*` (e.g.
  `VETRO_API_KEY` → `VERICTO_API_KEY`, `VETRO_DATABASE_ID`,
  `VETRO_WIRE_PROTOCOL`, `VETRO_TELEMETRY_*`, …). Deployments and the control
  plane that set these must migrate.
- **Renamed** crate and container image `vetro-proxy` → `vericto-proxy`.
- **Adopt `vericto-engine v3.0.0`** (git dependency updated to the renamed
  `vericto-engine` repository at tag `v3.0.0`); imports updated to
  `vericto_engine::…`.
- **Rule codes** referenced in code, tests and docs renamed `VETRO-NNN` →
  `VERICTO-NNN` to match the engine.
- **Contact domain** updated `vetro.dev` → `vericto.com`.

### Notes

- No change to the TCP wire-proxy behaviour; only naming and identifiers.
- Historical entries below were rewritten to the `vericto-*` / `VERICTO-*`
  names for readability; they were originally published under `vetro-*`.

## [3.0.0] — 2026-07-08

### Changed (breaking)

- **Dialect-agnostic environment variables.** The upstream/listen configuration
  is no longer prefixed per engine. Rename in every deployment:
  - `UPSTREAM_PG_HOST` / `UPSTREAM_MYSQL_HOST` → `UPSTREAM_HOST`
  - `UPSTREAM_PG_PORT` / `UPSTREAM_MYSQL_PORT` → `UPSTREAM_PORT`
  - `PROXY_PG_LISTEN_PORT` / `PROXY_MYSQL_LISTEN_PORT` → `PROXY_LISTEN_PORT`
  - `UPSTREAM_PG_SSLMODE` / `UPSTREAM_MYSQL_SSLMODE` → `UPSTREAM_SSLMODE`
  - `UPSTREAM_PG_SSLROOTCERT` → `UPSTREAM_SSLROOTCERT`
  - `UPSTREAM_PG_SSLCERT` / `UPSTREAM_PG_SSLKEY` → `UPSTREAM_SSLCERT` / `UPSTREAM_SSLKEY`

  The wire protocol is still selected by `VERICTO_WIRE_PROTOCOL` (`postgres` |
  `mysql`), which now only changes the DEFAULT ports (Postgres 5432/5433, MySQL
  3306/3307) when they are not set explicitly. There is no backward-compatible
  fallback — the old names are ignored.

### Fixed

- **Upstream-failure resilience.** If the upstream ended while the intercept
  loop was blocked reading from the client (e.g. the database dies mid-auth),
  the session used to leak a hung client connection. The relay and intercept are
  now joined so either end tears down the other. During the connection phase the
  proxy also answers a native `ErrorResponse` (`SQLSTATE 08006`) instead of a
  bare closed socket; once bytes are already flowing it falls back to a clean
  close to avoid corrupting the stream.
- **Docker image build.** The production `Dockerfile` produced a stub binary
  (missing `Cargo.toml`/lockfile in the builder stage) and failed the private
  git-dependency fetch (token treated as username, missing
  `CARGO_NET_GIT_FETCH_WITH_CLI`). It now builds the real binary.

## [2.3.0] — 2026-07-07

### Added

- Multi-dialect wire-protocol support via a runtime `WireProtocol` strategy: the
  active protocol is selected at deploy time with `VERICTO_WIRE_PROTOCOL`
  (`postgres` | `mysql`; defaults to `postgres`, so existing deployments are
  unchanged). The session loop — evaluation, telemetry, enforcement — is now
  shared, protocol-agnostic code; each protocol supplies only its framing,
  classification, and native block response.
- **MySQL wire protocol (Phase 1)**: transparent proxy for the MySQL classic
  protocol. Extracts SQL from `COM_QUERY` and `COM_STMT_PREPARE` (including the
  `CLIENT_QUERY_ATTRIBUTES` prefix added by MySQL 8.0.23+), evaluates it with
  `Dialect::Mysql`, and blocks destructive statements with a native `ERR_Packet`
  (`ERROR 1142 … [VERICTO-xxx]`) so the driver sees a SQL error, not a broken
  connection. Configured with `UPSTREAM_MYSQL_HOST`/`PORT` and
  `PROXY_MYSQL_LISTEN_PORT` (default 3307).
- **MySQL TLS on both hops** (client→proxy and proxy→MySQL): the proxy
  participates in the connection-phase handshake as a strict sequential auth
  state machine (matching ProxySQL/MaxScale), terminating client-side TLS and
  re-establishing TLS to the upstream. Both hops must share the "secure
  connection" state or the `caching_sha2_password` scramble mismatches, so
  single-hop TLS is unsupported by design. Enabled with `PROXY_TLS_MODE`/
  `PROXY_TLS_CERT`/`PROXY_TLS_KEY` (client hop) and `UPSTREAM_MYSQL_SSLMODE`
  (upstream hop).
- Surface the dashboard-configured database `dialect` in `/sync/rules`; the
  proxy logs a warning when the deployed `VERICTO_WIRE_PROTOCOL` does not match it.

### Fixed

- CI could not fetch the private `vericto-engine` git dependency on any branch that
  changed `Cargo.lock`: the credential rewrite treated the token as a username
  (headless password prompt) and `~/.cargo/git` was cached with a stale,
  unauthenticated checkout. Use `x-access-token:<token>` and drop `~/.cargo/git`
  from the cache.

## [2.2.0] — 2026-06-27

### Changed

- Bump `vericto-engine` to `v2.1.0`, which closes the rule-coverage gaps
  ENG-001…ENG-010 (8 new rules, plus fixes to LIMIT handling, nested-SELECT
  detection, sleep detection, tautology depth, and DROP DATABASE/SCHEMA).

### Added

- Register the 8 new engine rules in the built-in `default_ruleset()` (and its
  verbatim R13 mirror test): `VERICTO-080`/`VERICTO-081` (Critical — COPY PROGRAM,
  DO block) and `VERICTO-017`/`018`/`019`/`082`/`083`/`084` (High — ALTER TABLE
  DROP CONSTRAINT / ALTER COLUMN TYPE / DISABLE TRIGGER, GRANT/REVOKE, MERGE,
  CREATE TABLE AS). The catalogue now carries 28 rules.

## [1.0.0] — 2025-06

### Added

- Deterministic SQL firewall engine using AST parsing (no AI, no heuristics).
- PostgreSQL parsing via `pg_query` (libpg_query) — full-fidelity protobuf AST,
  including destructive statements nested in data-modifying CTEs.
- MySQL, Oracle, and SQL Server parsing via `sqlparser-rs`.
- 20 built-in rules (VERICTO-001 through VERICTO-090) covering DELETE/UPDATE without
  WHERE, DROP, TRUNCATE, ALTER TABLE, dangerous function calls, and OR-tautology
  SQL injection.
- Custom rules defined as YAML AST conditions.
- HTTP evaluation endpoint (`POST /evaluate`) for CI/CD dry-runs.
- Transparent PostgreSQL TCP wire-protocol proxy (simple + extended protocol);
  destructive queries are blocked with a native `SQLSTATE 42501`.
- Fail-closed behavior: unparseable queries are blocked by default.
- Per-workspace ruleset cache with TTL-based invalidation.
- Optional control-plane link: ruleset hot-sync and telemetry reporting.
- `/health` and `/metrics` (p50/p99 latency) endpoints.

[Unreleased]: https://github.com/vericto/vericto-proxy/compare/v4.7.1...HEAD
[4.7.1]: https://github.com/vericto/vericto-proxy/compare/v4.7.0...v4.7.1
[4.7.0]: https://github.com/vericto/vericto-proxy/compare/v4.6.0...v4.7.0
[4.6.0]: https://github.com/vericto/vericto-proxy/compare/v4.5.1...v4.6.0
[4.5.1]: https://github.com/vericto/vericto-proxy/compare/v4.5.0...v4.5.1
[4.5.0]: https://github.com/vericto/vericto-proxy/compare/v4.4.2...v4.5.0
[4.4.2]: https://github.com/vericto/vericto-proxy/compare/v4.4.1...v4.4.2
[4.4.1]: https://github.com/vericto/vericto-proxy/compare/v4.4.0...v4.4.1
[4.4.0]: https://github.com/vericto/vericto-proxy/compare/v4.3.3...v4.4.0
[4.3.3]: https://github.com/vericto/vericto-proxy/compare/v4.3.0...v4.3.3
[4.3.0]: https://github.com/vericto/vericto-proxy/compare/v4.2.2...v4.3.0
[4.2.2]: https://github.com/vericto/vericto-proxy/compare/v4.2.1...v4.2.2
[4.2.1]: https://github.com/vericto/vericto-proxy/compare/v4.2.0...v4.2.1
[4.2.0]: https://github.com/vericto/vericto-proxy/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/vericto/vericto-proxy/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/vericto/vericto-proxy/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/vericto/vericto-proxy/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/vericto/vericto-proxy/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/vericto/vericto-proxy/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/vericto/vericto-proxy/compare/v1.0.0...v2.2.0
[1.0.0]: https://github.com/vericto/vericto-proxy/releases/tag/v1.0.0
