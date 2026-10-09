# Changelog

All notable changes to vericto-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
