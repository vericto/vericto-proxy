# Configuration reference

Advanced configuration for `vericto-proxy`. The [README](../README.md) covers what
most deployments need: the [required variable](../README.md#required), the
[ports](../README.md#ports), [Docker](../README.md#docker) and
[connection strings](../README.md#connection-strings). Everything here is optional.

All variables are **dialect-agnostic** — the same names apply to every engine.

- [Control-plane link (telemetry + rule sync)](#control-plane-link-telemetry--rule-sync)
  - [Over the monthly quota](#over-the-monthly-quota)
  - [Disk spool size](#disk-spool-size)
  - [Several proxies on one volume](#several-proxies-on-one-volume)
- [TLS (optional)](#tls-optional)
- [Query size limit](#query-size-limit)
- [Health check (optional)](#health-check-optional)
- [Observability](#observability)
  - [Metrics](#metrics)
- [CPU sizing](#cpu-sizing)
- [Engine-specific notes](#engine-specific-notes)
  - [MySQL details](#mysql-details)

## Control-plane link (telemetry + rule sync)

Recommended for production. When `VERICTO_API_URL`, `VERICTO_API_KEY` **and**
`VERICTO_DATABASE_ID` are set, the proxy reports every decision and polls the
active ruleset. Without the link it still protects using the built-in ruleset
(dev / air-gapped), but reports nothing.

If the control plane is unreachable, the proxy keeps enforcing the last ruleset and
policy it synced. With `VERICTO_TELEMETRY_BUFFER=disk` it also keeps a copy of them on
disk (`<spool dir>/.rules-cache`), so a restart during the outage resumes with the
workspace's custom rules and policy instead of only the built-in ruleset. Set
`VERICTO_RULES_CACHE_PATH` to put the copy elsewhere (or enable it with the memory
buffer), or to an empty value to turn it off.

> **All three are needed for telemetry.** Without `VERICTO_DATABASE_ID` no events
> are emitted at all (there is nothing to attribute them to) — even if the API
> URL and key are set. It is also the key the control-plane uses to correlate
> telemetry and resolve per-database rules.

| Variable                          | Default | Description                                      |
|-----------------------------------|---------|--------------------------------------------------|
| `VERICTO_API_URL`                   | —       | e.g. `https://api.vericto.com`. Must be `https://` (the API key travels with every request); `http://` only for a loopback host |
| `VERICTO_ALLOW_INSECURE_API_URL`    | `false` | `true` accepts an `http://` API URL on any host: development stacks only |
| `VERICTO_API_KEY`                   | —       | Workspace API key (`vtro_...`)                   |
| `VERICTO_DATABASE_ID`               | —       | UUID of the database record; enables + correlates telemetry |
| `VERICTO_RULES_SYNC_INTERVAL_SECS`  | `300`   | How often to poll `/sync/rules` (min 30)         |
| `VERICTO_TELEMETRY_BUFFER`          | `memory`| `memory` or `disk` (survives restarts), any case. Any other value fails startup |
| `VERICTO_TELEMETRY_DISK_PATH`       | `/var/lib/vericto/spool` | Spool dir when buffer=disk        |
| `VERICTO_TELEMETRY_SPOOL_SUBDIR`    | — (off) | buffer=disk, several proxies on one volume: spool to `<spool dir>/tasks/<name>/`, `<name>` = `task` (ECS task id, else hostname), `hostname`, or a fixed name. See [Several proxies on one volume](#several-proxies-on-one-volume) |
| `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` | `600` | With `VERICTO_TELEMETRY_SPOOL_SUBDIR`: a proxy's directory whose lease is this old is adopted by a live one (min 120) |
| `VERICTO_RULES_CACHE_PATH`          | `<spool dir>/.rules-cache` with buffer=disk, else off | Last-good ruleset kept for restarts; empty = off |
| `VERICTO_TELEMETRY_MEMORY_CAPACITY` | `10000` | Max undelivered events in the memory ring buffer (oldest dropped past it). With buffer=disk it also bounds the spool's event count when set, as it did up to 4.11 |
| `VERICTO_TELEMETRY_SPOOL_MAX_BYTES` | `1073741824` (1 GiB) | buffer=disk: most bytes of spool files kept on disk; past it the oldest are dropped and counted (min 1 MiB). See [Disk spool size](#disk-spool-size) |
| `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS` | — (bytes only) | buffer=disk: optional event bound on top of the byte bound; unset, `VERICTO_TELEMETRY_MEMORY_CAPACITY` applies if set |
| `VERICTO_TELEMETRY_BATCH_SIZE`      | `500`   | Max events per POST `/ingest/events` (at most 500, the API's limit); this many pending events trigger a send |
| `VERICTO_TELEMETRY_FLUSH_SECS`      | `5`     | Longest the oldest pending event waits before a partial batch is sent (whichever comes first with the batch size) |
| `VERICTO_TELEMETRY_MAX_IN_FLIGHT`   | `4`     | POSTs outstanding at once (1–64)                 |
| `VERICTO_TELEMETRY_GZIP`            | `true`  | gzip request bodies (`Content-Encoding: gzip`); turned off automatically if the API refuses them |
| `VERICTO_TELEMETRY_RETRY_BASE_MS`   | `1000`  | First wait after a retryable delivery failure; doubles per consecutive failure |
| `VERICTO_TELEMETRY_RETRY_MAX_SECS`  | `60`    | Longest wait between delivery retries            |
| `VERICTO_TELEMETRY_QUEUE_CAPACITY`  | `2048`  | buffer=disk: events queued in memory for the spool writer; past it new events are dropped and counted, queries never wait |
| `VERICTO_TELEMETRY_SPOOL_FLUSH_MS`  | `50`    | buffer=disk: longest an event waits before its batch is written and fsynced |
| `VERICTO_TELEMETRY_SPOOL_BATCH_MAX` | `1000`  | buffer=disk: most events per spool file (one write and fsync) |
| `VERICTO_TELEMETRY_SHUTDOWN_TIMEOUT_MS` | `5000` | On SIGTERM/SIGINT: time allowed to write queued events to the spool and deliver what it can before exiting |

Telemetry never holds a statement back. The query path only places the event in
memory; with `buffer=disk` a background writer persists events to the spool in
batches (one file per batch, fsynced), so a slow or network volume such as EFS
adds no latency to queries. An event reaches the disk at most
`VERICTO_TELEMETRY_SPOOL_FLUSH_MS` after its statement ran; a crash (not a
SIGTERM) inside that window loses those events. The proxy logs
`Telemetry pipeline stats` every minute while there is activity: queue depth,
spooled events, dropped events and the batch write time, and the delivery side:
events delivered, requests, retries, events refused permanently, requests in
flight and the last and longest request time.

Delivery (since 4.11.0) sends a batch as soon as `VERICTO_TELEMETRY_BATCH_SIZE`
events are pending, or when the oldest has waited `VERICTO_TELEMETRY_FLUSH_SECS`,
with up to `VERICTO_TELEMETRY_MAX_IN_FLIGHT` requests outstanding. An event leaves
the buffer only when the request that carried it is answered 2xx, whatever order the
answers arrive in; a retryable failure (network, 5xx, 429, 401/403) keeps the batch
for a later attempt with exponential backoff, a 413 splits the batch, and a
payload the API refuses (400, 415, 422) is dropped and logged at `error`.

Since 4.12.0 every rule sync (`GET /api/v1/sync/rules`, every
`VERICTO_RULES_SYNC_INTERVAL_SECS`) also sends the pipeline's counters in the
`X-Vericto-Telemetry-Stats` header, as compact JSON: events enqueued and
delivered, events dropped by cause (`dropped_queue_full`, `evicted_oldest`,
`dropped_permanent`, `write_failures`, and `dropped_quota`, see below), the events
and bytes buffered right now, and whether telemetry is paused for the quota
(`quota_paused`, `quota_resets_at`). The totals are since the process started, under a random `instance_id`
drawn at startup, so the Vericto API can tell new drops from a restart and show
them in the dashboard. No query text, user name or address is in it. An API that
does not know the header ignores it. The header also says how far behind delivery
is: `oldest_undelivered_age_s` (seconds since the oldest event still waiting was
recorded, 0 when none waits), `last_delivery_at` (the last 2xx, `null` before the
first) and `spool_max_bytes` (the spool's bound, 0 with the memory buffer). The
same figures are in [Metrics](#metrics).

### Over the monthly quota

On a plan with a hard monthly query limit the API refuses telemetry past it. Since
4.12.0, when `/ingest/events` answers 429 with `code: "QUOTA_EXCEEDED"` and the
reset time (`error.resets_at` or `Retry-After`), or a rule sync says
`telemetry_quota: "exceeded"`, the proxy **pauses telemetry**: it keeps evaluating
and enforcing every query exactly as before, but sends and retries nothing, and new
events are not buffered (counted as `dropped_quota`, so the spool does not fill
with events the API would refuse). Events buffered before the pause wait. It
resumes when a rule sync says `telemetry_quota: "ok"` (after an upgrade, or in the
new month), at the latest one `VERICTO_RULES_SYNC_INTERVAL_SECS` later, or when the
reset time passes. The log has one WARN when it pauses and one INFO when it
resumes. Any other 429 keeps the retries with backoff.

### Disk spool size

Up to 4.11 the spool held at most 10,000 events (`VERICTO_TELEMETRY_MEMORY_CAPACITY`),
under 7 seconds of an API outage at 1,500 statements per second. Since 4.12.0 it
is bounded by bytes, `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`, default 1 GiB:

- **Event size.** The test `the_default_spool_bound_covers_minutes_of_an_api_outage`
  (`src/tcp/postgres.rs`) evaluates a pgbench-style mix (the staging benchmark's
  traffic) plus statements that break rules, with the built-in ruleset, and
  measures the spool lines exactly as written: **417 bytes per event on average**.
- **Outage covered.** 1 GiB / (417 B × 1,500 events/s) ≈ **28 minutes** of API
  outage before the oldest events are dropped; ~12 minutes if events average
  1 KiB (long statements, several violations). At lower traffic, proportionally
  more.
- **Storage.** 1 GiB is 5% of the 20 GiB of ephemeral storage a Fargate task gets
  by default, and on EFS (elastic, no size to provision) it is about 1 GiB-month
  of standard storage at most. Writing at the rate above is ~0.6 MiB/s.
- **Files.** The spool also keeps at most 100,000 segment files, which bounds the
  proxy's in-memory index (~200 bytes per file) and the directory it lists at
  startup when traffic is so low that every file carries a single event.

Raise the bound for longer outages if the volume has room; lower it on a small
volume. A deployment that set `VERICTO_TELEMETRY_MEMORY_CAPACITY` keeps that
event bound on the spool as well, so set `VERICTO_TELEMETRY_SPOOL_MAX_EVENTS` (or
remove the variable) to let the spool grow to the byte bound. Spool files are
named `seg-<seq>-<count>-<bytes>.jsonl` since 4.12.0; 4.12 reads the files of
earlier versions, but an earlier version ignores 4.12's (they stay on disk,
undelivered), so let the spool drain before a downgrade.

### Several proxies on one volume

A disk spool belongs to one process: it names its files from its own counter,
bounds them by its own `VERICTO_TELEMETRY_SPOOL_MAX_BYTES`, and deletes each one
when the API acknowledges it. Replicas that mount one volume at the same path (an
ECS service with one EFS access point) must not share the directory: each would
send the others' events too, count them against its own bound and evict them.
Set `VERICTO_TELEMETRY_SPOOL_SUBDIR=task` (or `hostname`, or a name per replica):

- Each proxy spools to `<spool dir>/tasks/<name>/` and holds a lease there,
  `.lease`, rewritten every 30 seconds and released on a clean shutdown.
- At startup and every minute a proxy adopts the directories of the others whose
  lease is released or older than `VERICTO_TELEMETRY_SPOOL_ORPHAN_SECS` (default
  10 minutes): it renames each one into its own `adopted/` directory and delivers
  its events first, within its own byte bound. A task that is stopped or replaced
  therefore leaves nothing behind for good. The rename is the claim: it is atomic
  on a local filesystem and on NFSv4 (EFS), so when two proxies race for the same
  directory exactly one gets it, and nobody reads a directory it did not rename.
- Spool files at the top of the shared directory (written before the setting was
  turned on) are claimed the same way, one file at a time.
- The rules cache stays at `<spool dir>/.rules-cache`, shared: every replica syncs
  the same rules and writes the file atomically under its own temporary name.

A proxy that is alive but cannot write its lease for the whole orphan window (its
volume unreachable for ten minutes) can have its directory adopted under it: it
logs an error and continues in a fresh directory, and the adopter delivers what was
moved. The API deduplicates events by id, so a batch in flight at that moment that
is sent twice is stored once. Before a downgrade to a version without the setting,
let the spool drain: older versions do not read `tasks/`.

## TLS (optional)

Encrypts each hop independently. `UPSTREAM_SSLMODE` covers the proxy→database
hop; `PROXY_TLS_MODE` covers the client→proxy hop.

| Variable             | Values / Default | Description                              |
|----------------------|------------------|------------------------------------------|
| `UPSTREAM_SSLMODE`   | `disable` (def) \| `require` \| `verify-ca` \| `verify-full` | TLS to the database, as libpq's `sslmode`: `require` encrypts without verifying the server; `verify-ca` verifies the certificate chain against `UPSTREAM_SSLROOTCERT` but not the hostname; `verify-full` verifies both. Any case; any other value fails startup. `prefer` and `allow` are refused: they connect in plaintext when the server offers no TLS, and the proxy never falls back to plaintext |
| `UPSTREAM_SSLROOTCERT`| —               | CA bundle (PEM) for `verify-ca` (required) and `verify-full` (optional: without it, the public web roots), on Postgres and MySQL. Read at startup: a missing file, or one without a certificate, fails startup |
| `UPSTREAM_SSLCERT` / `UPSTREAM_SSLKEY` | —  | Client cert for upstream mutual TLS, on Postgres and MySQL. Read at startup when `UPSTREAM_SSLMODE` is not `disable`: half a pair, a missing file or one without a certificate/key fails startup |
| `PROXY_TLS_MODE`     | `disable` (def) \| `require` | Terminate client-side TLS. With `require`, a client that does not request TLS is refused (Postgres: SQLSTATE 28000), except a Postgres `CancelRequest`, which libpq sends in plaintext (4.16.1+; see [Postgres details](#postgres-details)). Any case; any other value fails startup |
| `PROXY_TLS_CERT` / `PROXY_TLS_KEY` | —  | Server cert/key presented to clients. Either a **path** to a PEM file or the **PEM contents inline** — inline lets a secrets manager deliver the key, so it never has to be baked into the image |

> **MySQL TLS caveat:** TLS must be on **both** hops or neither — never one. The
> proxy participates in the handshake, and MySQL derives its auth scramble from
> the "secure connection" state, so a plaintext hop paired with a TLS hop breaks
> authentication by protocol design. Set `PROXY_TLS_MODE=require` **and**
> `UPSTREAM_SSLMODE=require` (or `verify-ca` / `verify-full`) together (or
> leave both off). See
> [engine-specific notes](#engine-specific-notes).

## Query size limit

| Variable                  | Default              | Description                                   |
|---------------------------|----------------------|-----------------------------------------------|
| `VERICTO_MAX_QUERY_BYTES` | `10485760` (10 MiB)  | Largest statement the proxy evaluates         |

Evaluation runs before the query reaches the database, and its cost grows with the
statement's size. On the measurements in `src/tcp/query_limit.rs` it takes about
22 ms for 64 KB and 3.8 s for 10 MB. A statement over the limit is refused before it
is parsed, with the same native error as a blocked query and the code
`VERICTO-QUERY-TOO-LARGE`. In `monitor_mode` it is forwarded unevaluated instead.

A value larger than the wire protocol can carry is clamped, with a warning: 64 MiB for
PostgreSQL, 16 MiB − 1 byte for MySQL. A value that is not a positive integer falls
back to the default, also with a warning.

## Business policy rules (preview, off by default)

| Variable               | Default | Description                                                    |
|------------------------|---------|----------------------------------------------------------------|
| `VERICTO_POLICY_RULES` | `off`   | `off`, `observe` or `enforce`, any case. Any other value fails startup |
| `VERICTO_BUNDLE_SIGNING_KEYS` | — (the key embedded for `VERICTO_API_URL`) | 4.16.0+. The public keys a sync bundle may be signed with, as JSON: `[{"key_id": "…", "public_key": "<PEM, or base64 of the 32-byte key>"}]`. Replaces the embedded key. A malformed value fails startup. Read only with policy rules on |
| `VERICTO_BUNDLE_SIGNING_KEYS_FILE` | — | 4.16.0+. A path to a file with the same JSON (a mounted secret or config map). Setting both variables fails startup |

A preview of principal-aware policies (CEL inside the custom-rule YAML, engine
4.4.0), for workspaces the control plane has enabled it for. **With `off` (the
default) nothing below happens**: the rule sync does not announce `cel/1`, nothing
is compiled, the StartupMessage and `SET vericto.*` reach the database as they
come, statements are evaluated exactly as in 4.14.3 and telemetry carries no new
field.

With `observe` or `enforce`:

- **Rule sync.** Every `GET /sync/rules` carries `X-Vericto-Policy-Language: cel/1`.
  The response's `principals` section and its rules are compiled once per sync. A
  malformed `principals` section is ignored (every session is then unmatched); it
  never fails the sync.
- **Signed bundles (4.16.0).** The rule sync applies a response only when its
  `X-Vericto-Bundle-Signature` header verifies: Ed25519 over SHA-256 of
  `vericto-sync-bundle/1\n` followed by the body exactly as received, with the key
  the header's `key-id` names. The keys are public. By default the proxy trusts
  the key the Vericto API at its `VERICTO_API_URL` publishes, embedded in the
  binary (`https://api.vericto.com`: `vericto-production-2026`;
  `https://api-staging.vericto.com`: `vericto-staging-2026`; both readable at
  `GET /api/v1/meta/export-signing-key`). Any other API address trusts no key until
  `VERICTO_BUNDLE_SIGNING_KEYS` or `VERICTO_BUNDLE_SIGNING_KEYS_FILE` lists one,
  and logs a warning at startup.

  A response that is unsigned, malformed, signed by a key id the proxy does not
  trust, or whose signature or digest does not match is **not applied**: the last
  good bundle stays in effect, the rules cache is not rewritten, and its ETag is
  not adopted, so the next poll asks for a full body again. Each refusal logs a
  warning (`alert=bundle_signature_rejected`, with `reason` and `key_id`) and counts
  in `vericto_proxy_bundle_signature_rejected_total{reason}` (see
  [Metrics](#metrics)). The rules cache keeps the signature with the body and is
  verified the same way when it is loaded; a cache that does not verify is ignored.
  With no good bundle yet (a first start, or a cache written by 4.15.x, which has
  no signature), the built-in ruleset stays in effect without the workspace's rules
  or policies, and the proxy still becomes ready: never an unverified bundle, never
  an outage. Verification runs at sync time only, never per statement.

  **Key rotation.** Several keys can be trusted at once. Give the proxies the new
  public key first (a release that embeds both, or the override with both), then
  switch the control plane's active signing key; drop the old key from the proxies
  later. A proxy that does not hold the key a bundle names keeps its last good
  bundle until it does.
- **Principal.** Resolved once per session (again only when a sync changes the
  bundle, or a MySQL COM_CHANGE_USER changes the user) from the database user
  (`db_user`, `db_user_pattern`: medium trust), `application_name` (Postgres) or
  the `program_name` connect attribute (MySQL), and the listener (weak trust). The
  strongest identifying signal wins, `narrow` signals must also match and never
  raise trust, and two principals at the same top trust are ambiguous: the
  session is then `unknown` with `weak` trust. A session nothing matches is
  `unknown`, `weak`. The client address is not used.
- **Session context.** `vericto.ticket` and `vericto.tenant` (1 to 128
  characters) come from the Postgres StartupMessage (`options=-c vericto.ticket=OPS-1`,
  or a `vericto.ticket` parameter), from MySQL connect attributes, or from
  `SET vericto.ticket = 'OPS-1'` sent on its own as a simple query. The proxy
  consumes them: they never reach the database. Each is set once per session: a
  second `SET`, a `RESET` or a `set_config` of it is blocked
  (`VERICTO-SESSION-CONTEXT`), as is any other `vericto.*` name, a `SET LOCAL`, or
  a `SET vericto.*` sent as a prepared statement or together with other
  statements. A startup setting the proxy cannot accept refuses the connection.
  The proxy answers a consumed `SET` itself, with the transaction state the server
  reported last (Postgres ReadyForQuery `I` / `T` / `E`; MySQL status flags
  `SERVER_STATUS_IN_TRANS` and autocommit), so it may be sent inside a
  transaction block. In a failed Postgres transaction block it gets 25P02, as from
  the server, and the value is not taken. Like every reply the proxy writes
  itself, it assumes the client waits for the previous statement's answer.
- **`observe`.** The verdict is the one without policies; what a policy would
  have blocked is reported as `FLAGGED` with the policy's code. When the bundle
  has policies, each statement is evaluated twice (with and without them).
- **`enforce`.** Policies decide with the rest of the rules
  (`evaluate_with_context`); a statement the engine cannot read is blocked when an
  enforced blocking policy may apply to the session.
- **Telemetry.** Each event adds `principal_id`, `principal_type`,
  `principal_trust`, `principal_via`, `application_name`, `policy_bundle_version`,
  `ticket_id` and `session_tenant` (no client address).

## Health check (optional)

| Variable               | Default | Description                                   |
|------------------------|---------|-----------------------------------------------|
| `VERICTO_HEALTHZ_PORT` | — (off) | TCP port for load-balancer health checks      |
| `VERICTO_HEALTHZ_ADDR` | `0.0.0.0` | Address the health-check listener binds (an IP; an invalid value stops the proxy at startup). `vericto-proxy healthcheck` (the image's `HEALTHCHECK`) probes `127.0.0.1` when this is `0.0.0.0`, `::1` when `::`, and this address otherwise |

The listener accepts each connection and closes it without exchanging any bytes, so
a probe is a plain TCP connect. (Since 4.12.0 it closes when the peer does, or after
2 seconds of silence, and answers an HTTP request: `GET /metrics` when enabled, a 404
otherwise.) It is separate from the traffic port and never
contacts the database: a database outage does not take the proxy out of rotation.

It opens only once warm-up is done: at startup without the control-plane link, or
after the first rule-sync attempt (successful or not) with it. Until then probes get
connection refused. The image's `HEALTHCHECK` probes this port when it is set. A
value that is not a valid port number is ignored, and the listener stays off.

`vericto-proxy healthcheck` (4.15.2 and later) is that probe as a command, for the
image, which has no shell: it connects to the listener with a 3-second timeout,
closes, and exits `0` on success, `1` on failure or on a `VERICTO_HEALTHZ_PORT` that
is not a port number, and `0` when the variable is unset or empty (nothing to probe).
Use it in exec form wherever a container health check is declared:

```yaml
# Docker Compose
healthcheck:
  test: ["CMD", "/usr/local/bin/vericto-proxy", "healthcheck"]
```

```json
"healthCheck": { "command": ["CMD", "/usr/local/bin/vericto-proxy", "healthcheck"] }
```

The command reads the same `VERICTO_HEALTHZ_PORT` and `VERICTO_HEALTHZ_ADDR` as the
proxy, so it needs no arguments.

## Observability

| Variable        | Default | Description                                   |
|-----------------|---------|-----------------------------------------------|
| `RUST_LOG`      | `info`  | Log level (`info`, `debug`, `trace`)          |
| `RUST_BACKTRACE`| `0`     | Set to `1` to enable backtraces on panic      |
| `VERICTO_METRICS_PROMETHEUS` | `false` | Serve `GET /metrics` (Prometheus text) on the health-check listener; needs `VERICTO_HEALTHZ_PORT` |
| `VERICTO_METRICS_EMF` | `false` | Write the metrics as one CloudWatch Embedded Metric Format line on stdout per interval |
| `VERICTO_METRICS_EMF_NAMESPACE` | `Vericto/Proxy` | CloudWatch namespace of the EMF line |
| `VERICTO_METRICS_EMF_INTERVAL_SECS` | `60` | Seconds between EMF lines (10–3600) |
| `VERICTO_METRICS_PROXY_NAME` | `vericto-proxy` | The EMF `ProxyName` dimension |
| `VERICTO_METRICS_EMF_TASK_DIMENSION` | `true` | Also publish under `[ProxyName, TaskId]` (ECS task id, else hostname) |

### Metrics

Since 4.12.0 the telemetry pipeline is also visible locally, in two opt-in forms with
the same figures. All names start with `vericto_proxy_`:

| Metric | Type | Meaning |
|--------|------|---------|
| `vericto_proxy_telemetry_oldest_undelivered_age_seconds` | gauge | Age of the oldest event not yet delivered; 0 when none waits |
| `vericto_proxy_telemetry_seconds_since_last_delivery` | gauge | Seconds without a successful delivery while events wait; 0 when none waits |
| `vericto_proxy_telemetry_last_delivery_timestamp_seconds` | gauge | Unix time of the last 2xx (Prometheus only; 0 before the first) |
| `vericto_proxy_telemetry_spool_bytes` / `_spool_events` | gauge | What is buffered now |
| `vericto_proxy_telemetry_spool_capacity_bytes` / `_spool_used_percent` | gauge | The spool's bound and how full it is (0 with the memory buffer) |
| `vericto_proxy_telemetry_enqueued_total` / `_delivered_total` | counter | Events accepted and delivered since the process started |
| `vericto_proxy_telemetry_dropped_total{cause}` | counter | Dropped events; `cause` is `queue_full`, `evicted`, `permanent`, `write_failure` or `quota` (not recorded while over the monthly quota) |
| `vericto_proxy_telemetry_quota_paused` | gauge | 1 while telemetry is paused for the monthly quota |
| `vericto_proxy_telemetry_requests_in_flight` | gauge | Telemetry requests outstanding |
| `vericto_proxy_info{version,buffer}` / `vericto_proxy_telemetry_enabled` | gauge | Build and buffer; whether the control-plane link is on |
| `vericto_proxy_bundle_signature_verified` | gauge | 4.16.0+, Prometheus only, policy rules on only: 1 once a verified sync bundle is in effect, 0 while the built-in ruleset is |
| `vericto_proxy_bundle_signature_accepted_total` / `_rejected_total{reason}` | counter | Same conditions. Bundles (responses and the rules cache) whose signature verified, and those refused; `reason` is `missing`, `malformed`, `unsupported_scheme`, `digest_mismatch`, `unknown_key_id`, `bad_signature` or `no_trusted_key` |

- **Prometheus**: `VERICTO_METRICS_PROMETHEUS=true` serves `GET /metrics` on the
  health-check listener (`VERICTO_HEALTHZ_PORT`), never on the database port.
- **CloudWatch EMF**: `VERICTO_METRICS_EMF=true` writes one JSON line per
  `VERICTO_METRICS_EMF_INTERVAL_SECS` to stdout; with the `awslogs` log driver
  CloudWatch Logs turns it into metrics in `VERICTO_METRICS_EMF_NAMESPACE`, under the
  dimension sets `[ProxyName]` and `[ProxyName, TaskId]`. Alarm on `[ProxyName]` with
  the `Maximum` statistic (the worst task): task ids change with every deployment.
  Counters are sent as what happened during the interval: `vericto_proxy_telemetry_delivered`,
  `_dropped_queue_full`, `_dropped_evicted`, `_dropped_permanent`,
  `_dropped_write_failure`, `_dropped_quota`, and `_dropped_loss` (every cause but
  the quota). Each `TaskId` series is a custom metric; set
  `VERICTO_METRICS_EMF_TASK_DIMENSION=false` to publish only `[ProxyName]`.

What they never carry: query text, database user names, client addresses, or
workspace, database or API-key ids. The only labels are `cause` (five fixed values),
`version` and `buffer` (one value each per process), so the number of series is
fixed whatever the traffic. The figures are not secret, but they say how busy the
database is: bind the health-check listener to a private address
(`VERICTO_HEALTHZ_ADDR`), keep its port reachable only from the load balancer and
your monitoring, and never expose it to the internet.

## CPU sizing

| Variable | Default | Description |
|----------|---------|-------------|
| `VERICTO_WORKER_THREADS` | from the CPU limit | 4.16.2+. Async worker threads (1–1024; anything else stops the proxy at startup). By default the CPU limit rounded up, at most the CPUs the process may run on: the cgroup CPU quota visible in the container, or the ECS task's `Limits.CPU` from the task metadata endpoint, whichever is lower; without a limit, one per CPU. `TOKIO_WORKER_THREADS` is still honoured when this is unset |

The proxy logs its choice once at startup (`"Runtime sizing"`, with
`worker_threads`, `source`, `cpu_limit` and `available_cpus`).

**Why a limit, not the CPU count.** On ECS Fargate the CPU quota of a task sits on
the task's cgroup, which the container cannot see: a 0.5 vCPU task runs on a host
with 1 or 2 vCPUs, sees no quota, and up to 4.16.1 started one worker per vCPU. With
2 workers on a 0.5 vCPU quota the proxy spent about 25% more CPU per statement
(work moving between threads), reached the quota earlier and was then throttled
for the rest of each 100 ms CFS period, which stalls every connection at once.
Measured at 0.5 vCPU spread over two cores (PostgreSQL pgbench select-only,
extended protocol, TLS on both hops): added p99 0.40 ms with 1 worker against
39 ms with 2 at 4,826 statements/s, and 0.49 ms against a collapse (p50 above
60 ms) at 5,429/s. Since 4.16.2 such a task starts 1 worker.

**Capacity and the knee.** A proxy limited to a fraction of a CPU by a quota keeps
its latency until its average CPU reaches the quota, then each 100 ms period runs
out of CPU before it ends and statements wait for the next one: the p99 goes from
about 1 ms to tens of ms within a few percent of load. Size from CPU per
statement, not from a saturation test with many concurrent connections (that one
batches work and overstates what an evenly spread load can sustain by up to 25%).
Measured on Graviton3 with TLS on both hops, the proxy needs about 85 µs of CPU per
statement for PostgreSQL pgbench select-only (extended protocol) and about 1.5 ms
per sysbench `oltp_read_only` transaction on MySQL (14 statements). Workload
statements that are larger or match more rules cost more; measure yours with the
task's CPU metric against its statement rate.

- **Scale out on CPU at 50–60% of the task's reservation** (ECS
  `CPUUtilization`, a target-tracking policy). Bursts above the average reach the
  quota first; a quota is a hard limit, not a soft one.
- **Inside a Fargate container the throttling is invisible**: `cpu.stat` of the
  container shows no throttled periods because the quota is on the task's cgroup.
  A task at 100% of its reservation in `CPUUtilization` is being throttled.
- **0.5 vCPU tasks** are fine for steady loads well below their capacity. For a
  bursty load, or a tail-latency budget of a few ms at high utilization, use
  **1 vCPU tasks** (twice the headroom per task) or more tasks. Two 0.5 vCPU tasks
  carry about 1.9 times the load of one.
- The CFS period (100 ms) cannot be changed on Fargate; on your own hosts a shorter
  period (`--cpu-period`) shortens each stall but does not raise the capacity.
- Set `VERICTO_WORKER_THREADS` only to override the detection, e.g. on a platform
  that neither exposes the quota nor ECS task metadata.

---

## Engine-specific notes

Only two things differ per engine; everything above is shared.

- **`VERICTO_WIRE_PROTOCOL`** selects the protocol and the default ports (see
  [Ports](../README.md#ports)).
- **Block response** is native to each protocol: Postgres `ErrorResponse`
  (`SQLSTATE 42501`), MySQL `ERR_Packet` (`ERROR 1142`). Either way the driver
  sees a normal SQL error and the connection stays open. The statement never
  reaches the database, so the session's transaction state is the server's:
  the Postgres `ReadyForQuery` after a refusal reports it (`I`, `T` inside a
  transaction block, `E` in a failed one; 4.16.1+, with policy rules off too),
  and a MySQL `ERR_Packet` carries no status flags, so the client keeps those
  of the server's last OK.

### Postgres details

- **Query cancellation** (psql's Ctrl+C, a driver's cancel API such as JDBC's
  `Statement.cancel()`) works through the proxy, also with `PROXY_TLS_MODE=require`
  (4.16.1+). The proxy relays the server's `BackendKeyData` unchanged and
  forwards a `CancelRequest` (in plaintext, or over TLS as libpq 17's
  `PQcancelCreate` sends it) on a new connection to the database, over
  `UPSTREAM_SSLMODE` like any other, only when its process id and secret key are
  those of a session open on **the same proxy process**. Any other cancel is
  dropped without an answer, as the server would. Behind a load balancer with
  more than one proxy replica, a cancel only works when it lands on the replica
  that holds the session (for example, with source-IP affinity).

### MySQL details

- The proxy speaks the MySQL classic protocol: it extracts SQL from `COM_QUERY`
  and `COM_STMT_PREPARE` (including the `CLIENT_QUERY_ATTRIBUTES` prefix MySQL
  8.0.23+ prepends) and evaluates it with the engine's `Mysql` dialect.
- **TLS is both-hops-or-neither** (see the TLS caveat above). For a trusted
  network (sidecar / private subnet) leave both plaintext — the default. A
  plaintext proxy does not offer TLS in its greeting, so a client in the default
  `ssl-mode=PREFERRED` connects in plaintext, as it would to a server without
  TLS; one that requires TLS is refused by the client itself. With
  `PROXY_TLS_MODE=require`, a client that does not ask for TLS gets
  `ERROR 3159 (HY000)`, as from a server with `require_secure_transport`.
- **No protocol compression.** The proxy reads each command as a plain packet,
  so it clears `CLIENT_COMPRESS` and zstd from the greeting and from the
  client's response, and clients see what a server with
  `protocol_compression_algorithms=uncompressed` offers: one that prefers
  compression (`--compress`, a list that includes `uncompressed`, mysql2
  `compress: true`) runs uncompressed; one that allows only `zlib` or `zstd` is
  refused at connect with `ERROR 2066`.
