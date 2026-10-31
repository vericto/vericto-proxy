# MCP Proxy mode: `vericto-proxy mcp`

`vericto-proxy mcp` is an [MCP](https://modelcontextprotocol.io) server that lets an AI
agent (Claude Code, Cursor, Codex, any MCP client) read a PostgreSQL database
**through Vericto**. The agent gets an `execute_sql` tool and no database credential.
Every statement is evaluated against the rules first, and the server runs exactly what
it evaluated, or the policy's own rewrite of it (masked columns, a `LIMIT` bound). What
is checked is what runs.

**No account is needed to try it**: without a control plane the server runs locally on
Vericto's built-in ruleset, the same rules the TCP proxy runs standalone, and reports
nothing anywhere ([Try it without an account](#try-it-without-an-account)). Linked to a
Vericto workspace it applies the workspace's rules instead
([Connect to Vericto](#connect-to-vericto)).

It is the same binary and image as the TCP proxy, in a second mode, and it reuses the
proxy's evaluator, masks, agent-access allowlists, business policies, signed rule sync,
kill switch and telemetry. This release (4.21.0) is **read-only**: `execute_sql` runs
reads only (the "read tier").

> **The guarantee holds only if the agent has no other database credential.** If the
> agent can also read a `DATABASE_URL`, a `~/.pgpass` or the server's secret file, it
> can run SQL around Vericto. The server warns when it sees such a credential in its
> environment (see [Security](#security)).

- [Try it without an account](#try-it-without-an-account)
- [Connect to Vericto](#connect-to-vericto)
- [How it works](#how-it-works)
- [Set up (Streamable HTTP) for a team](#set-up-streamable-http-for-a-team)
- [Tools](#tools)
- [What execute_sql runs](#what-execute_sql-runs)
- [Limits](#limits)
- [Results](#results)
- [Errors and next steps](#errors-and-next-steps)
- [The control plane](#the-control-plane)
- [Security](#security)
- [Configuration reference](#configuration-reference)
- [What is not in this release](#what-is-not-in-this-release)

## Try it without an account

Five minutes, nothing to sign up for: the server runs **locally**, on Vericto's
built-in ruleset.

**1. A dedicated read-only role.** Create a role only this server uses:

```sql
CREATE ROLE vericto_agent_ro LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE shop TO vericto_agent_ro;
GRANT USAGE ON SCHEMA public TO vericto_agent_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO vericto_agent_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO vericto_agent_ro;
```

Supabase, Neon, RDS and Cloud SQL all support such a role. On Supabase use the
Supavisor pooler host (session mode, port 5432, or transaction mode, 6543).

**2. The URL in a file, not in the agent's configuration.**

```bash
mkdir -p ~/.config/vericto && chmod 700 ~/.config/vericto
printf '%s' 'postgres://vericto_agent_ro:…@db.example.com:5432/shop?sslmode=verify-full' \
  > ~/.config/vericto/shop.url
chmod 600 ~/.config/vericto/shop.url
```

TLS is `verify-full` by default for any host that is not loopback; `sslrootcert=` in the
URL (or `UPSTREAM_SSLROOTCERT`) names a CA bundle when the provider's certificate is not
publicly trusted. A database on your own machine (`localhost`, `127.0.0.1`) needs no TLS.

**3. Register the server**, with the published image or a binary built from source.
None of `VERICTO_API_KEY`, `VERICTO_DATABASE_ID` or `VERICTO_API_URL` is set: that is
what makes it local.

With Docker (Docker cannot read a `0600` file owned by your user as the image's own
user, so the container runs as you):

```bash
claude mcp add vericto-db -- \
  docker run -i --rm --user "$(id -u):$(id -g)" \
    -v ~/.config/vericto/shop.url:/run/secrets/db.url:ro \
    vericto/vericto-proxy:4.21.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
```

Cursor (`.cursor/mcp.json`) or any client that takes a command:

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--user", "501:20",
               "-v", "/Users/me/.config/vericto/shop.url:/run/secrets/db.url:ro",
               "vericto/vericto-proxy:4.21.0", "/usr/local/bin/vericto-proxy", "mcp",
               "--database-url-file", "/run/secrets/db.url"]
    }
  }
}
```

From inside the container a database on your own machine is `host.docker.internal`,
which is not loopback: put `?sslmode=disable` in the URL and add
`-e VERICTO_MCP_ALLOW_PLAINTEXT_DB=true` (the traffic stays on your machine), or use a
source build, which reaches `localhost` directly.

From source (`cargo build --release --locked`, see
[CONTRIBUTING.md](../CONTRIBUTING.md#run-from-source)):

```bash
claude mcp add vericto-db -- /path/to/vericto-proxy/target/release/vericto-proxy \
  mcp --database-url-file ~/.config/vericto/shop.url
```

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "/path/to/vericto-proxy/target/release/vericto-proxy",
      "args": ["mcp", "--database-url-file", "/Users/me/.config/vericto/shop.url"]
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vericto-db]
command = "/path/to/vericto-proxy/target/release/vericto-proxy"
args = ["mcp", "--database-url-file", "/Users/me/.config/vericto/shop.url"]
```

In stdio mode stdout carries protocol messages only; every log line goes to stderr,
which MCP clients show in their server log. The process exits when the client closes
stdin. Homebrew and npm packages for a one-line setup are planned; until then use the
image or a source build.

**4. Ask the agent to call `whoami`**, then `describe_schema`. `whoami` reports the local
mode: `control_plane.mode: "none"`, `control_plane.ruleset: "built-in"`,
`control_plane.reporting: false` and the warning `no_control_plane` in
`execution.warnings`.

**What the local mode is:**

- **The rules**: the built-in ruleset (destructive statements, missing `WHERE`, risky
  DDL, data exposure), the rules the TCP proxy runs without a control plane, with the
  default enforcement policy. `check_sql` evaluates with the same rules.
- **The same safety**: the read tier only, the exact-text guarantee, read-only twice,
  the limits, sanitized database errors and TLS `verify-full` are those of a linked
  server; nothing about them depends on an account.
- **Nothing is reported**: no event, heartbeat or rule sync leaves the machine; the
  server talks to your database only.
- **No masks, allowlists, business policies or kill switch.** Without a dashboard there
  is no kill switch to press: to stop the agent, remove the server from the client or
  stop the process.
- **HTTP needs its own tokens**: `--transport http` without a control plane does not
  start unless `VERICTO_MCP_AUTH_TOKENS_FILE` lists at least one bearer token
  ([Streamable HTTP](#set-up-streamable-http-for-a-team)); it is never served
  unauthenticated.

## Connect to Vericto

A Vericto account adds what the local mode does not have: **custom rules**, **business
policies**, **sensitive-column masking** and agent-access allowlists, an **audit** of
every call (Dashboard → Queries), a **kill switch** and the **dashboard** to manage them.
The server then evaluates with the workspace's rules, synced as signed bundles
([The control plane](#the-control-plane)).

Add the control-plane key (`VERICTO_API_KEY`, a runtime key with `rules:read`,
`telemetry:write` and `sql:read`) and `VERICTO_DATABASE_ID` to the setup above.
`VERICTO_API_URL` defaults to `https://api.vericto.com` when a key is set.

Claude Code:

```bash
claude mcp add vericto-db \
  -e VERICTO_API_KEY=vtro_... -e VERICTO_DATABASE_ID=<database id> -- \
  docker run -i --rm --user "$(id -u):$(id -g)" -e VERICTO_API_KEY -e VERICTO_DATABASE_ID \
    -v ~/.config/vericto/shop.url:/run/secrets/db.url:ro \
    vericto/vericto-proxy:4.21.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
```

Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--user", "501:20",
               "-e", "VERICTO_API_KEY", "-e", "VERICTO_DATABASE_ID",
               "-v", "/Users/me/.config/vericto/shop.url:/run/secrets/db.url:ro",
               "vericto/vericto-proxy:4.21.0", "/usr/local/bin/vericto-proxy", "mcp",
               "--database-url-file", "/run/secrets/db.url"],
      "env": { "VERICTO_API_KEY": "vtro_...", "VERICTO_DATABASE_ID": "<database id>" }
    }
  }
}
```

Codex, with a source build:

```toml
[mcp_servers.vericto-db]
command = "/path/to/vericto-proxy/target/release/vericto-proxy"
args = ["mcp", "--database-url-file", "/Users/me/.config/vericto/shop.url"]
env = { VERICTO_API_KEY = "vtro_...", VERICTO_DATABASE_ID = "<database id>" }
```

`whoami` then reports `control_plane.mode: "linked"` and, once the first signed bundle
is in force, `control_plane.ruleset: "signed_bundle"` (`rules_cache` when it came from
the rules cache).

**A configured control plane is never replaced by the built-in rules.** The server is
linked as soon as `VERICTO_API_KEY` is set (`VERICTO_DATABASE_ID` may be left out, as
for the TCP proxy: the workspace-level ruleset applies and nothing is reported), and
then:

- until a signed bundle (or the verified rules cache) is in force, `execute_sql` and
  `describe_schema` answer `NOT_READY`, also when the control plane is unreachable or a
  bundle fails the signature check; `whoami` shows `control_plane.ruleset: "none"`;
- `VERICTO_API_URL` or `VERICTO_DATABASE_ID` without `VERICTO_API_KEY` is a startup
  error, as are `VERICTO_API_KEY` with an empty `VERICTO_API_URL` and
  `VERICTO_MCP_REQUIRE_CONTROL_PLANE=true` without a key: a process meant to be linked
  never starts on the built-in rules.

## How it works

```text
MCP client ──JSON-RPC (stdio or HTTP)──► vericto-proxy mcp ──PostgreSQL protocol──► database
                                           │  1. one statement? no NUL byte? params match?
                                           │  2. evaluate it (rules, masks, allowlist, policies, kill switch)
                                           │  3. a read? (statement class from the AST, side-effect functions)
                                           │  4. BEGIN READ ONLY; SET LOCAL timeouts
                                           │     Parse{the evaluated bytes} Bind{params} Execute{rows+1} Sync
                                           │     ROLLBACK, always
                                           └─ 5. rows within the caps, one event to the control plane
```

- **The same bytes.** The statement is sent with the extended protocol, as one unnamed
  prepared statement: PostgreSQL refuses a `Parse` with two commands, and parameters
  travel only in `Bind`, never interpolated into the text. The text sent is the text the
  evaluator returned. A NUL byte, which would make the server parse a prefix of what was
  evaluated, is refused.
- **Read-only twice.** The statement class must be a read (checked from the parse tree),
  and every call runs in `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`
  that always ends in `ROLLBACK`, so even a function that writes cannot persist anything.
  Use a database role with `SELECT` grants only as the third line.
- **No SQL of its own** besides fixed control statements (the transaction, `SET LOCAL`
  settings, `ROLLBACK`, and the catalog queries of `describe_schema`), all in
  `src/mcp/control.rs`, with a test that fails if SQL appears anywhere else. It uses the
  low-level `postgres-protocol` encoders, not a full driver, which would send catalog
  lookups of its own.

## Set up (Streamable HTTP) for a team

Run the server next to the database, where agents cannot reach the database directly,
and give each agent or developer its own runtime key with `sql:read`:

```bash
docker run -d --name vericto-mcp -p 8808:8808 \
  -e VERICTO_API_KEY=vtro_proxy_key -e VERICTO_DATABASE_ID=<id> \
  -e VERICTO_MCP_TRANSPORT=http -e VERICTO_MCP_LISTEN=0.0.0.0:8808 \
  -e VERICTO_MCP_ALLOWED_HOSTS=vericto-mcp.internal \
  -e PROXY_TLS_MODE=require -e PROXY_TLS_CERT=/run/secrets/tls.crt -e PROXY_TLS_KEY=/run/secrets/tls.key \
  -v /srv/secrets:/run/secrets:ro \
  vericto/vericto-proxy:4.21.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
```

Clients connect with the URL and their own key:

```json
{ "url": "https://vericto-mcp.internal:8808/mcp", "headers": { "Authorization": "Bearer vtro_..." } }
```

- **Stateless**: one `POST /mcp` per JSON-RPC message, answered with
  `application/json` (`202` for a notification). `GET` and `DELETE` are `405`: there is
  no server-initiated stream and no session.
- **Before any tool runs**, in this order: the `Host` header must name an allowed host
  (`localhost`, `127.0.0.1`, `::1`, the listen address, and
  `VERICTO_MCP_ALLOWED_HOSTS`) and an `Origin`, if sent, must be in
  `VERICTO_MCP_ALLOWED_ORIGINS` (or be loopback when the listener is): a local HTTP MCP
  server a browser can reach is the DNS-rebinding case the MCP specification warns
  about. Then the bearer token, mandatory also on loopback. Then the body size.
- **Keys are checked offline**: the signed rules bundle lists the workspace's runtime
  keys with `sql:read` by the SHA-256 of the key; a revoked key stops at the next sync
  (every 30 s in `mcp` mode). Without a control plane, list tokens in
  `VERICTO_MCP_AUTH_TOKENS_FILE` (one per line: the token itself, at least 32
  characters, or `sha256:<hex>`, optionally followed by a name); the HTTP mode does not
  start without a control plane and at least one token there.
- **TLS**: a listener on any address other than loopback needs `PROXY_TLS_MODE=require`
  with `PROXY_TLS_CERT`/`PROXY_TLS_KEY`, or `VERICTO_MCP_ALLOW_PLAINTEXT_HTTP=true`
  behind a TLS-terminating sidecar.
- `VERICTO_HEALTHZ_PORT` opens the TCP health listener, as for the TCP proxy.

## Tools

| Tool | What it does |
| --- | --- |
| `execute_sql` | Runs one read statement and returns its rows (below). `readOnlyHint: true` |
| `describe_schema` | Tables and views the role can read, columns and types, primary and foreign keys; masked columns carry their mask and blocked ones `sensitive: block`. Under an enforced allowlist, only what the database user may read. Optional `schema`, `table` |
| `check_sql` | Evaluates a script or pre-split queries without running them, as the hosted `check_sql` answers, **locally** (no CI checks are spent). Its hints point to `execute_sql` |
| `whoami` | The database, the tiers (`read` only), the limits in force, the ruleset version and where it comes from (`control_plane.mode`: `none` or `linked`; `control_plane.ruleset`: `built-in`, `signed_bundle`, `rules_cache`, or `none` while `NOT_READY`), the identity calls are recorded under, and warnings about the setup |
| `list_rules`, `show_rule` | With the control-plane link only: the rules of the signed bundle in force |

`execute_sql` input:

```jsonc
{
  "sql": "SELECT id, email FROM users WHERE created_at > $1 ORDER BY id LIMIT 50",
  "params": ["2026-10-01"],   // optional; JSON scalars or null, at most 100, bound as $1…$n
  "max_rows": 50,             // optional, 1 … the cap
  "timeout_ms": 5000,         // optional, at most the cap
  "tier": "read",             // optional; checked against the statement, never trusted
  "ticket": "OPS-123"         // optional; declared, recorded with the event
}
```

The answer has a short text for the model (a status line, the rows as a tab-separated
table in a fenced block labelled untrusted data, and a `Next:` line) and
`structuredContent` with every field of the contract: `status` (`EXECUTED`, `BLOCKED`,
`ERROR`), `verdict`, `executed_sql`, `rewritten`, `statement_sha256`, `columns`, `rows`,
`row_count`, `truncated`, `truncation`, `cells_truncated`, `command_tag`,
`duration_ms`, `tier`, `enabled_tiers`, `ruleset_version`, `event_id`, `error`,
`next_action` and `next_steps`. `isError` is true for `BLOCKED` and `ERROR`. The output
schema is open: fields are only ever added. The shared fixtures in
[`tests/mcp-contract/`](../tests/mcp-contract/) are the contract, asserted by this
repository's tests and by the control plane's.

## What execute_sql runs

| Runs (read tier) | Refused |
| --- | --- |
| `SELECT` (without `FOR UPDATE/SHARE` or `INTO`), `WITH` whose parts all read, `VALUES`, `TABLE`, `EXPLAIN` without `ANALYZE` (of a read), `SHOW` | `INSERT`, `UPDATE`, `MERGE`, `DELETE`, DDL, `TRUNCATE`: `TIER_NOT_ENABLED`. `SET`/`RESET`, `COPY`, `DO`, `CALL`, `LOCK`, `VACUUM`, `LISTEN`/`NOTIFY`, `PREPARE`/`EXECUTE`, transaction control, cursors, roles, extensions, functions: `INVALID_INPUT`, at any tier |

- The class comes from the parse tree of the statement (after the policy's rewrite, which
  is classified again); a data-modifying `WITH` anywhere raises the tier (the highest
  part wins). A statement the parser cannot read is refused, whatever the workspace's
  parse-error policy: its class cannot be shown.
- **Side-effect functions** a `SELECT` could call are refused wherever they appear in the
  tree: `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_read_file`,
  `pg_ls_*`, `lo_*`, `dblink*`, `set_config`, `pg_advisory_*`, `pg_notify`, `txid_*`,
  the functions that run SQL given as text (`query_to_xml*`, `table_to_xml*`,
  `ts_stat`, `crosstab*` …) and `nextval`/`setval` (the full list is
  `DENIED_FUNCTIONS` in `src/mcp/classify.rs`).
- **One statement per call.** A trailing `;` and comments are fine; a second statement
  is `INVALID_INPUT`. The placeholders `$1…$n` must match `params` exactly.
- Each call pins its session settings inside the transaction (`SET LOCAL`): UTC
  `TimeZone`, ISO `DateStyle` and `IntervalStyle`, `extra_float_digits = 3`,
  `standard_conforming_strings = on`, `bytea_output = hex`, the timeouts, and the search
  path (`VERICTO_MCP_SEARCH_PATH`, or under an agent-access allowlist its default schema,
  so `users` means the same table to the evaluator and to the database). A pooler in
  transaction mode therefore cannot hand a call a session with other settings.

## Limits

| Limit | Default | Cap | Setting | When reached |
| --- | --- | --- | --- | --- |
| Rows | 200 | 1000 | `VERICTO_MCP_MAX_ROWS`, `VERICTO_MCP_MAX_ROWS_CAP`, `max_rows` | `truncated: true`, `truncation.reason: "max_rows"` |
| Result size (serialized rows) | 256 KiB | 1 MiB | `VERICTO_MCP_MAX_RESULT_BYTES` | `reason: "max_bytes"`; the last row that fits is the last one returned |
| Value size | 8 KiB | 64 KiB | `VERICTO_MCP_MAX_CELL_BYTES` | the value ends with `…[truncated N bytes]`; `cells_truncated` counts them |
| Statement time | 15 s | 60 s | `VERICTO_MCP_STATEMENT_TIMEOUT_MS`, `…_CAP_MS`, `timeout_ms` | `TIMEOUT` |
| Lock wait | 2 s | 10 s | `VERICTO_MCP_LOCK_TIMEOUT_MS` | `DATABASE_ERROR` 55P03 |
| Statement size | 64 KiB | 1 MiB | `VERICTO_MAX_QUERY_BYTES` | `INVALID_INPUT` |

The control plane sends the database's limits in the bundle; a value lower than this
process's applies, a higher one never does. Rows are fetched with `Execute{max_rows+1}`,
so the server stops after one row more than is returned; nothing beyond the caps is held
in memory, and a truncated answer says so three times (`truncated`, the text, and a
`refine_query` next step that teaches keyset paging).

## Results

Values are requested in text and converted by type: `bool` → boolean; `int2`, `int4`,
`float4`, `float8` → numbers (`NaN`, `Infinity` as strings); `int8`, `numeric`, `money`
→ strings (exact); text types, `uuid`, dates and times (ISO 8601, UTC) → strings;
`json`, `jsonb` → the JSON value; arrays of these → JSON arrays; `bytea` →
`{ "base64": <first KiB>, "bytes": n }`; anything else → the server's text form.
`columns[].type` names the built-in type (`oid:<n>` for enums, domains and extension
types). Masking is a rewrite, so a masked value is computed by the database and the
clear value never reaches Vericto or the agent; `columns[].masked` names the mask.

## Errors and next steps

| `error.code` | When | Next action |
| --- | --- | --- |
| `INVALID_INPUT` | Two statements, NUL byte, too large, empty, params mismatch, a declared `tier` that is not the statement's, a statement no tier runs, a bad argument | `fix_and_recheck` (or `do_not_run`) |
| `BLOCKED` | The evaluator blocked it, or it could not be parsed | `apply_fix_and_recheck`, `do_not_run`, `request_access`, `fix_and_recheck` |
| `KILL_SWITCH` | A kill-switch block stops the database user, the workspace, or the key; a statement already running is cancelled | `stop` |
| `TIER_NOT_ENABLED` | Above read (`layer`: `database` when linked, `process` otherwise), or reading is off for the key (`scope`) | `request_write_access` |
| `DATABASE_ERROR` | PostgreSQL refused it: `sqlstate` and a sanitized message | `fix_sql_error` |
| `TIMEOUT` | `statement_timeout` (57014) | `refine_query` |
| `DATABASE_UNAVAILABLE` | Connect, TLS or login failure, or every connection busy; never names the host, user or password | `retry_later`, or `stop` for TLS and login |
| `NOT_READY` | No signed bundle loaded yet (`VERICTO_MCP_REQUIRE_CONTROL_PLANE`) | `retry_later` |

Every answer ends with `next_action` and `next_steps` (the vocabulary of the hosted MCP):
what to call next, or that no call will help. Hints never come from row contents.

**Database errors are sanitized** (`VERICTO_MCP_RESULT_DETAIL=sanitized`, the default):
`DETAIL`, `HINT`, `WHERE` and `CONTEXT` are dropped, and quoted parts of the message are
redacted for data, constraint and raise errors (SQLSTATE classes 21, 22, 23, P0), so
`SELECT 1 WHERE CAST(ssn AS int) = 0` cannot print an SSN in
`invalid input syntax for type integer`. `full` keeps the server's fields.

## The control plane

With `VERICTO_API_KEY` and `VERICTO_DATABASE_ID` the server syncs the workspace's rules
the way the TCP proxy does, with three differences:

- **Every bundle must be signed** (Ed25519, the keys of
  [business policy rules](CONFIGURATION.md#business-policy-rules-preview-off-by-default)),
  whatever `VERICTO_POLICY_RULES` says; in `mcp` mode it defaults to `enforce` (`off`
  is refused). A tampered or downgraded bundle cannot remove a mask. The rules cache
  (`VERICTO_RULES_CACHE_PATH`) is verified on load as well.
- **No statement runs before a bundle is in force** (`VERICTO_MCP_REQUIRE_CONTROL_PLANE`,
  on by default with the link): `execute_sql` answers `NOT_READY` until the first signed
  bundle or the rules cache is loaded.
- The sync sends `X-Vericto-Proxy-Mode: mcp` and polls every 30 s by default; the
  bundle's `mcp` section carries the database's tiers and limits, this key's own
  kill-switch block and, for HTTP, the agent keys (`tests/mcp-contract/sync-mcp.json`).

**Events.** Every call is one query event in Dashboard → Queries, refused ones included,
with `source: "mcp_proxy"` and `execution_status`, `tier`, `rows_returned`,
`bytes_returned`, `truncated`, `sqlstate`, `execution_ms`, `mcp_client_name`,
`mcp_client_version`, `statement_sha256` and, over HTTP, `api_key_id` (the agent key).
Counts and hashes only: **no result value is ever part of an event**. Input refused before
evaluation is reported with `status: "INVALID"` and its hash, not its text. An older
control plane that refuses the `mcp_proxy` source gets the same events as `source: "mcp"`
(the reporter falls back once and remembers). Over the monthly query quota enforcement
continues and telemetry pauses, as for the TCP proxy.

Without the link the server runs locally with the built-in ruleset and reports nothing:
no masks, allowlists or kill switch, and `whoami` says so
([Try it without an account](#try-it-without-an-account)).

## Security

- **Give the agent no other way to the database.** In stdio mode the server runs as the
  same OS user as the agent. At startup and in `whoami.execution.warnings`
  (`agent_environment_has_db_credentials`) it reports, by name only, `DATABASE_URL*`,
  `PGPASSWORD`, `PGPASSFILE`, `PGSERVICE`, `POSTGRES_URL*`, `SUPABASE_DB_*`, `NEON_*` and
  `VERICTO_MCP_DATABASE_URL` in its environment, a `~/.pgpass`, and a secret file other
  users can read. The strong setups: HTTP mode in a separate container or host (the agent
  never sees the secret), a role only this server uses, and the database network open to
  the server's address only. Locally, deny the agent's own tools access to the secret
  where the client supports it, for example in Claude Code's `settings.json`:
  `"permissions": { "deny": ["Read(~/.config/vericto/**)", "Bash(psql:*)", "Bash(cat ~/.config/vericto/*)"] }`.
- **The credential** is read once (`VERICTO_MCP_DATABASE_URL_FILE` is the documented
  path; the URL in the environment is accepted and warned about; `--database-url` on the
  command line is refused), its `Debug` form redacts the password, and no error or log
  line names the URL.
- **Authentication to the database**: SCRAM-SHA-256; MD5 is refused unless
  `VERICTO_MCP_ALLOW_MD5=true`; a cleartext password only over TLS or to loopback;
  certificates through `UPSTREAM_SSLCERT`/`UPSTREAM_SSLKEY`.
- **Rows are data, not instructions.** The text puts rows in a fenced block labelled as
  untrusted data, the server instructions say so, and next steps never derive from rows.
  An injected instruction can still steer the agent's other tools; read-only access and
  the caps bound what it can read here.
- **Masks have known limits**: a tagged column used only in `WHERE`, `JOIN`, `GROUP BY`
  or `ORDER BY` is not a read, so an agent can infer a masked value by filtering on it.
  For an agent, add an agent-access allowlist for this server's database user, where
  every reference counts ([AGENT_ACCESS.md](AGENT_ACCESS.md)). Views, functions and
  partitions are not tagged ([SENSITIVE_COLUMNS.md](SENSITIVE_COLUMNS.md)).
- **Parser divergence**: the evaluator reads PostgreSQL with the PostgreSQL 17 grammar;
  a newer server is reported at startup (see
  [CONFIGURATION.md](CONFIGURATION.md#sql-parser-version-and-database-version)).
- **Deeply nested statements**: every parse of agent text runs on a thread with a large
  stack, and statements are limited to 64 KiB by default (`VERICTO_MAX_QUERY_BYTES`, at
  most 1 MiB in `mcp` mode).

## Configuration reference

Every `VERICTO_MCP_*` variable below is also a flag of the subcommand: `--transport http`
is `VERICTO_MCP_TRANSPORT=http` (`vericto-proxy mcp --help` lists them). A flag wins over
the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VERICTO_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `VERICTO_MCP_LISTEN` | `127.0.0.1:8808` | HTTP only |
| `VERICTO_MCP_DATABASE_URL_FILE` | — | A file holding the `postgres://` URL (preferred; `~` is expanded) |
| `VERICTO_MCP_DATABASE_URL` | — | The URL in the environment (accepted, warned about) |
| `UPSTREAM_HOST`, `UPSTREAM_PORT`, `UPSTREAM_USER`, `UPSTREAM_PASSWORD_FILE`, `UPSTREAM_DBNAME` | — | Instead of a URL |
| `UPSTREAM_SSLMODE`, `UPSTREAM_SSLROOTCERT`, `UPSTREAM_SSLCERT`, `UPSTREAM_SSLKEY` | `verify-full` off loopback | As for the TCP proxy; they override the URL's `sslmode`/`sslrootcert`/`sslcert`/`sslkey` |
| `VERICTO_MCP_ALLOW_PLAINTEXT_DB` | `false` | Allow `sslmode=disable` to a host that is not loopback |
| `VERICTO_MCP_ALLOW_MD5` | `false` | Allow MD5 password authentication |
| `VERICTO_MCP_TIERS` | `read` | Tiers this process may use; above `read` is reported and ignored in this release |
| `VERICTO_MCP_MAX_ROWS`, `VERICTO_MCP_MAX_ROWS_CAP` | `200`, `1000` | [Limits](#limits) |
| `VERICTO_MCP_MAX_RESULT_BYTES` | `262144` | |
| `VERICTO_MCP_MAX_CELL_BYTES` | `8192` | |
| `VERICTO_MCP_STATEMENT_TIMEOUT_MS`, `VERICTO_MCP_STATEMENT_TIMEOUT_CAP_MS` | `15000`, `60000` | |
| `VERICTO_MCP_LOCK_TIMEOUT_MS` | `2000` | |
| `VERICTO_MAX_QUERY_BYTES` | `65536` in `mcp` mode | At most 1 MiB in `mcp` mode |
| `VERICTO_MCP_POOL_SIZE` | `4` (at most 32) | Database connections, opened lazily |
| `VERICTO_MCP_POOL_IDLE_SECS` | `300` | Idle connections are closed after it |
| `VERICTO_MCP_SEARCH_PATH` | the role's (under an allowlist: its default schema) | Comma-separated schema names |
| `VERICTO_MCP_RESULT_DETAIL` | `sanitized` | `sanitized` or `full` ([errors](#errors-and-next-steps)) |
| `VERICTO_MCP_REQUIRE_CONTROL_PLANE` | `true` when linked | Refuse `execute_sql` until a signed bundle is loaded; `true` without a control plane is a startup error |
| `VERICTO_MCP_ALLOWED_HOSTS`, `VERICTO_MCP_ALLOWED_ORIGINS` | loopback | HTTP Host and Origin allow-lists |
| `VERICTO_MCP_ALLOW_PLAINTEXT_HTTP` | `false` | HTTP on a non-loopback address without `PROXY_TLS_MODE=require` |
| `VERICTO_MCP_AUTH_TOKENS_FILE` | — | HTTP bearer tokens accepted besides the bundle's keys; required for HTTP without a control plane |
| `VERICTO_API_KEY`, `VERICTO_DATABASE_ID` | — | The control-plane link; none of the three set is the [local mode](#try-it-without-an-account), `VERICTO_API_URL` or `VERICTO_DATABASE_ID` without a key a startup error |
| `VERICTO_API_URL` | `https://api.vericto.com` when a key is set | |
| `VERICTO_RULES_SYNC_INTERVAL_SECS` | `30` in `mcp` mode | At least 30 |
| `VERICTO_POLICY_RULES` | `enforce` in `mcp` mode | `enforce` or `observe` |

The telemetry buffer, rules cache, bundle-signing keys and log settings are those of the
TCP proxy ([CONFIGURATION.md](CONFIGURATION.md)). The TCP listener is off in `mcp` mode;
run a second container from the same image for the TCP proxy.

## What is not in this release

- **Tiers above read** (write, delete, DDL), approvals and impact verification: off until
  the engine's write-safety release (the write gate). `VERICTO_MCP_TIERS` cannot turn
  them on.
- **Trust labels and taint**: `taint` is `null` in every answer and in `whoami`.
- **HTTP sessions** (`Mcp-Session-Id`): the HTTP transport is stateless.
- **The hosted Gateway**, Gateway with connector, MySQL, and the Homebrew and npm
  packages.
