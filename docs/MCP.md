# MCP Proxy mode: `vericto-proxy mcp`

`vericto-proxy mcp` is an [MCP](https://modelcontextprotocol.io) server that lets an AI
agent (Claude Code, Cursor, Codex, any MCP client) read a PostgreSQL, MySQL or MariaDB
database **through Vericto** (MySQL and MariaDB since 5.2.0). The agent gets an `execute_sql` tool and no database credential.
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
kill switch and telemetry. This release (5.2.0) is **read-only**: `execute_sql` runs
reads only (the "read tier").

> **The guarantee holds only if the agent has no other database credential.** If the
> agent can also read a `DATABASE_URL`, a `~/.pgpass` or the server's secret file, it
> can run SQL around Vericto. The server warns when it sees such a credential in its
> environment (see [Security](#security)), and [hard mode](#hard-mode) keeps the
> credential out of the agent's reach.

- [Try it without an account](#try-it-without-an-account)
- [Connect to Vericto](#connect-to-vericto)
- [Hard mode](#hard-mode)
- [MySQL and MariaDB](#mysql-and-mariadb)
- [Read-only database roles](#read-only-database-roles)
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
Supavisor pooler host (session mode, port 5432, or transaction mode, 6543). MySQL and
MariaDB, and what each provider needs, are in
[Read-only database roles](#read-only-database-roles).

**2. The URL in a file, not in the agent's configuration** (or in the OS keychain:
[hard mode](#hard-mode)).

```bash
mkdir -p ~/.config/vericto && chmod 700 ~/.config/vericto
printf '%s' 'postgres://vericto_agent_ro:…@db.example.com:5432/shop?sslmode=verify-full' \
  > ~/.config/vericto/shop.url
chmod 600 ~/.config/vericto/shop.url
```

TLS is `verify-full` by default for any host that is not loopback (`sslmode=require`, `prefer` or `allow`, and MySQL's `REQUIRED`/`PREFERRED`, encrypt without checking the certificate, as in libpq and the MySQL clients; off loopback the server says so at startup with the `database_tls_unverified` warning); `sslrootcert=` in the
URL (or `UPSTREAM_SSLROOTCERT`) names a CA bundle when the provider's certificate is not
publicly trusted. A database on your own machine (`localhost`, `127.0.0.1`) needs no TLS.

**3. Register the server**, with the release binary, the published image or a binary
built from source. None of `VERICTO_API_KEY`, `VERICTO_DATABASE_ID` or `VERICTO_API_URL`
is set: that is what makes it local.

With the release binary (5.0.1 and later; no Docker, and a database on `localhost` is
reached directly). On Linux and macOS the installer checks the archive's SHA-256 and
puts `vericto-proxy` in `~/.cargo/bin`; Windows and manual downloads are in the
[README](../README.md#install-the-native-binary):

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/vericto/vericto-proxy/releases/download/v5.2.0/vericto-proxy-installer.sh | sh
claude mcp add vericto-db -- ~/.cargo/bin/vericto-proxy \
  mcp --database-url-file ~/.config/vericto/shop.url
```

Or with Homebrew (5.0.2 and later), on macOS (Apple silicon and Intel) and Linux (arm64
and x86_64). The formula pins each archive's SHA-256, and `brew upgrade` follows the
releases; the command is then `$(brew --prefix)/bin/vericto-proxy`:

```bash
brew install vericto/tap/vericto-proxy
claude mcp add vericto-db -- "$(brew --prefix)/bin/vericto-proxy" \
  mcp --database-url-file ~/.config/vericto/shop.url
```

Cursor (`.cursor/mcp.json`) or any client that takes a command:

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "/Users/me/.cargo/bin/vericto-proxy",
      "args": ["mcp", "--database-url-file", "/Users/me/.config/vericto/shop.url"]
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vericto-db]
command = "/Users/me/.cargo/bin/vericto-proxy"
args = ["mcp", "--database-url-file", "/Users/me/.config/vericto/shop.url"]
```

With Docker (Docker cannot read a `0600` file owned by your user as the image's own
user, so the container runs as you):

```bash
claude mcp add vericto-db -- \
  docker run -i --rm --user "$(id -u):$(id -g)" \
    -v ~/.config/vericto/shop.url:/run/secrets/db.url:ro \
    vericto/vericto-proxy:5.2.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
```

Cursor (`.cursor/mcp.json`) or any client that takes a command:

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--user", "501:20",
               "-v", "/Users/me/.config/vericto/shop.url:/run/secrets/db.url:ro",
               "vericto/vericto-proxy:5.2.0", "/usr/local/bin/vericto-proxy", "mcp",
               "--database-url-file", "/run/secrets/db.url"]
    }
  }
}
```

From inside the container a database on your own machine is `host.docker.internal`,
which is not loopback: put `?sslmode=disable` in the URL and add
`-e VERICTO_MCP_ALLOW_PLAINTEXT_DB=true` (the traffic stays on your machine), or use the
release binary or a source build, which reach `localhost` directly.

From source (`cargo build --release --locked`, see
[CONTRIBUTING.md](../CONTRIBUTING.md#run-from-source)), the same commands with the path
of the build:

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
stdin. Install it with Homebrew, the release binary (and its installer script), the
image or a source build; there is no npm package.

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

Claude Code, with the release binary (the client passes both variables to it):

```bash
claude mcp add vericto-db \
  -e VERICTO_API_KEY=vtro_... -e VERICTO_DATABASE_ID=<database id> -- \
  ~/.cargo/bin/vericto-proxy mcp --database-url-file ~/.config/vericto/shop.url
```

With Docker, the variables are also passed into the container:

```bash
claude mcp add vericto-db \
  -e VERICTO_API_KEY=vtro_... -e VERICTO_DATABASE_ID=<database id> -- \
  docker run -i --rm --user "$(id -u):$(id -g)" -e VERICTO_API_KEY -e VERICTO_DATABASE_ID \
    -v ~/.config/vericto/shop.url:/run/secrets/db.url:ro \
    vericto/vericto-proxy:5.2.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
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
               "vericto/vericto-proxy:5.2.0", "/usr/local/bin/vericto-proxy", "mcp",
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

## Hard mode

Hard mode (5.2.0) is the setup where **the agent never holds a database credential**:
the only way from the agent to the database is `execute_sql`, and the credential lives
where the agent's own tools do not look. It is what `vericto guard install --hard` (the
CLI) configures. Three parts:

1. **The URL in the OS keychain**, read by the server at startup, never in a file the
   agent can `cat`, in the MCP client configuration, or in the environment the agent's
   shell inherits.
2. **A role that cannot write**, checked at startup; `--require-read-only` refuses to
   start otherwise.
3. **The agent's direct database clients and credential files denied** in the agent's
   own permissions (the CLI's guard writes these rules).

```bash
# Once: store the URL (read from stdin; hidden on a terminal, never echoed or logged).
vericto-proxy mcp credential set shop
# Check it: connects, reports the engine, and whether the role can write.
vericto-proxy mcp credential test shop --require-read-only
# Register the server with the entry's name, not the URL.
claude mcp add vericto-db -- ~/.cargo/bin/vericto-proxy \
  mcp --database-url-keychain shop --require-read-only
```

Cursor (`.cursor/mcp.json`), Codex and any client that takes a command:

```json
{
  "mcpServers": {
    "vericto-db": {
      "command": "/Users/me/.cargo/bin/vericto-proxy",
      "args": ["mcp", "--database-url-keychain", "shop", "--require-read-only"]
    }
  }
}
```

**`vericto-proxy mcp credential`** stores, removes and checks keychain entries. An
entry is `name` (under the service `vericto-proxy`) or `service/name`. Every action
prints one JSON object on stdout and a sentence on stderr; neither ever contains the URL.

| Action | What it does | Exit codes |
| --- | --- | --- |
| `set <name>` | Reads the URL from stdin (hidden on a terminal; a pipe is read whole), checks that it parses, and stores it. `{"ok", "entry", "backend", "replaced", "dialect", "engine", "database", "tls"}` | `0`, `1` (bad URL, store error) |
| `test <name> [--require-read-only] [flags]` | Connects as the server would (TLS settings and flags apply) and runs the role check. `{"ok", "engine", "server_version", "database", "database_role": {"read_only", "verified", "user", "reasons", "notes"}}` | `0` connected; `2` no such entry; `3` `--require-read-only` and the role can write or is unverified; `4` unreachable or login refused; `1` usage |
| `delete <name>` | Removes it | `0`, `2` no such entry |

**Precedence** when several credentials are configured (first wins; the others are
named in a startup warning): `--database-url-keychain` /
`VERICTO_MCP_DATABASE_URL_KEYCHAIN`, then `--database-url-file` /
`VERICTO_MCP_DATABASE_URL_FILE`, then `VERICTO_MCP_DATABASE_URL`, then `UPSTREAM_*`.
`whoami.credential_source` says which (`keychain`, `file`, `environment`,
`upstream_variables`).

**The role check** runs at startup on one connection (in the background, or before
serving with `--require-read-only` / `VERICTO_MCP_REQUIRE_READ_ONLY=true`) and shows in
the log, in `whoami.database_role` and, when the role can write, as the notice
`database_role_can_write` (`database_role_unverified` when it could not tell):

- **PostgreSQL**: superuser, `CREATEROLE`, `CREATEDB`, any `INSERT`, `UPDATE`, `DELETE`
  or `TRUNCATE` on a table or view outside the system schemas, `CREATE` on a schema or on
  the database, membership of `pg_write_all_data`. A hot standby (read replica) is
  read-only whatever the role. `default_transaction_read_only` is reported but never
  counted: a session can turn it off.
- **MySQL and MariaDB**: `SHOW GRANTS` (any privilege that writes data or schema or
  administers the server, `WITH GRANT OPTION`), `read_only` and `super_read_only`.
  Privileges granted through roles (MySQL 8 roles, MariaDB roles) are not expanded, so a
  user that has them is *unverified*: grant `SELECT` to the user directly.

The check is one control statement of `src/mcp/control.rs` (`ROLE_CHECK`,
`MYSQL_SHOW_GRANTS`, `MYSQL_READ_ONLY_SETTINGS`); it reads the catalog and writes nothing.

### Threat model and honest limits

What hard mode defends against: an agent (or a prompt injection steering it) that reads
the credential from where agents usually find one (`.env`, `DATABASE_URL`, `~/.pgpass`,
`~/.my.cnf`, the MCP configuration, a URL file) and runs SQL around Vericto with `psql`,
`mysql`, an ORM or a script; and a write that gets past both the statement-class check
and the read-only transaction (the role cannot write).

What it does not do: hard mode is not an OS security boundary. **In stdio mode the server
runs as the same OS user as the agent**, and anything that user can do, a determined
agent with a shell can do:

| Platform | Who can read the entry without a prompt |
| --- | --- |
| macOS Keychain | The binary that created it (its access list names `vericto-proxy`). Another program of the same user (`security find-generic-password -w`, a script) gets a system prompt the user must approve; a user who clicks *Always Allow* removes that barrier. A new binary (an upgrade) prompts once for itself. |
| Windows Credential Manager | Any process of the same user, without a prompt (`CredRead` on a generic credential). It keeps the URL out of files and the environment, not out of the user's processes. |
| Linux Secret Service (GNOME Keyring, KWallet) | Any process of the same user while the collection is unlocked (normally the whole desktop session), without a prompt. The server uses libsecret's `secret-tool` (package `libsecret-tools` on Debian and Ubuntu, `libsecret` on Fedora and Arch); a server or container without a session bus has no Secret Service, use `--database-url-file` there. |

Also: the agent can run `vericto-proxy mcp --database-url-keychain shop` itself, which
gives it nothing more than `execute_sql`; the keychain entry is only as safe as the
user's login; and an agent denied `psql` can still try another client the deny list does
not name. **For strict isolation**, run the server as a different OS user (the agent's
user cannot read that user's keychain or files) or in a container or on another host,
over Streamable HTTP ([Set up for a team](#set-up-streamable-http-for-a-team)), with the
database's network open to the server only. The role that cannot write stays the third
line in every setup.

## MySQL and MariaDB

Since 5.2.0 the URL's scheme picks the database: `mysql://` (MySQL 8.0 and later, and
compatible servers) or `mariadb://` (MariaDB; a MySQL URL to a MariaDB server is
recognised from its version too). With `UPSTREAM_*` instead of a URL, set
`VERICTO_WIRE_PROTOCOL=mysql` (or `mariadb`); the port defaults to 3306.

```bash
printf '%s' 'mysql://vericto_agent_ro:…@db.example.com:3306/shop?ssl-mode=VERIFY_IDENTITY' \
  | vericto-proxy mcp credential set shop
```

- **TLS**: `verify-full` by default off loopback, as for PostgreSQL. The URL takes
  `ssl-mode` (`DISABLED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`; `PREFERRED` means
  `REQUIRED` here) or `sslmode` with PostgreSQL's names, `ssl-ca`/`sslrootcert`,
  `ssl-cert`/`sslcert`, `ssl-key`/`sslkey`, and PlanetScale's `sslaccept=strict`.
  `UPSTREAM_SSL*` override them. Authentication: `caching_sha2_password` (over plaintext
  loopback with the server's RSA key, never a cleartext password) and
  `mysql_native_password`.
- **The database the URL names is the scope.** Unqualified names mean it;
  `describe_schema` lists it (or the `schema` argument's database); a URL without a
  database needs qualified names. `VERICTO_MCP_SEARCH_PATH` is PostgreSQL's and is refused.
- **The same checks and caps**: the evaluator in the MySQL dialect (rules, masks,
  allowlists, business policies, kill switch), one statement per call, the read tier
  only, the limits and the output format of PostgreSQL. Placeholders are `?`, bound in
  order from `params` (a JSON number or boolean is bound as a number, anything else as a
  string).
- **What is sent**: every call is one control batch (`SET NAMES utf8mb4`, a pinned
  `sql_mode` without `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES` or `PIPES_AS_CONCAT`, so the
  server reads quotes and backslashes as the evaluator did; `time_zone = '+00:00'`; the
  statement timeout as `max_execution_time` (MySQL, ms) or `max_statement_time`
  (MariaDB, s); `lock_wait_timeout` and `innodb_lock_wait_timeout` rounded up to whole
  seconds; `START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`), then the statement
  exactly as evaluated through `COM_STMT_PREPARE` (which refuses a second statement) and
  `COM_STMT_EXECUTE`, then `ROLLBACK`. The client (`mysql_async`) is configured to send
  no statement of its own.
- **Refused before evaluation or execution** (`INVALID_INPUT`, or `BLOCKED` when the
  engine's rule refuses first): executable comments (`/*! … */`, MariaDB's
  `/*M! … */`), which the server runs as SQL; optimizer hints (`/*+ … */`), which can
  raise `MAX_EXECUTION_TIME` or set session variables; named parameters (`:name`), which
  the driver would rewrite; user-variable assignment (`:=`); `SELECT … INTO`,
  `FOR UPDATE`/`FOR SHARE`/`LOCK IN SHARE MODE`, `EXPLAIN ANALYZE`; `SET`, `USE`,
  `CALL`, `LOCK TABLES`, `LOAD DATA`, transaction control, `PREPARE`/`EXECUTE`, `KILL`,
  users, roles and grants; and the functions `get_lock`, `release_lock`,
  `release_all_locks`, `master_pos_wait`, `source_pos_wait`,
  `wait_for_executed_gtid_set`, `wait_until_sql_thread_after_gtids`, `benchmark`,
  `load_file`, `sys_exec`, `sys_eval`, `sys_get`, `sys_set`, `lib_mysqludf_*` (and
  `nextval`/`setval`, which are `write`): `MYSQL_DENIED_FUNCTIONS` in
  `src/mcp/classify.rs`. Runs: `SELECT`, `WITH` (reads), `VALUES`, `TABLE`, `EXPLAIN`
  and `DESCRIBE` of a read, `DESCRIBE <table>`, `SHOW`.
- **Rows past the cap**: MySQL has no row limit on an execute, so when a result has
  more rows (or bytes) than the call returns, the server closes that connection instead
  of reading the rest; the server stops sending and rolls the transaction back. The next
  call opens a new connection. A row larger than 16 MiB closes the connection
  (`DATABASE_UNAVAILABLE`); select fewer or shorter columns.
- **Timeouts**: `max_execution_time` stops a `SELECT` on MySQL, `max_statement_time`
  any statement on MariaDB; at the client-side deadline (or when the kill switch
  engages) the server sends `KILL QUERY` from a second connection of the same user.
  Errors 3024, 1969 and 1317 answer `TIMEOUT`.
- **Types**: `tinyint`…`int`, `year` → numbers; `bigint` (signed or `unsigned`) and
  `decimal` → strings (exact); `float`, `double` → numbers; `date` (`YYYY-MM-DD`),
  `datetime`, `timestamp` (`YYYY-MM-DD HH:MM:SS[.ffffff]`, UTC for `timestamp`) and
  `time` → strings; `json` → the JSON value; `binary`, `varbinary`, `blob`, `bit`,
  `geometry` → `{ "base64", "bytes" }`; text types, `enum`, `set` → strings.
  `columns[].type` names the MySQL type (`int unsigned`, `varchar` …). A comparison or
  `COUNT(*)` is a `bigint` in MySQL, so it comes back as a string.
- **Errors**: `DATABASE_ERROR` carries the SQLSTATE; the sanitized mode also redacts
  quoted values under MySQL's general `HY000` (for example error 1366). `42S02`
  (unknown table) and `42S22` (unknown column) point to `describe_schema`.
- **Not tested yet**: PlanetScale (Vitess) and other MySQL-compatible proxies may refuse
  a session variable of the control batch; the call then answers `DATABASE_ERROR` with
  the server's message. MariaDB is supported by the same code (its session variables
  and `/*M!` comments) and was not part of this release's integration runs.

## Read-only database roles

A role that can only read is the line that holds even if everything above it failed.
Create one this server alone uses, then check it with
`vericto-proxy mcp credential test <name>` (or `--require-read-only`).

**PostgreSQL** (any provider):

```sql
CREATE ROLE vericto_agent_ro LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE shop TO vericto_agent_ro;
GRANT USAGE ON SCHEMA public TO vericto_agent_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO vericto_agent_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO vericto_agent_ro;
-- PostgreSQL 14 and earlier: PUBLIC may create objects in schema public.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Optional, a fourth line (the server's own transaction is read-only anyway):
ALTER ROLE vericto_agent_ro SET default_transaction_read_only = on;
```

Or, on PostgreSQL 14 and later, `GRANT pg_read_all_data TO vericto_agent_ro;` for every
table and schema at once. Repeat the `GRANT USAGE` / `SELECT` lines for each schema.

- **Supabase**: create the role in the SQL editor as above (not the `postgres` or
  `service_role` roles, which bypass RLS and can write); connect through the Supavisor
  pooler as `vericto_agent_ro.<project-ref>`. RLS policies apply to the role as written;
  without a policy that names it, tables with RLS on return no rows.
- **Neon**: create the role in the console or with SQL (Neon's roles created in the
  console are members of `neon_superuser`, which can write: create it with SQL instead,
  or check it with `credential test`). A read replica (compute endpoint of type read-only)
  is reported as a hot standby: read-only whatever the role.
- **RDS, Cloud SQL, Azure**: as above; the providers' admin roles (`rds_superuser`,
  `cloudsqlsuperuser`, `azure_pg_admin`) can write.

**MySQL** (8.0 and later) and **MariaDB**:

```sql
CREATE USER 'vericto_agent_ro'@'%' IDENTIFIED BY '…' REQUIRE SSL;
GRANT SELECT, SHOW VIEW ON shop.* TO 'vericto_agent_ro'@'%';
-- Nothing else: no INSERT/UPDATE/DELETE, no CREATE TEMPORARY TABLES, no EXECUTE.
-- Grant the privileges to the user itself, not through a role, so the role check can
-- verify them.
```

- **PlanetScale**: create a password with the **Read-only** role (branch → Passwords);
  the URL takes `sslaccept=strict`. PlanetScale's own grants are not `SHOW GRANTS` lines
  the check can read, so `credential test` may report the role as unverified; the
  password's role is then the line that holds.
- **Amazon RDS / Aurora MySQL, Cloud SQL, Azure Database for MySQL**: as above, and
  `REQUIRE SSL` with `ssl-mode=VERIFY_IDENTITY` and the provider's CA in `ssl-ca` when it
  is not publicly trusted. A read replica with `read_only=ON` (and the user without
  `SUPER`/`CONNECTION_ADMIN`) is reported read-only.

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
  settings, `ROLLBACK`, the catalog queries of `describe_schema` and the startup role
  check), all in `src/mcp/control.rs`, with a test that fails if SQL appears anywhere
  else. It uses the low-level `postgres-protocol` encoders, not a full driver, which
  would send catalog lookups of its own. MySQL and MariaDB: [what is sent](#mysql-and-mariadb).

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
  vericto/vericto-proxy:5.2.0 /usr/local/bin/vericto-proxy mcp --database-url-file /run/secrets/db.url
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
| Binary operators in one unparenthesized expression | 10,000 | configurable | `VERICTO_MAX_BINARY_OPERATORS` | parse-error policy (`check_sql`: flag by default; `execute_sql`: unreadable, so refused) |

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
  `PGPASSWORD`, `PGPASSFILE`, `PGSERVICE`, `POSTGRES_URL*`, `SUPABASE_DB_*`, `NEON_*`,
  `MYSQL_PWD`, `MYSQL_PASSWORD`, `MYSQL_URL*`, `MARIADB_PASSWORD`, `PLANETSCALE_*` and
  `VERICTO_MCP_DATABASE_URL` in its environment, a `~/.pgpass`, a `~/.my.cnf` or
  `~/.mylogin.cnf`, and a secret file other users can read. [Hard mode](#hard-mode)
  covers the rest. The strong setups: HTTP mode in a separate container or host (the agent
  never sees the secret), a role only this server uses, and the database network open to
  the server's address only. Locally, deny the agent's own tools access to the secret
  where the client supports it, for example in Claude Code's `settings.json`:
  `"permissions": { "deny": ["Read(~/.config/vericto/**)", "Bash(psql:*)", "Bash(cat ~/.config/vericto/*)"] }`.
- **The credential** is read once (the OS keychain, `--database-url-keychain`, or
  `VERICTO_MCP_DATABASE_URL_FILE`; the URL in the environment is accepted and warned
  about; `--database-url` on the command line is refused; precedence in
  [Hard mode](#hard-mode)), its `Debug` form redacts the password, and no error or log
  line names the URL. A URL file that other users can read is reported at startup.
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
| `VERICTO_MCP_DATABASE_URL_KEYCHAIN` | — | `--database-url-keychain`: an OS keychain entry (`name` or `service/name`) holding the URL ([Hard mode](#hard-mode)); first in the precedence |
| `VERICTO_MCP_DATABASE_URL_FILE` | — | A file holding the `postgres://`, `mysql://` or `mariadb://` URL (`~` is expanded) |
| `VERICTO_MCP_DATABASE_URL` | — | The URL in the environment (accepted, warned about) |
| `UPSTREAM_HOST`, `UPSTREAM_PORT`, `UPSTREAM_USER`, `UPSTREAM_PASSWORD_FILE`, `UPSTREAM_DBNAME` | — | Instead of a URL; `VERICTO_WIRE_PROTOCOL=mysql` or `mariadb` for MySQL (port 3306) |
| `VERICTO_MCP_REQUIRE_READ_ONLY` | `false` | `--require-read-only`: refuse to start unless the [role check](#hard-mode) finds the role cannot write |
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
- **The hosted Gateway**, Gateway with connector, and an npm package.
