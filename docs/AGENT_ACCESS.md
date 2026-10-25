# Agent access

The full reference for agent-access allowlists in `vericto-proxy`. The
[README](../README.md#agent-access) has the summary.

An allowlist per database user (Team and Enterprise plans), set in the Vericto
dashboard: which tables and columns that user may read, and which it may write.
Everything else is denied (`VERICTO-087`). The policies reach the proxy with the
ruleset (`/sync/rules`, so the control-plane link and `VERICTO_DATABASE_ID` are
required), keyed by database user, with an optional `"*"` default for every user
not listed.

**The TCP proxy enforces per database user.** The identity of a session is the
user it authenticated as: the Postgres StartupMessage `user`, the MySQL
HandshakeResponse username. A database with a policy for user X applies it only to
sessions as X; a user with no policy (and no `"*"`) is not restricted, exactly as
before. To give an agent a dedicated proxy instance, give it its own database user
and a policy for that user.

| Outcome | Postgres | MySQL |
|---------|----------|-------|
| Allowed | Forwarded as sent | Same |
| Denied, policy `enforce` | Never reaches the database: `ErrorResponse`, SQLSTATE 42501, `[VERICTO-087]` and what was denied | Never reaches the database: `ERR_Packet`, ERROR 1142 |
| Denied, policy `observe` | Forwarded as sent, recorded as FLAGGED | Same |

- **Every reference counts**, not only what the query returns: `WHERE`, `JOIN`,
  `GROUP BY`, `ORDER BY`, subqueries, CTEs, `RETURNING`. `*` needs every column of
  the table granted. A write needs `read_write` on its target; DDL is always denied.
  Catalogue schemas (`information_schema`, `pg_catalog`, `mysql`, …) are denied
  unless listed. Both protocols of each database are covered: a Postgres simple
  `Query` and the extended protocol's `Parse` (the sequence is then discarded up to
  `Sync`), MySQL `COM_QUERY` and `COM_STMT_PREPARE`.
- **The identity cannot be changed from inside the session.** Under a policy,
  `SET ROLE`, `SET SESSION AUTHORIZATION`, `SET search_path`, `set_config('role', …)`
  and `USE` are denied by the engine, and so are the protocol commands that do the
  same outside SQL: a Postgres `FunctionCall` message, MySQL `COM_INIT_DB`,
  `COM_FIELD_LIST` and the replication/process commands, and any command the proxy
  does not know (deny by default). MySQL `COM_CHANGE_USER` is refused when the
  current or the target user has a policy. On Postgres, `search_path`, `role` and
  `session_authorization` set by the StartupMessage (as parameters or in
  `options`, e.g. `PGOPTIONS='-c search_path=…'`) are evaluated as the `SET` they
  are: under an enforced policy the connection is refused with 42501 before it
  reaches the database; under `observe` it is flagged.
- **Unqualified names resolve to the default schema** (vericto-engine 3.8.1). An
  entry without a schema is the table in the default schema only; a table of the
  same name in another schema needs an entry naming it. The default is the
  database's setting in the dashboard (`default_schema` in `/sync/rules`), else
  `public` on Postgres. On MySQL it is the session's current database: the one
  named at login, then each forwarded `COM_INIT_DB` or `USE` (allowed without a
  policy or under `observe`), which wins over the dashboard's setting; a name
  qualified with it (Prisma's `` `db`.`User` ``) matches entries without a schema.
  Postgres names compare as Postgres does (quoted names exactly, unquoted ones
  folded to lower case); MySQL table and database names compare exactly.
- **Writes and locks.** `DELETE` needs a `read_write` entry for the table, whatever
  its column list, and is reported as the table. `SELECT … FOR UPDATE` /
  `FOR SHARE` need `read_write` on each locked table.
- **Policy changes apply to open sessions.** The policy is selected again for every
  statement, so a sync that adds, changes or removes it takes effect on each
  session's next statement, without reconnecting. The last-good policies are kept in
  the rules cache with the rest of the bundle.
- Session statements drivers send on connect (transaction control, `SET NAMES`,
  time zone, timeouts, Rails' `sql_mode` setup) are allowed; other `SET` statements
  are denied under a policy. Under `enforce`, a query the engine cannot parse is
  blocked.
- **With sensitive columns:** a `block` tag still wins; a column that is allowed and
  tagged `mask` comes back masked; a column that is not allowed is denied whether or
  not it is tagged.
- `monitor_mode` turns a would-be block into a flag, as for every rule.

Every event carries the session's `db_user`; under a policy also its mode
(`access_policy_mode`) and what was denied (`access_denied`: schema, table, column
and whether it needed read, write or ddl). Names only: in sanitized telemetry mode,
a MySQL name the query did not spell as an identifier (a `"…"` string the engine
also reads as a possible column) is reported as `?`.

Known limits come from the engine, which works from the SQL alone: a view or
function over a table is not resolved to it (grant the view itself), and an
unqualified column in a multi-table query must be allowed in every table it could
belong to (qualify it). See the
[engine documentation](https://github.com/vericto/vericto-engine#agent-access-allowlists-vericto-087).

## Kill switch (VERICTO-105)

Since 4.18.0. "Block all statements" in the dashboard's Incident response panel stops
one agent (an API key, a database user or a principal) or every agent of the
workspace until an owner or admin lifts it. `/sync/rules` carries the active blocks
that cover the proxy's database in a `kill_switch` field, and the proxy applies them
from that sync on, to open sessions too:

| | Postgres | MySQL |
|---|---|---|
| Refused | `Query`, `Parse`, and `Bind` / `Execute` of a statement prepared before the block (the sequence is discarded up to `Sync`); `FunctionCall` closes the session, as under an allowlist; any message not known to be plumbing | `COM_QUERY`, `COM_STMT_PREPARE`, `COM_STMT_EXECUTE` / `COM_STMT_FETCH` of an earlier statement, `COM_INIT_DB`, `COM_FIELD_LIST`, `COM_CHANGE_USER`, any command not known to be plumbing |
| Error | `ErrorResponse`, SQLSTATE 42501 | `ERR_Packet`, ERROR 1142 |
| Passes | `Describe`, `Close`, `Sync`, `Flush`, COPY data, `Terminate` | `COM_PING`, `COM_STATISTICS`, `COM_STMT_SEND_LONG_DATA`, `COM_STMT_CLOSE`, `COM_STMT_RESET`, `COM_SET_OPTION`, `COM_RESET_CONNECTION`, `COM_QUIT` |

- **Every statement**, including those that read no table (`SELECT 1`, `SET`,
  `BEGIN`, `SET vericto.*`): the whole agent is blocked. The check comes before the
  size guard, the parser, the rules, the allowlist and the business policies, and it
  does not depend on `monitor_mode`, an observe window or `VERICTO_POLICY_RULES`.
- **The error text is the block's message**, the same text the Runtime API, MCP and
  the CLI return (who set it, when, the block id, and to stop and ask a person).
- **Who is blocked.** The session's database user's own block, else the workspace
  switch. A session whose user could not be read is refused by any block (it might
  be the blocked user), as the allowlists treat it. Principal blocks reach the proxy
  only for principals identified by an exact database user.
- **Telemetry.** Each refusal is a BLOCKED event with `rule_code` `VERICTO-105`,
  severity `critical`, path `KillSwitch > <target>` and `kill_switch_id` (the block
  id), which the control plane links to the block. One event per statement: the
  `Bind` and `Execute` of one execution are one refusal.
- **Older proxies and control planes.** The control plane keeps sending the deny-all
  allowlist of each blocked user, which 4.17.x and older proxies (they ignore the new
  field) enforce as `VERICTO-087`; there, statements that read no table pass. A
  4.18.0 proxy talking to a control plane without the field behaves the same way.
  A malformed `kill_switch` entry is skipped and logged as an error
  (`alert=kill_switch_malformed`); the rest of the bundle, the deny-all allowlist of
  that user included, still applies.
- **Cost.** With no active block a statement pays one atomic load; with blocks, one
  hash lookup by the session user.
