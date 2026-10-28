# Sensitive columns

The full reference for sensitive-column tags in `vericto-proxy`. The
[README](../README.md#sensitive-columns) has the summary.

Columns can be tagged as sensitive per database in the Vericto dashboard (Team and
Enterprise plans). The tags reach the proxy with the ruleset (`/sync/rules`, so the
control-plane link and `VERICTO_DATABASE_ID` are required) and are enforced on the
wire, before the database sees the query. Each tag has a policy; when a query reads
several tagged columns the strictest wins (`block` > `mask` > `flag`). A column read
is a projection: what the query returns, or copies into another table. A column used
only in `WHERE`, `JOIN`, `GROUP BY` or `ORDER BY` is not a read.

**The proxy enforces.** Unlike the Validation API or the CLI, which only advise,
what the proxy decides is what the database receives:

| Policy  | Postgres | MySQL |
|---------|----------|-------|
| `block` | The query never reaches the database: `ErrorResponse`, SQLSTATE 42501 | Never reaches the database: `ERR_Packet`, ERROR 1142 |
| `flag`  | Forwarded as sent, recorded as FLAGGED | Same |
| `mask`  | The proxy forwards a **rewritten** query in which the column is masked (`full`, `last4`, `email` or `hash`) under its own name, and never the original. The client receives masked values. | Same: the proxy forwards the rewritten query in the same `COM_QUERY` or `COM_STMT_PREPARE`, and never the original. |

What holds under `mask`:

- Both protocols of each database are rewritten. Postgres: a simple `Query` and the
  extended protocol's `Parse`; on a `Parse` the statement name and the parameter types
  are kept, and `$n` placeholders survive, so the client's `Bind`/`Execute` run
  unchanged. MySQL: `COM_QUERY` (keeping the `CLIENT_QUERY_ATTRIBUTES` prefix) and
  `COM_STMT_PREPARE`. The `?` placeholders survive in the same order, so the
  parameter count the server returns in `COM_STMT_PREPARE_OK` is the one the client
  expects, and `COM_STMT_EXECUTE` / `COM_STMT_SEND_LONG_DATA` pass through untouched.
  The proxy keeps no statement map: the client executes the id the server gave the
  rewritten statement.
- The MySQL masks use only functions present in MySQL 5.7 and 8.0, Aurora MySQL and
  MariaDB, and give the same values as on Postgres (`a***@example.io`, `****4242`).
  The rewrite is printed from the parsed statement, so comments and formatting are
  not kept (string literals are). A query the engine cannot reproduce faithfully
  (optimizer hints `/*+ … */`, `SQL_CALC_FOUND_ROWS` and the other SELECT modifiers,
  bit literals) is blocked rather than rewritten. Rule evaluation on MySQL follows
  MySQL's own reading of comments and string escapes; text the engine cannot read
  with certainty is blocked by `VERICTO-086`, tags or not.
- A masked column becomes `text` (a string on MySQL). A computed expression over it
  (`lower(email)`, `substring(card, 1, 4)`) is masked `full`, whatever the style.
- `SELECT *`, `t.*`, whole-row references (`row_to_json(t)`) and `COPY t TO` over a
  table with a masked or blocked column are blocked; list the columns. So are copies
  of a masked column into another table (`INSERT … SELECT`, `CREATE TABLE AS`), since
  masking them would change stored data.
- **Fail-safe:** if anything about the rewrite does not hold together (no rewritten
  query for a masked read, an empty rewrite or one with a NUL, a rewrite for a dialect
  without one, a rewrite that drops a `$n` or changes the number of `?` the client
  will bind), the proxy blocks with `VERICTO-085` and a message saying why (MySQL:
  ERROR 1142). It never forwards the original instead.
- `monitor_mode` never changes what runs: a would-be block or mask is forwarded as sent
  and recorded, as for every other rule.

With any `block` or `mask` tag configured, a query the engine cannot parse is
**blocked**, whatever the workspace's parse-error policy says: a query that cannot be
read cannot be shown not to read the column. With no tags, or only `flag` tags,
parse errors behave as before. A PostgreSQL newer than the proxy's parser accepts
syntax the parser cannot read; the proxy logs one warning per upstream when it
connects to one: see
[SQL parser version and database version](CONFIGURATION.md#sql-parser-version-and-database-version).

Every read of a tagged column is reported with rule code `VERICTO-085`, the tagged
columns it touched and, for a mask, the rewritten query next to the original (both
sanitized in sanitized telemetry mode: Postgres text with libpg_query, MySQL text with
the MySQL lexer, every literal and comment replaced). The two share the per-event query budget, so a
masked event is no larger than any other.

Known limits come from the engine, which works from the SQL alone: a view, function or
partition over a tagged table is not covered unless it is tagged too. See the
[engine documentation](https://github.com/vericto/vericto-engine#sensitive-columns-vericto-085).
