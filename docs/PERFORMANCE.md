# Performance

How the proxy's per-statement cost is measured, the gate that keeps it from
regressing, and the tuning knobs that affect it.

## CI performance gate

`.github/workflows/perf-gate.yml` runs on every pull request. It builds the
proxy at the pull request's head and at its base, runs both under callgrind on
the same statement corpus, and fails when a workload costs more instructions per
statement than the base by more than the threshold, or when the head answers any
statement of the corpus differently from the base.

### What is measured

`perf/callgrind-gate.sh measure` starts one proxy per workload under
`valgrind --tool=callgrind`, with one async worker (`VERICTO_WORKER_THREADS=1`).
The driver (`examples/perf_gate.rs`) connects through it, runs a warm-up, asks
callgrind for a dump (`callgrind_control -d`), runs the measured statements one
at a time (each waits for its answer), and asks for a second dump. The second
dump holds exactly what those statements cost the proxy in user-space
instructions, on every thread (the async worker, the evaluation pool, the
telemetry threads), without process startup, connection set-up or warm-up. The
figure reported is that count divided by the number of statements.

| dialect | workload | statements |
|---|---|---|
| pg, mysql | `trivial` | `BEGIN`, `SELECT 1`, `COMMIT`, simple query / COM_QUERY |
| pg | `oltp_simple` | a pgbench TPC-B transaction (7 statements), literals in the text |
| pg | `oltp_extended` | the same with parameters, unnamed statements (Parse/Bind/Execute/Sync each) |
| pg | `oltp_prepared` | the same through named prepared statements (Bind/Execute only) |
| mysql | `oltp_text` | the TPC-B transaction over COM_QUERY |
| mysql | `oltp_prepared` | the same over COM_STMT_EXECUTE (BEGIN/COMMIT as text) |
| pg, mysql | `large_result` | 2,000 rows (about 200 KB) per statement |
| pg, mysql | `connect` | a new connection per statement (start-up, authentication, one `SELECT 1`, close) |
| pg, mysql | `policy_mix` | masked column, join, writes, a business-policy block, a DELETE without WHERE, an allowlist refusal (VERICTO-087), with sanitized telemetry |
| pg, mysql | `trivial_cp` | `trivial` with the control plane of `policy_mix` |

The `policy_mix` and `trivial_cp` workloads run against a local control plane
(`perf_gate stub`): the built-in rules plus a business policy, an e-mail mask,
an enforced agent-access allowlist and sanitized telemetry, signed with a key
generated for the run (`VERICTO_POLICY_RULES=enforce`). Telemetry stays in
memory during the measurement (one batch, flush interval of an hour), so no
export runs mid-workload and the count stays deterministic.

Every run also prints an outcome digest per workload: a hash of every measured
statement's answer (row count, or SQLSTATE / MySQL error code and message). A
head whose digest differs from the base's answered some statement differently,
which fails the gate even when it is faster. A pull request that changes an
answer on purpose (a new rule, a reworded message) carries the
`perf-gate:outcome-change` label and re-runs the job; the table then reports the
difference without failing.

### Threshold

`PERF_GATE_THRESHOLD_PCT`, default **3** (percent, per workload; a repository
variable of the same name overrides it in CI).

- Repeated runs of the same build differ by at most 0.3% per workload (two runs
  of 4.18.0, all 13 statement workloads, and of the `connect` workloads,
  2026-10-26), so 3% is ten times the noise floor and does not fail at random.
- 3% is the CPU-per-transaction criterion of the EC2 release gate. A change the
  gate lets through can still fail that criterion through kernel time
  (callgrind does not count system calls), but one that costs 3% more user-space
  instructions would fail it in any case, and is caught here before the bench.
- It catches the regression of #89 (4.17.1): 4.17.0 -> 4.17.1 measures +15.7%
  on `pg oltp_extended`, +132.9% on `pg oltp_prepared`, +11.9% on `pg trivial`,
  +4.3% on `pg oltp_simple` and +1,683% on `pg large_result`, every one of them
  over the threshold.

What it does not see: system calls and context switches (count them with
`strace -f -c`, see below), contention between connections, and anything that
depends on the CPU or the allocator's behaviour under memory pressure. The EC2
bench (`vericto-bench`) remains the release gate.

### Running it locally

Linux (valgrind does not run on macOS; on a Mac, run it in a Linux container),
with PostgreSQL and MySQL reachable:

```sh
docker run -d --name perf-pg -p 5432:5432 -e POSTGRES_USER=bench -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=bench postgres:17
docker run -d --name perf-my -p 3306:3306 -e MYSQL_ROOT_PASSWORD=bench -e MYSQL_DATABASE=bench -e MYSQL_USER=bench -e MYSQL_PASSWORD=bench mysql:8.0

cargo build --release --locked --bin vericto-proxy --example perf_gate
target/release/examples/perf_gate setup --dialect pg --url "host=127.0.0.1 user=bench password=bench dbname=bench"
target/release/examples/perf_gate setup --dialect mysql --url "mysql://bench:bench@127.0.0.1:3306/bench"
cp target/release/vericto-proxy /tmp/head

git worktree add /tmp/proxy-base origin/main
cargo build --release --locked --bin vericto-proxy --manifest-path /tmp/proxy-base/Cargo.toml --target-dir target
cp target/release/vericto-proxy /tmp/base

export PERF_DRIVER=target/release/examples/perf_gate
perf/callgrind-gate.sh measure /tmp/base /tmp/base.jsonl
perf/callgrind-gate.sh measure /tmp/head /tmp/head.jsonl
perf/callgrind-gate.sh compare /tmp/base.jsonl /tmp/head.jsonl
```

`PERF_WORKLOADS="oltp_extended policy_mix"` and `PERF_DIALECTS=pg` narrow a run;
`PERF_WORK=dir` keeps the callgrind files (`dir/<dialect>-<workload>/cg.out.2`
is the measured dump; `callgrind_annotate` reads it, best with a build that has
line tables: `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`). If
`callgrind_control` cannot reach the proxy, allow ptrace
(`sudo sysctl -w kernel.yama.ptrace_scope=0`, or run as root in a container
with `--cap-add SYS_PTRACE`). The whole run takes under a minute per build.

System calls per statement, which callgrind does not count: run the proxy under
`strace -f -c -o out` with the driver at two statement counts and take the
difference.
