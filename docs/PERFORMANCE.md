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

## Allocator

Since 4.19.0 the proxy is built with [mimalloc](https://github.com/microsoft/mimalloc)
as its global allocator (the default `mimalloc` cargo feature;
`cargo build --release --no-default-features` keeps the system allocator). The
image is glibc-based (Chainguard `glibc-dynamic`), so the comparison is against
glibc's malloc; there is no musl build.

Measured with the callgrind gate on the same code (2026-10-26, linux/arm64,
instructions per statement, change against glibc):

| workload | mimalloc | jemalloc (tikv-jemallocator 0.6) |
|---|---:|---:|
| pg trivial | -2.2% | -2.9% |
| pg oltp_simple / oltp_extended | -2.9% / -3.3% | -3.3% / -3.6% |
| pg oltp_prepared | -0.3% | -2.6% |
| pg large_result | -2.1% | -2.8% |
| pg policy_mix / trivial_cp | -14.9% / -10.8% | -15.1% / -10.0% |
| mysql trivial | -8.3% | -8.5% |
| mysql oltp_text / oltp_prepared | -14.0% / -6.7% | -11.3% / -6.4% |
| mysql large_result | -15.3% | -16.9% |
| mysql policy_mix / trivial_cp | -28.2% / -17.0% | -26.5% / -16.8% |

Peak resident memory under pgbench / sysbench with 8 and 64 connections and two
workers: glibc 9.1 to 11.1 MB, mimalloc 17.1 to 18.1 MB, jemalloc 10.3 to
12.0 MB.

jemalloc and mimalloc save about the same instructions. mimalloc was chosen: it
builds with the C compiler alone (jemalloc needs `make` and its configure script in
the builder image) and its sources are MIT like the crate, while the jemalloc
sources tikv-jemalloc-sys bundles are BSD-2-Clause, a license the dependency policy
(`deny.toml`, `third-party/about.toml`) does not list and the crate's own
`MIT/Apache-2.0` metadata does not declare. The cost is about 7 MB more resident
memory per process, which no supported task size notices.

## TLS

What a TLS connection costs and the settings that change it are in
[CONFIGURATION.md, "Certificates, resumption and TLS cost"](CONFIGURATION.md#certificates-resumption-and-tls-cost).
The measurements behind it: an in-process rustls benchmark (handshake server and
client side, resumed handshakes with tickets and with the session cache, 64 MiB
of 16 KiB records encrypted and decrypted), both providers, ECDSA P-256 and
RSA-2048 certificates, best of 9 rounds of 300 handshakes on linux/arm64; and the
`connect` workload of the gate (a connection per statement) with
`PERF_PROXY_ENV="UPSTREAM_SSLMODE=require"` against a PostgreSQL with `ssl=on`,
and with TLS on both MySQL hops (`PERF_CLIENT_TLS=1`,
`PROXY_TLS_MODE=require`).

### Kernel TLS (not implemented)

kTLS hands the record layer of an established connection to the kernel: after
the handshake, user space installs the traffic keys on the socket
(`setsockopt(SOL_TLS, TLS_TX / TLS_RX)`) and then reads and writes plaintext; the
kernel encrypts and decrypts, and with a NIC that supports TLS offload, the NIC
does. What it would take here:

- **Library support.** rustls exports the secrets for it
  (`ServerConfig::enable_secret_extraction`,
  `Connection::dangerous_extract_secrets`), but the proxy would own the
  `setsockopt` calls (`unsafe`, which the crate forbids today, or a dependency
  such as `ktls` that does it) and the sequence numbers.
- **What the kernel cannot do.** TLS 1.3 KeyUpdate and post-handshake messages
  (session tickets, which the listener sends) arrive as control records that
  user space must handle with `recvmsg` and `cmsg`; rustls expects to see them.
  TLS 1.3 RX offload needs Linux 5.10 or later, and the cipher suite must be one
  the kernel has (AES-GCM, ChaCha20-Poly1305 since 5.11).
- **Where it applies.** Only to the hop the proxy relays without reading: the
  database to client direction of large results. Every frontend message must
  still be decrypted in user space, because it is parsed and evaluated. The
  relay copies the response bytes once; with kTLS on both sockets of that
  direction (and `splice` between them) the copy goes away and the AES-GCM work
  moves to the kernel or, with offload, to the NIC.
- **Expected gain.** Measured with the gate's `large_result` workload on MySQL
  (2,000 rows, about 200 KB per statement): 133,000 user-space instructions per
  statement in plaintext, 1,550,000 with TLS on both hops. Decrypting the
  database's records and encrypting them again for the client is about 90% of
  what a large result costs the proxy. Software kTLS moves that work into the
  kernel rather than removing it (the kernel's AES-GCM uses the same CPU
  instructions), so its gain is the user-space copy and some system calls, a few
  percent; only a NIC with TLS offload takes the cryptography off the CPU, and
  then the gain on large results approaches that 90%. For OLTP traffic (small
  responses) the gain is negligible either way.
- **Risk.** A second code path for every read and write of a TLS session, kernel
  version and NIC dependent, in the component that terminates customers'
  database traffic.

Worth doing only if large-result traffic over TLS on both hops becomes the
dominant cost of a deployment; the EC2 bench can measure it with `large_result`
and TLS on both hops first.
