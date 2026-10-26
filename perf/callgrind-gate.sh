#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Instructions per statement of a vericto-proxy build, under callgrind, on the
# corpus of examples/perf_gate.rs (docs/PERFORMANCE.md, "CI performance gate").
#
#   perf/callgrind-gate.sh measure PROXY_BIN OUT.jsonl
#       one line per workload: user-space instructions per statement (Ir), the
#       statement count and the outcome digest
#   perf/callgrind-gate.sh compare BASE.jsonl HEAD.jsonl
#       a Markdown table (to stdout and $GITHUB_STEP_SUMMARY when set); exit 1 when
#       a workload's Ir per statement grows by more than PERF_GATE_THRESHOLD_PCT,
#       or its outcome digest differs (the head answered a statement differently)
#       unless PERF_GATE_ALLOW_OUTCOME_CHANGE=1
#
# Every workload runs against its own proxy process under callgrind, with one
# async worker (VERICTO_WORKER_THREADS=1). The driver connects, runs a warm-up,
# asks callgrind for a dump, runs the measured statements one at a time, asks for
# another dump: the second dump holds exactly the instructions those statements
# cost, on every thread of the proxy (evaluation pool and telemetry included),
# without startup, connection set-up or warm-up.
#
# Environment (defaults in brackets):
#   PERF_DRIVER              the perf_gate example binary [target/release/examples/perf_gate]
#   PERF_PG_HOST/PORT        PostgreSQL for the pg workloads [127.0.0.1/5432]
#   PERF_MYSQL_HOST/PORT     MySQL for the mysql workloads [127.0.0.1/3306]
#   PERF_DIALECTS            "pg mysql" [both]
#   PERF_WORKLOADS           only these workload names [all]
#   PERF_SCALE               multiplies every statement count [1]
#   PERF_GATE_THRESHOLD_PCT  allowed growth of Ir per statement, percent [3]
#   PERF_GATE_ALLOW_OUTCOME_CHANGE=1  report a different outcome digest without failing
#   PERF_STUB_ARGS           extra arguments of the stub, e.g. "--telemetry raw" []
#   PERF_PROXY_ENV           extra proxy settings, e.g. "VERICTO_INLINE_EVAL_MAX_BYTES=0" []
#   PERF_CLIENT_TLS=1        the MySQL driver connects with TLS (needs PROXY_TLS_* in PERF_PROXY_ENV)
#   PERF_WORK                scratch directory [a mktemp -d, removed at exit]
set -euo pipefail

die() { echo "callgrind-gate: $*" >&2; exit 2; }

# workload  warm-up  measured statements (cycles of the workload's statements)
counts() {
  case "$1" in
    trivial|trivial_cp) echo "30 600" ;;
    oltp_simple|oltp_extended|oltp_prepared|oltp_text) echo "70 700" ;;
    large_result) echo "2 20" ;;
    connect) echo "3 60" ;;
    policy_mix) echo "40 400" ;;
    *) die "no counts for workload $1" ;;
  esac
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_port() { # port seconds
  local i
  for ((i = 0; i < $2 * 10; i++)); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

measure() {
  local bin=$1 out=$2
  [ -x "$bin" ] || die "not an executable: $bin"
  local driver=${PERF_DRIVER:-target/release/examples/perf_gate}
  [ -x "$driver" ] || die "driver not built: $driver (cargo build --release --example perf_gate)"
  command -v valgrind >/dev/null || die "valgrind is not installed"
  work=${PERF_WORK:-}
  own_work=
  if [ -z "$work" ]; then work=$(mktemp -d); own_work=1; fi
  mkdir -p "$work"
  : > "$out"
  local scale=${PERF_SCALE:-1}
  stub_pid= proxy_pid=
  cleanup() {
    [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true
    [ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    if [ -n "$own_work" ]; then rm -rf "$work"; fi
    return 0
  }
  trap cleanup EXIT

  local line dialect name cp
  while read -r dialect name cp; do
    case " ${PERF_DIALECTS:-pg mysql} " in *" $dialect "*) ;; *) continue ;; esac
    if [ -n "${PERF_WORKLOADS:-}" ]; then
      case " $PERF_WORKLOADS " in *" $name "*) ;; *) continue ;; esac
    fi
    read -r warm count < <(counts "$name")
    warm=$((warm * scale)); count=$((count * scale))
    local port; port=$(free_port)
    local dir="$work/$dialect-$name"; rm -rf "$dir"; mkdir -p "$dir"
    local -a env=(
      RUST_LOG=error VERICTO_WORKER_THREADS=1 PROXY_LISTEN_PORT="$port"
    )
    # Extra proxy settings for a local experiment, e.g. "VERICTO_INLINE_EVAL_MAX_BYTES=0".
    if [ -n "${PERF_PROXY_ENV:-}" ]; then read -r -a extra <<<"$PERF_PROXY_ENV"; env+=("${extra[@]}"); fi
    if [ "$dialect" = pg ]; then
      env+=(VERICTO_WIRE_PROTOCOL=postgres UPSTREAM_HOST="${PERF_PG_HOST:-127.0.0.1}" UPSTREAM_PORT="${PERF_PG_PORT:-5432}")
    else
      env+=(VERICTO_WIRE_PROTOCOL=mysql UPSTREAM_HOST="${PERF_MYSQL_HOST:-127.0.0.1}" UPSTREAM_PORT="${PERF_MYSQL_PORT:-3306}")
    fi
    local hz=
    if [ "$cp" = 1 ]; then
      local cp_port; cp_port=$(free_port)
      "$driver" stub --listen "127.0.0.1:$cp_port" --keys-out "$dir/keys.json" ${PERF_STUB_ARGS:-} 2>"$dir/stub.log" &
      stub_pid=$!
      wait_port "$cp_port" 30 || die "the control-plane stub did not start"
      hz=$(free_port)
      # Telemetry stays in memory during the measurement: one batch holds all of
      # it and the flush interval is far away, so no export runs mid-workload.
      env+=(
        VERICTO_API_URL="http://127.0.0.1:$cp_port" VERICTO_ALLOW_INSECURE_API_URL=true
        VERICTO_API_KEY=vk_perf_gate VERICTO_DATABASE_ID=00000000-0000-0000-0000-000000000001
        VERICTO_POLICY_RULES=enforce VERICTO_BUNDLE_SIGNING_KEYS_FILE="$dir/keys.json"
        VERICTO_RULES_CACHE_PATH="$dir/rules-cache.json" VERICTO_RULES_SYNC_INTERVAL_SECS=3600
        VERICTO_TELEMETRY_BUFFER=memory VERICTO_TELEMETRY_MEMORY_CAPACITY=100000
        VERICTO_TELEMETRY_BATCH_SIZE=500 VERICTO_TELEMETRY_FLUSH_SECS=3600
        VERICTO_HEALTHZ_PORT="$hz" VERICTO_HEALTHZ_ADDR=127.0.0.1
      )
    fi
    env "${env[@]}" valgrind --tool=callgrind --callgrind-out-file="$dir/cg.out" \
      "$bin" >"$dir/proxy.log" 2>&1 &
    proxy_pid=$!
    wait_port "$port" 120 || { cat "$dir/proxy.log" >&2; die "$dialect proxy did not listen"; }
    # With a control plane the health listener binds after the first sync.
    if [ -n "$hz" ]; then
      wait_port "$hz" 120 || { cat "$dir/proxy.log" >&2; die "no first sync"; }
    fi
    "$driver" run --dialect "$dialect" --addr "127.0.0.1:$port" --workload "$name" \
      --warmup "$warm" --count "$count" \
      --mark "callgrind_control -d $proxy_pid >/dev/null 2>&1" >"$dir/run.json"
    kill -TERM "$proxy_pid"; wait "$proxy_pid" 2>/dev/null || true; proxy_pid=
    if [ -n "$stub_pid" ]; then kill "$stub_pid"; wait "$stub_pid" 2>/dev/null || true; stub_pid=; fi
    [ -f "$dir/cg.out.2" ] || die "$dialect $name: no measured dump"
    local ir; ir=$(sed -n 's/^totals: //p' "$dir/cg.out.2")
    python3 - "$dir/run.json" "$ir" >>"$out" <<'PY'
import json, sys
run = json.load(open(sys.argv[1]))
run["ir_total"] = int(sys.argv[2])
run["ir_per_stmt"] = round(run["ir_total"] / run["count"], 1)
print(json.dumps(run, sort_keys=True))
PY
    tail -n 1 "$out"
  done < <("$driver" list)
}

compare() {
  python3 - "$1" "$2" "${PERF_GATE_THRESHOLD_PCT:-3}" <<'PY'
import json, os, sys
def load(p):
    return {(r["dialect"], r["workload"]): r for r in map(json.loads, open(p)) if r}
base, head, limit = load(sys.argv[1]), load(sys.argv[2]), float(sys.argv[3])
allow_outcome_change = os.environ.get("PERF_GATE_ALLOW_OUTCOME_CHANGE") == "1"
rows, failed = [], []
for key in sorted(set(base) | set(head)):
    b, h = base.get(key), head.get(key)
    if not b or not h:
        rows.append(f"| {key[0]} | {key[1]} | {b and b['ir_per_stmt']} | {h and h['ir_per_stmt']} | n/a | missing |")
        failed.append(f"{key}: missing on one side")
        continue
    delta = (h["ir_per_stmt"] - b["ir_per_stmt"]) / b["ir_per_stmt"] * 100
    verdict = "ok"
    if delta > limit:
        verdict = f"**regression > {limit:g}%**"
        failed.append(f"{key}: +{delta:.2f}%")
    if b["digest"] != h["digest"] or b["count"] != h["count"]:
        if allow_outcome_change:
            verdict += " (outcomes differ: allowed)"
        else:
            verdict = "**outcomes differ**"
            failed.append(f"{key}: outcome digest {b['digest']} -> {h['digest']}")
    rows.append(f"| {key[0]} | {key[1]} | {b['ir_per_stmt']:,.0f} | {h['ir_per_stmt']:,.0f} | {delta:+.2f}% | {verdict} |")
out = [f"### Instructions per statement (callgrind), threshold +{limit:g}%", "",
       "| dialect | workload | base | head | change | |", "|---|---|---:|---:|---:|---|", *rows]
text = "\n".join(out) + "\n"
print(text)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        f.write(text)
if failed:
    print("callgrind-gate: FAILED: " + "; ".join(failed), file=sys.stderr)
    sys.exit(1)
PY
}

case "${1:-}" in
  measure) [ $# -eq 3 ] || die "usage: $0 measure PROXY_BIN OUT.jsonl"; measure "$2" "$3" ;;
  compare) [ $# -eq 3 ] || die "usage: $0 compare BASE.jsonl HEAD.jsonl"; compare "$2" "$3" ;;
  *) die "usage: $0 measure PROXY_BIN OUT.jsonl | compare BASE.jsonl HEAD.jsonl" ;;
esac
