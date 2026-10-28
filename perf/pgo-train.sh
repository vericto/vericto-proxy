#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Trains the profile of a profile-guided (PGO) release build on the corpus of the
# performance gate (docs/PERFORMANCE.md, "PGO").
#
#   perf/pgo-train.sh INSTRUMENTED_PROXY OUT.profdata
#
# INSTRUMENTED_PROXY is a release build with -Cprofile-generate. Every workload of
# examples/perf_gate.rs runs against it natively, a proxy per dialect and
# control-plane setting (two async workers), then llvm-profdata merges what the
# proxies wrote. Needs the llvm-tools rustup component and the corpus tables
# (`perf_gate setup`).
#
# Environment: PERF_DRIVER, PERF_PG_HOST/PORT, PERF_MYSQL_HOST/PORT as for
# perf/callgrind-gate.sh; PERF_PGO_STATEMENTS statements per workload [3000].
set -euo pipefail

die() { echo "pgo-train: $*" >&2; exit 2; }
[ $# -eq 2 ] || die "usage: $0 INSTRUMENTED_PROXY OUT.profdata"
bin=$1 out=$2
[ -x "$bin" ] || die "not an executable: $bin"
driver=${PERF_DRIVER:-target/release/examples/perf_gate}
[ -x "$driver" ] || die "driver not built: $driver"
profdata="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-profdata"
[ -x "$profdata" ] || die "llvm-profdata not found (rustup component add llvm-tools)"
statements=${PERF_PGO_STATEMENTS:-3000}

work=$(mktemp -d)
proxy_pid= stub_pid=
cleanup() {
  [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true
  [ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
wait_port() {
  local i
  for ((i = 0; i < $2 * 10; i++)); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# The driver may be instrumented too (built in the same cargo invocation): what
# it writes goes elsewhere and is not merged.
export LLVM_PROFILE_FILE="$work/driver/%p-%m.profraw"

for dialect in pg mysql; do
  for cp in 0 1; do
    port=$(free_port)
    env=(RUST_LOG=error VERICTO_WORKER_THREADS=2 PROXY_LISTEN_PORT="$port"
         LLVM_PROFILE_FILE="$work/proxy/%p-%m.profraw")
    if [ "$dialect" = pg ]; then
      env+=(VERICTO_WIRE_PROTOCOL=postgres UPSTREAM_HOST="${PERF_PG_HOST:-127.0.0.1}" UPSTREAM_PORT="${PERF_PG_PORT:-5432}")
    else
      env+=(VERICTO_WIRE_PROTOCOL=mysql UPSTREAM_HOST="${PERF_MYSQL_HOST:-127.0.0.1}" UPSTREAM_PORT="${PERF_MYSQL_PORT:-3306}")
    fi
    hz=
    if [ "$cp" = 1 ]; then
      cp_port=$(free_port) hz=$(free_port)
      "$driver" stub --listen "127.0.0.1:$cp_port" --keys-out "$work/keys.json" 2>/dev/null &
      stub_pid=$!
      wait_port "$cp_port" 30 || die "the control-plane stub did not start"
      env+=(VERICTO_API_URL="http://127.0.0.1:$cp_port" VERICTO_ALLOW_INSECURE_API_URL=true
            VERICTO_API_KEY=vk_pgo VERICTO_DATABASE_ID=00000000-0000-0000-0000-000000000001
            VERICTO_POLICY_RULES=enforce VERICTO_BUNDLE_SIGNING_KEYS_FILE="$work/keys.json"
            VERICTO_RULES_CACHE_PATH="$work/rules-cache.json" VERICTO_TELEMETRY_BUFFER=memory
            VERICTO_HEALTHZ_PORT="$hz" VERICTO_HEALTHZ_ADDR=127.0.0.1)
    fi
    env "${env[@]}" "$bin" >"$work/proxy.log" 2>&1 &
    proxy_pid=$!
    wait_port "$port" 60 || { cat "$work/proxy.log" >&2; die "$dialect proxy did not listen"; }
    if [ -n "$hz" ]; then wait_port "$hz" 60 || die "no first sync"; fi
    while read -r d name c; do
      [ "$d" = "$dialect" ] && [ "$c" = "$cp" ] || continue
      n=$statements
      case "$name" in large_result) n=$((statements / 30)) ;; connect) n=$((statements / 15)) ;; esac
      "$driver" run --dialect "$dialect" --addr "127.0.0.1:$port" --workload "$name" \
        --warmup 0 --count "$n" >/dev/null
    done < <("$driver" list)
    # SIGTERM: the proxy exits through exit(), which writes the profile.
    kill -TERM "$proxy_pid"; wait "$proxy_pid" 2>/dev/null || true; proxy_pid=
    if [ -n "$stub_pid" ]; then kill "$stub_pid"; wait "$stub_pid" 2>/dev/null || true; stub_pid=; fi
  done
done

ls "$work"/proxy/*.profraw >/dev/null 2>&1 || die "the proxy wrote no profile (built with -Cprofile-generate?)"
mkdir -p "$(dirname "$out")"
"$profdata" merge -o "$out" "$work"/proxy/*.profraw
echo "pgo-train: $(ls "$work"/proxy/*.profraw | wc -l) profiles merged into $out"
