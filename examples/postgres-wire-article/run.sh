#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)

if [[ ${1:-} == --list ]]; then
  command -v python3 >/dev/null || { echo 'error: python3 is required' >&2; exit 2; }
  PG17_PROXY_PORT=1 PG17_TLS_DISTINCT_PORT=1 PG17_TLS_SHARED_PORT=1 \
    PG17_REFRESH_PORT=1 PG18_PROXY_PORT=1 PG_PASSWORD=list \
    CONTROL_ADMIN_URL=http://127.0.0.1:1 CONTROL_STATUS_FILE=/dev/null \
    python3 "$HERE/pgwire_repro.py" --jsonl /dev/null --list
  exit 0
fi

POSTGRES17_DEFAULT='postgres:17@sha256:b8faeff7712663c2773a190181e1246e37e364b887611c04658c28b44e2408fe'
POSTGRES18_DEFAULT='postgres:18@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6'
export POSTGRES17_IMAGE=${POSTGRES17_IMAGE:-$POSTGRES17_DEFAULT}
export POSTGRES18_IMAGE=${POSTGRES18_IMAGE:-$POSTGRES18_DEFAULT}
export BUILD_LOCAL=${BUILD_LOCAL:-1}
export RUN_UID=$(id -u)
export RUN_GID=$(id -g)

suffix=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
export COMPOSE_PROJECT_NAME="vericto-wire-${suffix}"
RUN_DIR="$HERE/.run/$COMPOSE_PROJECT_NAME"
export CERT_DIR="$RUN_DIR/certs"
ARTIFACT_DIR="$HERE/artifacts"
RESULTS="$ARTIFACT_DIR/results-${COMPOSE_PROJECT_NAME}.jsonl"
mkdir -p "$CERT_DIR" "$ARTIFACT_DIR"
chmod 0700 "$RUN_DIR" "$CERT_DIR"
export PG_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
LOCAL_IMAGE="${COMPOSE_PROJECT_NAME}-proxy:local"
BUILT_LOCAL=0
CONTROL_PID=
COMPOSE=(docker compose -f "$HERE/compose.yaml" -p "$COMPOSE_PROJECT_NAME")

is_pinned() {
  [[ "$1" =~ @sha256:[0-9a-f]{64}$ ]]
}
require_pinned() {
  local name=$1 value=$2
  if ! is_pinned "$value" && [[ ${ALLOW_UNPINNED:-0} != 1 ]]; then
    printf 'error: %s must end in @sha256:<64 hex>; set ALLOW_UNPINNED=1 to opt out\n' "$name" >&2
    exit 2
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ ${KEEP:-0} == 1 || ( $rc -ne 0 && ${KEEP_ON_FAIL:-0} == 1 ) ]]; then
    printf '[KEEP] project=%s run_dir=%s results=%s\n' "$COMPOSE_PROJECT_NAME" "$RUN_DIR" "$RESULTS" >&2
  else
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    if [[ -n $CONTROL_PID ]]; then
      kill "$CONTROL_PID" >/dev/null 2>&1 || true
      wait "$CONTROL_PID" 2>/dev/null || true
    fi
    if [[ $BUILT_LOCAL == 1 ]]; then
      docker image rm "$LOCAL_IMAGE" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$RUN_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null || { echo 'error: docker is required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'error: python3 is required' >&2; exit 2; }
docker compose version >/dev/null
docker info >/dev/null
require_pinned POSTGRES17_IMAGE "$POSTGRES17_IMAGE"
require_pinned POSTGRES18_IMAGE "$POSTGRES18_IMAGE"

if [[ "$BUILD_LOCAL" == 1 ]]; then
  export PROXY_IMAGE="$LOCAL_IMAGE"
  printf '[BUILD] %s from %s\n' "$PROXY_IMAGE" "$ROOT"
  docker build --tag "$PROXY_IMAGE" "$ROOT"
  BUILT_LOCAL=1
else
  : "${VERICTO_IMAGE:?set VERICTO_IMAGE to a published proxy image when BUILD_LOCAL=0}"
  require_pinned VERICTO_IMAGE "$VERICTO_IMAGE"
  export PROXY_IMAGE=$VERICTO_IMAGE
fi

# PostgreSQL's pinned image supplies OpenSSL; no host crypto package is needed.
printf '[CERT] generating one-day test certificates under %s\n' "$CERT_DIR"
docker run --rm --user "$RUN_UID:$RUN_GID" -v "$CERT_DIR:/out" "$POSTGRES17_IMAGE" \
  bash -euc '
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
      -subj /CN=pg17 -addext subjectAltName=DNS:pg17,DNS:proxy-tls-shared \
      -addext basicConstraints=CA:FALSE \
      -keyout /out/shared.key -out /out/shared.crt >/dev/null 2>&1
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
      -subj /CN=proxy-distinct -addext subjectAltName=DNS:proxy-tls-distinct \
      -addext basicConstraints=CA:FALSE \
      -keyout /out/distinct.key -out /out/distinct.crt >/dev/null 2>&1
    openssl genpkey -algorithm ED25519 -out /out/bundle-signing.key
    openssl pkey -in /out/bundle-signing.key -pubout -out /out/bundle-signing.pub
    chmod 0600 /out/shared.key /out/distinct.key /out/bundle-signing.key
    chmod 0644 /out/shared.crt /out/distinct.crt /out/bundle-signing.pub
  '
key_mode() {
  if [[ $(uname -s) == Darwin ]]; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}
[[ $(key_mode "$CERT_DIR/shared.key") == 600 ]]
[[ $(key_mode "$CERT_DIR/distinct.key") == 600 ]]
[[ $(key_mode "$CERT_DIR/bundle-signing.key") == 600 ]]

CONTROL_DIR="$RUN_DIR/control"
mkdir -p "$CONTROL_DIR"
chmod 0700 "$CONTROL_DIR"
python3 - "$CERT_DIR" "$CONTROL_DIR" <<'PY'
import hashlib, json, sys
from pathlib import Path
keys, out = map(Path, sys.argv[1:])
common = {"rules": [], "policy": {"severity_actions": {}, "parse_error_action": "allow_report"}}
bodies = {
    "allow": {**common, "version": "article-allow-v1", "agent_access": {}},
    "deny": {
        **common,
        "version": "article-deny-v1",
        "agent_access": {"postgres": {"mode": "enforce", "ddl": "deny", "entries": []}},
    },
}
for name, value in bodies.items():
    body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    (out / f"{name}.json").write_bytes(body)
    (out / f"{name}.digest").write_bytes(hashlib.sha256(b"vericto-sync-bundle/1\n" + body).digest())
public_key = (keys / "bundle-signing.pub").read_text()
(keys / "bundle-signing-keys.json").write_text(json.dumps([
    {"key_id": "article-ephemeral", "public_key": public_key}
]))
PY
for state in allow deny; do
  docker run --rm --user "$RUN_UID:$RUN_GID" \
    -v "$CERT_DIR:/keys:ro" -v "$CONTROL_DIR:/fixtures" "$POSTGRES17_IMAGE" \
    openssl pkeyutl -sign -rawin -inkey /keys/bundle-signing.key \
      -in "/fixtures/$state.digest" -out "/fixtures/$state.sig"
done
python3 - "$CONTROL_DIR" <<'PY'
import base64, sys
from pathlib import Path
root = Path(sys.argv[1])
for name in ("allow", "deny"):
    digest = (root / f"{name}.digest").read_bytes().hex()
    signature = base64.b64encode((root / f"{name}.sig").read_bytes()).decode()
    (root / f"{name}.header").write_text(
        f"scheme=ed25519-sha256; key-id=article-ephemeral; sha256={digest}; sig={signature}\n"
    )
PY
CONTROL_PORT_FILE="$CONTROL_DIR/port"
CONTROL_STATUS_FILE="$CONTROL_DIR/status.json"
python3 "$HERE/mock_control_plane.py" --fixtures "$CONTROL_DIR" \
  --status-file "$CONTROL_STATUS_FILE" --port-file "$CONTROL_PORT_FILE" &
CONTROL_PID=$!
for _ in $(seq 1 100); do
  [[ -s $CONTROL_PORT_FILE ]] && break
  kill -0 "$CONTROL_PID" 2>/dev/null || { echo 'error: mock control plane exited' >&2; exit 2; }
  sleep 0.05
done
[[ -s $CONTROL_PORT_FILE ]] || { echo 'error: mock control plane did not start' >&2; exit 2; }
CONTROL_PORT=$(cat "$CONTROL_PORT_FILE")
export CONTROL_PLANE_URL="http://host.docker.internal:$CONTROL_PORT"
export CONTROL_ADMIN_URL="http://127.0.0.1:$CONTROL_PORT"
export CONTROL_STATUS_FILE

printf '[UP] project=%s\n' "$COMPOSE_PROJECT_NAME"
"${COMPOSE[@]}" up -d --wait --wait-timeout 180

port_of() {
  "${COMPOSE[@]}" port "$1" 5433 | awk -F: 'END {print $NF}'
}
export PG17_PROXY_PORT=$(port_of proxy)
export PG17_TLS_DISTINCT_PORT=$(port_of proxy-tls-distinct)
export PG17_TLS_SHARED_PORT=$(port_of proxy-tls-shared)
export PG17_REFRESH_PORT=$(port_of proxy-refresh)
export PG18_PROXY_PORT=$(port_of proxy18)

printf '[RUN] JSONL=%s\n' "$RESULTS"
python3 "$HERE/pgwire_repro.py" --jsonl "$RESULTS" "$@"
