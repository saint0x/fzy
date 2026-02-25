#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
TRACE_PATH="$ARTIFACT_DIR/production-gate.trace.fozzy"

mkdir -p "$ARTIFACT_DIR"

echo "[gate] deterministic doctor"
fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null

echo "[gate] deterministic strict tests"
fozzy test --det --strict tests/*.fozzy.json --seed "$SEED" --json >/dev/null

echo "[gate] record deterministic trace"
fozzy run tests/example.fozzy.json --det --seed "$SEED" --record "$TRACE_PATH" --record-collision overwrite --json >/dev/null

echo "[gate] trace verify/replay/ci"
fozzy trace verify "$TRACE_PATH" --strict --json >/dev/null
fozzy replay "$TRACE_PATH" --json >/dev/null
fozzy ci "$TRACE_PATH" --json >/dev/null

echo "[gate] host-backed run"
fozzy run tests/runtime.bind_json_env.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null

echo "[gate] full command-surface checks"
fozzy fuzz scenario:tests/example.fozzy.json --mode coverage --runs 5 --seed "$SEED" --json >/dev/null
fozzy explore tests/distributed.pass.fozzy.json --schedule coverage_guided --steps 10 --seed "$SEED" --json >/dev/null
fozzy shrink "$TRACE_PATH" --json >/dev/null
fozzy artifacts ls latest --json >/dev/null
fozzy report show latest --format json --json >/dev/null
fozzy env --json >/dev/null
fozzy usage --json >/dev/null

echo "[gate] pedantic topology closure"
MAP_JSON="$(fozzy map suites --root . --scenario-root tests --profile pedantic --json)"
python3 - <<'PY' "$MAP_JSON"
import json, sys
payload = json.loads(sys.argv[1])
uncovered = int(payload.get("uncoveredHotspotCount", 0))
required = int(payload.get("requiredHotspotCount", 0))
print(f"requiredHotspotCount={required} uncoveredHotspotCount={uncovered}")
if uncovered != 0:
    raise SystemExit(2)
PY

echo "[gate] PASS"
