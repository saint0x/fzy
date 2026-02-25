#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
TRACE_PATH="$ARTIFACT_DIR/production-gate.trace.fozzy"
MEM_TRACE_PATH="$ARTIFACT_DIR/production-memory.trace.fozzy"
UNSAFE_BUDGET="${UNSAFE_BUDGET:-0}"
UNSAFE_AUDIT_TARGET="${UNSAFE_AUDIT_TARGET:-examples/fullstack}"

if command -v fz >/dev/null 2>&1; then
  FZ_CMD=(fz)
else
  FZ_CMD=(cargo run -q -p fz --)
fi

mkdir -p "$ARTIFACT_DIR"

echo "[gate] deterministic doctor"
fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null

echo "[gate] language primitive drift gate"
python3 ./scripts/language_primitive_drift_gate.py >/dev/null

echo "[gate] deterministic strict tests"
fozzy test --det --strict tests/*.fozzy.json --seed "$SEED" --json >/dev/null

echo "[gate] primitive parity/equivalence probes"
"${FZ_CMD[@]}" parity tests/fixtures/primitive_parity/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence tests/fixtures/primitive_parity/main.fzy --seed "$SEED" --json >/dev/null

echo "[gate] deterministic memory doctor/tests"
fozzy doctor --deep --scenario tests/memory_graph_diff_top.pass.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null
fozzy test --det --strict tests/memory_graph_diff_top.pass.fozzy.json --seed "$SEED" --json >/dev/null

echo "[gate] record deterministic trace"
fozzy run tests/example.fozzy.json --det --seed "$SEED" --record "$TRACE_PATH" --record-collision overwrite --json >/dev/null

echo "[gate] trace verify/replay/ci"
fozzy trace verify "$TRACE_PATH" --strict --json >/dev/null
fozzy replay "$TRACE_PATH" --json >/dev/null
fozzy ci "$TRACE_PATH" --json >/dev/null

echo "[gate] memory trace record/verify/replay/ci"
fozzy run tests/memory_graph_diff_top.pass.fozzy.json --det --seed "$SEED" --record "$MEM_TRACE_PATH" --record-collision overwrite --json >/dev/null
fozzy trace verify "$MEM_TRACE_PATH" --strict --json >/dev/null
fozzy replay "$MEM_TRACE_PATH" --json >/dev/null
fozzy ci "$MEM_TRACE_PATH" --json >/dev/null

echo "[gate] host-backed run"
fozzy run tests/runtime.bind_json_env.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null
fozzy run tests/memory_graph_diff_top.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null
fozzy run tests/primitive.host_operators.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null

echo "[gate] host-backed C interop matrix"
fozzy run tests/c_ffi_matrix.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null

echo "[gate] full command-surface checks"
fozzy fuzz scenario:tests/example.fozzy.json --mode coverage --runs 5 --seed "$SEED" --json >/dev/null
fozzy explore tests/distributed.pass.fozzy.json --schedule coverage_guided --steps 10 --seed "$SEED" --json >/dev/null
fozzy shrink "$TRACE_PATH" --json >/dev/null
fozzy artifacts ls latest --json >/dev/null
fozzy report show latest --format json --json >/dev/null
fozzy env --json >/dev/null
fozzy usage --json >/dev/null
./scripts/lsp_editor_smoke.sh >/dev/null
./scripts/lsp_determinism_smoke.sh >/dev/null

echo "[gate] tooling DX strict smokes"
RUSTFLAGS="-D warnings" cargo check -p driver --all-targets >/dev/null
cargo run -q -p fozzyfmt -- examples/fullstack/src examples/robust_cli/src --check >/dev/null
cargo run -q -p fozzydoc -- examples/fullstack/src --format markdown --out "$ARTIFACT_DIR/fullstack.api.md" >/dev/null
test -s "$ARTIFACT_DIR/fullstack.api.md"

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

echo "[gate] unsafe budget gate"
UNSAFE_JSON="$("${FZ_CMD[@]}" audit unsafe "$UNSAFE_AUDIT_TARGET" --json)"
python3 - <<'PY' "$UNSAFE_JSON" "$UNSAFE_BUDGET"
import json, sys
payload = json.loads(sys.argv[1])
budget = int(sys.argv[2])
count = len(payload.get("entries", []))
missing = int(payload.get("missingReasonCount", 0))
print(f"unsafe_entries={count} missing_reason={missing} budget={budget}")
if missing > 0:
    raise SystemExit(2)
if count > budget:
    raise SystemExit(3)
PY

echo "[gate] PASS"
