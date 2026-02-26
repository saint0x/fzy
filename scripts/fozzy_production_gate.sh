#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
TRACE_PATH="$ARTIFACT_DIR/production-gate.trace.fozzy"
MEM_TRACE_PATH="$ARTIFACT_DIR/production-memory.trace.fozzy"
UNSAFE_BUDGET="${UNSAFE_BUDGET:-0}"
UNSAFE_AUDIT_TARGET="${UNSAFE_AUDIT_TARGET:-.}"
RUST_UNSAFE_BUDGET="${RUST_UNSAFE_BUDGET:-2}"

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

echo "[gate] direct-memory architecture gate"
python3 ./scripts/direct_memory_architecture_gate.py >/dev/null

echo "[gate] direct-memory perf exit gate"
python3 ./scripts/direct_memory_perf_gate.py >/dev/null

echo "[gate] safety claim integrity gate"
python3 ./scripts/safety_claim_integrity_gate.py >/dev/null

echo "[gate] deterministic strict tests"
fozzy test --det --strict tests/*.fozzy.json --seed "$SEED" --json >/dev/null

echo "[gate] primitive parity/equivalence probes"
"${FZ_CMD[@]}" parity tests/fixtures/primitive_parity/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence tests/fixtures/primitive_parity/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/native_completeness/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence tests/fixtures/native_completeness/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/direct_memory_contract/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence tests/fixtures/direct_memory_contract/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/direct_memory_safety/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence tests/fixtures/direct_memory_safety/main.fzy --seed "$SEED" --json >/dev/null

echo "[gate] native completeness execute-and-compare"
cargo test -q -p driver pipeline::tests::cross_backend_native_completeness_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_array_index_lowers_without_data_plane_runtime_calls -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_switch_and_constant_string_chain_lowering_is_parity_safe -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_contract_fixture_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_bounds_probe_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_i64_array_layout_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_string_slice_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_rolling_window_index_executes_consistently -- --exact >/dev/null

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
fozzy run tests/host_backends_run.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null

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
UNSAFE_JSON="$("${FZ_CMD[@]}" audit unsafe "$UNSAFE_AUDIT_TARGET" --workspace --json)"
python3 - <<'PY' "$UNSAFE_JSON" "$UNSAFE_BUDGET"
import json, sys
payload = json.loads(sys.argv[1])
budget = int(sys.argv[2])
count = len(payload.get("entries", []))
missing = int(payload.get("missingContractCount", 0))
invalid = int(payload.get("invalidProofRefCount", 0))
projects = len(payload.get("projects", []))
print(f"unsafe_entries={count} missing_contract={missing} invalid_proof_ref={invalid} projects={projects} budget={budget}")
if missing > 0:
    raise SystemExit(2)
if invalid > 0:
    raise SystemExit(4)
if count > budget:
    raise SystemExit(3)
PY

echo "[gate] rust unsafe inventory gate"
python3 ./scripts/rust_unsafe_inventory.py --root "$ROOT" --out "$ARTIFACT_DIR/rust_unsafe_inventory.json" --budget "$RUST_UNSAFE_BUDGET" --policy "$ROOT/policy/rust_unsafe_islands.json"

echo "[gate] ffi abi compatibility gate"
while IFS= read -r manifest; do
  project_root="$(dirname "$(dirname "$manifest")")"
  project_name="$(basename "$project_root")"
  gen_dir="$ARTIFACT_DIR/abi/$project_name"
  mkdir -p "$gen_dir"
  gen_header="$gen_dir/${project_name}.h"
  "${FZ_CMD[@]}" headers "$project_root" --out "$gen_header" >/dev/null
  gen_abi="${gen_header%.h}.abi.json"
  "${FZ_CMD[@]}" abi-check "$gen_abi" --baseline "$manifest" --json >/dev/null
done < <(find "$ROOT/examples" -type f -name '*.abi.json' | sort)

echo "[gate] PASS"
