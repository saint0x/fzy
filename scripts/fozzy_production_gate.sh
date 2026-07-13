#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
TRACE_BASENAME="production-gate.${SEED}.$$"
MEM_TRACE_BASENAME="production-memory.${SEED}.$$"
TRAIT_TRACE_BASENAME="trait-generic-gate.${SEED}.$$"
TRACE_PATH="$ARTIFACT_DIR/${TRACE_BASENAME}.trace.fozzy"
MEM_TRACE_PATH="$ARTIFACT_DIR/${MEM_TRACE_BASENAME}.trace.fozzy"
TRAIT_TRACE_PATH="$ARTIFACT_DIR/${TRAIT_TRACE_BASENAME}.trace.fozzy"
UNSAFE_BUDGET="${UNSAFE_BUDGET:-38}"
UNSAFE_AUDIT_TARGET="${UNSAFE_AUDIT_TARGET:-.}"
RUST_UNSAFE_BUDGET="${RUST_UNSAFE_BUDGET:-2}"

FZ_CMD=(cargo run -q -p fz --)

mkdir -p "$ARTIFACT_DIR"
TMP_DIR="$(mktemp -d "$ROOT/.tmp.production-gate.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[gate] deterministic doctor"
"${FZ_CMD[@]}" doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null

echo "[gate] language primitive drift gate"
python3 ./scripts/language_primitive_drift_gate.py >/dev/null

echo "[gate] traits/generics contract gate"
python3 ./scripts/traits_generics_gate.py >/dev/null

echo "[gate] direct-memory architecture gate"
python3 ./scripts/direct_memory_architecture_gate.py >/dev/null

echo "[gate] runtime core execution path gate"
python3 ./scripts/runtime_core_execution_path_gate.py >/dev/null

echo "[gate] core package check/build"
cargo run -q -p fz -- check core --json >/dev/null
cargo run -q -p fz -- build core --backend llvm --release --json >/dev/null

echo "[gate] direct-memory perf exit gate"
python3 ./scripts/direct_memory_perf_gate.py >/dev/null

echo "[gate] safety claim integrity gate"
python3 ./scripts/safety_claim_integrity_gate.py >/dev/null

echo "[gate] deterministic strict tests"
"${FZ_CMD[@]}" test tests/*.fozzy.json --det --strict-verify --seed "$SEED" --json >/dev/null

echo "[gate] primitive parity probes"
"${FZ_CMD[@]}" parity tests/fixtures/primitive_parity/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/native_completeness/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/direct_memory_contract/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/direct_memory_safety/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/trait_generic/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/trait_generic_async/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/generic_data_structure/main.fzy --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity tests/fixtures/trait_service/main.fzy --seed "$SEED" --json >/dev/null

echo "[gate] native test manifest and nondet routing"
NATIVE_TEST_FIXTURE="$TMP_DIR/native_test_surface.fzy"
NATIVE_TEST_RECORD="$ARTIFACT_DIR/native-test-gate.${SEED}.$$.trace.json"
cat > "$NATIVE_TEST_FIXTURE" <<'FZY'
test "stable" {
    assert.eq_i32(1, 1)
}

test "chaos" nondet {
    assert.eq_i32(2, 2)
}

fn main() -> i32 {
    return 0
}
FZY
"${FZ_CMD[@]}" test "$NATIVE_TEST_FIXTURE" --det --strict-verify --seed "$SEED" --record "$NATIVE_TEST_RECORD" --json >"$TMP_DIR/native.det.json"
"${FZ_CMD[@]}" test "$NATIVE_TEST_FIXTURE" --seed "$SEED" --json >"$TMP_DIR/native.fast.json"
python3 - <<'PY' "$TMP_DIR/native.det.json" "$TMP_DIR/native.fast.json"
import json, pathlib, sys

det = json.loads(pathlib.Path(sys.argv[1]).read_text())
fast = json.loads(pathlib.Path(sys.argv[2]).read_text())

assert det["mode"] == "det", det
assert det["deterministicTestNames"] == ["stable"], det
assert det["nondeterministicTestNames"] == [], det
artifacts = det["artifacts"]
assert artifacts is not None, det
trace = pathlib.Path(artifacts["trace"])
report = pathlib.Path(artifacts["report"])
manifest = pathlib.Path(artifacts["manifest"])
for path in (trace, report, manifest):
    assert path.exists(), path
assert json.loads(trace.read_text())["schemaVersion"] == "fozzylang.test_trace.v1"
assert json.loads(report.read_text())["schemaVersion"] == "fozzylang.test_report.v1"
assert json.loads(manifest.read_text())["schemaVersion"] == "fozzylang.test_manifest.v1"

assert fast["mode"] == "fast", fast
assert fast["nondeterministicTestNames"] == ["chaos"], fast
assert fast["passedTests"] == 2, fast
PY
NATIVE_TEST_MANIFEST="${NATIVE_TEST_RECORD%.json}.manifest.json"
"${FZ_CMD[@]}" trace verify "$NATIVE_TEST_MANIFEST" --strict --json >/dev/null
"${FZ_CMD[@]}" replay "$NATIVE_TEST_MANIFEST" --json >/dev/null
"${FZ_CMD[@]}" ci "$NATIVE_TEST_MANIFEST" --strict --json >/dev/null
if "${FZ_CMD[@]}" run "$NATIVE_TEST_FIXTURE" --det --host-backends --json >/dev/null 2>"$TMP_DIR/native.host.err"; then
  echo "native deterministic host-backed bridge unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'deterministic execution is unavailable for host-backed native `fz run`' "$TMP_DIR/native.host.err"

echo "[gate] native completeness execute-and-compare"
cargo test -q -p driver pipeline::tests::cross_backend_native_completeness_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_array_index_lowers_without_data_plane_runtime_calls -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_switch_and_constant_string_chain_lowering_is_parity_safe -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_contract_fixture_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_bounds_probe_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_i64_array_layout_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_string_slice_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_rolling_window_index_executes_consistently -- --exact >/dev/null
cargo test -q -p hir tests::flags_overlapping_trait_impls_as_ambiguous -- --exact >/dev/null

echo "[gate] deterministic memory doctor/tests"
"${FZ_CMD[@]}" doctor --deep --scenario tests/memory_graph_diff_top.pass.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" test tests/memory_graph_diff_top.pass.fozzy.json --det --strict-verify --seed "$SEED" --json >/dev/null

echo "[gate] deterministic trait/generic doctor/tests"
"${FZ_CMD[@]}" doctor --deep --scenario tests/trait_generic.pass.fozzy.json --runs 5 --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" test tests/trait_generic.pass.fozzy.json --det --strict-verify --seed "$SEED" --json >/dev/null

echo "[gate] record deterministic trace"
"${FZ_CMD[@]}" run tests/example.fozzy.json --det --seed "$SEED" --record "$TRACE_PATH" --record-collision overwrite --json >/dev/null

echo "[gate] trace verify/replay/ci"
"${FZ_CMD[@]}" trace verify "$TRACE_PATH" --strict --json >/dev/null
"${FZ_CMD[@]}" replay "$TRACE_PATH" --json >/dev/null
"${FZ_CMD[@]}" ci "$TRACE_PATH" --strict --json >/dev/null

echo "[gate] memory trace record/verify/replay/ci"
"${FZ_CMD[@]}" run tests/memory_graph_diff_top.pass.fozzy.json --det --seed "$SEED" --record "$MEM_TRACE_PATH" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$MEM_TRACE_PATH" --strict --json >/dev/null
"${FZ_CMD[@]}" replay "$MEM_TRACE_PATH" --json >/dev/null
"${FZ_CMD[@]}" ci "$MEM_TRACE_PATH" --strict --json >/dev/null

echo "[gate] trait/generic trace record/verify/replay/ci"
"${FZ_CMD[@]}" run tests/trait_generic.pass.fozzy.json --det --seed "$SEED" --record "$TRAIT_TRACE_PATH" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$TRAIT_TRACE_PATH" --strict --json >/dev/null
"${FZ_CMD[@]}" replay "$TRAIT_TRACE_PATH" --json >/dev/null
"${FZ_CMD[@]}" ci "$TRAIT_TRACE_PATH" --strict --json >/dev/null

echo "[gate] host-backed run"
"${FZ_CMD[@]}" run tests/runtime.bind_json_env.pass.fozzy.json --host-backends --json >/dev/null
"${FZ_CMD[@]}" run tests/memory_graph_diff_top.pass.fozzy.json --host-backends --json >/dev/null
"${FZ_CMD[@]}" run tests/primitive.host_operators.pass.fozzy.json --host-backends --json >/dev/null
"${FZ_CMD[@]}" run tests/host_backends_run.pass.fozzy.json --host-backends --json >/dev/null
"${FZ_CMD[@]}" run tests/trait_generic.pass.fozzy.json --host-backends --json >/dev/null

echo "[gate] host-backed C interop matrix"
"${FZ_CMD[@]}" run tests/c_ffi_matrix.pass.fozzy.json --host-backends --json >/dev/null

echo "[gate] full command-surface checks"
"${FZ_CMD[@]}" fuzz tests/example.fozzy.json --json >/dev/null
"${FZ_CMD[@]}" explore tests/distributed.pass.fozzy.json --json >/dev/null
"${FZ_CMD[@]}" shrink "$TRACE_PATH" --json >/dev/null
"${FZ_CMD[@]}" artifacts ls latest --json >/dev/null
"${FZ_CMD[@]}" report show latest --format json --json >/dev/null
"${FZ_CMD[@]}" env --json >/dev/null
"${FZ_CMD[@]}" usage --json >/dev/null
./scripts/lsp_editor_smoke.sh >/dev/null
./scripts/lsp_determinism_smoke.sh >/dev/null

echo "[gate] tooling DX strict smokes"
RUSTFLAGS="-D warnings" cargo check -p driver --all-targets >/dev/null
cargo test -p formatter -- --nocapture >/dev/null
cargo test -p driver formatter -- --nocapture >/dev/null
"${FZ_CMD[@]}" fmt examples/fullstack/src examples/robust_cli/src --check >/dev/null
"${FZ_CMD[@]}" doc gen examples/fullstack/src --format markdown --out "$ARTIFACT_DIR/fullstack.api.md" >/dev/null
test -s "$ARTIFACT_DIR/fullstack.api.md"
grep -q 'ext unsafe c fn fs_open' "$ARTIFACT_DIR/fullstack.api.md"
grep -q 'rpc GetUser(req: GetUserReq) -> GetUserRes;' "$ARTIFACT_DIR/fullstack.api.md"
"${FZ_CMD[@]}" rpc gen examples/fullstack --out-dir "$ARTIFACT_DIR/fullstack-rpc" --json >/dev/null
test -s "$ARTIFACT_DIR/fullstack-rpc/rpc.schema.json"
grep -q '"schemaVersion": "fozzylang.rpc.v1"' "$ARTIFACT_DIR/fullstack-rpc/rpc.schema.json"
grep -q '"mode": "bidirectional_streaming"' "$ARTIFACT_DIR/fullstack-rpc/rpc.schema.json"
! grep -q 'transport_send' "$ARTIFACT_DIR/fullstack-rpc/rpc.client.fzy"
grep -q 'return GetUser(req)' "$ARTIFACT_DIR/fullstack-rpc/rpc.client.fzy"
grep -q 'prepare_getuser_handler' "$ARTIFACT_DIR/fullstack-rpc/rpc.server.fzy"

echo "[gate] direct built-binary confidence pass"
MINIMAL_BUILD_JSON="$("${FZ_CMD[@]}" build "$ROOT/examples/minimal_runtime" --release --json)"
MINIMAL_BUILD_OUTPUT="$(python3 - <<'PY' "$MINIMAL_BUILD_JSON"
import json, sys
print(json.loads(sys.argv[1])["output"])
PY
)"
"$MINIMAL_BUILD_OUTPUT" >/dev/null
ROBUST_BUILD_JSON="$("${FZ_CMD[@]}" build "$ROOT/examples/robust_cli" --release --json)"
ROBUST_BUILD_OUTPUT="$(python3 - <<'PY' "$ROBUST_BUILD_JSON"
import json, sys
print(json.loads(sys.argv[1])["output"])
PY
)"
"$ROBUST_BUILD_OUTPUT" >/dev/null

echo "[gate] pedantic topology closure"
MAP_JSON="$("${FZ_CMD[@]}" map suites --root . --scenario-root tests --profile pedantic --json)"
python3 - <<'PY' "$MAP_JSON"
import json, sys
payload = json.loads(sys.argv[1])
uncovered = int(payload.get("uncoveredHotspotCount", 0))
required = int(payload.get("requiredHotspotCount", 0))
print(f"requiredHotspotCount={required} uncoveredHotspotCount={uncovered}")
if uncovered != 0:
    raise SystemExit(2)
PY

echo "[gate] determinism flake budget gate"
python3 ./scripts/determinism_flake_budget_gate.py "${FLAKE_BUDGET:-0}" >/dev/null

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
