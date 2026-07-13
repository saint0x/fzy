#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$ARTIFACT_DIR"

FZ_CMD=(cargo run -q -p fz --)

TMP_DIR="$(mktemp -d "$ROOT/.tmp.ship-gate.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[ship] compiler pipeline gate (workspace check)"
cargo check --workspace >/dev/null

echo "[ship] warning-free gate"
RUSTFLAGS="-D warnings" cargo check --workspace >/dev/null

echo "[ship] workspace tests"
cargo test --workspace -- --test-threads=1 >/dev/null

echo "[ship] language primitive drift gate"
python3 ./scripts/language_primitive_drift_gate.py >/dev/null

echo "[ship] traits/generics contract gate"
python3 ./scripts/traits_generics_gate.py >/dev/null

echo "[ship] direct-memory architecture gate"
python3 ./scripts/direct_memory_architecture_gate.py >/dev/null

echo "[ship] runtime core execution path gate"
python3 ./scripts/runtime_core_execution_path_gate.py >/dev/null

echo "[ship] core package check/build"
cargo run -q -p fz -- check core --json >/dev/null
cargo run -q -p fz -- build core --backend llvm --release --json >/dev/null

echo "[ship] direct-memory perf exit gate"
python3 ./scripts/direct_memory_perf_gate.py >/dev/null

echo "[ship] safety claim integrity gate"
python3 ./scripts/safety_claim_integrity_gate.py >/dev/null

echo "[ship] parity representative probes"
PROBE_A="$TMP_DIR/parity_probe_a.fzy"
PROBE_B="$TMP_DIR/parity_probe_b.fzy"
PROBE_C="$ROOT/tests/fixtures/primitive_parity/main.fzy"
PROBE_D="$ROOT/tests/fixtures/native_completeness/main.fzy"
PROBE_E="$ROOT/tests/fixtures/direct_memory_contract/main.fzy"
PROBE_F="$ROOT/tests/fixtures/direct_memory_safety/main.fzy"
PROBE_G="$ROOT/tests/fixtures/trait_generic/main.fzy"
PROBE_H="$ROOT/tests/fixtures/trait_generic_async/main.fzy"
PROBE_I="$ROOT/tests/fixtures/generic_data_structure/main.fzy"
PROBE_J="$ROOT/tests/fixtures/trait_service/main.fzy"
cat > "$PROBE_A" <<'FZY'
fn main() -> i32 {
    return 0
}
FZY
cat > "$PROBE_B" <<'FZY'
fn select(flag: bool) -> i32 {
    if flag {
        return 7
    }
    return 3
}

fn main() -> i32 {
    let picked = select(true)
    return picked
}
FZY
"${FZ_CMD[@]}" parity "$PROBE_A" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_B" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_C" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_D" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_E" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_F" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_G" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_H" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_I" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_J" --seed "$SEED" --json >/dev/null

echo "[ship] native test manifest and nondet routing"
NATIVE_TEST_FIXTURE="$TMP_DIR/native_test_surface.fzy"
NATIVE_TEST_RECORD="$ARTIFACT_DIR/native-test-ship.${SEED}.$$.trace.json"
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

echo "[ship] native backend execute-and-compare control-flow parity"
cargo test -q -p driver pipeline::tests::cross_backend_primitive_control_flow_and_operator_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_native_completeness_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_non_i32_and_aggregate_signatures_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::non_entry_infinite_loop_function_fixture_stays_non_regressing -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_array_index_lowers_without_data_plane_runtime_calls -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::direct_memory_backend_contract_switch_and_constant_string_chain_lowering_is_parity_safe -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_contract_fixture_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_bounds_probe_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_i64_array_layout_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_string_slice_executes_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_rolling_window_index_executes_consistently -- --exact >/dev/null
cargo test -q -p hir tests::flags_overlapping_trait_impls_as_ambiguous -- --exact >/dev/null

echo "[ship] examples conformance on default production backend"
for example_root in "$ROOT"/examples/*; do
  [[ -d "$example_root" ]] || continue
  [[ -f "$example_root/fozzy.toml" ]] || continue
  "${FZ_CMD[@]}" check "$example_root" --json >/dev/null
  "${FZ_CMD[@]}" build "$example_root" --release --json >/dev/null
  echo "[ship] example ok: $(basename "$example_root")"
done

echo "[ship] one-shot example strict runs"
for example_root in \
  "$ROOT/examples/agent_runtime" \
  "$ROOT/examples/bounds_service" \
  "$ROOT/examples/context_runtime" \
  "$ROOT/examples/fullstack" \
  "$ROOT/examples/minimal_runtime" \
  "$ROOT/examples/robust_cli" \
  "$ROOT/examples/service_app" \
  "$ROOT/examples/simd_kernels"; do
  "${FZ_CMD[@]}" run "$example_root" --strict-verify --seed "$SEED" --json >/dev/null
  echo "[ship] example strict run ok: $(basename "$example_root")"
done

echo "[ship] direct built-binary confidence pass"
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

echo "[ship] service and GPU example validations"
LIVE_SERVER_SCENARIO="$ROOT/tests/live_server.http.pass.fozzy.json"
"${FZ_CMD[@]}" test "$LIVE_SERVER_SCENARIO" --det --strict-verify --seed "$SEED" --json >/dev/null
echo "[ship] live_server scenario ok"

GPU_METAL_TRACE="$ARTIFACT_DIR/gpu_metal_image_example.trace.fozzy"
GPU_CPU_TRACE="$ARTIFACT_DIR/gpu_cpu_aggregate.trace.fozzy"
GPU_ASCII_TRACE="$ARTIFACT_DIR/gpu_ascii_ripple.trace.fozzy"
"${FZ_CMD[@]}" run "$ROOT/examples/gpu_metal_image" --det --seed "$SEED" --record "$GPU_METAL_TRACE" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$GPU_METAL_TRACE" --strict --json >/dev/null
"${FZ_CMD[@]}" run "$ROOT/examples/gpu_cpu_aggregate" --host-backends --json >/dev/null
"${FZ_CMD[@]}" run "$ROOT/examples/gpu_cpu_aggregate" --det --seed "$SEED" --record "$GPU_CPU_TRACE" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$GPU_CPU_TRACE" --strict --json >/dev/null
"${FZ_CMD[@]}" run "$ROOT/examples/gpu_ascii_ripple" --host-backends --json >/dev/null
"${FZ_CMD[@]}" run "$ROOT/examples/gpu_ascii_ripple" --det --seed "$SEED" --record "$GPU_ASCII_TRACE" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$GPU_ASCII_TRACE" --strict --json >/dev/null
echo "[ship] GPU example validations ok"

if [[ "${ENABLE_CROSS_REPO_SMOKE:-0}" == "1" ]]; then
  echo "[ship] optional cross-repo anthropic_smoke adjunct"
  ANTHROPIC_SMOKE_ROOT="${ANTHROPIC_SMOKE_ROOT:-$ROOT/../fzllm/anthropic_smoke}"
  if [[ ! -f "$ANTHROPIC_SMOKE_ROOT/fozzy.toml" ]]; then
    echo "missing anthropic smoke repo at $ANTHROPIC_SMOKE_ROOT (expected fozzy.toml)" >&2
    exit 2
  fi
  ANTHROPIC_TRACE="$ARTIFACT_DIR/anthropic_smoke.crossrepo.trace.fozzy"
  "${FZ_CMD[@]}" check "$ANTHROPIC_SMOKE_ROOT" --json >/dev/null
  "${FZ_CMD[@]}" build "$ANTHROPIC_SMOKE_ROOT" --release --json >/dev/null
  "${FZ_CMD[@]}" run "$ANTHROPIC_SMOKE_ROOT" --det --strict-verify --seed "$SEED" --record "$ANTHROPIC_TRACE" --json >/dev/null
  "${FZ_CMD[@]}" run "$ANTHROPIC_SMOKE_ROOT" --strict-verify --seed "$SEED" --json >/dev/null
  "${FZ_CMD[@]}" trace verify "$ANTHROPIC_TRACE" --strict --json >/dev/null
  "${FZ_CMD[@]}" replay "$ANTHROPIC_TRACE" --json >/dev/null
  "${FZ_CMD[@]}" ci "$ANTHROPIC_TRACE" --json >/dev/null
  echo "[ship] anthropic_smoke cross-repo ok"
fi

echo "[ship] anthropic smoke matrix (llvm + cranelift)"
ANTHROPIC_SMOKE="$TMP_DIR/anthropic_smoke.fzy"
cat > "$ANTHROPIC_SMOKE" <<'FZY'
use core.http;
use core.error;

fn main() -> i32 {
    http.post_json_capture("https://api.anthropic.com/v1/messages", "{}")
    discard error.message()
    return 0
}
FZY
for backend in llvm cranelift; do
  "${FZ_CMD[@]}" check "$ANTHROPIC_SMOKE" --json >/dev/null
  "${FZ_CMD[@]}" build "$ANTHROPIC_SMOKE" --backend "$backend" --json >/dev/null
  "${FZ_CMD[@]}" run "$ANTHROPIC_SMOKE" --backend "$backend" --seed "$SEED" --json >/dev/null
  echo "[ship] anthropic smoke ok: $backend"
done

echo "[ship] FFI release-blocking examples (headers + abi-check)"
for example in fullstack live_server; do
  example_root="$ROOT/examples/$example"
  baseline_abi="$example_root/include/$example.abi.json"
  generated_header="$TMP_DIR/$example.h"
  "${FZ_CMD[@]}" headers "$example_root" --out "$generated_header" --json >/dev/null
  generated_abi="$TMP_DIR/$example.abi.json"
  if [[ ! -f "$generated_abi" ]]; then
    echo "missing generated ABI manifest: $generated_abi" >&2
    exit 2
  fi
  if [[ ! -f "$baseline_abi" ]]; then
    echo "missing baseline ABI manifest: $baseline_abi" >&2
    exit 2
  fi
  "${FZ_CMD[@]}" abi-check "$generated_abi" --baseline "$baseline_abi" --json >/dev/null
  echo "[ship] abi ok: $example"
done

echo "[ship] production gate"
./scripts/fozzy_production_gate.sh

echo "[ship] PASS"
