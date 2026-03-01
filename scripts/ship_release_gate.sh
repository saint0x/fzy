#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$ARTIFACT_DIR"

if command -v fz >/dev/null 2>&1; then
  FZ_CMD=(fz)
else
  FZ_CMD=(cargo run -q -p fz --)
fi

TMP_DIR="$(mktemp -d "$ROOT/.tmp.ship-gate.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[ship] compiler pipeline gate (workspace check)"
cargo check --workspace >/dev/null

echo "[ship] warning-free gate"
RUSTFLAGS="-D warnings" cargo check --workspace >/dev/null

echo "[ship] workspace tests"
cargo test --workspace >/dev/null

echo "[ship] language primitive drift gate"
python3 ./scripts/language_primitive_drift_gate.py >/dev/null

echo "[ship] traits/generics contract gate"
python3 ./scripts/traits_generics_gate.py >/dev/null

echo "[ship] direct-memory architecture gate"
python3 ./scripts/direct_memory_architecture_gate.py >/dev/null

echo "[ship] runtime corelib execution path gate"
python3 ./scripts/runtime_corelib_execution_path_gate.py >/dev/null

echo "[ship] corelib package check/build"
cargo run -q -p fz -- check corelib --json >/dev/null
cargo run -q -p fz -- build corelib --backend llvm --release --json >/dev/null

echo "[ship] direct-memory perf exit gate"
python3 ./scripts/direct_memory_perf_gate.py >/dev/null

echo "[ship] safety claim integrity gate"
python3 ./scripts/safety_claim_integrity_gate.py >/dev/null

echo "[ship] parity/equivalence representative probes"
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
"${FZ_CMD[@]}" equivalence "$PROBE_A" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_B" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_B" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_C" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_C" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_D" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_D" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_E" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_E" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_F" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_F" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_G" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_G" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_H" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_H" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_I" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_I" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" parity "$PROBE_J" --seed "$SEED" --json >/dev/null
"${FZ_CMD[@]}" equivalence "$PROBE_J" --seed "$SEED" --json >/dev/null

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
  "${FZ_CMD[@]}" test "$example_root" --strict-verify --seed "$SEED" --json >/dev/null
  "${FZ_CMD[@]}" run "$example_root" --strict-verify --seed "$SEED" --json >/dev/null
  echo "[ship] example ok: $(basename "$example_root")"
done

echo "[ship] cross-repo anthropic_smoke conformance"
ANTHROPIC_SMOKE_ROOT="${ANTHROPIC_SMOKE_ROOT:-$ROOT/../fzllm/anthropic_smoke}"
if [[ ! -f "$ANTHROPIC_SMOKE_ROOT/fozzy.toml" ]]; then
  echo "missing anthropic smoke repo at $ANTHROPIC_SMOKE_ROOT (expected fozzy.toml)" >&2
  exit 2
fi
ANTHROPIC_TRACE="$ARTIFACT_DIR/anthropic_smoke.crossrepo.trace.fozzy"
"${FZ_CMD[@]}" check "$ANTHROPIC_SMOKE_ROOT" --json >/dev/null
"${FZ_CMD[@]}" build "$ANTHROPIC_SMOKE_ROOT" --release --json >/dev/null
"${FZ_CMD[@]}" test "$ANTHROPIC_SMOKE_ROOT" --det --strict-verify --seed "$SEED" --record "$ANTHROPIC_TRACE" --json >/dev/null
"${FZ_CMD[@]}" run "$ANTHROPIC_SMOKE_ROOT" --strict-verify --seed "$SEED" --json >/dev/null
fozzy trace verify "$ANTHROPIC_TRACE" --strict --json >/dev/null
fozzy replay "$ANTHROPIC_TRACE" --json >/dev/null
fozzy ci "$ANTHROPIC_TRACE" --json >/dev/null
echo "[ship] anthropic_smoke cross-repo ok"

echo "[ship] anthropic smoke matrix (llvm + cranelift)"
ANTHROPIC_SMOKE="$TMP_DIR/anthropic_smoke.fzy"
cat > "$ANTHROPIC_SMOKE" <<'FZY'
use core.http;

fn main() -> i32 {
    http.post_json_capture("https://api.anthropic.com/v1/messages", "{}")
    let emsg = error.message()
    if emsg == "" {
        return 91
    }
    return 0
}
FZY
for backend in llvm cranelift; do
  "${FZ_CMD[@]}" check "$ANTHROPIC_SMOKE" --json >/dev/null
  "${FZ_CMD[@]}" build "$ANTHROPIC_SMOKE" --backend "$backend" --json >/dev/null
  "${FZ_CMD[@]}" test "$ANTHROPIC_SMOKE" --backend "$backend" --seed "$SEED" --json >/dev/null
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
