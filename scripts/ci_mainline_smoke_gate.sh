#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED="${SEED:-4242}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$ARTIFACT_DIR"

FZ_CMD=(cargo run -q -p fz --)
TMP_DIR="$(mktemp -d "$ROOT/.tmp.ci-smoke.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[smoke] compiler workspace check"
cargo check --workspace >/dev/null

echo "[smoke] representative cross-backend unit slice"
cargo test -q -p driver pipeline::tests::cross_backend_primitive_control_flow_and_operator_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_native_completeness_fixture_execute_consistently -- --exact >/dev/null
cargo test -q -p driver pipeline::tests::cross_backend_non_i32_and_aggregate_signatures_execute_consistently -- --exact >/dev/null

echo "[smoke] example backend build parity"
"${FZ_CMD[@]}" check "$ROOT/examples/minimal_runtime" --json >/dev/null
"${FZ_CMD[@]}" build "$ROOT/examples/minimal_runtime" --backend llvm --json >/dev/null
"${FZ_CMD[@]}" build "$ROOT/examples/minimal_runtime" --backend cranelift --json >/dev/null
"${FZ_CMD[@]}" check "$ROOT/examples/fullstack" --json >/dev/null
"${FZ_CMD[@]}" build "$ROOT/examples/fullstack" --backend cranelift --json >/dev/null
"${FZ_CMD[@]}" check "$ROOT/examples/live_server" --json >/dev/null
"${FZ_CMD[@]}" build "$ROOT/examples/live_server" --backend cranelift --json >/dev/null
"${FZ_CMD[@]}" check "$ROOT/examples/robust_cli" --json >/dev/null
"${FZ_CMD[@]}" build "$ROOT/examples/robust_cli" --backend cranelift --json >/dev/null

echo "[smoke] deterministic trace lifecycle"
TRACE_PATH="$ARTIFACT_DIR/ci_mainline_smoke.${SEED}.trace.fozzy"
"${FZ_CMD[@]}" run tests/example.fozzy.json --det --seed "$SEED" --record "$TRACE_PATH" --record-collision overwrite --json >/dev/null
"${FZ_CMD[@]}" trace verify "$TRACE_PATH" --strict --json >/dev/null
"${FZ_CMD[@]}" replay "$TRACE_PATH" --json >/dev/null
"${FZ_CMD[@]}" ci "$TRACE_PATH" --strict --json >/dev/null

echo "[smoke] host-backed scenario"
mkdir -p "$TMP_DIR/host-backed"
(
  cd "$TMP_DIR/host-backed"
  "${FZ_CMD[@]}" run "$ROOT/tests/host_backends_run.pass.fozzy.json" --host-backends --json >/dev/null
)

echo "[smoke] ffi abi/header surface"
for example in fullstack live_server; do
  example_root="$ROOT/examples/$example"
  baseline_abi="$example_root/include/$example.abi.json"
  baseline_header="$example_root/include/$example.h"
  generated_header="$TMP_DIR/$example.h"
  "${FZ_CMD[@]}" headers "$example_root" --out "$generated_header" --json >/dev/null
  generated_abi="${generated_header%.h}.abi.json"
  test -f "$generated_abi"
  test -f "$baseline_abi"
  test -f "$baseline_header"
  if ! diff -u "$baseline_header" "$generated_header" >/dev/null; then
    echo "generated header drifted from checked-in header: $example" >&2
    diff -u "$baseline_header" "$generated_header" >&2 || true
    exit 2
  fi
  if ! diff -u "$baseline_abi" "$generated_abi" >/dev/null; then
    echo "generated ABI drifted from checked-in ABI: $example" >&2
    diff -u "$baseline_abi" "$generated_abi" >&2 || true
    exit 2
  fi
done

echo "[smoke] PASS"
