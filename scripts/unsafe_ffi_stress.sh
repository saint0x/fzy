#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fzy-unsafe-ffi-XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

run_expect_fail() {
  local cmd="$1"
  local expect="$2"
  set +e
  output="$(eval "$cmd" 2>&1)"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    echo "expected failure but command succeeded: $cmd" >&2
    exit 2
  fi
  if [[ "$output" != *"$expect"* ]]; then
    echo "expected error text not found: $expect" >&2
    echo "$output" >&2
    exit 3
  fi
}

case "$MODE" in
  pointer_misuse)
    cat > "$TMP/pointer_bad.fzy" <<'FZY'
#[ffi_panic(abort)]
pub extern "C" fn write(ptr_borrowed: *u8) -> i32;
FZY
    run_expect_fail \
      "cd \"$ROOT\" && cargo run -q -p fz -- headers \"$TMP/pointer_bad.fzy\"" \
      "paired length parameter"
    ;;
  callback_lifecycle)
    cat > "$TMP/callback_bad.fzy" <<'FZY'
#[ffi_panic(error)]
pub extern "C" fn register_callback(cb_callback: *u8, cb_len: usize) -> i32;
FZY
    run_expect_fail \
      "cd \"$ROOT\" && cargo run -q -p fz -- headers \"$TMP/callback_bad.fzy\"" \
      "missing lifetime context param"
    ;;
  unsafe_contract_invariant)
    cat > "$TMP/unsafe_bad.fzy" <<'FZY'
fn main() -> i32 {
    let p = alloc(8)
    unsafe("reason:test", "invariant:pointer valid", "owner:p", "scope:main", "risk_class:memory", "proof_ref:trace://bad")
    free(p)
    return 0
}
FZY
    run_expect_fail \
      "cd \"$ROOT\" && cargo run -q -p fz -- verify \"$TMP/unsafe_bad.fzy\"" \
      "supported predicate DSL"
    ;;
  trace_host)
    cd "$ROOT"
    mkdir -p artifacts
    TRACE="artifacts/unsafe_ffi_boundary.trace.fozzy"
    fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record "$TRACE" --json >/dev/null
    fozzy trace verify "$TRACE" --strict --json >/dev/null
    fozzy replay "$TRACE" --json >/dev/null
    fozzy ci "$TRACE" --json >/dev/null
    fozzy run tests/host_backends_run.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json >/dev/null
    ;;
  *)
    echo "usage: $0 {pointer_misuse|callback_lifecycle|unsafe_contract_invariant|trace_host}" >&2
    exit 64
    ;;
esac

echo "unsafe-ffi-stress-ok"
