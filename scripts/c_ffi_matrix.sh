#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fz() {
  if [[ -x "$ROOT/target/debug/fz" ]]; then
    "$ROOT/target/debug/fz" "$@"
  else
    cargo run -p fz -- "$@"
  fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-cffi-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

MODULE="$WORK/cffi.fzy"
cat > "$MODULE" <<'FZY'
extern "C" fn c_mul(left: i32, right: i32) -> i32;

#[ffi_panic(abort)]
pub extern "C" fn add(left: i32, right: i32) -> i32 {
    return left + right
}

#[ffi_panic(abort)]
pub extern "C" fn call_mul(left: i32, right: i32) -> i32 {
    return c_mul(left, right)
}
FZY

BUILD_JSON="$(fz build "$MODULE" --lib --json)"
STATIC_LIB="$(python3 - <<'PY' "$BUILD_JSON"
import json, sys
payload = json.loads(sys.argv[1])
print(payload.get("staticLib", ""))
PY
)"
HEADER="$(python3 - <<'PY' "$BUILD_JSON"
import json, sys
payload = json.loads(sys.argv[1])
print(payload.get("header", ""))
PY
)"

if [[ -z "$STATIC_LIB" || -z "$HEADER" ]]; then
  echo "missing static library or header in build output" >&2
  exit 2
fi

cat > "$WORK/host.c" <<EOF_C
#include <stdint.h>
#include <stdio.h>
#include "$(basename "$HEADER")"

int32_t c_mul(int32_t left, int32_t right) {
  return left * right;
}

static int32_t cb_inc(int32_t arg) {
  return arg + 1;
}

int main(void) {
  if (fz_host_init() != 0) return 1;
  if (add(2, 3) != 5) return 2;
  if (call_mul(3, 4) != 12) return 3;
  if (fz_host_register_callback_i32(0, cb_inc) != 0) return 4;
  if (fz_host_invoke_callback_i32(0, 9) != 10) return 5;
  if (fz_host_shutdown() != 0) return 6;
  if (fz_host_cleanup() != 0) return 7;
  puts("c-ffi-matrix-ok");
  return 0;
}
EOF_C

cc "$WORK/host.c" "$STATIC_LIB" -I"$(dirname "$HEADER")" -lpthread -o "$WORK/host"
OUTPUT="$($WORK/host)"
if [[ "$OUTPUT" != "c-ffi-matrix-ok" ]]; then
  echo "unexpected host output: $OUTPUT" >&2
  exit 3
fi

echo "$OUTPUT"
