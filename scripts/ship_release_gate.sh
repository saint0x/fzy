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

echo "[ship] parity/equivalence representative probes"
PROBE_A="$TMP_DIR/parity_probe_a.fzy"
PROBE_B="$TMP_DIR/parity_probe_b.fzy"
PROBE_C="$ROOT/tests/fixtures/primitive_parity/main.fzy"
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
