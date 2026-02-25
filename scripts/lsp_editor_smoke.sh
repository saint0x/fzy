#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FZ_BIN="${FZ_BIN:-}"
if [[ -z "$FZ_BIN" ]]; then
  FZ_BIN="$(find "$ROOT/target" -path "*/debug/fz" -perm -111 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "$FZ_BIN" || ! -x "$FZ_BIN" ]]; then
  cargo build -p fz >/dev/null
  FZ_BIN="$(find "$ROOT/target" -path "*/debug/fz" -perm -111 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "$FZ_BIN" || ! -x "$FZ_BIN" ]]; then
  FZ_BIN="fz"
fi

SAMPLE="$ROOT/tmp/lsp_smoke_sample.fzy"
mkdir -p "$(dirname "$SAMPLE")"
cat > "$SAMPLE" <<'SRC'
fn main() -> i32 {
    let value = 1
    return value
}
SRC

"$FZ_BIN" lsp diagnostics "$SAMPLE" --json >/dev/null
"$FZ_BIN" lsp definition "$SAMPLE" main --json >/dev/null
"$FZ_BIN" lsp hover "$SAMPLE" main --json >/dev/null
"$FZ_BIN" lsp smoke "$SAMPLE" --json >/dev/null
"$FZ_BIN" lsp rename "$SAMPLE" main entry_main --json >/dev/null

echo "lsp-editor-smoke: ok"
