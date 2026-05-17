#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -n "${FZ_BIN:-}" ]]; then
  FZ_CMD=("$FZ_BIN")
elif command -v fz >/dev/null 2>&1; then
  FZ_CMD=(fz)
elif [[ -x "$ROOT/target/debug/fz" ]]; then
  FZ_CMD=("$ROOT/target/debug/fz")
elif [[ -x "$ROOT/target/aarch64-apple-darwin/debug/fz" ]]; then
  FZ_CMD=("$ROOT/target/aarch64-apple-darwin/debug/fz")
else
  FZ_CMD=(cargo run -q -p fz --)
fi

WORK_DIR="$ROOT/tmp/browser_editor_gate"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/src"

cat > "$WORK_DIR/fozzy.toml" <<'EOF'
[package]
name = "browser_editor_gate"
version = "0.1.0"

[[target.bin]]
name = "browser_editor_gate"
path = "src/main.fzy"
EOF

cat > "$WORK_DIR/src/main.fzy" <<'EOF'
fn main() -> i32 {
    let value = 7
    return value
}
EOF

measure_ms() {
  python3 - "$@" <<'PY'
import subprocess, sys, time
cmd = sys.argv[1:]
start = time.perf_counter()
subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
elapsed = (time.perf_counter() - start) * 1000.0
print(f"{elapsed:.3f}")
PY
}

diag_ms="$(measure_ms "${FZ_CMD[@]}" lsp diagnostics "$WORK_DIR/src/main.fzy" --json)"
def_ms="$(measure_ms "${FZ_CMD[@]}" lsp definition "$WORK_DIR/src/main.fzy" main --json)"
hover_ms="$(measure_ms "${FZ_CMD[@]}" lsp hover "$WORK_DIR/src/main.fzy" main --json)"
smoke_ms="$(measure_ms "${FZ_CMD[@]}" lsp smoke "$WORK_DIR/src/main.fzy" --json)"

python3 - <<'PY' "$diag_ms" "$def_ms" "$hover_ms" "$smoke_ms"
import json, pathlib, sys

diag_ms, def_ms, hover_ms, smoke_ms = map(float, sys.argv[1:])
budgets = {
    "diagnostics": 750.0,
    "definition": 750.0,
    "hover": 750.0,
    "smoke": 1500.0,
}
observed = {
    "diagnostics": diag_ms,
    "definition": def_ms,
    "hover": hover_ms,
    "smoke": smoke_ms,
}
errors = [
    f"{name} exceeded budget: observed={value:.3f}ms budget={budgets[name]:.3f}ms"
    for name, value in observed.items()
    if value > budgets[name]
]
if errors:
    raise SystemExit("\n".join(errors))
out = {
    "ok": True,
    "budgetsMs": budgets,
    "observedMs": observed,
}
path = pathlib.Path("artifacts/browser_editor_responsiveness_gate.json")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print("browser-editor-responsiveness-ok")
PY
