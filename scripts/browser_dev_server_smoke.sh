#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
WORK_DIR="$ROOT/tmp/browser_dev_server_smoke"
PORT="${FZ_BROWSER_DX_PORT:-4317}"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/public"

cat > "$WORK_DIR/fozzy.toml" <<'EOF'
[package]
name = "browser_dx_smoke"
version = "0.1.0"

[[target.bin]]
name = "browser_dx_smoke"
path = "src/main.fzy"
EOF

mkdir -p "$WORK_DIR/src"
cat > "$WORK_DIR/src/main.fzy" <<'EOF'
fn main() -> i32 {
    return 0
}
EOF

cat > "$WORK_DIR/public/index.html" <<'EOF'
<!doctype html>
<html>
  <body>
    <div id="app">browser dx smoke</div>
  </body>
</html>
EOF

"${FZ_CMD[@]}" dev-server "$WORK_DIR" --entry "$WORK_DIR/src/main.fzy" --port "$PORT" >/tmp/fz-browser-dev-server.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true; rm -rf "$WORK_DIR"' EXIT

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$PORT/__fz/health" >/dev/null; then
    break
  fi
  sleep 0.2
done

curl -fsS "http://127.0.0.1:$PORT/" | grep "/__fz/overlay.js" >/dev/null
curl -fsS "http://127.0.0.1:$PORT/__fz/overlay.js" | grep "Fozzy Browser Diagnostics" >/dev/null
curl -fsS "http://127.0.0.1:$PORT/__fz/diagnostics" | grep '"target":"browser"' >/dev/null
curl -fsS -X POST "http://127.0.0.1:$PORT/__fz/runtime-error" \
  -H 'content-type: application/json' \
  -d '{"message":"runtime smoke","frames":[{"file":"index.js","line":1,"column":1}]}' >/dev/null
curl -fsS "http://127.0.0.1:$PORT/__fz/diagnostics" | grep '"runtimeErrors"' >/dev/null

echo "browser-dev-server-smoke: ok"
