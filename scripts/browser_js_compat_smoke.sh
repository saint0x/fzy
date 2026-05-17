#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-browser-compat-XXXXXX")"
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/src"
cat >"$WORK_DIR/fozzy.toml" <<'EOF'
[package]
name="browser_compat"
version="0.1.0"

[[target.bin]]
name="browser_compat"
path="src/main.fzy"
EOF

cat >"$WORK_DIR/src/main.fzy" <<'EOF'
pub fn run(flag: bool) -> i32 {
    if flag {
        discard import("./lazy_chunk.mjs")
        return 7
    }
    return 3
}
EOF

cat >"$WORK_DIR/lazy_chunk.mjs" <<'EOF'
globalThis.__fzLazyChunkLoaded = (globalThis.__fzLazyChunkLoaded || 0) + 1;
export function lazyValue() {
  return 7;
}
EOF

mkdir -p "$WORK_DIR/public"
cat >"$WORK_DIR/public/index.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Fzy Browser Compat</title>
  </head>
  <body>
    <main id="app">pending</main>
    <script type="module">
      import { __fz_run } from '/__fz/build/main.js';
      document.getElementById('app').textContent = String(__fz_run(true));
    </script>
  </body>
</html>
EOF

BUILD_JSON="$(
  cargo run -q -p fz -- build "$WORK_DIR" --backend js --sourcemap --json
)"

JS_PATH="$(
  python3 - <<'PY' "$BUILD_JSON"
import json, sys
print(json.loads(sys.argv[1])["output"])
PY
)"

MAP_PATH="$(
  python3 - <<'PY' "$BUILD_JSON"
import json, sys
print(json.loads(sys.argv[1])["sourcemapOutput"])
PY
)"

cp "$JS_PATH" "$WORK_DIR/main.js"
cp "$MAP_PATH" "$WORK_DIR/main.js.map"

cat >"$WORK_DIR/index.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Fzy Browser Compat</title>
  </head>
  <body>
    <main id="app">pending</main>
    <script type="module">
      import { __fz_run } from './main.js';
      document.getElementById('app').textContent = String(__fz_run(true));
    </script>
  </body>
</html>
EOF

node --input-type=module - <<'EOF' "$WORK_DIR/main.js"
const path = process.argv[2];
const mod = await import(`file://${path}`);
if (mod.__fz_run(true) !== 7 || mod.__fz_run(false) !== 3) {
  throw new Error('node direct import contract failed');
}
for (let i = 0; i < 100 && !globalThis.__fzLazyChunkLoaded; i += 1) {
  await new Promise((resolve) => setTimeout(resolve, 20));
}
if (!globalThis.__fzLazyChunkLoaded) {
  throw new Error('lazy chunk did not load through dynamic import boundary');
}
EOF

npx --yes esbuild "$WORK_DIR/main.js" --bundle --format=esm --outfile="$WORK_DIR/esbuild-out.js" >/dev/null
test -s "$WORK_DIR/esbuild-out.js"

npx --yes rollup "$WORK_DIR/main.js" --format esm --dir "$WORK_DIR/rollup-out" >/dev/null
test -s "$WORK_DIR/rollup-out/main.js"

(
  cd "$WORK_DIR"
  npx --yes vite build --outDir vite-dist >/dev/null
)
test -s "$WORK_DIR/vite-dist/index.html"

bun build "$WORK_DIR/main.js" --outfile "$WORK_DIR/bun-out.js" >/dev/null
test -s "$WORK_DIR/bun-out.js"

PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK_DIR" >/tmp/fz-browser-js-compat.log 2>&1 &
SERVER_PID=$!

python3 - <<'PY' "$PORT"
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 5
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("browser compat server did not become ready")
PY

cat >"$WORK_DIR/browser-compat.spec.js" <<'EOF'
const { test, expect } = require('@playwright/test');

test('direct browser loading executes emitted module', async ({ page }) => {
  await page.goto(process.env.FZ_BROWSER_COMPAT_URL, { waitUntil: 'networkidle' });
  await expect(page.locator('#app')).toHaveText('7');
  await expect.poll(async () => page.evaluate(() => globalThis.__fzLazyChunkLoaded || 0)).toBeGreaterThan(0);
});
EOF

(
  cd "$WORK_DIR"
  npm init -y >/dev/null 2>&1
  npm install --silent --save-dev @playwright/test >/dev/null
  FZ_BROWSER_COMPAT_URL="http://127.0.0.1:$PORT/index.html" \
    npx playwright test browser-compat.spec.js --reporter=line --workers=1
)

echo "browser-js-compat-ok"
