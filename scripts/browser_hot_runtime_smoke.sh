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

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-browser-hot-XXXXXX")"
PROBE_DIR="$WORK_DIR/probe"
STATIC_DIR="$WORK_DIR/static"
mkdir -p "$PROBE_DIR/public" "$PROBE_DIR/src" "$STATIC_DIR"

cleanup() {
  if [[ -n "${OVERLAY_SERVER_PID:-}" ]]; then
    kill "$OVERLAY_SERVER_PID" >/dev/null 2>&1 || true
    wait "$OVERLAY_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "${STATIC_SERVER_PID:-}" ]]; then
    kill "$STATIC_SERVER_PID" >/dev/null 2>&1 || true
    wait "$STATIC_SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cat >"$PROBE_DIR/fozzy.toml" <<'EOF'
[package]
name = "browser_hot_runtime"
version = "0.1.0"

[[target.bin]]
name = "browser_hot_runtime"
path = "src/main.fzy"
EOF

cat >"$PROBE_DIR/src/main.fzy" <<'EOF'
pub fn run() -> i32 {
    return 1
}
EOF

cat >"$PROBE_DIR/public/index.html" <<'EOF'
<!doctype html>
<html><body>overlay probe</body></html>
EOF

OVERLAY_PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

"${FZ_CMD[@]}" dev-server "$PROBE_DIR" --entry "$PROBE_DIR/src/main.fzy" --port "$OVERLAY_PORT" >/tmp/fz-browser-hot-overlay.log 2>&1 &
OVERLAY_SERVER_PID=$!

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$OVERLAY_PORT/__fz/health" >/dev/null; then
    break
  fi
  sleep 0.2
done

curl -fsS "http://127.0.0.1:$OVERLAY_PORT/__fz/overlay.js" >"$STATIC_DIR/overlay.js"

cat >"$STATIC_DIR/index.html" <<'EOF'
<!doctype html>
<html>
  <body>
    <div id="app">booting</div>
    <script>
      window.fetch = async () => ({ json: async () => ({ compiler: { diagnostics: [] }, runtimeErrors: [] }) });
      window.EventSource = class {
        addEventListener() {}
      };
    </script>
    <script src="./overlay.js"></script>
    <script type="module">
      window.addEventListener('load', () => {
        const root = document.getElementById('app');
        function boot() {
          const hot = window.__fozzyHot;
          if (!hot || typeof hot.registerBoundary !== 'function') {
            setTimeout(boot, 20);
            return;
          }
          let state = { count: 1 };
          let restored = false;
          hot.registerBoundary('demo-counter', {
            accept(payload) {
              window.__fzLastRevision = Number(payload?.revision || 0);
            },
            dispose() {
              state.count += 1;
            },
            capture() {
              return { count: state.count };
            },
            restore(saved) {
              state = saved || state;
              restored = true;
              root.textContent = `restored:${state.count}`;
            }
          });
          if (!window.__demoCounterReady) {
            window.__demoCounterReady = true;
            if (!restored) {
              root.textContent = `live:${state.count}`;
            }
            window.bumpDemo = () => {
              state.count += 1;
              root.textContent = `live:${state.count}`;
            };
          }
        }
        boot();
      });
    </script>
  </body>
</html>
EOF

STATIC_PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

python3 -m http.server "$STATIC_PORT" --bind 127.0.0.1 --directory "$STATIC_DIR" >/tmp/fz-browser-hot-static.log 2>&1 &
STATIC_SERVER_PID=$!

python3 - <<'PY' "$STATIC_PORT"
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("browser hot runtime static server did not become ready")
PY

cat >"$WORK_DIR/browser-hot.spec.js" <<'EOF'
const { test, expect } = require('@playwright/test');

test('browser hot runtime preserves registered boundary state across reload-safe restore', async ({ page }) => {
  await page.goto(process.env.FZ_BROWSER_HOT_URL, { waitUntil: 'load' });
  await expect(page.locator('#app')).toHaveText('live:1');
  await page.evaluate(() => window.bumpDemo());
  await expect(page.locator('#app')).toHaveText('live:2');
  await page.evaluate(() => {
    window.__fozzyHot.prepareForReload({
      revision: 7,
      strategy: 'reload',
      changedFiles: ['module:src/main.fzy']
    });
  });
  await page.goto(process.env.FZ_BROWSER_HOT_URL, { waitUntil: 'load' });
  await expect(page.locator('#app')).toHaveText('restored:3');
  await expect.poll(async () => page.evaluate(() => window.__fozzyHot.snapshot().revision || 0)).toBe(7);
});
EOF

(
  cd "$WORK_DIR"
  npm init -y >/dev/null 2>&1
  npm install --silent --save-dev @playwright/test >/dev/null
  FZ_BROWSER_HOT_URL="http://127.0.0.1:$STATIC_PORT/index.html" \
    npx playwright test browser-hot.spec.js --reporter=line --workers=1
)

echo "browser-hot-runtime-ok"
