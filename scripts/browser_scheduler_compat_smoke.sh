#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-browser-scheduler-XXXXXX")"
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

BUILD_JSON="$(
  cargo run -q -p fz -- build tests/fixtures/browser_scheduler_js/main.fzy --backend js --sourcemap --json
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
    <title>Fzy Browser Scheduler Compat</title>
  </head>
  <body>
    <main id="app">pending</main>
    <script type="module">
      const events = [];
      let nextTaskId = 1;
      const taskResults = new Map();

      globalThis.__fozzyRuntime = {
        spawn(fn) {
          const id = nextTaskId++;
          events.push('spawn.schedule');
          taskResults.set(id, new Promise((resolve) => {
            queueMicrotask(async () => {
              events.push('spawn.run');
              resolve(await fn());
            });
          }));
          return id;
        },
        join(taskId) {
          events.push('join.await');
          return taskResults.get(taskId);
        },
        'browser.set_timeout'(ms, fn) {
          events.push(`timeout.schedule:${ms}`);
          return setTimeout(async () => {
            events.push('timeout.fire');
            await fn();
          }, ms);
        },
        'browser.clear_timeout'(handle) {
          clearTimeout(handle);
          events.push('timeout.clear');
          return 0;
        }
      };

      const mod = await import('./main.js');
      const value = await mod.__fz_run();
      document.getElementById('app').textContent = JSON.stringify({ value, events });
    </script>
  </body>
</html>
EOF

PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK_DIR" >/tmp/fz-browser-scheduler-compat.log 2>&1 &
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
raise SystemExit("browser scheduler compat server did not become ready")
PY

cat >"$WORK_DIR/browser-scheduler.spec.js" <<'EOF'
const { test, expect } = require('@playwright/test');

test('browser scheduler semantics remain compatible with browser event loop', async ({ page }) => {
  await page.goto(process.env.FZ_BROWSER_SCHEDULER_URL, { waitUntil: 'networkidle' });
  const payload = JSON.parse(await page.locator('#app').textContent());
  expect(payload.value).toBe(7);
  expect(payload.events).toEqual([
    'timeout.schedule:0',
    'spawn.schedule',
    'timeout.clear',
    'join.await',
    'spawn.run',
  ]);
});
EOF

(
  cd "$WORK_DIR"
  npm init -y >/dev/null 2>&1
  npm install --silent --save-dev @playwright/test >/dev/null
  FZ_BROWSER_SCHEDULER_URL="http://127.0.0.1:$PORT/index.html" \
    npx playwright test browser-scheduler.spec.js --reporter=line --workers=1 >/dev/null
)

echo "browser-scheduler-compat-ok"
