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

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-browser-devtools-XXXXXX")"
NODE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fozzylang-browser-devtools-node-XXXXXX")"
PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
DEBUG_PORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR" "$NODE_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/public" "$WORK_DIR/src"
cat >"$WORK_DIR/fozzy.toml" <<'EOF'
[package]
name = "browser_devtools_proof"
version = "0.1.0"

[[target.bin]]
name = "browser_devtools_proof"
path = "src/main.fzy"
EOF

cat >"$WORK_DIR/src/main.fzy" <<'EOF'
capability io;

pub fn compute() -> i32 {
    let left = 20
    let right = 22
    return left + right
}
EOF

cat >"$WORK_DIR/public/index.html" <<'EOF'
<!doctype html>
<html>
  <body>
    <button id="run">Run</button>
    <div id="result">idle</div>
    <script type="module">
      import { __fz_compute } from '/__fz/build/main.js';
      window.__fzCompute = __fz_compute;
      document.getElementById('run').addEventListener('click', () => {
        const value = __fz_compute();
        document.getElementById('result').textContent = String(value);
      });
    </script>
  </body>
</html>
EOF

"${FZ_CMD[@]}" dev-server "$WORK_DIR" --entry "$WORK_DIR/src/main.fzy" --port "$PORT" >/tmp/fz-browser-devtools-smoke.log 2>&1 &
SERVER_PID=$!

python3 - <<'PY' "$PORT"
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("browser devtools smoke server did not become ready")
PY

(
  cd "$NODE_DIR"
  npm init -y >/dev/null 2>&1
  npm install --silent playwright >/dev/null
  cat > proof.js <<'EOF'
const { chromium } = require('playwright');
const http = require('http');

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(new Error(`failed parsing ${url}: ${error.message}\n${data}`));
        }
      });
    }).on('error', reject);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  const appUrl = process.env.FZ_DEVTOOLS_APP_URL;
  const debugPort = process.env.FZ_DEVTOOLS_DEBUG_PORT;
  const browser = await chromium.launch({
    headless: true,
    args: [
      `--remote-debugging-port=${debugPort}`,
      '--remote-allow-origins=*',
    ],
  });
  try {
    const page = await browser.newPage();
    await page.goto(appUrl, { waitUntil: 'load' });
    const targets = await getJson(`http://127.0.0.1:${debugPort}/json/list`);
    const target = targets.find((entry) => entry.url === appUrl);
    if (!target) {
      throw new Error(`missing inspected target for ${appUrl}`);
    }

    const inspector = await browser.newPage();
    await inspector.goto(
      `http://127.0.0.1:${debugPort}/devtools/inspector.html?ws=${target.webSocketDebuggerUrl.replace('ws://', '')}`,
      { waitUntil: 'load', timeout: 60000 },
    );
    await inspector.waitForTimeout(12000);

    const setup = await inspector.evaluate(async ({ appUrl }) => {
      const Breakpoints = await import('./models/breakpoints/breakpoints.js');
      const Workspace = await import('./models/workspace/workspace.js');
      const SDK = await import('./core/sdk/sdk.js');
      const workspace = Workspace.Workspace.WorkspaceImpl.instance();
      const uiSourceCodes = workspace.uiSourceCodes().map((code) => ({
        url: code.url(),
        name: code.name(),
        project: code.project().id(),
      }));
      const uiSourceCode = workspace.uiSourceCodes().find((code) => code.url() === `${appUrl}__fz/source/main.fzy`);
      if (!uiSourceCode) {
        return {
          ok: false,
          reason: 'missing-authored-source',
          uiSourceCodes,
        };
      }

      const models = SDK.TargetManager.TargetManager.instance().models(SDK.DebuggerModel.DebuggerModel);
      const mainScript = models
        .flatMap((model) => model.scripts())
        .find((script) => script.sourceURL === `${appUrl}__fz/build/main.js`);
      if (!mainScript || mainScript.sourceMapURL !== '/__fz/build/main.js.map') {
        return {
          ok: false,
          reason: 'missing-generated-script-or-sourcemap',
          scripts: models.flatMap((model) =>
            model.scripts().map((script) => ({
              url: script.sourceURL,
              sourceMapURL: script.sourceMapURL,
            })),
          ),
        };
      }

      const breakpointManager = Breakpoints.BreakpointManager.BreakpointManager.instance();
      const breakpoint = await breakpointManager.setBreakpoint(
        uiSourceCode,
        5,
        0,
        '',
        true,
        false,
        'USER_ACTION',
      );

      return {
        ok: true,
        breakpointCreated: !!breakpoint,
        authoredUrl: uiSourceCode.url(),
      };
    }, { appUrl });

    if (!setup.ok) {
      console.log(JSON.stringify(setup, null, 2));
      process.exit(1);
    }

    await page.evaluate(() => {
      setTimeout(() => document.getElementById('run').click(), 250);
    });

    let paused = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      paused = await inspector.evaluate(async () => {
        const SDK = await import('./core/sdk/sdk.js');
        const Bindings = await import('./models/bindings/bindings.js');
        const models = SDK.TargetManager.TargetManager.instance().models(SDK.DebuggerModel.DebuggerModel);
        const model = models[0];
        if (!model || !model.isPaused()) {
          return null;
        }
        const frame = model.selectedCallFrame() || model.debuggerPausedDetails()?.callFrames?.[0] || null;
        const rawLocation = frame?.location?.();
        const binding = Bindings.DebuggerWorkspaceBinding.DebuggerWorkspaceBinding.instance();
        const uiLocation = rawLocation ? await binding.rawLocationToUILocation(rawLocation) : null;
        const snapshot = {
          raw: {
            functionName: frame?.functionName || null,
            lineNumber: rawLocation?.lineNumber ?? null,
            columnNumber: rawLocation?.columnNumber ?? null,
            url: frame?.script?.sourceURL || null,
          },
          ui: uiLocation ? {
            url: uiLocation.uiSourceCode.url(),
            lineNumber: uiLocation.lineNumber,
            columnNumber: uiLocation.columnNumber,
          } : null,
        };
        await model.resume();
        return snapshot;
      });
      if (paused) {
        break;
      }
      await sleep(250);
    }

    if (!paused) {
      throw new Error('devtools-authored-breakpoint-did-not-pause');
    }
    if (paused.ui?.url !== `${appUrl}__fz/source/main.fzy`) {
      throw new Error(`unexpected authored url: ${JSON.stringify(paused)}`);
    }
    if (paused.ui?.lineNumber !== 5 || paused.ui?.columnNumber !== 0) {
      throw new Error(`unexpected authored ui location: ${JSON.stringify(paused)}`);
    }
    if (paused.raw?.url !== `${appUrl}__fz/build/main.js`) {
      throw new Error(`unexpected raw script url: ${JSON.stringify(paused)}`);
    }
    console.log('browser-devtools-sourcemap-ok');
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
EOF
  FZ_DEVTOOLS_APP_URL="http://127.0.0.1:${PORT}/" \
  FZ_DEVTOOLS_DEBUG_PORT="$DEBUG_PORT" \
    node proof.js
)
