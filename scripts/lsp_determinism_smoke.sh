#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build -p fz >/dev/null

FZ_BIN="${FZ_BIN:-}"
if [[ -z "$FZ_BIN" ]]; then
  FZ_BIN="$(find "$ROOT/target" -path "*/debug/fz" -perm -111 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "$FZ_BIN" || ! -x "$FZ_BIN" ]]; then
  FZ_BIN="fz"
fi

WORK_DIR="$ROOT/tmp/lsp_determinism"
mkdir -p "$WORK_DIR"
SAMPLE="$WORK_DIR/sample.fzy"
cat > "$SAMPLE" <<'SRC'
fn helper() -> i32 {
    return 1
}
fn main() -> i32 {
    return helper()
}
SRC

DIAG1="$WORK_DIR/diag1.json"
DIAG2="$WORK_DIR/diag2.json"
HOVER1="$WORK_DIR/hover1.json"
HOVER2="$WORK_DIR/hover2.json"
DEF1="$WORK_DIR/def1.json"
DEF2="$WORK_DIR/def2.json"

"$FZ_BIN" lsp diagnostics "$SAMPLE" --json > "$DIAG1"
"$FZ_BIN" lsp diagnostics "$SAMPLE" --json > "$DIAG2"
"$FZ_BIN" lsp hover "$SAMPLE" main --json > "$HOVER1"
"$FZ_BIN" lsp hover "$SAMPLE" main --json > "$HOVER2"
"$FZ_BIN" lsp definition "$SAMPLE" helper --json > "$DEF1"
"$FZ_BIN" lsp definition "$SAMPLE" helper --json > "$DEF2"

python3 - <<'PY' "$DIAG1" "$DIAG2" "$HOVER1" "$HOVER2" "$DEF1" "$DEF2"
import json
import sys

def canonical(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.dumps(json.loads(f.read()), sort_keys=True, separators=(",", ":"))

pairs = [(sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4]), (sys.argv[5], sys.argv[6])]
for left, right in pairs:
    if canonical(left) != canonical(right):
        raise SystemExit(f"nondeterministic LSP output: {left} != {right}")
PY

python3 - <<'PY' "$FZ_BIN" "$WORK_DIR"
import json
import subprocess
import sys

fz = sys.argv[1]
root = sys.argv[2]
proc = subprocess.Popen(
    [fz, "lsp", "serve", "--path", root],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

messages = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": f"file://{root}"}},
    {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "textDocument/hover", "params": {}},
    {"jsonrpc": "2.0", "method": "exit", "params": {}},
]

assert proc.stdin is not None
assert proc.stdout is not None

for msg in messages:
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    proc.stdin.write(header + body)
    proc.stdin.flush()

responses = {}
while len(responses) < 3:
    header = b""
    while b"\r\n\r\n" not in header:
        b = proc.stdout.read(1)
        if not b:
            break
        header += b
    if not header:
        break
    line = header.decode("utf-8", errors="replace")
    prefix = "Content-Length: "
    if prefix not in line:
        raise SystemExit("invalid lsp response header")
    size = int(line.split(prefix, 1)[1].split("\r\n", 1)[0])
    payload = proc.stdout.read(size)
    msg = json.loads(payload.decode("utf-8"))
    if "id" in msg:
        responses[msg["id"]] = msg

proc.wait(timeout=10)
if proc.returncode != 0:
    stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
    raise SystemExit(f"lsp server exited non-zero: {stderr}")

init = responses.get(1)
shutdown = responses.get(2)
post = responses.get(3)
if not init or "result" not in init:
    raise SystemExit("missing initialize response")
if not shutdown or shutdown.get("result", "sentinel") is not None:
    raise SystemExit("missing shutdown null result")
if not post or post.get("error", {}).get("code") != -32600:
    raise SystemExit("server did not reject request after shutdown")
PY

echo "lsp-determinism-smoke: ok"
