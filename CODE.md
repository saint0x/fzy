# CODE.md

Fully verifiable, copy-paste examples for real fzy workflows.

All examples assume you are in repo root:

```bash
cd fozzylang
```

If `fz` is not installed globally, define a local fallback once in your shell:

```bash
if ! command -v fz >/dev/null 2>&1; then
  fz() { cargo run -q -p fz -- "$@"; }
fi
```

CLI behavior notes (current):
- Most path-based `fz` commands default to current working directory when `[path]` is omitted.
- `fz run` text mode streams child stdout/stderr live; `--json` captures structured `exitCode/stdout/stderr`.

## 1) Minimal fzy file: check/build/test

Create a tiny `.fzy` program:

```bash
cat > /tmp/code_min.fzy <<'FZY'
fn main() -> i32 {
    return 0
}
FZY
```

Run checks:

```bash
fz check /tmp/code_min.fzy --json
fz build /tmp/code_min.fzy --backend cranelift --json
fz test /tmp/code_min.fzy --det --seed 7 --json
```

Verify success:

```bash
fz check /tmp/code_min.fzy --json | jq -r '.diagnostics'
# expected: 0 (or no blocking errors)
```

## 2) Deterministic artifacts from a real example project

Run deterministic tests and emit rich artifacts:

```bash
fz test examples/live_server --det --seed 77 --record artifacts/live_server.code.trace.json --rich-artifacts --json
```

Verify artifact files exist:

```bash
ls -la artifacts/live_server.code.trace.json*
# expected to include trace/report/timeline/explore/shrink/scenarios/manifest files
```

## 3) Replay lifecycle on a recorded trace

```bash
fz replay artifacts/live_server.code.trace.json --json
fz ci artifacts/live_server.code.trace.json --json
fz shrink artifacts/live_server.code.trace.json --json
```

Verify replay/ci status:

```bash
fz ci artifacts/live_server.code.trace.json --json | jq -r '.ok // .status'
# expected: true or pass
```

## 4) Header generation from extern declarations

```bash
fz headers examples/fullstack --out artifacts/fullstack.from-code.h --json
```

Verify header output:

```bash
test -f artifacts/fullstack.from-code.h && echo ok
# expected: ok
```

## 5) RPC schema and stubs generation

```bash
fz rpc gen examples/fullstack --out-dir artifacts/fullstack.rpc --json
```

Verify generated files:

```bash
ls -la artifacts/fullstack.rpc
# expected: rpc.schema.json, rpc.client.fzy, rpc.server.fzy
```

## 6) ABI compatibility check

```bash
fz abi-check examples/fullstack/include/fullstack.abi.json --baseline examples/fullstack/include/fullstack.abi.json --json
```

Verify ABI check passes:

```bash
fz abi-check examples/fullstack/include/fullstack.abi.json --baseline examples/fullstack/include/fullstack.abi.json --json | jq -r '.ok // .status'
# expected: true or ok
```

## 7) Project convention gate (layout + module rules)

```bash
fz dx-check examples/fullstack --strict --json
fz dx-check examples/robust_cli --strict --json
fz dx-check examples/live_server --strict --json
```

Verify all three pass by exit code:

```bash
fz dx-check examples/fullstack --strict --json >/dev/null && echo fullstack-ok
fz dx-check examples/robust_cli --strict --json >/dev/null && echo robust-ok
fz dx-check examples/live_server --strict --json >/dev/null && echo live-ok
```

## 8) Formatting a directory of `.fzy` code

```bash
fz fmt examples/fullstack/src --json
fz fmt examples/robust_cli/src --json
```

Optional strict check via standalone formatter:

```bash
cargo run -q -p fozzyfmt -- examples/fullstack/src examples/robust_cli/src --check
# expected: "fozzyfmt: clean" when formatted
```

## 9) Generate API docs from `.fzy` source

```bash
cargo run -q -p fozzydoc -- examples/robust_cli/src --format markdown --out artifacts/robust_cli.api.from-code.md
```

Verify docs output:

```bash
test -f artifacts/robust_cli.api.from-code.md && rg -n "API Documentation|rpc|fn" artifacts/robust_cli.api.from-code.md
```

## 10) Deterministic run on a scenario file

```bash
fz run tests/run.pass.fozzy.json --det --record artifacts/run.pass.from-code.fozzy --json
```

Verify trace written:

```bash
test -f artifacts/run.pass.from-code.fozzy && echo recorded
# expected: recorded
```

## 11) Host-backed confidence run (real backends)

```bash
fz run tests/host.pass.fozzy.json --host-backends --json
```

Verify host-backed run status:

```bash
fz run tests/host.pass.fozzy.json --host-backends --json | jq -r '.status // .ok'
# expected: pass or true
```

## 12) Full “real work” sequence for a feature branch

```bash
# 1) format + static validation
fz fmt examples/fullstack/src --json
fz check examples/fullstack --json
fz dx-check examples/fullstack --strict --json

# 2) deterministic tests + trace artifacts
fz test examples/fullstack --det --seed 101 --record artifacts/fullstack.feature.trace.json --rich-artifacts --json

# 3) replay integrity
fz replay artifacts/fullstack.feature.trace.json --json
fz ci artifacts/fullstack.feature.trace.json --json

# 4) output interfaces
fz headers examples/fullstack --out artifacts/fullstack.feature.h --json
fz rpc gen examples/fullstack --out-dir artifacts/fullstack.feature.rpc --json
fz abi-check examples/fullstack/include/fullstack.abi.json --baseline examples/fullstack/include/fullstack.abi.json --json
```

Verify final gate quickly:

```bash
fz ci artifacts/fullstack.feature.trace.json --json | jq
```

## 13) Useful one-liners during debugging

```bash
# show CLI surface
fz --help

# inspect compiler version
fz version

# IR emission
fz emit-ir examples/fullstack --json

# parity/equivalence probes
fz parity examples/fullstack --seed 13 --json
fz equivalence examples/fullstack --seed 13 --json

# safety map
fz audit unsafe examples/fullstack --json
```

## 14) Known-good paths used in this repo

- fzy source examples: `examples/*/src/**/*.fzy`
- scenarios: `tests/*.fozzy.json`
- artifacts output: `artifacts/`
- runtime/cached compiler output: `.fz/`

## 15) Troubleshooting quick checks

If a command fails unexpectedly:

```bash
# 1) ensure CLI is wired
which fz
fz version

# 2) rebuild workspace metadata quickly
cargo check --workspace

# 3) rerun the failing command with --json
fz <command> ... --json
```

If deterministic replay fails:

```bash
# regenerate deterministic trace and replay
fz test examples/fullstack --det --seed 41 --record artifacts/repro.trace.json --json
fz replay artifacts/repro.trace.json --json
```
