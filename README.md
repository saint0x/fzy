# fzy (fozzylang)

Correctness-first systems language toolchain with deterministic verification workflows.

fzy pairs a language/compiler (`fz`) with Fozzy runtime testing so determinism, replay, and artifact-driven debugging are first-class, not bolt-ons.

## Start Here

- Full user manual: `USAGE.md`
- Canonical production workflow: `docs/production-workflow-v1.md`
- System safety/trust model: `docs/system-safety-trust-model-v1.md`
- `fozzy`: [ariacomputecompany/fozzy](https://github.com/ariacomputecompany/fozzy)
- `fzyllm`: [saint0x/fzyllm](https://github.com/saint0x/fzyllm)

## What This Repo Contains

- compiler CLI (binary: `fz`) (build/run/test/verify/emit-ir/rpc gen/headers)
- `apps/fozzyfmt`: formatter
- `apps/fozzydoc`: docs extractor/generator
- `crates/parser`, `crates/ast`, `crates/hir`, `crates/fir`: front-end + IR pipeline
- `crates/verifier`: correctness/safety/capability checks
- `crates/runtime`: deterministic scheduler/executor primitives
- `crates/driver`: command orchestration + artifact emission
- `tests/*.fozzy.json`: executable Fozzy scenarios

## Current State (Practical)

Implemented and verified in this repo:

- Deterministic scheduler modes (`fifo`, `random`, `coverage_guided`) for non-scenario tests
- Thread/async/RPC decision artifacts in `fz test --det --record ...`
- RPC frame model events: `rpc_send`, `rpc_recv`, `rpc_deadline`, `rpc_cancel`
- Explore + shrink metadata artifacts for replay/shrink prioritization
- Language-native scenario generation from parsed `test` blocks (combined + per-test)
- Recursive multi-file module loading from `mod` declarations (`foo.fzy`, `foo/mod.fzy`, `foo::bar`)
- C header generation from exported `pub extern "C" fn` signatures
- RPC schema/client/server stub generation (`fz rpc gen`)
- `fz run` executes compiled native output:
  - text mode streams child stdout/stderr live (server-friendly)
  - json mode captures `exitCode/stdout/stderr` payloads
- Native HTTP runtime hardening:
  - transport failures preserve diagnostics through `http.last_error`
  - deterministic fallback failure status when HTTP status cannot be parsed
  - curl execution fallback paths (`curl`, `/usr/bin/curl`, `/opt/homebrew/bin/curl`)
- Language/native completeness:
  - closure/lambda lexical capture lowering parity in LLVM + Cranelift for supported forms
  - array/index expression family lowers natively in LLVM + Cranelift with execute-and-compare parity fixtures
  - module import surface includes executable `use ... as alias` and `pub use ...` re-export semantics

## Build And Test

```bash
cargo check --workspace
cargo test --workspace
```

## Core CLI

```bash
# Build source/project (path defaults to current working directory)
fz build [path] [--release] [--lib] [--threads N] [--backend llvm|cranelift] [-l lib] [-L path] [-framework name] [--json]

# Run source/project or .fozzy scenario (path defaults to current working directory)
fz run [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--json]

# Test source/project or .fozzy scenario (path defaults to current working directory)
fz test [path] [--det] [--strict-verify] [--sched fifo|random|coverage_guided] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--json]

# Verify/check/IR
fz check [path] [--json]
fz verify [path] [--json]
fz dx-check [project] [--strict] [--json]
fz spec-check [--json]
fz emit-ir [path] [--json]
fz parity [path] [--seed N] [--json]
fz equivalence [path] [--seed N] [--json]
fz audit unsafe [path] [--json]
fz vendor [project] [--json]
fz abi-check <current.abi.json> --baseline <baseline.abi.json> [--json]
fz debug-check [path] [--json]
fz lsp diagnostics [path] [--json]
fz lsp definition <path> <symbol> [--json]
fz lsp hover <path> <symbol> [--json]
fz lsp rename <path> <from> <to> [--json]
fz lsp smoke [path] [--json]
fz lsp serve [--path <workspace>] [--json]

# FFI / RPC outputs
fz headers [path] [--out path] [--json]
fz rpc gen [path] [--out-dir dir] [--json]
```

VS Code editor integration is available under `tooling/vscode` (language config, TextMate grammar, LSP client bootstrap to `fz lsp serve`).

Runtime defaults for native host-backed HTTP:
- bind host default: `127.0.0.1` (`FZ_HOST` > `AGENT_HOST` > default)
- bind port default: `8787` (`FZ_PORT` > `AGENT_PORT` > `PORT` > default)
- startup visibility: runtime prints effective bind target on successful `listen`
- env bootstrap: runtime loads `.env` (or `FZ_DOTENV_PATH`) once before env/http operations

Runtime logging defaults:
- default log format is human-readable text (`[ts] level message`)
- structured fields are appended as `| fields={...}`
- JSON log mode is opt-in via `log.set_json(1)`

## Deterministic Artifacts

With `fz test <file.fzy> --det --record artifacts/name.trace.json --json`, the driver emits:

- `*.trace.json`: deterministic execution trace (thread + async + RPC frame events)
- `*.timeline.json`: schedule decisions (`thread.schedule`, `async.schedule`, `rpc.frame`)
- `*.report.json`: summary + findings + failure-class grouping
- `*.explore.json`: schedule candidates + RPC frame permutations + scenario priorities
- `*.shrink.json`: deterministic shrink hints for minimization workflows
- `*.scenarios/`: generated language-native `.fozzy.json` scenarios
- `*.scenarios.json`: index for generated scenarios
- `*.manifest.json`: artifact map including primary scenario path

## Native Backend Policy

- Only two native compiler paths are supported:
  - `cranelift` (dev-default)
  - `llvm` (release-default)
- Backend selection order:
  - explicit `--backend`
  - `FZ_NATIVE_BACKEND`
  - profile default (`dev -> cranelift`, `release -> llvm`)

## Dependency Locking + Vendor

- Project builds enforce `fozzy.lock` drift checks for path dependencies.
- Lock drift fails builds until refreshed.
- Refresh lock + snapshot dependencies:

```bash
fz vendor [project] --json
```

- Vendor command writes:
  - `fozzy.lock` (updated dependency graph hash)
  - `vendor/fozzy-vendor.json` (lock hash + per-dependency source/vendor hashes)

Spec: `docs/dependency-locking-v1.md`

## ABI Compatibility Gate

- `fz abi-check` now enforces policy-level compatibility:
  - schema validity
  - package identity
  - panic boundary compatibility
  - baseline export presence + signature immutability
  - symbol version non-regression
- Additive exports are allowed.

## C Interop

- Production guide: `docs/c-interop-production-v1.md`
- `#[ffi_panic(abort|error)]` is required on every exported `pub extern "C" fn`.
- `fz build --lib` emits static/shared libraries plus installable header + ABI manifest.

## Fozzy-First Validation Contract

Use this exact sequence for strict confidence:

```bash
# 1) Determinism audit first
fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json

# 2) Strict deterministic tests
fozzy test --det --strict tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json

# 3) Record one real trace
fozzy run tests/run.pass.fozzy.json --det --record artifacts/trace.fozzy --json

# 4) Validate replay pipeline
fozzy trace verify artifacts/trace.fozzy --strict --json
fozzy replay artifacts/trace.fozzy --json
fozzy ci artifacts/trace.fozzy --json

# 5) Host-backed confidence pass
fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
```

Ship release gate (strict, no compatibility fallback):

```bash
./scripts/ship_release_gate.sh
```

This includes release-blocking docs claim-integrity checks via `scripts/safety_claim_integrity_gate.py`.

## Example: Native Test Lifecycle

```bash
cat >/tmp/demo.fzy <<'FZY'
test "alpha" {}
test "beta" nondet {}
rpc Ping(req: PingReq) -> PingRes;
async fn worker() -> i32 {}
fn main() -> i32 {
    timeout(1)
    return 0
}
FZY

fz test /tmp/demo.fzy --det --sched random --seed 13 --record artifacts/demo.trace.json --json
```

Inspect:

- `artifacts/demo.trace.json`
- `artifacts/demo.trace.timeline.json`
- `artifacts/demo.trace.report.json`
- `artifacts/demo.trace.explore.json`
- `artifacts/demo.trace.shrink.json`
- `artifacts/demo.trace.scenarios.json`
- `artifacts/demo.trace.manifest.json`

## Example Projects

All shipped examples follow the v1 narrative DX convention:

- `src/main.fzy` is orchestration-only and the `fn main` declaration is last.
- tests live under `src/tests/*` (no test declarations in `main.fzy`).
- domain module roots use `mod.fzy`:
  - `api`, `model`, `services`, `runtime`, `cli`, `tests`

Available projects:

- `examples/minimal_runtime`
- `examples/service_app`
- `examples/fullstack`
- `examples/robust_cli`
- `examples/live_server`

Validate a project:

```bash
cargo run -q -p fz -- dx-check examples/fullstack --strict --json
```

Run fullstack flow:

```bash
cargo run -q -p fz -- check examples/fullstack --json
cargo run -q -p fz -- build examples/fullstack --backend cranelift --json
cargo run -q -p fz -- build examples/fullstack --release --backend llvm --json
cargo run -q -p fz -- run examples/fullstack --backend cranelift --json
cargo run -q -p fz -- test examples/fullstack --det --seed 41 --backend llvm --json
cargo run -q -p fz -- headers examples/fullstack --json
cargo run -q -p fz -- abi-check examples/fullstack/include/fullstack.abi.json --baseline examples/fullstack/include/fullstack.abi.json --json
```

Run robust CLI app:

```bash
cargo run -q -p fz -- dx-check examples/robust_cli --strict --json
cargo run -q -p fz -- build examples/robust_cli --backend cranelift --json
cargo run -q -p fz -- run examples/robust_cli --backend llvm --json
cargo run -q -p fz -- test examples/robust_cli --det --seed 55 --backend cranelift --json
```

Run live server runtime + verified runtime stats:

```bash
cargo run -q -p fz -- dx-check examples/live_server --strict --json
cargo run -q -p fz -- build examples/live_server --backend cranelift --json
cargo run -q -p fz -- run examples/live_server --backend llvm --json
cargo run -q -p fz -- test examples/live_server --det --seed 77 --backend cranelift --record artifacts/live_server.stats.trace.json --rich-artifacts --json

# inspect runtime stats artifacts
cat artifacts/live_server.stats.trace.report.json
cat artifacts/live_server.stats.trace.timeline.json
cat artifacts/live_server.stats.trace.explore.json
```

Host-backed internet probe scenario:

```bash
fozzy run tests/live.server.internet.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
```

## Plan Tracking

Execution planning docs are tracked in-repo and versioned:

- `PLAN.md`
- `FEATURES-TO-SHIP.md`

Keep these updated during implementation as release and delivery source-of-truth documents.
