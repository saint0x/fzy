# fzy

Correctness-first systems language toolchain with deterministic verification workflows.

FozzyLang pairs a language/compiler (`fozzyc`) with Fozzy runtime testing so determinism, replay, and artifact-driven debugging are first-class, not bolt-ons.

## What This Repo Contains

- `apps/fozzyc`: language CLI (build/run/test/verify/emit-ir/rpc gen/headers)
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
- Thread/async/RPC decision artifacts in `fozzyc test --det --record ...`
- RPC frame model events: `rpc_send`, `rpc_recv`, `rpc_deadline`, `rpc_cancel`
- Explore + shrink metadata artifacts for replay/shrink prioritization
- Language-native scenario generation from parsed `test` blocks (combined + per-test)
- Recursive multi-file module loading from `mod` declarations (`foo.fzy`, `foo/mod.fzy`, `foo::bar`)
- C header generation from exported `pub extern "C" fn` signatures
- RPC schema/client/server stub generation (`fozzyc rpc gen`)
- `fozzyc run` executes compiled native output and reports real process exit/stdout/stderr

## Build And Test

```bash
cargo check --workspace
cargo test --workspace
```

## Core CLI

```bash
# Build source/project
fozzyc build <path> [--release] [--threads N] [--backend llvm|cranelift] [--json]

# Run source/project or .fozzy scenario
fozzyc run <path> [--det] [--strict-verify] [--safe-profile] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--json]

# Test source/project or .fozzy scenario
fozzyc test <path> [--det] [--strict-verify] [--safe-profile] [--sched fifo|random|coverage_guided] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--json]

# Verify/check/IR
fozzyc check <path> [--json]
fozzyc verify <path> [--json]
fozzyc spec-check [--json]
fozzyc emit-ir <path> [--json]
fozzyc parity <path> [--seed N] [--json]
fozzyc equivalence <path> [--seed N] [--json]
fozzyc audit unsafe <path> [--json]
fozzyc vendor <project> [--json]
fozzyc abi-check <current.abi.json> --baseline <baseline.abi.json> [--json]
fozzyc debug-check <path> [--json]
fozzyc lsp diagnostics <path> [--json]
fozzyc lsp definition <path> <symbol> [--json]
fozzyc lsp hover <path> <symbol> [--json]
fozzyc lsp rename <path> <from> <to> [--json]
fozzyc lsp smoke <path> [--json]

# FFI / RPC outputs
fozzyc headers <path> [--out path] [--json]
fozzyc rpc gen <path> [--out-dir dir] [--json]
```

## Deterministic Artifacts

With `fozzyc test <file.fzy> --det --record artifacts/name.trace.json --json`, the driver emits:

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
- `c_shim` backend is removed and unsupported.
- Backend selection order:
  - explicit `--backend`
  - `FOZZYC_NATIVE_BACKEND`
  - profile default (`dev -> cranelift`, `release -> llvm`)

## Dependency Locking + Vendor

- Project builds enforce `fozzy.lock` drift checks for path dependencies.
- Lock drift fails builds until refreshed.
- Refresh lock + snapshot dependencies:

```bash
fozzyc vendor <project> --json
```

- Vendor command writes:
  - `fozzy.lock` (updated dependency graph hash)
  - `vendor/fozzy-vendor.json` (lock hash + per-dependency source/vendor hashes)

Spec: `docs/dependency-locking-v0.md`

## ABI Compatibility Gate

- `fozzyc abi-check` now enforces policy-level compatibility:
  - schema validity
  - package identity
  - panic boundary compatibility
  - baseline export presence + signature immutability
  - symbol version non-regression
- Additive exports are allowed.

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

fozzyc test /tmp/demo.fzy --det --sched random --seed 13 --record artifacts/demo.trace.json --json
```

Inspect:

- `artifacts/demo.trace.json`
- `artifacts/demo.trace.timeline.json`
- `artifacts/demo.trace.report.json`
- `artifacts/demo.trace.explore.json`
- `artifacts/demo.trace.shrink.json`
- `artifacts/demo.trace.scenarios.json`
- `artifacts/demo.trace.manifest.json`

## Generics v0 Example

Project: `examples/generics`

- Scoped container generics are accepted in v0 surface:
  - `Vec<T>`
  - `Option<T>`
  - `Result<T,E>`

Run parity check:

```bash
cargo run -q -p fozzyc -- parity examples/generics --seed 7 --json
```

## Complex Multi-File Exhibition

Project: `examples/exhibit`

- `src/main.fzy` orchestrates a realistic entry flow:
  - explicit capabilities (`time/rng/fs/net/proc/mem/thread`)
  - contracts (`requires` / `ensures`)
  - linear-resource cleanup via `defer close(...)`
  - `try ... catch ...`, `match`, `spawn`, `checkpoint`, `yield`, timeout/cancel markers
  - host syscall marker (`syscall.*`) behind extern ABI declarations
- `src/api/ffi.fzy` exposes `pub extern "C"` exports for header generation
- `src/api/rpc.fzy` defines unary + streaming RPC methods for schema/stub generation
- `src/model/types.fzy` uses `#[repr(...)]`, `struct`, and `enum` declarations
- `src/services/*` and `src/runtime/*` provide additional multi-file function/capability coverage

Run full flow:

```bash
cargo run -q -p fozzyc -- check examples/exhibit --json
cargo run -q -p fozzyc -- build examples/exhibit --json
cargo run -q -p fozzyc -- run examples/exhibit --json
cargo run -q -p fozzyc -- headers examples/exhibit --json
cargo run -q -p fozzyc -- rpc gen examples/exhibit --json
cargo run -q -p fozzyc -- test examples/exhibit --det --strict-verify --sched coverage_guided --seed 23 --record artifacts/exhibit_rich.trace.json --json
fozzy doctor --deep --scenario artifacts/exhibit_rich.trace.scenarios/all.fozzy.json --runs 5 --seed 23 --json
fozzy test --det --strict artifacts/exhibit_rich.trace.scenarios/all.fozzy.json --json
fozzy run artifacts/exhibit_rich.trace.scenarios/all.fozzy.json --det --record artifacts/exhibit_rich.goal.fozzy --json
fozzy trace verify artifacts/exhibit_rich.goal.fozzy --strict --json
fozzy replay artifacts/exhibit_rich.goal.fozzy --json
fozzy ci artifacts/exhibit_rich.goal.fozzy --json
```

## Fullstack Example (CLI DB + RPC + FFI)

Project: `examples/fullstack`

- Multi-module CLI-style data service flow with all implemented language/runtime hooks:
  - capabilities: `time/rng/fs/net/proc/mem/thread`
  - contracts (`requires` / `ensures`), `try/catch`, `match`, `defer`
  - structured async/task markers: `spawn`, `checkpoint`, `yield`, `async fn`
  - RPC declarations + call sites with deadline/cancel markers
  - C interop exports for header + ABI generation
  - host syscall marker path (`syscall.*`) for boundary verification
  - richer service topology:
    - auth + store + HTTP + replication + metrics modules
    - runtime worker/scheduler/supervisor task orchestration
    - deterministic + nondeterministic language-native test blocks
    - native replay decision stream includes `thread.schedule`, `async.schedule`, `rpc.frame`

Run full flow:

```bash
cargo run -q -p fozzyc -- check examples/fullstack --json
cargo run -q -p fozzyc -- build examples/fullstack --json
cargo run -q -p fozzyc -- run examples/fullstack --json
cargo run -q -p fozzyc -- headers examples/fullstack --json
cargo run -q -p fozzyc -- rpc gen examples/fullstack --json
cargo run -q -p fozzyc -- test examples/fullstack --det --sched coverage_guided --seed 41 --record artifacts/fullstack.trace.json --rich-artifacts --json
cargo run -q -p fozzyc -- replay artifacts/fullstack.trace.manifest.json --json
cargo run -q -p fozzyc -- shrink artifacts/fullstack.trace.manifest.json --json
cargo run -q -p fozzyc -- ci artifacts/fullstack.trace.manifest.json --json
fozzy doctor --deep --scenario artifacts/fullstack.trace.scenarios/all.fozzy.json --runs 5 --seed 41 --json
fozzy test --det --strict artifacts/fullstack.trace.scenarios/all.fozzy.json --json
fozzy run artifacts/fullstack.trace.scenarios/all.fozzy.json --det --record artifacts/fullstack.goal.fozzy --json
fozzy trace verify artifacts/fullstack.goal.fozzy --strict --json
fozzy replay artifacts/fullstack.goal.fozzy --json
fozzy ci artifacts/fullstack.goal.fozzy --json
```

## Plan Tracking

Execution status is maintained in:

- `PLAN.md` (undone-first, done+verified second, prose third)

When implementation changes, update `PLAN.md` immediately with accurate ✅/⬜ status.
