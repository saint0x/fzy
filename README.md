# fzy (fozzylang)

General-purpose systems language and production toolchain with a memory-safe-by-default shipped safe-language surface, verifiable correctness, deterministic execution, and replay-first debugging built in.

fzy ships one production CLI, `fz`, for both compiler workflows and deterministic validation. Correctness, determinism, replay, incident artifacts, and production evidence are part of the normal workflow rather than an afterthought. For a quick visual tour of the language, open the shipped [FZL showcase](./fzl-showcase.html) in your browser with `open fzl-showcase.html`. For the short argument for why you might pick it, see [WHYFZY.md](./WHYFZY.md).

## Start Here

- Install: `INSTALL.md`
- Full manual: `USAGE.md`
- Why fzy: `WHYFZY.md`
- Syntax and command examples: `CODE.md`
- Production workflow: `docs/production-workflow-v1.md`
- Safety and trust model: `docs/system-safety-trust-model-v1.md`
- Unsafe authoring: `docs/unsafe-contract-authoring-v1.md`
- Stability tiers: `docs/language-stability-v1.md`
- Workspace policy inheritance: `docs/workspace-policy-v1.md`
- Operational insights: `docs/operational-insights-v1.md`
- `fzyllm`: [saint0x/fzyllm](https://github.com/saint0x/fzyllm)

## Install

Recommended install:

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh
```

That installs `fz` to `~/.local/bin`, updates `PATH` if needed, and verifies the install with `fz version` and `fz env`.

Source fallback:

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh -s -- --from-source
```

## Quick Look

Want the fastest overview? Open [fzl-showcase.html](./fzl-showcase.html) with `open fzl-showcase.html`, skim [WHYFZY.md](./WHYFZY.md) for the product argument, then use the sample below as a compact executable sketch.

```fzy
use core.log;
use core.path;
use core.process;
use core.time;

enum Mode {
    Fast,
    Safe,
}

trait Scorer {
    fn score(endpoint: Url) -> i32;
}

struct HttpScorer {}

impl Scorer for HttpScorer {
    fn score(endpoint: Url) -> i32 {
        discard endpoint;
        return 7;
    }
}

struct Config<TEndpoint> {
    retries: i32,
    endpoint: TEndpoint,
    mode: Mode,
}

fn weight(mode: Mode) -> i32 {
    match mode {
        Mode::Fast => return 3,
        Mode::Safe => return 1,
        _ => return 1,
    }
}

async fn boost(v: i32) -> i32 {
    checkpoint()
    return v + 1
}

fn normalize<T: Scorer>(cfg: Config<Url>) -> i32 {
    return weight(cfg.mode) + T.score(cfg.endpoint)
}

async fn run_once(cfg: Config<Url>) -> i32 {
    let base = normalize<HttpScorer>(cfg)
    return await boost(base)
}

fn main() -> i32 {
    let cfg = Config { retries: 4, endpoint: url.parse("https://example.test"), mode: Mode::Fast }
    let now = time.now()
    let out_path = path.join("tmp", "score.log")
    let mode = process.argv_or(1, "showcase")
    let score = normalize<HttpScorer>(cfg)
    log.info("snippet.run", out_path)
    discard mode
    discard run_once
    if score + now > 0 then return score
    return score
}
```

For broader language coverage, use `CODE.md`, `examples/`, and the browser-friendly [FZL showcase](./fzl-showcase.html).

## What fzy Contains

- `fz`: compiler CLI for build, run, test, verify, docs, IR, RPC, headers, ABI checks, and more
- built-in formatting and docs generation: `fz fmt`, `fz doc gen`
- front-end and IR pipeline: `crates/parser`, `crates/ast`, `crates/hir`, `crates/fir`
- verifier and safety enforcement: `crates/verifier`
- deterministic runtime primitives: `crates/runtime`
- driver and artifact orchestration: `crates/driver`
- executable Fozzy scenarios: `tests/*.fozzy.json`

## Current State

Implemented and validated today:

- general-purpose systems-language scope, not a niche single-domain tool
- safe by default, with explicit unsafe islands, compiler-generated unsafe inventory/docs, and opt-in manual memory management via `alloc(...)` / `free(...)`
- real runtime `defer` semantics across normal code and `unsafe { ... }` islands, so deterministic cleanup is enforced rather than merely documented
- verifier-enforced ownership, borrow, capability, FFI, and native-lowerability rules
- explicit manual memory management is supported inside that model, with ownership-aware `alloc(...)` / `free(...)` flows and verifier-visible lifecycle checks
- deterministic trace, replay, and scheduler validation as normal production gates
- host-backed confidence paths for filesystem, process, and HTTP behavior
- deterministic scheduler modes: `fifo`, `random`, `coverage_guided`
- decision artifacts for async, thread, and RPC execution
- RPC frame events: `rpc_send`, `rpc_recv`, `rpc_deadline`, `rpc_cancel`
- explore and shrink metadata for replay/minimization workflows
- language-native scenario generation from parsed `test` blocks
- recursive multi-file module loading from `mod` declarations
- C header generation from exported `pubext c fn` signatures
- RPC schema, client, and server stub generation via `fz rpc gen`
- modern language/runtime surface across ADTs, pattern matching, traits, generics, JSON, process, terminal, logging, filesystem/path, and outbound streaming HTTP
- production crypto/security surface via `core.crypto` and `core.security`, including secure random, hashing, HMAC, constant-time compare, and URL-safe encodings
- `fzweb` production web framework modules for app routing, cookies, sessions, multipart uploads, persistence, SSE, websockets, and OpenAPI export
- `fz run` executes native output directly with live text streaming or JSON capture
- LLVM and Cranelift native backends with parity-oriented validation
- direct-memory release gates:
  - `python3 scripts/direct_memory_architecture_gate.py`
  - `python3 scripts/direct_memory_perf_gate.py`

## Production Claims

fzy is set up to support these production claims today:

- the shipped safe-language surface is memory-safe by default within the documented verifier/compiler rule scope, with explicit audited unsafe boundaries and opt-in ownership-tracked manual memory management
- `alloc(...)` / `free(...)` stay in safe code when the compiler can still verify ownership, provenance, and cleanup execution
- verifiable correctness through the verifier, diagnostics, deterministic testing, replay, and CI artifacts
- deterministic execution through recorded traces, replay, and scheduler control
- general-purpose systems coverage across async/tasks, RPC, ADTs, traits/generics, process control, terminal I/O, logging, filesystem/path, JSON work, and streaming HTTP
- production web/service coverage through `fzweb` plus security primitives that keep session/cookie/auth flows inside the supported runtime surface

See also:

- `docs/system-safety-trust-model-v1.md`
- `docs/production-memory-model-v1.md`
- `docs/production-workflow-v1.md`

## Build And Test

```bash
cargo check --workspace
cargo test --workspace
```

## Core CLI

```bash
# Scaffold a project in the current directory or a target path
fz init [path] [--name package] [--template minimal|rust|ts] [--with run,fuzz,explore,memory,host|all] [--force]

# Build source/project
fz build [path] [--release] [--lib] [--threads N] [--backend llvm|cranelift] [--pgo-generate|--pgo-use file] [-l lib] [-L path] [-framework name] [--json]

# Run source/project or .fozzy scenario
fz run [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--max-seconds N] [--exit-on-healthcheck URL] [--smoke-http URL] [-- <args>] [--json]

# Test source/project or .fozzy scenario
fz test [path] [--det] [--strict-verify] [--sched fifo|random|coverage_guided] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--filter substring] [--json]

# Verify/check/docs/tooling
fz fmt [path ...] [--check] [--json]
fz check [path] [--json]
fz verify [path] [--json]
fz lint [path] [--tier production|pedantic|compat] [--json]
fz dx-check [project] [--strict] [--json]
fz spec-check [--json]
fz emit-ir [path] [--json]
fz perf [--artifact artifacts/bench_corelibs_rust_vs_fzy.json] [--json]
fz stability-dashboard [--json]
fz parity [path] [--seed N] [--json]
fz equivalence [path] [--seed N] [--json]
fz audit unsafe [path] [--workspace] [--json]
fz vendor [project] [--json]
fz abi-check <current.abi.json> --baseline <baseline.abi.json> [--json]
fz debug-check [path] [--json]
fz pgo merge [path] [--out file] [--json]
fz lsp diagnostics [path] [--json]
fz lsp definition <path> <symbol> [--json]
fz lsp hover <path> <symbol> [--json]
fz lsp rename <path> <from> <to> [--json]
fz lsp smoke [path] [--json]
fz lsp serve [--path <workspace>] [--json]
fz map suites [--root dir] [--scenario-root dir] [--profile pedantic|production|compat] [--json]
fz artifacts ls latest [--json]
fz report show latest [--format json|text] [--json]
fz usage [--json]
fz env [--json]
fz schema [--json]
fz validate <scenario> [--json]
fz trace verify <trace> [--strict] [--json]
fz replay <trace> [--json]
fz shrink <trace> [--json]
fz ci <trace> [--json]
fz trace-native <trace.fozzy> [--out path] [--json]

# FFI / RPC / docs outputs
fz headers [path] [--out path] [--json]
fz rpc gen [path] [--out-dir dir] [--json]
fz doc gen [path] [--format json|html|markdown] [--out path] [--reference path] [--json]
```

VS Code integration lives in `tooling/vscode` and targets `fz lsp serve`.

Runtime defaults and surfaced behavior:

- host bind default: `127.0.0.1`
- port default: `8787`
- effective bind target is printed on successful `listen`
- `.env` or `FZ_DOTENV_PATH` is loaded once before env/HTTP operations
- text logs are the default; JSON logs are opt-in via `log.set_json(1)`
- standard library surface includes `core.process`, `core.term`, `core.thread`, `core.log`, `core.text`, `core.io`, `core.path`, and `core.util`
- terminal-safe string escapes, structured log fields, JSON builders, JSON key iteration, and map-backed object literals are first-class
- process helpers support argv/env builders plus spawn/run flows with wait/stdout/stderr/exit inspection
- `core.crypto` and `core.security` cover secure random, digests, HMAC, URL-safe encodings, and constant-time comparisons for production auth/session flows
- `fzweb` ships concern-grouped framework modules plus built-in routes for health, readiness, metrics, inspect, search, cookies, sessions, uploads, events, websockets, item CRUD, OpenAPI, and static assets

## Deterministic Artifacts

With `fz test <file.fzy> --det --record artifacts/name.trace.json --json`, the driver emits:

- `*.trace.json`: deterministic execution trace
- `*.timeline.json`: schedule decisions
- `*.report.json`: summary, findings, and failure grouping
- `*.explore.json`: schedule candidates and scenario priorities
- `*.shrink.json`: deterministic shrink hints
- `*.scenarios/` and `*.scenarios.json`: generated language-native scenarios
- `*.manifest.json`: artifact map including the primary scenario path

## Native CLI Surface

Canonical authoring split:

- `core.process`, `core.term`, `core.text`: argv and terminal UX
- `core.log`: logging policy and structured output
- `core.io`, `core.path`: filesystem discovery and path assembly
- `proc.*`: child-process execution

Example:

```fzy
use core.log;
use core.process;
use core.term;
use core.text;

fn main() -> i32 {
    let mode = process.argv_or(1, "serve")
    discard log.set_sink_name("stderr")
    discard log.set_level_name("warn")
    discard term.transcript_kv("mode", mode, 8)
    if term.is_interactive() == 1 {
        discard term.eprint_line(str.concat("interactive=", str.from_i32(term.is_interactive())))
    }
    discard term.print_line(text.indent("ready\nwaiting", "  "))
    return 0
}
```

EOF is explicit:

- empty line: `term.read_line() == ""` and `term.stdin_eof() == 0`
- EOF: `term.read_line() == ""` and `term.stdin_eof() == 1`

For serious CLI/runtime work, use both the compiler-integrated launcher and the built binary when exact terminal behavior matters.

## Native Backend Policy

- supported backends: `cranelift` and `llvm`
- selection order: explicit `--backend`, then `FZ_NATIVE_BACKEND`, then profile default
- profile defaults: `dev -> cranelift`, `release -> llvm`

## Dependency Locking + Vendor

- project builds enforce `fozzy.lock` drift checks for path dependencies
- refresh lock state with `fz vendor [project] --json`
- vendor output includes `fozzy.lock` and `vendor/fozzy-vendor.json`
- spec: `docs/dependency-locking-v1.md`

## ABI Compatibility Gate

`fz abi-check` enforces:

- schema validity
- package identity
- panic boundary compatibility
- baseline export presence and signature immutability
- baseline contract immutability
- symbol version non-regression

Additive exports are allowed.

## C Interop

- guide: `docs/c-interop-production-v1.md`
- every exported `pubext c fn` requires `#[ffi_panic(abort|error)]`
- prefer `ext unsafe c fn` for unsafe C imports and call them only inside `unsafe { ... }`
- `fz build --lib` emits static/shared libraries plus an installable header and ABI manifest
  - current backend contract is Cranelift-only for library builds; explicit `--backend llvm` is rejected with a migration hint

## Unsafe Docs Artifacts

- unsafe is first-class via `unsafe fn` and `unsafe { ... }`
- `fz audit unsafe --workspace --json` emits `.fz/unsafe-map.workspace.json`, `.fz/unsafe-docs.workspace.json`, `.fz/unsafe-docs.workspace.md`, and `.fz/unsafe-docs.workspace.html`
- metadata fields such as `reason`, `invariant`, `owner`, `scope`, `risk_class`, and `proof_ref` are compiler-generated and policy-driven
- the default production flow is non-blocking for missing metadata unless strict unsafe policy is enabled
- optional hardened scope controls live in `fozzy.toml`

## Deterministic Validation Contract

Use this sequence for strict confidence:

```bash
# 1) Determinism audit first
fz doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json

# 2) Strict deterministic tests
fz test --det --strict-verify tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json

# 3) Record one real trace
fz run tests/run.pass.fozzy.json --det --record artifacts/trace.fozzy --json

# 4) Validate replay pipeline
fz trace verify artifacts/trace.fozzy --strict --json
fz replay artifacts/trace.fozzy --json
fz ci artifacts/trace.fozzy --json

# 5) Host-backed confidence pass
fz run tests/host.pass.fozzy.json --host-backends --json
```

Strict release gate:

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

- `src/main.fzy` is orchestration-only and places `fn main` last
- tests live under `src/tests/*`
- domain module roots use `mod.fzy`

Available projects:

- `examples/agent_runtime`
- `examples/context_runtime`
- `examples/minimal_runtime`
- `examples/service_app`
- `examples/fullstack`
- `examples/robust_cli`
- `examples/live_server`

Validation and project flows:

```bash
fz dx-check examples/fullstack --strict --json

fz check examples/fullstack --json
fz build examples/fullstack --backend cranelift --json
fz build examples/fullstack --release --backend llvm --json
fz run examples/fullstack --backend cranelift --json
fz test examples/fullstack --det --seed 41 --backend llvm --json
fz headers examples/fullstack --json
fz abi-check examples/fullstack/include/fullstack.abi.json --baseline examples/fullstack/include/fullstack.abi.json --json

fz dx-check examples/robust_cli --strict --json
fz build examples/robust_cli --backend cranelift --json
fz run examples/robust_cli --backend llvm --json
fz test examples/robust_cli --det --seed 55 --backend cranelift --json

fz dx-check examples/live_server --strict --json
fz build examples/live_server --backend cranelift --json
fz run examples/live_server --backend llvm --json
fz test examples/live_server --det --seed 77 --backend cranelift --record artifacts/live_server.stats.trace.json --rich-artifacts --json

fz run tests/live.server.interhttp.fozzy.json --host-backends --json
```

If you are contributing from a checkout instead of installing a release build, use `cargo run -q -p fz -- <args>` as a source-only fallback.

## Plan Tracking

Keep these versioned delivery documents updated during implementation:

- `PLAN.md`
- `FEATURES-TO-SHIP.md`
