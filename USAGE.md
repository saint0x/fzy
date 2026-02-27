# fzy User Guide (USAGE.md)

This is the definitive user manual for working with the fzy toolchain in this repository.

It is optimized for onboarding and day-to-day developer experience:

- what to run
- when to run it
- how to interpret outputs
- team conventions to follow

It intentionally avoids deep internal compiler/runtime implementation details.

Canonical production workflow: `docs/production-workflow-v1.md`  
Failure triage playbook: `docs/production-failure-triage-v1.md`
Exit criteria tracking policy: `docs/exit-criteria-v1.md`
System safety/trust model: `docs/system-safety-trust-model-v1.md`

## 1. What You Use In Practice

You will mainly use these tools:

- `fz`: language/compiler/project workflow CLI
- `fozzy`: deterministic scenario testing, replay, fuzzing, diagnosis
- `fz fmt`: source formatter for `.fzy`
- `fz doc gen`: API docs extractor/generator for `.fzy`

In this repo, the canonical way to invoke local binaries is:

```bash
cargo run -q -p <tool> -- <args>
```

Examples:

```bash
cargo run -q -p fz -- check examples/fullstack --json
cargo run -q -p fz -- fmt examples/fullstack/src --check
cargo run -q -p fz -- doc gen examples/fullstack/src --format markdown --out artifacts/fullstack.api.md
```

If you have globally installed binaries, direct usage also works:

```bash
fozzy ...
fz ...
```

## 2. Prerequisites

Minimum expected environment:

- Rust toolchain (`cargo`) installed
- Run commands from repo root
- Network access only when you intentionally run host-backed scenarios

Recommended sanity check:

```bash
cargo check --workspace
cargo test --workspace
```

## 3. 10-Minute Quickstart

### 3.1 Validate one example project

```bash
cargo run -q -p fz -- dx-check examples/fullstack --strict --json
cargo run -q -p fz -- check examples/fullstack --json
cargo run -q -p fz -- build examples/fullstack --backend cranelift --json
cargo run -q -p fz -- run examples/fullstack --backend cranelift --json
cargo run -q -p fz -- test examples/fullstack --det --seed 41 --json
```

### 3.2 Format and generate docs

```bash
cargo run -q -p fz -- fmt examples/fullstack/src --check
cargo run -q -p fz -- doc gen examples/fullstack/src --format markdown --out artifacts/fullstack.api.md
```

### 3.3 Run Fozzy deterministic confidence flow

```bash
fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json
fozzy test --det --strict tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json
fozzy run tests/run.pass.fozzy.json --det --record artifacts/trace.fozzy --json
fozzy trace verify artifacts/trace.fozzy --strict --json
fozzy replay artifacts/trace.fozzy --json
fozzy ci artifacts/trace.fozzy --json
```

## 4. Core Mental Model

Treat your workflow as three layers:

1. Authoring layer (`.fzy` source and project layout)
2. Language toolchain layer (`fz` commands)
3. Deterministic validation layer (`fozzy` commands, trace lifecycle)

A complete change is not done when it only compiles. It is done when:

- project conventions pass (`dx-check`)
- deterministic tests pass (`fz test --det` and/or `fozzy test --det --strict`)
- at least one trace is recordable, verifiable, and replayable

## 5. `fz` Command Guide

## 5.1 Create and scaffold

```bash
fz init <name>
```

Use for new projects.

## 5.2 Build, run, test

```bash
fz build [path] [--release] [--lib] [--threads N] [--backend llvm|cranelift] [-l lib] [-L path] [-framework name] [--json]
fz run [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--max-seconds N] [--exit-on-healthcheck http://host:port/path] [--smoke-http http://host:port/path] [--json]
fz test [path] [--det] [--strict-verify] [--seed N] [--record path] [--host-backends] [--backend llvm|cranelift] [--sched fifo|random|coverage_guided] [--filter substring] [--json]
```

Use cases:

- `build`: compile only
- `build --lib`: emit `.a` + shared library (`.so`/`.dylib`) plus C header + ABI manifest
- `run`: execute a project or scenario once
  - text mode streams child stdout/stderr live
  - `--max-seconds` enforces bounded runtime (returns timeout exit code on limit)
  - `--exit-on-healthcheck` and `--smoke-http` probe an HTTP endpoint and exit once healthy/smoke-success is observed
- `test`: execute discovered tests with optional deterministic scheduler policy
  - `--host-backends` on native `.fzy` sources now auto-bridges through generated temporary scenario artifacts (single command flow)
- production memory safety verification is always enabled for `run` and `test`

Native host-backed runtime defaults:
- bind host default is `127.0.0.1` (`FZ_HOST` > `AGENT_HOST` > default)
- bind port default is `8787` (`FZ_PORT` > `AGENT_PORT` > `PORT` > default)
- runtime emits effective bind `addr/port` on successful `listen`
- runtime bootstraps env from `.env` (or `FZ_DOTENV_PATH`) before env/http calls
- HTTP transport diagnostics are available through `http.last_error`

Runtime logging defaults:
- human-readable logs by default (`[ts] level message`)
- structured fields appended as `| fields={...}`
- JSON logging is opt-in (`log.set_json(1)`)
- module-level capability declaration required for log APIs: `use core.log;`
- typed error policy surfaces use `use core.error;` in modules that rely on error contracts
- `use core.text;` is invalid; string intrinsics (`str.*`) do not require capability imports
- canonical structured logging fields use `log.fields(map_handle)`
- canonical dynamic JSON builders use `json.array(list_handle)` / `json.object(map_handle)`
- first-class object literal syntax is available for small map payloads: `#{ "k": json.str("v") }`
- canonical process builders use `proc.argv_new/push`, `proc.env_new/set`, `proc.spawn_cmd` / `proc.run_cmd`
- canonical persistence helpers use `storage.append`, `storage.atomic_append`, `storage.kv_open/get/put`
- shared helper surface is available under `core.util` for common JSON/log/http/concurrency patterns

## 5.3 Quality and verification

```bash
fz fmt [path]
fz check [path]
fz verify [path]
fz lint [path] [--tier production|pedantic|compat]
fz explain <diag-code>
fz doctor project [path] [--strict]
fz devloop [path] [--backend llvm|cranelift]
fz dx-check [project] [--strict]
fz spec-check
```

Recommended order for feature work:

1. `fmt`
2. `check`
3. `doctor project --strict`
4. `devloop`
5. `dx-check --strict`
6. `test --det`
7. `verify` or `spec-check` when relevant to your gate

## 5.4 Analysis and debugging commands

```bash
fz emit-ir [path]
fz perf [--artifact artifacts/bench_corelibs_rust_vs_fzy.json]
fz stability-dashboard
fz parity [path] [--seed N]
fz equivalence [path] [--seed N]
fz audit unsafe [path] [--workspace]
fz debug-check [path]
```

Use these when behavior is correct in one mode but drifts in another, or when hardening safety properties.
Unsafe island details (`unsafe fn`, `unsafe { ... }`, optional metadata, strict audit mode) are documented in `docs/unsafe-contract-authoring-v1.md`.
`fz audit unsafe --workspace` emits compiler-generated unsafe docs/inventory artifacts:
- `.fz/unsafe-map.workspace.json`
- `.fz/unsafe-docs.workspace.json`
- `.fz/unsafe-docs.workspace.md`
- `.fz/unsafe-docs.workspace.html`
Default production policy keeps missing metadata non-blocking; strict CI/release policy can make missing/invalid metadata blocking.
Hardened repositories can scope unsafe usage in `fozzy.toml`:
- `[unsafe].deny_unsafe_in = ["tests::*"]`
- `[unsafe].allow_unsafe_in = ["runtime::*"]`

Recommended native completeness probe:

```bash
fz parity tests/fixtures/native_completeness/main.fzy --seed 4242 --json
fz equivalence tests/fixtures/native_completeness/main.fzy --seed 4242 --json
python3 scripts/direct_memory_architecture_gate.py
python3 scripts/direct_memory_perf_gate.py
```

Import ergonomics surface in shipped examples:

- `use <path>::<item> as <alias>` executable alias import support
- `pub use <path>::<item>` executable re-export support

## 5.5 LSP helpers

```bash
fz lsp diagnostics [path]
fz lsp definition <path> <symbol>
fz lsp hover <path> <symbol>
fz lsp rename <path> <from> <to>
fz lsp smoke [path]
fz lsp serve [--path <workspace>]
```

Use these for scripted editor-like operations and refactoring checks.

## 5.6 FFI / RPC outputs and ABI checks

```bash
fz headers [path] [--out path]
fz rpc gen [path] [--out-dir dir]
fz abi-check <current.abi.json> --baseline <baseline.abi.json>
```

Typical use:

- generate or refresh C headers and RPC outputs
- compare ABI manifests before merge/release
- `#[ffi_panic(abort|error)]` is required on exported `pubext c fn`
- `ext unsafe c fn` imports require unsafe context at callsites (`unsafe { ... }` or `unsafe fn`)
- ABI contract weakening is breaking and rejected by `abi-check`
- full production interop contract: `docs/c-interop-production-v1.md`

## 5.7 Dependency locking and vendor

```bash
fz vendor [project]
```

When to run:

- after dependency graph updates
- when build/test reports lock drift

Expected outputs:

- `fozzy.lock`
- `vendor/fozzy-vendor.json`

## 5.8 Deterministic artifact flows

```bash
fz fuzz <scenario>
fz explore <scenario>
fz replay <trace>
fz shrink <trace>
fz ci <trace>
```

Use this family when you already have (or want) trace-driven debugging and minimization.

## 6. `fozzy` Command Guide

`fozzy` is your system-level deterministic testing plane.

High-level command map:

- everyday validation: `doctor`, `test`, `run`
- reproduction/integrity: `trace verify`, `replay`, `ci`
- failure investigation: `explore`, `shrink`, `report`, `artifacts`, `memory`, `profile`
- coverage and suites: `fuzz`, `corpus`, `map`, `gate`, `full`

## 6.1 Baseline confidence sequence (recommended)

```bash
fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json
fozzy test --det --strict <scenario...> --json
fozzy run <scenario> --det --record artifacts/<name>.fozzy --json
fozzy trace verify artifacts/<name>.fozzy --strict --json
fozzy replay artifacts/<name>.fozzy --json
fozzy ci artifacts/<name>.fozzy --json
```

Single-command strict ship release gate:

```bash
./scripts/ship_release_gate.sh
```

## 6.2 Host-backed confidence pass

Use host backends when you want real OS/process/fs/http behavior in addition to deterministic scripted checks:

```bash
fozzy run <scenario> --proc-backend host --fs-backend host --http-backend host --json
```

Notes:

- host-backed confidence runs are intentionally a separate pass from strict deterministic replay checks.
- for native `.fzy` tests, `fz test --host-backends` supports a single-command bridge that generates temporary scenarios and runs host-backed execution directly.

## 6.3 Useful discovery commands

```bash
fozzy usage
fozzy env --json
fozzy map suites --root . --scenario-root tests --profile pedantic --json
fozzy schema --json
fozzy validate <scenario> --json
```

## 7. Formatting and Documentation Tools

## 7.1 `fz fmt`

```bash
fz fmt <path> [<path> ...] [--check]
```

Use `--check` in CI/pre-commit to fail on style drift without rewriting files.

## 7.2 `fz doc gen`

```bash
fz doc gen <path> [--format json|html|markdown] [--out <file>] [--reference <language-reference.md>]
```

Typical workflows:

```bash
# Generate API doc snapshot
fz doc gen examples/robust_cli/src --format markdown --out artifacts/robust_cli.api.md

# Keep language reference synced with extracted API section
fz doc gen examples/robust_cli/src --format markdown --reference docs/language-reference-v1.md --out artifacts/robust_cli.api.md
```

## 8. Repository Conventions You Must Follow

Source of truth: `docs/project-conventions-v1.md`.

## 8.1 Required structure

Project layout:

- `src/main.fzy`
- `src/api/mod.fzy`
- `src/model/mod.fzy`
- `src/services/mod.fzy`
- `src/runtime/mod.fzy`
- `src/cli/mod.fzy`
- `src/tests/mod.fzy`

## 8.2 Main file rules

- module declarations in this order: `api`, `model`, `services`, `runtime`, `cli`, `tests`
- `fn main` is last top-level item
- no `test` declarations in `main.fzy`

## 8.3 Test placement

- all tests under `src/tests/*`
- `src/tests/mod.fzy` is the entry for test modules

## 8.4 Convention gate

Always run:

```bash
fz dx-check [project] --strict
```

## 9. Day-to-Day Workflows

## 9.1 Add or change feature code

1. Edit source.
2. `fz fmt <paths>`
3. `fz check [project] --json`
4. `fz dx-check [project] --strict --json`
5. `fz test [project] --det --seed <seed> --json`
6. For high confidence: record + replay a trace with `fozzy`.

## 9.2 Investigate flaky or nondeterministic failures

1. `fozzy doctor --deep --scenario ... --runs 5 --seed ... --json`
2. `fozzy run ... --det --record artifacts/fail.fozzy --json`
3. `fozzy trace verify artifacts/fail.fozzy --strict --json`
4. `fozzy replay artifacts/fail.fozzy --json`
5. `fozzy shrink artifacts/fail.fozzy --json`
6. `fozzy report ...` / `fozzy artifacts ...` for analysis

## 9.3 Prepare ABI-sensitive changes

1. Run/update generation:
   - `fz headers [path]`
   - `fz rpc gen [path]`
2. Compare ABI:
   - `fz abi-check <current.abi.json> --baseline <baseline.abi.json> --json`

## 9.4 Refresh dependency lock/vendor state

1. `fz vendor [project] --json`
2. rerun build/test pipeline

## 10. Artifacts and How To Read Them

You will commonly see artifacts in `artifacts/` and `.fozzy/runs/<runId>/`.

Common files:

- trace: deterministic execution record
- timeline: scheduling/event ordering view
- report: summarized findings and outcomes
- explore/shrink outputs: guided search and minimization hints
- manifest/index: artifact map and scenario listings

Operational rule:

- if a behavior is hard to reproduce, do not debug from logs alone; debug from recorded trace + replay.

## 11. Output Mode Conventions (`--json`)

Use `--json` when:

- running automation/CI
- collecting machine-readable evidence
- chaining commands in scripts

Use human output when:

- ad hoc local exploration
- quick manual checks

## 12. Release/CI Checklist (Practical)

For meaningful changes, run at least:

1. `cargo test --workspace`
2. `fz dx-check [project] --strict --json`
3. `fz test [project] --det --seed <seed> --json`
4. `fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json`
5. trace lifecycle:
   - `fozzy run ... --det --record ... --json`
   - `fozzy trace verify ... --strict --json`
   - `fozzy replay ... --json`
   - `fozzy ci ... --json`
6. one host-backed run when feasible:
   - `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`

## 13. Common Pitfalls and Fixes

- `dx-check` failure:
  - usually layout/order/tests placement mismatch; align with section 8.
- lock drift/build blocked:
  - run `fz vendor [project]`.
- deterministic replay mismatch:
  - verify trace file integrity with `fozzy trace verify --strict`.
- host-backend discrepancies:
  - keep deterministic and host-backed runs as separate confidence signals.

## 14. Command Reference Snapshot

`fz` top-level commands:

- `init`, `build`, `run`, `test`
- `fmt`, `check`, `verify`, `dx-check`, `spec-check`
- `emit-ir`, `parity`, `equivalence`, `audit unsafe`, `debug-check`
- `vendor`, `abi-check`
- `lsp diagnostics|definition|hover|rename|smoke|serve`
- `headers`, `rpc gen`
- `fuzz`, `explore`, `replay`, `shrink`, `ci`, `version`

`fozzy` top-level commands:

- `init`, `test`, `run`, `fuzz`, `explore`, `replay`, `trace`, `shrink`, `corpus`
- `artifacts`, `report`, `memory`, `profile`, `map`, `doctor`, `env`, `ci`, `gate`
- `version`, `usage`, `schema`, `validate`, `full`

## 15. Team DX Rules (Short Form)

- prefer deterministic-first validation
- always keep at least one replayable trace for meaningful fixes
- keep project layout conventional so tooling keeps working without custom glue
- treat `--json` outputs as the automation contract
- use host-backed runs as additional confidence, not a replacement for deterministic checks

## 16. Where To Go Next

- Language semantics: `docs/language-reference-v1.md`
- Stdlib behavior scope: `docs/stdlib-v1.md`
- Project conventions: `docs/project-conventions-v1.md`
- Dependency lock/vendor policy: `docs/dependency-locking-v1.md`
- ABI policy: `docs/abi-policy-v1.md`

---

If you are new to the repo, start with section 3, then section 9, then adopt section 12 as your default PR checklist.
