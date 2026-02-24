# FEATURES-TO-SHIP.md

## 1) Undone First (Execution Queue)

### 1.0 P0 — Semantic Trust Contracts (Do First)
- [x] ✅ P0.1: Ship `docs/language-reference-v0.md` with normative semantics for evaluation order, overflow, async cancellation, capability semantics, deterministic scheduling scope, and panic/FFI boundaries.
- [x] ✅ P0.1: Add `fozzyc spec-check` gate that fails when required spec sections are missing.
- [x] ✅ P0.2: Add mode parity harness `fozzyc parity <path> --seed N --json` across `fast`, `det`, and `verify`.
- [x] ✅ P0.2: Emit a normalized semantic signature hash (exit class, normalized outputs, event categories, invariant outcomes) per mode.
- [x] ✅ P0.3: Add native-vs-scenario-vs-host equivalence suite with shared semantic signatures.
- [x] ✅ P0.3: Gate equivalence on pass/fail class, invariant set, and normalized event kinds.
- [x] ✅ P0.4: Split strict semantics from safe-profile enforcement with explicit flags (`--strict-verify`, `--safe-profile`) and remove `--strict` backward compatibility from `fozzyc` CLI.

### 1.1 P1 — Runtime + Safety Hardening
- [x] ✅ P1.1: Replace source-marker-derived deterministic scheduling hints with execution-derived runtime instrumentation at FIR/lowered scheduling points.
- [x] ✅ P1.1: Record causal scheduling evidence in trace artifacts and replay from runtime events.
- [x] ✅ P1.1: Add adversarial scheduler corpus covering starvation/deadlock/preemption claims.
- [x] ✅ P1.2: Publish explicit safe-profile v0 guarantees, rejected patterns, and out-of-scope cases.
- [x] ✅ P1.2: Require reason strings for unsafe escapes and emit `unsafe-map.json`.
- [x] ✅ P1.2: Add `fozzyc audit unsafe` command for unsafe accountability.
- [x] ✅ P1.3: Add deterministic dependency graph hashing and lockfile (`fozzy.lock`) for path dependencies.
- [x] ✅ P1.3: Add optional `fozzyc vendor` workflow.
- [x] ✅ P1.4: Publish ABI policy (`docs/abi-policy-v0.md`) for layout stability, symbol/versioning policy, and breaking-change handling.
- [x] ✅ P1.4: Add ABI compatibility checker command using baseline `*.abi.json`.

### 1.2 P2 — Language + Tooling Readiness
- [x] ✅ P2.1: Implement scoped generics v0 (container type acceptance + generic instantiation capture).
- [x] ✅ P2.1: Add deterministic parity coverage for generic container usage (`examples/generics`).
- [x] ✅ P2.2: Add debug symbol and async-backtrace readiness checks (`fozzyc debug-check`).
- [x] ✅ P2.2: Deliver minimal LSP set (definition, diagnostics, hover, rename) with workspace smoke tests.

### 1.3 DX — Rust-Like Entrypoint Conventions
- [ ] ⬜ DX1: Upgrade `fozzyc init` scaffold to `src/main.fzy` entrypoint + `mod app;` fan-out with module directories.
- [ ] ⬜ DX2: Add `main.fzy` complexity lint (warn when orchestration boundary is violated).
- [ ] ⬜ DX3: Publish module layout convention docs for app/model/services/runtime splits.

---

## 2) Completed (Verified)

### 2.0 Confirmed Baseline Strengths
- [x] ✅ Native build/run + deterministic replay tooling are implemented and runnable.
- [x] ✅ Deterministic artifact contract exists (`trace`, `timeline`, `report`, `explore`, `shrink`, `manifest`).
- [x] ✅ FFI contract generation/enforcement exists (`headers`, `*.abi.json`, panic-boundary checks).
- [x] ✅ Rust-like multi-file fan-out already works from `src/main.fzy` via `mod ...;`.

### 2.1 Fozzy-First Validation Evidence (Current)
- [x] ✅ `fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json` passes with consistent signatures.
- [x] ✅ `fozzy test --det --strict tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json` passes.
- [x] ✅ Trace lifecycle passes: run+record -> trace verify -> replay -> ci.
- [x] ✅ Non-scenario deterministic trace emission works with native replay/explore/ci artifact flow.

### 2.2 Section Implemented In This Pass
- [x] ✅ P0.4 strict/safe split implemented in `fozzyc` CLI and driver command model (no backwards compatibility for `--strict`).
- [x] ✅ P1.3 lockfile hardening completed: deterministic dependency graph hashing, drift detection on project builds, explicit lock refresh via `fozzyc vendor`, and vendor manifest/hash evidence.
- [x] ✅ P1.4 ABI hardening completed: policy-level ABI manifest fields, compatibility gate for schema/package/panic boundary/signature stability/symbol-version non-regression, additive export allowance.

### 2.3 Backend Compiler Path (LLVM + Cranelift Only, No C Shim)
- [x] ✅ Investigated current backend reality in code:
- [x] ✅ Native artifact backend selection is now LLVM + Cranelift only (`c_shim` removed).
- [x] ✅ Cranelift is now a native artifact generation path (object emission + link), not only `emit-ir` text output.
- [x] ✅ B23.1 Removed `c_shim` native backend path entirely from driver pipeline.
- [x] ✅ B23.1 Removed C-shim-specific source generation and toolchain invocation code.
- [x] ✅ B23.1 Backend selector now hard-fails for values other than `llvm` or `cranelift`.
- [x] ✅ B23.2 Added real Cranelift native artifact builder as first-class backend.
- [x] ✅ B23.2 Cranelift path uses same FIR-derived contract outcome semantics as LLVM.
- [x] ✅ B23.2 Added backend enforcement tests (removed-backend rejection + profile default behavior).
- [x] ✅ B23.3 Set backend policy defaults:
- [x] ✅ B23.3 Default `dev` profile to Cranelift for compile throughput.
- [x] ✅ B23.3 Default `release` profile to LLVM for peak optimization.
- [x] ✅ B23.3 `verify` defaults to LLVM for strict/release-aligned semantics.
- [x] ✅ B23.4 Added backend matrix validation for `build`, `run`, `test`, `headers`, and `abi-check`.
- [x] ✅ B23.4 Native replay/trace semantics remain backend-agnostic (strict Fozzy lifecycle still green).
- [x] ✅ B23.5 CLI/DX cleanup:
- [x] ✅ B23.5 Added explicit CLI backend control (`--backend llvm|cranelift`) while retaining env override fallback.
- [x] ✅ B23.5 Updated docs/help to advertise LLVM + Cranelift policy.
- [x] ✅ B23.5 Removed runtime `c_shim` mentions from backend selection/error guidance.

---

## 3) CI Target Contract

- [ ] ⬜ `fozzyc verify <project>`
- [ ] ⬜ `fozzyc test <project> --det --strict-verify --record artifacts/ci.trace.json --json`
- [ ] ⬜ `fozzyc parity <project> --seed 42 --json`
- [ ] ⬜ `fozzyc replay artifacts/ci.trace.manifest.json --json`
- [ ] ⬜ `fozzyc ci artifacts/ci.trace.manifest.json --json`
- [ ] ⬜ `fozzy doctor --deep --scenario <generated_or_curated> --runs 5 --seed 42 --json`
- [ ] ⬜ `fozzy test --det --strict <scenario-set> --json`

---

## 4) Release Claim Exit Criteria

- [ ] ⬜ Semantics reference exists and is enforced by test-oracle checks.
- [ ] ⬜ Mode parity suite is green on required corpus.
- [ ] ⬜ Native/scenario/host equivalence signatures are stable in CI.
- [ ] ⬜ Strict verification is demonstrably separate from safe-profile bans.
- [ ] ⬜ ABI policy + compatibility checks are enforced in CI.
