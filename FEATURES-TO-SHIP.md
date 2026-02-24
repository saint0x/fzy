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
- [x] ✅ DX1: Upgraded `fozzyc init` scaffold to convention-first fan-out with module directories + `mod.fzy` roots.
- [x] ✅ DX2: Added `fozzyc dx-check <project> [--strict]` enforcing main-placement, module-order, mod-root, and test-placement rules.
- [x] ✅ DX3: Published module layout conventions in `docs/project-conventions-v0.md`.

### 1.4 P3 — Production Runtime + Stdlib (Serious Systems Baseline)
- [x] ✅ P3.0 Layering contract: networking/runtime primitives belong to stdlib/runtime; web framework is a library on top.
- [x] ✅ P3.0 Publish `docs/runtime-networking-v0.md` and `docs/stdlib-v0.md` with hard stability guarantees and non-goals.
- [x] ✅ P3.1 Live internet server core in stdlib/runtime:
- [x] ✅ P3.1 Add real socket primitives (`bind`, `listen`, `accept`, `connect`, `read`, `write`, `close`) with explicit ownership semantics.
- [x] ✅ P3.1 Add nonblocking I/O + poller abstraction (`epoll`/`kqueue` equivalent backend contract) with bounded queues.
- [x] ✅ P3.1 Add request context cancellation/deadline propagation for long-lived services.
- [x] ✅ P3.1 Add graceful shutdown semantics (drain in-flight requests, close listeners, bounded timeout).
- [x] ✅ P3.1 Ship minimal HTTP/1.1 server stack (parser, router hooks, request/response types, keepalive controls).
- [x] ✅ P3.1 Add TLS boundary strategy (native TLS adapter or proxy-facing mode) with explicit policy.
- [x] ✅ P3.2 Deterministic replay model for real networked services:
- [x] ✅ P3.2 Record/replay network decisions (`accept` order, read chunk boundaries, timeout ordering, reset/close events).
- [x] ✅ P3.2 Ensure same app API in `fast` and `det` modes; only decision source differs.
- [x] ✅ P3.2 Add incident replay flow from production traces into deterministic local reproduction.
- [x] ✅ P3.3 Observability primitives in stdlib:
- [x] ✅ P3.3 Structured logging API (levels, fields, request IDs, redaction policy).
- [x] ✅ P3.3 Metrics API (counters, gauges, histograms, latency buckets, error classes).
- [x] ✅ P3.3 Tracing/span API (root span, child span, correlation propagation across async/RPC boundaries).
- [x] ✅ P3.3 Runtime stats surface (task queue depth, scheduler lag, allocation pressure, file/socket counts).
- [x] ✅ P3.4 Process + OS primitives:
- [x] ✅ P3.4 Signal handling (`SIGTERM`, `SIGINT`) and shutdown hooks.
- [x] ✅ P3.4 Environment/config loading with typed parsing + validation.
- [x] ✅ P3.4 Child process spawn/io controls with timeout + cancellation + exit classification.
- [x] ✅ P3.5 Storage + durability primitives:
- [x] ✅ P3.5 Durable fs APIs (`flush`, `fsync`, atomic rename/write patterns, temp file discipline).
- [x] ✅ P3.5 File lock primitive and multi-process contention behavior contract.
- [x] ✅ P3.5 Streaming IO readers/writers with bounded buffering and backpressure.
- [x] ✅ P3.6 Concurrency + memory primitives:
- [x] ✅ P3.6 Bounded channels/queues in stdlib (default bounded, explicit overflow policy).
- [x] ✅ P3.6 Synchronization primitives (`mutex`, `rwlock`, `condvar`/event) with deterministic test hooks.
- [x] ✅ P3.6 Pooling primitives (buffer pool/object pool) for low-allocation hot paths.
- [x] ✅ P3.6 Stable atomics/memory-order contract in language reference.
- [x] ✅ P3.7 Security + hardening defaults:
- [x] ✅ P3.7 Safe server defaults (header/body/time limits, parse limits, timeout defaults, connection caps).
- [x] ✅ P3.7 Secret handling primitive (zeroization boundary + redacted logs).
- [x] ✅ P3.7 Capability-gated privileged operations with strict audit output.
- [x] ✅ P3.8 Runtime packaging/deploy primitives:
- [x] ✅ P3.8 Health/readiness probe conventions.
- [x] ✅ P3.8 Profiled runtime config (`dev`, `verify`, `release`) with semantic parity guarantees.
- [x] ✅ P3.8 Service manifest for ports, limits, worker count, and graceful-stop budget.

### 1.5 P1 — Compiler Foundation (Parser, Types, Codegen)
- [x] ✅ P1.5.1 Replaced line-splitting parser with real lexer/token stream + recursive-descent precedence parser.
- [x] ✅ P1.5.1 Added parser error recovery with multi-diagnostic reporting per file.
- [x] ✅ P1.5.1 Added multiline expression support, nested calls, member-call parsing, and structured statement sub-parsers.
- [x] ✅ P1.5.2 Replaced stringly type system with structured `ast::Type` end-to-end (AST/parser/HIR/FIR/driver/verifier).
- [x] ✅ P1.5.2 Added scoped symbol tables and real function call signature validation in HIR.
- [x] ✅ P1.5.2 Added expression type propagation and type-error accounting through lowering.
- [x] ✅ P1.5.3 Added `if`/`else` and `while` to AST/parser/HIR/FIR.
- [x] ✅ P1.5.4 Added tree-walking interpreter semantics for typed `main` evaluation (replacing constant-only heuristics).
- [x] ✅ P1.5.5 Upgraded FIR from metadata bag to typed function IR with basic blocks, control-flow edges, and instruction nodes.
- [x] ✅ P1.5.5 Added call graph construction and AST visitor/walker for shared analysis traversal.
- [ ] ⬜ P1.5.next Cranelift/LLVM full instruction selection for all expression/statement forms still pending.
- [ ] ⬜ P1.5.next Dataflow/liveness and advanced generics/traits specialization still pending.

### 1.6 P2 — Capability Enforcement & Memory Model (Started)
- [x] ✅ P2.1 Added function-scoped capability requirement propagation (callee requirements flow to callers).
- [x] ✅ P2.1 Added verifier diagnostics for per-function missing required capabilities.
- [x] ✅ P2.2 Added ownership transfer tracking for `alloc`/`free` through assignments and returns.
- [x] ✅ P2.2 Added ownership violation reporting (double-free/non-owned free/leak-at-function-exit baseline).
- [ ] ⬜ P2.next Capability tokens, revocation/delegation/algebra, and stdlib capability-token wiring still pending.
- [ ] ⬜ P2.next Full region/lifetime model and secure-zero optimization barriers still pending.

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
- [x] ✅ Live internet-facing server can run with real sockets and documented graceful shutdown semantics.
- [x] ✅ Deterministic replay captures/permutes network decisions from real incident traces.
- [x] ✅ Observability primitives are production-usable (structured logs, metrics, trace/span propagation).
- [x] ✅ Security defaults enforce bounded parsing, timeouts, connection caps, and secret redaction.
- [x] ✅ Durable storage/process/config primitives support real service lifecycle operations.
