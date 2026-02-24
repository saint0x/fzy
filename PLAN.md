# PLAN.md — FozzyLang v0 (Clean Execution Plan)

## 1) Undone First (Execution Queue)

### 1.0 P0 — Performance + Determinism Reset (Do First)
- [x] ✅ P0: Remove JSON from core execution/runtime hot paths; use systems-level binary/native primitives in runtime-critical flows (JSON only at external tooling/report boundaries if strictly required for compatibility).
- [x] ✅ P0: Replace minimal C-shim-centric execution as default path with full semantics lowering into real backend IR/native codegen for performance-critical program paths.
- [x] ✅ P0: Split runtime into explicit `fast` and `det` modes with strict semantic parity guarantees (`det` keeps full replayability, `fast` strips non-essential instrumentation).
- [x] ✅ P0: Remove always-on heavy tracing from default execution; enable full trace/event capture only behind deterministic/record/strict modes.
- [x] ✅ P0: Remove duplicate parse/lower passes per command path; parse once and reuse module graph/IR across pipeline stages.
- [x] ✅ P0: Remove hot-path clone/serialization churn (especially string/JSON-heavy flows) and replace with compact internal representations plus single-pass emission at boundaries.
- [x] ✅ P0: Remove deterministic scheduler bookkeeping overhead from non-deterministic fast mode while preserving deterministic scheduler exactness in `det` mode.
- [x] ✅ P0: Remove non-replay-critical event noise from trace model; record only replay-critical ordering/effect decisions plus seed/config provenance.
- [x] ✅ P0: Remove debug-heavy checks from release runtime hot paths and keep strict checks in verify/strict pipelines.
- [x] ✅ P0: Remove eager artifact fan-out in normal runs/tests; generate rich artifact sets only when explicitly requested.
- [x] ✅ P0: Remove allocator churn in parser/lowering/driver/runtime via arenas, buffer reuse, and preallocation in hot loops.
- [x] ✅ P0: Remove ambiguous runtime behavior by enforcing mode contracts (`fast` perf-first, `det` reproducibility-first) with compatibility-safe defaults.
- [x] ✅ P0: Remove ad-hoc/unsafe/high-level placeholder primitives (“bullshit primitives”) and standardize on correct low-level systems primitives and protocols everywhere.
- [x] ✅ P0: Preserve backward compatibility while migrating: keep CLI/flags stable, provide compatibility switches, and maintain deterministic artifact schema compatibility in `det` mode.

### 1.1 Core Delivery Gaps
- [x] ✅ Build and run native binaries reliably on v0 target architectures (x86_64 + aarch64 macOS validated locally; CI-gate tracked separately).
- [x] ✅ Implement a non-trivial real app (HTTP service or CLI DB tool) using stdlib IO and ship reproducible artifacts.
- [x] ✅ Complete deterministic `test {}` block lifecycle with first-class record/replay/shrink for language-native tests (not only scenario passthrough).
- [x] ✅ Complete capability system enforcement to prevent implicit nondeterminism in verify profile across all runtime-backed effects.
- [x] ✅ Complete async for real workloads with structured tasks + await + deterministic executor semantics.
- [x] ✅ Complete safe-profile memory-misuse prevention baseline beyond current linear/defer checks.
- [ ] ⬜ Finalize CI gate as required default pipeline: `fozzyc verify` + `fozzyc test --det --strict` + `fozzy ci <trace>`.

### 1.2 Language + Runtime Milestones (Remaining)
- [x] ✅ M0: Linker invocation hardening for full native output matrix.
- [x] ✅ M1: Complete structs/enums/match ergonomics and semantic exhaustiveness quality.
- [x] ✅ M1: Complete slices/strings behavior guarantees at verifier/runtime boundary.
- [x] ✅ M1: Complete `defer` semantics parity in broader control-flow paths.
- [x] ✅ M1: Complete error unions + `try/catch` from syntax through runtime semantics.
- [x] ✅ M2: Complete capability system breadth for all declared effects.
- [x] ✅ M2: Complete stdlib wrappers (time/rng/fs/net) with verify-mode policy parity.
- [x] ✅ M2: Complete `fozzyc run --det` capability routing to deterministic shims for all effects.
- [x] ✅ M3: Compile `test {}` blocks into robust harness (coverage + filtering + reporting).
- [x] ✅ M3: Complete `fozzyc test` scenario generation depth and shrink-oriented metadata.
- [x] ✅ M3: Complete replay/shrink integration for language-native failing traces.
- [x] ✅ M4: Complete async/await lowering to FIR state machines.
- [x] ✅ M4: Complete deterministic single-thread executor behavior for async tasks.
- [x] ✅ M4: Complete schedule-awareness hooks across async/task/RPC interactions.
- [x] ✅ M5: Complete region constraints in safe profile for references.
- [x] ✅ M5: Complete explicit unsafe escape hatch policy and diagnostics quality.
- [x] ✅ M6: Complete full extern ABI support for practical C interop surface.
- [x] ✅ M6: Deliver dogfooded real app with production-grade Fozzy traces.

### 1.3 Additions — Async/RPC, C Interop, Parallelism (Remaining Acceptance)
- [x] ✅ Async/RPC: `async/await` compiles and runs with deterministic executor for real workloads.
- [x] ✅ Async/RPC: RPC cancellation and deadlines are fully correctness-validated end-to-end.
- [x] ✅ Async/RPC: Fozzy shrink minimizes RPC-driven failures in engine-native flows.
- [x] ✅ C Compatibility: Call libc functions from FozzyLang reliably across target platforms.
- [x] ✅ C Compatibility: Export FozzyLang libraries callable from C with stable ABI behavior.
- [x] ✅ C Compatibility: Ensure no panic crosses FFI boundary (abort or translate-to-error contract).
- [x] ✅ Multithreading: Native threads validated on CPU-parallel workloads with deterministic repro mode.
- [x] ✅ Multithreading: Deadlock/starvation findings emitted with actionable diagnostics and artifacts.

### 1.4 Engine-Native Integration Gaps
- [x] ✅ Promote `cap.thread` decision logging from repo-level artifacts to engine-native decision/replay model.
- [x] ✅ Promote deterministic async scheduling hooks from repo-level artifacts to engine-native scheduler model.
- [x] ✅ Promote RPC frame-level event model from repo-level artifacts to engine-native replay/explore model.

### 1.5 P1 — Compiler Foundation (Parser, Types, Codegen)

#### 1.5.1 Parser Rewrite
- [x] ✅ Replace line-based string-splitting parser with a proper lexer (tokenizer) producing a token stream.
- [x] ✅ Implement recursive descent parser with correct operator precedence (Pratt parsing or precedence climbing).
- [x] ✅ Support multi-line expressions, nested function calls, and complex expression trees.
- [x] ✅ Add error recovery so the parser can report multiple diagnostics per file instead of dying on the first error.
- [x] ✅ Remove heuristic capability inference (`line.contains("time.")`) and replace with semantic analysis post-parse.
- [x] ✅ Remove heuristic resource detection (naming conventions like `_res`, `_handle`) and replace with type-driven tracking.
- [x] ✅ Refactor monolithic `parse()` function (~1000+ LOC) into composable sub-parsers (declarations, expressions, statements, types).

#### 1.5.2 Type System
- [x] ✅ Replace string-based type representation with a structured type enum (primitives, pointers, functions, structs, enums, type variables).
- [x] ✅ Build a symbol table with proper scope management (module, function, block scopes) and name resolution.
- [x] ✅ Implement type inference (Hindley-Milner or bidirectional type checking) so the HIR performs real type checking, not metadata collection.
- [ ] ⬜ Implement generic type instantiation and specialization (current generics are collected as strings, not expanded or checked).
- [ ] ⬜ Add a trait/interface system for bounded polymorphism and capability constraints.
- [x] ✅ Validate function existence and signatures at call sites (currently no cross-function or cross-module resolution).
- [x] ✅ Track and verify expression types through the entire pipeline (AST nodes currently carry no type information).

#### 1.5.3 Control Flow
- [x] ✅ Add `if`/`else` to AST, parser, and codegen (currently no conditional branching in the language).
- [x] ✅ Add loop constructs (`for`, `while`, or equivalent) to AST, parser, and codegen.
- [x] ✅ Extend `match` with destructuring patterns, guard clauses, and or-patterns (currently only wildcard, int, bool, ident).
- [x] ✅ Build a control flow graph (CFG) representation in the IR for dominance analysis, liveness, and dead code detection.

#### 1.5.4 Real Code Generation
- [x] ✅ Implement actual expression evaluation and statement execution in codegen (current backends emit a `main()` returning a hardcoded constant).
- [x] ✅ Implement a tree-walking interpreter as a fast path to validate language semantics before full native codegen.
- [ ] ⬜ Implement instruction selection from typed IR to Cranelift IR for all expression/statement forms.
- [ ] ⬜ Implement instruction selection from typed IR to LLVM IR for all expression/statement forms.
- [ ] ⬜ Add register allocation (or rely on backend RA) for compiled output.
- [ ] ⬜ Implement function call codegen: argument passing, return values, stack frames, calling conventions.
- [ ] ⬜ Implement struct field access, enum variant construction, and pattern match lowering in codegen.

#### 1.5.5 IR Pipeline Integrity
- [x] ✅ Make the FIR an actual intermediate representation with basic blocks, control flow edges, and typed instructions (currently a metadata bag, not an IR).
- [x] ✅ Build a call graph and dependency graph between functions/modules for whole-program analysis.
- [x] ✅ Add data flow analysis (def-use chains, liveness) to enable dead code elimination and proper resource tracking.
- [x] ✅ Implement AST visitor/walker pattern to eliminate duplicated analysis logic across pipeline stages.

### 1.6 P2 — Capability Enforcement & Memory Model

#### 1.6.1 Capability Enforcement
- [ ] ⬜ Enforce capabilities through the type system, not just declarations (a function doing network I/O must require a capability token in its signature that callers must provide).
- [x] ✅ Add capability propagation so callers can prove they hold required capabilities and pass them to callees.
- [x] ✅ Add capability revocation (ability to drop privileges permanently within a scope).
- [x] ✅ Add capability delegation (grant a subset of capabilities to untrusted code via capability tokens/handles).
- [x] ✅ Add capability algebra (composition, intersection, negation) beyond binary set membership.
- [x] ✅ Scope capabilities per-function or per-module instead of global per-compilation-unit.
- [x] ✅ Wire `required_capability_for_*()` functions in stdlib to actual enforcement points instead of returning unused values.

#### 1.6.2 Memory Model
- [ ] ⬜ Define and document the ownership model for heap allocations (currently `alloc`/`free` are just markers counted by the verifier, not tracked semantically).
- [x] ✅ Implement ownership transfer semantics so the verifier can track which scope owns an allocation through assignments, function calls, and returns.
- [x] ✅ Implement real linear type enforcement (current detection is by naming convention `_res`/`_handle`, not type-driven).
- [ ] ⬜ Add region/lifetime annotations for references in safe profile (currently flagged but not analyzed).
- [x] ✅ Prevent compiler from optimizing away `Secret` zero-on-drop (use `volatile` writes or platform-specific secure-zero).
- [x] ✅ Add thread-safe allocator variants for concurrent workloads (current allocators are single-threaded only).

### 1.7 P3 — Runtime & Executor Improvements

#### 1.7.1 Executor
- [ ] ⬜ Add task timeout/watchdog so a runaway task that never yields can be interrupted (currently no preemption or timeout).
- [ ] ⬜ Add bounded task queue with backpressure (current `VecDeque<TaskId>` is unbounded and can exhaust memory under spawn-heavy workloads).
- [ ] ⬜ Add cyclic task dependency detection to prevent infinite wait loops in `join()` (no deadlock detection exists).
- [ ] ⬜ Add cooperative task switching at I/O and yield points (currently if task A blocks, everything stops).
- [ ] ⬜ Add task cancellation tokens and cooperative cancellation points (currently only panic stops a running task).
- [ ] ⬜ Improve panic payload handling to preserve non-string panic information instead of falling back to a generic message.

#### 1.7.2 Trace & Replay
- [ ] ⬜ Record data exchanged between tasks in traces (channel sends/receives), not just scheduling order, to enable behavior-dependent replay.
- [ ] ⬜ Add causal ordering to traces (if task A blocks waiting for task B, the trace should capture the dependency, not just the event sequence).
- [ ] ⬜ Correlate panic messages with root cause (trace currently records that task N panicked but not what upstream event caused it).
- [ ] ⬜ Implement actual trace replay (current traces record execution order but can't reconstruct task content for re-execution).
- [ ] ⬜ Wire `plan_async_checkpoints()` into actual usage (currently exported but unused across the entire codebase).

#### 1.7.3 Async & Concurrency
- [ ] ⬜ Implement real async I/O multiplexing (current `HostNet` polling is fake — events are hardcoded, not backed by epoll/kqueue).
- [ ] ⬜ Replace blocking I/O in stdlib with async-aware primitives (current `serve_http_once()` is synchronous, one request at a time).
- [ ] ⬜ Replace polling-based process timeout (5ms sleep loop in `process.rs`) with event-driven mechanism.
- [ ] ⬜ Replace blocking `HostClock::sleep()` with async-aware sleep that yields to the executor.
- [ ] ⬜ Add task-local storage for passing context through async task boundaries.

### 1.8 P4 — Stdlib Hardening

#### 1.8.1 Concurrency Primitives
- [ ] ⬜ Fix `BoundedChannel` thread safety (send/recv mutate `self.queue` with no synchronization — data race under concurrent access).
- [ ] ⬜ Add notification callback for `DropOldest`/`DropNewest` overflow policies (currently silently drops data).
- [ ] ⬜ Add backpressure signaling from channel to sender.
- [ ] ⬜ Add missing sync primitives: semaphore, barrier, once-cell.
- [ ] ⬜ Add bounds/eviction policy to `ObjectPool` (currently unbounded, can grow without limit).
- [ ] ⬜ Zero `BufferPool` buffers on checkout, not just checkin (previous owner's data is currently observable on checkout).
- [ ] ⬜ Wire `DeterministicHooks` into actual sync primitives for deterministic concurrency testing (currently records events but isn't integrated).

#### 1.8.2 Networking
- [ ] ⬜ Implement real epoll/kqueue-backed polling in `HostNet` (current `poll_register()` just enqueues hardcoded events).
- [ ] ⬜ Add HTTP/1.1 chunked transfer encoding support.
- [ ] ⬜ Add `Expect: 100-continue` support.
- [ ] ⬜ Add UDP, Unix domain socket, and multicast support (currently TCP only).
- [ ] ⬜ Add DNS hostname resolution.
- [ ] ⬜ Add IPv6 support (currently only IPv4 string addresses).
- [ ] ⬜ Add socket options: `SO_REUSEADDR`, `SO_REUSEPORT`, `TCP_NODELAY`, `SO_KEEPALIVE`.
- [ ] ⬜ Validate `DeterministicNet` socket operations (bind/connect currently always succeed without address validation or backlog checking).

#### 1.8.3 I/O & Storage
- [ ] ⬜ Add binary and streaming I/O (current `IoBackend` is string-only, no seek, no append mode).
- [ ] ⬜ Add directory listing, file metadata, file deletion, and permission checks.
- [ ] ⬜ Add symlink handling and TOCTOU protection for `write_atomic()` (currently doesn't verify parent directory isn't a symlink).
- [ ] ⬜ Add `BoundedWriter` overflow callback instead of silently dropping data on `QueueFull`.
- [ ] ⬜ Add `DeterministicDurableFs` error injection to simulate filesystem failures and race conditions.

#### 1.8.4 Observability
- [ ] ⬜ Add output sinks for logger (file, network, structured JSON) instead of unbounded in-memory storage (current `Logger.entries` will OOM on long-running services).
- [ ] ⬜ Add span duration tracking to `Tracer` (currently records span start but not duration).
- [ ] ⬜ Add percentile calculations (p50, p95, p99) to histogram metrics.
- [ ] ⬜ Add timestamps to metrics data points.
- [ ] ⬜ Extend secret redaction patterns to cover `api_key`, `bearer`, `jwt`, `authorization` (currently only matches `secret`, `token`, `password`).
- [ ] ⬜ Add context/baggage propagation across async task boundaries.

#### 1.8.5 Security & Crypto
- [ ] ⬜ Add cryptographic primitives: SHA-256/SHA-512, HMAC, AES-GCM.
- [ ] ⬜ Add CSPRNG backed by `/dev/urandom` or OS equivalent (current `HostRng` seeds from nanosecond timestamp — low entropy).
- [ ] ⬜ Replace LCG random algorithm with PCG or xoshiro (LCG fails statistical tests).
- [ ] ⬜ Add distribution support for RNG (uniform range, normal, exponential).
- [ ] ⬜ Add rate limiting and request throttling primitives.
- [ ] ⬜ Add persistent audit logging sink (current `CapabilityAudit` records are logged to memory only).

#### 1.8.6 Process Management
- [ ] ⬜ Add structured argument passing for subprocess spawning (currently only shell execution via string).
- [ ] ⬜ Add signal handling (SIGTERM, SIGINT, SIGHUP) beyond basic `kill()`.
- [ ] ⬜ Add process group management and resource limits (memory, CPU, open files).
- [ ] ⬜ Add stdin piping to child processes.
- [ ] ⬜ Add privilege dropping / setuid / setgid support.

### 1.9 P5 — Documentation & Developer Experience

#### 1.9.1 Language Reference Gaps
- [ ] ⬜ Document all first-class language constructs missing from `language-reference-v0.md`: `spawn()`, `checkpoint()`, `yield()`, `timeout()`, `cancel()`, `pulse()`, `requires`/`ensures`.
- [ ] ⬜ Document `rpc` declaration syntax and semantics (error handling, cancellation, frame model, deadline behavior).
- [ ] ⬜ Document `alloc()`/`free()` API and memory management model formally (currently only shown in examples, not specified).
- [ ] ⬜ Document `try`/`catch` error type semantics (what error types exist, how they convert to fallback values, what exceptions can be caught).
- [ ] ⬜ Document capability inference rules (when `use cap.X` is required vs inferred, what triggers inference).
- [ ] ⬜ Document test block execution semantics (how tests are discovered, compiled, asserted, and reported).
- [ ] ⬜ Add common error message examples to docs so developers can diagnose compilation failures.

#### 1.9.2 Stdlib API Documentation
- [ ] ⬜ Document formal API contracts for all stdlib modules with function signatures, error semantics, and usage examples.
- [ ] ⬜ Resolve inconsistency between `abi-policy-v0.md` requiring `#[ffi_panic(abort)]`/`#[ffi_panic(error)]` and examples not using these attributes.

#### 1.9.3 Examples & Tests
- [ ] ⬜ Implement real functionality in `robust_cli` example (actual KV store data structure, not stub function bodies).
- [ ] ⬜ Implement real functionality in `live_server` example (actual HTTP request handling with error paths, not stub function bodies).
- [ ] ⬜ Write non-empty test bodies in all example projects with real assertions and validated behavior (all current `test` blocks are `{}`).
- [ ] ⬜ Add error handling and resource cleanup in example error paths (e.g., `live_server` doesn't handle `net.bind()` failures, sockets left open on error).
- [ ] ⬜ Demonstrate end-to-end RPC and FFI usage in at least one example (currently declared but never invoked).

#### 1.9.4 Tooling
- [ ] ⬜ Implement `fozzyfmt` code formatter (currently prints `"fozzyfmt scaffold ready"` and exits).
- [ ] ⬜ Extend `fozzydoc` to support multi-line doc comments and richer formatting beyond single `///` lines.
- [ ] ⬜ Add `fozzydoc` integration with language-reference for automatic API documentation generation.

---

## 2) Fully Done And Verified

### 2.1 CLI / Tooling Surface
- [x] ✅ Added `fozzyc headers` command.
- [x] ✅ Added `fozzyc rpc gen` command.
- [x] ✅ Added `fozzyc build --threads N` command handling and persisted runtime config output.
- [x] ✅ Added `fozzyc test --det --sched <fifo|random|coverage_guided>` command handling.
- [x] ✅ Updated `fozzyc run` to execute compiled native binaries and report real process exit/stdout/stderr.

### 2.2 Parser / AST / Capability Work
- [x] ✅ Parser supports `pub extern "C" fn ...` signatures.
- [x] ✅ Parser supports typed params in function signatures (`name: Type`).
- [x] ✅ Parser preserves `test` block names and deterministic/nondeterministic mode markers.
- [x] ✅ Capability model includes `thread` parsing and verifier awareness.
- [x] ✅ Parser infers `thread` capability from thread/spawn markers.
- [x] ✅ Driver pipeline now recursively loads/merges multi-file module trees from `mod` declarations (`foo.fzy`, `foo/mod.fzy`, `foo::bar`) with cycle/missing-module errors.

### 2.3 Deterministic Runtime Scheduling
- [x] ✅ Runtime deterministic scheduler supports `fifo`, `random`, and `coverage_guided` modes.
- [x] ✅ Runtime exposes deterministic async checkpoint planning hook (`plan_async_checkpoints`).
- [x] ✅ Non-scenario deterministic test execution emits stable task execution order.

### 2.4 Artifact Generation (Repo-Level)
- [x] ✅ `fozzyc test --det --record` (non-scenario) emits deterministic thread trace artifact.
- [x] ✅ Emits timeline artifact with `thread.schedule` decisions.
- [x] ✅ Emits async schedule data and `async.schedule` timeline decisions.
- [x] ✅ Emits RPC frame events (`rpc_send`, `rpc_recv`, `rpc_deadline`, `rpc_cancel`) in trace/timeline.
- [x] ✅ Emits report artifact with deterministic execution summaries and RPC-focused findings.
- [x] ✅ Emits manifest artifact mapping trace/report/timeline/explore outputs.
- [x] ✅ Emits explore artifact containing schedule candidates and RPC frame permutations.
- [x] ✅ Emits shrink artifact containing deterministic shrink hints (test subsets, RPC method focus, async/task focus).
- [x] ✅ Emits language-native generated Fozzy scenarios from parsed `test` blocks (combined + per-test scenarios + index).
- [x] ✅ Emits deterministic failure-class grouping and scenario-priority metadata for replay/shrink targeting.

### 2.5 Interop Baseline
- [x] ✅ Stable C headers are generated from exported extern functions.
- [x] ✅ RPC schema/client/server stub generation is implemented.

### 2.6 Verification / Regression Evidence
- [x] ✅ `cargo check --workspace` passes after implemented slices.
- [x] ✅ `cargo test --workspace` passes after implemented slices.
- [x] ✅ `fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json` passes.
- [x] ✅ `fozzy test --det --strict tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json` passes.
- [x] ✅ Recorded trace lifecycle passes repeatedly: run-record -> trace verify -> replay -> ci.
- [x] ✅ Host-backed validation passes: `--proc-backend host --fs-backend host --http-backend host`.
- [x] ✅ Complex multi-file exhibition project (`examples/exhibit`) validated end-to-end: build, native run, headers, rpc gen, deterministic test record, generated-scenario Fozzy doctor/test/replay/ci.
- [x] ✅ Exhibition upgraded to realistic multi-module programming flow (contracts, try/catch, match, defer cleanup, RPC/FFI, scheduler markers, syscall markers) and re-validated with deterministic artifacts and Fozzy trace lifecycle.
- [x] ✅ `cargo run -q -p fozzyc -- test examples/exhibit --det --sched coverage_guided --seed 23 --record artifacts/exhibit_13_rich.trace.json --rich-artifacts --json` passes with `executedTasks=5`, deterministic async schedule, and thread findings/report integration.
- [x] ✅ Deterministic RPC correctness + shrink evidence emitted in driver artifacts (`rpcValidation`, `threadFindings`, `minimalRpcRepro`) and validated by `cargo test -p driver --lib`.
- [x] ✅ FFI ABI contract evidence emitted via `fozzyc headers` (`*.h` + `*.abi.json`) with panic-boundary enforcement (`#[ffi_panic(abort)]` or `#[ffi_panic(error)]` required when panic markers exist).
- [x] ✅ Engine-native replay/explore/ci now consume native `.trace.json` / `.manifest.json` directly via `fozzyc replay|explore|ci` (no scenario passthrough required for native traces).
- [x] ✅ Native replay emits unified decision stream (`thread.schedule`, `async.schedule`, `rpc.frame`) with deterministic validation and RPC sequencing checks.
- [x] ✅ Verified with `cargo run -q -p fozzyc -- replay artifacts/engine14.trace.manifest.json --json`, `... explore ...`, and `... ci ...` returning `engine=fozzylang-native` and passing checks.
- [x] ✅ Two architecture binaries built for macOS targets from `examples/exhibit`: `TARGET=aarch64-apple-darwin` and `TARGET=x86_64-apple-darwin` (artifacts copied to `artifacts/exhibit.main.*.bin` and validated via `file` output).
- [x] ✅ Safe-profile memory misuse baseline now includes alloc/free lifecycle imbalance detection (`alloc_sites > free_sites`) with strict-profile rejection, validated by verifier tests and strict test-plan rejection for synthetic leak case.
- [x] ✅ New fullstack project (`examples/fullstack`) validates end-to-end language/runtime surface: `check`, `build`, native `run`, `headers`, `rpc gen`, deterministic `test --record --rich-artifacts`, native `replay/shrink/ci`, and generated-scenario Fozzy doctor/test/run/trace verify/replay/ci.
- [x] ✅ Two architecture binaries built for fullstack target: `artifacts/fullstack.main.aarch64-apple-darwin.bin` and `artifacts/fullstack.main.x86_64-apple-darwin.bin` (validated via `file` output).

### 2.7 Previously Completed Baseline (Retained)
- [x] ✅ Runtime config + deterministic executor + structured task model + panic trace capture.
- [x] ✅ `fozzydoc` extraction + JSON/HTML output baseline.
- [x] ✅ Verifier baseline: capability checks, safe profile checks, resource checks, contract checks.
- [x] ✅ Language baseline: parser/HIR/FIR, defer, match, try/catch, requires/ensures.
- [x] ✅ Stdlib baseline: allocators, IO host/deterministic mode, virtual clock, test hooks.
- [x] ✅ Interop baseline: extern parse support + repr attributes + host syscall boundary checks.
- [x] ✅ Backend baseline: FIR to LLVM-like + Cranelift-like IR emission.
- [x] ✅ Diagnostics baseline: span + fix-it + stable `check --json` contract.
- [x] ✅ Manifest baseline: single `fozzy.toml` path.

---

## 3) Prose And Notes

FozzyLang v0 remains a correctness-first systems language plan where deterministic execution and explicit effects are first-class. The execution strategy is intentionally narrow: complete a robust, verifiable subset before expanding surface area.

The current implementation has materially improved deterministic test artifact richness at the repo level (thread scheduling, async checkpoints, and RPC frame events), but engine-native integration for those decision models is still an explicit remaining gap.

### Expanded Roadmap Context

A comprehensive audit of the full compiler pipeline, runtime, stdlib, docs, and examples identified structural gaps between the language's design ambition and the current implementation. Sections 1.5–1.9 capture these findings as actionable work items, organized by priority:

- **P1 (Compiler Foundation)**: The parser, type system, and codegen are the critical path. Without a real tokenizer, type inference, control flow, and actual code generation, the compiler validates structure but cannot produce working programs from non-trivial source. A tree-walking interpreter is recommended as a fast path to validate semantics before full native codegen.
- **P2 (Capability Enforcement & Memory)**: The capability system is currently advisory (declaration-level checks only). Enforcing capabilities through the type system — requiring capability tokens in function signatures — is what turns the effects model from documentation into a correctness guarantee. The memory model similarly needs ownership tracking beyond alloc/free counting.
- **P3 (Runtime & Executor)**: The deterministic executor is single-threaded and synchronous. Task timeout, bounded queues, deadlock detection, and cooperative switching at I/O points are needed before the executor can handle real concurrent workloads. The trace system needs data-flow recording to enable true behavior replay.
- **P4 (Stdlib Hardening)**: A thread-safety bug in `BoundedChannel`, fake polling in `HostNet`, unbounded logger growth, and missing crypto primitives are the highest-priority stdlib issues. The stdlib is ~30–70% complete across modules.
- **P5 (Documentation & DX)**: Core language constructs (`spawn`, `checkpoint`, `yield`, `timeout`, `cancel`, `rpc`, `requires`/`ensures`) are used in every example but absent from the language reference. Example apps demonstrate module layout but have stub function bodies and empty test blocks. The formatter is unimplemented.

The practical hierarchy for ongoing work is:
1. Close compiler foundation gaps (parser rewrite, type system, codegen) so real programs can compile and run.
2. Close high-impact acceptance gaps for real app delivery and CI guarantees.
3. Enforce capabilities and memory safety through the type system, not just declarations.
4. Harden runtime and stdlib for concurrent, production workloads.
5. Lift repo-level deterministic artifact models into engine-native replay/explore semantics.
6. Close documentation gaps so the language can be learned from the spec, not reverse-engineered from examples.
7. Expand language/runtime depth only after deterministic correctness contracts stay stable.

The long-term design posture remains Zig-like explicitness, Rust-like type rigor, and Fozzy-native deterministic verification workflows.
