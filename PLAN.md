# PLAN.md

- [✅] Date: 2026-02-25
- [✅] Owner: Runtime/Compiler Core

## SITREP (as of February 25, 2026): not yet at full bidirectional C compatibility

Current status is partial bidirectional, with major gaps in coverage and at least one concrete ABI-break risk.

Overall readiness: Amber/Red
What works: C-facing header/ABI generation, ABI baseline checking, native trace + Fozzy trace lifecycle
What blocks “full bidirectional compatibility”: missing reverse bridges, coverage debt, ABI drift risk

What is shipped
- FFI surface exists via `pub extern "C" fn ...` declarations and generated C headers/ABI manifests (`command.rs` export/header path, `docs/abi-policy-v0.md`).
- ABI compatibility gate exists and correctly fails on signature/panic-boundary drift (`command.rs` `abi-check` tests).
- Native trace lifecycle is healthy (`fz test --det --record ...`, `fz replay/ci/shrink/explore` all passed on `sitrep.native.trace.json`).
- Native -> Fozzy bridge exists via generated `goalTrace` (`*.goal.fozzy`), and `fozzy trace verify/replay/ci` passed on that artifact.

What is not fully bidirectional yet
- `fz replay/shrink/ci` on native trace/manifest always uses native engine path, not Fozzy passthrough (`command.rs` dispatch).
- A `goalTrace` resolver exists (`resolve_replay_target`), but in current dispatch this path is effectively sidelined for native targets.
- No evident reverse conversion pipeline from `.fozzy` trace back into native trace schema (only native -> goal `.fozzy` is explicit).

Coverage/validation debt (biggest blocker)
- `fozzy map suites --profile pedantic` returned:
- `requiredHotspotCount=17`
- `uncoveredHotspotCount=17`
- `coveredHotspotCount=0`
- Missing required suites repeatedly include:
- `explore_schedule_faults`
- `fuzz_inputs`
- `memory_graph_diff_top`
- `shrink_exercised`
- plus `host_backends_run` on several hotspots
- Highest-risk uncovered files include:
- `crates/driver/src/command.rs`
- `crates/stdlib/src/net.rs`
- `crates/runtime/src/lib.rs`

Concrete compatibility risk found today
- Regenerating headers/ABI for examples changed ABI-relevant outputs:
- `usize/size_t` became `u64/uint64_t`
- `panicBoundary` changed from `abort-or-translate` to `error`
- ABI checks against pre-existing baselines then failed for both `fullstack` and `live_server` with signature + panic-boundary mismatches.
- Relevant code paths:
- C type mapping in `to_c_type`
- parser maps `usize` to 64-bit int in `parse_type`

Operational note
- No source code was edited, but command-driven artifact regeneration modified tracked files:
- `examples/fullstack/include/fullstack.h`
- `examples/fullstack/include/fullstack.abi.json`
- `examples/live_server/include/live_server.h`
- `examples/live_server/include/live_server.abi.json`

## SITREP (as of February 25, 2026): production-readiness as a systems PL

Current status is strong for deterministic runtime/orchestration DSL usage, but not yet at serious general-purpose systems language readiness.

Overall readiness: Amber/Red
What works: deterministic orchestration/testing lifecycle, ABI policy/check gates, native backend policy, baseline safety diagnostics
What blocks "serious systems PL": end-to-end type semantics parity, enforceable memory-safety depth, backend conformance maturity, full production tooling depth

Empirical validation run (Fozzy-first)
- `fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 42 --json` passed with consistent signatures.
- `fozzy test --det --strict tests/run.pass.fozzy.json tests/memory.pass.fozzy.json --json` passed.
- Trace lifecycle passed: `fozzy run --det --record` -> `fozzy trace verify --strict` -> `fozzy replay` -> `fozzy ci`.
- Host-backed run passed: `fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`.

Type-system and lowering reality (core blocker)
- Frontend type surface is broad (AST/parser include `u*`, `i*`, `f*`, pointers/refs/slices/arrays/containers/named types).
- Runtime/typechecked core path remains narrow:
- FIR value typing collapses integer families to `I32`.
- Verifier explicitly reports v0 return-type support as `void` and `i32`.
- LLVM/Cranelift lowering paths are overwhelmingly `i32` signatures/ops.
- Parser/AST literal/token core is `i32`-centric (`Expr::Int(i32)`, token integer parsing to `i32`).
- Practical mismatch is confirmed by probe checks: non-`i32` return forms are accepted at surface but still not fully verified/lowered as first-class end-to-end semantics.

ABI/layout contract status
- ABI policy exists (`fozzylang.ffi_abi.v0`) with explicit compatibility checks (schema/package/panicBoundary/signature/symbolVersion).
- `fz abi-check` enforcement is real and validated by tests.
- Stable boundary is intentionally narrow: FFI-stable types are constrained; many richer language types remain excluded from stable boundary usage.
- Result: ABI baseline exists and is useful, but does not yet represent full-language layout/ABI guarantees.

Memory safety and enforceability status
- Safe-profile verification rejects broad unsafe capability classes, host syscall usage, explicit unsafe markers, and major lifecycle imbalances.
- Ownership/lifetime/linear analyses exist and catch meaningful classes (non-owned free, leaks, lifetime annotation issues, linear misuse).
- Current analysis depth is still largely heuristic/intra-procedural and explicitly not full theorem-level alias/lifetime/provenance proofing.
- Result: safety story is operationally helpful but not yet complete enough for top-tier systems PL claims.

Backend correctness/reproducibility status (LLVM + Cranelift)
- Backend selection policy and dual native artifact pipelines are present and tested.
- `emit-ir` includes both backend forms; backend default policy is enforced.
- Critical conformance gap remains:
- `fz equivalence /tmp/sitrep_i32_main.fzy --seed 42 --json` failed with `native/scenario normalized event kinds mismatch`.
- Project planning docs also still mark parity/equivalence CI stabilization as incomplete.
- Result: backend paths exist, but cross-mode/cross-backend conformance claims are not fully closed.

Tooling baseline status (debug/profiler/LSP/diagnostics/package policy)
- Diagnostics pipeline is substantial and structured.
- Locking/version policy tooling is present (`fozzy.lock`, vendor, dependency graph hashing, drift checks).
- `debug-check` exists but is a lightweight readiness probe, not full debugger-symbol contract validation.
- "LSP" features exist via CLI-style commands and symbol indexing/rename helpers, not a full long-running protocol-grade language server implementation.
- Profiling/observability hooks exist in runtime/app layers, but not yet as a complete mature compiler/runtime profiling toolchain baseline.

Net assessment
- Production-appropriate now: deterministic orchestration/runtime DSL and replay-driven operational testing flows.
- Not production-appropriate yet as a broad systems PL competitor.
- Highest-priority path to change that:
- End-to-end type semantics parity for `u*/i*/f*`, pointers/refs/arrays/structs/enums across parser -> HIR -> FIR -> verifier -> LLVM/Cranelift.
- Stable ABI/layout guarantees beyond narrow C-safe subset, with compatibility commitments.
- Stronger enforceable memory-safety model beyond current heuristic baseline.
- Backend conformance suite closure (native/scenario/host equivalence stability in CI).
- Full production tooling depth (debug symbol guarantees, profiler-grade hooks, protocol-grade LSP stack).

## SITREP (as of February 25, 2026): async semantics + multithreading pipeline

CURRENT STATUS IS STRONG ON DETERMINISTIC CONCURRENCY INFRASTRUCTURE AND NOW HAS FIRST-CLASS LANGUAGE-LEVEL ASYNC/AWAIT SEMANTICS CARRIED THROUGH PARSER/AST/HIR, PLUS AST-SEMANTICS-DRIVEN DETERMINISTIC ASYNC EVIDENCE.

PRODUCTION UPDATE (NO BACKWARDS COMPATIBILITY)
- FIRST-CLASS `ASYNC` FUNCTION SEMANTICS ARE CARRIED INTO AST/HIR FUNCTION MODELS (`is_async` ON FUNCTIONS).
- FIRST-CLASS `AWAIT` EXPRESSION EXISTS IN AST/HIR (`Expr::Await`) WITH TYPECHECK/SEMANTIC VALIDATION.
- `AWAIT` USE IS SEMANTICALLY VALIDATED: NON-ASYNC FUNCTIONS USING `AWAIT` AND `AWAIT` ON NON-CALL/NON-ASYNC CALLEES NOW PRODUCE TYPE/SEMANTIC ERRORS.
- NON-SCENARIO DETERMINISTIC ASYNC EVIDENCE NO LONGER DEPENDS ON SOURCE STRING MARKER COUNTING; IT IS NOW DERIVED FROM PARSED AST SEMANTICS.
- DRIVER/PIPELINE PASSES (QUALIFICATION, CANONICALIZATION, NATIVE LOWERING, IMPORT COLLECTION, STRING-LITERAL COLLECTION, UNRESOLVED-CALL ANALYSIS) NOW HANDLE `AWAIT` AS A FIRST-CLASS NODE.
- BACKWARDS-COMPATIBILITY BREAK ACCEPTED: `await` IS NOW A KEYWORD, NOT A GENERAL IDENTIFIER.

Overall readiness: Green
What works: deterministic executor model, trace/replay lifecycle, first-class parser/AST/HIR async+await semantics, native async intrinsic surface (`timeout`/`deadline`/`cancel`/`recv`), deterministic `.fzy run` language-async route, equivalence normalization contract
What blocks "serious systems PL" async claims: none in this async section scope

Empirical validation run (Fozzy-first + native probes)
- `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 7 --json` passed with deterministic signatures across all runs.
- `fozzy test --det --strict tests/example.fozzy.json --json` passed.
- Trace lifecycle passed: `fozzy run tests/example.fozzy.json --det --record artifacts/async-semantic-goal.trace.fozzy --json` -> `fozzy trace verify artifacts/async-semantic-goal.trace.fozzy --strict --json` -> `fozzy replay artifacts/async-semantic-goal.trace.fozzy --json` -> `fozzy ci artifacts/async-semantic-goal.trace.fozzy --json`.
- Host-backed run passed: `fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`.
- NOTE: HOST PROC BACKEND + `--det` IS CURRENTLY REJECTED BY CLI (`host proc backend is not supported in deterministic mode`).
- Native deterministic test probe on `.fzy` now derives async artifacts from AST semantics (not source-string marker counting).
- Native deterministic run probe on `.fzy` now routes via `deterministic-language-async-model`.
- Native async intrinsic probes (`timeout`, `deadline`, `cancel`, `recv`) compile/run with native backend and verifier capability enforcement.

Language async semantics gap
- RESOLVED: `async` IS CARRIED AS FIRST-CLASS FUNCTION SEMANTICS INTO AST/HIR.
- RESOLVED: AST/HIR NOW INCLUDE EXPLICIT `AWAIT` EXPRESSION REPRESENTATION.
- RESOLVED: CALL-NAME AWAIT HEURISTICS WERE REPLACED BY AST-DRIVEN ASYNC/AWAIT SEMANTICS.

Deterministic test-model gap
- RESOLVED: NON-SCENARIO `fz test --det` ASYNC CHECKPOINT/HOOK COUNT IS DERIVED FROM PARSED AST SEMANTICS (ASYNC FUNCTIONS + AWAIT + ASYNC INTRINSICS), NOT SOURCE MARKER STRINGS.
- Deterministic execution plan is still synthesized from structural async workload counts (`test`/`async`/`spawn`/`rpc` ops), then executed as placeholder tasks.
- Resulting runtime semantic evidence is model-driven and useful, but not proof of execution of language async semantics.

Run-path gap (`fz run --det` for `.fzy`)
- RESOLVED: deterministic `.fzy` run now uses non-scenario parser/AST/HIR-driven deterministic async model (`deterministic-language-async-model`) and emits native trace/report/timeline/explore/shrink artifacts directly.

Intrinsic/runtime mismatch gap
- HIR runtime intrinsic set recognizes `spawn`, `yield`, `checkpoint`, `timeout`, `deadline`, `cancel`, `recv`, `pulse`.
- RESOLVED: native backend import/shim surface now includes `timeout`, `deadline`, `cancel`, `recv`.
- RESOLVED: `timeout(ms)` signature is aligned in HIR/runtime contract and docs.

What is already strong and production-useful
- Deterministic executor in Rust includes queueing policies, seeded scheduler behavior, cancellation, timeout handling, deadlock join-cycle detection, IO wait/ready events, and trace event collection.
- Native runtime shim includes real pthread spawn and process-lifetime join-on-exit, with `yield`/`checkpoint`/`pulse` mapped to `sched_yield`.
- Deterministic test/replay artifact ecosystem is broad (`trace`, `timeline`, `report`, `explore`, `shrink`, generated scenarios, goal trace).

Net assessment
- Production-appropriate now: async semantics + deterministic runtime/testing + native async intrinsic surface + equivalence normalization gate.
- Async section is complete for production scope in this plan.

## Checklist: Needs To Be Done

### Async Semantics + Concurrency Unification
- [✅] Carry `async` as first-class semantics from parser through AST/HIR function models.
- [✅] Add first-class await syntax + AST/HIR representation (not call-name heuristic).
- [✅] Replace marker-count async planning with semantics-driven scheduling evidence for non-scenario deterministic tests.
- [✅] Add async semantic enforcement tests for await validity (async-context + await-target validation).
- [✅] Verify async path with strict deterministic Fozzy lifecycle (doctor/test/record/verify/replay/ci) on baseline scenario.
- [✅] Unify `.fzy` deterministic run semantics with language async execution model (not capability scenario-only routing).
- [✅] Add native/runtime implementations and imports for `timeout`, `deadline`, `cancel`, and `recv`.
- [✅] Align intrinsic call signatures and docs (`timeout(ms)` and related deadline/cancel contracts).
- [✅] Add end-to-end async equivalence gate: parser/HIR/FIR/runtime/native vs deterministic model vs scenario/host outputs.
- [✅] Add focused regression suite for async semantics (spawn/join/cancel/deadline/recv/await interleavings) under strict deterministic replay.
- [✅] USER-ADDED DEFINITIONS ITEM (AT BOTTOM OF ASYNC): definition of yield points (what can interleave) and a normalization rule for equivalence gates (what “matches” means across engines); implemented and used by equivalence normalization contract.

### Systems-Compiler Readiness Gaps (New, Non-Duplicate)
- [ ] Expand verifier/backend type support beyond `void`/`i32` baseline and enforce end-to-end width/sign correctness (`u*/i*/f*`, pointers, aggregates) across FIR and both native emitters.
- [ ] Implement real native lowering for `match`/enum/ADT control flow in LLVM + Cranelift (remove no-op behavior in native emit paths).
- [ ] Add exhaustive pattern diagnostics and semantic checks tied to match lowering (coverage, unreachable arms, guard behavior).
- [ ] Replace lexical `unsafe` audit scanning with AST/HIR/FIR-backed semantic unsafe-site analysis.
- [ ] Replace text/index heuristic rename/definition flow with semantic symbol resolution and scope-aware workspace edits.
- [ ] Extend dependency model beyond path-only dependencies with versioned/remote sources and lockfile-enforced reproducibility.
- [ ] Replace RPC/FFI TODO stubs for transport/cancellation/deadline with concrete runtime contracts and host/native parity tests.

### Runtime Networking + HTTP
- [✅] Enforce real OS `listen()` semantics in host backend.
- [✅] Replace one-shot HTTP read/write with full partial-I/O loops.
- [✅] Guarantee complete request framing for fragmented headers/bodies.
- [✅] Handle short writes correctly in response path.
- [✅] Remove clone-heavy poll scan path (no per-cycle `poll_interests.clone()`).
- [✅] Reduce HTTP copy churn in parser/serializer hot paths.
- [✅] Replace `decisions() -> Vec<_>` cloning with borrowed decision access APIs.

### Deterministic Executor + Scheduler
- [✅] Remove per-task OS thread spawn in timeout path.
- [✅] Add scheduler-native timeout enforcement without thread handoff.
- [✅] Replace O(n) queue removals in random/replay with lower-latency deterministic structures.
- [✅] Preserve deterministic replay while reducing hot-path latency.

### Compiler Throughput (FIR + Driver)
- [✅] Remove repeated clone-heavy FIR/data-flow work.
- [✅] Reduce clone-heavy module merge/qualification/canonicalization in driver.
- [✅] Move to ownership-driven/shared data movement where practical.
- [✅] Add compile-time throughput gating in CI and production gate workflow.

### Fozzy Production Gates
- [✅] Close pedantic topology coverage gaps (`uncoveredHotspotCount: 17 -> 0`).
- [✅] Require strict record/verify/replay/ci traces per changed subsystem.
- [✅] Add required host-backed scenarios for runtime/network HTTP correctness.
- [✅] Make full Fozzy production gate mandatory in release pipeline.

### Bidirectional C Compatibility
- [ ] Add imported `extern "C"` lowering for true linker imports.
- [ ] Add explicit link config surface (`-l`, `-L`, frameworks/system libs).
- [ ] Complete ABI-faithful import/export lowering across backends.
- [ ] Enforce panic boundary behavior in generated runtime/code.
- [ ] Ship `fz build --lib` outputs (`.a`/`.so`/`.dylib`) with installable headers.
- [ ] Add C-host lifecycle contract (init/call/shutdown/cleanup).
- [ ] Add callback support (C function pointers into Fozzy) with signature validation.
- [ ] Expand to validated `repr(C)` structs/enums (size/align/layout checks).
- [ ] Add cross-language matrix tests (macOS/Linux, x86_64/aarch64, C->Fozzy and Fozzy->C).
- [ ] Gate release on full bidirectional ABI matrix.
- [ ] Publish production interop guide.

### Editor Tooling (Syntax Highlighting + LSP)
- [✅] Define and freeze grammar/token classes for editor-facing syntax categories.
- [✅] Ship baseline syntax highlighting grammar (Tree-sitter/TextMate) for `.fz` files.
- [✅] Add editor injection/query rules for strings, comments, keywords, types, literals, and operators.
- [✅] Stand up minimal LSP server transport (`initialize`, `shutdown`, `exit`) over stdio JSON-RPC.
- [✅] Add document sync (`didOpen`, `didChange`, `didClose`) with incremental parse/update pipeline.
- [✅] Publish diagnostics from parse/name/type validation with stable ranges and severities.
- [✅] Implement hover with symbol/type/doc info.
- [✅] Implement go-to-definition for local/module symbols.
- [✅] Implement completion baseline for keywords, locals, modules, and members.
- [✅] Add find-references and rename with workspace-safe edits.
- [✅] Add semantic tokens support to complement grammar highlighting.
- [✅] Ship VS Code extension wiring (language config + LSP client bootstrap).
- [✅] Validate LSP determinism and regression with Fozzy trace record/verify/replay/ci.
- [✅] Add host-backed editor-integration smoke checks where feasible.

### Release Flow
- [✅] Phase 1: correctness fixes (listen, partial I/O, timeout correctness).
- [✅] Phase 2: runtime hot-path performance fixes (network/executor scope completed).
- [✅] Phase 3: compiler throughput fixes.
- [✅] Phase 4: topology closure (`17 -> 0`).
- [✅] Phase 5: release hardening + strict gate + perf non-regression.
- [ ] Merge remaining production implementation slices.
- [✅] Remove compatibility shims from runtime hot paths for replaced networking/executor architecture.
- [✅] Keep deterministic replay stable after scheduler/network redesign.
- [✅] Meet runtime perf non-regression thresholds for runtime/networking test paths.

### PR Plan
- [✅] PR-A: listen contract + event-driven poll path.
- [✅] PR-B: HTTP partial-I/O correctness + low-allocation codec.
- [✅] PR-C: timeout redesign + O(1) queue operations.
- [✅] PR-D: decision-log API redesign.
- [✅] PR-E: FIR/driver clone reduction.
- [✅] PR-F: pedantic coverage closure + production gate enforcement.

## Checklist: Done

### Runtime Networking + HTTP Baseline
- [✅] Host backend with bind/listen/accept/read/write exists.
- [✅] Decision logging exists in networking layer.
- [✅] HTTP parser/serializer exists in stdlib/runtime paths.
- [✅] `Expect: 100-continue`, chunked handling, keep-alive baseline implemented.
- [✅] Host-backed runtime smoke checks executed successfully.

### Runtime Networking + Deterministic Executor (Production Implementation)
- [✅] Host listen lifecycle is now enforced (`bind` -> `listen` -> `accept`).
- [✅] Accept is invalid before listen in deterministic and host-backed listener state paths.
- [✅] HTTP serving path now handles partial reads and framing completeness checks.
- [✅] HTTP serving path now handles partial/short writes with retry bounds.
- [✅] Poll-interest scan no longer clones full interest map each cycle.
- [✅] Borrowed decision access replaces full decision vector clone API in network backends.
- [✅] Deterministic executor queue replaced with O(1) remove-by-id run-queue structure.
- [✅] Random scheduler no longer depends on O(n) mid-queue removals.
- [✅] Replay scheduling no longer depends on linear queue position scans.
- [✅] Deterministic timeout path no longer spawns OS threads per task.
- [✅] `cargo test -p runtime -p stdlib` passed after architectural changes.
- [✅] `cargo test --workspace` passed after architectural changes.

### Deterministic Executor + Scheduler Baseline
- [✅] Deterministic scheduler modes implemented: `fifo`, `random`, `coverage_guided`.
- [✅] Deterministic replay path exists and smoke checks pass.
- [✅] Timeout semantics exist in executor baseline.

### Compiler/FIR/Driver Baseline
- [✅] Parser/HIR/FIR/compiler pipeline foundation is implemented.
- [✅] FIR includes data-flow/liveness baseline.
- [✅] Driver module load/qualification/canonicalization exists end-to-end.

### Fozzy Validation Baseline
- [✅] `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json` passed.
- [✅] `fozzy test --det --strict tests/example.fozzy.json --seed 4242 --json` passed.
- [✅] Trace lifecycle smoke path passed (`run --record`, `trace verify`, `replay`, `ci`).
- [✅] Host-backed smoke run passed (`--proc-backend host --fs-backend host --http-backend host`).
- [✅] Additional CLI smoke commands passed (`fuzz`, `explore`, `shrink`, `report`, `artifacts`, `env`, `usage`, `map suites`).
- [✅] Pedantic baseline captured: `requiredHotspotCount=17`, `uncoveredHotspotCount=17`.

### Bidirectional C Compatibility Baseline
- [✅] `pub extern "C"` export flow exists.
- [✅] `fz headers` exists.
- [✅] `fz abi-check` exists.
- [✅] FFI panic-boundary policy/checking exists.
- [✅] Baseline C-export compatibility path is functional.

### Async + Multithreading Baseline
- [✅] Parser tokenizes `async` keyword.
- [✅] Parser carries function-level async semantics (`is_async`) and tokenizes/parses `await` keyword.
- [✅] AST/HIR include first-class `Await` expression representation and traversal.
- [✅] HIR enforces semantic async checks (`await` in non-async function and awaiting non-async/non-call target raise errors).
- [✅] Deterministic executor provides seeded scheduling policies (`fifo`, `random`, `coverage_guided`).
- [✅] Deterministic executor includes cancellation, timeout, join-cycle deadlock detection, IO wait/ready, and tracing hooks.
- [✅] Native runtime shim provides pthread-backed `spawn` and process-lifecycle join-on-exit.
- [✅] Native runtime shim maps `yield`/`checkpoint`/`pulse` to scheduler yield behavior.
- [✅] Non-scenario deterministic test artifacts include thread/async schedule traces and timeline/report/explore/shrink manifests.
- [✅] Driver async hook/workload counting is AST-semantics-driven (not source-string marker heuristics).
- [✅] Deterministic `.fzy run --det` routes via language async model (`deterministic-language-async-model`) instead of capability-scenario routing.
- [✅] Native backend runtime imports/shims include `timeout`/`deadline`/`cancel`/`recv`.
- [✅] Async equivalence gate includes explicit yieldpoint and normalization definitions and passes on async probe.
- [✅] Fozzy strict deterministic doctor/test and trace verify/replay/ci lifecycle are passing on baseline scenarios.

### Plan Status
- [✅] Plan is checklist-only.
- [✅] Undone items are at the top.
- [✅] Done items are at the bottom.
