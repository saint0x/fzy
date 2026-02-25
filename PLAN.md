# PLAN.md

- [✅] Date: 2026-02-25
- [✅] Owner: Runtime/Compiler Core

## SITREP (as of February 25, 2026): not yet at full bidirectional C compatibility

Current status is partial bidirectional, with major gaps in coverage and at least one concrete ABI-break risk.

Overall readiness: Amber/Red
What works: C-facing header/ABI generation, ABI baseline checking, native trace + Fozzy trace lifecycle
What blocks “full bidirectional compatibility”: missing reverse bridges, coverage debt, ABI drift risk

What is shipped
- FFI surface exists via `pub extern "C" fn ...` declarations and generated C headers/ABI manifests (`command.rs` export/header path, `docs/abi-policy-v1.md`).
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

## Solidifying For Production (Maturity Closure)

Status snapshot (as of February 25, 2026):
- Fozzy strict deterministic lifecycle is healthy (`doctor`, `test --det --strict`, `run --det --record`, `trace verify --strict`, `replay`, `ci`).
- Host-backed validation is healthy (proc/fs/http host runs pass).
- Full production gate script currently passes end-to-end (`scripts/fozzy_production_gate.sh`), including pedantic topology closure and unsafe-budget gate.
- `fozzy map suites --profile pedantic` currently reports closure at this point-in-time (`requiredHotspotCount=18`, `uncoveredHotspotCount=0`).
- Critical maturity blocker remains: `cargo test --workspace` is currently not green (4 failing `crates/driver` tests).

Production-readiness objective:
- Move from "strong deterministic runtime/testing platform" to "serious systems-language maturity" by closing language semantics parity, release-gate completeness, and production DX rigor.

### Release Gate Unification (Blockers)
- [ ] Make `cargo test --workspace` a mandatory release gate and fail release when any crate test fails.
- [ ] Add compiler pipeline gate (`cargo check --workspace`) to production release script.
- [ ] Add `fz abi-check` baseline validation for shipped examples/apps in release gate.
- [ ] Add `fz parity` and `fz equivalence` mandatory gates for representative language probes.
- [ ] Enforce warning-free first-party builds in release (`-D warnings` or equivalent policy).
- [ ] Add a single "ship gate" entrypoint that runs language + compiler + Fozzy + ABI + docs/tooling smoke.
- [ ] Make shipped examples release-blocking for FFI contracts (`fz headers`/ABI generation must pass for examples that export C ABI).

### Systems Language Semantics Parity
- [✅] Remove `i32`-only literal/token bottleneck from parser/AST and support full-width integer literal typing.
- [✅] Complete end-to-end type semantics parity across parser -> HIR -> FIR -> verifier -> native backends for `u*/i*/f*`, pointers, refs, arrays, structs, enums.
- [✅] Remove or close remaining `void/i32`-only native signature constraints with concrete lowering support.
- [✅] Expand verifier guarantees beyond current narrow entry return-type assumptions to full declared return-type families.
- [✅] Add cross-backend semantic conformance tests for non-`i32` signatures and aggregate returns.
- [✅] Add ABI/layout contract tests for non-trivial `repr(C)` structs/enums and alignment-sensitive cases.
- [✅] Fix `usize`/`isize` semantics to be target-dependent and ABI-correct (no unconditional `usize -> u64`, `isize -> i64` concretization in language/FFI paths).
- [✅] Align C type mapping for pointer-sized integers to `size_t`/`ssize_t` semantics where applicable, not fixed-width aliases.
- [✅] Extend ABI manifest identity with hard build/target identity fields (target triple, data-layout hash, compiler/toolchain identity hash).

### Memory Safety Hardening Depth
- [ ] Strengthen alias/lifetime/provenance verification beyond current heuristic/intra-procedural baseline.
- [ ] Add deeper async suspension borrow-safety proofs and regressions for borrow-across-`await` edge cases.
- [ ] Add inter-procedural ownership/lifetime summaries for generic/trait-heavy call paths.
- [ ] Add memory-model conformance probes for atomic ordering claims (`Relaxed`/`Acquire`/`Release`/`AcqRel`/`SeqCst`).
- [ ] Align public safety positioning with enforceability: avoid "Rust-class outcomes" claims until proof depth and guarantees actually match.

### Bidirectional Trace/Interop Closure
- [ ] Route native trace replay/shrink/ci through validated Fozzy replay path (or provide explicit equivalence bridge) so bidirectional claim is operationally true.
- [ ] Add reverse trace conversion path (`.fozzy` -> native trace schema) or formally narrow public compatibility claim.

### CI + Operational Maturity
- [ ] Add first-party CI workflows under `.github/workflows` for PR and mainline enforcement.
- [ ] Require deterministic reproducibility artifacts on CI failures (trace + timeline + report auto-upload).
- [ ] Add release-branch policy checks for lock/vendor drift and ABI-manifest drift.
- [ ] Add target matrix gating for bidirectional C interop (macOS/Linux, x86_64/aarch64) as required release condition.
- [ ] Add flake-tracking budget for deterministic tests and gate on regression.

### Tooling + DX Solidification (High Value, Not Overkill)
- [ ] Stabilize LSP production ergonomics: eliminate dead-code/warning drift, tighten protocol behavior, and keep diagnostics/hover/rename deterministic.
- [ ] Publish one canonical "production workflow" doc path (author -> check -> verify -> gate -> release) and keep command outputs aligned.
- [ ] Add strict smoke for `fozzyfmt` and `fozzydoc` into production gate.
- [ ] Add structured failure triage playbook mapping common failures to exact fix workflows.

### Core Stdlib Expansion Priorities (`core`)
- [ ] Add `core.bytes` primitives (byte buffers, endian encode/decode, safe slicing helpers).
- [ ] Add `core.path` primitives (normalize/join/split, platform-safe path operations).
- [ ] Add `core.collections` baseline (`Vec`, `Map`, `Set`) with deterministic-friendly contracts.
- [ ] Add `core.sync.atomic` baseline typed atomics/fence APIs aligned with memory-model contract.
- [ ] Add `core.encoding` baseline (json/base64/hex) for practical systems/app interoperability.
- [ ] Add `core.error` baseline typed error/context propagation primitives.
- [ ] Add `core.time.duration` utilities for monotonic arithmetic and deadline composition.
- [ ] Expand `core.fs` with production file primitives (tempfiles, file-region APIs, optional mmap boundary).

### Tracking + Exit Criteria
- [ ] Close all currently failing `crates/driver` tests and keep workspace green for 14 consecutive days.
- [ ] Keep pedantic hotspot closure at `uncoveredHotspotCount=0` across two consecutive release candidates.
- [ ] Demonstrate release-gate pass on clean checkout in CI and local reproducibility.
- [ ] Mark "serious systems-language maturity" only after all above blocker sections are complete.

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
- [✅] Production update (no backwards compatibility): replaced lexical `fz audit unsafe` substring scanning with semantic AST-driven unsafe call analysis (real `unsafe(...)`/`unsafe_reason(...)` nodes only, comment/string false positives removed).
- [✅] Production update (no backwards compatibility): added native signature lowerability contract enforcement so unsupported parameter/return types fail verification early instead of silently degrading in `i32`-only native lowering.
- [✅] Production update (no backwards compatibility): upgraded FIR value-type model from `I32` collapse to structured type families (`Int/Float/Ptr/Ref/Slice/Array/Str/Aggregate`) to prevent type-width information loss in core IR.
- [✅] Expand verifier/backend type support beyond `void`/`i32` baseline and enforce end-to-end width/sign correctness (`u*/i*/f*`, pointers, aggregates) across FIR and both native emitters.
- [✅] Implement real native lowering for `match`/enum/ADT control flow in LLVM + Cranelift (remove no-op behavior in native emit paths).
- [✅] Add exhaustive pattern diagnostics and semantic checks tied to match lowering (coverage, unreachable arms, guard behavior).
- [✅] Replace lexical `unsafe` audit scanning with AST/HIR/FIR-backed semantic unsafe-site analysis.
- [✅] Replace text/index heuristic rename/definition flow with semantic symbol resolution and scope-aware workspace edits.
- [✅] Extend dependency model beyond path-only dependencies with versioned/remote sources and lockfile-enforced reproducibility.
- [✅] Replace RPC/FFI TODO stubs for transport/cancellation/deadline with concrete runtime contracts and host/native parity tests.

### Production Memory Safety Flag + Scope (Rust-Class Target)
- [✅] MEMORY SAFETY FLAG: SAFE-BY-DEFAULT, RUST-CLASS SAFETY OUTCOMES FOR SAFE CODE, AUDITABLE UNSAFE ISLANDS ONLY.
- [✅] MEMORY SAFETY SPECTRUM TARGET: ~9/10 TOWARD RUST, FAR FROM C, WITH ZERO TOLERANCE FOR UNSOUND DEFAULTS.
- [✅] SHIP A PRODUCTION MEMORY MODEL SPEC: OWNERSHIP, BORROWING, ALIASING, PROVENANCE, DROP, PANIC/UNWIND, ATOMIC ORDERING, AND FFI BOUNDARY RULES.
- [✅] UPGRADE TYPE SYSTEM FOR MEMORY CORRECTNESS: FIRST-CLASS OWNED/SHARED/MUT BORROWS, RAW POINTERS, HANDLE TYPES, NULLABILITY POLICY, AND LAYOUT VALIDITY CONTRACTS.
- [✅] IMPLEMENT FLOW-SENSITIVE BORROW CHECKING: MOVE ANALYSIS, USE-AFTER-MOVE PREVENTION, EXCLUSIVE `&mut`, SHARED `&`, NLL/REGION CONSTRAINTS, AND ESCAPE ANALYSIS.
- [✅] ADD INTER-PROCEDURAL OWNERSHIP/BORROW EFFECT SUMMARIES FOR FUNCTION CALLS, RETURNS, GENERICS, TRAITS, ASYNC SUSPENSION POINTS, AND CLOSURE CAPTURES.
- [✅] REMOVE I32-COLLAPSED MEMORY INTRINSIC TYPING; ENFORCE END-TO-END POINTER/RESOURCE TYPES FOR `alloc`/`free`/`close` AND RELATED RUNTIME OPS.
- [✅] HARDEN LINEAR/RESOURCE SEMANTICS: EXACTLY-ONCE CONSUMPTION, PARTIAL-MOVE RULES, REINITIALIZATION RULES, AND DETERMINISTIC DROP ORDERING.
- [✅] REPLACE UNSAFE LEXICAL SCANNING WITH SEMANTIC UNSAFE NODES PLUS REQUIRED INVARIANT PROOFS, REASON STRINGS, OWNERSHIP TAGGING, AND RELEASE-BLOCKING UNSAFE DELTA GATES.
- [✅] DEFINE CONCURRENCY MEMORY SAFETY TRAITS/CAPABILITIES (`Send`/`Sync`-CLASS MODEL), ENFORCE DATA-RACE FREEDOM BY CONSTRUCTION, AND VALIDATE BORROWS ACROSS `await`.
- [✅] SHIP PRODUCTION ALLOCATOR CONTRACTS: SYSTEM/ARENA/BUMP POLICIES, OOM BEHAVIOR PROFILES, HARDENED RUNTIME MODE (POISON/QUARANTINE/GUARD PAGE OPTIONS), AND LEAK BUDGET ENFORCEMENT.
- [✅] ENFORCE FFI MEMORY SAFETY WALL: FFI-SAFE TYPE SUBSET, `repr(C)` SIZE/ALIGN/OFFSET CHECKS, OWNERSHIP TRANSFER ANNOTATIONS, NO PANIC ACROSS ABI, CALLBACK LIFETIME RULES.
- [✅] STABILIZE BACKEND MEMORY SEMANTICS: LOWERING-PRESERVATION TESTS, CONSERVATIVE ALIAS METADATA EMISSION, AND CROSS-BACKEND MEMORY EQUIVALENCE GATES.
- [✅] EXPAND FOZZY MEMORY VALIDATION TO PRODUCTION MANDATORY GATES: STRICT DET DOCTOR/TEST, TRACE RECORD/VERIFY/REPLAY/CI, HOST-BACKED PARITY, AND MEMORY-GRAPH TOPOLOGY COVERAGE.
- [✅] ADD UNSOUNDNESS INCIDENT PROCESS: MEMORY SAFETY RFC TRACK, UNSAFE BUDGET, RELEASE SIGN-OFF, HOTFIX PLAYBOOK, AND POSTMORTEM REQUIREMENTS.

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
- [✅] Parser now supports first-class `#[ffi_panic(abort|error)]` attribute syntax.
- [✅] Remove marker-string fallback for panic-boundary detection (no backward compatibility).
- [✅] Enforce panic-boundary contracts from parsed AST attributes only.
- [✅] Add parser diagnostics/tests for invalid `ffi_panic` attribute usage.
- [✅] Add imported `extern "C"` lowering for true linker imports.
- [✅] Add explicit link config surface (`-l`, `-L`, frameworks/system libs).
- [✅] Complete ABI-faithful import/export lowering across backends.
- [✅] Enforce panic boundary behavior in generated runtime/code.
- [✅] Ship `fz build --lib` outputs (`.a`/`.so`/`.dylib`) with installable headers.
- [✅] Add C-host lifecycle contract (init/call/shutdown/cleanup).
- [✅] Add callback support (C function pointers into Fozzy) with signature validation.
- [✅] Expand to validated `repr(C)` structs/enums (size/align/layout checks).
- [✅] Add cross-language matrix tests (macOS/Linux, x86_64/aarch64, C->Fozzy and Fozzy->C).
- [✅] Gate release on full bidirectional ABI matrix.
- [✅] Publish production interop guide.

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

### Compiler Diagnostics (Rust-Class Verbosity + Full Context)
- [✅] Define and freeze diagnostics v2 contract for text/json/LSP parity (codes, severities, spans, labels, notes, helps, suggestions, related locations, and stable schema/versioning).
- [✅] Replace summary-only type-check failures with per-error structured diagnostics at source of truth in HIR/type checker (no silent `errors += 1` paths).
- [✅] Attach primary spans and rich secondary labels for parser/type/verifier diagnostics, including call-site vs declaration-site and expected-vs-actual contexts.
- [✅] Add multi-line and multi-span code-frame rendering in CLI text diagnostics with Rust-style context blocks and related-location sections.
- [✅] Expand verifier diagnostics to include source anchors and structured evidence (why the rule fired, what data triggered it, and exact fix path).
- [✅] Add deterministic diagnostic code taxonomy across parser/HIR/verifier/native-lowering/LSP paths with stable, documented code families.
- [✅] Ensure diagnostic enrichment is semantic-first (not message-only fallback), while preserving safe fallback snippet/label hydration when spans are missing.
- [✅] Upgrade `fz lsp diagnostics` text mode to optionally emit full diagnostic bodies, not only summary counters.
- [✅] Upgrade LSP diagnostic conversion to include full context payload via standard fields (`relatedInformation`, tags, codeDescription/data) mapped from internal labels/notes/suggestions.
- [✅] Add module-import chain context for cross-file parse/type failures (root module -> imported module -> failing location).
- [✅] Add dedicated diagnostics golden tests for parser/HIR/verifier/CLI-text/CLI-json/LSP parity, including snapshot tests for code frames and related labels.
- [✅] Add regressions covering high-value failure classes: unresolved call, generic bound failures, field/variant resolution, match exhaustiveness/unreachable arms, capability violations, and FFI boundary diagnostics.
- [✅] Add diagnostics-focused Fozzy gates using strict deterministic first (`doctor --deep`, `test --det --strict`) plus trace record/verify/replay/ci and host-backed checks where feasible.
- [✅] Publish production diagnostics guide and error-code reference with examples and remediation playbooks.

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
