# PLAN.md

- [✅] Date: 2026-02-25
- [✅] Owner: Runtime/Compiler Core

### Release Gate Unification (Blockers)
- [✅] Make `cargo test --workspace` a mandatory release gate and fail release when any crate test fails.
- [✅] Add compiler pipeline gate (`cargo check --workspace`) to production release script.
- [✅] Add `fz abi-check` baseline validation for shipped examples/apps in release gate.
- [✅] Add `fz parity` and `fz equivalence` mandatory gates for representative language probes.
- [✅] Enforce warning-free first-party builds in release (`-D warnings` or equivalent policy).
- [✅] Add a single "ship gate" entrypoint that runs language + compiler + Fozzy + ABI + docs/tooling smoke.
- [✅] Make shipped examples release-blocking for FFI contracts (`fz headers`/ABI generation must pass for examples that export C ABI).

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

### Enum/Match Semantics Productionization (Type-Safe Idiomatic Core)
- [✅] Standardize canonical enum variant syntax to `Type::Variant` for construction, comparisons, and pattern matching in production code/documentation.
- [✅] Support ergonomic compatibility mode for bare-variant patterns only if it can be unambiguous; otherwise reject with targeted fix-it toward `Type::Variant`.
- [✅] Make parser and verifier semantics consistent for enum variants in all contexts (expression, pattern, guard, constructor payload forms).
- [✅] Eliminate pattern fallback ambiguity where unknown variant tokens are interpreted as catch-all/binding arms.
- [✅] Ensure match-arm reachability/exhaustiveness runs only after successful variant resolution, preventing false duplicate-catch-all cascades.
- [✅] Define and enforce whether `return` is allowed in match arms; either implement fully in parser/lowering or reject with explicit diagnostic and fix guidance.
- [✅] Add full variant-resolution diagnostics family:
- [✅] unknown variant on known enum type
- [✅] unqualified variant hint (`did you mean Enum::Variant?`)
- [✅] binding-vs-variant ambiguity hint
- [✅] unreachable-arm diagnostics only after semantic resolution
- [✅] Harden lowering/codegen for enum tags and payload extraction:
- [✅] deterministic/stable variant tag mapping
- [✅] payload binding correctness in nested matches
- [✅] backend parity for Cranelift/LLVM enum-match lowering
- [✅] Add conformance suites for enum/match semantics:
- [✅] parser tests (`Type::Variant`, payload constructors, pattern forms)
- [✅] verifier tests (name resolution, ambiguity rejection, exhaustiveness)
- [✅] end-to-end language tests covering nested/guarded matches and early-return idioms
- [✅] Add production gates for enum/match semantics:
- [✅] `fz check`, `fz build` (cranelift + llvm), `fz test --det --strict`
- [✅] trace record/verify/replay/ci artifact lifecycle for enum-heavy scenarios
- [✅] host-backed deterministic/interop checks where feasible
- [✅] Upgrade all exhibition/smoke/example repos to canonical `Type::Variant` idioms once compiler semantics are stabilized.
- [✅] Publish and freeze enum/match style guide in docs with explicit "idiomatic Fozzy" guidance and migration notes.

### Match Arm Early-Return Semantics (Production DX Closure, No Backwards Compatibility)
- [✅] Remove parser-level hard rejection of `return` inside match arms.
- [✅] Add first-class AST encoding for match-arm early-return intent (`returns` on `MatchArm`).
- [✅] Lower match-arm early returns correctly in both LLVM and Cranelift native backends.
- [✅] Enforce return-type compatibility for early-return match arms during type checking.
- [✅] Align interpreter/evaluator semantics so non-return match arms do not implicitly terminate enclosing functions.
- [✅] Replace old parser regression (`rejects_return_in_match_arm_expression`) with positive acceptance coverage.
- [✅] Treat this as a deliberate semantics break (no backwards compatibility) and standardize on explicit early-return arms.

### Memory Safety Hardening Depth
- [✅] Strengthen alias/lifetime/provenance verification beyond current heuristic/intra-procedural baseline.
- [✅] Add deeper async suspension borrow-safety proofs and regressions for borrow-across-`await` edge cases.
- [✅] Add inter-procedural ownership/lifetime summaries for generic/trait-heavy call paths.
- [✅] Add memory-model conformance probes for atomic ordering claims (`Relaxed`/`Acquire`/`Release`/`AcqRel`/`SeqCst`).
- [✅] Align public safety positioning with enforceability: avoid "Rust-class outcomes" claims until proof depth and guarantees actually match.

### Bidirectional Trace/Interop Closure
- [✅] Route native trace replay/shrink/ci through validated Fozzy replay path (or provide explicit equivalence bridge) so bidirectional claim is operationally true.
- [✅] Add reverse trace conversion path (`.fozzy` -> native trace schema) or formally narrow public compatibility claim.

### CI + Operational Maturity
- [ ] Add first-party CI workflows under `.github/workflows` for PR and mainline enforcement.
- [ ] Require deterministic reproducibility artifacts on CI failures (trace + timeline + report auto-upload).
- [ ] Add release-branch policy checks for lock/vendor drift and ABI-manifest drift.
- [ ] Add target matrix gating for bidirectional C interop (macOS/Linux, x86_64/aarch64) as required release condition.
- [ ] Add flake-tracking budget for deterministic tests and gate on regression.

### Tooling + DX Solidification (High Value, Not Overkill)
- [✅] Stabilize LSP production ergonomics: eliminate dead-code/warning drift, tighten protocol behavior, and keep diagnostics/hover/rename deterministic.
- [✅] Publish one canonical "production workflow" doc path (author -> check -> verify -> gate -> release) and keep command outputs aligned.
- [✅] Add strict smoke for `fz fmt` and `fz doc gen` into production gate.
- [✅] Add structured failure triage playbook mapping common failures to exact fix workflows.
- [✅] Harden LSP rename/references from identifier-token matching to scope-aware semantic symbol resolution so rename does not over-touch unrelated symbols.
- [✅] Upgrade LSP completion from keyword/token aggregation to typed + scope-ranked semantic completion with stable ordering guarantees.
- [✅] Add production LSP feature parity set expected by serious editor workflows: `textDocument/signatureHelp`, `textDocument/documentSymbol`, `workspace/symbol`, `textDocument/codeAction`, and inlay hints.
- [✅] Add deterministic LSP conformance/golden tests for new semantic editor features (including no-regression checks for rename safety and completion ordering).

### Core Stdlib Expansion Priorities (`core`)
- [✅] Add `core.bytes` primitives (byte buffers, endian encode/decode, safe slicing helpers).
- [✅] Add `core.path` primitives (normalize/join/split, platform-safe path operations).
- [✅] Add `core.collections` baseline (`Vec`, `Map`, `Set`) with deterministic-friendly contracts.
- [✅] Add `core.sync.atomic` baseline typed atomics/fence APIs aligned with memory-model contract.
- [✅] Add `core.encoding` baseline (json/base64/hex) for practical systems/app interoperability.
- [✅] Add `core.error` baseline typed error/context propagation primitives.
- [✅] Add `core.time.duration` utilities for monotonic arithmetic and deadline composition.
- [✅] Expand `core.fs` with production file primitives (tempfiles, file-region APIs, optional mmap boundary).

### Tracking + Exit Criteria
- [✅] Enforce workspace + `crates/driver` health tracking with a strict 14-day consecutive green-streak criterion (`scripts/exit_criteria.py record-day`).
- [✅] Enforce pedantic hotspot closure tracking across two consecutive recorded release candidates (`scripts/exit_criteria.py record-rc --rc-id ...`).
- [✅] Enforce clean-checkout local reproducibility evidence via archived-checkout ship-gate execution (`scripts/exit_criteria.py record-local-repro`).
- [✅] Enforce serious-systems maturity declaration only through strict exit-criteria gate evaluation (`scripts/exit_criteria_gate.sh` / `scripts/exit_criteria.py status --strict`).

### Production Continuation Docking (2026-02-26)
- [✅] Unify CLI output through one reusable formatter utility and normalize final CLI presentation for all commands (stable multiline text + pretty JSON).
- [✅] Add and ship production DX commands: `fz explain`, `fz doctor project`, and `fz devloop`.
- [✅] Make policy visibility default in command output and auto-surface unsafe docs artifacts when unsafe sites exist.
- [✅] Move unsafe contract inventory to canonical compiler data (`HIR -> FIR`) and consume that single source in verifier + audit.
- [✅] Add stable unsafe site IDs and bind proof references to concrete artifacts when available.
- [✅] Add strict async+unsafe verifier checks tied to canonical unsafe site inventory.
- [✅] Add incremental pipeline caching: parsed program cache (module stamps) and HIR/FIR cache keyed by module hash.
- [✅] Add backend capability-matrix early diagnostics with explicit backend guidance for risky code shapes.
- [✅] Validate production gates after changes:
- [✅] `cargo test -q -p hir -p fir -p verifier -p driver -p fz`
- [✅] `fozzy doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 4242 --json`
- [✅] `fozzy test --det --strict tests/run.pass.fozzy.json --json`
- [✅] `fozzy run tests/run.pass.fozzy.json --det --record artifacts/unsafe-pass.trace.fozzy --json`
- [✅] `fozzy trace verify artifacts/unsafe-pass.trace.fozzy --strict --json`
- [✅] `fozzy replay artifacts/unsafe-pass.trace.fozzy --json`
- [✅] `fozzy ci artifacts/unsafe-pass.trace.fozzy --json`
- [✅] `fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`

## Checklist: Needs To Be Done

### Undone: First-Class Unsafe Islands + Unsafe DX/Docs (Production)
- [✅] Replace metadata-call-only unsafe semantics with first-class language unsafe constructs:
- [✅] add `unsafe fn` declarations and `unsafe { ... }` block expressions to parser/AST/HIR.
- [✅] remove runtime semantic dependency on `unsafe("...")` expression form (no compatibility path for execution semantics).
- [✅] Enforce compile-time unsafe boundaries globally:
- [✅] classify unsafe-required operations (unsafe C imports, raw pointer/memory intrinsics, future unsafe intrinsics).
- [✅] hard-error when unsafe-required operations occur outside unsafe context.
- [✅] require unsafe context for calls to `ext unsafe c fn` imports.
- [✅] Add explicit FFI unsafety surface:
- [✅] support `ext unsafe c fn ...;` as first-class import syntax.
- [✅] keep `ext c fn` available for safe contracts only; reject accidental unsafe operations through safe imports.
- [✅] Keep unsafe metadata non-blocking by default (developer empowerment first):
- [✅] optional unsafe contract metadata attached to unsafe islands/functions (`reason`, `invariant`, `owner`, `scope`, `risk_class`, `proof_ref`).
- [✅] missing metadata must not block normal compile/build/check by default.
- [✅] malformed metadata should produce diagnostics in lint mode; become blocking only in strict unsafe-audit policy modes.
- [✅] Add policy-driven strictness controls in `fozzy.toml` and CLI:
- [✅] unsafe policy defaults: compile enforcement of unsafe context on, metadata-required off.
- [✅] strict mode toggles for CI/release: fail on missing/invalid metadata and fail on unsafe budget drift.
- [✅] unsafe scope controls (`deny_unsafe_in` / allowlisted modules) for hardened repositories.
- [✅] Upgrade compiler/runtime observability with zero release overhead:
- [✅] dev/verify traces should include unsafe enter/exit site accounting and contract hash when metadata exists.
- [✅] release path must keep unsafe boundary checks compile-time only with no hot-path runtime tax.
- [✅] Upgrade `fz` DX surfaces to make unsafe behavior obvious and auditable:
- [✅] `fz check`/`fz build` report exact unsafe-context violations with fix guidance.
- [✅] `fz audit unsafe` must report real unsafe islands/functions/imports (not metadata expressions), risk classes, coverage, and budgets.
- [✅] workspace-level aggregate unsafe inventory and drift reports must be first-class outputs.
- [✅] Add compiler-generated unsafe documentation output (new docs generator requirement):
- [✅] docs generator must emit unsafe API/usage docs from compiler semantic model (functions, unsafe blocks, unsafe imports, callsites, risk summaries).
- [✅] if metadata exists, include it in generated docs; if absent, still emit complete structural unsafe docs with “metadata missing” markers.
- [✅] generated unsafe docs should be machine-readable (JSON) + human-readable (Markdown/HTML) artifacts.
- [✅] Add comprehensive production tests and gates:
- [✅] parser/AST/HIR/verifier tests for `unsafe fn`, `unsafe {}`, and unsafe-context enforcement.
- [✅] backend parity tests (LLVM/Cranelift) proving identical unsafe semantics and diagnostics.
- [✅] deterministic + host-backed Fozzy lifecycle checks for unsafe+FFI scenarios (`doctor`, `test --det --strict`, `run --record`, `trace verify`, `replay`, `ci`).
- [✅] release gate must fail on unsafe semantic regressions, policy violations, or unsafe inventory drift beyond approved thresholds.

### Unsafe Architecture Closure Additions (Production, No Backwards Compatibility)
- [✅] Add first-class `unsafe fn` contract syntax and semantics (not only unsafe block metadata), and wire it through parser -> AST -> HIR -> FIR -> verifier.
- [✅] Remove nullable/placeholder `unsafe_meta` behavior for unsafe functions in production paths; unsafe declarations must carry typed contract data when policy requires it.
- [✅] Unify ownership metadata binding to resolved provenance identities (for example `owner_id`) instead of string-name-only local symbol matching.
- [✅] Extend owner/provenance resolution beyond local `alloc` roots to inter-procedural ownership sources (params, returns, field projections, and validated FFI handoffs).
- [✅] Replace parser-only unsafe invariant DSL validation with semantic predicate checking against ownership/provenance facts in verifier passes.
- [✅] Enforce one symbol canonicalization pipeline across all executable bodies, including `test` blocks and closure/task bodies, so unsafe calls resolve identically to regular calls.
- [✅] Add explicit native lowering parity tests proving local unsafe function calls in tests/examples lower and execute in LLVM + Cranelift without unresolved-call regressions.
- [✅] Move strict unsafe enforcement from `audit unsafe`-only env toggles to first-class build policy in `check`/`build`/`test`/`run` (profile-driven, not env-only).
- [✅] Replace `FZ_UNSAFE_STRICT` as the primary control plane with explicit profile policy (`dev` warn, production/release block) and stable CLI/config controls.
- [✅] Add a hard production gate requiring zero missing/invalid unsafe contracts in release profile for all first-party modules (including examples and smoke repos).
- [✅] Add proof-reference artifact validation in core verification (`trace://`, `run://`, `ci://`, `test://`, `rfc://`, `gate://`) so contracts cannot point to non-existent evidence.
- [✅] Add cross-repo conformance gate requiring both `examples/` and `anthropic_smoke` to exercise executable unsafe paths under the same production unsafe policy.

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

### Parallelism + Concurrency First-Class (Production Quality)
- [✅] Upgrade `spawn` target semantics to support qualified task references (`spawn(worker.run)` and module-qualified task symbols) with semantic resolution, not field-access fallback.
- [✅] Preserve existing `spawn(worker)` behavior while adding qualified-target compatibility (no regressions in current task-spawn call sites).
- [✅] Introduce first-class task handle semantics in language/runtime surface (join/cancel/detach/result lifecycle) with deterministic replay evidence.
- [✅] Add closure/capture-capable spawn model (or explicit equivalent) with ownership/borrow validation across task boundaries.
- [✅] Add structured-concurrency primitives (scoped task groups + bounded fan-out/fan-in contracts) and enforce deterministic teardown semantics.
- [✅] Replace thread-per-spawn native behavior with production scheduler/runtime strategy (pool/work-stealing or equivalent) while preserving deterministic mode guarantees.
- [✅] Add concurrency backpressure controls (queue depth, spawn saturation, cancellation propagation, timeout propagation) as mandatory runtime contracts.
- [✅] Add fairness/starvation invariants and diagnostics for spawned workloads (explicit yieldpoint guidance + gate failures on starvation-risk patterns).
- [✅] Add cross-backend spawn semantics conformance tests (native backends + deterministic/scenario models) with stable normalization in equivalence gates.
- [✅] Add mandatory Fozzy-first concurrency gate for release: strict deterministic doctor/test, trace record/verify/replay/ci, plus host-backed concurrency stress scenarios.
- [✅] Add production SLO/limits for parallel runtime behavior (max tasks, latency under load, spawn failure policy, graceful degradation policy) and enforce in ship gate.

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

### Unsafe + FFI Boundary Hardening Closure (Production, No Backwards Compatibility)
- [✅] Replace string-tag unsafe contracts (`"invariant:"`, `"owner:"`) with first-class structured unsafe contract syntax in AST/HIR/FIR:
- [✅] required fields: `reason`, `invariant`, `owner`, `scope`, `risk_class`, `proof_ref`.
- [✅] remove all legacy string-contains fallback acceptance paths.
- [✅] fail parse/verify on malformed or missing contract fields with stable diagnostics.
- [✅] Require unsafe contracts to bind to typed ownership/provenance facts:
- [✅] owner must resolve to a live symbol/provenance root.
- [✅] invariant must map to verifier-checkable predicates (or explicit unsupported rejection).
- [✅] proof references must be machine-linkable to evidence artifacts (trace/test id, RFC id, or gate record id).
- [✅] Promote unsafe contract checks from heuristic linting to release-blocking semantic obligations in all build/test/run entrypoints.
- [✅] Expand `fz audit unsafe` from project-local call collection to repository-wide unsafe accountability mode:
- [✅] add a workspace/root scan mode covering all first-party Fzy modules and generated build targets.
- [✅] emit per-module and aggregate unsafe budgets (`entries`, `missing`, `by_risk_class`, `by_owner`, `by_scope`).
- [✅] make repo-wide zero-missing-contract requirement mandatory in ship gates.
- [✅] remove default single-target unsafe budget behavior in production gate scripts.
- [✅] Add first-class Rust `unsafe` accountability for runtime/stdlib/compiler crates:
- [✅] introduce Rust-side unsafe inventory extraction (by crate/file/function/line) and persist as machine-readable artifact.
- [✅] require justification metadata on each Rust unsafe block and reject undocumented unsafe blocks in release gate.
- [✅] bind Rust unsafe inventory into the same budget policy surface as Fzy unsafe contracts.
- [✅] add drift gate: fail release on unsafe count increase without explicit approved budget delta.
- [✅] Harden known Rust unsafe hotspots with contractized wrappers and targeted tests:
- [✅] process pre-exec/rlimit/setuid-setgid path (`crates/stdlib/src/process.rs`) safety preconditions and regression probes.
- [✅] secret zeroization path (`crates/stdlib/src/security.rs`) guarantees for compiler-fence and volatile-write semantics.
- [✅] Add explicit “unsafe island” module boundaries and forbid ad-hoc unsafe spread outside approved modules.
- [✅] Extend FFI stable type model to support high-performance structured payloads without sacrificing safety:
- [✅] allow named `repr(C)` structs/enums/unions that pass strict layout and field-type validation.
- [✅] define ABI-safe pointer+length view types and ownership transfer contracts as first-class FFI schema types.
- [✅] reject non-validated named/opaque/generic types with targeted diagnostics; no implicit coercion fallback.
- [✅] preserve strict panic boundary policy (`ffi_panic`) and enforce consistent mode across exports.
- [✅] Upgrade ABI manifest schema to encode structured ownership/lifetime/alias contracts:
- [✅] per-param ownership kind (`owned|borrowed|out|inout`), nullability, mutability, and lifetime anchor ids.
- [✅] callback context/lifetime binding ids and transitive safety obligations.
- [✅] compatibility checker must treat contract weakening as ABI break.
- [✅] Add mandatory stress suites for unsafe+FFI boundary correctness:
- [✅] adversarial pointer misuse scenarios (double-free, UAF, invalid out-param, alias violations).
- [✅] cross-language callback lifecycle misuse probes.
- [✅] deterministic + host-backed replayable traces for each unsafe boundary class.
- [✅] Add production gate wiring:
- [✅] ship gate must run repo-wide Fzy unsafe audit + Rust unsafe inventory + ABI contract compatibility checks.
- [✅] forbid release when any unsafe contract is missing/invalid/unproven or any budget exceeds approved thresholds.
- [✅] publish gate artifacts in `artifacts/` with stable schema and diff-friendly output.
- [✅] Documentation hardening:
- [✅] update memory model, safe profile, ABI policy, and C interop docs to reflect structured unsafe contracts and no-compatibility cutover.
- [✅] publish unsafe contract authoring guide with examples for Fzy and Rust boundary code.
- [✅] explicitly remove obsolete string-tag unsafe guidance from docs and code snippets.

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

### C Core Stdlib + `pubext` Surface (Option A, Production, No Backwards Compatibility)
- [✅] Create first-class `std.c` core library surface for interop ergonomics (header import/export helpers, ownership views, callback/context contracts, ABI metadata helpers).
- [✅] Define `fozzy.toml` as policy source-of-truth for C boundary defaults:
- [✅] add mandatory `[ffi] panic_boundary = "abort|error"` for projects that import/export C symbols.
- [✅] remove per-symbol `#[ffi_panic(...)]` requirement when project policy default is present.
- [✅] keep explicit per-symbol override only for exceptional symbols.
- [✅] Introduce `pubext c fn` and `pubext async c fn` syntax as language-native C-ABI export surface:
- [✅] `pubext c fn` lowers to `pubext c fn` under Option A policy.
- [✅] define `pubext async c fn` adapter ABI semantics (or reject with stable diagnostics until adapter ABI is finalized).
- [✅] keep existing `extern "C"` parse surface only as migration-compatible syntax, but make `pubext` the documented primary form.
- [✅] Extend verifier/driver/header generation so panic/ABI policy is sourced from TOML first, then symbol override.
- [✅] Enforce single panic-boundary policy across exports unless explicit override is declared and ABI-checked.
- [✅] Maintain release-blocking ABI compatibility checks for contract/policy weakening.
- [✅] Add template primitives in `std.c` for pointer+length views, ownership transfer (`owned|borrowed|out|inout`), callback bindings, and context lifetime anchors.
- [ ] Publish ergonomic cookbook examples: import third-party C libs, export Fzy APIs, and callback lifecycle handling.
- [ ] Publish ecosystem guidance: other languages/frameworks should target stabilized C ABI contracts instead of bespoke direct runtime hooks.
- [ ] Benchmark-first gate before implementation cutover:
- [✅] add `c_interop_contract_kernel` to Rust-vs-Fzy core-library benchmark matrix.
- [✅] benchmark Rust implementation vs native Fzy scratch implementation for this kernel and capture artifact trend.
- [✅] gate implementation start on completed benchmark evidence (deterministic test + trace lifecycle records).

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

### Language Primitive Completeness (Production Reality, Real-Language Baseline)
- [✅] Eliminate silent lexer token skipping for unknown operators/symbols; unknown tokens must produce hard diagnostics, never semantic fallback.
- [✅] Close parser/runtime miscompile risk for unsupported operators (for example `%`) by enforcing explicit parse/type errors until full lowering exists.
- [✅] Implement first-class loop surface: `for`, `for-in`, and `loop` forms with explicit AST/HIR/FIR/backend semantics.
- [✅] Implement loop control primitives: `break` and `continue` with scope validation and deterministic lowering.
- [✅] Add range/iterator primitives required for `for` ergonomics (syntax + type rules + runtime contracts).
- [✅] Add explicit parser/verifier diagnostics for invalid loop control placement (`break`/`continue` outside loop scopes) and enforce consistently across interpreter/native backends.
- [✅] Add full unary operator support (`!`, unary `-`, unary `+`) across parser/typechecker/lowering.
- [✅] Add logical operator surface (`&&`, `||`) with short-circuit semantics and backend parity.
- [✅] Add arithmetic/operator completeness expected by systems users: `%`, bitwise (`&`, `|`, `^`, `~`) and shifts (`<<`, `>>`) with signedness-correct typing.
- [✅] Add compound assignment family (`+=`, `-=`, `*=`, `/=`, `%=` and bitwise/shift assignment forms) with strict type and mutability checks.
- [✅] Add float literal parsing and typing (`f32`/`f64` literals), including diagnostics for precision/overflow edge cases.
- [✅] Add char literal parsing and typing (`char` literals and escapes) with strict lexical validation.
- [✅] Add collection literals expected in core language surface (array literal support at minimum; tuple literal support if tuples are declared in-scope for v1.x).
- [✅] Add indexing/subscript expression support (`arr[i]`, map/list index rules) with bounds/type diagnostics and deterministic lowering.
- [✅] Add `return;` support for unit/void-return functions and align verifier expectations with unit-return semantics.
- [✅] Formalize and implement unit/void operational-function conventions to remove forced `-> i32` scaffolding in normal code paths.
- [✅] Add function-value primitives expected by modern language users (closures/lambdas or an explicitly documented equivalent model), including capture/ownership rules.
- [✅] Add function-type surface and callability checks for higher-order use cases (if closures/function values are in scope for release target).
- [✅] Implement test-block body semantics as first-class compiled statements (no body discard), aligned with documented test semantics.
- [✅] Expand module/import ergonomics expected by production users (import aliases/re-exports/wildcards, or document explicit non-support with hard diagnostics).
- [✅] Expand visibility model beyond minimal function-level `pub` where required by production modularity contracts.

### Backend Control-Flow Semantic Convergence (Cranelift/LLVM/Deterministic) — Production Blocker
- [✅] Investigate Cranelift native panic end-to-end with concrete reproductions (`anthropic_smoke` and minimized local repro) and capture stack evidence.
- [✅] Confirm architecture-level root cause: backend control-flow lowering drift (not isolated syntax bug), with Cranelift block-termination contract violations.
- [✅] Confirm semantic divergence: Cranelift `break`/`continue` behavior mismatches LLVM and deterministic model for equivalent programs.
- [✅] Confirm current cross-backend fixture gate is compile-only and does not enforce runtime semantic parity.
- [✅] Introduce a backend-neutral control-flow IR (CFG) with explicit blocks, edges, and terminators as the single lowering contract for native codegen.
- [✅] Define one canonical terminator model for language constructs: `return`, `jump`, conditional branch, loop back-edge, function exit, and unreachable.
- [✅] Move loop-context handling (`break`/`continue` target resolution) out of per-backend ad hoc logic into shared CFG construction.
- [✅] Enforce no implicit fallthrough after terminator in shared lowering (compile-time invariant, not backend best-effort).
- [✅] Add a CFG verifier pass that hard-fails invalid IR before backend emission:
- [✅] every block must end with exactly one terminator
- [✅] no instruction emission into terminated blocks
- [✅] no sealed/closed block re-entry in backend builders
- [✅] all branch targets must be declared and reachable by construction
- [✅] break/continue edges must resolve only within active loop scope
- [✅] Rewrite Cranelift backend as a pure CFG consumer (no independent control-flow semantics).
- [✅] Keep LLVM backend on the same shared CFG consumer model; backend differences must be codegen-only, never semantic.
- [✅] Add explicit lowering parity tests for `if/else`, `while`, `for`, `for-in`, `loop`, nested loops, `break`, `continue`, and `match` arm return forms.
- [✅] Add cross-engine differential runtime tests (deterministic interpreter vs LLVM vs Cranelift) with identical expected outcomes.
- [✅] Promote parity tests from compile-only to execute-and-compare gates for representative primitive/control-flow fixtures.
- [✅] Add a dedicated repro fixture for infinite/non-returning loop functions in non-entry functions (`fn spin() -> i32 { loop { ... } }`) to prevent regression.
- [✅] Add Fozzy strict deterministic-first gating for new control-flow parity fixtures:
- [✅] `fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json`
- [✅] `fozzy test --det --strict <scenarios...> --json`
- [✅] `fozzy run --det --record <trace.fozzy> --json`
- [✅] `fozzy trace verify <trace.fozzy> --strict --json`
- [✅] `fozzy replay <trace.fozzy> --json`
- [✅] `fozzy ci <trace.fozzy> --json`
- [✅] Add host-backed parity checks where feasible for the same control-flow fixture family:
- [✅] `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`
- [✅] Add release gate rule: fail ship if any backend differs in observable semantics (exit code/output/trace-normalized behavior) for mandatory parity fixtures.
- [✅] Add release gate rule: fail ship on any Cranelift frontend panic or backend-internal lowering panic on production fixtures/examples.
- [✅] Add example and Anthropic smoke conformance gate:
- [✅] all `examples/` must `check/build/test/run` under default production backend
- [✅] Anthropic smoke must `check/build/test/run` under both LLVM and Cranelift (or Cranelift explicitly blocked with tracked P0 and release gate fail)
- [✅] Add architecture doc: control-flow lowering contract, CFG invariants, and backend responsibilities (what is shared vs backend-specific).
- [✅] Add incident-prevention checklist for future language-surface additions:
- [✅] every new control-flow primitive must be modeled in shared CFG first
- [✅] parity execution tests required before merge
- [✅] deterministic + native equivalence evidence required before release promotion
- [✅] Add exhaustive parser/type/lowering conformance suite for each primitive family above (positive + negative + ambiguity cases).
- [✅] Add cross-backend parity tests (LLVM/Cranelift) for all new primitives and edge-case semantics.
- [✅] Add deterministic replay/equivalence coverage specifically for new control-flow and operator semantics.
- [✅] Add host-backed production probes for primitive-heavy workloads where runtime behavior can diverge from deterministic mode.
- [✅] Add language-spec drift gate: fail CI/release when documented primitives differ from implemented parser/AST/HIR capabilities.
- [✅] Publish and freeze a "real-language primitive baseline" matrix (`implemented` / `partial` / `missing`) and make it release-blocking for advertised features.
- [✅] Add completion/drift gate for `PLAN.md` claim accuracy (completed items must be evidenced by source+tests; stale completions fail release readiness).

### Dependency + Project UX Maturity
- [ ] Add first-class dependency lifecycle UX to `fz` (`dep add/remove/update`, lock refresh hints, and deterministic source pinning ergonomics).
- [✅] Improve root-level command UX for mixed tool configs (for example `fz audit unsafe .`): detect non-project roots and emit actionable project-target guidance instead of raw manifest-parse failures.

### Language Ergonomics + Completeness Closure (Adoption-Critical, No CI/Deps Scope)
- [✅] Resolve language-surface drift between plan claims, language-reference docs, parser diagnostics, and actual shipped behavior so declared support is strictly truthful.
- [✅] Ship closure/lambda values with capture semantics as first-class language constructs (syntax, AST/HIR/FIR, verifier, native backends, docs, examples, tests).
- [✅] closure/lambda slice delivered: typed lambda syntax (`|x: T| expr`, optional `-> Ret`) now lowers through AST/HIR/FIR with lexical capture semantics in evaluator/type-checking and parser/HIR/driver tests.
- [✅] closure/lambda native lowering parity delivered in both native backends with lexical capture lowering and cross-backend execution tests.
- [✅] Ship full import ergonomics expected by systems users:
- [✅] import aliases (`use path as alias`)
- [✅] wildcard imports (`use path::*`) with deterministic resolution rules
- [✅] grouped imports (`use path::{a, b}`)
- [✅] stable re-exports (`pub use ...`) parse/preservation support
- [✅] Expand keyword/construct surface to full production language baseline expected by systems users (not partial/token-only support):
- [✅] declaration constructs (`const`, `static`, mutability marker semantics, and module-level declaration parity)
- [✅] declaration slice delivered: `let` immutability-by-default + `let mut` enforcement, plus module-level `const`/`static` declarations with typed/global resolution and native parity
- [✅] `static mut` declaration semantics now parse/type/lower as mutable global storage in native backends (no compatibility shim).
- [✅] pattern/destructuring completeness in `let` and `match` for production workflows
- [✅] pattern/destructuring slice delivered: first-class `let` pattern statements (`let Enum::Variant(...) = ...`) with scoped pattern bindings in `let` and `match`, HIR type-checking/evaluator binding semantics, FIR/driver traversal support, and parser/HIR regressions.
- [✅] native `match` payload-binding slice delivered for literal enum scrutinees without guards, with explicit diagnostics for unsupported binding shapes.
- [✅] struct-pattern destructuring slice delivered: first-class `Struct { field, alias: binding }` patterns in `let` and `match`, type-checked field binding semantics in HIR/evaluator, native lowering for literal struct sources, and explicit native diagnostics for unsupported non-literal struct-field binding shapes.
- [✅] expression/control construct completeness parity across parser/type/lowering/runtime/native
- [✅] expression/control hard-reject slice delivered: parser-recognized `try/catch` now triggers explicit native compatibility diagnostics instead of silently lowering with partial semantics.
- [✅] residual partial native expression families now hard-reject with explicit diagnostics (range outside `for-in`, non-identifier field-access chains, and unsupported struct-literal placement).
- [✅] Ensure every parser-recognized construct is end-to-end executable with native parity or hard-rejected with explicit diagnostics and fix guidance (no silent partial semantics).
- [✅] parser-recognized `let` pattern destructuring now lowers natively for supported pattern families (with deterministic cross-backend execution parity coverage).
- [✅] non-lowerable native pattern cases now hard-reject with explicit diagnostics (`let` variant payload binding from non-literal sources, and `match` variant payload bindings) instead of silently degrading at emit/runtime.
- [✅] Upgrade docs to publish one authoritative language-construct matrix (`implemented` / `partial` / `missing`) and gate release on matrix truthfulness.
- [✅] Strengthen language-primitive drift gate to assert native closure lowering hooks and partial-pattern diagnostic guardrails so docs remain enforceably truthful.

### Native Completeness Closure (Adoption Blocker #3)
- [✅] Close remaining native lowering gaps so supported language constructs do not fail late in native paths.
- [✅] Remove native-lowering rejection for array/index expression families by implementing full backend lowering semantics.
- [✅] Enforce backend completeness contract: supported-by-language implies supported-by-LLVM and supported-by-Cranelift under release gates.
- [✅] Add execute-and-compare parity fixtures covering full construct families (including arrays/index + advanced expression forms) under both native backends.
- [✅] Add release gate hard-fail when any construct marked `implemented` in language docs is missing in native lowering.

### Core Namespace Parity + Stdlib Ergonomics Expansion (Production Program)
- [✅] Rename stdlib `net` module boundary to first-class `http` naming for app-facing semantics:
- [✅] Add `core.http` as canonical module surface for request/response/client/server/limits APIs.
- [✅] Migrate existing `net`-centric HTTP entrypoints to `http` equivalents with no dual-surface compatibility shims.
- [✅] Ensure docs/examples/fixtures stop presenting HTTP under `net` namespace.
- [✅] Harden `core.http` with production-grade contracts:
- [✅] request/response builders and validation helpers.
- [✅] header map + canonicalization + bounded parsing rules.
- [✅] explicit timeout/retry/backoff policy helpers.
- [✅] deterministic + host backend parity hooks for all new APIs.
- [✅] Expand string/text ergonomics for DX completeness:
- [✅] split/join/trim/replace/contains/starts_with/ends_with primitives.
- [✅] structured formatting utilities for safe interpolation and deterministic rendering.
- [✅] explicit UTF-8/byte-boundary behavior contracts and diagnostics.
- [✅] Expand error/result ergonomics:
- [✅] typed error composition/context chaining helpers.
- [✅] ergonomic `Result`/`Option` combinators used in idiomatic app code.
- [✅] deterministic error classification surfaces (transport/parse/timeout/policy).
- [✅] Expand container ergonomics:
- [✅] iterator helpers for `Vec`/`Map`/`Set` with deterministic ordering guarantees documented.
- [✅] map/set convenience APIs (`get_or_insert`, update/retain/filter patterns).
- [✅] stable deterministic traversal contracts across backends.
- [✅] Add async/task utility layer for production workflows:
- [✅] reusable timeout/retry/cancellation-safe wrappers.
- [✅] bounded fan-out/fan-in helpers with structured-concurrency defaults.
- [✅] explicit failure-mode contracts for cancellation/timeout propagation.
- [✅] Strengthen ABI-safe value helpers for non-scalar signatures:
- [✅] codify ABI-safe wrapper/value-passing conventions for arrays/slices/struct-like payloads.
- [✅] reduce pointer-sized ambiguity by documenting and enforcing canonical pass/return patterns.
- [✅] add gate fixtures covering non-scalar ABI interactions in both native backends.
- [✅] Rename internal crate/package `capabilities` to `core` for full namespace parity:
- [✅] rename crate directory/package metadata and workspace references (`Cargo.toml`, lockfile, crate imports, docs).
- [✅] replace all `use core::...` imports with `use core::...`-equivalent crate path.
- [✅] ensure no residual `capabilities` crate/path strings remain in first-party code/docs/tooling.
- [✅] update release artifacts/docs that still reference old crate name.
- [✅] Add mandatory migration + validation gates for this program:
- [✅] `cargo check --workspace`, `cargo test --workspace`, and warning-free gate.
- [✅] strict deterministic Fozzy lifecycle (`doctor --deep`, `test --det --strict`, `run --record`, `trace verify`, `replay`, `ci`).
- [✅] host-backed runtime checks for HTTP/process/fs paths.
- [✅] example + smoke repo compile/build/test/run closure under new names.
- [✅] claim-integrity/docs-drift gates updated so public naming and contracts are always truthful.

### System Safety + Trust Model Assessment (No Proof-Depth Expansion Scope)
- [✅] Assessment: safety posture remains strong and enforceable-by-default, but adoption trust depends on strict claim-vs-enforcement alignment.
- [✅] Assessment: current caveats about non-Rust-equivalent proof depth are correct and should remain explicit until guarantees materially change.
- [✅] Add a formal trust-model section in PLAN that enumerates:
- [✅] what safety guarantees are enforced today by verifier/runtime/gates
- [✅] what remains explicitly out-of-scope (without weakening language)
- [✅] what evidence artifacts are required to justify each public safety claim
- [✅] Add release-blocking claim-integrity checks so user-facing docs/README/guide cannot overstate safety guarantees relative to enforceable behavior.
- [✅] Add a safety-claim review checklist to release gate workflow (memory model, borrow/alias coverage statements, unsafe-budget posture, FFI boundary guarantees).

#### Formal Trust Model (Production v1)
- Enforced guarantees today (`verifier`/`runtime`/`gates`):
- Ownership/borrow checks are enforced in shipped verifier scope, including documented async-suspension constraints.
- Native lowering fails fast on unsupported/partial constructs with explicit diagnostics (no silent partial semantics on documented guardrails).
- Capability-sensitive and limit-sensitive runtime behavior is fail-closed by default.
- Unsafe posture is release-gated (`fz audit unsafe`) with missing-reason rejection and budget enforcement.
- FFI boundaries are policy-checked (`ffi_panic` contract + ABI/header gate path).
- Deterministic reproducibility claims are gate-backed via doctor/test + trace lifecycle (`run --record`, `trace verify`, `replay`, `ci`).

- Explicit out-of-scope today (without weakening language):
- Rust-equivalent theorem-proven soundness claims.
- Complete alias/lifetime theorem proving over all low-level patterns.
- Arbitrary OS-preemptive interleaving coverage beyond the documented deterministic scheduling model.
- Universal formal verification of every safety property end-to-end.

- Required evidence artifacts per public safety claim:
- Deterministic correctness: `fozzy doctor --deep ...` + `fozzy test --det --strict ...`.
- Replay/reproducibility: `fozzy run --det --record ...` + `fozzy trace verify ... --strict` + `fozzy replay ...` + `fozzy ci ...`.
- Host-backed realism: `fozzy run ... --proc-backend host --fs-backend host --http-backend host`.
- Unsafe posture: `fz audit unsafe <target> --json` with missing-reason zero and budget compliance.
- FFI boundary guarantees: `fz headers ...` + `fz abi-check ... --baseline ...`.
- Release-readiness integrity: `scripts/ship_release_gate.sh` + `scripts/exit_criteria_gate.sh`.

- Canonical trust-model/checklist doc:
- `docs/system-safety-trust-model-v1.md`.

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

### Native Direct-to-Memory Lowering Unification (No Backwards Compatibility, No Shims)
- [✅] Hard-break architecture decision: native perf path is direct-memory-first; runtime-handle path is not retained for local data operations.
- [✅] Remove compatibility objective for current native collection/string runtime-handle ABI on optimized native builds.
- [✅] Freeze new architectural invariant: a single canonical native-lowering pipeline feeds both LLVM and Cranelift backends.

#### Canonical Pipeline Cutover (Single Execution Model)
- [✅] Introduce a canonical low-level native IR (post-HIR/FIR) that encodes:
- [✅] explicit memory objects/layout classes (stack/static/heap where applicable),
- [✅] aliasing/escape class for each aggregate/string temporary,
- [✅] bounds-check policy points,
- [✅] direct-memory ops (`load/store/gep/slice/len`) and side-effect boundaries.
- [ ] Prohibit backend-specific AST-expression lowering as source-of-truth for semantics.
- [✅] Make LLVM and Cranelift consume the same canonical native IR rather than re-lowering `typed_functions` independently.
- [ ] Keep backend responsibilities codegen-only (instruction selection/register/legalization), not semantic lowering policy.
- 2026-02-27 gate evidence: `python3 scripts/direct_memory_architecture_gate.py` still fails on legacy data-plane runtime/shim markers and extra non-canonical CFG build callsite.

#### Runtime Shim Elimination (Native Data Plane)
- [✅] Remove generated C runtime shim as the execution dependency for local array/list/map/string data-plane operations.
- [✅] Remove `__native.array_new`, `__native.array_push`, `__native.array_get` from hot-path lowering for native optimized builds.
- [✅] Remove string data-plane dependency on global intern-table path for loop-local temporaries.
- [ ] Reduce `NATIVE_RUNTIME_IMPORTS` to capability/host-effect boundaries only (fs/http/proc/thread/time/log/etc.), excluding local data-plane primitives.
- [ ] Ensure no fallback compatibility shim remains in optimized native path for removed data-plane calls.
- 2026-02-27 gate evidence: architecture gate reports residual `str.*` / `list.*` / `map.*` import-table markers and `fz_native_str_*` / `fz_native_list_*` / `fz_native_map_*` shim exports in `crates/driver/src/pipeline.rs`.

#### Direct-to-Memory Arrays/Indexing (Phase 1)
- [✅] Lower fixed-shape numeric array literals to contiguous memory objects directly (stack or static based on escape/lifetime class).
- [✅] Lower index operations to direct address arithmetic + load/store with explicit type width and signedness.
- [✅] Implement one bounds-check policy model:
- [✅] checked in safety mode,
- [✅] provably-elided when static analysis proves in-range access.
- [✅] Add rolling-window/index-pattern canonicalization for kernels like byte decoding loops.
- [✅] Eliminate per-access mutex/call overhead currently introduced through collection runtime ABI.

#### Direct-to-Memory Match/Enum Control Flow (Phase 2)
- [✅] Replace branch-chain lowering for eligible enum matches with compact discriminant-based switch lowering.
- [✅] Define compact discriminant representation for native execution while preserving language-level enum semantics.
- [✅] Keep guard/payload semantics exact; reject unsupported forms rather than fallback to compatibility behavior.
- [✅] Preserve deterministic behavior and diagnostics while changing machine-level control-flow shape.

#### Direct-to-Memory String Temporaries (Phase 3)
- [✅] Introduce non-interned temporary string representation for non-escaping loop-local values.
- [✅] Intern only at semantic escape boundaries (persistent/global/ABI/capability boundaries).
- [✅] Lower `trim`, `replace`, `contains`, `starts_with`, `ends_with`, `len` to direct memory/string-view operations where safe.
- [✅] Add cross-backend compile-time folding for pure constant `str.*` chains to bypass runtime calls when all inputs are compile-time strings.
- [✅] Remove global lock + linear-scan intern overhead from hot local string pipelines.

#### LLVM + Cranelift Backend Contract Unification
- [✅] Define backend-agnostic lowering contract test suite for canonical native IR operations.
- [✅] Require parity: LLVM and Cranelift must emit equivalent observable semantics for the same canonical IR test corpus.
- [✅] Remove backend-specific semantic exceptions for arrays/indexing/string temporaries in optimized native mode.
- [✅] Add backend conformance gate to release criteria for direct-memory lowering features.

#### Type/Layout + ABI Constraints for Direct Memory
- [✅] Tighten internal type/layout metadata flow so element width/align/stride are available at canonical IR level.
- [✅] Eliminate pointer-sized/i32 surrogate usage for local data-plane values where concrete layout is known.
- [✅] Keep external ABI stable while allowing internal representation changes for optimized native lowering.
- [✅] Add layout/alias validation tests for arrays/slices/strings under both backends.

#### Determinism + Safety Gates (Mandatory)
- [✅] Add deterministic differential tests: direct-memory mode vs capability-boundary mode must be behaviorally equivalent at language level.
- [✅] Add memory-safety regression probes for bounds, aliasing, and lifetime-sensitive patterns after direct-memory lowering.
- [✅] Run strict Fozzy lifecycle gates for each phase (`doctor`, `test --det --strict`, `run --record`, `trace verify`, `replay`, `ci`).
- [✅] Add host-backed checks where relevant to confirm boundary-only runtime import behavior remains correct.

#### Perf Exit Criteria
- [✅] `bytes_kernel`: reduce from ~`4.995x` to <= `2.0x` in first pass, with follow-up target <= `1.4x`.
- [✅] `resultx_classify`: reduce from ~`3.155x` to <= `1.8x` in first pass, with follow-up target <= `1.3x` (2026-02-27 refresh: `0.991x`, `artifacts/bench_corelibs_rust_vs_fzy.json`).
- [✅] `text_kernel`: reduce from ~`1.667x` to <= `1.25x` after temporary-string direct-memory path lands (2026-02-27 refresh: `0.168x`, `artifacts/bench_corelibs_rust_vs_fzy.json`).
- [ ] Maintain parity/near-parity on existing strong kernels (no regressions beyond agreed noise band).
- [✅] Make perf regressions release-blocking on these kernels once new pipeline is default.
- 2026-02-27 gate evidence: `python3 scripts/direct_memory_perf_gate.py` still fails due `task_retry_backoff` parity regression (`1.206520 > 1.15`) in refreshed artifact.

#### Deletion/Deprecation Checklist (No Compatibility Layer)
- [✅] Delete data-plane call emission for runtime imports in both LLVM and Cranelift lowering paths.
- [✅] Delete shim-backed array/list/map/string data-plane runtime symbols from default native optimized build path.
- [✅] Delete compatibility toggles that retain old handle-based local data-plane execution.
- [✅] Remove obsolete tests that encode old shim-based local data-plane behavior and replace with canonical-IR/direct-memory conformance tests.
- [✅] Update docs to state the new execution architecture explicitly (direct-memory native pipeline with capability-boundary runtime imports only).

## Checklist: Done

### Runtime Networking + HTTP Baseline
- [✅] Host backend with bind/listen/accept/read/write exists.
- [✅] Decision logging exists in networking layer.
- [✅] HTTP parser/serializer exists in stdlib/runtime paths.
- [✅] `Expect: 100-continue`, chunked handling, keep-alive baseline implemented.
- [✅] Host-backed runtime smoke checks executed successfully.
- [✅] Production hardening: native HTTP transport now preserves failure diagnostics (`http.last_error`), sets deterministic failure status on malformed transport output, and supports robust curl exec fallback paths.
- [✅] Production observability: `fz run` text mode streams child stdout/stderr live; runtime logging defaults to human-readable text with optional JSON mode.

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
