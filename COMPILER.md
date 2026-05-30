# Compiler Hardening Checklist

This document tracks the current compiler-side memory-safety hardening work for production readiness.

Status convention:

- `✅` means completed and verified work
- pending work is written as plain bullets or numbered items only

## Historical Three-Agent Parallel Work Split

Use this section as the coordination source of truth before touching any unfinished item below. The detailed issue sections later in this document remain authoritative for problem statements, required fixes, and required tests. This split exists so three agents can work in parallel without stepping on one another.

This split is historical now that the work has been merged; later sections reflect the final closed vs blocked state on `main`.

Parallel-work rules:

- each unfinished section in this document has exactly one primary owner below
- agents are working in the same repository and must not revert one another's edits
- if a task needs another agent's new API, summary shape, or diagnostic contract, land the producer side first and note the dependency in the owned section rather than silently expanding scope
- when a task spans multiple layers, the primary owner coordinates the handoff, but file ownership boundaries still apply
- after finishing a section, mark the original detailed section with `✅` and record the commands/tests/doc updates there so nothing is lost in transit

Historical ownership map before merges:

- Agent 1 owns sections `1`, `3`, `5.35`, `6`, `7.25`, and `11`
- Agent 2 owns sections `7.75`, `9`, `10`, `12`, `13`, `13.5`, `13.75`, and Priority `5`
- Agent 3 owns Additional Product / Tooling Bug `10`, Additional Product / Tooling Bug `11`, and `Production Blocker: Native Filesystem Surface Too Thin For Real Artifact Builders`

### Agent 1: Core HIR Analysis Owner

Preamble:

- you own the compiler-side semantic model in `crates/hir` and closely related parser/type-flow changes only when they are required to make `hir` correct
- your job is to make control-flow ownership, lifetime flow, inferred owned-resource classification, and FFI semantic checks sound inside the compiler core
- you are not alone in the codebase; do not revert verifier, docs, CLI, runtime, or scenario work from other agents
- if you need verifier follow-up, expose the minimum stable summary/diagnostic surface and leave downstream verifier wording and release-gate work to Agent 2

Strict file boundaries:

- owned: `crates/hir/**`
- allowed only if directly required by a `hir` fix: tightly scoped parser/type-definition updates and `crates/hir` unit tests
- do not own: `crates/verifier/**`, `docs/**`, `tests/*.fozzy.json`, `corelib/**`, `crates/driver/**`

Owned unfinished sections:

1. Section `1`: conditional ownership merge can erase maybe-freed state
2. Section `3`: loop ownership semantics need a real fixed-point model
3. Section `5.35`: inferred handle-producing locals can bypass cleanup enforcement entirely
4. Section `6`: lifetime analysis is too shallow for production-strength claims
5. Section `7.25`: FFI alias and ownership-transfer checks are still identifier-shaped
6. Section `11`: add targeted unit tests in `crates/hir`

Expected outputs:

- path-sensitive ownership-state modeling for branches and loops
- inferred owned-handle/resource classification that does not depend on explicit `let` type spelling
- deeper lifetime/control-flow coverage in the compiler core
- semantic FFI alias/transfer checks that are provenance-based rather than identifier-shaped
- direct `crates/hir` regressions for every newly closed bug class you touch

Handoff notes for other agents:

- document any new ownership-state categories, provenance summary shapes, or lifetime-summary contracts in the touched `hir` section notes
- call out any verifier-visible behavior changes that require Agent 2 to update diagnostics, docs, or scenario expectations

### Agent 2: Verifier, Evidence, And Docs Owner

Preamble:

- you own the verifier-facing enforcement story, unsafe-accounting honesty, public wording, and release-gate evidence
- your job is to make sure the product says exactly what the implementation proves, and that the gate suite exercises those claims directly
- you are not alone in the codebase; do not revert `hir`, driver, stdlib, or scaffold work from other agents
- if you depend on new `hir` summaries from Agent 1, consume the published surface and keep any additional asks explicit rather than editing core analysis opportunistically

Strict file boundaries:

- owned: `crates/verifier/**`, `docs/**`, `USAGE.md`, `tests/*.fozzy.json`, verifier-facing integration fixtures, and release-checklist wording in this document
- allowed when required for integration coverage: targeted driver/verify harness tests that do not change compiler semantics
- do not own: `crates/hir/**` semantic changes, `corelib/**`, scaffold/bootstrap implementation, native build backend implementation

Owned unfinished sections:

1. Section `7.75`: verifier release rules currently require local `defer` even where transfer-based cleanup should be legal
2. Section `9`: unsafe “reasoned contract” accounting is overstated
3. Section `10`: unsafe docs and public language must stay within actual enforcement scope
4. Section `12`: add verifier integration tests at the `fz verify` surface
5. Section `13`: add Fozzy scenarios for compiler memory-safety regressions
6. Section `13.5`: the current Fozzy memory release gate is too narrow
7. Section `13.75`: some passing runtime evidence is still script-backed and too indirect for compiler-memory guarantees
8. Priority `5`: release criteria before reclaiming stronger production language

Expected outputs:

- verifier behavior and diagnostics that match the implemented ownership-transfer model
- unsafe-accounting/reporting language that distinguishes structural metadata from validated evidence
- docs and usage text aligned to actual compiler/verifier enforcement scope
- first-class `fz verify` fixtures and Fozzy scenarios covering every open compiler-memory bug class that is supposed to gate release

Handoff notes for other agents:

- if a scenario or doc claim depends on unresolved `hir` work, mark it as blocked by the exact section number rather than softening the requirement silently
- keep the evidence matrix explicit: unit coverage from Agent 1 is not a replacement for verifier fixtures and Fozzy gate coverage here

### Agent 3: Product Surface And Runtime Owner

Preamble:

- you own the unfinished product/tooling/runtime surface outside the core `hir` and verifier semantic engine
- your job is to make the shipped CLI, scaffold, native build surface, and stdlib filesystem surface match the real supported product contract
- you are not alone in the codebase; do not revert compiler-analysis or verifier/doc work from other agents
- when docs must change for product-surface accuracy, coordinate narrowly with Agent 2 instead of broadening into the compiler-memory wording track

Strict file boundaries:

- owned: `crates/driver/**`, `corelib/**`, product-surface docs directly tied to CLI/runtime behavior, scaffold/bootstrap implementation, native-build integration tests, and filesystem/runtime tests
- do not own: `crates/hir/**` semantic analysis, `crates/verifier/**` policy/diagnostic semantics, compiler-memory Fozzy gate design unless a product-flow scenario specifically exercises your shipped surface

Owned unfinished sections:

1. Additional Product / Tooling Bug `10`: native library backend contract is inconsistent with the public build surface
2. Additional Product / Tooling Bug `11`: `fz init` is split, underpowered, and not yet a production one-shot bootstrap command
3. `Production Blocker: Native Filesystem Surface Too Thin For Real Artifact Builders`

Expected outputs:

- one coherent shipped contract for native library backend support
- one canonical `fz init` implementation and scaffold story
- a production-usable filesystem surface for native-first artifact builders, with docs and runtime behavior reconciled

Handoff notes for other agents:

- if product-surface fixes introduce new user-facing claims in docs, flag the exact wording delta for Agent 2 review
- keep Fozzy-first validation attached to real product flows for init/build/filesystem work, not just unit or doc checks

## Completed Review Evidence

✅ Completed the source-level audit across `crates/hir`, `crates/verifier`, product docs, and verifier-facing integration surfaces.

✅ Reproduced the key pre-fix bug classes that motivated this checklist: borrowed-reference false positives, `defer free(...)` undercounting, inferred-owned cleanup gaps, branch/`match` ownership blind spots, loop/lifetime control-flow limitations, pointer/import unsafe enforcement gaps, callback context-anchor gaps, and proof-ref/accounting overstatement.

✅ Landed the HIR-side fixes for branch-sensitive ownership joins, loop fixed-point analysis, grouped/projected consume roots, inferred handle cleanup parity, assignment-aware reference lifetime flow, async borrow hardening, and expanded alias/provenance tracking.

✅ Landed the verifier/docs/evidence fixes for transfer-aware cleanup acceptance, unsafe-accounting honesty, proof-ref validation, thread-boundary diagnostics, scoped public safety wording, and first-class `fz verify` / Fozzy compiler-memory scenario gates.

✅ Landed the product-surface fixes for canonical `fz init`, explicit Cranelift-only `fz build --lib` contract wording, and the native filesystem/runtime closure needed for real artifact builders.

✅ Verified the merged checkout directly with `cargo test -q -p hir`, `cargo test -q -p verifier`, targeted `driver` / `fz` CLI tests, strict deterministic Fozzy doctor/test flows, recorded trace verify/replay/CI, and host-backed runs for the compiler-memory and init surfaces.

✅ Confirmed the current unsafe-accounting posture is clean on this checkout, with zero missing contracts, invalid proof refs, or unsafe-context violations and the approved Rust `unsafe` footprint still limited to [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs:74) and [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs:198).

✅ Added first-class `fz verify` / Fozzy release-gate coverage for conditional ownership joins, loop ownership merges, and returned-reference lifetime mismatches so the shipped evidence now matches the deeper HIR control-flow model.

## Priority 0: Fix Real Safety Gaps

### ✅ 0. Historical `hir` buildability regression is closed on this checkout

Update:

- this no longer reproduces on the current checkout
- keep this section as historical context only unless the compile failure reappears on a clean branch
- current direct evidence is `cargo test -q -p hir` passing locally

Problem:

- the current checkout fails to build the `hir` memory-safety path
- `crates/hir/src/lib.rs` compares `Option<Option<String>>` against `Option<String>` in the reference-return lifetime validator
- this prevents `cargo test -p hir` from compiling, which blocks direct verification of the memory-safety analysis itself

Why this matters:

- a non-building safety path is a release blocker regardless of the underlying soundness story
- we cannot claim production readiness for the compiler area while the core `hir` safety crate does not compile
- this also weakens trust in any passing higher-level gate that does not exercise the broken path directly

Required fixes:

1. repair the type mismatch in the return-lifetime comparison path
2. add a focused regression test that compiles the affected `hir` lifetime checker path
3. make sure CI runs a direct `cargo test -p hir` target so this cannot hide behind broader gates

Required tests:

1. `cargo test -p hir` must compile cleanly on a clean checkout
2. the returned-reference lifetime mismatch tests must run and pass after the fix
3. CI must fail immediately if the `hir` crate no longer builds

Compressed completion:

- the type mismatch in the lifetime checker is fixed
- `hir` now builds directly again on a clean checkout
- the returned-reference lifetime path is covered by direct crate tests and release-gate execution

### ✅ 1. Conditional ownership joins are now path-sensitive and preserve maybe-consumed state

### ✅ 2. `match` ownership effects are modeled for direct cleanup paths and regression-covered

### ✅ 3. Loop ownership semantics now use a real fixed-point model

### ✅ 3.5. Inferred pointer-return ownership now enters the cleanup model for inferred locals

## Priority 1: Fix Incorrect Rejections Of Safe Code

### ✅ 4. Borrowed references are no longer classified as linear resources

### ✅ 5. `free`/`close` classification now uses structural traversal for cleanup accounting

### ✅ 5.3. Inferred `alloc(...)` locals are no longer misclassified as non-linear at release points

### ✅ 5.35. Inferred handle-producing locals now match explicit handle cleanup enforcement

### ✅ 5.1. Semantic-hint collection is now structural rather than statement-shape dependent

### ✅ 5.25. The documented `defer free(...)` cleanup path now counts as real cleanup

## Priority 2: Deepen The Analysis Model

### ✅ 6. Lifetime analysis now tracks assignment and control-flow joins for return validation

### ✅ 6.5. Borrow-across-`await` detection is now expression- and control-flow-aware for same-statement shared-borrow misuse

### ✅ 7. Alias/provenance analysis now covers core destructuring and stale-root overwrite paths

### ✅ 7.1. Interprocedural pointer/ref-return provenance is no longer misattributed to the first matching argument

### ✅ 7.25. FFI alias and ownership-transfer checks now follow grouped and projected consume roots

### ✅ 7.3. Plain pointer-shaped `ext c fn` imports now require `ext unsafe c fn`

### ✅ 7.35. Callback lifetime-anchor requirements are now enforced structurally

### ✅ 7.4. Native ship C contracts now validate imports and exports through one symmetric rule set

### ✅ 7.5. Ownership transfer on argument passing now follows an explicit consume-summary rule

### ✅ 7.75. Verifier release rules no longer require local `defer` where validated transfer-based cleanup is legal

### ✅ 8. Partial-move detection now covers the core aggregate extraction shapes in v1

## Priority 3: Make Unsafe Accounting Honest And Actionable

### ✅ 9. Unsafe “reasoned contract” accounting no longer overstates compiler assurance

### ✅ 9.25. Verifier proof-ref validation now matches the strict unsafe-audit path

### ✅ 9.5. Thread-boundary borrow/send-sync failures now use a dedicated diagnostic lane

### ✅ 10. Unsafe docs and public language now stay within the enforced scope

## Priority 4: Strengthen Regression Defenses

### ✅ 11. Added targeted unit tests in `crates/hir`

### ✅ 12. Added verifier integration tests at the `fz verify` surface

### ✅ 13. Added Fozzy scenarios for compiler memory-safety regressions

### ✅ 13.5. The Fozzy memory release gate is materially broader, with remaining expansions left explicitly blocked

### ✅ 13.75. Runtime evidence is no longer the primary proof for compiler-memory guarantees

## ✅ Priority 5: Release Criteria For Stronger Production Language Are Satisfied On This Checkout

Do not consider the compiler area production-complete for full memory-safety claims until all items below are true:

1. conditional and `match` ownership state is path-sensitive and tested
2. borrowed references are no longer treated as linear cleanup obligations
3. loop ownership semantics are modeled soundly enough for shipped control-flow forms
4. lifetime analysis coverage is expanded and documented honestly
5. unsafe summary/accounting no longer overstates compiler assurance
6. unit tests, verifier fixtures, and Fozzy scenarios cover every bug class in this document
7. public docs are reconciled to the actual enforcement model

Current status on this checkout:

- Items `1` through `7` are closed for the currently shipped compiler/verifier surface.
- Full memory-safety language remains scoped to the shipped safe-language surface plus the documented compiler/verifier rule set; do not broaden that wording beyond the enforced boundary described elsewhere in this file and the public docs.

Compressed completion:

- the release criteria are satisfied for the currently shipped compiler/verifier boundary
- stronger language remains intentionally scoped to the enforced safe-language and verifier-backed surface
- future wording expansion still requires new enforcement, tests, and public-doc updates rather than inference from existing passes

## Historical Suggested Execution Order

1. Fix the borrowed-reference false positive first so safe code stops failing for the wrong reason.
2. Fix `match` ownership analysis next because it is a clear blind spot.
3. Replace `if` ownership merging with path-sensitive state.
4. Strengthen loop semantics once branch modeling is in place.
5. Expand lifetime and alias coverage on top of the new control-flow model.
6. Rework unsafe accounting and documentation once the enforcement story is stabilized.
7. Lock everything in with unit tests, verifier fixtures, and Fozzy scenarios.

## Additional Product / Tooling Bugs

### ✅ 10. Native library backend contract is now explicit about the shipped Cranelift-only `--lib` path

### ✅ 11. `fz init` now uses one canonical shipped bootstrap path

## ✅ Compiler-Owned Build Surface

The following build responsibilities should remain native to the compiler / `fz` tool rather than being pushed into a separate ecosystem builder:

- ABI lowering and symbol/link-name rules for `pubext c fn`, `pubext async c fn`, and `ext unsafe c fn`
- C header generation and ABI manifest generation
- ABI compatibility enforcement (`fz abi-check`) and contract validation
- native object/artifact emission for supported backends
- runtime-shim generation and compilation for native targets
- manifest-defined target/profile/link configuration parsing
- stable machine-readable build outputs that higher-level tools can consume
- backend capability reporting and diagnostics when a requested build mode is unsupported

Why this boundary matters:

- these concerns depend directly on compiler IR, verified type/layout information, and language safety policy
- duplicating them in a standalone builder would create drift between the language contract and the build contract
- the separate builder should orchestrate builds, not redefine the meaning of Fozzy ABI, profiles, or native artifact semantics

Recommended downstream builder scope:

- workspace orchestration
- dependency graph scheduling
- incremental caching and rebuild policy
- external C library discovery/integration
- packaging, install/export flows, and higher-level product UX
- multi-project automation on top of `fz` machine-readable outputs

Compressed completion:

- the compiler/runtime boundary is now explicit on this checkout
- `fz` remains the source of truth for ABI lowering, runtime shims, manifests, native artifact semantics, and machine-readable build outputs
- downstream builders are expected to orchestrate around that contract rather than redefine it

## Additional Completed DX / Runtime Hardening

✅ Closed the split `fz init` product surface by removing the old scaffold path, centralizing bootstrap under the shipped `fz init` command, narrowing the generated tree to the canonical minimal layout, aligning generated guidance with real commands, and validating it with crate tests plus deterministic, trace-backed, replay, CI, and host-backed Fozzy runs.

✅ Closed the process-handle lifecycle contract gap by giving `proc.spawn*` handles an explicit typed cleanup path through `proc.close(handle)`, wiring the intrinsic end to end, regression-covering the typing path in `crates/hir`, and validating it with compiler and real-project checks.

✅ Closed the qualified module-path inconsistency so dot-qualified type paths parse in signatures and cross-module const/static value paths resolve consistently, with focused parser and driver regressions backing the fix.

✅ Closed the `core.log` stdlib/verifier import poison so logging helper setup no longer leaks linear map ownership during normal import/configuration flows, with driver regression coverage and doc alignment.

✅ Closed the host-backed live-server read contract gap so `http.read(conn)` now returns `0` on successful request parse, waits through transient socket-readiness stalls, and no longer turns normal `GET /healthz` traffic into the old `503 {"error":"read_failed"}` branch.

✅ Closed the native poller surface mismatch so `http.poll_register` is now wired through native lowering, `http.poll_next` is implemented in the host runtime instead of stubbed, and both are regression-covered by driver tests plus a trace-backed host Fozzy scenario.

✅ Closed the remaining compiler control-flow evidence gap by adding a dedicated `fz verify` / Fozzy scenario for conditional ownership joins, loop iteration merges, and returned-reference lifetime mismatches, alongside passing control-flow/lifetime counterparts.

✅ Closed the native namespaced-constant lowering bug so same-module `const i32` references and dotted module constant paths no longer collapse to `0` under native codegen; `fzaudio inspect` and `build` now agree again, with driver cross-backend regression coverage plus a dedicated Fozzy scenario guarding the exact project-kind-label case.

✅ Closed the Cranelift linear-emission crash triggered by statement-position `unsafe { ... }` blocks that contained nested branches and returns around `ext unsafe c fn` calls inside exported control-plane code. Unsafe block bodies are now flattened into the surrounding CFG before backend linearization, the exported-FFI dispatch shape is regression-covered across LLVM and Cranelift, and the `megaserver` control-plane build now fails only on ordinary verifier/frontend diagnostics instead of aborting in backend codegen.

✅ Re-ran the production Fozzy trace lifecycle after the DX/runtime fixes through deterministic doctor, strict test, recorded trace, trace verify, replay, CI, and host-backed execution.

## ✅ Production Blocker: Native Filesystem Surface Is Closed On This Checkout

✅ Closed the native runtime shim helper-ordering bug by emitting forward declarations for the shared bytes-buffer and fd-wait helpers before first use, adding a shim render regression plus a native build/run Fozzy gate, and re-verifying real `fzaudio` `check` / `build` / `run` on the production path.

## ✅ Production Blocker: Spawned Child Processes Can Stall When Output Is Not Drained During Wait

✅ Closed the native process backpressure stall by teaching `proc.wait(...)` to poll and drain child stdout/stderr while waiting, adding a large-output regression plus a host-backed Fozzy scenario, and fixing return/defer lowering so deferred `proc.close(...)` no longer clobbers returned exit codes. Re-ran the real `/Users/deepsaint/Desktop/fzaudio/fixtures/cmake-plugin` production path through `inspect`, `build`, `validate`, `package`, and `release`, then completed deterministic doctor, strict test, recorded trace, trace verify, replay, CI, and native execution validation for the active runtime fix.
Compressed completion: runtime shim now drains child pipes during wait, native backends preserve explicit return values across `defer`, and the shipped gate includes targeted Rust regressions plus deterministic/host-backed Fozzy scenario coverage.

## ✅ Production Blocker: `fz run` Native Execution Diverges From The Built Binary For Child-Process Orchestration

✅ Re-ran the live `fzaudio` reproduction from a clean fixture state and verified parity again: the direct binary and `fz run` both complete the same child-process-heavy CMake build successfully. Added a dedicated driver regression that compiles a tiny Fozzy program which shells out, writes a configure-style report, and asserts identical success when invoked directly and through `Command::Run`, so wrapper/native parity for this orchestration path now has coverage instead of relying on ad hoc manual repros.
- add a dedicated regression that launches a process-spawning fixture both ways and asserts identical success / exit code / stdout behavior
- gate it with deterministic Fozzy execution plus at least one real host-backed run

## ✅ Production Blocker: No Cryptographic Or Secure-Random Runtime Surface

✅ Closed the missing crypto/runtime surface by adding native `core.crypto` intrinsics for secure random hex/base64 output, SHA-256, HMAC-SHA256, constant-time equality, and base64 encode/decode, then layering production `core.security` helpers for signed values and URL-safe token transport. Added HIR/driver/native-runtime regression coverage plus a dedicated deterministic Fozzy scenario and trace lifecycle for the shipped crypto/corelib surface. Documented the production-safe contract honestly: this checkout exposes textual encodings rather than raw binary-string APIs because native Fzy strings are NUL-terminated.

## ✅ Production DX Blocker: Safe FFI Wrapper Layers Did Not Count As Documented ABI Facades

✅ Closed the narrow strict-verification wrapper gap by distinguishing call-edge coverage from independently proven unsafe evidence: documented `ext unsafe c fn` imports and their immediate safe Fzy facades now satisfy caller-edge ownership verification without pretending compiler-generated unsafe metadata is a full proof artifact. Added HIR and `fz verify` regressions plus a Fozzy scenario for the exact two-layer host-ABI wrapper pattern.

## ✅ Production Blocker: `unsafe { ext_call(...) }` Expression Wrappers Collapsed To `void` On Strict Verify

✅ Closed the remaining FFI wrapper verifier gap by treating `unsafe { ... }` as a real expression block in type inference and by honoring the shipped borrowed pointer-length FFI contract during signature resolution and post-check validation. This fixes production-safe wrappers of the form `let code = unsafe { host_touch(s, str.len(s)) }` and moved the Megaserver control-plane path from a grouped type-check failure to an ordinary host-link stage. Added HIR and driver regressions for both the direct-return and let-bound wrapper forms.

## ✅ Production Blocker: Borrowed `str -> ptr_borrowed + len` Host Callback Payloads Crashed At Runtime

✅ Closed the native FFI payload bug by adding an internal string-byte pointer helper at the runtime boundary and teaching both LLVM and Cranelift extern-C import lowering to materialize real borrowed byte views for `_borrowed` pointer parameters instead of passing internal string-handle IDs. Also fixed native import/data-op collection through `unsafe { ... }` bodies so wrapper-local `str.len(...)` calls are declared during library builds. Added a driver regression that builds a real shared library and proves a host callback can read exact borrowed payload bytes on both backends, then revalidated Megaserver end to end by restoring the direct `megaserver_host_dispatch(ptr_borrowed, len)` path and probing the emitted library from C without the old file-read workaround in the host callback.

## Open Hardening Program: From Serious Prototype To Trusted v1 Systems Language

This section is the next open work queue after the current memory-safety/compiler hardening pass. The goal is not to make FZY bigger. The goal is to make the existing language/compiler/runtime surfaces difficult to break, easy to validate, and honest about what they guarantee.

Audit baseline on this checkout:

1. The compiler pipeline is already split into explicit crates for lexer/parser-adjacent parsing, AST, HIR, FIR, verifier, driver, stdlib, runtime, and manifest handling.
2. The verifier and driver already emit production-shaped artifacts for diagnostics, memory safety, unsafe accounting, async safety, RPC safety, and trace/reporting surfaces.
3. Native runtime imports already have one centralized table, but the current contract is still mostly callee/symbol/arity level rather than full ownership/capability/trace/blocking metadata.
4. Async/task/runtime machinery already exists in both the language and Rust support layers, but several shipped reports still describe policy as `unspecified` rather than enforced compiler law.
5. Manifest/runtime profile support currently centers on `dev`, `verify`, and `release`; there is not yet one explicit `strict` production profile contract spanning compiler, verifier, runtime, imports, and artifacts.
6. The stdlib/runtime surface is already broad enough to warrant formal per-module contracts: HTTP, JSON, process, filesystem, task/thread, crypto/security, logging, observability, time, and C interop are all first-class.
7. Both LLVM and Cranelift are already live backends, and parity hooks exist, but parity is not yet a documented all-feature guarantee with a closed allowlist/denylist.
8. Trace/reporting artifacts already carry multiple schema versions, but the language version, manifest schema version, runtime ABI/import-table version, trace schema version, and diagnostic catalog version are not yet locked together as one explicit compatibility policy.

Completed slices already landed from this queue:

- 🟢 strict production profile is now first-class across manifest, driver, runtime routing, and CLI entrypoints
- 🟢 native runtime imports now emit contract artifacts with ownership/capability/linearity/error/trace/blocking metadata
- 🟢 `fz audit ffi` and `fz audit memory` are first-class commands with shipped JSON/markdown outputs
- 🟢 RPC safety artifacts now report enforced per-call deadline evidence instead of placeholder `unspecified` policy
- 🟢 strict builds reject RPC call paths that are not explicitly bounded by `timeout(...)` or `deadline(...)`
- 🟢 task-handle runtime contracts now distinguish consuming operations (`join` / `detach` / `cancel_task`) from observational ones (`task_result`)
- 🟢 async-safety artifacts now report task-handle lifecycle policy, task-handle misuse findings, task-group misuse findings, and strict async requirements
- 🟢 strict builds now surface dedicated async/task diagnostics for handle misuse and missing/repeated task-group terminal policy
- 🟢 backend parity coverage now includes observable behavior checks for exit code, stdout, stderr, and emitted file artifacts across LLVM and Cranelift for real runtime shapes

## Priority 6: Lock Compiler And Runtime Behavior Behind Brutal Regression Coverage

### 14. Build a compiler-phase lock-in suite that makes changes safe

Problem:

- the repository already has meaningful verifier, driver, and Fozzy coverage, but the next v1 step is to make every compiler phase changeable without fear
- today the evidence is stronger for selected memory-safety and product-flow bugs than for a complete phase-by-phase compiler regression story

Required fixes:

1. build a golden corpus that covers lexer, parser, AST shaping, HIR typing/effects, FIR lowering, verifier outcomes, native lowerability, LLVM backend output, Cranelift backend output, and runtime shim linking
2. require both positive and negative coverage for every phase:
   - valid programs compile
   - invalid programs fail
   - diagnostics remain stable
   - verify/build behavior matches
   - LLVM/Cranelift outputs agree where the feature is marked parity-supported
   - module imports resolve correctly
   - caches do not hide stale results
3. add regression classes specifically for multi-file projects, nested modules, public/wildcard imports, manifest-root discovery, dependency-graph hashing, and module-cache invalidation
4. add panic-resistance gates so invalid user programs produce diagnostics rather than Rust panics across parser, HIR, verifier, and driver/native-lowerability paths

Required tests:

1. direct crate tests for parser/AST/HIR/FIR/verifier behavior
2. `fz check`, `fz verify`, `fz build`, and `fz parity` fixture coverage for the same corpus
3. strict deterministic Fozzy doctor/test coverage for representative compiler scenarios
4. at least one recorded trace for the active compiler-regression suite, followed by strict trace verify, replay, and CI
5. host-backed runs for compiler/runtime integration scenarios where native linking and runtime shim behavior matter

### 15. Expand memory-safety adversarial coverage from “sound core” to “v1 trustable”

🟢 Completed slice:
- ownership/provenance regressions already cover core use-after-move, double-free, branch-divergent ownership, grouped/projection provenance transfer, owned-parameter consumption, owned return transfer, loop merge cleanup, and runtime-handle cleanup parity
- ownership-transfer regressions now lock both grouped and plain owned returns as real transfer sites, so returning an owned local no longer requires a grouped workaround to avoid leak/resource-escape fallout
- local borrow-region enforcement is live for the currently supported static model: mutable/shared alias conflicts are rejected, mismatched reference returns are diagnosed, borrowed references are rejected across `await`, and thread-capable borrowed-return / mutable-reference boundary violations are surfaced separately from capability failures
- local borrow-region enforcement now also rejects shared borrowed parameters across thread-capable boundaries, not just mutable ones, so borrowed params/returns are consistently forced through owned or Send-safe handoff shapes
- partial-move regressions are now locked for tuple, struct-field, and struct-pattern aggregate shapes
- match-pattern ownership now applies the same partial-move law to enum destructuring too, and HIR regressions plus `fz verify` snapshots lock both struct and enum aggregate failures to the same stable diagnostic surface
- defer/cleanup ordering regressions now explicitly cover `free`-after-`defer`, `defer`-after-`free`, early-return leaks, branch leaks, and loop-scoped cleanup gaps
- driver diagnostics now snapshot-lock representative memory failures for conditional consumption and partial-move wording/help/code stability
- driver diagnostics now also snapshot-lock representative double-free wording/help/code stability, while deterministic transfer scenarios cover plain owned returns and owned-parameter handoff through real `fz verify` runs
- driver diagnostics now snapshot-lock the remaining high-value ownership/lifetime failures too: `free`-after-`defer`, `defer`-after-`free`, branch-leak ownership loss, and shared borrowed thread-boundary rejection
- local borrow-live enforcement now rejects consuming an owned source while a derived borrowed alias is still live, so borrow-then-free and borrow-then-move are covered by direct HIR regressions instead of relying only on downstream alias fallout
- deterministic Fozzy adversarial coverage now exercises defer-ordering faults, early-return/branch/loop leak paths, conditional moves, partial moves, borrow-across-`await`, and reference-return mismatch through real `fz verify` CLI runs, with recorded trace verify/replay/CI coverage for the active suite

Problem:

- the current checkout has closed the known first-wave ownership and lifetime bugs, but v1 trust requires adversarial coverage against the shapes users will actually write
- local borrow/lifetime analysis exists, yet the policy needs to be spelled out as a stable borrow-region contract and tested against hostile programs

Required fixes:

1. lock in the local borrow-region model explicitly:
   - borrow starts at creation
   - borrow ends at last statically accepted use
   - owned value cannot be moved or freed while a borrow is live
   - mutable borrow excludes all other access during its live region
   - borrow cannot cross `await` unless the language explicitly marks that path as legal
2. add adversarial tests for:
   - use-after-move
   - double-free
   - free-after-defer
   - defer-after-free
   - leak on early return
   - leak through branch
   - leak through loop
   - move in one branch only
   - return owned resource
   - consume owned parameter
   - partial move from struct
   - partial move from enum
   - borrow then move
   - borrow then free
   - mutable borrow conflict
   - reference return lifetime mismatch
   - borrow across `await`
   - borrow across `spawn`
3. extend partial-move and provenance logic to the remaining aggregate/control-flow forms that are still only partially covered by current targeted regressions
4. ensure every shipped linear or owned runtime handle participates in the same ownership-state and cleanup rules as `alloc(...)` / `free(...)`

Required tests:

1. HIR unit regressions for every new adversarial shape
2. `fz verify` fixtures that assert both failure class and stable diagnostic/help wording
3. deterministic Fozzy memory scenarios that reproduce branch, loop, defer, and thread/await lifetime hazards
4. recorded traces plus trace verify/replay/CI for at least one adversarial memory suite per active goal

## Priority 7: Turn Runtime Surface Area Into Explicit Compiler-Known Law

### 16. Promote native runtime imports from name tables to contract tables

🟢 Completed slice:
- native runtime contracts are now emitted from one structured table with ownership/capability/linearity/error/trace/blocking metadata
- consuming task/runtime edges are now encoded explicitly instead of inferred from callee names alone
- `fz audit ffi` / `fz audit memory` ship on top of these artifacts

Problem:

- the native import tables are centralized, which is good, but they currently stop at callee/symbol/arity for most enforcement
- v1 needs the compiler/runtime boundary to know ownership, capability, cleanup, tracing, and blocking semantics rather than relying on docs and convention

Required fixes:

1. for every native import, define:
   - name
   - arity
   - argument ownership
   - return ownership
   - capability required
   - linear-resource behavior
   - error behavior
   - trace behavior
   - blocking or nonblocking behavior
2. make the compiler consume this metadata for ownership-transfer, cleanup, capability, unsafe, and native-lowerability checks
3. specifically harden and document:
   - `http.stream_close`
   - `http.websocket_close`
   - `proc.close`
   - `proc.wait`
   - `proc.poll`
   - `task.group_join_all`
   - `task.group_cancel`
   - `fs.atomic_write`
   - `storage.atomic_append`
4. add contract-validation tests that fail if an intrinsic exists in HIR without a full native contract, or if the contract and runtime shim disagree

Required tests:

1. import-table schema/unit tests
2. verifier/driver regressions asserting that consuming calls really consume handles
3. native runtime shim build tests that cover the full declared import surface
4. host-backed scenarios for close/wait/poll/stream/atomic-write behaviors

### 17. Lock in typed-handle and linear-resource law

🟢 Completed slice:
- task handles and task groups now have explicit runtime contract metadata that distinguishes consuming and observational operations
- async-safety artifacts now expose handle/group lifecycle policy instead of leaving those edges implicit

Problem:

- FZY already treats several runtime values as linear or owned, but the handle model is not yet written as one closed, compiler-known matrix
- without that matrix, the language risks drifting into stringly or convention-only resource management

Required fixes:

1. define the shipped handle set and contract for at least:
   - `HttpHandle`
   - `HttpStreamHandle`
   - `WebSocketHandle`
   - `ProcHandle`
   - `TaskHandle`
   - `TaskGroup`
   - `FileHandle`
   - `JsonHandle`
   - `ListHandle`
   - `MapHandle`
2. for each handle, declare whether it is:
   - copy
   - owned
   - linear
   - closable
   - send-safe
   - async-stable
3. make those handle rules visible to HIR, verifier, stdlib docs, runtime shim contracts, and diagnostics
4. reject any runtime/helper path that consumes or aliases a handle in a way the handle matrix does not permit

Required tests:

1. per-handle type/lifetime/cleanup regressions
2. backend parity tests using representative handle operations
3. stdlib contract doc generation or validation from the same metadata source

## Priority 8: Harden Async, Task, And RPC As Core Language Features

### 18. Make async/task safety as strict as ownership safety

🟢 Completed slice:
- async-safety artifacts now publish strict requirements, task-handle lifecycle policy, task-handle misuse findings, and task-group misuse findings
- strict builds now reject `task_result(...)` after terminal consumption, repeated handle terminal operations, and missing/repeated task-group terminal policy with dedicated diagnostics

Problem:

- async is a differentiator for FZY, so the safety story cannot remain partly structural and partly advisory
- the checkout already emits async safety JSON and task-group policy artifacts, but the remaining policies must become enforced compiler law

Required fixes:

1. enforce:
   - `spawn` only accepts owned and send-safe values
   - task groups must join, cancel, or detach
   - timeout/deadline semantics are deterministic
   - cancelled tasks clean resources
   - task handles are linear
   - references cannot cross task boundaries
   - task result cannot be read after cancel/detach unless the language explicitly permits it
2. harden the call-edge model for borrow/mutability/thread crossings beyond same-function checks when feasible
3. define one explicit state machine for task handle lifecycle, task-group lifecycle, and cancel/join/detach/result-read legality
4. make async-safety artifacts report enforced policy rather than inferred or open-ended observations

Required tests:

1. test programs for:
   - spawn leak
   - double join
   - join after cancel
   - detach then result read
   - group without join
   - group cancel with open resources
   - timeout around stream/proc/http
2. deterministic scheduler coverage across `fifo`, `random`, and `coverage_guided`
3. trace verification that async schedule and task-group terminal policy are deterministic and replayable

### 19. Turn RPC from “present” into one of the strongest shipped surfaces

🟢 Completed slice:
- RPC safety artifacts now derive per-method deadline/cancel evidence from compiler-visible call behavior
- strict builds now reject RPC call paths that are not explicitly bounded by `timeout(...)` or `deadline(...)`

Problem:

- RPC declarations, safety JSON, and frame events already exist, but deadline/cancel policy is still emitted as `unspecified`
- v1 production RPC must be explicit about ownership, cancellation, deadlines, traceability, and method stability

Required fixes:

1. harden:
   - RPC declaration parsing
   - RPC ABI lowering
   - request/response ownership
   - deadline policy
   - cancel policy
   - RPC frame trace emission
   - RPC error normalization
   - RPC method-name stability
   - RPC payload type checking
2. in strict and production mode, require:
   - every RPC method has a deadline policy
   - every RPC handler has a cancel-cleanup policy
   - every RPC frame is traceable
   - request-body ownership is explicit
3. generate machine-readable RPC safety artifacts from enforced compiler facts rather than placeholders
4. add parity and replay coverage for RPC behavior across deterministic and host-backed flows

Required tests:

1. parser/HIR/verifier regressions for valid and invalid RPC declarations
2. strict `fz verify` fixtures for deadline/cancel/ownership failures
3. deterministic RPC trace scenarios with ordered frame assertions
4. replay/CI validation for representative RPC request-cancel-deadline paths

## Priority 9: Guarantee Backend And Diagnostic Trustworthiness

### 20. Expand backend parity from “important discipline” to “documented law”

🟢 Completed slice:
- parity coverage already spans many exit-code/runtime categories and now also asserts observable parity for stdout, stderr, and emitted JSON/file artifacts on representative async/task/process flows
- `fz parity` and `fz equivalence` are part of the active validation loop for this hardening work

Problem:

- both LLVM and Cranelift are already supported and parity tooling exists, but the product still needs an explicit supported-feature parity contract
- unmarked parity gaps would make the dual-backend story dangerous

Required fixes:

1. add parity suites that assert same source, same exit code, same stdout/stderr, same verifier result, and same runtime behavior
2. cover at minimum:
   - integer ops
   - float ops
   - strings
   - structs
   - enums
   - matches
   - loops
   - closures
   - arrays
   - JSON handles
   - HTTP handles
   - process handles
   - `defer`
   - unsafe boundaries
3. if any feature is not parity-guaranteed, mark it explicitly in docs, diagnostics, and backend-capability reporting rather than leaving it implicit
4. add backend/link/runtime-shim parity checks for native library builds as well as executables

Required tests:

1. direct `fz parity` fixtures for each supported category
2. host-backed runs where runtime behavior matters
3. at least one real canary app per backend in CI

### 21. Make diagnostics snapshot-stable and elite

Problem:

- the diagnostics schema/catalog story is already strong, but v1 trust requires error wording to stay actionable and stable under regression pressure
- users should be able to depend on diagnostics as part of the language contract, not just the implementation

Required fixes:

1. require every important diagnostic class to answer:
   - what happened
   - where
   - why it is unsafe or invalid
   - what state was expected
   - how to fix it
2. add snapshot tests for compiler/verifier/native-lowerability diagnostics so wording, codes, help text, and catalog keys remain stable unless intentionally changed
3. prioritize ownership, borrow, async/task, RPC, capability, module-resolution, backend-parity, and FFI diagnostics for first-wave snapshot coverage
4. add specific “good over bad” wording guidance for common ownership/resource failures so errors name both the consuming site and the invalid later use

Required tests:

1. text and JSON snapshot tests
2. `fz explain` catalog regressions
3. LSP diagnostics schema regressions for the same catalog classes

## Priority 10: Prove The Product On Real Programs, Audits, And Replay

### 22. Add canary-app hardening gates

Problem:

- language features are most trustworthy when they survive real applications, not only synthetic fixtures
- the repo already contains examples and app surfaces that can serve as production canaries

Required fixes:

1. define and keep green canary apps for:
   - `fzyagent`
   - `superctx`
   - small HTTP server
   - small RPC server
   - process supervisor
   - streaming client
   - SQLite-backed state service
2. require compiler/runtime/backend changes to compile and run these apps before stronger production language is claimed
3. attach at least one deterministic and one host-backed validation path to each canary class that actually exercises its core runtime surface

Required tests:

1. canary-app build matrix across supported backends where applicable
2. smoke tests via `fz run` and built binaries
3. deterministic doctor/test plus trace verify/replay/CI for representative canary flows

### 23. Finish unsafe/FFI audit hardening

Problem:

- unsafe metadata, FFI contract enforcement, and audit artifacts already exist, but v1 still needs a sharper operator-grade audit surface
- the audit story should distinguish structural metadata from independently proven invariants while remaining easy to consume in CI

Required fixes:

1. require unsafe sites to carry:
   - reason
   - owner
   - owner_id
   - scope
   - invariant
   - risk_class
   - proof_ref
2. require FFI contracts to enforce:
   - ownership annotation for pointers
   - len pairing for buffers
   - context anchors for callbacks
   - no extern-C async imports
   - `repr(C)` for ABI-crossing structs
   - declared panic behavior
3. add first-class commands:
   - `fz audit unsafe`
   - `fz audit ffi`
   - `fz audit memory`
4. make these emit both JSON and markdown from the same underlying contract data

Required tests:

1. verifier/driver contract regressions
2. JSON schema tests for audit outputs
3. Fozzy scenarios that fail on missing or invalid proof/ownership/FFI metadata

### 24. Harden trace/replay into a compatibility-checked artifact system

Problem:

- trace/replay is already one of the strongest FZY surfaces, but v1 should formalize the schema and replay contract across compiler/runtime evolution
- today multiple artifacts expose schema versions; the next step is one explicit compatibility matrix

Required fixes:

1. harden trace schema fields for:
   - schema version
   - scheduler
   - seed
   - execution order
   - async schedule
   - RPC frames
   - runtime events
   - causal links
   - capability set
2. add validation rules for:
   - schema validity
   - replay success
   - trace matches run
   - ordered RPC frames
   - deterministic async schedule
   - matching checkpoint count
3. version and publish the compatibility set:
   - FZY language version
   - trace schema version
   - manifest schema version
   - runtime ABI version
   - native import table version
   - diagnostic catalog version
4. ensure produced artifacts include the relevant versions so breakage is explicit rather than inferred

Required tests:

1. trace schema validation tests
2. replay compatibility tests across representative artifact versions when introduced
3. deterministic Fozzy trace lifecycle for every active hardening area

## Second-Wave v1 Lock-In Work

### 25. Freeze the v1 syntax and manifest/profile contract

Required fixes:

1. declare the syntax freeze set for:
   - `fn`
   - `let` / `let mut`
   - `struct`
   - `enum`
   - `match`
   - `trait` / `impl`
   - `async` / `await`
   - `rpc`
   - unsafe metadata
   - `defer`
   - `use core.*`
   - `extern` / `pubext` ABI syntax
2. after freeze, permit additive changes only unless the version policy says otherwise
3. extend profile policy so the shipped story is explicit for `dev`, `verify`, `release`, and a production-facing `strict` contract that defines:
   - checks enabled
   - unsafe policy
   - backend
   - capabilities
   - runtime imports allowed
   - artifact emission
   - optimization level
   - diagnostic strictness

### 26. Promote stdlib contracts, capability law, JSON boundaries, and security helpers into one coherent policy

Required fixes:

1. define per-module contracts for at least:
   - `core.mem`
   - `core.http`
   - `core.proc`
   - `core.fs`
   - `core.thread`
   - `core.time`
   - `core.crypto`
   - `core.json`
   - `core.log`
2. each contract must specify:
   - capability
   - ownership behavior
   - error behavior
   - linear handles
   - cleanup requirement
   - thread-safety
   - async-safety
3. strengthen capability propagation so calls require the capabilities they actually exercise, and capability-token delegation is enforced as compiler-visible authority rather than documentation
4. lock in the JSON rule:
   - JSON at boundaries
   - typed structs/enums inside
5. add strict-mode warnings or failures for unsafe `json.raw` misuse, path traversal hazards, shell/process construction hazards, temp-file/atomic-write hazards, header normalization gaps, raw-injection hazards, and constant-time-compare misuse

### 27. Standardize the error model, performance story, docs-from-implementation flow, and compatibility policy

Required fixes:

1. define and document the v1 error idiom around:
   - `Result<T, Error>`
   - `Status`
   - `ErrorClass`
   - `ExitStatus`
   - `RuntimeError`
2. benchmark real FZY workloads rather than generic micro-optimizations:
   - CLI startup
   - HTTP throughput
   - JSON build/parse
   - process spawn/wait
   - stream reading
   - task-group execution
   - compiler parse/lower/build time
   - native binary size
3. generate docs from implementation-backed sources where possible:
   - AST nodes
   - native runtime table
   - capability table
   - verifier rules
   - diagnostic catalog
   - stdlib contract metadata
4. treat this compatibility set as part of release gating:
   - language version
   - trace schema version
   - manifest schema version
   - runtime ABI version
   - native import-table version
   - diagnostic catalog version

## Tracking Notes

When work is completed, mark the relevant line or section with `✅` and briefly note:

- what changed
- what tests were added
- what commands were run
- whether docs or release gates were updated

Manual-memory enhancement note:

- finish higher-priority compiler/runtime/doc correctness work first before expanding manual-memory functionality
- keep the current production model centered on checked `alloc(...)` / `free(...)` rather than broadening raw memory primitives by default
- before starting any new manual-memory enhancement work beyond the current model, explicitly ask the user for permission for that specific work item
