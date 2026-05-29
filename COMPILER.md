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
