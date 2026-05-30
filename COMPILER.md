# Compiler Hardening Checklist

Production status board. Detailed issue sections below remain the source of truth for full problem statements, required fixes, and required tests.

## Unfinished Work

- `14. Compiler-phase lock-in suite`: add a golden corpus and lock every compiler phase behind direct tests, `fz` surface coverage, deterministic Fozzy runs, trace lifecycle, and host-backed validation.
  Start in `Priority 6 / 14` and wire this through the parser/AST/HIR/FIR/verifier crates plus the driver/native-lowerability fixtures, because the gap here is whole-pipeline lock-in rather than one isolated bug.
- `15. Memory-safety adversarial coverage`: formalize the borrow-region law and expand hostile ownership/lifetime coverage across moves, frees, branches, loops, `defer`, `await`, `spawn`, partial moves, and all linear handles.
  Start in `Priority 6 / 15` and extend the existing `crates/hir` regressions, `fz verify` fixtures, and Fozzy memory scenarios, because the missing work is coverage depth around the already-shipped ownership model.
- `16. Native import contract tables`: replace name/arity-only metadata with full ownership/capability/cleanup/trace/blocking/error contracts and prove contract-table/runtime-shim agreement.
  Start in `Priority 7 / 16` at the centralized native import table and its lowering/runtime-shim consumers, because the risk is contract drift between compiler metadata and the actual host/runtime behavior.
- `17. Typed-handle and linear-resource law`: freeze one compiler-known handle matrix for `Http*`, `Proc*`, `Task*`, `File*`, `Json*`, `List*`, and `Map*` semantics across HIR, verifier, runtime, docs, and diagnostics.
  Start in `Priority 7 / 17` and follow every shipped handle type through HIR classification, verifier enforcement, stdlib docs, and runtime contracts, because this is about closing the remaining semantic matrix, not inventing new handles.
- `18. Async/task safety`: make async/task behavior compiler law with owned/send-safe `spawn`, linear task handles, explicit lifecycle state machines, deterministic timeout/deadline semantics, cancel cleanup, and replayable scheduling.
  Start in `Priority 8 / 18` across the async/task verifier paths, runtime task lifecycle, and scheduler-backed Fozzy coverage, because the remaining holes are terminal-state and cross-boundary enforcement rather than surface syntax.
- `19. RPC hardening`: enforce explicit deadline, cancel, ownership, ABI, payload, trace, and error contracts so RPC is a production-grade verified surface.
  Start in `Priority 8 / 19` at RPC declaration parsing, verifier policy, ABI lowering, and trace emission, because the unfinished work is making the existing RPC surface fully enforced instead of partly reported.
- `20. Backend parity law`: turn LLVM/Cranelift parity into a documented contract for semantics, output, verifier results, runtime behavior, and native-library builds, with explicit non-parity carveouts where needed.
  Start in `Priority 9 / 20` with `fz parity` fixtures, backend capability reporting, and native-library build coverage, because the main job is to convert observed parity into an explicit shipped boundary.
- `21. Diagnostic stability`: snapshot-lock important compiler, verifier, native-lowerability, and LSP diagnostics so wording, help text, JSON, and catalog keys stay stable and actionable.
  Start in `Priority 9 / 21` by enumerating the high-value diagnostic classes in compiler/verifier/native-lowerability/LSP tests, because this is a snapshot and catalog discipline problem more than a semantic one.
- `22. Canary-app gates`: require real applications to stay green through deterministic and host-backed build/run coverage across the main compiler/runtime product shapes.
  Start in `Priority 10 / 22` with the named canary apps and their build/run matrices, because the missing proof is application-level survival across real compiler/runtime flows rather than fixture-level correctness.
- `23. Unsafe/FFI audit hardening`: require complete unsafe metadata, tighten FFI contracts, and ship `fz audit unsafe`, `fz audit ffi`, and `fz audit memory` on one validated contract model.
  Start in `Priority 10 / 23` in the unsafe metadata, verifier contract checks, and audit command outputs, because the remaining gap is operator-grade audit completeness and consistency across JSON/markdown/reporting paths.
- `24. Trace/replay compatibility system`: formalize trace/replay as compatibility-checked artifacts with explicit versioning and deterministic replay guarantees.
  Start in `Priority 10 / 24` where trace schema fields, replay validators, and artifact version metadata are defined, because the work is to turn strong tooling into a published compatibility contract.
- `25. v1 syntax and profile freeze`: freeze the syntax set and make `dev`, `verify`, `release`, and `strict` profiles explicit about checks, unsafe policy, backend, capabilities, imports, artifacts, optimization, and diagnostics.
  Start in `Second-Wave / 25` across parser grammar, manifest/profile handling, driver profile routing, and docs, because this is a freeze-and-policy exercise across already-existing surfaces.
- `26. Stdlib and capability policy`: promote per-module contracts, capability propagation, JSON boundary rules, and security misuse checks into one compiler-visible policy.
  Start in `Second-Wave / 26` with the `core.*` module contracts, verifier capability propagation, and boundary/security checks, because the missing work is policy unification across the shipped stdlib surface.
- `27. Error/perf/docs/compat policy`: standardize the v1 error model, benchmark real workloads, generate docs from implementation-backed metadata, and gate releases on the full compatibility set.
  Start in `Second-Wave / 27` at the error/reporting types, benchmark harnesses, metadata-driven docs sources, and release-gate version matrix, because this is the final contract-polish layer tying the whole product together.

## Completed Work

- ✅ Core compiler-memory hardening is closed: branch/`match` ownership joins, loop fixed-point analysis, inferred-owned and inferred-handle cleanup parity, lifetime/control-flow return validation, alias/provenance tracking, FFI ownership transfer checks, partial-move coverage, and callback/import safety checks are landed and regression-covered.
- ✅ Safe-code false positives are closed: borrowed references are no longer treated as linear, cleanup detection is structural, inferred `alloc(...)` and handle-producing locals are classified correctly, and documented `defer free(...)` cleanup paths count as real cleanup.
- ✅ Unsafe accounting and public wording are now honest: proof-ref validation, dedicated thread-boundary diagnostics, and scoped safety language match the actual enforced boundary.
- ✅ Compiler-memory regression defense is in place: targeted `crates/hir` tests, `fz verify` fixtures, deterministic Fozzy scenarios, and broader release gates now back the shipped claims directly.
- ✅ Stronger production-language release criteria are satisfied for the shipped compiler/verifier boundary, with scope intentionally limited to the enforced safe-language and verifier-backed surface.
- ✅ Product-surface blockers are closed: canonical `fz init`, explicit Cranelift-only `fz build --lib`, native filesystem/runtime closure, process-handle cleanup parity, module-path and constant-lowering fixes, live-server/native poller/runtime-shim fixes, child-process wait/drain fixes, `fz run` parity, and crypto/security runtime delivery.
- ✅ FFI and wrapper blockers are closed: safe ABI facades count correctly, `unsafe { ext_call(...) }` wrappers lower correctly, and borrowed `str -> ptr_borrowed + len` host callback payloads pass real byte views on both backends.
- ✅ Validation evidence is production-shaped: direct `cargo test -q -p hir` and `-p verifier`, targeted driver/CLI tests, strict deterministic Fozzy doctor/test coverage, recorded trace verify/replay/CI, and host-backed runs have all been exercised on this checkout.
- ✅ Unsafe-accounting posture is clean on this checkout, with zero missing contracts, invalid proof refs, or unsafe-context violations; approved Rust `unsafe` remains limited to [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs:74) and [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs:198).

## Priority 0: Fix Real Safety Gaps

### ✅ 0. Historical `hir` buildability regression is closed on this checkout

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
Release criteria are closed for the currently shipped compiler/verifier boundary, and stronger language remains intentionally scoped to the enforced safe-language and verifier-backed surface.

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

The compiler/runtime build boundary is now explicit: `fz` remains the source of truth for ABI lowering, runtime shims, manifests, native artifact semantics, and machine-readable build outputs, while downstream builders are expected to orchestrate around that contract.

## Additional Completed DX / Runtime Hardening

✅ `fz init` is now one canonical shipped bootstrap path with minimal generated layout and real-command guidance.
✅ `proc.spawn*` handles now have an explicit typed cleanup path through `proc.close(handle)`.
✅ Dot-qualified module/type paths and cross-module const/static resolution now behave consistently.
✅ `core.log` import/configuration no longer leaks linear map ownership.
✅ Host-backed `http.read(conn)` now handles normal request parsing and transient readiness stalls correctly.
✅ Native poller wiring is closed: `http.poll_register` lowers natively and `http.poll_next` runs in the host runtime.
✅ Compiler control-flow evidence now includes dedicated `fz verify` / Fozzy coverage for branch joins, loop merges, and returned-reference lifetime mismatches.
✅ Native namespaced constant lowering is fixed, so `inspect` and `build` agree on same-module and dotted constant paths.
✅ Cranelift no longer crashes on statement-position `unsafe { ... }` blocks with nested branches/returns around exported FFI calls.
✅ Production Fozzy trace lifecycle was re-run after the DX/runtime fixes through deterministic, replay, CI, and host-backed paths.

## ✅ Production Blocker: Native Filesystem Surface Is Closed On This Checkout
Native runtime shim helper ordering is fixed, with shim/render regressions and native build/run gating backing the production path.

## ✅ Production Blocker: Spawned Child Processes Can Stall When Output Is Not Drained During Wait
`proc.wait(...)` now drains child pipes while waiting, preserves explicit return values across `defer`, and is backed by targeted regressions plus deterministic and host-backed Fozzy coverage.

## ✅ Production Blocker: `fz run` Native Execution Diverges From The Built Binary For Child-Process Orchestration
Direct binary execution and `fz run` now agree on child-process-heavy orchestration paths, with dedicated driver regression coverage and deterministic plus host-backed validation.

## ✅ Production Blocker: No Cryptographic Or Secure-Random Runtime Surface
Native `core.crypto` and `core.security` runtime surface is shipped with secure random, hashing, HMAC, constant-time equality, base64 helpers, and regression-backed deterministic trace coverage.

## ✅ Production DX Blocker: Safe FFI Wrapper Layers Did Not Count As Documented ABI Facades
Documented `ext unsafe c fn` imports and their immediate safe facades now satisfy caller-edge ownership verification, with HIR, `fz verify`, and Fozzy coverage for the shipped wrapper pattern.

## ✅ Production Blocker: `unsafe { ext_call(...) }` Expression Wrappers Collapsed To `void` On Strict Verify
`unsafe { ... }` expression wrappers now type-check and lower correctly under strict verify, including borrowed pointer-length wrapper forms, with HIR and driver regressions for direct-return and let-bound cases.

## ✅ Production Blocker: Borrowed `str -> ptr_borrowed + len` Host Callback Payloads Crashed At Runtime
Borrowed `str -> ptr_borrowed + len` host callback payloads now lower to real borrowed byte views on both backends, with shared-library regression coverage and end-to-end host validation.

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

- 🟢 strict production profile, native runtime contract artifacts, and first-class `fz audit ffi` / `fz audit memory` commands are already shipped
- 🟢 RPC deadline enforcement, async/task lifecycle reporting, and dedicated strict diagnostics are already live on the current surface
- 🟢 backend parity coverage already includes observable exit code, stdout, stderr, and emitted artifact checks for representative runtime flows

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
Core ownership/provenance regressions, borrow-region enforcement, partial-move coverage, diagnostic snapshots, process-builder handle tracking, and deterministic Fozzy memory scenarios are already in place; the remaining work is extending that closed core to the remaining adversarial shapes and handle classes.
- `ProcessArgv` / `ProcessEnv` now follow compiler-owned linear-handle law too: unused builders leak, `proc.spawn_cmd` / `proc.run_cmd` / `proc.spawnl` / `proc.runl` consume them, helper-mediated transfer is regression-covered, and the shipped Fozzy corpus now exercises that exact builder-ownership surface
- implicit borrow admission is now compiler law instead of an accidental partial behavior: reference-typed calls and explicit reference locals accept borrowable owned expressions, generic reference calls resolve without fake signature fallout, and borrow-region failures now surface as ownership diagnostics instead of bogus `call signature mismatch` or `linear value ... was not consumed/freed` noise
- the borrow-region suite is now end-to-end regression-covered across HIR, `fz verify`, and deterministic Fozzy scenarios for: explicit borrowed locals, borrow-then-free, borrow-then-move, mutable/shared alias conflicts, and returned-reference lifetime mismatch without downstream diagnostic pollution
- overlapping borrow exclusivity is now enforced in local borrow regions too: creating a mutable borrow while a shared borrow is still live, creating a shared borrow while a mutable borrow is still live, and creating transient call-site borrows that overlap a live mutable borrow now all fail as first-class ownership violations
- mutable-borrow exclusivity now rejects direct owner access during the live borrow too: reading the owner directly or passing it through plain owner-based calls while a mutable alias is still live now fails with dedicated guidance, while owner access after the borrow's last accepted use remains valid and regression-covered
- `memory-report.json` is now aligned with compiler law for process builder handles too, so `ProcessArgv` / `ProcessEnv` appear in emitted linear-resource evidence instead of being enforced by HIR but omitted from the production safety artifact surface
- async borrow-edge analysis is now verify-surface law too: mutable borrowed call edges across `await`, borrowed-return propagation across async suspension, and generic/trait-heavy borrowed async call edges now emit dedicated diagnostics with action-oriented fixes instead of collapsing into generic ownership noise
- borrow-across-`spawn` is now compiler law for spawned closures too: `spawn`, `spawn_ctx`, `task.group_spawn`, and `task.parallel_map` reject closures that capture shared or mutable borrowed references across task boundaries, while owned captures remain legal and regression-covered; this also closed a real compiler gap where `task.*` calls were not consistently treated as `thread` capability use
- owned-return transfer accounting is now branch- and wrapper-aware instead of only happy-path aware: branch relays, `if`-expression relays, and runtime-handle wrapper returns now count as intentional ownership handoff in compiler summaries and verifier lifecycle accounting, and the lifecycle diagnostic now distinguishes alloc/free imbalance from paths that explicitly return owned values
- expression-valued ownership transfer is now path-sensitive at terminal returns too: grouped moves, `let q = if ... { p } else { ... }`, and `let q = match ...` all participate in source-move tracking, `return if ...` / `return match ...` now reject one-branch-only ownership transfer as real leaks, and the linear-resource pass only treats a returned owner as consumed when every return path hands it off
- control-flow leak and owned-parameter transfer coverage now reaches the verify/Fozzy surface too: early-return leaks, loop leaks, grouped owned returns, and helper-owned-parameter cleanup are all snapshot-covered in `fz verify` and locked into deterministic Fozzy scenarios instead of living only as HIR-local regressions
- runtime-handle ownership law now has verify/Fozzy lock-in across the real shipped handle families too: task-handle binary joins, websocket close wrappers, process-handle close wrappers, HTTP connection response writers, non-consuming stream helpers, and loop-local consumed HTTP handles are all regression-covered at the compiler surface instead of only being trusted through HIR-only tests

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
Native runtime contracts already come from one structured table with ownership/capability/linearity/error/trace/blocking metadata, and consuming task/runtime edges plus `fz audit ffi` / `fz audit memory` already ride on that surface.

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
Task handles and task groups already have explicit consuming-vs-observational contract metadata, and async-safety artifacts already expose handle/group lifecycle policy on the current surface.

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
Async-safety artifacts already publish strict requirements and lifecycle findings, and strict builds already reject post-terminal `task_result(...)`, repeated handle terminal operations, and missing/repeated task-group terminal policy.

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
RPC safety artifacts already derive per-method deadline/cancel evidence from compiler-visible behavior, and strict builds already reject call paths that are not explicitly bounded by `timeout(...)` or `deadline(...)`.

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
Parity coverage already spans key exit-code/runtime categories, including observable stdout/stderr/emitted-artifact checks on representative async/task/process flows, and `fz parity` / `fz equivalence` are already part of the active validation loop.

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
