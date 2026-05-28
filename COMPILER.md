# Compiler Hardening Checklist

This document tracks the current compiler-side memory-safety hardening work for production readiness.

It is intentionally focused on:

- concrete correctness gaps
- over-claimed or under-specified guarantees
- missing analysis coverage
- regression tests and release gates needed to close the gaps

Status convention:

- `✅` means completed and verified work
- pending work is written as plain bullets or numbered items only

## Current Sit Rep

The current memory-safety story is promising, but not yet complete enough to claim that the compiler area is bug free or that all shipped memory-safety guarantees are fully enforced in all relevant control-flow shapes.

The biggest concerns today are:

1. the current `hir` memory-safety path is not buildable on this checkout
2. ownership/control-flow unsoundness around conditional and `match` paths
3. false-positive rejection of valid borrowed-reference code as if it were a linear resource
4. analysis passes that only cover top-level or simplified shapes rather than full program structure
5. async borrow checking is still statement-shaped and can miss some same-statement suspension misuse
6. unsafe-contract accounting that currently acts more like metadata presence than proven safety evidence
7. inferred pointer-return ownership can bypass cleanup enforcement entirely
8. some FFI ownership/alias checks are still identifier-shaped heuristics
9. public ownership-transfer wording is stronger than the current call-site ownership model
10. the current Fozzy memory release gate is too narrow to justify stronger compiler memory-safety claims

## Completed Review Evidence

✅ Completed a source-level review of the compiler memory-safety surface across `crates/hir`, `crates/verifier`, docs, and verifier integration.

✅ Ran the prescribed deterministic Fozzy memory flow, including doctor, strict test, recorded trace, trace verification, replay, and CI, against `tests/memory_graph_diff_top.pass.fozzy.json`.

✅ Confirmed the current memory scenario is deterministic and replay/CI-clean on the path it covers.

✅ Reproduced the borrowed-reference false positive where a local `&'a` binding was incorrectly treated as a linear resource requiring `defer close(...)`.

✅ Reproduced the documented `defer free(...)` contradiction by showing that `let p = alloc(...); defer free(p)` still triggered leak and unreleased-linear diagnostics.

✅ Reproduced an active `hir` reference-lifetime compile failure where `crates/hir/src/lib.rs` compared `Option<Option<String>>` against `Option<String>`.

✅ Ran targeted unsafe-FFI and trace-backed checks beyond the basic memory scenario to widen evidence coverage around pointer misuse, callback lifecycle, and host replay.

✅ Reproduced an inferred-owned-pointer escape hatch where `let p = unsafe { acquire_owned() }` with no cleanup produced warnings only and `errors: 0`.

✅ Reproduced the helper-call ownership-transfer mismatch where a callee that `free(...)`d its parameter was still treated as consuming a non-owned value while the caller leaked the original owner.

✅ Reproduced a control-flow asymmetry where direct cleanup inside `if` updated ownership state correctly but the equivalent `match`-arm cleanup did not.

✅ Reproduced an inferred-`alloc(...)` false positive where `let p = alloc(n); free(p);` was misdiagnosed as freeing a non-linear value because enforcement still depended on explicit type spelling.

✅ Ran the current compiler, verifier, and unsafe-accounting evidence flow with direct crate tests, workspace unsafe audit, and Rust unsafe inventory.

✅ Confirmed the current checkout builds the compiler safety crates directly, with both `hir` and `verifier` test suites passing and the earlier return-lifetime compile failure no longer reproducing here.

✅ Confirmed the current unsafe-accounting posture is clean on this checkout, with zero missing contracts, invalid proof refs, or unsafe-context violations and the Rust unsafe inventory still within the approved budget of `2`.

✅ Confirmed the approved Rust `unsafe` footprint remains limited to [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs:74) and [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs:198).

✅ Confirmed the current host-backed memory scenario also passes on this checkout.

✅ Re-ran the unsafe and FFI scenarios individually to remove ambiguity from multi-target invocation and confirm each target passes on its own.

✅ Added a second deterministic memory evidence pass with a fresh seed and an explicit recorded trace lifecycle.

✅ Fixed and regression-covered the live cleanup-logic gaps so borrowed refs stop being treated as linear, inferred owned locals are tracked correctly, deferred cleanup counts as real release, `match` cleanup updates ownership state, and inferred unsafe pointer returns no longer bypass leak analysis.

✅ Added focused `crates/hir` regressions for borrowed-reference linear-resource classification, inferred-allocation release handling, deferred cleanup, inferred unsafe pointer-return ownership, and `match`-arm cleanup state.

✅ Re-ran the production Fozzy flow for the compiler safety surface, including validate, deterministic strict tests, recorded trace, trace verify, replay, CI, and host-backed execution.

✅ Tightened same-statement async borrow checking so shared borrows used after `await` inside nested `if`, `match`, and loop bodies are now rejected and regression-covered.

✅ Re-ran a fresh post-fix HIR Fozzy trace lifecycle to validate the async-borrow hardening under deterministic, replayable, and host-backed coverage.

✅ Fixed helper-boundary pointer/ref provenance attribution by switching to callee return-provenance summaries so first-arg and second-arg passthrough helpers no longer collapse to the same caller root.

✅ Re-ran a fresh provenance-focused HIR Fozzy trace lifecycle to validate the helper-boundary provenance fix under deterministic, replayable evidence.

✅ Expanded aggregate alias/provenance coverage so tuple, struct, and variant destructuring preserve roots correctly and stale roots are cleared on reassignment.

✅ Re-ran a fresh aggregate-provenance HIR Fozzy trace lifecycle and refreshed the recorded memory trace verification, replay, and CI evidence.

✅ Confirmed additional runtime/compiler evidence by passing host-backed `c_ffi_matrix` coverage and sampled direct-memory backend consistency tests.

✅ Reproduced an inferred-handle cleanup escape hatch where `let listener = http.bind(); return 0` verified cleanly while the explicitly typed `HttpHandle` form correctly failed.

✅ Reproduced a plain-pointer and `_borrowed` C-import escape hatch where pointer-shaped safe imports still passed with warnings instead of requiring `ext unsafe c fn`.

✅ Reproduced missing callback-context enforcement where a callback-bearing unsafe C import passed without the documented adjacent `*_ctx` or `*_context` lifetime anchor.

## Priority 0: Fix Real Safety Gaps

### 0. Current `hir` buildability regression blocks all release confidence

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

### 1. Conditional ownership merge can erase maybe-freed state

Problem:

- Ownership state after `if` is merged by intersection in `crates/hir/src/lib.rs`.
- If a value is freed or moved on one branch but not the other, the post-merge state can forget that the value is only conditionally live.
- That can allow post-branch reuse of a maybe-freed or maybe-moved value without a precise diagnostic.

Why this matters:

- This is a real safe-code soundness risk, not just a conservative false positive.
- Production claims about ownership enforcement are too strong if this remains.

Required fixes:

1. Replace simple set intersection merge with path-sensitive ownership state merging.
2. Represent ownership state with at least these categories:
   - definitely owned
   - definitely moved/freed
   - maybe moved/freed
   - unreachable
3. Emit diagnostics for post-merge uses of maybe-freed or maybe-moved values.
4. Ensure returns, early returns, and diverging paths participate correctly in the merge model.
5. Revisit `break`/`continue` interactions so loop exits do not silently preserve invalid ownership state.

Required tests:

1. `if flag { free(p); } use(p)` must fail.
2. `if flag { let q = p; } use(p)` must fail when the move is path-reachable.
3. `if/else` where both sides consume the value exactly once must pass.
4. `if/else` where one side returns and the other frees must be analyzed correctly.
5. Nested `if` ownership merges must not regress.

### ✅ 2. `match` ownership effects are modeled for direct cleanup paths and regression-covered

Update:

Direct `free(...)` and `close(...)` inside `match` arms now participate in ownership-state updates, produce correct post-`match` divergent/already-consumed diagnostics, and are locked in by a targeted HIR regression.

Problem:

- `Stmt::Match` currently does not feed arm effects into ownership state in `analyze_ownership_block`.
- Frees, moves, and resource transfers inside match arms are not incorporated into post-match ownership.
- More specifically, `Stmt::Match` currently routes each `arm.value` through `analyze_expr_value_ownership(...)`, but that helper only models `UnsafeBlock`, `If`, and nested `Match` expression shapes.
- A direct arm expression such as `free(p)`, `close(p)`, or an ownership-moving helper call can therefore evade the ownership-state transition entirely even though the surrounding `match` merge still runs.
- current reproduction confirms the asymmetry directly:
  - `if flag { free(p); } free(p);` is diagnosed
  - equivalent `match`-arm cleanup is not

Why this matters:

- `match` is a first-class control-flow form.
- Skipping its state effects creates a direct blind spot for use-after-free, double-consume, and leak detection.

Required fixes:

1. Analyze every match arm as a separate control-flow branch.
2. Merge arm ownership state using the same path-sensitive rules used for `if`.
3. Include guard expressions in ownership/use analysis where relevant.
4. Treat wildcard arms, exhaustive arms, and statically unreachable arms consistently.
5. Make sure arm-local moves do not disappear after the match expression.

Required tests:

1. `match x { 1 => free(p), _ => ... } use(p)` must fail.
2. `match x { 1 => let q = p, _ => ... } use(p)` must fail when the move reaches the join.
3. `match` arms that all consume exactly once must pass.
4. Nested `match` and `if` combinations must preserve ownership accuracy.
5. Guarded arms using borrowed or moved values must be validated.

### 3. Loop ownership semantics need a real fixed-point model

Problem:

- `while`, `for`, and `loop` bodies are recursively analyzed, but not with a principled loop-state fixed-point.
- Repeated iteration effects, conditional loop exits, and partial-consumption paths can be modeled imprecisely.

Why this matters:

- Loops are a common shape for resource cleanup and ownership transfer.
- Weak loop modeling can produce both missed bugs and noisy false positives.

Required fixes:

1. Define loop entry and loop back-edge ownership states explicitly.
2. Compute a stable merge/fixed-point for loop-carried ownership.
3. Track `break` exits separately from fallthrough/back-edge continuation.
4. Model `continue` as a path back to the loop header.
5. Ensure values consumed on one iteration are not silently treated as live on later iterations.

Required tests:

1. consume-inside-loop then reuse on a later iteration must fail.
2. break-after-free must not leak invalid live state to the post-loop block.
3. continue-after-move must not preserve the moved binding as definitely owned.
4. loops with cleanup on all exits must pass.

### ✅ 3.5. Inferred pointer-return ownership now enters the cleanup model for inferred locals

Update:

Inferred locals receiving pointer returns now seed ownership tracking from typed expression results instead of explicit annotations only, with targeted HIR coverage for missing-cleanup extern pointer returns.

Problem:

- ownership and semantic-hint collection currently recognize owned linear resources mainly from:
  - explicit pointer-typed locals
  - `alloc(...)`
- inferred locals receiving pointer returns from unsafe externs or other pointer-returning callees can avoid both leak tracking and `defer`-release checks entirely
- this was directly reproduced with:
  - `ext unsafe c fn acquire_owned() -> *u8;`
  - `let p = unsafe { acquire_owned() }`
  - no cleanup
  - `fz check` reported warnings only and `errors: 0`

Why this matters:

- this is a real enforcement hole, not just imprecise wording
- it undermines the production claim that missing cleanup is rejected whenever the compiler is supposed to be tracking ownership
- it is especially risky at FFI boundaries where pointer-returning imports are a natural ownership source

Required fixes:

1. seed ownership/linear-resource state from typed pointer-returning expressions, not only explicit local annotations or `alloc(...)`
2. ensure inferred pointer locals participate in:
   - ownership leak detection
   - provenance tracking
   - linear-resource/defer release checks
3. distinguish borrowed pointer returns from owned pointer returns where the signature or contract can express that difference
4. add an explicit audit of pointer-returning call sites to verify they cannot silently evade cleanup enforcement

Required tests:

1. inferred local from unsafe extern pointer return with no cleanup must fail
2. inferred local from unsafe extern pointer return with `defer free(...)` must pass when otherwise valid
3. explicit and inferred pointer locals must produce equivalent cleanup diagnostics
4. pointer-returning helper wrappers must not erase ownership tracking

## Priority 1: Fix Incorrect Rejections Of Safe Code

### ✅ 4. Borrowed references are no longer classified as linear resources

Update:

Borrowed references no longer flow into `linear_resources` because semantic-hint collection now distinguishes borrowed values from owned cleanup obligations, and the fix is regression-covered in HIR.

Problem:

- `Type::Ref` is considered pointer-like by `Type::is_pointer_like()`.
- semantic hint collection adds pointer-like locals to `linear_resources`
- verifier then demands `defer close(...)` for those names

Observed symptom:

- valid borrowed-reference locals can fail verification with `linear resource <name> is not released via defer`

Why this matters:

- This blocks valid safe programs.
- It damages trust in the verifier because correct code is rejected for the wrong reason.

Required fixes:

1. Separate:
   - borrowed references
   - raw pointers
   - slices
   - actual owned linear resources
2. Stop using `is_pointer_like()` as a proxy for “must be explicitly released.”
3. Make linear-resource detection semantic, not syntactic.
4. Audit every caller of `is_pointer_like()` for ownership-vs-borrow confusion.
5. Revisit whether slices should ever participate in linear cleanup tracking.

Required tests:

1. local `&'a T` bindings must not require `close`
2. borrowed params must not appear in `linear_resources`
3. slice bindings must not trigger `defer close(...)` unless intentionally modeled as owned resources
4. true linear handles should still require exact release

### ✅ 5. `free`/`close` classification now uses structural traversal for cleanup accounting

Update:

Cleanup accounting now traverses the AST structurally across control flow and nested expressions so direct and deferred `free(...)`/`close(...)` share one consistent release-recognition path.

Problem:

- linear-type and ownership checks use narrow syntactic patterns
- top-level-only scanning misses nested calls and richer cleanup shapes
- `close` is used as both a generic consume API and a specific handle cleanup concept

Why this matters:

- Can misdiagnose correct programs.
- Can miss nested cleanup failures.

Required fixes:

1. Unify cleanup recognition across ownership analysis, linear analysis, and semantic hint collection.
2. Detect cleanup calls structurally throughout the full AST, not just top-level statements.
3. Distinguish generic consume operations from type-specific close semantics where needed.
4. Ensure deferred cleanup and direct cleanup share the same release accounting.

Required tests:

1. nested cleanup inside `if`, `match`, and loop bodies should count
2. cleanup wrapped in `unsafe {}` should count
3. cleanup inside deferred expressions should count consistently

### ✅ 5.3. Inferred `alloc(...)` locals are no longer misclassified as non-linear at release points

Update:

Inferred `alloc(...)` locals now enter linear-resource accounting through typed expression results rather than explicit annotations only, eliminating the old false-positive non-linear release diagnostic and locking it in with HIR regression coverage.

Problem:

- the linear-resource pass only seeds `linear_owned` from `Stmt::Let { ty: Some(ty), ... }` when the explicit type is already linear-like
- an inferred local created by `let p = alloc(...)` is tracked by ownership/provenance as allocation-shaped, but the linear pass can still treat it as “non-linear” when `free(p)` appears later
- this was directly reproduced with:
  - `let p = alloc(n);`
  - `free(p);`
- and produced `function 'main' frees non-linear value 'p' as linear resource`

Why this matters:

- this is a concrete false positive in one of the canonical safe manual memory-management paths
- it makes diagnostics harder to trust because the compiler is simultaneously recognizing allocation behavior and misclassifying the same local at release time
- it also obscures real ownership issues behind a misleading error message

Required fixes:

1. seed linear-resource classification from inferred ownership-producing expressions such as `alloc(...)`, not only explicit local annotations
2. keep linear/resource classification aligned with ownership/provenance seeding so the same local cannot be “owned” in one pass and “non-linear” in another
3. make release diagnostics prefer the true semantic failure, if any, rather than an annotation-shaped fallback message
4. audit other inferred owned-resource introductions for the same explicit-type dependency

Required tests:

1. `let p = alloc(...); free(p);` must not report “frees non-linear value” when the only issue is an unrelated type/backend constraint
2. inferred and explicitly typed allocation locals must produce equivalent linear-resource diagnostics
3. inferred allocation locals cleaned up with `defer free(...)` must behave the same as explicitly typed ones

### 5.35. Inferred handle-producing locals can bypass cleanup enforcement entirely

Problem:

- the current release / linear-resource path still depends heavily on explicit local type spelling
- this is not limited to `alloc(...)`-shaped locals
- a directly reproduced `use core.http; let listener = http.bind(); return 0` probe verified cleanly, while the explicitly typed `let listener: HttpHandle = http.bind(); return 0` form correctly failed with leak and linear-consumption diagnostics

Why this matters:

- this is a stronger failure mode than the existing inferred-`alloc(...)` false positive because it becomes a false negative
- equivalent programs should not switch from release-blocking leak detection to silent acceptance based only on whether the programmer spelled the handle type explicitly
- public cleanup guarantees are overstated while inferred handle-producing expressions can evade the same enforcement that catches explicitly typed handles

Required fixes:

1. seed linear/resource ownership from typed expression results, not only explicit `let` annotations
2. make handle-producing runtime calls such as `http.bind()` participate in the same cleanup model as explicitly typed handle locals
3. keep ownership, linear-resource, and semantic-hint passes aligned so inferred owned handles cannot disappear from one pass but remain visible to another
4. audit other inferred handle/resource introductions for the same annotation-sensitive false-negative path

Required tests:

1. inferred and explicitly typed `HttpHandle` locals with no cleanup must fail identically
2. inferred and explicitly typed handle locals cleaned up with `close(...)` or `defer close(...)` must pass identically
3. equivalent inferred/typed resource programs across other handle-returning stdlib calls must not diverge in cleanup diagnostics

### ✅ 5.1. Semantic-hint collection is now structural rather than statement-shape dependent

Update:

Semantic-hint collection now walks the AST structurally instead of relying on statement-shape special cases, so cleanup nested inside `if`, `match`, loops, and `unsafe` feeds the same release accounting.

Problem:

- semantic-hint collection currently recurses through `if` and `while`, but still skips several other control-flow shapes for `linear_resources` / `deferred_resources` discovery
- in particular, `for`, `for in`, `loop`, and `match` arm values are not traversed the same way as other bodies
- this makes verifier-visible cleanup/resource behavior depend on surface syntax rather than the underlying ownership semantics

Why this matters:

- the verifier currently relies on semantic hints when deciding whether a resource was locally released via `defer`
- shape-dependent traversal can therefore create both false positives and false negatives depending on whether equivalent cleanup appears under `if` versus `for` / `loop` / `match`
- this weakens confidence that the compiler is enforcing one coherent cleanup model

Required fixes:

1. make semantic-hint traversal structurally recursive across all statement/control-flow forms
2. collect `linear_resources` and `deferred_resources` from `for`, `for in`, `loop`, and `match` arm bodies/values the same way as `if` and `while`
3. stop relying on statement-shape special cases when the underlying concern is ownership/cleanup semantics
4. align semantic-hint traversal with the ownership and provenance walkers so the same program shape cannot disagree across passes

Required tests:

1. `defer`-based cleanup under `for` must count identically to the same cleanup at top level
2. `defer`-based cleanup under `loop` / `for in` must count identically to the same cleanup under `while`
3. `match` arms containing cleanup expressions must feed the same semantic-hint state as equivalent `if` branches
4. equivalent programs expressed with different control-flow forms must not diverge in linear-resource diagnostics

### ✅ 5.25. The documented `defer free(...)` cleanup path now counts as real cleanup

Update:

Deferred `free(...)` and `close(...)` now count as real cleanup in ownership and verifier release accounting, matching the documented model and backed by targeted HIR regression plus refreshed CLI checks.

Problem:

- the public docs recommend `defer free(ptr)` / `defer close(handle)` as the canonical safe manual cleanup pattern
- the ownership and provenance analyzers still ignore `Stmt::Defer(...)` when deciding whether a resource was actually consumed
- as a result, the compiler can diagnose a leak even when code follows the documented cleanup pattern exactly

Observed symptom:

- a minimal probe of:
  - `let p = alloc(...)`
  - `defer free(p)`
  - `return 0`
- still produced a verifier leak diagnostic for `p`

Why this matters:

- this is not just a wording mismatch; it is a direct implementation contradiction of the shipped cleanup guidance
- it makes one of the core advertised safe manual resource-management patterns unreliable
- it also weakens trust in any release claim that says cleanup behavior is compiler-tracked under production memory safety

Required fixes:

1. make deferred cleanup participate in the same ownership-consume accounting as direct `free(...)` / `close(...)`
2. make deferred cleanup participate in provenance invalidation so deferred consumption and direct consumption stay semantically aligned
3. ensure cleanup recognition is structural across nested `defer`, `unsafe`, and control-flow shapes rather than statement-form special-casing
4. reconcile verifier diagnostics so documented canonical cleanup patterns do not produce leak errors

Required tests:

1. `let p = alloc(...); defer free(p); return 0` must pass when otherwise valid
2. `defer close(handle)` must count as real cleanup for owned linear handles
3. deferred cleanup inside `unsafe { ... }` must count identically to direct cleanup
4. direct cleanup and deferred cleanup must produce identical post-consume ownership/provenance behavior

## Priority 2: Deepen The Analysis Model

### 6. Lifetime analysis is too shallow for production-strength claims

Problem:

- current lifetime validation focuses on explicit lifetime presence and top-level `return ident`
- it does not yet model full region flow for nested expressions and control-flow joins

Why this matters:

- The docs correctly avoid Rust-equivalent theorem claims.
- But even the narrower “verifier-enforced ownership/borrow constraints” claim needs careful scoping if analysis remains shallow.

Required fixes:

1. Expand lifetime validation beyond top-level `Stmt::Return(Some(Expr::Ident(...)))`.
2. Analyze return expressions through branches, matches, helper expressions, and temporaries.
3. Model local reference provenance and escaping more explicitly.
4. Validate borrow-return relationships through assignments and aliases, not only declaration sites.
5. Revisit async suspension rules once path-sensitive ownership/lifetime state exists.

Required tests:

1. branch-returned references with mismatched lifetime regions must fail
2. references returned via temporary aliases must be validated
3. nested match/if return expressions involving refs must be covered
4. async borrowed-reference misuse across suspension must remain rejected

### ✅ 6.5. Borrow-across-`await` detection is now expression- and control-flow-aware for same-statement shared-borrow misuse

Update:

Borrow-after-`await` analysis now carries post-suspension state through nested expressions and control flow so same-statement shared-borrow misuse in `if`, `match`, and loop bodies is rejected and regression-covered.

Problem:

- the current `ref_used_after_await(...)` logic flips into post-`await` mode only after a whole statement has been scanned
- mutable references get an extra same-statement check, but shared references do not
- this can miss cases where a borrowed shared reference is used after an `await` within the same compound statement body

Why this matters:

- async suspension is one of the explicit safety boundaries the docs rely on today
- same-statement control-flow shapes such as nested `if`, `match`, or loop bodies are realistic code and should not depend on statement-boundary quirks for correctness
- leaving this as-is makes the async borrow guarantee narrower than it appears

Required fixes:

1. make the borrow-after-`await` analysis expression- and control-flow-aware rather than statement-boundary-aware
2. apply same-statement post-suspension checks to shared references, not only mutable ones
3. validate nested `await` plus later-use ordering inside `if`, `match`, loop, and closure bodies
4. align the async borrow checker with the broader path-sensitive ownership/lifetime model once that lands

Required tests:

1. shared borrowed reference used after `await` in the same `if` body must fail
2. shared borrowed reference used after `await` in the same `match` arm must fail
3. shared borrowed reference used after `await` in loop bodies must fail
4. valid pre-`await` shared-reference use in the same statement must still pass

### ✅ 7. Alias/provenance analysis now covers core destructuring and stale-root overwrite paths

Update:

Alias/provenance analysis now propagates roots through core destructuring and clears stale roots on reassignment, bringing aggregate locals and helper-boundary reasoning into closer semantic alignment.

Problem:

- provenance roots are tracked for a limited set of expression forms
- pattern destructuring, richer assignments, and aggregate paths are under-covered

Why this matters:

- alias/provenance is one of the key backstops against use-after-free and double-free.
- gaps here can become latent soundness issues.

Required fixes:

1. extend root propagation through destructuring and aggregate extraction
2. model alias creation through more expression forms
3. ensure reassignment invalidates stale alias state correctly
4. validate interop ownership transfer with stronger provenance semantics

Required tests:

1. destructuring aliases from owned aggregates
2. field-based aliasing of owned values
3. reassignment after aliasing and cleanup
4. extern unsafe ownership-transfer calls followed by local reuse

### ✅ 7.1. Interprocedural pointer/ref-return provenance is no longer misattributed to the first matching argument

Update:

Pointer/ref-returning helper calls now use callee return-provenance summaries instead of first-argument heuristics, distinguishing returned-arg roots, fresh roots, and unknown provenance with focused HIR regression coverage.

Problem:

- `infer_expr_provenance_root(...)` in `crates/hir/src/lib.rs` currently assigns the provenance of a pointer/ref-returning call to the first argument whose provenance can be inferred
- this is not equivalent to tracking which parameter the callee actually returns
- as a result, helper calls that return their second pointer argument can be analyzed as if they returned the first, and vice versa
- direct local reproduction against `parser` + `hir` confirmed that both:
  - `fn passthrough(a: *mut u8, b: *mut u8) -> *mut u8 { return a }`
  - `fn passthrough(a: *mut u8, b: *mut u8) -> *mut u8 { return b }`
  produced the same downstream provenance result in the caller

Why this matters:

- this is a real compiler-analysis correctness issue in one of the core use-after-free / double-free backstops
- it can produce false positives, but more importantly it can also hide real aliasing/provenance defects behind the wrong root attribution
- any production claim about provenance-aware helper-boundary safety is too strong while return-root attribution is still “first matching arg” instead of semantically tied to the callee

Required fixes:

1. replace first-argument provenance inference for pointer/ref-returning calls with a callee-summary model that records which parameter, if any, the return value is derived from
2. distinguish at least:
   - returns arg 0 provenance
   - returns arg N provenance
   - returns fresh provenance
   - return provenance unknown / rejected
3. make provenance inference conservative when helper summaries are ambiguous rather than silently binding to the first matching argument
4. keep reference-lifetime and pointer-provenance summaries aligned so helper-boundary borrow/alias reasoning does not diverge across passes

Required tests:

1. helper returning first pointer arg and helper returning second pointer arg must produce different caller provenance when appropriate
2. `free(a); free(ret_from_a);` must fail while `free(a); free(ret_from_b);` must not be diagnosed as the same root
3. pointer/ref-returning helper wrappers must not collapse distinct provenance sources onto the first argument
4. ambiguous helper return provenance must degrade to a limitation-accurate diagnostic or conservative rejection rather than a silent guess

### 7.25. FFI alias and ownership-transfer checks are still identifier-shaped

Problem:

- several FFI-specific ownership and alias checks currently trigger only when arguments are plain identifier expressions
- the `_owned` transfer path removes caller ownership only for `Expr::Ident(...)`
- mutable/shared reference alias checks likewise focus on repeated plain identifier arguments rather than richer equivalent expressions

Why this matters:

- this leaves real gaps at one of the highest-risk boundaries in the system
- grouped expressions, projections, aliases, and helper-shaped call sites can evade checks that appear stronger at first glance
- the current behavior makes FFI enforcement depend too heavily on surface syntax

Verified progress on this checkout:

Verified progress on this checkout:

✅ Grouped-expression `_owned` FFI arguments and grouped mutable-reference aliases now collapse to the same semantic provenance/alias roots as their ungrouped forms, with targeted HIR regressions and refreshed deterministic, trace-backed, replay, CI, and host-backed Fozzy evidence.

Required fixes:

1. generalize FFI ownership-transfer analysis beyond plain identifier arguments
2. detect alias equivalence through grouped expressions, field projections, and other supported aliasing forms
3. ensure `_owned`, `_borrowed`, and related contract checks operate on semantic provenance, not only syntactic names
4. keep the diagnostics explicit when the compiler still cannot prove an ownership transfer safely

Required tests:

1. `_owned` extern call with grouped or projected owned argument must preserve the intended ownership diagnostic behavior
2. mutable/shared aliasing through equivalent non-identifier expressions must be rejected
3. FFI helper wrappers must not erase alias and transfer checks

### ✅ 7.3. Plain pointer-shaped `ext c fn` imports now require `ext unsafe c fn`

Verified closure:

Any pointer-shaped `ext c fn` import now requires `ext unsafe c fn` regardless of `_owned`-style naming, with explicit verifier diagnostics, dedicated verifier tests, and deterministic trace-backed plus host-backed Fozzy validation.

### ✅ 7.35. Callback lifetime-anchor requirements are now enforced structurally

Verified closure:

Callback-bearing FFI imports now structurally require an adjacent `*_ctx` or `*_context` anchor, with explicit verifier failures for missing anchors, pass coverage for valid anchors, and shared trace-backed Fozzy validation.

### ✅ 7.5. Ownership transfer on argument passing now follows an explicit consume-summary rule

Verified closure:

Ownership transfer on argument passing now follows an explicit consume-summary rule for local helpers and unsafe extern `_owned` parameters, the production memory model has been narrowed to match that behavior, and the change is covered by crate tests plus deterministic trace-backed and host-backed Fozzy validation.

### 7.75. Verifier release rules currently require local `defer` even where transfer-based cleanup should be legal

Problem:

- verifier-side linear-resource enforcement currently treats local `defer` registration as the main proof that a resource was released
- the public ownership model separately says ownership may transfer on assignment, return, and argument passing of owned values
- together, this means the implementation is acting closer to “owned locals must be deferred here” than “owned values must be safely consumed or transferred”

Why this matters:

- this over-constrains the implementation relative to the published model
- it risks false positives for code that safely transfers ownership out of the local scope instead of closing/freeing locally
- it makes the user-facing guarantee about ownership transfer inaccurate unless the docs are narrowed or the verifier grows transfer-aware summaries

Verified progress on this checkout:

✅ Argument-transfer cleanup through consuming helpers and unsafe extern `_owned` parameters is now accepted without forced local `defer`, grouped returns and returns of consuming helper calls transfer ownership correctly, and the production memory model now states the narrower proof-of-consumption rule.

Required fixes:

1. decide whether local `defer` is a recommendation or a hard semantic requirement for all tracked owned locals
2. if transfer-based cleanup is intended, teach verifier/resource checks to accept validated ownership transfer without mandatory local `defer`
3. if transfer-based cleanup is not yet intended, narrow the public ownership wording so it does not promise broader transfer semantics than the implementation enforces
4. keep diagnostics explicit about whether the failure is “resource not released” or “transfer proof unsupported”

Required tests:

1. return/argument-transfer cases that are intended to be legal must not be rejected solely for missing local `defer`
2. transfer cases that are not yet supported must fail with limitation-accurate diagnostics
3. local cleanup via `defer` must remain accepted for canonical safe manual resource management

Verified tests:

The return-transfer hardening is covered by targeted HIR tests, passing `hir` and `verifier` suites, and deterministic trace-backed, replay, CI, and host-backed Fozzy production checks.

### ✅ 8. Partial-move detection now covers the core aggregate extraction shapes in v1

Verified closure:

Partial-move detection now rejects the core aggregate extraction shapes in v1, including tuple holes, nested field projections, and pattern holes over linear members, with targeted HIR tests and deterministic trace-backed plus host-backed Fozzy validation.

## Priority 3: Make Unsafe Accounting Honest And Actionable

### 9. Unsafe “reasoned contract” accounting is overstated

Problem:

- summary logic increments `unsafe_reasoned_sites` whenever unsafe is seen
- generated metadata is treated as if it were evidence of a reasoned proof
- compiler-generated unsafe docs currently auto-fill structural fields such as:
  - `reason = compiler-generated: ...`
  - `invariant = owner_live(<owner>)`
  - `proof_ref = gate://compiler-generated/...`
- verifier-side checking mostly validates field presence and shape, not the semantic truth of the underlying safety argument

Why this matters:

- this can make internal summaries sound stronger than the underlying proof story
- it risks overstating how much assurance unsafe metadata currently provides
- the current unsafe docs are valuable accountability artifacts, but they should be described as structural audit records unless and until stronger proof validation exists
- direct local audit reproduction also showed that an `unsafe fn main() { unsafe { ... } }` probe is emitted with:
  - `owner = scope_root`
  - `invariant = owner_live(scope_root)`
  - `risk_class = memory`
- that confirms the current generated contracts are still using placeholder ownership/risk defaults in some no-parameter cases rather than resolved semantic ownership facts

Verified progress on this checkout:

✅ Compiler-generated placeholder unsafe contracts no longer count toward `unsafe_reasoned_sites`, verifier messaging now distinguishes structural metadata from independently reasoned evidence, and the change is covered by `hir`/`verifier` tests plus deterministic trace-backed and host-backed Fozzy validation.

Required fixes:

1. redefine `unsafe_reasoned_sites` so it means something stronger than “unsafe site exists”
2. distinguish:
   - unsafe present
   - metadata complete
   - invariant shape valid
   - evidence linked
   - evidence independently validated
3. decide whether compiler-generated placeholder contracts should count as “review-ready” or just “draft”
4. update any diagnostics or dashboards that imply stronger assurance than exists
5. make public/internal wording explicit that compiler-generated unsafe contracts are structural accountability artifacts unless independent semantic evidence is attached and validated

Required tests:

1. unsafe with generated placeholder metadata should not be counted as fully reasoned unless policy says so
2. malformed invariant metadata should degrade the summary correctly
3. invalid or missing proof refs should be visible in summary counts
4. no-parameter unsafe sites must not silently fall back to `scope_root` if stronger ownership/provenance facts are available
5. generated `risk_class` values must reflect the actual unsafe boundary kind rather than defaulting to a broad placeholder bucket

### 9.25. Verifier proof-ref validation is weaker than the strict unsafe-audit path

Problem:

- verifier-side `unsafe_proof_ref_valid(...)` in `crates/verifier/src/lib.rs` currently accepts any non-empty `gate://`, `trace://`, `run://`, `test://`, or `ci://` string
- the stricter unsafe-audit path in `crates/driver/src/command.rs` performs stronger validation for evidence-like refs, including path existence checks for `trace://`, `run://`, `test://`, and `ci://`
- direct local reproduction against `verifier` confirmed that a strict verifier run accepted `trace:///definitely/missing/path.fozzy#site=u1` as clean and still emitted `compiler contract checks passed`
- this means verifier success can currently certify nonexistent unsafe evidence links

Why this matters:

- this is not just metadata nitpicking; it is an honesty gap in the production safety story
- the verifier currently communicates a stronger unsafe-evidence posture than it has actually established
- users can get a clean strict-verifier result while the stricter audit path would reject the same proof reference as unbacked

Verified closure on this checkout:

✅ Verifier proof-ref validation now matches the stricter artifact-backed semantics for `trace://`, `run://`, `test://`, and `ci://`, rejects missing artifacts in strict mode, still accepts real evidence, and keeps `gate://` placeholders clearly separate.

Verified tests:

This proof-ref hardening is covered by dedicated verifier tests, passing `hir` and `verifier` suites, and deterministic trace-backed, replay, CI, and host-backed Fozzy production checks.

Required fixes:

1. unify verifier proof-ref validation with the stricter audit semantics or factor both call sites through one shared validator
2. distinguish structural URI shape checks from evidence-existence checks in diagnostics and summary counts
3. do not emit “compiler contract checks passed” wording when proof references have only passed a syntactic screen
4. ensure strict verifier mode rejects nonexistent artifact-backed proof refs the same way the unsafe-audit path does
5. keep `gate://` placeholders explicitly separated from artifact-backed evidence so dashboards and summaries do not conflate them

Required tests:

1. strict verifier mode must reject nonexistent `trace://...`, `run://...`, `test://...`, and `ci://...` proof refs
2. existing artifact-backed proof refs must continue to pass in both verifier and unsafe-audit flows
3. summary wording must differ between:
   - structural metadata present
   - machine-linkable evidence present
   - independently validated evidence present

### ✅ 9.5. Thread-boundary borrow/send-sync failures are emitted through the wrong diagnostic path

Problem:

- `analyze_send_sync_contracts(...)` currently extends `capability_token_violations` rather than a dedicated concurrency / borrow-safety diagnostic stream
- verifier rendering for that bucket tells the user to add capability-token parameters, even when the real failure is a thread-boundary mutable-reference or borrowed-return violation
- current direct verification evidence on this checkout showed thread-boundary borrowed-reference failures surfacing with capability-token remediation text

Why this matters:

- this is a real compiler diagnostics bug even if the underlying rejection is correct
- it makes production triage harder because the reported fix points at the wrong subsystem
- it weakens trust in the memory-safety story when the compiler correctly rejects a program but explains the failure inaccurately

Verified closure on this checkout:

✅ Thread-boundary borrow/send-sync failures now flow through a dedicated `thread_boundary_violations` lane with boundary-specific remediation, while real capability-token failures keep their own guidance and summary bucket.

Verified tests:

This diagnostic-lane split is covered by targeted `hir` and `verifier` tests, passing compiler suites, and deterministic trace-backed, replay, CI, and host-backed Fozzy production checks.

Required fixes:

1. route send/sync and thread-boundary borrow failures through a dedicated diagnostic category instead of `capability_token_violations`
2. give these diagnostics remediation text about owned returns, send/sync-safe wrappers, or borrow-boundary changes rather than capability-token propagation
3. keep capability-token diagnostics reserved for actual delegated-capability contract failures
4. make sure summary counts and grouped output preserve the distinction between capability-policy failures and memory/concurrency safety failures

Required tests:

1. async/thread-capable function returning a borrowed reference must fail with thread-boundary remediation text, not capability-token guidance
2. thread-capable function taking mutable pointer/reference parameters must fail with send/sync-wrapper guidance
3. real capability-token failures must continue to emit capability-token-specific help text

### 10. Unsafe docs and public language must stay within actual enforcement scope

Problem:

- the public docs are mostly careful, but we should keep compiler behavior and wording tightly aligned

Required fixes:

1. audit `USAGE.md`, `docs/production-memory-model-v1.md`, and `docs/system-safety-trust-model-v1.md`
2. ensure no wording implies:
   - full formal borrow-checker equivalence
   - complete alias/lifetime theorem proving
   - complete control-flow ownership coverage before it exists
3. narrow “memory-safe by default” language if needed until the control-flow gaps are closed
4. add explicit wording about shipped rule scope where helpful

Required review output:

1. claim-by-claim table of:
   - current wording
   - actual enforcement basis
   - keep / revise / defer decision

## Priority 4: Strengthen Regression Defenses

### 11. Add targeted unit tests in `crates/hir`

Needed additions:

1. `if` maybe-free then reuse
2. `if` maybe-move then reuse
3. `match` free/move then reuse
4. branch-sensitive double-free
5. borrowed local incorrectly classified as linear resource
6. nested cleanup counting
7. loop-carried ownership regressions
8. richer reference-return lifetime regressions

Goal:

- every bug class found in this review should have at least one direct unit test

### 12. Add verifier integration tests at the `fz verify` surface

Verified progress on this checkout:

✅ `fz verify` integration coverage now includes direct pipeline tests for borrowed-return thread-boundary failures, mutable-reference thread-boundary failures, and non-thread borrowed-reference pass paths that must not regress.

Needed additions:

1. minimal `.fzy` fixtures for each bug class
2. expected diagnostic assertions for both real safety failures and false-positive regressions
3. coverage for compiler-managed profile enforcement in verify mode

Goal:

- prove that user-visible diagnostics match the intended compiler semantics

### 13. Add Fozzy scenarios for compiler memory-safety regressions

Verified progress on this checkout:

✅ Added `tests/compiler_verify_thread_boundary.pass.fozzy.json` as a first-class `fz verify` scenario gate covering negative borrowed-return and mutable-reference thread-boundary failures plus a positive borrowed-reference pass path.

Needed additions:

1. scenario(s) that compile/verify fixtures expected to fail for ownership unsoundness
2. scenario(s) that compile/verify fixtures expected to pass for borrowed references
3. trace-backed replayable regressions for the active bug set
4. host-backed variants where feasible for shipped CLI/runtime flows

Goal:

- make the newly discovered failure modes part of the release gate, not just local unit coverage

### 13.5. The current Fozzy memory release gate is too narrow

Problem:

- the prescribed memory scenario currently proves a very small alloc/free lifecycle only
- it does not exercise the compiler-side failure modes identified in this review:
  - conditional ownership joins
  - `match` arm ownership effects
  - loop-carried ownership state
  - borrowed-reference false positives
  - richer lifetime-return/control-flow cases
- a green deterministic/replay/CI result on that scenario is therefore weaker evidence than the surrounding production wording suggests

Why this matters:

- release gates should validate the actual bug classes we are relying on for production confidence
- a narrow passing scenario can create false confidence even when compiler enforcement still has uncovered blind spots

Verified progress on this checkout:

✅ Strict deterministic Fozzy coverage now includes `tests/compiler_verify_thread_boundary.pass.fozzy.json`, with recorded trace evidence at `/Users/deepsaint/Desktop/fozzylang/artifacts/compiler-verify-thread-boundary.trace.fozzy` and full doctor, strict test, trace verify, replay, CI, and host-backed validation.

Required fixes:

1. expand the Fozzy memory/compiler gate set so each bug class in this document has at least one scenario-backed regression
2. add negative scenarios expected to fail verification for ownership/control-flow unsoundness
3. add positive scenarios expected to pass for valid borrowed-reference and cleanup patterns
4. ensure the production memory release checklist references the expanded scenario set, not only the current simple alloc/free trace
5. keep trace verify/replay/CI coverage on the expanded set so failures remain deterministic and replayable

Required gate additions:

1. branch-sensitive maybe-free then reuse scenario
2. `match`-arm consume then reuse scenario
3. loop-carried consume/reuse scenario
4. borrowed-reference non-linear cleanup scenario
5. richer reference-return/control-flow scenario

### 13.75. Some passing runtime evidence is still script-backed and too indirect for compiler-memory guarantees

Problem:

- the current memory scenario is a synthetic alloc/free accounting check rather than a compiler-semantics exercise
- several unsafe-FFI scenarios pass by shelling out through `scripts/unsafe_ffi_stress.sh`
- that evidence is useful, but it is still indirect compared with first-class compiler/verifier fixtures for the exact ownership/lifetime rules claimed here

Why this matters:

- a green runtime gate can hide missing compiler-side coverage if the exercised path is too abstract or too delegated to scripts
- production compiler-memory claims need direct evidence for compiler diagnostics and verifier outcomes, not only end-to-end shell-backed stress coverage

Required fixes:

1. keep the current script-backed unsafe-FFI stress coverage, but pair it with direct compiler/verifier fixtures for the same bug classes
2. ensure each claimed ownership/lifetime rule has at least one first-class fixture that asserts the expected verifier result
3. treat runtime/script-backed passes as supporting evidence, not the primary proof for compiler-enforced safety claims

Required tests:

1. direct `fz verify` fixture coverage for deferred cleanup, ownership joins, and lifetime-return cases
2. scenario coverage that records/replays the exact compiler-memory regressions under discussion
3. script-backed FFI stress coverage remains in place as a secondary regression layer

## Priority 5: Release Criteria Before Reclaiming Stronger Production Language

Do not consider the compiler area production-complete for full memory-safety claims until all items below are true:

1. conditional and `match` ownership state is path-sensitive and tested
2. borrowed references are no longer treated as linear cleanup obligations
3. loop ownership semantics are modeled soundly enough for shipped control-flow forms
4. lifetime analysis coverage is expanded and documented honestly
5. unsafe summary/accounting no longer overstates compiler assurance
6. unit tests, verifier fixtures, and Fozzy scenarios cover every bug class in this document
7. public docs are reconciled to the actual enforcement model

## Suggested Execution Order

1. Fix the borrowed-reference false positive first so safe code stops failing for the wrong reason.
2. Fix `match` ownership analysis next because it is a clear blind spot.
3. Replace `if` ownership merging with path-sensitive state.
4. Strengthen loop semantics once branch modeling is in place.
5. Expand lifetime and alias coverage on top of the new control-flow model.
6. Rework unsafe accounting and documentation once the enforcement story is stabilized.

## Additional Product / Tooling Bugs

### 10. Native library backend contract is inconsistent with the public build surface

Problem:

- the public `fz build` CLI and docs present backend selection as a general `llvm|cranelift` choice
- `fz build --lib` rejects an explicit `--backend llvm` request and narrows library production to Cranelift-only behavior
- this creates a user-visible contract mismatch between the advertised build surface and the actual library build implementation

Why this matters:

- this is a real product bug, not just a roadmap gap
- it makes backend selection less predictable for users trying to standardize release builds
- it weakens the case for shipping a polished builder/product surface on top of the current toolchain contract

Required fixes:

1. either implement LLVM-backed `fz build --lib` end to end or formally narrow the documented contract so library builds are explicitly Cranelift-only
2. make backend capability differences visible in CLI help, docs, and diagnostics rather than relying on a late rejection path
3. ensure profile features such as PGO and library emission do not describe a contradictory backend matrix

Required tests:

1. explicit `fz build --lib --backend llvm` behavior must match the documented contract
2. backend-specific library build expectations must be covered in CLI-level regression tests
3. release documentation must reflect the actual supported native-library backend matrix

### 11. `fz init` is split, underpowered, and not yet a production one-shot bootstrap command

Problem:

- the shipped `fz` binary exposes a native `init <name>` command, but that path is a hardcoded starter-app generator rather than the intended full production bootstrap flow
- the repo also contains a richer Fozzy scaffold implementation with template, test-selection, corpora, and init-guide support, but it is not wired into the shipped `fz init` parser path
- the result is two divergent init implementations, neither of which is the canonical one-shot project bootstrap command we actually want to ship
- current docs and usage text already imply a more robust `fz init` surface than the shipped parser supports
- some folders and files emitted by the old scaffold appear likely to be legacy/demo structure rather than a justified canonical initialized project layout

Current direct evidence:

- shipped parser/help currently accepts only `init <name>`
- driver-local init path writes a fixed `src/api`, `src/model`, `src/services`, `src/runtime`, `src/cli`, and `src/tests` tree plus `fozzy.toml`
- richer scenario-side scaffold creates `.fozzy` runtime directories, scenario fixtures, corpus seeds, and `tests/INIT_GUIDE.md`, but is not the shipped source of truth for `fz init`
- richer usage/init-guide content references `fz init --template ... --with ... --force` and post-init flows like `fz full` / `fz gate`, while the shipped parser does not currently expose that full contract
- current checked-in/generated init guidance also shows naming drift between `fozzy` and `fz`

Why this matters:

- this is a top-of-funnel product command; if `fz init` is inconsistent, users start with the wrong project shape and the wrong expectations
- the command currently behaves more like a hardcoded historical scaffold than a production bootstrap flow
- the split implementation guarantees future drift between parser/help/docs/scaffold logic unless it is centralized
- generating stale or placeholder folders bakes unsupported architecture into every new project and raises long-term cleanup cost
- a one-shot init command is only credible if the scaffolded project, tests, artifacts, and first-run guidance all match the actual shipped CLI surface

Required fixes:

1. remove the old driver-local scaffold implementation in full and replace it with a single canonical `fz init` implementation
2. centralize all init behavior behind the shipped `fz` command so parser/help/docs/scaffold logic share one source of truth
3. upgrade `fz init` from `init <name>` only into the intended production surface, including robust template/scaffold-selection/force behavior where those features remain part of the supported contract
4. make `fz init` a true one-shot bootstrap command that can create:
   - project root / current-directory bootstrap as appropriate
   - `fozzy.toml`
   - canonical `src/main.fzy` and only the justified starter source layout
   - `.fozzy/runs`
   - `.fozzy/corpora`
   - `tests/*.fozzy.json`
   - `tests/INIT_GUIDE.md`
   - README/template assets that are actually supported
5. separate target path semantics from package/project naming so `fz init` can behave intentionally rather than treating raw path input as both directory and manifest package name
6. implement explicit collision and overwrite policy for existing roots, manifests, source trees, tests, and `.fozzy` directories rather than relying on ad hoc filesystem behavior
7. audit every generated folder/file from both the old native scaffold and the newer scenario scaffold and classify each as:
   - required canonical scaffold output
   - optional template-specific material
   - stale/legacy output to remove
8. remove any dead generator logic, dead template branches, placeholder architecture folders, speculative starter modules, or duplicated scaffold paths that are not part of the real supported production workflow
9. do not preserve historical scaffold structure just because it exists today; the final initialized layout must be minimal, canonical, and fully justified
10. reconcile CLI help, README, `USAGE.md`, generated init-guide content, and any machine-readable usage output so they all describe the same shipped `fz init` contract
11. ensure post-init guidance references only commands that actually exist and work in the shipped CLI
12. if the intended one-shot init flow depends on commands such as `fz full` or `fz gate`, either implement/expose them properly or remove them from generated guidance until they are real

Required tests:

1. direct CLI regression coverage for:
   - named-directory init
   - current-directory init
   - collision behavior without `--force`
   - overwrite behavior with `--force`
   - template/scaffold selection behavior
   - manifest naming/path resolution
2. scaffold-content assertions proving the final initialized tree contains only the canonical supported files and excludes stale historical folders/modules
3. end-to-end coverage that a freshly initialized project can run the advertised first-step commands successfully
4. regression coverage that parser/help/docs/generated guide stay aligned on the same `fz init` contract
5. negative coverage for unsupported template names, unsupported scaffold kinds, and unsafe overwrite cases

Required Fozzy validation:

1. always validate at least one strict deterministic init flow with:
   - `fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json`
   - `fozzy test --det --strict <scenarios...> --json`
2. record and validate at least one real init-related trace with:
   - `fozzy run ... --det --record <trace.fozzy> --json`
   - `fozzy trace verify <trace.fozzy> --strict --json`
   - `fozzy replay <trace.fozzy> --json`
   - `fozzy ci <trace.fozzy> --json`
3. include host-backed checks where feasible for filesystem-heavy init behavior:
   - `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`
4. ensure the active init goal is covered by real trace-backed evidence rather than docs-only or unit-test-only validation

Release bar:

1. `fz init` must have exactly one production implementation path
2. the old scaffold code must be removed rather than left dormant
3. the final scaffolded layout must be minimal and canonical, with no legacy placeholder structure
4. the generated project must match the actual shipped CLI/runtime workflow end to end
5. parser/help/docs/generated onboarding content must all agree
6. Fozzy-first deterministic, trace, replay, CI, and host-backed evidence must exist for the new init flow before calling it production-ready

## Compiler-Owned Build Surface

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
7. Lock everything in with unit tests, verifier fixtures, and Fozzy scenarios.

## Additional Completed DX / Runtime Hardening

✅ Closed the split `fz init` product surface by removing the old scaffold path, centralizing bootstrap under the shipped `fz init` command, narrowing the generated tree to the canonical minimal layout, aligning generated guidance with real commands, and validating the result with crate tests plus deterministic, trace-backed, replay, CI, and host-backed Fozzy runs.

✅ Closed the process-handle lifecycle contract gap by giving `proc.spawn*` handles an explicit typed cleanup path through `proc.close(handle)`, wiring the intrinsic end to end, regression-covering the typing path in `crates/hir`, and validating it with compiler and real-project checks.

✅ Closed the qualified module-path inconsistency so dot-qualified type paths parse in signatures and cross-module const/static value paths resolve consistently, with focused parser and driver regressions backing the fix.

✅ Closed the `core.log` stdlib/verifier import poison so logging helper setup no longer leaks linear map ownership during normal import/configuration flows, with driver regression coverage and doc alignment.

✅ Re-ran the production Fozzy trace lifecycle after the DX/runtime fixes through deterministic doctor, strict test, recorded trace, trace verify, replay, CI, and host-backed execution.

## Production Blocker: Native Filesystem Surface Too Thin For Real Artifact Builders

While pushing `/Users/deepsaint/Desktop/fzaudio` from scaffold mode into real packaging and artifact validation, I hit a language/runtime boundary that should be treated as production signal rather than worked around in shell scripts.

Current blocker:

- the canonical `core.io` / `core.fs` surface is missing basic native-product filesystem operations needed for a real release tool:
  - no directory metadata / file-type inspection
  - no recursive directory removal
  - no file copy primitive
  - no directory copy / tree staging primitive
  - `list_dir(...)` returns names only, with no typed entry metadata

Why this blocks real production software:

- a serious release builder must be able to:
  - discover whether a discovered path is a file, directory, bundle root, or symlink-like entry
  - stage built plugin bundles into deterministic `dist/` layouts
  - clean generated build/package directories without shelling out
  - validate artifact trees without guessing from string suffixes alone
- using `/bin/sh`, `find`, `cp`, `rm`, or `ditto` for these core operations would hide a real stdlib/runtime gap instead of exercising the language as a production systems surface

Concrete mismatch observed on the current checkout:

- docs advertise a richer `io` contract:
  - [docs/stdlib-v1.md] lists `metadata(path) -> Result<FileMetadata, IoError>` and `remove(path) -> Result<(), IoError>`
- actual shipped `core.io` wrapper currently exposes only:
  - `read_text`
  - `write_text`
  - `mkdir`
  - `exists`
  - `remove_file`
  - `stat_size`
  - `temp_file`
  - `list_dir`
- see:
  - `docs/stdlib-v1.md:42-49`
  - `docs/stdlib-v1.md:250-259`
  - `corelib/src/io.fzy:3-33`

Required fix direction:

1. add a real typed filesystem metadata surface for production code, including at minimum:
   - exists
   - is_file
   - is_dir
   - size
   - mtime or stable timestamp access
2. add first-class copy/remove operations suitable for packaging workflows:
   - file copy
   - recursive directory copy or explicit tree staging API
   - recursive directory removal
3. enrich directory listing so callers can inspect entry kinds without shelling out
4. reconcile the stdlib docs with the actual shipped surface and add focused regressions proving the documented APIs exist and work in native builds

This is currently blocking further native-first implementation of `fzaudio package`, `fzaudio clean`, and robust bundle validation.

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
