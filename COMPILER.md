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

✅ Performed a source-level review of the memory-safety compiler area, centered on `crates/hir`, `crates/verifier`, public safety docs, and verifier integration.

✅ Ran the prescribed Fozzy deterministic memory scenario flow:

- `fozzy doctor --deep --scenario tests/memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 42 --json`
- `fozzy test --det --strict tests/memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/memory_graph_diff_top.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/memory-sitrep-review.trace.fozzy --json`
- `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/memory-sitrep-review.trace.fozzy --strict --json`
- `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/memory-sitrep-review.trace.fozzy --json`
- `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/memory-sitrep-review.trace.fozzy --json`

✅ Confirmed the current memory scenario is deterministic and passes replay/CI with no reported leaks on the covered path.

✅ Reproduced a borrowed-reference false positive where a local `&'a` binding is treated as a linear resource requiring `defer close(...)`.

✅ Reproduced the documented `defer free(...)` contradiction on this checkout:

- minimal `fz verify` probe using `let p = alloc(...)` plus `defer free(p)` still produced leak / unreleased-linear diagnostics instead of accepting the documented cleanup pattern

✅ Reproduced an active `hir` compile failure in the reference-lifetime path:

- `cargo test -p hir detects_ -- --nocapture`
- compiler error at `crates/hir/src/lib.rs` comparing `Option<Option<String>>` against `Option<String>` in the return-lifetime checker

✅ Ran targeted unsafe-FFI and trace-backed checks beyond the simple memory scenario:

- `fozzy test --det --strict tests/memory_graph_diff_top.pass.fozzy.json tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json --json`
- `fozzy run tests/memory_graph_diff_top.pass.fozzy.json --det --record /tmp/memory-sitrep.trace.fozzy --json`
- `fozzy replay /tmp/memory-sitrep.trace.fozzy --json`
- `fozzy ci /tmp/memory-sitrep.trace.fozzy --json`

✅ Reproduced the inferred-owned-pointer escape hatch on this checkout:

- minimal `fz verify` probe using:
  - `ext unsafe c fn acquire_owned() -> *u8;`
  - `let p = unsafe { acquire_owned() }`
  - no cleanup
- returned warnings only and `errors: 0`

✅ Reproduced the ordinary helper-call ownership-transfer mismatch on this checkout:

- minimal `fz verify` probe using a helper that `free(...)`s its pointer parameter reported:
  - callee consumed a non-owned value
  - caller still leaked the original owner

✅ Reproduced a control-flow asymmetry between `if` and `match` for the same cleanup shape:

- `if flag { free(p); } free(p);` produced the expected divergent-state / moved-value / double-free-style diagnostics
- the analogous `match flag { true => free(p), false => 0, _ => 0 } free(p);` probe did not surface the same ownership/provenance failures
- this matches the current implementation shape where `Stmt::Match` routes arm values through expression-only ownership/provenance helpers that do not model direct call expressions like `free(p)`

✅ Reproduced an inferred-`alloc(...)` linear-resource false positive on this checkout:

- minimal `fz verify` probe using:
  - `let p = alloc(n);`
  - `free(p);`
- reported `function 'main' frees non-linear value 'p' as linear resource`
- this indicates the current linear-resource pass is still relying too heavily on explicit local type annotations rather than inferred owned-resource semantics

✅ Ran current compiler/verifier and unsafe-accounting evidence on this checkout:

- `cargo test -q -p hir`
- `cargo test -q -p verifier`
- `fz audit unsafe . --workspace --json`
- `python3 scripts/rust_unsafe_inventory.py --root . --out /tmp/rust_unsafe_inventory_sitrep.json --budget 2 --policy policy/rust_unsafe_islands.json`

✅ Confirmed the current checkout does build the compiler safety crates directly:

- `cargo test -q -p hir` passed (`75 passed; 0 failed`)
- `cargo test -q -p verifier` passed (`26 passed; 0 failed`)
- the previously noted `Option<Option<String>>` vs `Option<String>` `hir` lifetime-checker compile failure did not reproduce on this checkout and should be treated as stale or branch-local unless it reappears

✅ Confirmed current unsafe-accounting posture on this checkout:

- workspace unsafe audit returned `entries: 0`
- `missingContractCount: 0`
- `invalidProofRefCount: 0`
- `unsafeContextViolationCount: 0`
- Rust unsafe inventory passed at the approved budget of `2`

✅ Confirmed the currently approved Rust `unsafe` footprint remains exactly these two documented sites:

- [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs:74)
- [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs:198)

✅ Confirmed the current host-backed memory scenario also passes on this checkout:

- `fozzy run tests/memory_graph_diff_top.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

✅ Re-ran the unsafe / FFI scenario checks individually on this checkout to avoid ambiguity from multi-target test invocation:

- `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json --json`
- `fozzy test --det --strict tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json --json`
- `fozzy test --det --strict tests/unsafe_ffi.trace_host_replay.pass.fozzy.json --json`
- `fozzy test --det --strict tests/c_ffi_matrix.pass.fozzy.json --json`

✅ Added a second current-checkout memory evidence pass with a fresh deterministic seed and explicit trace lifecycle:

- `fz doctor --deep --scenario tests/memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 1337 --json`
- `fz test tests/memory_graph_diff_top.pass.fozzy.json --det --strict-verify --seed 1337 --json`
- `fz run tests/memory_graph_diff_top.pass.fozzy.json --det --seed 1337 --record artifacts/memory-sitrep.trace.fozzy --json`

✅ Fixed and regression-covered the remaining live false-logic cleanup issues on the current checkout:

- borrowed references are no longer collected as linear resources requiring cleanup
- inferred `alloc(...)` locals now participate in linear-resource accounting the same way as explicitly typed pointer locals
- deferred `free(...)` now counts as a real release for ownership/leak accounting
- direct `free(...)` / `close(...)` and deferred cleanup now share verifier release accounting instead of “defer only” logic
- direct cleanup in `match` arms now updates post-`match` ownership state and diagnoses divergent / already-consumed paths
- inferred unsafe pointer-return locals are now tracked by ownership leak analysis

✅ Added focused compiler regressions in `crates/hir` for:

- borrowed-reference locals not appearing in `linear_resources`
- inferred allocation locals not producing “frees non-linear value” false positives
- deferred cleanup preventing leak / unreleased-linear false positives
- inferred unsafe pointer-return locals being tracked as owned resources
- `match`-arm cleanup updating ownership state

✅ Re-ran the production Fozzy flow for the compiler safety surface on this checkout:

- `fozzy validate tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy validate tests/pedantic.crates_verifier.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy doctor --deep --scenario tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 42 --json`
- `fozzy test --det --strict tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json tests/pedantic.crates_verifier.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --record artifacts/compiler-hardening.trace.fozzy --json`
- `fozzy trace verify artifacts/compiler-hardening.trace.fozzy --strict --json`
- `fozzy replay artifacts/compiler-hardening.trace.fozzy --json`
- `fozzy ci artifacts/compiler-hardening.trace.fozzy --json`
- `fozzy run tests/pedantic.crates_hir.lib.host_backends_run.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

✅ Tightened same-statement async borrow checking on the current checkout:

- shared borrowed references are now rejected when used after `await` within the same nested `if`, `match`, or loop body
- covered by focused HIR regressions for:
  - same `if` body post-`await` shared borrow use
  - same `match` statement post-`await` shared borrow use
  - same loop body post-`await` shared borrow use

✅ Re-ran a fresh post-fix HIR Fozzy trace lifecycle on this checkout:

- `fozzy doctor --deep --scenario tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 99 --json`
- `fozzy test --det --strict tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --record artifacts/await-hardening.trace.fozzy --json`
- `fozzy trace verify artifacts/await-hardening.trace.fozzy --strict --json`
- `fozzy replay artifacts/await-hardening.trace.fozzy --json`
- `fozzy ci artifacts/await-hardening.trace.fozzy --json`
- `fozzy run tests/pedantic.crates_hir.lib.host_backends_run.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

✅ Fixed helper-boundary pointer/ref provenance attribution on the current checkout:

- pointer/ref-returning helpers now carry a callee return-provenance summary instead of inheriting the first provenance-bearing argument by heuristic
- helpers returning the first pointer arg and helpers returning the second pointer arg now produce different caller provenance when appropriate
- covered by focused HIR regressions for:
  - distinct first-arg versus second-arg helper return provenance
  - second-arg passthrough not collapsing onto the first-arg root

✅ Re-ran a fresh provenance-focused HIR Fozzy trace lifecycle on this checkout:

- `fozzy doctor --deep --scenario tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 123 --json`
- `fozzy test --det --strict tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --record artifacts/provenance-hardening.trace.fozzy --json`
- `fozzy trace verify artifacts/provenance-hardening.trace.fozzy --strict --json`
- `fozzy replay artifacts/provenance-hardening.trace.fozzy --json`
- `fozzy ci artifacts/provenance-hardening.trace.fozzy --json`

✅ Expanded aggregate alias/provenance coverage on the current checkout:

- `let` pattern bindings now inherit provenance through tuple, struct, and variant destructuring instead of being ignored
- overwriting a provenance-bearing local with a value whose provenance cannot be tied back now clears the stale root instead of preserving a false alias
- covered by focused HIR regressions for:
  - tuple destructuring preserving per-element provenance
  - struct destructuring preserving per-field provenance
  - reassignment clearing stale provenance before later cleanup

✅ Re-ran a fresh aggregate-provenance HIR Fozzy trace lifecycle on this checkout:

- `fozzy doctor --deep --scenario tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 777 --json`
- `fozzy test --det --strict tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --record artifacts/aggregate-provenance.trace.fozzy --json`
- `fozzy trace verify artifacts/aggregate-provenance.trace.fozzy --strict --json`
- `fozzy replay artifacts/aggregate-provenance.trace.fozzy --json`
- `fozzy ci artifacts/aggregate-provenance.trace.fozzy --json`
- `fz trace verify artifacts/memory-sitrep.trace.fozzy --strict --json`
- `fz replay artifacts/memory-sitrep.trace.fozzy --json`
- `fz ci artifacts/memory-sitrep.trace.fozzy --json`

✅ Confirmed additional current-checkout runtime/compiler evidence not previously listed here:

- host-backed `fz run tests/c_ffi_matrix.pass.fozzy.json --host-backends --json` passed
- sampled direct-memory backend consistency tests passed:
  - `cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_bounds_probe_executes_consistently -- --exact`
  - `cargo test -q -p driver pipeline::tests::cross_backend_direct_memory_contract_fixture_executes_consistently -- --exact`

✅ Reproduced an inferred-handle cleanup escape hatch on this checkout:

- `let listener = http.bind(); return 0` verified with `diagnostics: 0`
- the equivalent explicitly typed `let listener: HttpHandle = http.bind(); return 0` correctly failed with leak / linear-resource diagnostics
- this confirms cleanup enforcement still depends on explicit local type spelling for at least some handle-producing expressions

✅ Reproduced a plain-pointer / `_borrowed` C-import escape hatch on this checkout:

- `ext c fn c_read(buf: *u8) -> i32;` verified with warnings only
- `ext c fn c_read(buf_borrowed: *u8) -> i32;` also verified with warnings only
- this shows the current verifier only forces `ext unsafe c fn` for a narrower subset of pointer-shaped imports than the docs imply

✅ Reproduced missing callback-context enforcement on this checkout:

- `ext unsafe c fn register(cb_owned: *u8, cb: fn(i32) -> i32) -> i32;` verified with warnings only
- no verifier error required a companion `*_ctx` / `*_context` lifetime anchor even though the production memory model documents that rule

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

- direct `free(...)` / `close(...)` arm expressions now flow through ownership-state updates instead of being skipped as expression-shaped no-ops
- post-`match` state now diagnoses divergent ownership and already-consumed follow-up uses on the same local
- covered by a targeted HIR regression that reproduces `match`-arm cleanup followed by a second cleanup

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

- inferred locals receiving pointer returns now seed ownership tracking through typed local information rather than explicit local annotations only
- covered by a targeted HIR regression for `ext unsafe c fn acquire_owned() -> *u8` with missing cleanup

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

- semantic-hint collection no longer uses pointer-like syntax as a proxy for owned cleanup obligations
- borrowed references stop flowing into `linear_resources`
- covered by a targeted HIR regression over an inferred borrowed local returned from a helper

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

- cleanup target collection now traverses control-flow and nested expression shapes structurally
- direct cleanup and deferred cleanup share the same collected release accounting surface

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

- inferred allocation locals now enter linear-resource accounting through typed local information instead of explicit annotations only
- covered by a targeted HIR regression that `free(...)`s an inferred allocation local without producing the old “frees non-linear value” diagnostic

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

- semantic-hint collection now uses structural AST traversal instead of a hand-picked subset of statement forms
- nested cleanup inside `if`, `match`, loops, `unsafe`, and other expression shapes feeds the same release accounting

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

- deferred cleanup now participates in ownership leak accounting
- verifier release checks now accept both direct cleanup and deferred cleanup instead of a defer-only rule
- covered by a targeted HIR regression plus refreshed CLI spot checks on the current checkout

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

- the borrow-after-`await` walker now carries post-suspension state through nested expressions and statement bodies instead of only flipping state after a whole statement finishes
- shared references now get the same same-statement post-`await` checking that mutable references previously received
- covered by focused HIR regressions for nested `if`, `match`, and loop-body shapes

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

- provenance roots now propagate through tuple and struct pattern destructuring instead of skipping `let` patterns entirely
- reassignment now clears stale provenance when the new value does not preserve the previous alias root
- helper-boundary return provenance and local destructuring coverage now align more closely across the major aggregate cases we can verify today

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

- pointer/ref-returning helper calls now consult a callee return-provenance summary instead of binding silently to the first provenance-bearing argument
- summary inference now distinguishes at least:
  - returns parameter 0 provenance
  - returns parameter N provenance
  - returns fresh provenance
  - unknown / unsupported provenance
- covered by focused HIR regressions that distinguish first-arg and second-arg passthrough helpers

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

- ✅ grouped-expression `_owned` FFI arguments now consume the same semantic provenance root as the ungrouped value instead of bypassing the transfer check
- ✅ grouped mutable-reference aliasing now collapses onto the same alias key as the underlying value instead of evading the repeated-borrow check through syntax alone
- `cargo test -q -p hir` now includes:
  - `detects_mutable_aliasing_through_grouped_ref_argument`
  - `grouped_owned_ffi_argument_marks_root_consumed`
- refreshed FFI trace evidence passed on this checkout:
  - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
  - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-shape-hardening.trace.fozzy --json`
  - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-shape-hardening.trace.fozzy --strict --json`
  - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-shape-hardening.trace.fozzy --json`
  - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-shape-hardening.trace.fozzy --json`
  - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

- the verifier no longer relies on `_owned` / `_out` / `_inout` suffixes for this boundary
- any pointer-like C import shape now requires `ext unsafe c fn`, including:
  - plain pointer parameters such as `ext c fn c_read(buf: *u8) -> i32;`
  - borrowed-pointer naming shapes such as `ext c fn c_read(buf_borrowed: *u8) -> i32;`
  - mixed pointer-parameter / pointer-return signatures
- the diagnostic remains explicit about the unsafe-boundary requirement instead of leaving pointer-shaped safe imports in the nominally safe surface

Verified tests:

1. `cargo test -q -p verifier` now includes:
   - `safe_extern_c_pointer_param_requires_unsafe_boundary`
   - `safe_extern_c_borrowed_pointer_param_requires_unsafe_boundary`
   - `safe_extern_c_mixed_pointer_signature_requires_unsafe_boundary`
2. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 735 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-boundary-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-boundary-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-boundary-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/ffi-boundary-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

### ✅ 7.35. Callback lifetime-anchor requirements are now enforced structurally

Verified closure:

- callback-shaped FFI parameters now trigger verifier enforcement for an adjacent `*_ctx` or `*_context` anchor
- callback-bearing imports without that neighbor now fail with an explicit diagnostic instead of passing with warnings only
- imports with an adjacent context anchor pass the structural verifier check, which aligns the compiler boundary with the documented callback lifetime model

Verified tests:

1. `cargo test -q -p verifier` now includes:
   - `callback_extern_c_import_without_context_anchor_fails`
   - `callback_extern_c_import_with_adjacent_context_anchor_passes_structural_check`
2. the same Fozzy trace-backed FFI production pass above completed cleanly, with recorded evidence at `/Users/deepsaint/Desktop/fozzylang/artifacts/ffi-boundary-hardening.trace.fozzy`

### ✅ 7.5. Ownership transfer on argument passing now follows an explicit consume-summary rule

Verified closure:

- the shipped rule on this checkout is now explicit and enforced:
  - assignment and identifier return still transfer ownership
  - argument passing transfers ownership only when the callee contract/body proves consumption
  - non-consuming helpers remain borrow/non-transfer call edges
- local helper bodies now contribute conservative consumed-parameter summaries, so a helper that actually `free(...)`s an owned argument no longer reports:
  - callee-side “consumes non-owned value”
  - caller-side leak of the original owner
- unsafe extern `_owned` parameters now participate in the same caller-side ownership-transfer rule instead of living as a disconnected one-off behavior
- the public production memory model was narrowed to match the implemented rule in `/Users/deepsaint/Desktop/fozzylang/docs/production-memory-model-v1.md`

Verified tests:

1. `cargo test -q -p hir` now includes:
   - `helper_freeing_owned_param_transfers_ownership_from_caller`
   - `non_consuming_helper_preserves_caller_ownership`
   - `unsafe_extern_owned_param_transfers_ownership_from_caller`
2. compiler suites passed on this checkout:
   - `cargo test -q -p hir`
   - `cargo test -q -p verifier`
3. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 941 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/ownership-transfer-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/ownership-transfer-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/ownership-transfer-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/ownership-transfer-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

- ✅ argument-transfer cleanup through consuming local helpers is now accepted without forcing a local `defer` at the original call site
- ✅ argument-transfer cleanup through unsafe extern `_owned` parameters is now accepted under the same consume-summary rule
- ✅ the production memory-model wording now reflects a proof-of-consumption rule instead of blanket argument-transfer wording
- ✅ grouped `return` of an owned local now transfers ownership instead of leaking by falling off the identifier-only return path
- ✅ `return` of a consuming helper call now applies the same consume-summary rule instead of still requiring local cleanup at the caller

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

1. `cargo test -q -p hir` now includes:
   - `grouped_return_transfers_ownership_without_local_defer`
   - `return_of_consuming_helper_call_does_not_require_local_defer`
2. compiler suites passed on this checkout:
   - `cargo test -q -p hir`
   - `cargo test -q -p verifier`
3. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 1201 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/return-transfer-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/return-transfer-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/return-transfer-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/return-transfer-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

### ✅ 8. Partial-move detection now covers the core aggregate extraction shapes in v1

Verified closure:

- partial-move detection no longer depends only on the simplest direct field-access shape
- the ownership pass now rejects partial extraction from aggregates that structurally contain linear members across:
  - tuple destructuring with holes
  - nested struct field projection chains
  - struct / variant-style pattern holes
- this closes the main structural gap where aggregates containing owned pointers could evade the v1 “no partial move” baseline simply because the move happened through a richer extraction form

Verified tests:

1. `cargo test -q -p hir` now includes:
   - `tuple_pattern_partial_move_is_rejected`
   - `nested_struct_field_partial_move_is_rejected`
   - `struct_pattern_partial_move_is_rejected`
2. compiler suites passed on this checkout:
   - `cargo test -q -p hir`
   - `cargo test -q -p verifier`
3. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 1601 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/partial-move-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/partial-move-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/partial-move-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/partial-move-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

- ✅ compiler-generated placeholder unsafe contracts no longer count toward `unsafe_reasoned_sites`
- ✅ verifier production messaging now distinguishes:
  - structural unsafe contract metadata present
  - independently reasoned evidence still required
- ✅ placeholder-generated contracts with `gate://compiler-generated/...` and `scope_root` ownership remain visible as audit records, but no longer trigger the over-claiming “compiler contract checks passed” wording
- `cargo test -q -p hir` now includes:
  - `compiler_generated_unsafe_sites_are_not_counted_as_reasoned`
- `cargo test -q -p verifier` now includes:
  - `production_mode_distinguishes_placeholder_unsafe_contracts_from_reasoned_evidence`
- compiler suites passed on this checkout:
  - `cargo test -q -p hir`
  - `cargo test -q -p verifier`
- Fozzy production checks passed on this checkout:
  - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 1901 --json`
  - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
  - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/unsafe-accounting-hardening.trace.fozzy --json`
  - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/unsafe-accounting-hardening.trace.fozzy --strict --json`
  - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/unsafe-accounting-hardening.trace.fozzy --json`
  - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/unsafe-accounting-hardening.trace.fozzy --json`
  - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

- ✅ verifier proof-ref validation now mirrors the stricter artifact-backed semantics for:
  - `trace://`
  - `run://`
  - `test://`
  - `ci://`
- ✅ nonexistent artifact-backed proof refs are now rejected directly in strict verifier mode instead of being accepted on URI shape alone
- ✅ existing artifact-backed proof refs still pass strict verifier validation
- ✅ `gate://` placeholders remain machine-linkable structural references, but they stay distinct from artifact-backed evidence

Verified tests:

1. `cargo test -q -p verifier` now includes:
   - `strict_unsafe_contracts_reject_missing_trace_artifact_proof_refs`
   - `strict_unsafe_contracts_accept_existing_trace_artifact_proof_refs`
   - `strict_unsafe_contracts_reject_malformed_proof_refs`
2. compiler suites passed on this checkout:
   - `cargo test -q -p hir`
   - `cargo test -q -p verifier`
3. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 2201 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/proof-ref-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/proof-ref-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/proof-ref-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/proof-ref-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

- ✅ thread-boundary borrow/send-sync failures now flow through a dedicated `thread_boundary_violations` lane instead of `capability_token_violations`
- ✅ verifier remediation now distinguishes:
  - borrowed returns crossing thread-capable boundaries
  - mutable pointer/reference parameters that need a Send/Sync-safe owned wrapper
  - real delegated-capability token failures
- ✅ capability-token diagnostics keep their capability-token-specific help text instead of absorbing thread-boundary borrow failures
- ✅ grouped verifier output and summary state now preserve the distinction by carrying thread-boundary failures separately from capability-policy failures

Verified tests:

1. `cargo test -q -p hir` now includes:
   - `routes_borrowed_return_thread_boundary_failures_out_of_capability_bucket`
   - `routes_mutable_reference_thread_boundary_failures_out_of_capability_bucket`
2. `cargo test -q -p verifier` now includes:
   - `thread_boundary_borrowed_return_uses_thread_boundary_remediation`
   - `thread_boundary_mutable_param_uses_send_sync_wrapper_guidance`
   - `capability_token_failures_keep_capability_specific_guidance`
3. compiler suites passed on this checkout:
   - `cargo test -q -p hir`
   - `cargo test -q -p verifier`
4. Fozzy production checks passed on this checkout:
   - `fozzy doctor --deep --scenario tests/c_ffi_matrix.pass.fozzy.json --runs 5 --seed 2501 --json`
   - `fozzy test --det --strict tests/unsafe_ffi.pointer_misuse.pass.fozzy.json tests/unsafe_ffi.callback_lifecycle.pass.fozzy.json tests/unsafe_ffi.trace_host_replay.pass.fozzy.json tests/c_ffi_matrix.pass.fozzy.json --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --record /Users/deepsaint/Desktop/fozzylang/artifacts/thread-boundary-diagnostics-hardening.trace.fozzy --json`
   - `fozzy trace verify /Users/deepsaint/Desktop/fozzylang/artifacts/thread-boundary-diagnostics-hardening.trace.fozzy --strict --json`
   - `fozzy replay /Users/deepsaint/Desktop/fozzylang/artifacts/thread-boundary-diagnostics-hardening.trace.fozzy --json`
   - `fozzy ci /Users/deepsaint/Desktop/fozzylang/artifacts/thread-boundary-diagnostics-hardening.trace.fozzy --json`
   - `fozzy run tests/c_ffi_matrix.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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

Needed additions:

1. minimal `.fzy` fixtures for each bug class
2. expected diagnostic assertions for both real safety failures and false-positive regressions
3. coverage for compiler-managed profile enforcement in verify mode

Goal:

- prove that user-visible diagnostics match the intended compiler semantics

### 13. Add Fozzy scenarios for compiler memory-safety regressions

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

✅ Closed the process-handle lifecycle contract gap on the current checkout.

- `proc.spawn*` handles now have an explicit typed cleanup path through `proc.close(handle)`
- native runtime tables and shim support were updated to carry the process-close intrinsic end to end
- focused regression added in `crates/hir` for wait/observe/close typing
- wrapper helpers that consume linear handle parameters now pass the same verifier accounting as direct close sites
- validated with:
  - `cargo test -q -p hir process_close_typechecks_after_wait_and_observation`
  - `cargo test -q -p hir process_close`
  - `cargo run -q -p fz -- check /Users/deepsaint/Desktop/fzaudio --json`
  - `cargo run -q -p fz -- build /Users/deepsaint/Desktop/fzaudio --backend cranelift --json`

✅ Closed the qualified module-path inconsistency for production code on the current checkout.

- dot-qualified type paths such as `-> model.types.ProjectKind` now parse in function signatures
- cross-module const/static value paths such as `model.types.CONST_VALUE` now resolve consistently with sibling helper calls
- focused regressions added in `crates/parser` and `crates/driver`
- validated with:
  - `cargo test -q -p parser parses_dot_qualified_return_types_in_function_signatures`
  - `cargo test -q -p driver compile_project_resolves_cross_module_const_value_paths`

✅ Closed the `core.log` stdlib/verifier import poison on the current checkout.

- `core.log` helper construction no longer leaks linear map ownership during ordinary import/configuration flows
- focused regression added in `crates/driver`
- docs were updated so logging boot helpers remain a supported production pattern
- validated with:
  - `cargo test -q -p driver verify_file_accepts_log_import_without_stdlib_leak_diagnostics`

✅ Re-ran the production Fozzy trace lifecycle after these DX/runtime fixes on the current checkout.

- `cargo run -q -p fz -- doctor --deep --scenario tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --runs 5 --seed 42 --json`
- `cargo run -q -p fz -- test tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --strict-verify --json`
- `cargo run -q -p fz -- run tests/pedantic.crates_hir.lib.memory_graph_diff_top.pass.fozzy.json --det --record artifacts/process-dx-hardening.trace.fozzy --json`
- `cargo run -q -p fz -- trace verify artifacts/process-dx-hardening.trace.fozzy --strict --json`
- `cargo run -q -p fz -- replay artifacts/process-dx-hardening.trace.fozzy --json`
- `cargo run -q -p fz -- ci artifacts/process-dx-hardening.trace.fozzy --json`
- `cargo run -q -p fz -- run tests/pedantic.crates_hir.lib.host_backends_run.pass.fozzy.json --det --proc-backend host --fs-backend host --http-backend host --json`

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
