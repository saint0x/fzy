# PERF.md

- [ ] Date: 2026-02-26
- [ ] Owner: Compiler + Runtime Core
- [ ] Status: Investigation complete, implementation pending

## Perf Baseline (Rust vs Fzy Scratch)

Source benchmark table:
- `BENCH.md`
- `artifacts/bench_corelibs_rust_vs_fzy.json`
- `artifacts/bench_corelibs_rust_vs_fzy.md`

Primary gaps to close:
- [ ] `bytes_kernel`: `4.995x` (Fzy slower)
- [ ] `resultx_classify`: `3.155x` (Fzy slower)
- [ ] `text_kernel`: `1.667x` (Fzy slower)

Observed parity/near-parity kernels:
- [ ] `capability_parse`, `task_retry_backoff`, `arithmetic_kernel`, `duration_kernel`, `abi_pair_kernel`

Interpretation:
- [ ] Arithmetic-heavy, low-runtime-bound kernels are already near parity.
- [ ] Current bottlenecks are dominated by runtime-call, lock, and representation/lowering overhead in hot loops.

---

## Root-Cause Findings

### 1) Array/Indexing Path Is Runtime-Call Bound

Current lowering shape:
- [ ] Array literal lowers to `__native.array_new` + repeated `__native.array_push`.
- [ ] `arr[idx]` lowers to `__native.array_get`.
- [ ] `__native.array_get` takes `fz_collections_lock` per read.

Implication:
- [ ] Tight loops pay call overhead + mutex overhead for each element load.
- [ ] `bytes_kernel` has multiple indexed loads per iteration, amplifying cost.

### 2) Match/Enum Classification Is Branch-Chain + Slot-Heavy

Current lowering shape:
- [ ] Match is lowered via condition chains (not jump-table/switch style for dense cases).
- [ ] Variant identity uses hashed-style tags (`variant_tag`) rather than compact discriminants.
- [ ] LLVM emission uses many stack slots (`alloca`/load/store), relying on later optimization to recover SSA quality.

Implication:
- [ ] Branch-heavy kernels (`resultx_classify`) pay predictable overhead per iteration.

### 3) String Hot Paths Are Runtime/Interning Bound

Current lowering shape:
- [ ] `str.trim`, `str.replace`, `str.contains`, `str.starts_with`, `str.ends_with`, `str.len` lower to native runtime calls.
- [ ] New strings are interned through global string tables with lock + linear scan behavior.

Implication:
- [ ] `text_kernel` pays repeated conversion/allocation/interning overhead in each iteration.

---

## Strategic Direction: Direct-to-Memory Lowering

Goal:
- [ ] Lower hot-path primitives to direct memory operations in native codegen whenever semantics are provably local and safe.
- [ ] Reserve runtime calls for boundary-crossing operations or semantics that require shared runtime state.

Execution architecture invariant:
- [ ] Optimized native pipeline is direct-memory-first; runtime imports are capability/host boundaries only.
- [ ] Legacy local data-plane shim symbols (`str.*`, `list.*`, `map.*`, `__native.array_*`) are not part of optimized native execution.

Design principle:
- [ ] Keep language idioms unchanged.
- [ ] Change lowering policy and runtime ABI contracts, not source-level style.

---

## Direct-to-Memory Plan (Checklist)

## Phase 0: Measurement + Guardrails

- [ ] Add kernel-level perf CI snapshots for `bytes_kernel`, `resultx_classify`, `text_kernel`.
- [ ] Add perf budget thresholds (regression alarms on p50/p95 and ratio vs Rust baseline).
- [ ] Add backend split reporting (`llvm` vs `cranelift`) for each kernel.

## Phase 1: Array/Index Memory Fast Path (Highest Priority)

- [ ] Introduce compiler-recognized fixed numeric array form for native backends.
- [ ] Lower fixed numeric arrays to contiguous native memory (stack or static, backend-dependent).
- [ ] Lower `arr[idx]` to direct load with compile-time-known element size/stride.
- [ ] Keep bounds semantics explicit:
- [ ] strict mode: checked bounds with predictable branch shape
- [ ] trusted hot mode: proven-safe paths elide checks
- [ ] Add canonical lowering for rolling-window index patterns (`off`, `off+1`, `off+2`, `off+3`).
- [ ] Keep runtime-array path as fallback for dynamic/escaping arrays.

Exit criteria:
- [ ] `bytes_kernel` ratio improves from `~4.995x` to target band `<=2.0x` in first pass.
- [ ] No semantic regressions in deterministic replay and conformance tests.

## Phase 2: Enum/Match Control-Flow Fast Path

- [ ] Introduce compact enum discriminant representation in lowered IR/native path.
- [ ] Lower eligible match arms to switch-like CFG where profitable.
- [ ] Preserve existing language semantics for guards/payloads with clear fallback.
- [ ] Keep deterministic tag mapping for ABI/external boundaries when required.

Exit criteria:
- [ ] `resultx_classify` ratio improves from `~3.155x` to target band `<=1.8x` in first pass.
- [ ] Match diagnostics/exhaustiveness behavior unchanged.

## Phase 3: String Temporary Fast Path

- [ ] Add non-interned temporary string representation for loop-local intermediates.
- [ ] Intern only at semantic escape boundaries (storage, API boundary, persistent handles).
- [ ] Add specialized fast paths for common operations:
- [ ] trim on ASCII whitespace
- [ ] single-token replace
- [ ] contains/starts_with/ends_with on literal needles
- [ ] Keep interned/global representation available as fallback.

Exit criteria:
- [ ] `text_kernel` ratio improves from `~1.667x` to target band `<=1.25x` in first pass.
- [ ] No behavior drift in string equality/identity semantics where externally visible.

## Phase 4: Lowering Quality Cleanup (Cross-Cutting)

- [ ] Shift LLVM lowering toward SSA-friendly emission to reduce slot churn.
- [ ] Reduce avoidable calls in expression lowering hot paths.
- [ ] Re-check Cranelift/LLVM parity after direct-to-memory adoption.

Exit criteria:
- [ ] Aggregate benchmark suite ratio median within `<=1.15x` of Rust for covered kernels.

---

## Runtime Coherence Rules (Single Policy Everywhere)

- [ ] Policy A: "Direct memory first" for proven-local, non-escaping data.
- [ ] Policy B: "Runtime handle path" for shared, dynamic, escaping, or capability-bound data.
- [ ] Policy C: "Determinism-first fallback" where optimization could perturb deterministic semantics.
- [ ] Document exact eligibility matrix (array kind, mutability, escape analysis result, backend support).

---

## Risk Register

- [ ] Risk: semantic drift between fast-path and fallback path.
- [ ] Mitigation: differential testing with forced-path toggles.

- [ ] Risk: determinism regressions due to optimization-dependent behavior.
- [ ] Mitigation: strict deterministic replay/trace verification gates per phase.

- [ ] Risk: ABI/interop surprises from new internal representations.
- [ ] Mitigation: freeze external ABI contracts; optimize only internal lowering representation.

- [ ] Risk: backend divergence (`llvm` vs `cranelift`).
- [ ] Mitigation: backend conformance tests and explicit feature parity tracking.

---

## Validation Matrix (Fozzy-First)

For each phase, run:
- [ ] `fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json`
- [ ] `fozzy test --det --strict <scenarios...> --json`
- [ ] `fozzy run ... --det --record <trace.fozzy> --json`
- [ ] `fozzy trace verify <trace.fozzy> --strict --json`
- [ ] `fozzy replay <trace.fozzy> --json`
- [ ] `fozzy ci <trace.fozzy> --json`
- [ ] Host-backed run where feasible:
- [ ] `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`

Production perf gate:
- [ ] `scripts/direct_memory_perf_gate.py` is now wired into ship/production gates and enforces:
- [ ] `bytes_kernel <= 1.40`, `resultx_classify <= 1.30`, `text_kernel <= 1.25`
- [ ] near-parity kernels (`capability_parse`, `task_retry_backoff`, `arithmetic_kernel`, `duration_kernel`, `abi_pair_kernel`) <= `1.15`

---

## Implementation Notes To Revisit

- [ ] Add compiler flag(s) for fast-path forcing and disabling:
- [ ] `--perf-fastpath=off|on|force`
- [ ] `--perf-lowering-report`
- [ ] Emit per-function lowering report with counts:
- [ ] direct loads/stores
- [ ] runtime handle calls
- [ ] bounds checks emitted/elided
- [ ] match lowered as switch vs branch chain
- [ ] Track gains per transformation rather than batch-only rollout.

---

## North-Star Targets

- [ ] Eliminate runtime-call overhead from hot numeric kernels where semantics allow direct memory lowering.
- [ ] Converge branch-heavy classify workloads toward near-parity through control-flow/discriminant improvements.
- [ ] Reduce string-kernel overhead primarily by avoiding unnecessary intern/lock/allocation churn.
- [ ] Preserve language idioms and deterministic guarantees while improving machine-level efficiency.
