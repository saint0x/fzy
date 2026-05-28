# SIMD Roadmap

This document defines the production roadmap for SIMD in fzy.

The plan has two distinct tracks:

1. auto-vectorization-friendly IR and lowering for ordinary scalar code
2. a stable portable SIMD surface exposed as `core.simd`

The goal is not to dump architecture-specific intrinsics into the language as fast as possible. The goal is to make SIMD fit the same production model as the rest of fzy:

- memory-safe by default
- verifier-aware
- portable first
- explicit unsafe escape hatches only where unavoidable
- parity-minded across LLVM and Cranelift
- benchmarked and replay-validated like the rest of the runtime/compiler surface

The canonical stdlib module name should be `core.simd`, not `core.SIMD`, to stay consistent with the rest of the core module surface.

## Scope

This roadmap covers:

- vectorization-friendly IR/lowering
- a stable portable SIMD type and operation surface
- testing, verification, perf gates, and docs needed for production confidence

This roadmap does not prioritize first:

- target-specific x86/ARM intrinsic dumps
- handwritten ISA specialization syntax
- unstable experimental-only public APIs
- heroic backend-specific peepholes before the portable model is sound

## Success Criteria

fzy should be able to claim all of the following before SIMD is considered production-ready:

- normal scalar loops can be lowered in a way that LLVM and Cranelift can reasonably auto-vectorize
- a portable SIMD surface exists and is stable enough for real applications
- safe SIMD code is possible without architecture-specific intrinsics
- backend drift is caught by parity and equivalence gates
- unsupported shapes fail clearly instead of silently scalarizing in surprising ways
- docs explain when to rely on scalar auto-vectorization versus explicit `core.simd`

## Track 1: Auto-Vectorization-Friendly Lowering

This track improves ordinary code generation so users get SIMD wins without writing explicit SIMD code.

### A. IR and analysis prerequisites

- [ ] Audit current FIR/native lowering for loop shapes that block vectorization.
- [ ] Document the canonical “vectorizable loop subset” for v1.5/v2 planning.
- [ ] Ensure counted loops lower into simple canonical induction-variable form.
- [ ] Ensure bounds/length expressions are hoisted and normalized where safe.
- [ ] Ensure array/list/string/bytes indexing lowers without extra opaque helper calls on hot scalar loops where direct lowering is possible.
- [ ] Reduce unnecessary aliasing ambiguity in lowered memory operations.
- [ ] Preserve alignment/provenance metadata where the backend can benefit.
- [ ] Distinguish side-effect-free math/data loops from loops with opaque calls.
- [ ] Introduce explicit IR markers or metadata for:
  - contiguous memory access
  - loop trip-count knowledge
  - no-alias regions when verifier can prove them
  - reduction patterns
  - gather/scatter-like fallback cases

### B. Canonical loop lowering

- [ ] Define a canonical lowering shape for vectorizable `while` and `for ... in range(...)` loops.
- [ ] Normalize accumulator/reduction patterns into backend-friendly SSA form.
- [ ] Lower common map/filter-like data-plane loops into straightforward index-based loops where appropriate.
- [ ] Avoid injecting unnecessary branches inside hot loops.
- [ ] Avoid hidden temporary allocations in obvious data-plane loops.
- [ ] Ensure `str.len`, `bytes.len`, `list.len`, and array lengths lower to simple scalar values in loop headers.
- [ ] Ensure slice/index expressions do not obscure memory access patterns.

### C. Backend-specific auto-vectorization enablement

- [ ] LLVM:
  - [ ] audit emitted IR for canonical vectorizable loops
  - [ ] confirm relevant optimization/vectorization passes are enabled in the right profiles
  - [ ] preserve alignment/noalias/readonly-like information where safe
- [ ] Cranelift:
  - [ ] document current vectorization limits clearly
  - [ ] align lowering with the most vectorization-friendly CLIF forms available
  - [ ] identify which shapes must remain scalar until backend support improves
- [ ] Keep backend expectations explicit in docs and tests instead of assuming equal SIMD maturity.

### D. Verifier and diagnostics

- [ ] Add optional analysis for “vectorization blockers” in perf-oriented tooling.
- [ ] Teach `fz perf` or a sibling command to surface likely vectorization blockers:
  - opaque calls in loop body
  - alias-unsafe mutable references
  - shape-changing branches
  - hidden bounds/materialization churn
- [ ] Add diagnostics or advisory notes for common anti-patterns when practical.
- [ ] Make sure no new optimization path weakens existing safety guarantees.

### E. Validation and benchmarks

- [ ] Add representative vectorization fixtures:
  - byte scanning
  - ASCII classification
  - delimiter search
  - reduction sums/min/max
  - equality mask scans
  - simple image/audio kernel loops
- [ ] Add LLVM/Cranelift parity tests for semantic correctness.
- [ ] Add perf benchmarks that compare:
  - old scalar lowering
  - new scalar-friendly lowering
  - explicit `core.simd` implementation later
- [ ] Add CI-visible evidence that the lowering changes improve or at least preserve hot-loop behavior.

## Track 2: Stable Portable SIMD Surface (`core.simd`)

This track adds an explicit author-facing SIMD model.

## Design principles

- portable first
- explicit lane counts
- no architecture-specific semantics in the primary API
- safe APIs wherever possible
- backend lowering must be predictable and diagnosable
- scalar fallback behavior should be explicit in implementation policy, not accidental in surface semantics

## Surface shape

### A. Types

- [ ] Introduce first-class SIMD lane vector types in the type system.
- [ ] Decide canonical syntax:
  - recommended direction: generic form like `Simd<i32, 4>`
  - possibly aliases like `i32x4`, `u8x16`, `f32x8`
- [ ] Support at least:
  - signed integers
  - unsigned integers
  - floating point
  - mask types
- [ ] Define lane-count policy:
  - fixed compile-time lane counts only
  - reject runtime-sized vectors in the initial design
- [ ] Define ABI/FFI posture:
  - probably no public FFI-stable promise in phase 1
  - verifier should reject unsupported ABI crossings clearly

### B. Core operations

- [ ] Construction:
  - `splat`
  - lane tuple/array construction
  - zero/all-ones helpers where appropriate
- [ ] Arithmetic:
  - add/sub/mul
  - min/max
  - saturating ops where applicable
- [ ] Bitwise:
  - and/or/xor/not
  - shifts
- [ ] Comparison:
  - eq/ne/lt/le/gt/ge
  - mask-producing comparisons
- [ ] Selection:
  - `select(mask, then, else)`
- [ ] Lane movement:
  - shuffle
  - zip/unzip
  - widen/narrow
  - cast/reinterpret with strict rules
- [ ] Reductions:
  - horizontal add
  - any/all
  - min/max reduction

### C. Memory operations

- [ ] Safe contiguous load/store operations.
- [ ] Explicit aligned vs unaligned load/store policy.
- [ ] Partial/tail handling policy:
  - masked loads/stores later
  - scalar tail loops initially if simpler
- [ ] Gather/scatter:
  - probably defer from phase 1 unless there is a strong use case
- [ ] Slice/array interop:
  - loading from `bytes`, arrays, or typed contiguous buffers
  - storing back into typed contiguous buffers

### D. Masks

- [ ] First-class portable mask type.
- [ ] Define whether masks are distinct from integer vectors.
- [ ] Add `any`, `all`, `none`, `bitmask` helpers.
- [ ] Define mask-to-select semantics clearly.

### E. Type system and verifier work

- [ ] Add SIMD types to AST/HIR/FIR type representations.
- [ ] Type-check lane-count compatibility.
- [ ] Type-check element-type compatibility.
- [ ] Reject unsupported implicit conversions.
- [ ] Define safe/unsafe boundary for:
  - reinterpret casts
  - raw pointer loads/stores
  - unaligned assumptions
- [ ] Add precise diagnostics for:
  - lane mismatch
  - unsupported backend type
  - illegal ABI crossing
  - invalid mask/vector mixing

### F. Lowering and backend mapping

- [ ] FIR should gain first-class SIMD instructions or a well-defined lowered op family, not just opaque function calls.
- [ ] Native lowering should map portable ops cleanly to:
  - LLVM vector IR
  - Cranelift vector ops where available
- [ ] Unsupported operations must fail clearly instead of silently degenerating into surprising behavior.
- [ ] Decide policy for scalar fallback:
  - either explicit backend fallback in controlled cases
  - or verifier rejection until implemented
- [ ] Keep operation coverage matrices for LLVM and Cranelift.

### G. Standard library layer

- [ ] Add `corelib/src/simd.fzy`.
- [ ] Register `use core.simd;` in parser + embedded stdlib merge path.
- [ ] Decide whether `core.simd` implies any capability.
  - likely no special capability unless raw CPU feature probing is added later
- [ ] Add ergonomic helpers:
  - aliases
  - constructors
  - reductions
  - safe load/store wrappers
- [ ] Keep naming consistent with `core.process`, `core.term`, `core.http`, etc.

### H. Feature detection and target policy

- [ ] Decide whether phase 1 portable SIMD is:
  - baseline-lowered when backend/target supports it
  - or gated behind explicit target features
- [ ] Add a target feature policy document:
  - baseline ISA expectations
  - optional AVX2/AVX-512/NEON/SVE/WASM SIMD story later
- [ ] If runtime detection is needed later, keep it separate from the initial portable surface.

## Phase Plan

### Phase 0: Design + constraints

- [ ] Finalize surface syntax and naming.
- [ ] Finalize verifier stance on safe vs unsafe operations.
- [ ] Finalize LLVM/Cranelift support matrix.
- [ ] Finalize docs language for public claims.

### Phase 1: Auto-vectorization-friendly lowering

- [ ] Land loop/IR/lowering cleanup for vectorizable scalar code.
- [ ] Add benchmarks and parity fixtures.
- [ ] Add perf diagnostics for vectorization blockers where practical.
- [ ] Publish the “vectorizable scalar subset” docs.

### Phase 2: Minimal portable SIMD

- [ ] Land `core.simd` import + type surface.
- [ ] Land core integer + float vector types.
- [ ] Land splat/load/store/basic arithmetic/bitwise/compare/select/reduction operations.
- [ ] Land LLVM lowering for the minimal surface.
- [ ] Land Cranelift lowering for the supported subset.
- [ ] Add cross-backend semantic parity tests.

### Phase 3: Production hardening

- [ ] Add stricter diagnostics and verifier coverage.
- [ ] Add perf regression gates.
- [ ] Add docs/examples/showcase updates.
- [ ] Add Fozzy scenarios for SIMD-oriented runtime/compiler parity where meaningful.
- [ ] Add release-gate coverage for SIMD representative workloads.

### Phase 4: Advanced portable SIMD

- [ ] Shuffles and lane rearrangement expansion.
- [ ] Widening/narrowing and saturating variants.
- [ ] Better mask handling.
- [ ] Better tail/masked memory operations.
- [ ] Optional target-specialized extensions after the portable contract is stable.

## Testing Checklist

### Compiler/verifier

- [ ] parser tests for SIMD syntax
- [ ] HIR tests for SIMD types and operations
- [ ] verifier tests for illegal conversions, ABI crossings, lane mismatches, unsafe boundaries
- [ ] FIR/lowering tests for canonical vector instructions or canonical scalar loop forms

### Backend/runtime

- [ ] LLVM execution tests
- [ ] Cranelift execution tests
- [ ] parity/equivalence tests across backends
- [ ] failure-mode tests for unsupported operations
- [ ] direct built-binary behavior checks for representative workloads

### Fozzy-first production validation

- [ ] `fozzy doctor --deep --scenario <simd-scenario> --runs 5 --seed <seed> --json`
- [ ] `fozzy test --det --strict <simd-scenarios...> --json`
- [ ] `fozzy run <simd-scenario> --det --record <trace.fozzy> --json`
- [ ] `fozzy trace verify <trace.fozzy> --strict --json`
- [ ] `fozzy replay <trace.fozzy> --json`
- [ ] `fozzy ci <trace.fozzy> --json`
- [ ] host-backed confidence pass where SIMD functionality interacts with real file/process/network workloads

### Benchmarking

- [ ] add scalar-vs-auto-vectorized-vs-explicit-SIMD benchmarks
- [ ] add architecture notes for Apple Silicon and x86_64 targets
- [ ] track wins in:
  - text scanning
  - JSON token classification
  - hashing/checksum kernels
  - search/filter loops
  - reductions

## Documentation Checklist

- [ ] update `README.md` production surface summary when `core.simd` is real
- [ ] update `USAGE.md` native/runtime surface guidance
- [ ] add SIMD section to `docs/language-reference-v1.md`
- [ ] add SIMD section to `docs/stdlib-v1.md`
- [ ] update `fzl-showcase.html` with portable SIMD examples once stable
- [ ] document the difference between:
  - writing scalar code that should auto-vectorize
  - writing explicit portable SIMD with `core.simd`
  - later target-specific intrinsics if they ever exist

## Risks To Avoid

- [ ] do not make the first public SIMD surface backend-specific
- [ ] do not silently expose unsound raw memory/vector operations as safe APIs
- [ ] do not claim equal SIMD capability across LLVM and Cranelift before the evidence exists
- [ ] do not silently scalarize in ways that make performance debugging impossible
- [ ] do not let SIMD escape hatches undermine the safe-by-default story
- [ ] do not ship a public surface without benchmark and parity coverage

## Recommended Immediate Order

If work starts now, the recommended order is:

1. define the canonical portable SIMD type model and verifier boundaries
2. audit current FIR/native lowering for vectorization blockers
3. land auto-vectorization-friendly loop lowering improvements
4. add representative perf fixtures and parity tests
5. add `core.simd` module plumbing and minimal portable types
6. land minimal portable ops and backend lowering
7. harden docs, diagnostics, and production gates

## Bottom Line

fzy should have a SIMD story, but it should be the fzy kind of SIMD story:

- scalar code gets better automatically when the lowering is clean
- explicit SIMD is portable and verifier-aware
- safety and diagnostics stay ahead of cleverness
- backend parity and production evidence come before marketing claims
