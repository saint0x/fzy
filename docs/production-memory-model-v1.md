# Production Memory Model v1

## Safety Target

- Safe-by-default semantics are mandatory for production run/test/build pipelines.
- Unsafe behavior is allowed only through first-class unsafe islands/functions.
- Production policy target is enforceable high-assurance default safety with no unsound default fallback path.
- The implementation intentionally does not claim full theorem-proved equivalence to Rust’s borrow checker.

## Ownership

- Heap values are single-owner by default.
- Ownership transfers on assignment, return, and argument passing of owned values.
- Ownership consumption APIs: `free(...)`, `close(...)`.
- Use-after-move and double-consume are verifier errors.

## Borrowing And Aliasing

- Borrowed references are non-owning.
- Mutable references are exclusive.
- Shared references are read-only.
- Mutable borrows across async suspension points are rejected.
- Partial move from owned aggregates is rejected in v1 baseline.

## Provenance

- Pointer values created by `alloc(...)` are treated as unique provenance roots.
- `free(...)` consumes pointer provenance and invalidates further uses.
- Pointer parameters at FFI boundaries must carry ownership tags via parameter name suffix:
  - `_owned`
  - `_borrowed`
  - `_out`

## Drop And Cleanup

- Deterministic drop model is LIFO via lexical `defer` registration.
- Linear/resource values must be consumed exactly once.
- Missing cleanup is a verifier error under production memory safety.

## Panic And Unwind

- Panic must not cross C ABI boundaries.
- `#[ffi_panic(abort|error)]` is required on exported `pubext c fn` functions.

## Atomics And Ordering

- Supported ordering model: Relaxed, Acquire, Release, AcqRel, SeqCst.
- Deterministic scheduler does not weaken ordering semantics.

## Concurrency And Send/Sync-Class Rules

- Thread-capable functions (async or thread-required) must not expose mutable pointer/reference parameters without Send/Sync-safe wrapping.
- Returning borrowed references from thread-capable boundaries is rejected.

## FFI Boundary Rules

- Only FFI-stable types are accepted.
- `repr(C)` layout checks are required for stable struct/enum layouts.
- Callback parameters require explicit context parameter (`*_ctx` or `*_context`) for lifetime anchoring.

## Unsafe Islands

- Unsafe surface:
  - `unsafe fn ...`
  - `unsafe { ... }`
  - optional metadata on unsafe blocks:
    - `unsafe("reason:...", "invariant:...", "owner:...", "scope:...", "risk_class:...", "proof_ref:...") { ... }`
- Calls to unsafe functions/imports must be inside unsafe context.
- Metadata is non-blocking by default.
- Strict mode (`FZ_UNSAFE_STRICT=1`) blocks missing/invalid metadata and unsafe-context violations.

## Production Gates

Mandatory for memory safety releases:

- `fozzy doctor --deep --scenario tests/memory_graph_diff_top.pass.fozzy.json --runs 5 --seed <seed> --json`
- `fozzy test --det --strict tests/memory_graph_diff_top.pass.fozzy.json --json`
- `fozzy run tests/memory_graph_diff_top.pass.fozzy.json --det --record <trace.fozzy> --json`
- `fozzy trace verify <trace.fozzy> --strict --json`
- `fozzy replay <trace.fozzy> --json`
- `fozzy ci <trace.fozzy> --json`
- host-backed parity run for memory scenario
- unsafe budget gate (strict mode enforces missing/invalid metadata = 0 and unsafe-context violations = 0)
