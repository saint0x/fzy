# Language Reference v0

This document defines the v0 observable semantics contract used by the toolchain.

## Evaluation Order

- Statements evaluate top-to-bottom within a function body.
- `let` initializers evaluate before binding assignment.
- Function call arguments evaluate left-to-right.
- `defer` registers cleanup in lexical order and executes in reverse registration order at scope exit.
- `match` evaluates the scrutinee first, then evaluates only the selected arm expression.

## Integer Overflow

- `dev`/`det` profiles: integer overflow is wrap-around at runtime unless the verifier rejects statically impossible contracts.
- `verify` profile: overflow-sensitive code paths are expected to be proven by pre/postconditions; verifier diagnostics are treated as gate failures when safe profile is enabled.
- Overflow behavior is profile-semantic and must remain parity-stable across `fast` and `det`.

## Error And Panic Semantics

- `try ... catch ...` evaluates the try branch first; catch branch is used as fallback value.
- `panic(...)` must never cross C ABI boundaries.
- Exported FFI boundaries must declare panic policy with `#[ffi_panic(abort)]` or `#[ffi_panic(error)]`.

## Async Cancellation Semantics

- Cancellation markers (`cancel`, timeout/deadline markers) are observable events in deterministic analysis.
- Cleanup registered via `defer` is guaranteed at function scope exit.
- Cancellation semantics are deterministic in `det` mode relative to recorded scheduling decisions.

## Deterministic Scheduling Model

- `det` mode uses deterministic scheduler policies: `fifo`, `random` (seeded), `coverage_guided`.
- Scheduling decisions are recorded as replay-critical trace data.
- Async checkpoints and RPC frame decisions are represented as deterministic events.
- v0 model controls explicit runtime scheduling points and does not claim arbitrary OS-preemptive interleaving coverage.

## Capability Semantics

- Capabilities are explicit via `use cap.<name>;` plus inferred usage markers.
- `fast` mode prioritizes execution speed with reduced deterministic instrumentation.
- `det` mode enforces replay-critical decision capture and deterministic scheduling.
- `verify`/safe-profile mode enforces additional capability and safety restrictions.

## Memory Safety And UB Model

- Safe-profile checks reject unsafe capabilities and unsafe escape sites.
- References in safe profile require explicit lifetime/region annotations (`&'name T` / `&'name mut T`) and verifier-valid handoff.
- Alloc/free imbalance is diagnosed and can be a hard failure in safe profile.
- v0 does not claim complete alias/lifetime proof coverage for all low-level patterns.

## Ownership Model (v0)

- Heap allocations are single-owner values by default: creating via `alloc(...)` establishes ownership in the current scope.
- Ownership moves on assignment, argument passing, and return of owning types; use-after-move is verifier-invalid.
- `free(...)` consumes ownership and invalidates further use in the current flow.
- `defer free(...)` is the preferred deterministic cleanup path.
- Borrowed references (`&'a T`, `&'a mut T`) do not transfer ownership and must not outlive the annotated region `'a`.

## Atomics And Memory Ordering Contract

- v0 exposes stable atomic orderings: `Relaxed`, `Acquire`, `Release`, `AcqRel`, `SeqCst`.
- `Acquire` reads synchronize-with `Release` writes on the same atomic location.
- `AcqRel` applies to read-modify-write operations and composes acquire + release edges.
- `SeqCst` operations participate in a single total order visible to all threads.
- Deterministic mode does not weaken memory ordering semantics; it only controls scheduling decision sources.
