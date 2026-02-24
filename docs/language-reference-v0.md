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

- `try <expr> catch <fallback>` evaluates the try branch first and returns the fallback value when the try branch fails.
- Catch fallback value must type-check against the try expression result type.
- v0 error classes are runtime operation failures (I/O, process, net), cancellation/deadline events, and verifier/runtime contract failures.
- `panic(...)` must never cross C ABI boundaries.
- Exported FFI boundaries must declare panic policy with `#[ffi_panic(abort)]` or `#[ffi_panic(error)]`.

## Async And Scheduling Constructs

### `spawn(task)`

- Creates a new schedulable task.
- Task scheduling is deterministic in `det` mode and recorded as replay-critical data.
- `spawn(...)` implies thread/executor capability requirements.

### `checkpoint()`

- Explicit scheduler yieldpoint for deterministic interleaving exploration.
- Always observable in traces under `--det --record`.

### `yield()`

- Cooperative handoff to scheduler.
- Does not imply task completion; execution may resume later.

### `timeout(ms)`

- Declares timeout/deadline behavior for the enclosing operation scope.
- Timeout decisions are observable deterministic events.

### `cancel()`

- Marks cancellation path for current operation scope/task context.
- Cleanup registered via `defer` remains guaranteed.

### `pulse()`

- Side-effect marker for deterministic heartbeat/event-signaling flows.
- Treated as a deterministic observable action in tracing.

## Contract Clauses

### `requires <expr>`

- Precondition required before continuing function execution.
- Verifier rejects statically false preconditions.

### `ensures <expr>`

- Postcondition expected at function completion.
- Verifier rejects statically false postconditions.

## RPC Declarations

Syntax:

```fzy
rpc Method(req: ReqType) -> ResType;
rpc StreamEvents(stream<WatchReq>) -> stream<WatchEvent>;
```

Semantics:

- RPC declarations define stable call surface used by codegen and deterministic trace framing.
- RPC activity emits frame events: `rpc_send`, `rpc_recv`, `rpc_deadline`, `rpc_cancel`.
- Deadline behavior is controlled by `timeout(...)` markers.
- Cancellation behavior is controlled by `cancel()` markers.
- RPC failure paths map to catchable operation failures in `try/catch` expressions.

## Memory Model: `alloc` / `free`

- `alloc(size)` creates owned heap memory in current scope.
- `free(ptr)` consumes ownership and invalidates the pointer for further use.
- `defer free(ptr)` is the preferred cleanup pattern.
- Safe-profile verification flags unmatched allocations/frees and flow paths where allocated memory escapes without release.

## Capability Semantics

- Capabilities are declared by `use cap.<name>;` at module scope.
- Core capabilities include: `time`, `rng`, `fs`, `net`, `proc`, `mem`, `thread`.
- Verifier emits diagnostics for unknown or missing required capabilities.

### Capability Inference Rules

- Using runtime operations tied to known effects infers required capability effects.
- Examples:
  - `spawn(...)`, `yield()`, `checkpoint()` infer thread/runtime scheduling effects.
  - filesystem operations infer `cap.fs`.
  - networking operations infer `cap.net`.
- Inference does not replace declaration requirements: inferred effects must still be satisfied by explicit module capabilities or propagated capability tokens.

## Test Block Semantics

Syntax:

```fzy
test "det_case" {
    // body
}

test "chaos_case" nondet {
    // body
}
```

- Test blocks are discovered from parsed module trees and emitted into generated scenario artifacts.
- Deterministic tests (`test "..." {}`) run with deterministic scheduler semantics under `fozzyc test --det`.
- `nondet` tests are marked for non-deterministic/chaos exploration flows.
- Test bodies compile as normal statement blocks and may call project functions/modules.
- Reporting includes per-test execution summaries when trace/report artifacts are requested.

## Deterministic Scheduling Model

- `det` mode uses deterministic scheduler policies: `fifo`, `random` (seeded), `coverage_guided`.
- Scheduling decisions are recorded as replay-critical trace data.
- Async checkpoints and RPC frame decisions are represented as deterministic events.
- v0 model controls explicit runtime scheduling points and does not claim arbitrary OS-preemptive interleaving coverage.

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

## Common Diagnostics (Examples)

- Missing capability:
  - `missing required capability: net`
  - Fix: add `use cap.net;` or propagate capability token.
- Unknown capability:
  - `unknown capability: foo`
  - Fix: use one of the supported capability names.
- Missing FFI panic contract:
  - `ffi panic contract missing: add #[ffi_panic(abort)] or #[ffi_panic(error)]`
- Invalid contract clause:
  - `requires[0] is statically false`
  - `ensures[0] is statically false`
- Invalid try/catch form:
  - `expected catch in try/catch expression`

<!-- fozzydoc:api:start -->

# API Documentation
<!-- fozzydoc:api:end -->
