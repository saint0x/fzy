# Language Reference v1

This document defines the v1 observable semantics contract used by the toolchain.

## Evaluation Order

- Statements evaluate top-to-bottom within a function body.
- `let` initializers evaluate before binding assignment.
- `let` bindings are immutable by default.
- `let mut <name> = ...` is required for reassignment (`=`, `+=`, `-=`, `*=`, `/=`, `%=` and bitwise compound assignments).
- `discard <expr>` explicitly evaluates and ignores an expression result.
- `let _ = ...` is removed.
- Function call arguments evaluate left-to-right.
- `defer` registers cleanup in lexical order and executes in reverse registration order at scope exit.
- `match` evaluates the scrutinee first, then evaluates only the selected arm expression.

## Ranges And Branch Shortcuts

- Exclusive ranges remain `start..end`.
- Inclusive `..=` is removed; use `range.closed(start, end)`.
- One-line control-flow branches use `if <cond> then return|break|continue`.

## If Expression

- `if` is valid in expression position:
  - `let x = if cond { a } else { b }`
  - `let x = if cond then a else b`
- `else` is required for expression-form `if`.
- Condition must be bool/integer-compatible.
- Then/else branches must resolve to compatible types.

## Statement Expression Model

- Control-flow constructs are expression-valid in v1 production mode.
- Expression forms:
  - `if ... else ...` returns a value (else required).
  - `match ... { ... }` returns the selected arm value.
  - `loop { ... }`, `while ... { ... }`, `for ... { ... }`, `for ... in ... { ... }` are expression-valid and resolve to `void`.
  - `discard <expr>` resolves to `void`.
  - `return`, `break`, and `continue` are valid in expression position and are diverging control-flow expressions (`never`).
- `break <expr>` is accepted; in v1 it is treated as control-flow without a value-level loop result.

## Declarations

- Module-level `const` declarations are supported:
  - `const NAME: Type = <compile-time integer/char/bool expr>;`
- Module-level `static` declarations are supported:
  - `static NAME: Type = <compile-time integer/char/bool expr>;`
- `static mut` is supported for module-level mutable integer globals and lowers in native backends.

## Integer Overflow

- `dev`/`det` profiles: integer overflow is wrap-around at runtime unless the verifier rejects statically impossible contracts.
- `verify` profile: overflow-sensitive code paths are expected to be proven by pre/postconditions; verifier diagnostics are treated as gate failures when safe profile is enabled.
- Overflow behavior is profile-semantic and must remain parity-stable across `fast` and `det`.

## Error And Panic Semantics

- `try <expr> catch <fallback>` evaluates the try branch first and returns the fallback value when the try branch fails.
- Catch fallback value must type-check against the try expression result type.
- v1 error classes are runtime operation failures (I/O, process, net), cancellation/deadline events, and verifier/runtime contract failures.
- `panic(...)` must never cross C ABI boundaries.
- Exported FFI boundaries should use `pubext c fn`; C imports use `ext unsafe c fn` when unsafety is required (and must be called from unsafe context); project panic policy is declared in `fozzy.toml` under `[ffi] panic_boundary`.
- Async C exports use `pubext async c fn` and lower to async-handle ABI symbols (`*_async_start/poll/await/drop`).
- `#[ffi_panic(abort|error)]` remains available as an explicit symbol override.

## Async And Scheduling Constructs

### `await <call>`

- Awaits an async call and yields control at an explicit async yieldpoint.
- `await` is valid only inside `async fn` bodies.
- Awaiting non-call expressions or known non-async calls is invalid.

### `spawn(task)`

- Creates a new schedulable task.
- Task scheduling is deterministic in `det` mode and recorded as replay-critical data.
- `spawn(...)` implies thread/executor capability requirements.

### Task Group Helpers

- `task.group_spawn_n(group, worker, n)` spawns `n` tasks into a group.
- `task.group_join_all(group)` is the canonical full-group join operation.
- `task.parallel_map(list_handle, worker)` provides high-level fan-out/fan-in over list length.
- Canonical production pattern:

```fzy
fn worker() -> i32 {
    checkpoint()
    return 0
}

fn run_group() -> i32 {
    let group = task.group_begin()
    discard task.group_spawn_n(group, worker, 8)
    return task.group_join_all(group)
}
```

### `checkpoint()`

- Explicit scheduler yieldpoint for deterministic interleaving exploration.
- Always observable in traces under `--det --record`.

### `yield()`

- Cooperative handoff to scheduler.
- Does not imply task completion; execution may resume later.

### `timeout(ms)`

- Declares timeout/deadline behavior for the enclosing operation scope.
- Timeout decisions are observable deterministic events.
- `ms` argument is required.

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
- RPC failure paths are exposed as operation failures in runtime data/diagnostics paths; `try/catch` expressions lower natively in both LLVM and Cranelift paths.

## Memory Model: `alloc` / `free`

- `alloc(size)` creates owned heap memory in current scope.
- `free(ptr)` consumes ownership and invalidates the pointer for further use.
- `defer free(ptr)` is the preferred cleanup pattern.
- Safe-profile verification flags unmatched allocations/frees and flow paths where allocated memory escapes without release.

## Capability Semantics

- Capabilities are declared by `use core.<name>;` at module scope.
- Core capabilities include: `time`, `rng`, `fs`, `http`, `proc`, `mem`, `thread`, `log`, `error`.
- `use core.text;` is invalid; text/string intrinsics are capability-free.
- Verifier emits diagnostics for unknown or missing required capabilities.

## Process Intrinsic Namespace

- Canonical process intrinsic namespace is `proc.*`.
- `process.*` is removed in production v1; unresolved-call diagnostics provide migration guidance to the nearest `proc.*` intrinsic.
- Structured process builders are first-class: `proc.argv_new/push`, `proc.env_new/set`, `proc.spawn_cmd`, `proc.run_cmd`.

## JSON And Logging Ergonomics

- First-class object literals are supported and lower to canonical map primitives:
  - `#{ "component": json.str("api"), "phase": json.str("boot") }`
- Object literal keys must be quoted strings.
- Dynamic JSON builders are canonical:
  - `json.array(list_handle)`
  - `json.object(map_handle)`
- `core.http` provides typed JSON payload wrappers for HTTP call sites:
  - `JsonPayload`
  - `json_payload_new/set_str/set_raw/encode`
  - `write_json_payload`
  - `post_json_capture_payload`
- List/map value construction is first-class:
  - `list.new/push/pop/len/get/set/clear/join`
  - `map.new/set/get/has/delete/keys/len`
- Structured logging fields use `log.fields(map_handle)` as the primary path.

## Storage Primitives

- Common persistence helpers are first-class:
  - `storage.append(path, line)`
  - `storage.atomic_append(path, line)`
  - `storage.kv_open(path)`, `storage.kv_get(handle, key)`, `storage.kv_put(handle, key, value)`

### Capability Inference Rules

- Using runtime operations tied to known effects infers required capability effects.
- Examples:
  - `spawn(...)`, `yield()`, `checkpoint()` infer thread/runtime scheduling effects.
  - filesystem operations infer `core.fs`.
  - networking operations infer `core.http`.
- Inference does not replace declaration requirements: inferred effects must still be satisfied by explicit module capabilities or propagated capability tokens.

## Function Value Semantics

### Function Type Surface

- Function types use `fn(<param-types...>) -> <return-type>`.
- Function items can be used as first-class values where a compatible `fn(...) -> ...` type is expected.
- Function type compatibility is exact on arity, parameter types, and return type.

### Higher-Order Callability Rules

- Calling a function value is valid only when the call target resolves to a `fn(...) -> ...` type.
- Calling non-callable values is a hard type error.
- Generic specialization syntax is not valid on function-value call targets.

## Arrays And Indexing

- Array literals (`[a, b, c]`) and index expressions (`arr[i]`) are first-class language expressions.
- Type checking enforces compatible element types and integer index expressions.
- Native lowering is supported in both LLVM and Cranelift backends.

## Module And Import Ergonomics (v1 Contract)

- `use path::item;` is supported.
- `use path as alias;` is supported.
- `use path::*;` is supported.
- `use path::{a, b};` is supported (including nested groups).
- `pub use ...;` re-exports are supported with executable symbol resolution semantics.
- Visibility support includes `pub fn`, `pub struct`, `pub enum`, `pub trait`, and `pub impl`.

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
- Deterministic tests (`test "..." {}`) run with deterministic scheduler semantics under `fz test --det`.
- `nondet` tests are marked for non-deterministic/chaos exploration flows.
- Test bodies compile as normal statement blocks and may call project functions/modules.
- Reporting includes per-test execution summaries when trace/report artifacts are requested.

## Deterministic Scheduling Model

- `det` mode uses deterministic scheduler policies: `fifo`, `random` (seeded), `coverage_guided`.
- Scheduling decisions are recorded as replay-critical trace data.
- Async checkpoints and RPC frame decisions are represented as deterministic events.
- v1 model controls explicit runtime scheduling points and does not claim arbitrary OS-preemptive interleaving coverage.

### Yieldpoint Definitions (Equivalence Contract)

- The following constructs are explicit yield/interleaving points for async equivalence: `await`, `yield()`, `checkpoint()`, `spawn(...)`, `recv()`, `timeout(ms)`, `deadline(ms)`, `cancel()`, `pulse()`.
- Cross-engine equivalence normalization uses deterministic event categories:
  - `thread.schedule`
  - `async.checkpoint`
  - `rpc.frame`
  - `test.event`
  - `test.assert`
- Normalization rule: engine-specific `async.schedule` is normalized to `async.checkpoint` before equivalence comparison.

## Memory Safety And UB Model

- Safe-profile checks reject unsafe capabilities and unsafe escape sites.
- References in safe profile require explicit lifetime/region annotations (`&'name T` / `&'name mut T`) and verifier-valid handoff.
- Alloc/free imbalance is diagnosed and can be a hard failure in safe profile.
- v1 does not claim complete alias/lifetime proof coverage for all low-level patterns.

## Ownership Model (v1)

- Heap allocations are single-owner values by default: creating via `alloc(...)` establishes ownership in the current scope.
- Ownership moves on assignment, argument passing, and return of owning types; use-after-move is verifier-invalid.
- `free(...)` consumes ownership and invalidates further use in the current flow.
- `defer free(...)` is the preferred deterministic cleanup path.
- Borrowed references (`&'a T`, `&'a mut T`) do not transfer ownership and must not outlive the annotated region `'a`.

## Atomics And Memory Ordering Contract

- v1 exposes stable atomic orderings: `Relaxed`, `Acquire`, `Release`, `AcqRel`, `SeqCst`.
- `Acquire` reads synchronize-with `Release` writes on the same atomic location.
- `AcqRel` applies to read-modify-write operations and composes acquire + release edges.
- `SeqCst` operations participate in a single total order visible to all threads.
- Deterministic mode does not weaken memory ordering semantics; it only controls scheduling decision sources.

## Common Diagnostics (Examples)

- Missing capability:
  - `missing required capability: http`
  - Fix: add `use core.http;` or propagate capability token.
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
