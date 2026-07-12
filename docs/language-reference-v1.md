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
- Scope exit for `defer` includes normal fallthrough, `return`, `break`, `continue`, cancellation paths, and `unsafe { ... }` bodies.
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

## Tuples And Pattern Destructuring

- Tuple values use `(a, b, c)` syntax.
- Grouping remains `(expr)` with no trailing comma.
- Tuple patterns are valid in `let` and `match`:
  - `let (left, (right, _)) = value`
  - `match value { (a, b) => a + b, _ => 0 }`
- Struct and enum variant patterns remain supported:
  - `let Pair { left, right: r } = pair`
  - `let Token::Number { whole, frac } = token`
- `or`-patterns remain supported with the existing identical-binding-shape rule.
- Native backends lower tuple/struct/enum values as first-class aggregate handles.
- `let` destructuring, field access, function parameters, calls, returns, helper-produced values, and control-flow-produced aggregate values all use typed aggregate layout metadata instead of source-shape reconstruction.
- Enum `match` lowering switches on the runtime aggregate tag, and enum payload extraction uses the matched variant layout.

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

### `await <expr>`

- Awaits a `Future<T>`-typed expression and yields control at an explicit async yieldpoint.
- `await` is valid only inside `async fn` bodies.
- Awaiting expressions that do not type-check as `Future<T>` is invalid.

### `spawn(task)`

- Creates a new schedulable task.
- Task scheduling is deterministic in `det` mode and recorded as replay-critical data.
- `spawn(...)` implies thread/executor capability requirements.

### `spawn_ctx(task, context_id)`

- Creates a new schedulable task with an explicit task-local context id.
- Spawned workers read that id through `thread.context_id()`.
- `thread.context_id()` returns `0` when no task-local context is bound.

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

fn tagged_worker() -> i32 {
    return thread.context_id()
}

fn run_group() -> i32 {
    let group = task.group_begin()
    discard task.group_spawn_n(group, worker, 8)
    return task.group_join_all(group)
}

fn run_tagged() -> i32 {
    let handle = spawn_ctx(tagged_worker, 41)
    return join(handle)
}
```

### `checkpoint()`

- Explicit scheduler yieldpoint for deterministic interleaving exploration.
- Always observable in traces under `--det --record`.

### `yield()`

- Cooperative handoff to scheduler.
- Does not imply task completion; execution may resume later.

### `thread.context_id()`

- Canonical current-task context getter for `spawn_ctx(...)` workers.
- Returns the context id bound at spawn time.
- Returns `0` when no task-local context id is bound.

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
- `fz check`, `fz build`, and `fz verify` surface statically false entrypoint contracts as compiler diagnostics.

### `ensures <expr>`

- Postcondition expected at function completion.
- Verifier rejects statically false postconditions.
- `fz check`, `fz build`, and `fz verify` surface statically false entrypoint contracts as compiler diagnostics.

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
- `alloc(...)` / `free(...)` are legal in safe code when ownership, provenance, and cleanup remain compiler-verifiable.
- `unsafe` is not required for ordinary owned allocation/release; it is reserved for unchecked raw-memory behavior such as dereference, pointer arithmetic, aliasing hazards, and unsafe FFI mutation boundaries.
- Safe-profile verification flags unmatched allocations/frees and flow paths where allocated memory escapes without release.

## Capability Semantics

- Capabilities are declared by `use core.<name>;` at module scope.
- Core capabilities include: `time`, `rng`, `fs`, `http`, `proc`, `mem`, `thread`, `log`, `error`.
- `use core.log;` now carries two roles:
  - it satisfies the `log` capability contract
  - it imports the `core.log` standard-library facade
- `use core.text;` is now a valid standard-library import for text/terminal composition helpers.
- Verifier emits diagnostics for unknown or missing required capabilities.

## Process Intrinsic Namespace

- Canonical process intrinsic namespace is `proc.*`.
- `process.*` is removed in production v1; unresolved-call diagnostics provide migration guidance to the nearest `proc.*` intrinsic.
- Current-process argv access is first-class:
  - `proc.argv_count()`
  - `proc.argv_get(index)`

## SIMD Surface

- Phase-1 portable SIMD types are first-class language types:
  - `i32x4`
  - `u32x4`
  - `f32x4`
  - `mask32x4`
- Lane counts are fixed at compile time in the current public surface.
- Masks are distinct from integer vectors in the public type system.
- SIMD values must not cross ABI/FFI boundaries in v1.
- Current public operations include:
  - constructors and `splat`
  - safe fixed-array `load`/`store`
  - fixed-array `load_masked`, `load_prefix`, `gather`, and vector-space `merge_masked`/`merge_prefix`
  - arithmetic, integer `saturating_add`/`saturating_sub`, min/max, shifts, bitwise ops
  - comparisons producing `mask32x4`
  - `select(mask, then, else)`
  - public `shuffle(left, right, i0, i1, i2, i3)`
  - paired lane-movement helpers `zip_lo/zip_hi` and `unzip_left/unzip_right`
  - explicit numeric reinterpret/bitcast helpers
  - lane extraction and reductions including `reduce_add`, `reduce_min`, and `reduce_max`
  - explicit `unsafe fn` raw-pointer aligned/unaligned load/store helpers for the shipped vector and mask aliases
- `shuffle` traps at runtime when any lane selector is outside `0..7`.
- Backend posture:
  - LLVM and Cranelift both lower the current phase-1 fixed-array-safe surface
  - backend parity is semantic for the shipped subset; equal optimization maturity is not implied
  - fixed-array return values are materialized into caller-owned native storage before later calls can reuse callee-local temporaries
- Fixed-array memory helpers are safe; raw contiguous-buffer SIMD interop exists only behind explicit `unsafe fn` aligned/unaligned pointer APIs, and `bytes`/slice-native views are still not part of the shipped v1 surface.
- [examples/simd_kernels](/Users/deepsaint/Desktop/fozzylang/examples/simd_kernels/README.md) is the reference example for the current production SIMD workflow.
- Canonical standard-library wrapper import is `use core.process;`.
- `core.process` exposes ergonomic wrappers like `process.argv_or`, `process.command_name`, and `process.has_flag`.
- Structured process builders are first-class: `proc.argv_new/push`, `proc.env_new/set`, `proc.spawn_cmd`, `proc.run_cmd`.
- `proc.run*` waits for completion and returns the child exit code.
- `proc.spawn*` returns a process handle for `proc.wait`, `proc.stdout`, `proc.stderr`, `proc.exit_code`, and `proc.close`.
- Small-value string conversion is first-class:
  - `str.from_i32(value)`
  - `str.from_bool(flag)`

## GPU Surface

- Production GPU authoring is centered on `use core.gpu;`.
- Execution spaces are explicit:
  - `host fn` for device discovery, allocation, upload/download, launch, and event waiting
  - `device fn` for helper functions callable from kernels
  - `kernel fn` for launchable GPU entry points
- Public opaque handle types:
  - `GpuDevice`
  - `GpuBuffer<T>`
  - `GpuSlice<T>`
  - `GpuEvent`
- Current host surface includes:
  - `gpu.device_count()`
  - `gpu.default_device()`
  - `gpu.device_name(dev)`
  - `gpu.device_memory_bytes(dev)`
  - `gpu.alloc_f32/i32/u32(dev, len)`
  - `gpu.free(buffer)`
  - `gpu.upload_f32/i32/u32(dev, values)`
  - `gpu.download_f32/i32/u32(buffer)`
  - `gpu.slice(buffer, offset, len)`
  - `gpu.launch0..4(kernel, grid, block, ...)`
  - `gpu.wait(event)`
  - `await gpu.wait_async(event)`
- Current device/kernel surface includes:
  - `gpu.global_id_x/y/z()`
  - `gpu.thread_id_x/y/z()`
  - `gpu.block_id_x/y/z()`
  - `gpu.block_dim_x/y/z()`
  - `gpu.grid_dim_x/y/z()`
  - `gpu.barrier()`
  - `slice[index]` indexing on `GpuSlice<f32/i32/u32>`
- Verifier/runtime contract:
  - kernels must return `void`
  - host functions cannot call device-only intrinsics
  - kernels cannot call host functions
  - `GpuBuffer<T>` is host-owned and linear; free it or defer its cleanup
  - `GpuSlice<T>` is a verifier-visible borrowed view; freeing or reusing the owner while slices are live is rejected
  - aliased launch parameters are rejected unless the aliasing is readonly-safe under the shared launch ABI
  - `gpu.barrier()` cannot appear in divergent control flow, including through helper calls
  - unsupported kernel parameter shapes fail before backend lowering as stable launch-ABI diagnostics
- Backend truth:
  - live executable backend today is `metal` on Apple
  - `spirv` and `nvptx` are first-class architecture adapters bound to the same shared kernel package and launch ABI, but are not yet executable
- Build/run artifacts:
  - GPU builds emit `.fz/gpu-kernel-package.json` and `.fz/gpu-kernel-package.md`
  - recorded native trace artifacts include GPU lifecycle and kernel-launch evidence
- Reference example:
  - [examples/gpu_metal_image](/Users/deepsaint/Desktop/fozzylang/examples/gpu_metal_image/README.md)

## Terminal Intrinsic Namespace

- Canonical current-process terminal namespace is `term.*`.
- This surface is distinct from child-process management in `proc.*`.
- Canonical standard-library wrapper import is `use core.term;`.
- `core.term` exposes ergonomic wrappers like `term.print_line`, `term.eprint_line`, `term.prompt_line`, `term.is_interactive`, and `term.transcript_kv`.
- First-class terminal operations:
  - `term.read_line()`
  - `term.stdin_eof()`
  - `term.write(text)`
  - `term.write_err(text)`
  - `term.stdin_is_tty()`
  - `term.stdout_is_tty()`
- `term.read_line()` removes a trailing newline and trailing carriage return when present.
- EOF is observed by pairing `term.read_line()` with `term.stdin_eof()`.

## Logging And Text Facades

- `use core.log;` is the canonical logging import for native products.
- Raw runtime controls remain first-class:
  - `log.set_json(enabled)`
  - `log.set_enabled(enabled)`
  - `log.set_level(level_name)`
  - `log.set_sink(sink_name)`
- `core.log` adds policy helpers:
  - `log.set_level_name("warn")`
  - `log.set_sink_name("stderr")`
  - `log.use_stdout()`
  - `log.use_stderr()`
  - `log.quiet()`
  - `log.verbose()`
  - `log.request_log(...)`
- `use core.text;` is the canonical standard-library text helper surface:
  - `text.repeat(piece, count)`
  - `text.spaces(count)`
  - `text.pad_left(value, width)`
  - `text.pad_right(value, width)`
  - `text.indent(value, prefix)`
  - `text.visible_len_ansi(value)`
  - `text.upper_ascii(value)`
  - `text.lower_ascii(value)`
- `use core.io;` is the canonical filesystem-discovery facade:
  - `io.read_text(path)`
  - `io.write_text(path, value)`
  - `io.mkdir(path)`
  - `io.exists(path)`
  - `io.metadata(path)`
  - `io.is_file(path)`
  - `io.is_dir(path)`
  - `io.is_symlink(path)`
  - `io.copy_file(src, dst)`
  - `io.copy_tree(src, dst)`
  - `io.stage_tree(src, dst)`
  - `io.remove(path)`
  - `io.remove_file(path)`
  - `io.stat_size(path)`
  - `io.stat_mtime(path)`
  - `io.temp_file(prefix)`
  - `io.list_dir(path)`
  - `io.list_dir_entries(path)`
- `use core.path;` is the canonical path helper import marker:
  - `path.join(base, child)`
  - `path.normalize(path)`
  - `path.basename(path)`
  - `path.dirname(path)`
  - `path.stem(path)`
  - `path.extension(path)`

## Boundary JSON And Logging Ergonomics

- First-class object literals are supported and lower to canonical map primitives:
  - `#{ "component": json.str("api"), "phase": json.str("boot") }`
- Typed structs/enums remain the source of truth for internal state; JSON builders exist for transport, persistence interchange, and operator-facing machine output.
- Object literal keys must be quoted strings.
- Canonical string assembly uses `str.concat(...)`.
  - `str.concat("a", "b")`
  - `str.concat("svc/", tenant, "/sessions/", session_id)`
  - `str.concat2/3/4` remain stable, but `str.concat(...)` is the primary general form.
  - `+` is not defined for strings; diagnostics should steer authors toward `str.concat(...)`.
- Canonical substring extraction uses end-exclusive slicing:
  - `str.slice(value, start, end_exclusive)`
  - `str.slice("name", 1, 3)` yields `"am"`
- Dynamic JSON builders are boundary tools:
  - `json.array(list_handle)`
  - `json.object(map_handle)`
- Dynamic parsed-JSON iteration is first-class at the boundary:
  - `json.keys(json_handle)` for object key iteration
  - `json.to_map(json_handle)` for object shapes whose values are strings
  - `json.to_list(json_handle)` for array shapes whose items are strings
- Transcript-style CLI UX should prefer one output stream for conversational ordering.
  - Use `term.print*` / `term.transcript_kv` for transcript lines.
  - Reserve `term.write_err` / `term.eprint*` for real errors or control-channel messages.
- For inbound HTTP JSON, `http.body_json(conn)` is the canonical production path.
  - Prefer `let body = http.body_json(conn)` over `json.parse(http.body(conn))`.
  - Convert boundary data into typed request/domain values before service logic runs.
  - Do not keep normal service logic on `JsonHandle` state after the boundary decode step.
  - Use `http.body(conn)` when you explicitly need the raw transport body as text.
  - Use the raw-body path for generic protocol surfaces, signature-sensitive payloads, or custom transport bridges where exact incoming text matters.
  - Typical handler shape:

```fzy
use core.http;

struct MessageRequest {
    message: str,
}

fn handle(conn: HttpHandle) -> i32 {
    http.read(conn)
    let body = http.body_json(conn)
    let req = MessageRequest { message: json.get_str(body, "message") }
    let field_count = list.len(json.keys(body))
    let payload = map.new()
    discard map.set(payload, "ok", json.raw("true"))
    discard map.set(payload, "message", json.str(req.message))
    discard map.set(payload, "field_count", json.str(str.from_i32(field_count)))
    return http.write_json(conn, 200, json.object(payload))
}
```

- Outbound request headers are explicit and runtime-owned:
  - `http.header_set("authorization", "Bearer ...")`
  - `http.header_set("x-request-id", "abc123")`
  - queued headers apply to the next `http.post_json`, `http.post_json_capture`, `http.post_json_stream`, or `http.request_stream` call, then reset.
- Outbound streaming HTTP is first-class in the native runtime:
  - `http.post_json_stream(endpoint, body_json) -> HttpStreamHandle`
  - `http.request_stream(method, endpoint, body) -> HttpStreamHandle`
  - `http.stream_read(handle, max_bytes) -> str`
  - `http.stream_read_line(handle) -> str`
  - `http.stream_eof(handle) -> i32`
  - `http.stream_status(handle) -> i32`
  - `http.stream_error(handle) -> str`
  - `http.stream_close(handle) -> i32`
- SSE-style integrations should prefer line-by-line stream consumption:
  - queue `accept: text/event-stream` with `http.header_set(...)`
  - open the stream with `http.post_json_stream(...)` or `http.request_stream(...)`
  - consume ordered event lines with `http.stream_read_line(...)`
  - use blank lines as event boundaries and `http.stream_eof(...)` for completion
- `core.http` also provides helper types for production call sites:
  - `JsonPayload`
  - `post_json_capture_payload(...)`
  - `post_json_stream_payload(...)`
  - `SseEvent`
  - `sse_next(stream)`
- List/map value construction is first-class:
  - `list.new/push/pop/len/get/set/clear/join`
  - `map.new/set/get/has/delete/keys/len`
- Structured logging fields use `log.fields(map_handle)` as the primary path.
- Path-safe assembly should prefer path primitives over raw string surgery:
  - `path.join(base, child)`
- Directory discovery should prefer the stdlib IO facade:
  - `io.list_dir(path)`
  - `io.list_dir_entries(path)`

## String Escape Sequences

- Supported string and char escapes:
  - `\\`
  - `\"`
  - `\'`
  - `\n`
  - `\r`
  - `\t`
  - `\0`
  - hex byte/scalar form: `\xNN`
  - fixed-width Unicode form: `\uNNNN`
  - braced Unicode scalar form: `\u{NN...}`
  - octal form: `\NNN` with 1-3 octal digits
- Terminal/control-character authoring should prefer `\x1b` or `\u001b` over raw literal escape bytes in source.
  - `path.normalize(path)`
  - `path.basename(path)`
  - `path.dirname(path)`
  - `path.stem(path)`
  - `path.extension(path)`

### String And Path Assembly

- Canonical string assembly uses `str.concat(...)`.
  - `str.concat("svc/", tenant, "/sessions/", session_id)`
  - `str.concat2/3/4` remain stable, but `str.concat(...)` is the primary general form.
  - `+` is not defined for strings; diagnostics should steer authors toward `str.concat(...)`.
- Use `str.from_i32(...)` and `str.from_bool(...)` for everyday diagnostics, labels, and config rendering work.
- Prefer `path.*` helpers over manual slash concatenation in production code.
  - `path.join` and `path.normalize` are the canonical path-construction surface.
  - `path.basename`, `path.dirname`, `path.stem`, and `path.extension` are the canonical decomposition surface.

```fzy
let label = str.concat(
    "worker=",
    str.from_i32(worker_id),
    " healthy=",
    str.from_bool(healthy),
)
let checkpoint = path.join("/var/lib/myservice", "checkpoint.json")
let ext = path.extension(checkpoint)
```

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

## Traits And Generics (v1 Contract)

- Trait declarations support signature-only methods:
  - `trait Name { fn method(...) -> ...; }`
- Trait declarations support associated types/constants:
  - `trait Name { type Item; const LIMIT: i32; ... }`
- Trait impl declarations support concrete impl targets:
  - `impl Trait for Type { fn method(...) -> ... { ... } }`
- Trait impls support associated item definitions:
  - `impl Trait for Type { type Item = ...; const LIMIT: i32 = ...; ... }`
- Impl methods are lowered as callable symbols using canonical `<Type>.<method>` naming.
- Method dispatch supports canonical type-qualified calls (`Type.method(...)`) and receiver-name resolution when receiver type is statically known.

### Trait Conformance

- Impl must reference an existing trait.
- Impl must provide all required trait methods.
- Impl must not define extra methods not declared by the trait.
- Method parameter count and parameter types must match trait declaration.
- Method return type must match trait declaration.
- In v1, impl methods for trait requirements must not be generic, async, or unsafe.

### Trait Coherence (v1)

- Trait impl targets must be concrete (non-type-variable) types.
- Overlapping impl targets for the same trait are rejected.
- Generic bound resolution is rejected when multiple impls match (ambiguous bound).

### Generic Bound Rules

- Function generic bounds must reference existing traits.
- Generic declarations/usages are supported across structs/enums/functions/methods and trait/impl headers.
- Generic calls support common call-site type-argument inference in production mode.
- Explicit specialization remains supported in production mode.
- Invalid specialization syntax and specialization arity mismatches are hard errors.
- Bound failures and ambiguous bound matches are hard errors.

### Monomorphization Controls (v1)

- Specialized symbols are canonicalized and deduplicated.
- Monomorphization enforces recursion-depth and specialization-count limits with explicit diagnostics.

### Hard-Rejected In v1

- Trait default method bodies.
- Generic trait methods.

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
- Module-qualified value and type references use dot paths in ordinary code:
  - `model.types.CONST_VALUE`
  - `model.types.helper(...)`
  - `-> model.types.ProjectKind`
- Import declarations continue to use `::` path syntax.
- Associated-item syntax such as `Self::Item` remains valid where the type system requires it.

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

- Test blocks are discovered from parsed module trees and executed as real compiled test bodies by `fz test`.
- Deterministic tests (`test "..." {}`) run under `fz test --det`.
- `nondet` tests run in the non-deterministic/native test surface when `fz test` is invoked without `--det`.
- Test bodies compile as normal statement blocks and may call project functions/modules.
- Reporting includes per-test execution summaries when trace/report artifacts are requested.

## Deterministic Scheduling Model

- `det` mode uses deterministic scheduler policies: `fifo`, `random` (seeded), `coverage_guided`.
- Scheduling decisions are recorded as replay-critical trace data.
- Async checkpoints and RPC frame decisions are represented as deterministic events.
- v1 model controls explicit runtime scheduling points and does not claim arbitrary OS-preemptive interleaving coverage.

### Yieldpoint Definitions (Deterministic Trace Contract)

- The following constructs are explicit yield/interleaving points for deterministic async traces: `await`, `yield()`, `checkpoint()`, `spawn(...)`, `recv()`, `timeout(ms)`, `deadline(ms)`, `cancel()`, `pulse()`.
- Parity and trace-analysis normalization use deterministic event categories:
  - `thread.schedule`
  - `async.checkpoint`
  - `rpc.frame`
  - `test.event`
  - `test.assert`
- Normalization rule: engine-specific `async.schedule` is normalized to `async.checkpoint` before parity or trace comparison.

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
