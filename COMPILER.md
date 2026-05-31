# Compiler Hardening Checklist

Only unfinished work lives here. When a work item is done, remove it entirely.

## Active Queue

- `14. Compiler-phase lock-in suite`
- `15. Memory-safety adversarial coverage`
- `16. Native import contract tables`
- `17. Typed-handle and linear-resource law`
- `18. Async/task safety`
- `19. RPC hardening`
- `20. Backend parity law`
- `21. Diagnostic stability`
- `22. Canary-app gates`
- `23. Unsafe/FFI audit hardening`
- `24. Trace/replay compatibility system`
- `25. v1 syntax and profile freeze`
- `26. Stdlib and capability policy`
- `27. Error/perf/docs/compat policy`

## Priority 6

### 14. Compiler-phase lock-in suite

Checklist:

- Build a golden corpus covering lexer, parser, AST shaping, HIR typing/effects, FIR lowering, verifier outcomes, native lowerability, LLVM output, Cranelift output, and runtime shim linking.
- Add positive and negative coverage for every phase.
- Lock diagnostics, verify/build behavior, parity-supported backend agreement, module import resolution, and cache invalidation behavior.
- Add regression classes for multi-file projects, nested modules, public and wildcard imports, manifest-root discovery, dependency-graph hashing, and module-cache invalidation.
- Add panic-resistance gates so invalid programs emit diagnostics instead of Rust panics across parser, HIR, verifier, and driver/native-lowerability paths.

Required tests:

- Direct crate tests for parser, AST, HIR, FIR, and verifier behavior.
- `fz check`, `fz verify`, `fz build`, and `fz parity` fixture coverage for the same corpus.
- Strict deterministic Fozzy doctor/test coverage for representative compiler scenarios.
- At least one recorded trace for the active compiler-regression suite, followed by strict trace verify, replay, and CI.
- Host-backed runs for compiler/runtime integration scenarios where native linking and runtime shim behavior matter.

### 15. Memory-safety adversarial coverage

Checklist:

- Finish promoting any remaining aggregate, provenance, and ownership-state shapes that are still only HIR-covered or partially regression-covered at the shipped `fz verify` surface.
- Finish bringing any still-unlocked shipped runtime handle families under the same ownership-state, cleanup, and post-consume law as `alloc(...)` and `free(...)`.

Required tests:

- HIR unit regressions for every new adversarial shape.
- `fz verify` fixtures that assert both failure class and stable diagnostic/help wording.
- Deterministic Fozzy memory scenarios that reproduce branch, loop, defer, and thread/await lifetime hazards.
- Recorded traces plus trace verify, replay, and CI for at least one adversarial memory suite per active goal.

## Priority 7

### 16. Native import contract tables

Checklist:

- Define full native-import metadata for every import: name, arity, argument ownership, return ownership, capability required, linear-resource behavior, error behavior, trace behavior, and blocking or nonblocking behavior.
- Make the compiler consume this metadata for ownership-transfer, cleanup, capability, unsafe, and native-lowerability checks.
- Harden and document `http.stream_close`, `http.websocket_close`, `proc.close`, `proc.wait`, `proc.poll`, `task.group_join_all`, `task.group_cancel`, `fs.atomic_write`, and `storage.atomic_append`.
- Add contract-validation tests that fail if an intrinsic exists in HIR without a full native contract, or if the contract and runtime shim disagree.

Required tests:

- Import-table schema and unit tests.
- Verifier and driver regressions asserting that consuming calls really consume handles.
- Native runtime shim build tests covering the full declared import surface.
- Host-backed scenarios for close, wait, poll, stream, and atomic-write behaviors.

### 17. Typed-handle and linear-resource law

Checklist:

- Finish defining the shipped handle set and contract for any still-unlocked handle families such as `FileHandle`.
- For each handle, declare whether it is copy, owned, linear, closable, send-safe, and async-stable.
- Make those handle rules visible to HIR, verifier, stdlib docs, runtime shim contracts, and diagnostics.
- Reject any runtime or helper path that consumes or aliases a handle in a way the handle matrix does not permit.

Required tests:

- Per-handle type, lifetime, and cleanup regressions.
- Backend parity tests using representative handle operations.
- Stdlib contract doc generation or validation from the same metadata source.

## Priority 8

### 18. Async/task safety

Checklist:

- Enforce owned and send-safe `spawn` inputs.
- Require task groups to join, cancel, or detach.
- Make timeout and deadline semantics deterministic.
- Ensure cancelled tasks clean resources.
- Keep task handles linear.
- Prevent references from crossing task boundaries unless explicitly legal.
- Reject result reads after cancel or detach unless the language explicitly permits them.
- Harden the call-edge model for borrow, mutability, and thread crossings beyond same-function checks where feasible.
- Define one explicit state machine for task handles, task groups, and cancel, join, detach, and result-read legality.
- Make async-safety artifacts report enforced policy rather than inferred observations.

Required tests:

- Test programs for spawn leak, double join, join after cancel, detach then result read, group without join, group cancel with open resources, and timeout around stream, process, and HTTP surfaces.
- Deterministic scheduler coverage across `fifo`, `random`, and `coverage_guided`.
- Trace verification that async schedule and task-group terminal policy are deterministic and replayable.

### 19. RPC hardening

Checklist:

- Harden RPC declaration parsing, RPC ABI lowering, request and response ownership, deadline policy, cancel policy, frame trace emission, error normalization, method-name stability, and payload type checking.
- In strict and production mode, require every RPC method to have a deadline policy, every handler to have a cancel-cleanup policy, every frame to be traceable, and request-body ownership to be explicit.
- Generate machine-readable RPC safety artifacts from enforced compiler facts rather than placeholders.
- Add parity and replay coverage for RPC behavior across deterministic and host-backed flows.

Required tests:

- Parser, HIR, and verifier regressions for valid and invalid RPC declarations.
- Strict `fz verify` fixtures for deadline, cancel, and ownership failures.
- Deterministic RPC trace scenarios with ordered frame assertions.
- Replay and CI validation for representative RPC request, cancel, and deadline paths.

## Priority 9

### 20. Backend parity law

Checklist:

- Add parity suites that assert same source, same exit code, same stdout/stderr, same verifier result, and same runtime behavior.
- Cover at minimum integer ops, float ops, strings, structs, enums, matches, loops, closures, arrays, JSON handles, HTTP handles, process handles, `defer`, and unsafe boundaries.
- If any feature is not parity-guaranteed, mark it explicitly in docs, diagnostics, and backend-capability reporting.
- Add backend, link, and runtime-shim parity checks for native library builds as well as executables.

Required tests:

- Direct `fz parity` fixtures for each supported category.
- Host-backed runs where runtime behavior matters.
- At least one real canary app per backend in CI.

### 21. Diagnostic stability

Checklist:

- Require every important diagnostic class to answer what happened, where, why it is unsafe or invalid, what state was expected, and how to fix it.
- Add snapshot tests for compiler, verifier, and native-lowerability diagnostics so wording, codes, help text, and catalog keys remain stable unless intentionally changed.
- Prioritize ownership, borrow, async/task, RPC, capability, module-resolution, backend-parity, and FFI diagnostics for first-wave snapshot coverage.
- Add wording guidance for common ownership and resource failures so errors name both the consuming site and the invalid later use.

Required tests:

- Text and JSON snapshot tests.
- `fz explain` catalog regressions.
- LSP diagnostics schema regressions for the same catalog classes.

## Priority 10

### 22. Canary-app gates

Checklist:

- Define and keep green canary apps for `fzyagent`, `superctx`, a small HTTP server, a small RPC server, a process supervisor, a streaming client, and a SQLite-backed state service.
- Require compiler, runtime, and backend changes to compile and run these apps before stronger production language claims.
- Attach at least one deterministic and one host-backed validation path to each canary class that exercises its core runtime surface.

Required tests:

- Canary-app build matrix across supported backends where applicable.
- Smoke tests via `fz run` and built binaries.
- Deterministic doctor/test plus trace verify, replay, and CI for representative canary flows.

### 23. Unsafe/FFI audit hardening

Checklist:

- Require unsafe sites to carry reason, owner, owner_id, scope, invariant, risk_class, and proof_ref.
- Require FFI contracts to enforce ownership annotation for pointers, len pairing for buffers, context anchors for callbacks, no extern-C async imports, `repr(C)` for ABI-crossing structs, and declared panic behavior.
- Ship first-class `fz audit unsafe`, `fz audit ffi`, and `fz audit memory` commands.
- Make those commands emit both JSON and markdown from the same underlying contract data.

Required tests:

- Verifier and driver contract regressions.
- JSON schema tests for audit outputs.
- Fozzy scenarios that fail on missing or invalid proof, ownership, or FFI metadata.

### 24. Trace/replay compatibility system

Checklist:

- Harden trace schema fields for schema version, scheduler, seed, execution order, async schedule, RPC frames, runtime events, causal links, and capability set.
- Add validation rules for schema validity, replay success, trace matches run, ordered RPC frames, deterministic async schedule, and matching checkpoint count.
- Version and publish the compatibility set: FZY language version, trace schema version, manifest schema version, runtime ABI version, native import table version, and diagnostic catalog version.
- Ensure produced artifacts include the relevant versions so breakage is explicit rather than inferred.

Required tests:

- Trace schema validation tests.
- Replay compatibility tests across representative artifact versions when introduced.
- Deterministic Fozzy trace lifecycle for every active hardening area.

## Second-Wave v1 Lock-In

### 25. v1 syntax and profile freeze

Checklist:

- Declare the syntax freeze set for `fn`, `let` and `let mut`, `struct`, `enum`, `match`, `trait` and `impl`, `async` and `await`, `rpc`, unsafe metadata, `defer`, `use core.*`, and `extern` and `pubext` ABI syntax.
- After freeze, permit additive changes only unless the version policy says otherwise.
- Extend profile policy so the shipped story is explicit for `dev`, `verify`, `release`, and a production-facing `strict` contract that defines checks enabled, unsafe policy, backend, capabilities, runtime imports allowed, artifact emission, optimization level, and diagnostic strictness.

### 26. Stdlib and capability policy

Checklist:

- Define per-module contracts for at least `core.mem`, `core.http`, `core.proc`, `core.fs`, `core.thread`, `core.time`, `core.crypto`, `core.json`, and `core.log`.
- For each contract, specify capability, ownership behavior, error behavior, linear handles, cleanup requirement, thread-safety, and async-safety.
- Strengthen capability propagation so calls require the capabilities they actually exercise, and capability-token delegation is enforced as compiler-visible authority rather than documentation.
- Lock in the JSON rule: JSON at boundaries, typed structs and enums inside.
- Add strict-mode warnings or failures for unsafe `json.raw` misuse, path traversal hazards, shell and process construction hazards, temp-file and atomic-write hazards, header normalization gaps, raw-injection hazards, and constant-time-compare misuse.

### 27. Error/perf/docs/compat policy

Checklist:

- Define and document the v1 error idiom around `Result<T, Error>`, `Status`, `ErrorClass`, `ExitStatus`, and `RuntimeError`.
- Benchmark real FZY workloads rather than generic micro-optimizations: CLI startup, HTTP throughput, JSON build and parse, process spawn and wait, stream reading, task-group execution, compiler parse, lower, and build time, and native binary size.
- Generate docs from implementation-backed sources where possible: AST nodes, native runtime table, capability table, verifier rules, diagnostic catalog, and stdlib contract metadata.
- Treat the compatibility set as part of release gating: language version, trace schema version, manifest schema version, runtime ABI version, native import-table version, and diagnostic catalog version.

## Working Rule

- Remove completed items instead of annotating them.
- Keep at least one Fozzy trace lifecycle check attached to the active goal.
- Prefer strict deterministic Fozzy coverage first, then host-backed checks where the runtime surface matters.
