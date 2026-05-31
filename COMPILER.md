# Compiler Hardening Checklist

Only unfinished work lives here. When a work item is done, remove it entirely.

## Active Queue

- `14. Compiler-phase lock-in suite`
- `15. Memory-safety adversarial coverage`
- `16. Native import contract tables`
- `22. Canary-app gates`
- `23. Unsafe/FFI audit hardening`
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

Required tests:

- HIR unit regressions for every new adversarial shape.
- `fz verify` fixtures that assert both failure class and stable diagnostic/help wording.
- Deterministic Fozzy memory scenarios that reproduce branch, loop, defer, and remaining ownership hazards.
- Recorded traces plus trace verify, replay, and CI for at least one adversarial memory suite per active goal.

## Priority 7

## Priority 8

## Priority 9

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
