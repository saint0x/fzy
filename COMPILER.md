# Compiler Hardening Checklist

Only unfinished work lives here. When a work item is done, remove it entirely.

## Active Queue

- `14. Compiler-phase lock-in suite`
- `22. Canary-app gates`

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

## Second-Wave v1 Lock-In

## Working Rule

- Remove completed items instead of annotating them.
- Keep at least one Fozzy trace lifecycle check attached to the active goal.
- Prefer strict deterministic Fozzy coverage first, then host-backed checks where the runtime surface matters.
