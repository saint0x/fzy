# Compiler Hardening Checklist

Only unfinished work lives here. When a work item is done, remove it entirely.

## Active Queue

- `14. Compiler-phase lock-in suite`
- `22. Canary-app gates`

## Priority 6

### 14. Compiler-phase lock-in suite

Checklist:

- Finish user-module wildcard import lock-in on the same golden corpus instead of relying only on explicit import/re-export coverage.
- Add direct panic-resistance gates inside parser/HIR/verifier/native-lowerability crate tests so malformed programs are proven not to panic below the command layer.

Required tests:

- Direct crate tests that specifically cover the remaining wildcard-import and panic-resistance gaps.

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
