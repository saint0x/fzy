# Compiler Hardening Checklist

Only unfinished work lives here. When a work item is done, remove it entirely.

## Active Queue

- `22. Canary-app gates`

## Priority 6

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
