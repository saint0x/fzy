# Project Conventions v0

## Goals

- Keep `main.fzy` as a readable program story.
- Make module topology obvious from filesystem layout.
- Preserve explicit systems-language ergonomics with minimal magic.

## Required Layout

- `src/main.fzy`
- `src/api/mod.fzy`
- `src/model/mod.fzy`
- `src/services/mod.fzy`
- `src/runtime/mod.fzy`
- `src/cli/mod.fzy`
- `src/tests/mod.fzy`

## Main File Rules

- `main.fzy` declares module roots in this order:
  - `mod api;`
  - `mod model;`
  - `mod services;`
  - `mod runtime;`
  - `mod cli;`
  - `mod tests;`
- `fn main` must be the last top-level item.
- Test declarations are forbidden in `main.fzy`.

## Testing Placement

- All project tests belong under `src/tests/*`.
- `src/tests/mod.fzy` serves as the test module entry.

## Module Story

- `api`: boundary surface (FFI, RPC)
- `model`: types/contracts/invariants
- `services`: business/data/IO workflows
- `runtime`: task/scheduler/supervisor orchestration
- `cli`: operator command entrypoints
- `tests`: deterministic and chaos test declarations

## Enforcement

- Run `fozzyc dx-check <project> --strict`.
- `dx-check` fails when conventions are violated.
