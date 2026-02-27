# Compiler Diagnostics v1 (Production)

This document defines the production diagnostics contract for `fz` and `fz lsp diagnostics`.

## Goals

- Deterministic and enforceable diagnostics.
- Human-readable output with actionable remediation.
- Shared diagnostic model across CLI text, CLI JSON, and LSP.
- Stable diagnostic catalog lookups via `fz explain`.
- Repro token + repro command surfaced in text diagnostics.

## Schema

- Schema version: `fozzylang.diagnostics.v2`
- Core fields:
  - `severity`
  - `code`
  - `message`
  - `path`
  - `span`
  - `labels`
  - `notes`
  - `help`
  - `fix` and `suggested_fixes`
  - `snippet`

## Code Taxonomy

Codes are deterministic and stable for unchanged diagnostics.

Format:

- `<severity>-<domain>-<hash>`

Severity prefixes:

- `E` error
- `W` warning
- `N` note

Domain prefixes:

- `PAR` parser
- `HIR` type/lowering semantic checks
- `VER` verifier policy/safety checks
- `NAT` native lowerability checks
- `DRV` driver-level fallback and pipeline diagnostics

Catalog:

- `fz explain <code>` returns family guidance + catalog summary/example.
- `fz explain catalog` returns the typed catalog index (`fozzylang.diagnostic_catalog.v1`).

## Output Modes

### CLI Text

- Includes severity + code header.
- Includes source location and multi-line code frames when span is available.
- Includes related labels with related-location frames.
- Includes help, notes, and suggestions.
- Repeated unresolved/type-check findings are de-duplicated into grouped root diagnostics.
- Type-check cascade mode reports one primary cause and summarizes suppressed secondary roots/counts.
- Removed-API unresolved calls include migration autofix guidance where possible (for example fixed-arity JSON/log helper removals).

### CLI JSON (`fz check --json`, `fz verify --json`)

- Emits diagnostics under `items` with schema version.
- Intended for machine parsing and CI gating.

### LSP

- Uses LSP diagnostics with:
  - `code`
  - `relatedInformation`
  - `codeDescription`
  - `data` payload carrying notes/help/fixes/labels/snippet
- `fz lsp diagnostics` text mode prints full diagnostic bodies.

## Source Anchoring Policy

- Semantic spans are preferred and treated as source of truth.
- If semantic span is unavailable, compiler attempts evidence-based anchor derivation from diagnostic tokens found in source.
- Derived anchors are marked in notes so consumers know provenance.

## Production Gate (Diagnostics)

Recommended minimal gate for diagnostics changes:

1. `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 1337 --json`
2. `fozzy test --det --strict tests/example.fozzy.json --json`
3. `fozzy run tests/example.fozzy.json --det --seed 1337 --record artifacts/diagnostics.trace.fozzy --json`
4. `fozzy trace verify artifacts/diagnostics.trace.fozzy --strict --json`
5. `fozzy replay artifacts/diagnostics.trace.fozzy --json`
6. `fozzy ci artifacts/diagnostics.trace.fozzy --json`
7. `fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`

## Regression Classes (Required)

At minimum keep regressions for:

- unresolved call targets
- unresolved call target nearest-symbol suggestions (`did you mean ...`)
- generic bound failures
- struct field resolution
- enum variant resolution
- match exhaustiveness/unreachable arms
- capability violations
- FFI boundary diagnostics
