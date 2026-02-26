# Language Stability Tiers v1

## Tiers

- `core_v1`:
  - default production tier
  - only Core v1 semantics are allowed
  - experimental semantics are rejected with hard diagnostics
- `experimental`:
  - requires explicit opt-in in `fozzy.toml`
  - enables language shapes that are not part of Core v1 guarantees

## Manifest Contract

```toml
[language]
tier = "core_v1"          # or "experimental"
allow_experimental = false
```

Rules:

- `tier` must be `core_v1` or `experimental`
- `tier = "experimental"` requires `allow_experimental = true`
- production guidance is `core_v1` for release builds

## Operational Policy

- `fz check|verify|build|run|test` enforce tier gating.
- A module using experimental semantics under `core_v1` fails with an actionable diagnostic.
- There is no compatibility fallback for tier violations.
