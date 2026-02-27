# Language Stability Tiers v1

## Tiers

- `core_v1`:
  - default production tier
  - only Core v1 semantics are allowed
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
- Manifest-level tier/opt-in contract violations fail with actionable diagnostics.
- Construct-level validity is enforced by parser/HIR/verifier/native lowerability diagnostics (no legacy shape-scanner gate path).
- There is no compatibility fallback for tier violations.
