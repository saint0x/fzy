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

## Core v1 Trait/Generic and Macro Surface

- Traits and generics in `core_v1` are governed by `docs/traits-generics-contract-v1.md`.
- Supported generic surface in `core_v1`: generic declarations/usages across structs/enums/functions/methods/trait headers/impl headers, with common call-site inference and explicit specialization support.
- Supported trait surface in `core_v1`: concrete impl targets, associated types/constants, strict conformance/coherence checks, canonical method dispatch contract.
- Unsupported trait/generic shapes in `core_v1` are hard-rejected with diagnostics (for example trait default method bodies and generic trait methods).
- Macro model in `core_v1` is constrained to supported attributes (`#[repr(...)]`, `#[ffi_panic(...)]`); broader macro expansion remains out of scope.
