# Safe Profile v0

## Guarantees

- Unsafe capabilities (`time`, `rng`, `fs`, `net`, `proc`, `mem`, `thread`) are rejected in safe profile verification.
- Host syscall usage is rejected in safe profile.
- Explicit unsafe escape markers are rejected in safe profile.
- Reference-region sites without proof are rejected in safe profile.
- Alloc/free lifecycle imbalance is rejected in safe profile.
- Unsafe sites without explicit reason strings are rejected in safe profile.

## Rejected Patterns

- `unsafe` escapes without reason strings.
- Host syscall markers (`syscall.*`) without strict boundary policy.
- Capability usage not permitted by safe-profile rules.
- Memory lifecycle imbalance (`alloc` without matching `free`).

## Out Of Scope In v0

- Full alias/lifetime theorem proving.
- Complete data-race freedom proofs for all shared-memory patterns.
- Exhaustive inter-procedural pointer provenance analysis.

## Reference Lifetime Annotations

- Safe profile requires explicit lifetime names on references (for example, `&'req str` or `&'buf mut u8`).
- Returning a reference requires matching annotated region proof from an input or another proven binding.
- Missing annotations or mismatched return lifetimes are verifier violations.

## Unsafe Reason Syntax

Preferred forms for auditable unsafe reasons:

- `unsafe("reason text")`
- `unsafe_reason("reason text")`

`fozzyc audit unsafe` emits `.fozzyc/unsafe-map.json` and fails if any unsafe site is missing a reason.
