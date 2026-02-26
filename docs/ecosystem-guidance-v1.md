# Ecosystem Guidance v1

## Interoperability Direction

- External languages/frameworks should integrate through stabilized C ABI surfaces.
- Do not couple directly to internal runtime shims.
- Treat `pubext c fn` + ABI manifests as the compatibility boundary.

## Compatibility Rules

- ABI contract weakening is breaking.
- Panic boundary policy (`abort|error`) is part of compatibility checks.
- Non-`repr(C)` layout is internal/unstable.

## Recommended Integration Workflow

1. Define C-facing API in Fzy with `pubext c fn`.
2. Generate headers and ABI manifests via `fz headers`.
3. Gate changes using `fz abi-check --baseline`.
4. Keep deterministic trace evidence for boundary workflows:
   - `fozzy run --det --record ...`
   - `fozzy trace verify --strict ...`
   - `fozzy replay ...`
   - `fozzy ci ...`
