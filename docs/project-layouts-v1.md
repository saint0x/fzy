# Project Layouts v1

These are the canonical production layouts for larger Fozzy codebases.

## CLI App

```text
src/
  main.fzy
  cli/
  services/
  model/
  tests/
```

## Service App

```text
src/
  main.fzy
  api/
  runtime/
  services/
  model/
  tests/
```

## FFI Library

```text
src/
  main.fzy
  api/
  ffi/
  model/
include/
```

Guidance:

- Keep exported `pubext c fn` declarations in `api/` or `ffi/`.
- Treat `include/*.h`, `*.abi.json`, and `*.artifacts.json` as generated embedding surfaces.

## Fullstack / Control Plane Runtime

```text
src/
  main.fzy
  api/
  runtime/
  services/
  model/
  cli/
  tests/
```

Guidance:

- Put route/schema/handler registration in one route catalog path.
- Keep transport-specific JSON shaping in `api/` or response helpers, not in business logic; `model/`, `services/`, and `runtime/` should keep typed source-of-truth state.
- Keep response/request DTOs and boundary encoders near the transport edge; do not let JSON builder code become the data model for the service.

## GPU Compute App

```text
src/
  main.fzy
  api/
  cli/
  model/
  runtime/
  services/
  tests/
```

Guidance:

- Keep `kernel fn ...` definitions and launch orchestration in `services/`.
- Keep grid/block sizing, expected outputs, and verifier-stable data contracts in `model/`.
- Keep device selection, backend summary, and operator-facing startup checks in `runtime/`.
- Keep CLI entrypoints in `cli/`; treat trace recording and deterministic validation as part of the normal run story, not a side workflow.
- Treat `.fz/gpu-kernel-package.{json,md}` as generated build artifacts that describe the shared backend-neutral launch contract.

## Reference

- `examples/service_app`
- `examples/fullstack`
- `examples/live_server`
- `examples/gpu_metal_image`
- `frameworklib/fzweb`
