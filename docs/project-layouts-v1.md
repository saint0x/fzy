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
- Keep transport-specific JSON shaping in `api/` or response helpers, not in business logic.
- Prefer object-literal JSON construction (`json.object(#{...})`) for static payloads.

## Reference

- `examples/service_app`
- `examples/fullstack`
- `examples/live_server`
- `frameworklib/fzweb`
