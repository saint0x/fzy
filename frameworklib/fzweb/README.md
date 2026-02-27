# fzweb

`fzweb` is the core-team web framework abstraction for FozzyLang.

## Design

- Lightweight hot path with deterministic dispatch.
- Full-featured middleware-ready surface.
- HTTP transport through `webcore.http` (Rust-backed path).
- Built-in concurrent probe/worker hooks using thread/task primitives.

## Layout (Grouped by Concern)

- `src/webcore/mod.fzy`: app signature, request/response primitives, routing, handler dispatch.
- `src/middleware/mod.fzy`: middleware flags, timeout/log/auth/cors/validation/rate-limit logic.
- `src/support/mod.fzy`: support utilities (openapi summary, compression/session/static helpers, defaults, errors).
- `src/main.fzy`: framework wiring and runtime profile.

## Core API

- `webcore.app_new/app_enable/app_get/app_post/app_all`
- `webcore.request_*`, `webcore.response_*`
- `webcore.route_select`, `webcore.handler_dispatch`
- `middleware.*` for opt-in behavior flags/policies.
