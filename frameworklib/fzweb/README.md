# fzweb

`fzweb` is the core-team web framework abstraction for FozzyLang.

## Design

- Lightweight hot path with deterministic dispatch.
- Full-featured middleware-ready surface.
- HTTP transport through `webcore.http` (Rust-backed path).
- First-class structured logging via `core.log` in live-server paths.
- First-class typed error capability surface via `core.error`.
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


## Live Server Entry

For now (before package publishing), use the in-tree live server entrypoint:

- Source: `frameworklib/fzweb/src/live_server_main.fzy`
- Build: `cargo run -q -p fz -- build frameworklib/fzweb/src/live_server_main.fzy --backend llvm --release --json`
- Run binary from the `output` path in the build JSON.
- Runtime behavior:
- Long-lived accept loop (`2_000_000_000` request budget) with cooperative yields.
- JSON structured server/request logging via `log.set_json(1)` and `log.info/log.warn`.
