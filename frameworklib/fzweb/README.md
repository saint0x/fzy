# fzweb

`fzweb` is the core-team web framework abstraction for FozzyLang.

## Design

- Lightweight hot path with deterministic dispatch.
- Production-shaped request/response/routing modules over `core.http`.
- Middleware and policy gates for auth, JSON validation, rate limiting, timeouts, and CORS preflight.
- First-class structured logging via `core.log` in live-server paths.

## Layout (Grouped by Concern)

- `src/webcore/mod.fzy`: low-level transport wrappers and response send helpers.
- `src/request/mod.fzy`: request readers, JSON/body helpers, query/param accessors, numeric parsing.
- `src/response/mod.fzy`: canonical JSON/text response helpers and envelope builders.
- `src/routing/mod.fzy`: deterministic route selection, route ids/names, OpenAPI route catalog.
- `src/middleware/mod.fzy`: timeout/log/auth/cors/validation/rate-limit policy logic.
- `src/support/mod.fzy`: live server loop, metrics, route handlers, configuration, support helpers.
- `src/main.fzy`: deterministic package tests and framework smoke surface.

## Core API

- `request.*` for route-time reads and parsing helpers.
- `response.*` for standard JSON/text responses and error envelopes.
- `routing.select`, `routing.route_name`, `routing.openapi_json`.
- `middleware.before_dispatch` and policy/rate helpers.
- `support.run_live_server` for the packaged production server entry.

## Built-In Routes

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /inspect`
- `GET /search?q=<text>&limit=<n>`
- `POST /echo`
- `GET /v1/echo/:name`
- `POST /bind`
- `PUT /v1/items/:id`
- `DELETE /v1/items/:id`
- `GET /openapi.json`
- `GET /static/:name`

## Live Server Entry

For now (before package publishing), use the in-tree live server entrypoint:

- Source: `frameworklib/fzweb/src/live_server_main.fzy`
- Build: `cargo run -q -p fz -- build frameworklib/fzweb/src/live_server_main.fzy --backend llvm --release --json`
- Run binary from the `output` path in the build JSON.
- Runtime behavior:
- Long-lived accept loop with bounded request budget and cooperative yields.
- Request readiness through `http.poll_register` + `http.poll_next` + `http.read`.
- JSON structured server/request logging via `log.set_json(1)` and `log.info`.
- Host-configurable auth, JSON validation, rate limit, timeout, and body-size policy via `FZWEB_*` env vars.
