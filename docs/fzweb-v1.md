# fzweb V1

`fzweb` is the core-team framework package at `frameworklib/fzweb`.

## Production Shape

- Concern-grouped modules (not one-file-per-function).
- Deterministic hot path.
- Rust-backed `core.http` transport usage through `webcore` wrappers.
- First-class `core.log` structured logging in live server path.
- Request/response/routing modules with deterministic live-server contracts.
- Host-backed readiness via `http.poll_register` + `http.poll_next` + `http.read`.
- Route-aware auth/rate behavior for public endpoints and stricter request-body policy.
- Production modules for cookies, opaque sessions, multipart uploads, persistence, event streaming, websockets, and declarative app routing.

## Module Groups

- `src/webcore/mod.fzy`
- `src/app/mod.fzy`
- `src/cookies/mod.fzy`
- `src/request/mod.fzy`
- `src/persistence/mod.fzy`
- `src/response/mod.fzy`
- `src/routing/mod.fzy`
- `src/sessions/mod.fzy`
- `src/multipart/mod.fzy`
- `src/streaming/mod.fzy`
- `src/middleware/mod.fzy`
- `src/support/mod.fzy`
- `src/main.fzy`

## Built-In Production Routes

- `GET /`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /inspect`
- `GET /search`
- `POST /echo`
- `GET /v1/echo/:name`
- `POST /bind`
- `GET /version`
- `GET /cookies/set`
- `POST /session/login`
- `GET /session/me`
- `POST /upload`
- `GET /events`
- `GET /ws`
- `GET /v1/items`
- `GET /v1/items/:id`
- `PUT /v1/items/:id`
- `PATCH /v1/items/:id`
- `DELETE /v1/items/:id`
- `GET /openapi.json`
- `GET /static/:name`

## Validation Commands

- `python3 scripts/verify_fzweb_framework.py`
- `fz doctor --deep --scenario tests/fzweb.framework.pass.fozzy.json --runs 5 --seed 20260227 --json`
- `fz test --det --strict-verify tests/fzweb.framework.pass.fozzy.json --json`
- `fz run tests/fzweb.framework.pass.fozzy.json --det --record artifacts/fzweb.framework.trace.fozzy --json`
- `fz trace verify artifacts/fzweb.framework.trace.fozzy --strict --json`
- `fz replay artifacts/fzweb.framework.trace.fozzy --json`
- `fz ci artifacts/fzweb.framework.trace.fozzy --json`
- `fz run tests/fzweb.framework.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`
