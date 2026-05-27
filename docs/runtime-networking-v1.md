# Runtime Networking v1

## Layering Contract

- Runtime and stdlib own transport/runtime primitives.
- HTTP framework behavior is library-level and must consume stdlib/runtime primitives instead of introducing alternate socket semantics.

## Stability Guarantees

- `bind`, `listen`, `accept`, `connect`, `read`, `write`, `close` are stable API operations in v1.
- Socket ownership is explicit: listener sockets are runtime-owned; accepted/connected sockets are application-owned until `close`.
- Cancellation/deadline checks are request-context scoped and stable in both host and deterministic modes.
- Graceful shutdown semantics are stable: stop accepting new requests, drain in-flight requests, stop at configured timeout.
- Network replay decisions are stable event categories: accept ordering, read chunk boundaries, timeout ordering, close/reset events.

## Poller Contract

- Backends expose readiness via `poll_register` and `poll_next`.
- Poll queues are bounded and must return queue-pressure errors instead of unbounded growth.
- Host backend may map to platform pollers (`epoll`/`kqueue` equivalent behavior); deterministic backend replays recorded readiness decisions.

## HTTP/1.1 Server Baseline

- Parser supports request line + headers + body with configured limits.
- Router hooks are framework-agnostic via request/response structs and routing trait.
- Keepalive policy is explicit and bounded (`keepalive_max_requests`).
- Native host-backed runtime bind defaults are explicit: host `127.0.0.1`, port `8787`.
- Native host-backed runtime must emit effective listen target (`addr`, `port`, source) at startup.
- Inbound JSON request handlers should use `http.body_json(conn)` as the primary decode surface.
- `json.parse(http.body(conn))` is valid but is not the preferred production path for normal JSON APIs.
- Raw-body handling (`http.body(conn)`) is the preferred escape hatch for generic protocol endpoints, signature-sensitive requests, or bridge/adaptor layers that must preserve exact transport text.
- Runtime stability work and regressions are keyed to the direct `http.read(conn)` -> `http.body_json(conn)` -> `json.get*` flow.
- When a handler stays on the raw-body path, document why exact transport preservation is required instead of normal typed JSON decode.

## Runtime Env Ergonomics

- Native runtime bootstraps process env from `.env` (or `FZ_DOTENV_PATH`) once before env/http lookups.
- Provider-bound HTTP primitives should fail early with explicit missing-key diagnostics before transport invocation.
- Native HTTP transport must preserve transport diagnostics via `http.last_error`.
- On malformed transport output (missing HTTP status trailer), runtime sets deterministic failure status (`599`) instead of silent `0` status.
- Native HTTP transport uses robust curl execution fallback paths (`curl`, `/usr/bin/curl`, `/opt/homebrew/bin/curl`) with bounded timeout defaults.
- Native outbound streaming transport is supported for long-lived response bodies:
  - `http.post_json_stream(endpoint, body_json)`
  - `http.request_stream(method, endpoint, body)`
  - `http.stream_read_line(handle)` for ordered line/event consumption
  - `http.stream_status(handle)` and `http.stream_error(handle)` for transport inspection
  - `http.stream_close(handle)` for explicit shutdown
- SSE clients should treat blank lines as event boundaries and use `http.stream_eof(handle)` as the completion signal.

## Runtime Logging Defaults

- Default log output is human-readable text lines (`[ts] level message`).
- Structured log fields are appended as `| fields={...}`.
- JSON log mode is opt-in only (`log.set_json(1)`).
- Services should avoid unnecessary per-request artifact churn on hot paths.
- When richer request logging is required, prefer bounded structured fields and JSON responses over ad hoc repeated string re-encoding.

## TLS Boundary Strategy

- `Disabled`: cleartext only.
- `ProxyTerminated`: TLS terminated before app boundary with trusted proxy forwarding policy.
- `NativeAdapter`: TLS managed by adapter boundary before request parsing.

## Non-goals (v1)

- HTTP/2 or HTTP/3 semantics.
- Cross-platform zero-copy transport tuning claims.
- Kernel-specific readiness optimization promises beyond bounded-event contract.
