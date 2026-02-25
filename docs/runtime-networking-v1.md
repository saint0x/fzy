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

## Runtime Env Ergonomics

- Native runtime bootstraps process env from `.env` (or `FZ_DOTENV_PATH`) once before env/http lookups.
- Provider-bound HTTP primitives should fail early with explicit missing-key diagnostics before transport invocation.

## TLS Boundary Strategy

- `Disabled`: cleartext only.
- `ProxyTerminated`: TLS terminated before app boundary with trusted proxy forwarding policy.
- `NativeAdapter`: TLS managed by adapter boundary before request parsing.

## Non-goals (v1)

- HTTP/2 or HTTP/3 semantics.
- Cross-platform zero-copy transport tuning claims.
- Kernel-specific readiness optimization promises beyond bounded-event contract.
