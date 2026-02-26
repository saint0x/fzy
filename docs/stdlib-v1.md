# Stdlib v1

## Scope

The v1 stdlib provides production baseline primitives for:

- networking + HTTP core + deterministic replay surface
- structured observability (logs, metrics, spans)
- process/config/signal controls
- durable filesystem and bounded streaming IO
- bounded concurrency/synchronization/pooling
- security defaults and capability-gated privileged operations
- deploy/runtime profile and manifest conventions

## Stability Guarantees

- Public API contracts in `crates/stdlib/src/*.rs` are semver-stable for v1 behavior.
- `Host` and `Deterministic` runtime modes preserve app API parity; only decision sources differ.
- Security defaults are fail-closed for limits and capability gates.
- Durability primitives keep atomic-write and lock-contention behavior stable.

## Module Contracts

### `core`

- `require_capability(token, required) -> Result<(), CapabilityError>`
- `parse_capability(name) -> Result<Capability, CapabilityError>`
- `revoke_capability(token, name) -> Result<(), CapabilityError>`
- `delegate_capability(token, subset) -> Result<CapabilityToken, CapabilityError>`
- Errors:
  - `CapabilityError::Missing(<cap>)`
  - `CapabilityError::Parse(<name>)`

### `c`

- Provides C-boundary helper primitives:
  - pointer+length borrowed/out views
  - ownership labels (`owned|borrowed|out|inout`)
  - callback/context binding metadata helpers
- Intended as the canonical interop utility surface for `pubext` exports.

### `io`

- `read_to_string_with_capability(path, token) -> Result<String, CapabilityError>`
- `write_atomic(path, bytes) -> Result<(), IoError>`
- `list_dir(path) -> Result<Vec<String>, IoError>`
- `metadata(path) -> Result<FileMetadata, IoError>`
- `remove(path) -> Result<(), IoError>`
- `read_stream` / `write_stream` APIs are bounded and deterministic-backend compatible.
- Errors:
  - Backend errors are mapped to structured `IoError` variants with path context.

### `durability`

- `required_capability_for_durable_fs() -> Capability`
- `write_atomic_with_capability(path, bytes, token) -> Result<(), CapabilityError>`
- Contract:
  - Writes are all-or-nothing under supported host filesystems.
  - Locking and rename semantics are deterministic under replay backends.

### `network`

- Polling/socket APIs support host and deterministic backends with parity goals.
- Supported v1 behavior includes IPv4/IPv6, DNS lookup, UDP, Unix sockets, and socket options.
- Errors are returned as explicit network/backend failures; deterministic backend can inject controlled failures.

### `http`

- HTTP/1.1 parsing/serving includes chunked transfer and `Expect: 100-continue` behavior.
- Request/response size and timeout limits are bounded by default.
- Error semantics preserve parse vs timeout vs IO separation.

### `concurrency`

- `BoundedChannel<T>` supports backpressure and overflow policies.
- Synchronization primitives include mutex/condvar/semaphore/barrier/once-cell surfaces.
- Deterministic hooks provide replay-visible synchronization decisions.
- Errors:
  - Channel send/recv return explicit queue/full/disconnected state variants.

### `process`

- `run_child_with_capability(config, token) -> Result<ProcessResult, CapabilityError>`
- Structured process config supports argv/env/stdin/resource limits/signal behavior.
- Timeout and cancellation states are explicit in returned process status.

### `security`

- Capability audits and operation policy evaluation are structured values.
- Secret redaction patterns include `secret`, `token`, `password`, `api_key`, `bearer`, `jwt`, `authorization`.
- Rate limiting primitives return explicit accepted/rejected outcomes.

### `rng` and crypto

- `next_u64_with_capability(token) -> Result<u64, CapabilityError>` and distribution helpers.
- CSPRNG source is OS-backed.
- Hash/HMAC/AES-GCM primitives expose deterministic test hooks and host-secure defaults.

### `test`

- Deterministic test utilities include eventual/retry and timeout-aware helpers.
- Contracts guarantee bounded retry attempts and explicit timeout error reporting.

## Error Semantics (Cross-Module)

- Capability failures are represented as `CapabilityError` and should be handled at API edges.
- IO/process/network subsystems expose typed backend errors with operation/path context.
- Deterministic mode keeps error ordering and decision points replay-stable for the same trace+seed.

## Usage Pattern

- Acquire/verify capabilities first.
- Use bounded resources and explicit timeouts.
- Pair allocations/handles with `defer` cleanup.
- Record traces for deterministic reproduction (`--det --record`).

## Hardening Defaults

- bounded headers, bodies, connection counts, and parse/request timeouts
- structured log redaction for secret/token/password fields
- bounded channels and bounded poll queues by default

## Deploy Conventions

- Health contract: `/healthz` for liveness, `/readyz` for readiness.
- Runtime profiles: `dev`, `verify`, `release` with explicit deterministic/strict behavior.
- Service manifest includes ports, limits, workers, graceful-stop budget.

## Non-goals (v1)

- complete replacement for external observability backends
- platform-specific process supervisor orchestration
- multi-tenant secret management service
