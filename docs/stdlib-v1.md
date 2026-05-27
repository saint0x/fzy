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
- Inbound JSON request handling should prefer `http.body_json(conn)` over `http.body(conn)` plus `json.parse(...)`.
- `http.body(conn)` remains the raw-text escape hatch for non-JSON or signature-sensitive payloads.
- Typed JSON payload helpers are available in `core.http`:
  - `JsonPayload`
  - `json_payload_new/set_str/set_raw/encode`
  - `write_json_payload`
  - `post_json_capture_payload`
- Rust stdlib parity is available in `stdlib::http` and routes through canonical builders (single execution path):
  - `JsonPayload`
  - `json_payload_new/set_str/set_raw/encode`
  - `write_json_payload(status, reason, payload, keep_alive, limits)`
  - `post_json_payload(path, payload, keep_alive, limits)`
- Canonical JSON wrapper helpers are provided via `core.util`:
  - `http_write_json_map(conn, status, map_handle)`
  - `http_post_json_capture_map(endpoint, map_handle)`

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
- Current-process argv helpers are first-class:
  - `proc.argv_count()`
  - `proc.argv_get(index)`
- Canonical language-facing process builders map to structured handles:
  - `proc.argv_new/push`
  - `proc.env_new/set`
  - `proc.spawn_cmd` / `proc.run_cmd`
- `proc.run*` waits for completion and returns the child exit code.
- `proc.spawn*` returns a process handle for later wait/stdout/stderr/exit inspection.
- Canonical structured process pattern:

```fzy
let argv = proc.argv_new()
discard proc.argv_push(argv, "--format")
discard proc.argv_push(argv, "json")
let env_map = proc.env_new()
discard proc.env_set(env_map, "MODE", "prod")
let handle = proc.spawn_cmd("/usr/bin/tool", argv, env_map, "")
discard proc.wait(handle, 1000)
let exit = proc.exit_code(handle)
let out = proc.stdout(handle)
let err = proc.stderr(handle)
```

### `term`

- Current-process terminal I/O is first-class:
  - `term.read_line()`
  - `term.stdin_eof()`
  - `term.write(text)`
  - `term.write_err(text)`
  - `term.stdin_is_tty()`
  - `term.stdout_is_tty()`
- `term.read_line()` strips the trailing newline and a trailing `\r` when present.
- Empty line and EOF are distinct:
  - empty line returns `""` with `term.stdin_eof() == 0`
  - EOF returns `""` with `term.stdin_eof() == 1`
- Canonical standard-library wrappers live in `core.term` and `core.process`:
  - `core.term.print_line`
  - `core.term.eprint_line`
  - `core.term.prompt_line`
  - `core.term.is_interactive`
  - `core.process.argv_or`
  - `core.process.command_name`
  - `core.process.has_flag`

### `path`

- Canonical path-safe authoring surface:
  - `path.join(base, child)`
  - `path.normalize(path)`
  - `path.basename(path)`
  - `path.dirname(path)`
  - `path.stem(path)`
  - `path.extension(path)`
- Prefer these helpers over raw slash concatenation in service/runtime code.

### `collections` + JSON

- Dynamic list/map handle APIs are first-class for runtime-safe composition:
  - `list.new/push/pop/len/get/set/clear/join`
  - `map.new/set/get/has/delete/keys/len`
- Canonical string assembly uses `str.concat(...)` for multi-part string construction.
- `str.concat2/3/4` remain stable, but `str.concat(...)` is the main authoring path.
- Small-value conversion helpers are first-class:
  - `str.from_i32(value)`
  - `str.from_bool(flag)`
- JSON composition uses dynamic builders:
  - `json.array(list_handle)`
  - `json.object(map_handle)`
- Canonical inbound JSON handler shape:

```fzy
http.read(conn)
let body = http.body_json(conn)
let name = json.get_str(body, "name")
let payload = map.new()
discard map.set(payload, "ok", json.raw("true"))
discard map.set(payload, "name", json.str(name))
http.write_json(conn, 200, json.object(payload))
```

- Canonical string/path assembly pattern:

```fzy
let port_label = str.concat("port=", str.from_i32(port))
let route_file = path.join("/srv/app/routes", str.concat(route_name, ".json"))
let route_dir = path.dirname(route_file)
let route_base = path.basename(route_file)
```

- Outbound request headers are explicit:
  - `http.header_set(key, value)`
  - queued headers apply to the next `http.post_json` / `http.post_json_capture` call and are then cleared
- Object literals (`#{ ... }`) lower to canonical map handles and are intended for small payload ergonomics.
- Use `http.body(conn)` plus manual parse only when you need raw protocol text or exact transport preservation.

### `security`

- Capability audits and operation policy evaluation are structured values.
- Secret redaction patterns include `secret`, `token`, `password`, `api_key`, `bearer`, `jwt`, `authorization`.
- Rate limiting primitives return explicit accepted/rejected outcomes.

### `log` and `error`

- `log` surface supports structured fields and JSON-mode logging contracts for production services.
- Canonical structured fields path is `log.fields(map_handle)`.
- `error` surface standardizes typed error classification, retryability, and status normalization.

### `util`

- Shared ergonomic helpers for common app patterns:
  - `log_fields2`, `log_fields3`
  - `json_object2`, `json_array2`
  - `http_write_json_map`, `http_post_json_capture_map`
  - `task_spawn_join_all`

### `storage`

- Storage primitives support low-boilerplate app state persistence:
  - `storage.append(path, line)`
  - `storage.atomic_append(path, line)`
  - `storage.kv_open(path)`, `storage.kv_get(handle, key)`, `storage.kv_put(handle, key, value)`

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
