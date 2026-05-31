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
- Language-facing `core.io` wrappers expose typed metadata plus native copy/remove staging helpers:
  - `io.metadata(path)` with `exists`, `is_file`, `is_dir`, `is_symlink`, `size`, `modified_unix_secs`
  - `io.copy_file(src, dst)`
  - `io.copy_tree(src, dst)`
  - `io.stage_tree(src, dst)`
  - `io.remove(path)` for recursive file-or-directory cleanup
  - `io.list_dir_entries(path)` plus `io.dir_len/io.dir_name/io.dir_path/io.dir_entry`
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
  - `post_json_stream_payload`
  - `SseEvent`
  - `sse_event`
  - `sse_next`
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
- Canonical current-process wrapper module is `core.process`.
- Current-process argv helpers are first-class:
  - `proc.argv_count()`
  - `proc.argv_get(index)`
- Common `core.process` helpers:
  - `process.argv_count()`
  - `process.argv(index)`
  - `process.argv_or(index, fallback)`
  - `process.command_name()`
  - `process.has_flag(flag)`
- Canonical language-facing process builders map to structured handles:
  - `proc.argv_new/push`
  - `proc.env_new/set`
  - `proc.spawn_cmd` / `proc.run_cmd`
- `proc.run*` waits for completion and returns the child exit code.
- `proc.spawn*` returns a process handle for later wait/stdout/stderr/exit inspection and explicit `proc.close(handle)` cleanup.
- `proc.poll(handle)` is the nonblocking readiness probe:
  - returns `0` while the child is still running
  - returns `1` once the child has completed
  - does not consume the handle; `proc.wait`, `proc.stdout/stderr`, `proc.exit_code`, and `proc.close` remain valid afterwards
- Canonical structured process pattern:

```fzy
let argv = proc.argv_new()
discard proc.argv_push(argv, "--format")
discard proc.argv_push(argv, "json")
let env_map = proc.env_new()
discard proc.env_set(env_map, "MODE", "prod")
let handle = proc.spawn_cmd("/usr/bin/tool", argv, env_map, "")
defer proc.close(handle)
discard proc.wait(handle, 1000)
let exit = proc.exit_code(handle)
let out = proc.stdout(handle)
let err = proc.stderr(handle)
```

## Resource-Management Guidance

- Pair owned resources with same-scope `defer` cleanup whenever possible.
- Canonical safe patterns include `defer free(ptr)` for heap memory, `defer proc.close(handle)` for process handles, `defer fs.close(file)` for filesystem handles, and `defer close(handle)` for other linear stdlib/runtime wrappers that expose bare `close(...)`.
- `alloc(...)` / `free(...)` remain part of the safe subset when verifier tracking succeeds; they do not require `unsafe` unless combined with unchecked raw-memory operations.

### Handle Contract Matrix

- `HttpHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `HttpStreamHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `WebSocketHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `ProcessHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `ProcessArgv`: copy=no, owned=yes, linear=yes, closable=no, send-safe=no, async-stable=no
- `ProcessEnv`: copy=no, owned=yes, linear=yes, closable=no, send-safe=no, async-stable=no
- `TaskHandle`: copy=no, owned=yes, linear=yes, closable=no, send-safe=yes, async-stable=yes
- `TaskGroupHandle`: copy=no, owned=yes, linear=yes, closable=no, send-safe=yes, async-stable=yes
- `TaskGroup`: copy=no, owned=yes, linear=yes, closable=no, send-safe=yes, async-stable=yes
- `FileHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `JsonHandle`: copy=no, owned=yes, linear=no, closable=no, send-safe=yes, async-stable=yes
- `ListHandle`: copy=no, owned=yes, linear=no, closable=no, send-safe=yes, async-stable=yes
- `MapHandle`: copy=no, owned=yes, linear=no, closable=no, send-safe=yes, async-stable=yes
- `KvStoreHandle`: copy=no, owned=yes, linear=yes, closable=yes, send-safe=no, async-stable=yes
- `ChannelHandle`: copy=no, owned=yes, linear=yes, closable=no, send-safe=yes, async-stable=yes
- `RpcFrame`: copy=no, owned=yes, linear=yes, closable=no, send-safe=no, async-stable=no
- Compiler-shipped handle contracts are emitted in `.fz/handle-contracts.json`.
- Native runtime edge contracts are emitted in `.fz/native-runtime-contracts.json`.
- Production code should treat the emitted contract artifacts as the source of truth for handle cleanup, borrowing, send-safety, and async-stability semantics.

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
- Canonical standard-library wrapper module is `core.term`.
- Common `core.term` helpers:
  - `term.print(text)`
  - `term.print_line(text)`
  - `term.eprint(text)`
  - `term.eprint_line(text)`
  - `term.prompt_line(prompt)`
  - `term.is_interactive()`
  - `term.transcript_line(text)`
  - `term.transcript_kv(label, value, label_width)`

Canonical production CLI shape:

```fzy
use core.process;
use core.term;

fn main() -> i32 {
    let mode = process.argv_or(1, "serve")
    discard term.transcript_kv("mode", mode, 8)
    if term.is_interactive() == 1 {
        discard term.eprint_line("interactive terminal detected")
    }
    return 0
}
```

Transcript guidance:

- Use one stream consistently for transcript-style UX.
- Prefer `term.print*` / `term.transcript_*` for ordered conversational output.
- Use `term.eprint*` only for genuine error/control output.

### `log`

- `use core.log;` is both the capability declaration and the stdlib logging facade.
- Raw runtime logging controls remain first-class:
  - `log.info(message, fields_json)`
  - `log.warn(message, fields_json)`
  - `log.error(message, fields_json)`
  - `log.fields(map_handle)`
  - `log.set_json(enabled)`
  - `log.set_enabled(enabled)`
  - `log.set_level(level_name)`
  - `log.set_sink(sink_name)`
- Common `core.log` helpers:
  - `log.set_level_name(level_name)`
  - `log.set_sink_name(sink_name)`
  - `log.use_stdout()`
  - `log.use_stderr()`
  - `log.quiet()`
  - `log.verbose()`
  - `log.default_config()`
  - `log.request_log(...)`
- Importing `core.log` and calling its configuration helpers is ordinary supported production usage; it must not introduce verifier-only ownership diagnostics by itself.

### `text`

### `simd`

- `core.simd` is the phase-1 portable SIMD facade.
- Shipped vector aliases:
  - `i32x4`
  - `u32x4`
  - `f32x4`
  - `mask32x4`
- Shipped operation families:
  - constructors and `splat`
  - safe fixed-array `load`/`store` for the four shipped vector/mask aliases
  - fixed-array `load_masked`, `load_prefix`, `gather`, and vector-space `merge_masked`/`merge_prefix` helpers before the final plain `store(...)`
  - add/sub/mul plus integer `saturating_add`/`saturating_sub`
  - min/max
  - shifts and bitwise ops
  - eq/ne/lt/le/gt/ge
  - `select(mask, then, else)`
  - `shuffle(left, right, i0, i1, i2, i3)`
  - paired lane helpers: `zip_lo/zip_hi`, `unzip_left/unzip_right`
  - explicit numeric bitcasts and signed/unsigned reinterpret helpers
  - lane extraction
  - reductions: `reduce_add`, `reduce_min`, `reduce_max`, `any`, `all`, `none`, `bitmask`
  - explicit unsafe raw-pointer aligned/unaligned load/store helpers for `i32x4`, `u32x4`, `f32x4`, and `mask32x4`
- Contract:
  - current production lowering for the shipped phase-1 subset is available in both LLVM and Cranelift
  - backend parity is semantic for the fixed-array-safe surface; this is not a performance-equivalence claim
  - fixed-array helper returns are caller-owned on the native backends, so array-valued SIMD workflows remain stable across subsequent helper calls
  - SIMD values are rejected across ABI/FFI boundaries in phase 1
  - `shuffle` traps on lane selectors outside `0..7`
  - masks remain distinct from integer vectors in the public API
  - fixed-array memory helpers are safe; raw contiguous-buffer interop is available through explicit `unsafe fn` aligned/unaligned pointer loads and stores
  - `bytes`/slice-native SIMD memory views are still future work
- Example:
  - [examples/simd_kernels](/Users/deepsaint/Desktop/fozzylang/examples/simd_kernels/README.md) shows the current production-style SIMD workflow for signed mix/limit, partial tail merges, channel swizzles, highlighted-lane scatter, and the same cross-backend vector contracts the fixture suite exercises.

- `use core.text;` is the standard-library text helper module for native CLI/service rendering.
- Common helpers:
  - `text.trim(value)`
  - `text.replace(value, needle, with)`
  - `text.repeat(piece, count)`
  - `text.spaces(count)`
  - `text.pad_left(value, width)`
  - `text.pad_right(value, width)`
  - `text.indent(value, prefix)`
  - `text.visible_len_ansi(value)`
  - `text.upper_ascii(value)`
  - `text.lower_ascii(value)`

### `crypto`

- `use core.crypto;` is the production cryptography and secure-random import.
- Native runtime surface:
  - `crypto.random_hex(bytes)`
  - `crypto.random_base64(bytes)`
  - `crypto.sha256(data)`
  - `crypto.hmac_sha256(key, data)`
  - `crypto.constant_time_eq(a, b)`
  - `crypto.base64_encode(data)`
  - `crypto.base64_decode(data)`
- `use core.security;` is the higher-level web/security helper facade on top of `core.crypto`.
- Common `core.security` helpers:
  - `security.random_hex(bytes)`
  - `security.random_base64(bytes)`
  - `security.random_base64_url(bytes)`
  - `security.sha256_hex(data)`
  - `security.hmac_sha256_hex(key, data)`
  - `security.sign_value(key, data)`
  - `security.verify_value(key, data, mac_hex)`
  - `security.secure_eq(a, b)`
  - `security.base64_encode(data)`
  - `security.base64_decode(data)`
  - `security.base64_url_encode(data)`
  - `security.base64_url_decode(data)`
- This checkout intentionally exposes textual crypto encodings rather than raw binary string APIs; native Fzy strings are NUL-terminated, so `hex`/`base64` are the production-safe surface for random output and digest transport.

### `thread`

- `use core.thread;` is the canonical concurrency-context helper import.
- Common helpers:
  - `thread.context_id()`
  - `thread.is_context_bound()`
- `thread.context_id()` returns the `context_id` supplied to `spawn_ctx(...)`.
- Outside a context-bound spawned worker, `thread.context_id()` returns `0`.

### `path`

- `use core.path;` is the canonical import marker for path-safe helper usage.
- Canonical path-safe authoring surface:
  - `path.join(base, child)`
  - `path.normalize(path)`
  - `path.basename(path)`
  - `path.dirname(path)`
  - `path.stem(path)`
  - `path.extension(path)`
- Prefer these helpers over raw slash concatenation in service/runtime code.

### `io`

- `use core.io;` is the canonical filesystem-discovery facade for native products.
- Common helpers:
  - `io.read_text(path)`
  - `io.write_text(path, value)`
  - `io.mkdir(path)`
  - `io.exists(path)`
  - `io.metadata(path)`
  - `io.is_file(path)`
  - `io.is_dir(path)`
  - `io.is_symlink(path)`
  - `io.copy_file(src, dst)`
  - `io.copy_tree(src, dst)`
  - `io.stage_tree(src, dst)`
  - `io.remove(path)`
  - `io.remove_file(path)`
  - `io.stat_size(path)`
  - `io.stat_mtime(path)`
  - `io.temp_file(prefix)`
  - `io.list_dir(path)`
  - `io.list_dir_entries(path)`

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
- Parsed JSON object/array bridges are first-class:
  - `json.keys(json_handle)` iterates arbitrary object keys
  - `json.to_map(json_handle)` bridges string-valued objects into `MapHandle`
  - `json.to_list(json_handle)` bridges string arrays into `ListHandle`
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
  - queued headers apply to the next `http.post_json`, `http.post_json_capture`, `http.post_json_stream`, or `http.request_stream` call and are then cleared
- Outbound streaming HTTP is available directly from the runtime surface:
  - `http.post_json_stream(endpoint, body_json)`
  - `http.request_stream(method, endpoint, body)`
  - `http.stream_read(handle, max_bytes)`
  - `http.stream_read_line(handle)`
  - `http.stream_eof(handle)`
  - `http.stream_status(handle)`
  - `http.stream_error(handle)`
  - `http.stream_close(handle)`
- SSE/event-stream clients should prefer:
  - `http.header_set("accept", "text/event-stream")`
  - `http.post_json_stream(...)` or `http.request_stream(...)`
  - line-oriented event parsing with `http.stream_read_line(...)`
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
- `storage.atomic_append(path, line)` appends exactly one newline-terminated record through the same atomic-write path the runtime uses for durable store updates.

### Filesystem write contracts

- `fs.atomic_write(path, bytes)` is the canonical all-or-nothing text write surface for runtime-visible state files.
- `fs.atomic_write(...)` and `storage.atomic_append(...)` are both compiler-known native contract edges:
  - they borrow their string inputs
  - they may block on host filesystems
  - they emit runtime events in safety artifacts

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
