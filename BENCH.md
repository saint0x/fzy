# FozzyLang Live Server Production Baseline

Date: 2026-02-24

## Target

- Service: `apps/live_server`
- Transport: HTTP/1.1 over TCP
- Persistence: durable `store.json` with atomic write + fsync + lock discipline
- Endpoints:
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics`
  - `GET /v1/items`
  - `GET /v1/items/:key`
  - `PUT /v1/items/:key`
  - `DELETE /v1/items/:key`

## Hardening And Runtime Contract

- bounded parse/body limits via stdlib HTTP limits
- request read/write timeout enforcement
- graceful stop path (`SIGINT`/`SIGTERM` handler)
- structured logging + metrics + trace spans
- capability-gated privileged op startup audit
- durable storage path (`write_atomic`, `fsync_file`, `acquire_file_lock`)

## Verification Evidence

### Rust Tests

Command:

```bash
cargo test -p live_server
```

Result:

- unit tests: `3/3` pass
- integration tests (real spawned server + TCP HTTP): `2/2` pass

### Benchmark (Local)

Command:

```bash
cargo run -p live_server -- bench
```

Observed output:

- `requests=2000`
- `total_ms=632`
- `rps=3164`
- `p50_us=2519`
- `p95_us=2692`
- `p99_us=3144`

Interpretation:

- Server now runs a fixed worker pool with bounded accept queue and async durability flusher.
- This moved the service from the prior ~`46 rps` baseline to ~`3164 rps` in local bench mode while preserving endpoint correctness and traceability.

## Production Heuristics To Track

- `http_request_total` growth slope
- `http_accept_error` rate
- `kv_write_total / kv_read_total` ratio
- `runtime_queue_depth`
- `runtime_scheduler_lag_ms`
- readiness transitions (`/readyz`) during restart windows

## Next Performance Iteration

1. Move from per-request thread spawn to fixed worker accept+dispatch pool.
2. Add buffered write-ahead journal and batch fsync.
3. Add keepalive request cap + connection reuse benchmark profile.
4. Add contention benchmarks under parallel PUT/DELETE workload.
