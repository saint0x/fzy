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

---

## Core Library Rewrite Feasibility Probe (Rust vs Fzy Scratch)

Date: 2026-02-26

### Target

- Core library candidate: `resultx::classify`
- Baseline: current Rust stdlib implementation (`stdlib::resultx::classify`)
- Comparison: scratch Fzy implementation with no `core.*` imports
  - source: `examples/benchmarks/resultx_scratch_bench.fzy`
- Benchmark runner:
  - `scripts/bench_resultx_rust_vs_fzy.py`

### Method

- Build both implementations in release mode once.
- Verify workload parity via checksum.
- Warmup runs: `5`
- Measured runs: `24`
- Workload: `20,000,000` classify operations per run.
- Execution order alternates each round to reduce drift bias.

### Repro Command

```bash
python3 scripts/bench_resultx_rust_vs_fzy.py
```

### Result Summary

- Rust mean: `29.731 ms`
- Fzy scratch mean: `108.264 ms`
- Relative: `3.641x` (Fzy slower)

Artifacts:

- `artifacts/bench_resultx_rust_vs_fzy.json`
- `artifacts/bench_resultx_rust_vs_fzy.md`

### Interpretation

- Even with an optimized scratch Fzy implementation (tight loop + 4x unroll), this core function remains materially slower than the current Rust stdlib baseline.
- A full rewrite decision for performance-critical core modules should be gated by:
  - lowering/backend optimization improvements for this class of hot loops, or
  - selective strategy: keep the hottest primitives native while moving higher-level orchestration to Fzy.

## Expanded Core Library Scope (8-benchmark suite)

Date: 2026-02-26

### Scope

- Result classification kernel (`resultx_classify`)
- Text kernel (`trim/replace/contains/starts_with/ends_with/len`)
- Capability parse kernel
- Retry backoff kernel
- Arithmetic hot-loop kernel

Runner:

- `scripts/bench_corelibs_rust_vs_fzy.py`

Artifacts:

- `artifacts/bench_corelibs_rust_vs_fzy.json`
- `artifacts/bench_corelibs_rust_vs_fzy.md`

### Result Table

| Benchmark | Rust mean ms | Fzy mean ms | Ratio (fzy/rust) |
|---|---:|---:|---:|
| resultx_classify | 14.789 | 46.665 | 3.155x |
| text_kernel | 725.900 | 1210.359 | 1.667x |
| capability_parse | 48.242 | 46.364 | 0.961x |
| task_retry_backoff | 34.973 | 33.324 | 0.953x |
| arithmetic_kernel | 78.157 | 75.931 | 0.972x |
| bytes_kernel | 33.926 | 169.458 | 4.995x |
| duration_kernel | 32.476 | 32.496 | 1.001x |
| abi_pair_kernel | 64.844 | 64.472 | 0.994x |

### Read

- Fzy scratch was slower on branch/string/bytes-heavy kernels in this sample (`resultx_classify`, `text_kernel`, `bytes_kernel`).
- Fzy scratch was competitive or slightly faster on simpler arithmetic/branch kernels (`capability_parse`, `task_retry_backoff`, `arithmetic_kernel`, `abi_pair_kernel`).
- `duration_kernel` is effectively parity (`~1.001x`).
- Rewrite strategy should prioritize modules whose hot paths resemble the faster/parity class first, and defer string/bytes-heavy kernels until further compiler/runtime optimization work lands.

## Robust Deterministic Rerun (8-benchmark suite)

Date: 2026-02-26

### Determinism + Trace Gate (Fozzy First)

Scenario:

- `tests/corelibs.bench_matrix.pass.fozzy.json`

Verifier script:

- `scripts/verify_corelibs_bench_matrix.py`

Commands run:

```bash
fozzy doctor --deep --scenario tests/corelibs.bench_matrix.pass.fozzy.json --runs 5 --seed 20260226 --strict --proc-backend host --fs-backend host --http-backend host --json
fozzy test --det --strict tests/corelibs.bench_matrix.pass.fozzy.json --json
fozzy test --strict tests/corelibs.bench_matrix.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
fozzy run tests/corelibs.bench_matrix.pass.fozzy.json --det --strict --record artifacts/corelibs_bench_matrix.trace.fozzy --record-collision overwrite --json
fozzy trace verify artifacts/corelibs_bench_matrix.trace.fozzy --strict --json
fozzy replay artifacts/corelibs_bench_matrix.trace.fozzy --json
fozzy ci artifacts/corelibs_bench_matrix.trace.fozzy --json
```

Determinism audit:

- `consistent=true` across 5/5 runs
- signature: `0123b2b7e6867403e88d6df5cdc3b057761014a07005bee255b67b37a8547821`

### Robust Timing Method

- Runner: `scripts/bench_corelibs_rust_vs_fzy.py`
- Workload parity: checksum-matched for each of 8 kernels.
- Warmup runs: `5`
- Measured runs: `30`
- Alternating run order each round (`rust->fzy`, then `fzy->rust`)
- Bootstrap ratio CI: `5000` samples, seed `20260226`

Repro:

```bash
python3 scripts/bench_corelibs_rust_vs_fzy.py --warmup-runs 5 --measured-runs 30 --bootstrap-samples 5000 --seed 20260226 --out-prefix bench_corelibs_rust_vs_fzy_robust
```

Artifacts:

- `artifacts/bench_corelibs_rust_vs_fzy_robust.json`
- `artifacts/bench_corelibs_rust_vs_fzy_robust.md`

### Result Table (Robust)

| Benchmark | Rust mean ms | Fzy mean ms | Ratio (fzy/rust) | 95% CI ratio | Verdict |
|---|---:|---:|---:|---:|---|
| resultx_classify | 14.974 | 46.564 | 3.110x | [3.089, 3.132] | rust_faster |
| text_kernel | 733.084 | 1233.755 | 1.683x | [1.625, 1.746] | rust_faster |
| capability_parse | 48.577 | 46.420 | 0.956x | [0.946, 0.964] | near_parity |
| task_retry_backoff | 35.426 | 33.088 | 0.934x | [0.901, 0.959] | fzy_faster |
| arithmetic_kernel | 79.657 | 77.340 | 0.971x | [0.948, 0.992] | near_parity |
| bytes_kernel | 33.508 | 168.405 | 5.026x | [4.984, 5.066] | rust_faster |
| duration_kernel | 32.739 | 32.758 | 1.001x | [0.997, 1.004] | near_parity |
| abi_pair_kernel | 64.787 | 64.685 | 0.998x | [0.995, 1.001] | near_parity |

### Suite Read (Robust)

- Fzy faster: `1/8`
- Rust faster: `3/8`
- Near parity: `4/8`
- Geometric mean ratio (fzy/rust): `1.478x`
- Arithmetic mean ratio (fzy/rust): `1.835x`

Interpretation:

- We have a clear split by kernel shape: branch + bytes + text kernels still favor Rust strongly; arithmetic/state-machine kernels are now consistently close and occasionally favorable for Fzy.
- CI bands are narrow on most kernels, which increases confidence that the ranking is stable and not a one-off sample artifact.
- The largest optimization gap remains the bytes-heavy path (`~5.0x`), and that single class materially drags suite-level mean ratio.
