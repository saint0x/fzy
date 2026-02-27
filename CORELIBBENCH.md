# Corelib Bench Findings (Rust vs Fzy)

## Scope

This document records full benchmark findings for production-corelib kernels implemented in both Rust and Fzy.

- Suite id: `corelibs-rust-vs-fzy-production-corelib-robust`
- Kernel count: `14`
- Equivalence contract: each Rust/Fzy kernel pair must return identical checksum before timing is accepted.
- Artifacts:
  - `artifacts/bench_corelibs_rust_vs_fzy.json`
  - `artifacts/bench_corelibs_rust_vs_fzy.longrun.json`

## Run A (Standard)

- Timestamp (UTC): `2026-02-27T13:36:47.238574+00:00`
- Commit: `fcdf3b944fce4997333da0ca7a68dac78c31ca79`
- Warmup: `5`
- Measured: `30`
- Bootstrap samples: `5000`
- Summary:
  - Fzy wins: `10`
  - Rust wins: `4`
  - Geomean ratio (Fzy/Rust): `0.933x`
  - Mean ratio (Fzy/Rust): `0.967x`

| Benchmark | Ratio (Fzy/Rust) | Winner | Advantage |
|---|---:|---|---|
| resultx_classify | 0.998x | Fzy | Fzy +0.25% |
| text_kernel | 0.357x | Fzy | Fzy +64.32% |
| capability_parse | 0.991x | Fzy | Fzy +0.94% |
| task_retry_backoff | 1.004x | Rust | Rust +0.44% |
| arithmetic_kernel | 0.972x | Fzy | Fzy +2.83% |
| bytes_kernel | 1.001x | Rust | Rust +0.15% |
| duration_kernel | 0.994x | Fzy | Fzy +0.59% |
| abi_pair_kernel | 1.000x | Fzy | Fzy +0.05% |
| c_interop_contract_kernel | 0.817x | Fzy | Fzy +18.35% |
| http_kernel | 1.345x | Rust | Rust +34.45% |
| network_kernel | 0.802x | Fzy | Fzy +19.82% |
| concurrency_kernel | 1.000x | Fzy | Fzy +0.00% |
| process_kernel | 1.271x | Rust | Rust +27.11% |
| security_kernel | 0.983x | Fzy | Fzy +1.68% |

- Overall winner (Run A): **Fzy**

## Run B (Long Stress)

- Timestamp (UTC): `2026-02-27T13:40:41.940380+00:00`
- Commit: `fcdf3b944fce4997333da0ca7a68dac78c31ca79`
- Warmup: `10`
- Measured: `80`
- Bootstrap samples: `10000`
- Summary:
  - Fzy wins: `9`
  - Rust wins: `5`
  - Geomean ratio (Fzy/Rust): `0.909x`
  - Mean ratio (Fzy/Rust): `0.940x`

| Benchmark | Ratio (Fzy/Rust) | Winner | Advantage |
|---|---:|---|---|
| resultx_classify | 1.038x | Rust | Rust +3.84% |
| text_kernel | 0.357x | Fzy | Fzy +64.34% |
| capability_parse | 0.981x | Fzy | Fzy +1.90% |
| task_retry_backoff | 0.863x | Fzy | Fzy +13.72% |
| arithmetic_kernel | 0.969x | Fzy | Fzy +3.12% |
| bytes_kernel | 1.001x | Rust | Rust +0.08% |
| duration_kernel | 1.001x | Rust | Rust +0.15% |
| abi_pair_kernel | 0.988x | Fzy | Fzy +1.17% |
| c_interop_contract_kernel | 0.817x | Fzy | Fzy +18.26% |
| http_kernel | 1.353x | Rust | Rust +35.34% |
| network_kernel | 0.799x | Fzy | Fzy +20.07% |
| concurrency_kernel | 0.996x | Fzy | Fzy +0.39% |
| process_kernel | 1.000x | Rust | Rust +0.04% |
| security_kernel | 0.997x | Fzy | Fzy +0.31% |

- Overall winner (Run B): **Fzy**

## Quality Gates

- `python3 scripts/verify_corelibs_bench_matrix.py`: pass
- `python3 scripts/direct_memory_perf_gate.py`: fail on current standard artifact (`http_kernel`, `process_kernel`)

## TL;DR (Forced Binary Winners)

- Run A winner: **Fzy**
- Run B winner: **Fzy**
- Final overall winner: **Fzy**
