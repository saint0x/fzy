# Corelib Bench Findings (Rust vs Fzy)

## Scope

This document records benchmark findings for production-corelib-style kernels implemented in both Rust and Fzy.

- Suite id: `corelibs-rust-vs-fzy-production-corelib-robust`
- Kernel count: `9`
- Equivalence contract: each Rust/Fzy kernel pair must return identical checksum before timing is accepted.
- Artifacts:
  - `artifacts/bench_corelibs_rust_vs_fzy.json`
  - `artifacts/bench_corelibs_rust_vs_fzy.longrun.json`

## Run A (Standard)

- Timestamp (UTC): `2026-02-27T05:06:08.710958+00:00`
- Warmup: `5`
- Measured: `30`
- Bootstrap samples: `5000`
- Summary:
  - Fzy faster: `2`
  - Near parity: `7`
  - Rust faster: `0`
  - Geomean ratio (Fzy/Rust): `0.870x`
  - Mean ratio (Fzy/Rust): `0.905x`

| Benchmark | Ratio (Fzy/Rust) | Verdict |
|---|---:|---|
| resultx_classify | 0.997x | near_parity |
| text_kernel | 0.364x | fzy_faster |
| capability_parse | 0.995x | near_parity |
| task_retry_backoff | 1.001x | near_parity |
| arithmetic_kernel | 0.971x | near_parity |
| bytes_kernel | 0.995x | near_parity |
| duration_kernel | 1.000x | near_parity |
| abi_pair_kernel | 0.999x | near_parity |
| c_interop_contract_kernel | 0.819x | fzy_faster |

### Percent Advantage (Run A)

- `resultx_classify`: Fzy `+0.29%`
- `text_kernel`: Fzy `+63.60%`
- `capability_parse`: Fzy `+0.50%`
- `task_retry_backoff`: Rust `+0.13%`
- `arithmetic_kernel`: Fzy `+2.87%`
- `bytes_kernel`: Fzy `+0.50%`
- `duration_kernel`: Rust `+0.01%`
- `abi_pair_kernel`: Fzy `+0.07%`
- `c_interop_contract_kernel`: Fzy `+18.08%`
- Overall geomean advantage: Fzy `+12.98%`
- Overall arithmetic-mean advantage: Fzy `+9.53%`
- Overall runtime-weighted advantage (sum mean ms): Fzy `+34.13%`

## Run B (Long Stress)

- Timestamp (UTC): `2026-02-27T05:11:21.701499+00:00`
- Warmup: `10`
- Measured: `80`
- Bootstrap samples: `10000`
- Summary:
  - Fzy faster: `2`
  - Near parity: `6`
  - Rust faster: `1`
  - Geomean ratio (Fzy/Rust): `0.878x`
  - Mean ratio (Fzy/Rust): `0.914x`

| Benchmark | Ratio (Fzy/Rust) | Verdict |
|---|---:|---|
| resultx_classify | 1.005x | near_parity |
| text_kernel | 0.359x | fzy_faster |
| capability_parse | 0.981x | near_parity |
| task_retry_backoff | 0.995x | near_parity |
| arithmetic_kernel | 0.967x | near_parity |
| bytes_kernel | 0.996x | near_parity |
| duration_kernel | 0.998x | near_parity |
| abi_pair_kernel | 1.069x | rust_faster |
| c_interop_contract_kernel | 0.854x | fzy_faster |

### Percent Advantage (Run B Long Stress)

- `resultx_classify`: Rust `+0.52%`
- `text_kernel`: Fzy `+64.14%`
- `capability_parse`: Fzy `+1.86%`
- `task_retry_backoff`: Fzy `+0.50%`
- `arithmetic_kernel`: Fzy `+3.27%`
- `bytes_kernel`: Fzy `+0.40%`
- `duration_kernel`: Fzy `+0.18%`
- `abi_pair_kernel`: Rust `+6.85%`
- `c_interop_contract_kernel`: Fzy `+14.61%`
- Overall geomean advantage: Fzy `+12.24%`
- Overall arithmetic-mean advantage: Fzy `+8.62%`
- Overall runtime-weighted advantage (sum mean ms): Fzy `+33.45%`

## Nuance About Test Interpretation

- Primary read: Fzy remains faster overall across both runs (geomean `< 1.0x` in both).
- Stable strong wins: `text_kernel` and `c_interop_contract_kernel` remain Fzy-faster in both runs.
- Most other kernels are effectively parity and should be treated as performance-equivalent for production planning.
- Long-run `abi_pair_kernel` shows high variance/outlier sensitivity:
  - 95% bootstrap CI is wide (`[0.893, 1.311]`).
  - Observed max latency spikes exist on both sides.
  - Interpretation: this single Rust-faster classification is not a stable directional signal yet; isolate with dedicated focused profiling before drawing architectural conclusions.

## Quality Gates Applied

- Checksum/equivalence verification: `python3 scripts/verify_corelibs_bench_matrix.py` (pass).
- Perf gate on refreshed artifact: `python3 scripts/direct_memory_perf_gate.py` (pass).

## Current TL;DR

- Fzy is still ahead overall on this corelib benchmark corpus.
- The corpus currently indicates:
  - repeatable Fzy wins in text-heavy and interop-contract workloads,
  - broad parity elsewhere,
  - one noisy long-run regression candidate (`abi_pair_kernel`) that needs targeted profiling rather than immediate architectural rollback.
