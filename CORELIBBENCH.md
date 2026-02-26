# CORELIBBENCH

- Suite: `corelibs-rust-vs-fzy-scratch-robust`
- Commit: `276adf72f039bee0bdd1da65692d069ca771fb6a`
- Timestamp (UTC): 2026-02-26T17:39:12.681501+00:00
- Warmup runs: 5
- Measured runs: 30
- Bootstrap samples: 5000

| Benchmark | Rust mean (ms) | Fzy mean (ms) | Ratio (Fzy/Rust) | 95% CI | Verdict |
|---|---:|---:|---:|---:|---|
| resultx_classify | 15.460 | 15.404 | 0.996x | [0.982, 1.008] | near_parity |
| text_kernel | 737.551 | 126.335 | 0.171x | [0.171, 0.172] | fzy_faster |
| capability_parse | 48.390 | 32.797 | 0.678x | [0.670, 0.683] | fzy_faster |
| task_retry_backoff | 40.633 | 36.498 | 0.898x | [0.750, 1.072] | fzy_faster |
| arithmetic_kernel | 80.719 | 76.277 | 0.945x | [0.902, 0.974] | fzy_faster |
| bytes_kernel | 33.397 | 33.527 | 1.004x | [0.993, 1.021] | near_parity |
| duration_kernel | 33.272 | 33.115 | 0.995x | [0.987, 1.003] | near_parity |
| abi_pair_kernel | 64.849 | 64.872 | 1.000x | [0.999, 1.002] | near_parity |
| c_interop_contract_kernel | 34.440 | 26.775 | 0.777x | [0.773, 0.782] | fzy_faster |

## Summary

- Fzy faster: 5
- Rust faster: 0
- Near parity: 4
- Geomean ratio (Fzy/Rust): 0.751x
- Mean ratio (Fzy/Rust): 0.830x
