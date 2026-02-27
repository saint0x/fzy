# Corelib Bench Findings (Rust vs Fzy)

## Scope

Production-corelib kernels, Rust vs Fzy, checksum-equivalent before timing.

- Suite id: `corelibs-rust-vs-fzy-production-corelib-robust`
- Kernel count: `17` (`log` + `error` added; HTTP split one-off/persistent)
- Canonical artifact (latest): `artifacts/corelibbench_post_log_error_opt3.json`
- Companion summary: `artifacts/corelibbench_post_log_error_opt3.md`

## Latest Full Run

- Timestamp (UTC): `2026-02-27T18:05:25.380485+00:00`
- Warmup: `5`
- Measured: `20`
- Bootstrap samples: `3000`

Summary:
- Fzy wins: `11`
- Rust wins: `6`
- Geomean ratio (Fzy/Rust): `0.968x`
- Mean ratio (Fzy/Rust): `1.006x`

## Per-Kernel Winners (Binary)

| Benchmark | Ratio (Fzy/Rust) | Winner | Advantage |
|---|---:|---|---|
| resultx_classify | 0.999x | Fzy | Fzy +0.14% |
| text_kernel | 0.349x | Fzy | Fzy +65.11% |
| capability_parse | 0.993x | Fzy | Fzy +0.68% |
| task_retry_backoff | 0.989x | Fzy | Fzy +1.14% |
| arithmetic_kernel | 0.971x | Fzy | Fzy +2.88% |
| bytes_kernel | 1.009x | Rust | Rust +0.91% |
| duration_kernel | 0.997x | Fzy | Fzy +0.32% |
| abi_pair_kernel | 1.003x | Rust | Rust +0.34% |
| c_interop_contract_kernel | 0.756x | Fzy | Fzy +24.36% |
| log_kernel | 1.447x | Rust | Rust +44.65% |
| error_kernel | 1.103x | Rust | Rust +10.27% |
| http_kernel_oneoff | 0.996x | Fzy | Fzy +0.40% |
| http_kernel_persistent | 1.609x | Rust | Rust +60.88% |
| network_kernel | 0.902x | Fzy | Fzy +9.78% |
| concurrency_kernel | 0.989x | Fzy | Fzy +1.07% |
| process_kernel | 0.995x | Fzy | Fzy +0.46% |
| security_kernel | 1.002x | Rust | Rust +0.21% |

## Current Focus

- Keep Fzy as canonical corelib path for `log` + `error`.
- Remaining high-delta Rust wins to optimize in Fzy:
  - `http_kernel_persistent`
  - `log_kernel`
  - `error_kernel`
