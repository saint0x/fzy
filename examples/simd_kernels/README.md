# SIMD Kernels

This example shows the current production SIMD model in a realistic fixed-size block workflow:

- signed sample mixing with saturating add plus an explicit limiter stage
- unsigned RGBA brightening with saturating add plus lane-wise clamp
- scalar summaries recovered from SIMD blocks with `reduce_min` and `reduce_max`

Recommended commands:

```bash
fz check examples/simd_kernels --json
fz test examples/simd_kernels --det --strict-verify --json
fz run examples/simd_kernels --backend llvm --json
```
