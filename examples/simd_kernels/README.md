# SIMD Kernels

This example shows the current production SIMD model in a realistic fixed-size block workflow:

- signed sample mixing with saturating add plus an explicit limiter stage
- tail-safe audio window merging via `load_prefix` plus vector-space `merge_prefix`
- unsigned RGBA brightening with saturating add plus lane-wise clamp
- channel swizzles via fixed-array `gather` and targeted highlight placement via `scatter`
- scalar summaries recovered from SIMD blocks with `reduce_min` and `reduce_max`
- array-valued helper composition that stays stable across both LLVM and Cranelift backends
- the same aligned/unaligned raw-pointer memory contract the portable fixture now validates end to end across both native backends

Recommended commands:

```bash
fz check examples/simd_kernels --json
fz test examples/simd_kernels --det --strict-verify --json
fz run examples/simd_kernels --backend llvm --json
fz run examples/simd_kernels --backend cranelift --json
fz run examples/simd_kernels --backend cranelift --host-backends --json
```
