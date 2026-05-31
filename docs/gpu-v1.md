# GPU v1

This document describes the production GPU surface that ships in this checkout today.

## Scope

Current GPU support is built around one backend-neutral contract and one live backend:

- shared kernel package and launch ABI for `metal`, `spirv`, and `nvptx`
- live executable `metal` runtime on Apple
- truthful non-executable adapter diagnostics for `spirv` and `nvptx`

There is no simulation path in the production contract.

## Current Backend Truth

- `metal`
  - live native backend on Apple
  - supports device discovery, buffer allocation, slicing, upload/download, launch, `wait`, and `wait_async`
- `spirv`
  - declared adapter bound to the shared launch/kernel package contract
  - not yet executable
- `nvptx`
  - declared adapter bound to the shared launch/kernel package contract
  - not yet executable

## Authoring Model

Import the GPU surface with:

```fzy
use core.gpu;
```

Execution spaces are explicit:

- `host fn`
  - device selection
  - allocation/free
  - upload/download
  - launch
  - event waiting
- `device fn`
  - helper functions callable from kernels
- `kernel fn`
  - launchable GPU entry points

Public opaque handles:

- `GpuDevice`
- `GpuBuffer<T>`
- `GpuSlice<T>`
- `GpuEvent`

Current stable host surface:

- `gpu.device_count()`
- `gpu.default_device()`
- `gpu.device_name(dev)`
- `gpu.device_memory_bytes(dev)`
- `gpu.alloc_f32/i32/u32(dev, len)`
- `gpu.free(buffer)`
- `gpu.upload_f32/i32/u32(dev, values)`
- `gpu.download_f32/i32/u32(buffer)`
- `gpu.slice(buffer, offset, len)`
- `gpu.launch0..4(kernel, grid, block, ...)`
- `gpu.wait(event)`
- `await gpu.wait_async(event)`

Current stable device/kernel surface:

- `gpu.global_id_x/y/z()`
- `gpu.thread_id_x/y/z()`
- `gpu.block_id_x/y/z()`
- `gpu.block_dim_x/y/z()`
- `gpu.grid_dim_x/y/z()`
- `gpu.barrier()`
- `GpuSlice<f32/i32/u32>` indexing

## Verifier Contract

The verifier is part of the public GPU programming model.

- kernels must return `void`
- kernels cannot call host functions
- host functions cannot call device-only GPU intrinsics
- `GpuBuffer<T>` is linear host-owned state and must be freed
- `GpuSlice<T>` is a verifier-visible borrowed view of its owner buffer
- freeing or reusing a buffer while derived slices are live is rejected
- competing live slices from the same owner are rejected when they violate the ownership contract
- aliased launch parameters are rejected unless the alias is readonly-safe under the shared launch ABI
- `gpu.barrier()` is rejected inside divergent control flow, including through helper calls
- unsupported kernel parameter shapes fail as stable launch-ABI diagnostics before backend lowering

## Build Artifacts

GPU builds emit:

- `.fz/gpu-kernel-package.json`
- `.fz/gpu-kernel-package.md`

These are the backend-neutral source of truth for:

- ABI version
- launch packet encoding
- parameter layout classes
- per-kernel capability flags
- backend adapter metadata

## Trace Evidence

Recorded native trace artifacts include GPU runtime events such as:

- `gpu.device_select`
- `gpu.alloc`
- `gpu.slice`
- `gpu.upload`
- `gpu.download`
- `gpu.kernel_launch`
- `gpu.event_wait`
- `gpu.kernel_complete`
- `gpu.error`
- `gpu.free`

Production GPU changes should still go through the normal Fozzy evidence path:

```bash
fz run <project> --det --record artifacts/<name>.trace.fozzy --json
fz trace verify artifacts/<name>.trace.fozzy --strict --json
fz replay artifacts/<name>.trace.fozzy --json
fz ci artifacts/<name>.trace.fozzy --json
```

## Reference Project

The canonical production-shaped example is:

- [examples/gpu_metal_image](/Users/deepsaint/Desktop/fozzylang/examples/gpu_metal_image/README.md)
- [examples/gpu_cpu_aggregate](/Users/deepsaint/Desktop/fozzylang/examples/gpu_cpu_aggregate/README.md)
- [examples/gpu_ascii_ripple](/Users/deepsaint/Desktop/fozzylang/examples/gpu_ascii_ripple/README.md)

`gpu_ascii_ripple` is the terminal-first showcase example:

- it runs a custom Fzy-authored `metal` kernel
- downloads each frame back to the host
- aggregates with CPU SIMD reductions
- animates in place on interactive terminals
- falls back to deterministic frame dumps for non-interactive runs, traces, and CI logs
- `FZ_GPU_ASCII_RENDER=animate` forces animation for `fz run` when the outer runner exposes a non-interactive stream

Recommended Apple/Metal workflow:

```bash
fz check examples/gpu_metal_image --json
fz build examples/gpu_metal_image --json
fz test examples/gpu_metal_image --det --strict-verify --json
fz run examples/gpu_metal_image --det --record artifacts/gpu_metal_image_example.trace.fozzy --json
fz trace verify artifacts/gpu_metal_image_example.trace.fozzy --strict --json
fz replay artifacts/gpu_metal_image_example.trace.fozzy --json
fz ci artifacts/gpu_metal_image_example.trace.fozzy --json
```

For cross-platform verification without live execution, `fz check` and `fz verify` still exercise the shared kernel package, launch ABI, and verifier contract.
