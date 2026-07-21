# Example Projects

These examples are meant to be executable production-shaped references, not syntax-only scraps.

House style across the suite:

- `main.fzy` only tells the boot story.
- `model/` owns typed shapes, contracts, and boundary payload helpers.
- `services/` owns direct effects.
- `runtime/` owns lifecycle, workers, and shutdown paths.
- `cli/` owns operator entrypoints.
- resource names expose ownership when the value is an owned runtime handle.

- `minimal_runtime`: smallest native runtime surface.
- `service_app`: compact service composition baseline.
- `robust_cli`: terminal-first product structure.
- `live_server`: long-lived native HTTP service shape.
- `fullstack`: broader product wiring surface.
- `simd_kernels`: fixed-array SIMD block processing for signed mixes, tail-safe merges, channel swizzles, and RGBA-style unsigned clamps.
- `gpu_metal_image`: production-shaped GPU compute app with a live Metal brightness kernel, deterministic trace capture, and shared kernel-package artifacts.
- `gpu_cpu_aggregate`: live Metal/ROCm integer kernel plus CPU SIMD aggregation/reporting over the downloaded result, returning a real aggregate struct summary.
- `gpu_ascii_ripple`: custom Fzy-authored GPU ripple kernel with CPU SIMD aggregation and a TTY-aware ASCII renderer that loops live in terminal until interrupted, while still falling back to deterministic frame dumps for logs/CI.
- `agent_runtime`: distilled from `/Users/deepsaint/Desktop/fzyagent` and focused on signed sessions, tool catalogs, audit trails, and parallel task planning.
- `context_runtime`: distilled from `/Users/deepsaint/Desktop/superctx` and focused on scoped memory scoring, protocol assembly, context framing, and deterministic compaction.
- `bounds_service`: production-shaped bounded service example that consumes `frameworklib/fzbounds` as a direct package dependency through compiler-backed library imports, package-aware direct-file validation, and dependency lock/vendor flow.

Recommended validation:

```bash
fz check examples/agent_runtime --json
fz test examples/agent_runtime --det --strict-verify --json
fz check examples/simd_kernels --json
fz test examples/simd_kernels --det --strict-verify --json
fz check examples/gpu_metal_image --json
fz run examples/gpu_metal_image --det --record artifacts/gpu_metal_image_example.trace.fozzy --json
fz trace verify artifacts/gpu_metal_image_example.trace.fozzy --strict --json
fz check examples/gpu_cpu_aggregate --json
fz run examples/gpu_cpu_aggregate --host-backends --json
fz run examples/gpu_cpu_aggregate --det --record artifacts/gpu_cpu_aggregate.trace.fozzy --json
fz check examples/gpu_ascii_ripple --json
fz run examples/gpu_ascii_ripple --host-backends --json
fz run examples/gpu_ascii_ripple --det --record artifacts/gpu_ascii_ripple.trace.fozzy --json
fz check examples/context_runtime --json
fz test examples/context_runtime --det --strict-verify --json
fz check examples/bounds_service --json
fz check examples/bounds_service/src/services/mod.fzy --json
fz test examples/bounds_service --det --strict-verify --json
python3 scripts/verify_bounds_service_example.py
```
