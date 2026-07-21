# GPU Metal Image

This example is the production-shaped reference app for the current live GPU path.

What it shows:

- modular project layout for a GPU app
- live `metal` device discovery on Apple
- real `GpuBuffer<f32>` upload, launch, wait, download, and cleanup
- a brightness kernel with scalar + slice launch arguments
- deterministic trace capture and shared kernel-package emission

The project runs a simple brightness pass over a tiny normalized image row and returns a nonzero exit code if the downloaded output drifts from the expected result.

On success it prints the live Metal device name and a kernel validation line so the run is visibly doing work rather than exiting silently.

Recommended commands:

```bash
fz check examples/gpu_metal_image --json
fz build examples/gpu_metal_image --json
fz test examples/gpu_metal_image --det --strict-verify --json
fz run examples/gpu_metal_image --det --record artifacts/gpu_metal_image_example.trace.fozzy --json
fz trace verify artifacts/gpu_metal_image_example.trace.fozzy --strict --json
fz replay artifacts/gpu_metal_image_example.trace.fozzy --json
fz ci artifacts/gpu_metal_image_example.trace.fozzy --json
fz run examples/gpu_metal_image --host-backends --json
```

Notes:

- live execution today is `metal` on Apple, `rocm` on Linux, and `cuda`/`nvptx` on Linux NVIDIA hosts
- `spirv` shares the same kernel-package and launch-ABI contract, but is not yet executable
- after a successful build, inspect `.fz/gpu-kernel-package.json` for the emitted shared launch contract
