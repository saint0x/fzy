# GPU ASCII Ripple

This example is a more visual GPU/CPU hybrid project:

- a custom Fzy-authored Metal GPU kernel generates ripple-band intensity frames
- the CPU downloads each frame, aggregates it with SIMD reductions, and renders ASCII output
- interactive direct runs get a live in-place animation; non-interactive runs fall back to deterministic frame dumps

What it proves:

- live `metal` kernel execution on Apple
- custom integer kernel logic written directly in Fzy
- CPU-side aggregation and presentation over downloaded GPU output
- a real terminal renderer contract instead of a silent validation harness

Recommended commands:

```bash
fz check examples/gpu_ascii_ripple --json
fz build examples/gpu_ascii_ripple --json
fz test examples/gpu_ascii_ripple --det --strict-verify --json
fz run examples/gpu_ascii_ripple --host-backends --json
fz run examples/gpu_ascii_ripple --det --record artifacts/gpu_ascii_ripple.trace.fozzy --json
fz trace verify artifacts/gpu_ascii_ripple.trace.fozzy --strict --json
fz replay artifacts/gpu_ascii_ripple.trace.fozzy --json
fz ci artifacts/gpu_ascii_ripple.trace.fozzy --json
```

Notes:

- live execution today is `metal` on Apple
- the kernel is authored in Fzy and lowered through the shared GPU launch/package contract
- host-backed runs render the same GPU frames plus `sum`, `min`, `max`, and `hot` counts for each frame
- override render mode with `FZ_GPU_ASCII_RENDER=animate` or `FZ_GPU_ASCII_RENDER=frames`
- `fz run` intentionally exposes a non-interactive stream, so the best animated demo command is `FZ_GPU_ASCII_RENDER=animate fz run examples/gpu_ascii_ripple --host-backends`
- the built binary at `.fz/build/gpu_ascii_ripple` also animates directly when launched from a normal terminal
