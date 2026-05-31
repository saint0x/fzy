# GPU ASCII Ripple

This example is a more visual GPU/CPU hybrid project:

- a custom Fzy-authored Metal GPU kernel generates ripple-band intensity frames
- the CPU downloads each frame, aggregates it with SIMD reductions, and renders ASCII output
- the terminal shows a short multi-frame animation sequence with per-frame stats

What it proves:

- live `metal` kernel execution on Apple
- custom integer kernel logic written directly in Fzy
- CPU-side aggregation and presentation over downloaded GPU output
- a nontrivial production-shaped example instead of a silent validation harness

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
- host-backed runs print the rendered frames plus `sum`, `min`, `max`, and `hot` counts for each frame
