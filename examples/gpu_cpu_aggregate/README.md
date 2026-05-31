# GPU CPU Aggregate

This example shows a real hybrid pipeline:

- live `metal` GPU execution on Apple
- integer GPU kernel output downloaded back to the host
- CPU SIMD aggregation over the downloaded values
- a real aggregate struct summary reported to the terminal

The GPU applies a bias to eight integer scores. The CPU then aggregates the downloaded output into `sum`, `min`, and `max` using the shipped `core.simd` reduction surface.

Recommended commands:

```bash
fz check examples/gpu_cpu_aggregate --json
fz build examples/gpu_cpu_aggregate --json
fz test examples/gpu_cpu_aggregate --det --strict-verify --json
fz run examples/gpu_cpu_aggregate --host-backends --json
fz run examples/gpu_cpu_aggregate --det --record artifacts/gpu_cpu_aggregate.trace.fozzy --json
fz trace verify artifacts/gpu_cpu_aggregate.trace.fozzy --strict --json
fz replay artifacts/gpu_cpu_aggregate.trace.fozzy --json
fz ci artifacts/gpu_cpu_aggregate.trace.fozzy --json
```

Notes:

- live execution today is `metal` on Apple
- the aggregate report is a real CPU-side struct value, not a log-only convention
- the recorded native trace includes the live GPU launch/wait/download lifecycle for the GPU phase
