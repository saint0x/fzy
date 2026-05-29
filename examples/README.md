# Example Projects

These examples are meant to be executable production-shaped references, not syntax-only scraps.

- `minimal_runtime`: smallest native runtime surface.
- `service_app`: compact service composition baseline.
- `robust_cli`: terminal-first product structure.
- `live_server`: long-lived native HTTP service shape.
- `fullstack`: broader product wiring surface.
- `simd_kernels`: fixed-array SIMD block processing for audio-style signed mixes and RGBA-style unsigned clamps.
- `agent_runtime`: distilled from `/Users/deepsaint/Desktop/fzyagent` and focused on signed sessions, tool catalogs, audit trails, and parallel task planning.
- `context_runtime`: distilled from `/Users/deepsaint/Desktop/superctx` and focused on scoped memory scoring, protocol assembly, context framing, and deterministic compaction.

Recommended validation:

```bash
fz check examples/agent_runtime --json
fz test examples/agent_runtime --det --strict-verify --json
fz check examples/simd_kernels --json
fz test examples/simd_kernels --det --strict-verify --json
fz check examples/context_runtime --json
fz test examples/context_runtime --det --strict-verify --json
```
