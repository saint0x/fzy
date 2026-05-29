# context_runtime

`context_runtime` is a compact, meaningful in-repo example distilled from `/Users/deepsaint/Desktop/superctx`.

It demonstrates:

- scoped memory records with ranking heuristics
- deterministic context-frame assembly
- planner/protocol JSON contracts
- compaction summaries for selected evidence

Validate it with:

```bash
fz check examples/context_runtime --json
fz test examples/context_runtime --det --strict-verify --json
fz run examples/context_runtime --backend cranelift --json
```
