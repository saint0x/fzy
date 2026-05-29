# agent_runtime

`agent_runtime` is a compact, meaningful in-repo example distilled from the larger `/Users/deepsaint/Desktop/fzyagent` app.

It demonstrates:

- signed session envelopes with `core.security`
- JSON tool catalogs and request plans
- audit-trail persistence through `core.storage`
- transcript-friendly CLI behavior
- `spawn_ctx(...)` + `thread.context_id()` for bounded parallel work

Validate it with:

```bash
fz check examples/agent_runtime --json
fz test examples/agent_runtime --det --strict-verify --json
fz run examples/agent_runtime --backend cranelift --json
```
