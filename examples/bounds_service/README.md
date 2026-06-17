# bounds_service

`bounds_service` is a production-shaped example app that consumes `frameworklib/fzbounds` as a real package dependency through the compiler.

It demonstrates:

- a local service budget model for request, queue, memory, and session capacity
- app-local gate logic that compares those budgets against the canonical `fzbounds` framework report
- direct package import of `fzbounds.inspect_json()` through `[deps]` and the compiler's dependency library resolution
- dependency lock/vendor wiring through `[deps]` so the example tracks the framework as a modular package
- package-aware direct file validation, so `fz check examples/bounds_service/src/services/mod.fzy --json` behaves like a real package check instead of an isolated-file parse

Validate it with:

```bash
fz check examples/bounds_service --json
fz check examples/bounds_service/src/services/mod.fzy --json
fz test examples/bounds_service --det --strict-verify --json
python3 scripts/verify_bounds_service_example.py
fz run tests/bounds_service.example.pass.fozzy.json --det --record artifacts/bounds_service.example.trace.fozzy --json
fz trace verify artifacts/bounds_service.example.trace.fozzy --strict --json
fz run examples/bounds_service --host-backends --json
```
