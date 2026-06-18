# fzbounds

`fzbounds` is the core-team bounded runtime framework package for FozzyLang.

Consume it like a normal package dependency:

- declare `fzbounds = { path = "../../frameworklib/fzbounds" }` under `[deps]`
- import it in source with `use fzbounds;`
- call the public surface such as `fzbounds.inspect_json()` or `fzbounds.doctor_json()`

Compiler DX note:

- direct checks such as `fz check examples/bounds_service/src/services/mod.fzy --json` and `fz check frameworklib/fzbounds/src/tests/mod.fzy --json` resolve through the owning package root, so framework imports, sibling modules, and test modules validate with the same package semantics as full-project checks

## Design

- Explicit service budgets for memory, regions, queues, maps, lists, channels, strings, sockets, and tasks.
- Deterministic runtime modes for `strict`, `audit`, `warn`, and `off`.
- Freeze-aware accounting so boot-time growth and runtime growth are modeled separately.
- Bounded arena, list, map, queue, channel, and buffer helpers with inspectable overflow state.
- Region lifecycle support with per-region allocation counts, peaks, timing, and validation.
- First-class telemetry and integration reports for `fzweb`, jobs, auth/session, and realtime-style workloads.

## Layout (Grouped by Concern)

- `src/model/mod.fzy`: shared state structs and JSON encoders.
- `src/budget/mod.fzy`: budget constructors and profile helpers.
- `src/runtime/mod.fzy`: runtime mode, freeze, allocation accounting, overflow recording, and assertions.
- `src/regions/mod.fzy`: bounded region lifecycle and validation helpers.
- `src/arena/mod.fzy`: fixed-capacity arena accounting.
- `src/containers/mod.fzy`: bounded list/map/queue/channel/buffer abstractions.
- `src/integration/mod.fzy`: framework-shaped integration examples for higher-level packages.
- `src/services/mod.fzy`: packaged reports, demos, and deterministic surface helpers.
- `src/cli/mod.fzy`: binary UX for `doctor`, `inspect`, `strict-demo`, `audit-demo`, and `fzweb`.
- `src/main.fzy`: packaged deterministic smoke surface.

## Core API

- `library_name`, `touch`, `doctor_json`, `inspect_json`
- `budget.default_budget`, `budget.production_budget`, `budget.fzweb_budget`
- `runtime.make`, `runtime.freeze`, `runtime.allocate`, `runtime.record_region`, `runtime.assert_no_heap_growth`
- `regions.open`, `regions.allocate`, `regions.close`, `regions.validate`
- `arena.make`, `arena.alloc`, `arena.reset`
- `containers.list_make`, `containers.map_make`, `containers.queue_make`, `containers.channel_make`, `containers.buffer_make`
- `services.doctor_json`, `services.inspect_json`, `services.strict_demo_json`, `services.audit_demo_json`, `services.metrics_text`

## Production Checks

- `python3 scripts/verify_fzbounds_framework.py`
- `cargo run -q -p fz -- doctor --deep --scenario tests/fzbounds.framework.pass.fozzy.json --runs 5 --seed 20260601 --json`
- `cargo run -q -p fz -- test tests/fzbounds.framework.pass.fozzy.json --det --strict-verify --json`
- `cargo run -q -p fz -- run tests/fzbounds.framework.pass.fozzy.json --det --record artifacts/fzbounds.framework.trace.fozzy --json`
- `cargo run -q -p fz -- trace verify artifacts/fzbounds.framework.trace.fozzy --strict --json`
- `cargo run -q -p fz -- replay artifacts/fzbounds.framework.trace.fozzy --json`
- `cargo run -q -p fz -- ci artifacts/fzbounds.framework.trace.fozzy --json`
- `cargo run -q -p fz -- run frameworklib/fzbounds --host-backends --json`

## CLI

- `fzbounds help`
- `fzbounds doctor`
- `fzbounds doctor-json`
- `fzbounds inspect`
- `fzbounds inspect-json`
- `fzbounds strict-demo`
- `fzbounds strict-demo-json`
- `fzbounds audit-demo`
- `fzbounds audit-demo-json`
- `fzbounds fzweb`
