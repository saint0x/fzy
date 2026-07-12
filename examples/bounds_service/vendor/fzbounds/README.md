# fzbounds

`fzbounds` is the core-team bounded runtime framework package for FozzyLang.

Consume it like a normal package dependency:

- declare `fzbounds = {}` under `[deps]`
- import it in source with `use fzbounds;`
- keep service logic on typed accessors such as `fzbounds.api.inspect_fzweb_request_budget_bytes()` and reserve `fzbounds.inspect_json()` / `doctor_json()` for explicit output boundaries

Compiler DX note:

- direct checks such as `fz check examples/bounds_service/src/services/mod.fzy --json` and `fz check frameworklib/fzbounds/src/tests/mod.fzy --json` resolve through the owning package root, so framework imports, sibling modules, and test modules validate with the same package semantics as full-project checks

## Design

- Explicit service budgets for memory, regions, queues, maps, lists, channels, strings, sockets, and tasks.
- Deterministic runtime modes for `strict`, `audit`, `warn`, and `off`.
- Freeze-aware accounting so boot-time growth and runtime growth are modeled separately.
- Bounded arena, list, map, queue, channel, and buffer helpers with inspectable overflow state.
- Region lifecycle support with per-region allocation counts, peaks, timing, and validation.
- Typed-first service and integration flows that carry structured reports until the named JSON emitters.
- First-class telemetry and integration profiles for `fzweb`, jobs, auth/session, and realtime-style workloads.

## Architecture

- `src/integration/mod.fzy` owns typed integration catalog/profile builders. JSON emission lives in named emitter helpers such as `catalog_json`, `fzweb_profile_json`, and `jobs_profile_json`.
- `src/services/mod.fzy` composes typed service reports (`DoctorReport`, `RuntimeDemoReport`, `InspectReport`) from runtime state and typed integration bundles, then exposes named emitters for CLI and package boundaries.
- `src/cli/mod.fzy` dispatches commands through typed service builders first and only renders JSON at the terminal boundary.
- Internal flow stays on structs; JSON is a boundary format, not the working representation.

## Layout (Grouped by Concern)

- `src/model/mod.fzy`: shared state structs and lower-level runtime records.
- `src/budget/mod.fzy`: budget constructors and profile helpers.
- `src/runtime/mod.fzy`: runtime mode, freeze, allocation accounting, overflow recording, and assertions.
- `src/regions/mod.fzy`: bounded region lifecycle and validation helpers.
- `src/arena/mod.fzy`: fixed-capacity arena accounting.
- `src/containers/mod.fzy`: bounded list/map/queue/channel/buffer abstractions.
- `src/integration/mod.fzy`: typed integration catalogs, integration profiles, and their boundary emitters.
- `src/services/mod.fzy`: typed report assembly plus named JSON emitters for package and CLI boundaries.
- `src/cli/mod.fzy`: binary UX for `doctor`, `inspect`, `strict-demo`, `audit-demo`, and `fzweb`, rendered from typed flows.
- `src/main.fzy`: packaged deterministic smoke surface.

## Core API

- `library_name`, `touch`, `doctor_json`, `inspect_json`
- `budget.default_budget`, `budget.production_budget`, `budget.fzweb_budget`
- `runtime.make`, `runtime.freeze`, `runtime.allocate`, `runtime.record_region`, `runtime.assert_no_heap_growth`
- `regions.open`, `regions.allocate`, `regions.close`, `regions.validate`
- `arena.make`, `arena.alloc`, `arena.reset`
- `containers.list_make`, `containers.map_make`, `containers.queue_make`, `containers.channel_make`, `containers.buffer_make`
- `integration.catalog`, `integration.profiles`, `integration.catalog_json`
- `services.doctor`, `services.inspect`, `services.strict_demo`, `services.audit_demo`
- `services.doctor_json`, `services.inspect_json`, `services.strict_demo_json`, `services.audit_demo_json`, `services.fzweb_json`, `services.metrics_text`
- typed boundary helpers under `api.*`, such as `api.inspect_runtime_mode`, `api.inspect_runtime_max_memory_bytes`, `api.inspect_runtime_max_queue_entries`, `api.inspect_fzweb_request_budget_bytes`, and `api.inspect_auth_session_capacity`

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
