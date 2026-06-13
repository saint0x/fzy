# PERF.md

- [ ] Date: 2026-06-13
- [ ] Owner: Compiler + Runtime Core

## Perf Baseline (Rust vs Fzy Scratch)

Source benchmark table:
- `BENCH.md`
- `artifacts/bench_core_rust_vs_fzy.json`
- `artifacts/bench_core_rust_vs_fzy.md`

Primary gaps to close:
- [ ] `bytes_kernel`: `4.995x` (Fzy slower)
- [ ] `result_classify`: `3.155x` (Fzy slower)
- [ ] `text_kernel`: `1.667x` (Fzy slower)

Interpretation:
- [ ] Arithmetic-heavy, low-runtime-bound kernels are already near parity.
- [ ] Current bottlenecks are dominated by runtime-call, lock, representation, and lowering overhead in hot loops.
- [ ] Public API scalar shape is not the top source of latency by itself, but it does contribute secondary overhead through normalization, extra branches, wider hot structs, and loss of semantic precision in optimization-relevant paths.

## Current Repo Reality Check

Source-of-truth warning:
- [ ] This file still starts from the older 8-kernel scratch baseline because it is useful for root-cause framing.
- [ ] The current canonical whole-core benchmark surface is broader: see `COREBENCH.md` and `scripts/bench_core_rust_vs_fzy.py`, which now cover a 17-kernel suite including `log`, `error`, and split HTTP one-off vs persistent paths.
- [ ] Perf prioritization should therefore use both views:
- [ ] older 8-kernel scratch baseline for root-cause explanations
- [ ] newer 17-kernel suite for present-day rollout ordering and production-facing priorities

Most important implication:
- [ ] Repo-wide perf is no longer in a “broad parity crisis” state.
- [ ] The remaining meaningful low-latency work is concentrated in a few surfaces:
- [ ] persistent HTTP/runtime-shim paths
- [ ] logging/observability paths
- [ ] error/control-plane hot paths
- [ ] compiler/LSP responsiveness and scenario-engine bookkeeping

Current highest-delta Rust wins from the broader suite:
- [ ] `http_kernel_persistent`
- [ ] `log_kernel`
- [ ] `error_kernel`

Current measured compile/build reality:
- [ ] The strongest remaining end-to-end latency debt is still compile/build responsiveness, especially warm no-op and warm near-no-op flows.
- [ ] `artifacts/bench_compile_times_rust_vs_fzy.md` currently shows:
- [ ] dev cold full: `~1.22x`-`1.59x`
- [ ] dev warm no-op: `~8.56x`-`14.70x`
- [ ] release warm no-op: `~47.28x`-`59.44x`
- [ ] This confirms that cache presence alone is not enough; the cheapest skip decisions are still too expensive.

Separate compiler/tooling baseline:
- [ ] `artifacts/bench_compile_times_rust_vs_fzy.md` is now a first-class perf input for repo-wide prioritization, not just a side benchmark.
- [ ] The current compile-time gap is materially larger than the remaining median kernel gap:
- [ ] cold dev compile still loses, but within a more plausible band (`~1.22x`-`1.59x`)
- [ ] warm noop and release flows remain the most severe end-to-end latency debt (`~8.56x`-`59.44x`)
- [ ] This means “overall perf” work cannot be framed only as runtime-kernel parity; compile/build responsiveness is now one of the largest remaining product-latency gaps.

LSP/editor reality check:
- [ ] The browser-backed editor responsiveness gates are currently green (`artifacts/browser_editor_responsiveness_gate.json`, `artifacts/browser_incremental_budget_gate.json`).
- [ ] That is useful because it means LSP is not in acute regression territory today.
- [ ] It does not mean the compiler/tooling path is done; it means the biggest remaining tooling work is more about CLI/build/check latency and cold workspace behavior than about immediate interactive breakage.
- [ ] Current gate evidence is materially under budget on the interactive browser checks:
- [ ] diagnostics `22.257 ms`
- [ ] definition `13.229 ms`
- [ ] hover `11.636 ms`
- [ ] smoke `9.622 ms`
- [ ] This strengthens the case for prioritizing cold workspace behavior and compile/build warm paths before chasing already-green interactive microflows.

Fresh broad-suite confirmation from this sweep:
- [ ] `cargo run -p fz -- perf --json` still reports broad suite-level parity (`averageRatioFzyOverRust ~1.004x` across `17` kernels).
- [ ] The remaining standout runtime laggard is still `http_kernel_persistent` (`worstRatioFzyOverRust ~1.589x`).
- [ ] This reinforces that the repo-wide perf story is now mostly concentrated debt rather than broad runtime underperformance.

---

## Root-Cause Findings

### 1) Array/Indexing Path Is Runtime-Call Bound

Current lowering shape:
- [ ] Array literal lowers to `__native.array_new` + repeated `__native.array_push`.
- [ ] `arr[idx]` lowers to `__native.array_get`.
- [ ] `__native.array_get` takes `fz_collections_lock` per read.

Implication:
- [ ] Tight loops pay call overhead + mutex overhead for each element load.
- [ ] `bytes_kernel` has multiple indexed loads per iteration, amplifying cost.

### 2) Match/Enum Classification Is Branch-Chain + Slot-Heavy

Current lowering shape:
- [ ] Match is lowered via condition chains rather than jump-table/switch style for dense cases.
- [ ] Variant identity still pays more than compact discriminant-based lowering in hot classify workloads.
- [ ] LLVM emission still leaves optimization work on the table through stack-slot-heavy patterns.

Implication:
- [ ] Branch-heavy kernels such as `result_classify` pay predictable overhead per iteration.

### 3) String Hot Paths Are Runtime/Interning Bound

Current lowering shape:
- [ ] `str.trim`, `str.replace`, `str.contains`, `str.starts_with`, `str.ends_with`, `str.len` lower to native runtime calls.
- [ ] New strings still pay intern/representation overhead more often than ideal in loop-local paths.

Implication:
- [ ] `text_kernel` pays repeated conversion/allocation/interning overhead in each iteration.

### 4) Fzy-Facing Stdlib Scalar Shape Still Carries Perf Debt

Current shape:
- [ ] The Rust stdlib/runtime layer already uses `bool` and typed enums in many hot-path-relevant places.
- [ ] The Fzy-facing `core/src/*.fzy` layer still uses many `i32` flags and `0/1` helper returns for values that are semantically binary.
- [ ] This does not dominate cost the way runtime-call and lock overhead do, but it adds aggregate overhead through:
- [ ] normalization helpers
- [ ] wider field layout in hot structs
- [ ] extra compare/branch patterns
- [ ] weaker semantic information for later lowering and optimization

Implication:
- [ ] We need a deliberate module-by-module sweep to keep `i32` where the domain is truly numeric and narrow binary public/internal state toward `bool` or enums where profitable.

### 5) Native Runtime Shim Still Pays Too Much For Interning, JSON Scans, And Handle Mutation

Current shape:
- [ ] The native runtime shim still calls `fz_intern_slice(...)` aggressively for empty strings, tiny literals, substrings, and transient body/error payloads.
- [ ] `fz_intern_slice(...)` still pays read-lock lookup, allocation/copy, and then a second write-locked insertion path on misses, which is correctness-safe but still expensive under hot missy/transient traffic.
- [ ] HTTP/JSON helpers still rely on repeated `fz_json_object_lookup(...)` / `fz_json_array_lookup(...)` rescans of raw text.
- [ ] `fz_json_object_lookup(...)` still allocates and frees temporary parsed key strings while linearly rescanning object text, so repeated field lookup compounds both parse and allocator cost.
- [ ] JSON handle creation/access still goes through `fz_json_lock`.
- [ ] List/map helper paths still mutate through runtime handle helpers such as `fz_runtime_list_push(...)` and `fz_runtime_map_set(...)` even in paths that are mostly local transformation work.
- [ ] Runtime list/map helpers still hold coarse mutexes while duplicating strings on push/get/set paths, which means container convenience helpers continue to inject lock + allocation overhead into otherwise small local operations.

Implication:
- [ ] This creates avoidable lock pressure, repeated parse work, and intern churn in service-facing and host-backed runtime paths.

### 6) Observability And Service Plumbing Are Allocation/Serialization Bound

Current shape:
- [ ] Rust-side observability still stores in-memory logs behind `Arc<Mutex<Vec<LogEntry>>>`.
- [ ] Hot emission paths still clone entries and serialize via `serde_json::to_string(...)` repeatedly.
- [ ] Logger file sinks still open append handles on each emit instead of reusing a long-lived writer.
- [ ] UDP JSON sinks still bind a fresh socket per event, which is simple but materially more expensive than a persistent sender on hot paths.
- [ ] Metrics/tracing state still leans heavily on `BTreeMap<String, ...>` and owned-string insertion even for common counters/gauges.
- [ ] Metrics still retain `BTreeMap<String, Vec<MetricPoint>>` histories even on paths that are primarily “increment/read latest value” workloads.
- [ ] Tracer span start/finish paths still clone span state and baggage maps more often than ideal.
- [ ] Service request paths still rebuild small JSON bodies, response header maps, and request/route strings per call even when shapes are highly repetitive.
- [ ] Service metrics/logging/tracing still take mutexes on common request paths, which creates avoidable p95/p99 pressure once concurrency rises.
- [ ] HTTP response serialization still rebuilds header/status text with repeated `format!`/`String` work on each response, even on persistent connections where shapes are often repetitive.

Implication:
- [ ] Even when business logic is fast, logging/metrics/tracing can inject tail latency, lock contention, and avoidable allocation churn into request-heavy paths.
- [ ] The remaining low-latency work is not only about compute kernels; request-path control-plane overhead is now a first-order concern.

### 7) Compiler And Tooling Pipelines Still Carry Significant Clone/String/Tree Churn

Current shape:
- [ ] `parser`, `hir`, `fir`, `pipeline`, and `lsp` still perform large volumes of `clone()`, `to_string()`, `format!()`, and `BTreeMap` / `BTreeSet` materialization.
- [ ] Some of that is fine for clarity and determinism, but the aggregate volume is high enough that compiler CLI latency, incremental analysis, and editor responsiveness can still pay a meaningful tax.
- [ ] Several passes still duplicate symbol names, type renderings, and transient collections instead of reusing cheaper borrowed/indexed forms where safe.
- [ ] The parse/lower caches are present, but several public driver entry points still clone parsed AST/HIR/FIR state back out of cache-owned `Arc` storage.
- [ ] `ParsedProgram` cache exits still clone large AST/path/source-composition state more eagerly than ideal, so cache hits do not automatically mean cheap caller-side reuse.
- [ ] Public cache-return entry points such as `parse_program(...)`, `parse_program_with_metadata(...)`, `lower_fir_cached(...)`, and `lower_fir_cached_with_metadata(...)` still materialize owned values for callers by default.
- [ ] `ParsedProgram::clone(...)` still clones the full `ast::Module` even though source text storage is already shared.
- [ ] LSP cold-path workspace semantics still depend on recursive directory walk + sorted materialization + full file reads when no open-document cache is already populated.

Implication:
- [ ] Runtime/kernel parity work is not the whole perf story; end-to-end product latency also depends on reducing compiler and tooling overhead.
- [ ] Cache presence alone is not enough if the hot API boundary still copies large structures before the caller can use them.
- [ ] The highest-value follow-up is to keep cached parsed/lowered artifacts shared all the way through more call boundaries instead of cloning them back into owned form by default.

### 7A) Build/Validation Orchestration Still Does Too Much Work Before Cheap No-Op Exit

Current shape:
- [ ] Parse/lower caches and native artifact cache markers already exist, which is good.
- [ ] Compile/verify/check flows still perform enough manifest resolution, dependency graph work, parsing, lowering, diagnostics collection, and policy orchestration that warm no-op latency remains far above the desired band.
- [ ] The current warm compile benchmark shape strongly suggests that the cheapest skip decisions are still happening too deep in the pipeline.
- [ ] Manifest/lockfile dependency-graph work still happens eagerly on project resolution paths before the cheapest possible “nothing changed” exit can fire.
- [ ] Native artifact cache keys still hash high-cost inputs such as formatted FIR state and runtime-shim file contents, which is correctness-safe but not latency-cheap.
- [ ] Artifact cache hits still arrive after meaningful front-half work such as source resolution, parse, lower, verifier setup, and diagnostics plumbing has already been paid in compile-oriented flows.
- [ ] `fz build` still layers additional command-path work such as unsafe-doc handling and interop/header artifact handling onto the compile path, which matters more once core compilation itself gets cheaper.

Implication:
- [ ] The next compiler-latency wins are not only “make parsing/lowering faster”.
- [ ] We also need earlier unchanged-input short-circuits so no-op and near-no-op workflows avoid entering expensive orchestration at all.

### 7B) Parser And LSP Cold Paths Still Pay Eager Materialization Cost

Current shape:
- [ ] The parser still lexes into a fully materialized `Vec<Token>` with owned token payloads before semantic work begins.
- [ ] Lexer helpers still rely on repeated character peeks/lookahead over source slices in a few hot literal/tokenization paths.
- [ ] LSP cold workspace semantics still recurse directories, sort entries, read full file contents, and rebuild semantic state from scratch when open-document cache coverage is absent.
- [ ] The lexer still uses repeated `chars().nth(...)` lookahead over sliced source in hot numeric/comment/string-adjacent paths, which is simple and correct but not especially cheap on cold scans.
- [ ] LSP cold semantics still reparse each `.fzy` document into semantic state after a full workspace materialization pass instead of reusing a more persistent workspace index.
- [ ] LSP cold semantic construction also pays for an additional identifier-token scan before full parse/semantic collection, so the cold path compounds “walk, sort, read, scan, parse” work.

Implication:
- [ ] Cold parse and cold tooling startup still have avoidable front-end cost even before HIR/FIR/backend work starts.
- [ ] This is not the highest-priority perf program by itself, but it is a real contributor to cold `fz check`, `fz build`, and first-open workspace latency.

### 8) Scenario Runtime And Trace Emission Still Carry High Event Allocation Cost

Current shape:
- [ ] Deterministic scenario execution still emits many `TraceEvent` records with freshly materialized `String` keys, `String` values, and `serde_json::Map` payloads inside step scheduling and replay loops.
- [ ] Network send/drop/deliver flows still clone payload-bearing state and append multiple trace records per logical operation.
- [ ] Checkpoint/restore machinery is intentionally correctness-first, but large scenario/state surfaces still imply meaningful clone pressure during shrink/replay-oriented workflows.
- [ ] Step lifecycle bookkeeping currently emits multiple trace records per executed step (`sched_pick`, `span_start`, `span_end`) using newly built field maps each time.
- [ ] Profile-building paths then rematerialize many of those event fields into fresh `BTreeMap<String, String>` tag sets, so trace cost is paid once at recording time and again during analysis.
- [ ] Finding-collapse/reporting paths still group by cloned title/message/location strings, which is fine at small scale but adds more owned-string churn to already trace-heavy large runs.

Implication:
- [ ] Large scenarios can still spend a surprising amount of time on observability/bookkeeping overhead rather than the behavior under test.
- [ ] End-to-end latency for `fozzy run` / `fozzy replay` / `fozzy shrink` will benefit from reducing trace-event construction cost even if the underlying semantics stay unchanged.

---

## Strategic Direction

Goal:
- [ ] Lower hot-path primitives to direct memory operations in native codegen whenever semantics are provably local and safe.
- [ ] Reserve runtime calls for boundary-crossing operations or semantics that require shared runtime state.
- [ ] Tighten scalar/domain representation so hot-path state carries the narrowest correct semantics.

Execution architecture invariant:
- [ ] Optimized native pipeline is direct-memory-first; runtime imports are capability/host boundaries only.
- [ ] Legacy local data-plane shim symbols (`str.*`, `list.*`, `map.*`, `__native.array_*`) are not part of optimized native execution.
- [ ] Scalar cleanup is justified only when it improves layout, branching, or lowering quality in aggregate; do not churn types for style alone.

Design principle:
- [ ] Keep language idioms unchanged where possible.
- [ ] Change lowering policy, runtime ABI contracts, and hot-path scalar shape where it produces measurable wins.

---

## Direct-to-Memory Plan (Checklist)

## Phase 0: Measurement + Guardrails

- [ ] Add kernel-level perf CI snapshots for `bytes_kernel`, `result_classify`, `text_kernel`.
- [ ] Add perf budget thresholds (regression alarms on p50/p95 and ratio vs Rust baseline).
- [ ] Add backend split reporting (`llvm` vs `cranelift`) for each kernel.
- [ ] Add a dedicated before/after perf snapshot for any scalar-shape sweep that touches hot structs or hot helper APIs.

## Phase 1: Array/Index Memory Fast Path (Highest Priority)

- [ ] Introduce compiler-recognized fixed numeric array form for native backends.
- [ ] Lower fixed numeric arrays to contiguous native memory (stack or static, backend-dependent).
- [ ] Lower `arr[idx]` to direct load with compile-time-known element size/stride.
- [ ] Keep bounds semantics explicit:
- [ ] strict mode: checked bounds with predictable branch shape
- [ ] trusted hot mode: proven-safe paths elide checks
- [ ] Add canonical lowering for rolling-window index patterns (`off`, `off+1`, `off+2`, `off+3`).
- [ ] Keep runtime-array path as fallback for dynamic/escaping arrays.

Exit criteria:
- [ ] `bytes_kernel` ratio improves from `~4.995x` to target band `<=2.0x` in first pass.
- [ ] No semantic regressions in deterministic replay and conformance tests.

## Phase 2: Enum/Match Control-Flow Fast Path

- [ ] Introduce compact enum discriminant representation in lowered IR/native path.
- [ ] Lower eligible match arms to switch-like CFG where profitable.
- [ ] Preserve existing language semantics for guards/payloads with clear fallback.
- [ ] Keep deterministic tag mapping for ABI/external boundaries when required.

Exit criteria:
- [ ] `result_classify` ratio improves from `~3.155x` to target band `<=1.8x` in first pass.
- [ ] Match diagnostics/exhaustiveness behavior unchanged.

## Phase 3: String Temporary Fast Path

- [ ] Add non-interned temporary string representation for loop-local intermediates.
- [ ] Intern only at semantic escape boundaries (storage, API boundary, persistent handles).
- [ ] Add specialized fast paths for common operations:
- [ ] trim on ASCII whitespace
- [ ] single-token replace
- [ ] contains/starts_with/ends_with on literal needles
- [ ] Keep interned/global representation available as fallback.

Exit criteria:
- [ ] `text_kernel` ratio improves from `~1.667x` to target band `<=1.25x` in first pass.
- [ ] No behavior drift in string equality/identity semantics where externally visible.

## Phase 4: Scalar Shape + Hot Struct Sweep

- [ ] Sweep Fzy-facing stdlib modules for semantically binary fields/returns that should become `bool`.
- [ ] Sweep multi-state integer-shaped flags that should become enums.
- [ ] Leave truly numeric domains as `i32`.
- [ ] Prioritize changes that improve:
- [ ] hot struct compactness
- [ ] branch quality
- [ ] normalization removal
- [ ] lowering clarity
- [ ] cross-layer semantic alignment with Rust stdlib/runtime types

Exit criteria:
- [ ] Hot-path module sweep is complete.
- [ ] No churn-only type edits remain.
- [ ] Aggregate benchmark suite median remains non-regressed and targeted kernels show measurable improvement where scalar cleanup overlaps hot paths.

## Phase 5: Lowering Quality Cleanup (Cross-Cutting)

- [ ] Shift LLVM lowering toward SSA-friendly emission to reduce slot churn.
- [ ] Reduce avoidable calls in expression lowering hot paths.
- [ ] Re-check Cranelift/LLVM parity after direct-to-memory adoption.

Exit criteria:
- [ ] Aggregate benchmark suite ratio median within `<=1.15x` of Rust for covered kernels.

## Phase 6: Runtime Shim De-Contention + Service Hot Path Cleanup

- [ ] Reduce unnecessary `fz_intern_slice(...)` traffic for empty strings, tiny literals, and loop-local/transient substrings.
- [ ] Add dedicated zero-/tiny-string fast paths so common sentinel values do not keep paying full intern lookup/allocation overhead.
- [ ] Add fast paths that keep temporary text uninterned until a true escape boundary.
- [ ] Reduce repeated raw JSON rescans by introducing parsed/cursor/indexed access where repeated lookup is expected.
- [ ] Remove temporary key allocation/free from repeated JSON object-field lookup on native shim paths.
- [ ] Audit `fz_json_lock` usage and narrow critical sections or redesign handle access where safe.
- [ ] Audit runtime list/map helpers for local-only transformation paths that can bypass generic handle mutation.
- [ ] Narrow or redesign coarse list/map helper mutexes where the current lock scope includes avoidable string duplication or join/lookup work.
- [ ] Reduce request-path mutex traffic in observability-heavy service flows.
- [ ] Replace repetitive small JSON/response/header/request formatting in service hot paths with cheaper reusable or direct-write forms where practical.
- [ ] Re-check tail latency impact of logging/tracing/metrics after each request-path cleanup so functional wins are not hidden by control-plane overhead.
- [ ] Audit per-request tracer/log/metric paths for clone-on-commit behavior that is semantically unnecessary once data is already owned by the sink/runtime.
- [ ] Audit persistent HTTP handlers for repeated response `BTreeMap` creation, body `Vec<u8>` materialization, request-id formatting, and tiny JSON string construction on the common path.
- [ ] Collapse the current “request completeness scan then full parse” double-work shape in persistent HTTP handling so header/body state is discovered once per request, not twice.
- [ ] Reduce response serialization rebuild cost on persistent connections by reusing or directly writing common status/header fragments where semantics allow.
- [ ] Keep logger sinks warm on hot paths instead of reopening files or rebinding UDP sockets per emitted record.
- [ ] Reduce per-request UTF-8/request-line/header re-materialization in the stdlib HTTP server path where borrowed byte-slice parsing can remain valid longer on the common path.
- [ ] Remove per-request socket timeout reconfiguration from persistent/steady request paths where the same connection/runtime policy is already known.
- [ ] Reduce accept-loop dispatch overhead in worker-pooled services where the current path probes multiple full queues before deciding overload or placement.

Exit criteria:
- [ ] Host-backed HTTP/process/service scenarios show reduced tail latency and allocation pressure.
- [ ] No determinism or API-contract regressions in runtime-bound scenarios.

## Phase 7: Compiler + Tooling Perf Sweep

- [ ] Run a clone/allocation/string-render census across parser, HIR, FIR, pipeline, and LSP.
- [ ] Replace avoidable owned-string churn with borrowed/indexed/reused forms in hot compilation and analysis passes.
- [ ] Re-evaluate `BTreeMap` / `BTreeSet` usage in hot paths and keep them only where deterministic ordering is part of the requirement.
- [ ] Pre-size and reuse hot vectors/queues where pass structure already exposes stable cardinality.
- [ ] Add compiler-side perf snapshots for CLI parse/check/build latency and incremental/editor-oriented flows.
- [ ] Audit public cache-return APIs and keep large parsed/lowered structures shared across boundaries where callers do not need owned clones.
- [ ] Move unchanged-input and no-op short-circuit decisions as early in the compile/validation pipeline as correctness allows.
- [ ] Separate warm no-op, warm leaf-change, and cold compile work as distinct perf programs rather than treating “compiler latency” as one bucket.
- [ ] Split LSP cold-start costs from warm open-doc flows and optimize recursive workspace scan/read behavior independently.
- [ ] Treat LSP cold first-answer latency as a first-class metric, not just warm open-document latency, so “editor is green” does not hide cold workspace cost.
- [ ] Separate compile-path work from diagnostic/report rendering so formatting-heavy code does not dominate steady-state tool latency.
- [ ] Audit parser lookahead helpers that currently rely on repeated sliced `chars().nth(...)` walks and replace them with cheaper fixed-lookahead mechanics where the hot lexer paths justify it.
- [ ] Reduce full-workspace LSP cold materialization by reusing a more persistent document/semantic index instead of always recurse-sort-read-reparse on cache-cold opens.
- [ ] Audit manifest/load/lockfile/dependency-graph work specifically as part of the warm no-op problem, not just parsing/lowering/codegen.
- [ ] Replace expensive cache-key construction inputs where cheaper stable fingerprints can preserve correctness without hashing debug-rendered whole-program structures.

Exit criteria:
- [ ] `fz check`, `fz build`, and LSP-oriented cold/warm flows show measurable non-noise improvement.
- [ ] Deterministic diagnostics ordering and semantic behavior remain unchanged.

## Phase 8: Scenario Engine + Trace Pipeline Sweep

- [ ] Run a trace-event allocation census across `run`, `replay`, `explore`, `shrink`, and network/memory-heavy scenario paths.
- [ ] Collapse repetitive event field construction into cheaper reusable helpers or more compact internal representations where semantics allow.
- [ ] Audit payload/message cloning in network delivery, memory events, and checkpoint/restore surfaces.
- [ ] Keep deterministic replay fidelity exact while reducing bookkeeping overhead in the non-user-meaningful parts of execution.
- [ ] Add scenario-side perf snapshots for large event volumes, replay-heavy traces, and shrink loops.
- [ ] Audit `run_flow` artifact/report assembly for repeated `events.clone()`, summary cloning, path string materialization, and unconditional run-directory setup that can be deferred or shared.

Exit criteria:
- [ ] Large trace-heavy scenarios show measurable latency/allocation reduction in `fozzy run`, `fozzy replay`, and `fozzy shrink`.
- [ ] Replay/CI/trace-verify signatures remain stable.

---

## Module-By-Module Scalar/Perf Sweep

Purpose:
- [ ] Perform a full source sweep anywhere scalar shape, hot struct layout, normalization, or helper return form is likely to produce aggregate latency wins.
- [ ] Do not treat every `i32` as a bug.
- [ ] Keep `i32` for counts, codes, indices, capacities, dimensions, durations, machine statuses, and ABI-facing numeric domains.
- [ ] Target binary state and multi-state control surfaces where the current `i32` shape costs readability, branching, layout, or lowering quality.

### Tier A — Highest Aggregate Value

#### `core/src/log.fzy`

- [ ] Review `LoggerConfig` fields `json`, `include_correlation`, and `enabled`.
- [ ] Review `should_emit(...)`, `should_sample(...)`, and other pure yes/no helpers.
- [ ] Remove `normalize_flag(...)` style churn where binary semantics can be made explicit.
- [ ] Check whether config/layout alignment with [crates/stdlib/src/observability.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/observability.rs) and Rust-side logging types can reduce translation overhead.

Why this matters:
- [ ] Logging sits on common service hot paths.
- [ ] Small branch and normalization costs can accumulate heavily.

#### `core/src/process.fzy`

- [ ] Review `has_flag(...) -> i32`.
- [ ] Review `ProcessObservation` fields `timed_out`, `cancelled`, and any other binary state.
- [ ] Keep `exit_code`, `wait_status`, `signal`, and limits as numeric.
- [ ] Align semantics more tightly with [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs), which already uses `bool` in several runtime-side contracts.

Why this matters:
- [ ] Process orchestration is common in tooling and production control paths.
- [ ] Observation structs can become cleaner and cheaper to reason about.

#### `core/src/network.fzy`

- [ ] Review `tls`, `ipv6`, `reuse_addr`, `reuse_port`, `tcp_nodelay`, `keepalive`.
- [ ] Review `has_deadline`, `cancelled`.
- [ ] Review pure predicate helpers like `endpoint_is_secure(...)`, `deadline_is_ready(...)`, `deadline_is_expired(...)`, `deadline_is_cancelled(...)`.
- [ ] Keep `port`, `deadline_ms`, and context ids numeric.
- [ ] Align surface more closely with [crates/stdlib/src/http.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/http.rs), which already uses boolean network/server config state internally.

Why this matters:
- [ ] Network/server setup and lifecycle checks are latency-sensitive and branch-heavy.

#### `core/src/io.fzy`

- [ ] Review metadata structs using `exists`, `is_file`, `is_dir`, `is_symlink`.
- [ ] Review plan structs using `recursive` as `i32`.
- [ ] Keep `size` and timestamps numeric.
- [ ] Align with [crates/stdlib/src/io.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/io.rs), which already uses booleans for file-kind metadata.

Why this matters:
- [ ] These metadata structs are common and good candidates for compaction/semantic tightening.

### Tier B — Important, But Less Likely To Move Benchmarks Alone

#### `core/src/thread.fzy`

- [ ] Review `ThreadContext.bound`.
- [ ] Review `has_context(...) -> i32`.
- [ ] Keep task ids, result codes, deadlines, counts, and handles numeric where appropriate.

Why this matters:
- [ ] Improves API precision and can simplify task/runtime lowering logic.

#### `core/src/http.fzy`

- [ ] Review `SseEvent.done`.
- [ ] Review `connection_allows_keep_alive(...) -> i32`.
- [ ] Keep limits, retries, sizes, and timeouts numeric.
- [ ] Confirm any binary connection state aligns with Rust-side HTTP server bool-heavy representation.

Why this matters:
- [ ] HTTP control surfaces are hot in real services, but the big wins here are still more likely in runtime/data-path work than scalar cleanup alone.

#### `core/src/result.fzy`

- [ ] Review `retryable` and `is_clear(...) -> i32`.
- [ ] Keep machine/status codes numeric.
- [ ] Consider whether binary state can tighten while preserving code/status interoperability.

Why this matters:
- [ ] Error handling is everywhere, but machine/status fields must remain cheap and explicit.

#### `core/src/security.fzy`

- [ ] Review `verify(...) -> i32`.
- [ ] Keep signer/version/token byte count domains numeric.
- [ ] Ensure the narrowed application-security facade stays minimal and does not re-grow low-level crypto duplication.

Why this matters:
- [ ] Security is not the top benchmark hot path today, but it is sensitive to branch shape and API cleanliness.

### Tier C — Keep Mostly Numeric Unless Proven Otherwise

#### `core/src/concurrency.fzy`

- [ ] Keep `capacity`, `depth`, and `high_watermark` numeric.
- [ ] Review pure predicates like `can_send`, `is_ready`, `is_high_watermark`, `is_saturated`.
- [ ] Do not churn queue math into booleans where the numeric domain is the actual hot-path value.

#### `core/src/gpu.fzy`

- [ ] Keep lengths, offsets, counts, ids, dimensions, and typed loads/stores numeric.
- [ ] Review only binary helper returns such as `has_device(...) -> i32`.
- [ ] Do not disturb numeric/GPU ABI domains for style.

#### `core/src/abi.fzy`

- [ ] Keep version numbers, sizes, alignments, pointer widths numeric.
- [ ] Review flag-like fields such as `stable_ffi` and predicate helpers such as `layout_is_valid(...) -> i32`.
- [ ] Be conservative: ABI-facing semantics are more sensitive to representation churn.

#### `core/src/cinterop.fzy`

- [ ] Keep numeric domains only where they are truly machine-facing.
- [ ] Review binary flag slots such as `nullable`, `mutable_mode`, and panic-boundary/predicate helpers.
- [ ] Avoid churn unless the new type shape improves contract clarity without hurting FFI discipline.

### Tier D — Deprioritize For This Perf Program

#### `core/src/simd.fzy`

- [ ] Leave numeric lane/index/vector domains numeric.
- [ ] The file already uses real `bool` where mask semantics are genuinely boolean.
- [ ] Treat SIMD work as a lowering/vectorization problem, not a scalar-type cleanup problem.

#### `core/src/bytes.fzy`, `core/src/duration.fzy`, `core/src/retry.fzy`, `core/src/text.fzy`, `core/src/mem.fzy`, `core/src/capability.fzy`

- [ ] Keep these mostly as-is unless measurement shows a concrete payoff.
- [ ] These are either clearly numeric, already small, or not likely to produce meaningful aggregate latency wins from scalar-shape edits alone.

### Rust Runtime / Stdlib Parity Sweep

Purpose:
- [ ] Use the Rust-side stdlib/runtime layer as a guide for where binary state already exists and can inform Fzy-facing cleanup.

Sweep targets:
- [ ] [crates/stdlib/src/http.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/http.rs)
- [ ] [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs)
- [ ] [crates/stdlib/src/io.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/io.rs)
- [ ] [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs)
- [ ] [crates/stdlib/src/text.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/text.rs)
- [ ] [crates/stdlib/src/concurrency.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/concurrency.rs)
- [ ] [crates/stdlib/src/observability.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/observability.rs)

Questions to answer in each:
- [ ] Where does the Rust layer already use `bool` or typed enums?
- [ ] Where is the Fzy-facing layer wider or less precise than the runtime layer?
- [ ] Which mismatches are worth fixing for measurable aggregate benefit?

---

## Whole-Codebase Perf Sweep

Purpose:
- [ ] Treat this document as the repo-wide remaining perf program, not just a scalar-shape follow-up.
- [ ] Sweep every layer where aggregate gains are plausible: compiler front-end, semantic pipeline, native runtime shim, stdlib runtime services, and Fzy-facing hot-path modules.
- [ ] Favor wins that compound across common workflows: `fz check`, `fz build`, `fz test`, host-backed service runs, request handling, and logging/observability-heavy scenarios.

### Sweep A — Compiler Front-End And Semantic Pipeline

Targets:
- [ ] [crates/parser/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/parser/src/lib.rs)
- [ ] [crates/hir/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/hir/src/lib.rs)
- [ ] [crates/fir/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/fir/src/lib.rs)
- [ ] [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs)
- [ ] [crates/driver/src/lsp.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/lsp.rs)

Checklist:
- [ ] Count hot `clone()`, `to_string()`, and `format!()` sites that sit inside repeated traversal/codegen/diagnostic loops.
- [ ] Identify large `BTreeMap` / `BTreeSet` constructions used for convenience rather than deterministic contract requirements.
- [ ] Audit repeated type/signature rendering and reuse cached/rendered forms where the same value is emitted many times in one pass.
- [ ] Audit repeated environment/scope copies and prefer narrower mutation windows or indexed ownership where safe.
- [ ] Separate hot compile-path work from cold diagnostic/report formatting work so cold-path string building does not leak into steady-state checks/builds.
- [ ] Audit cache-return boundaries so parsed/lowered artifacts are not cloned back into owned form when shared references would suffice.
- [ ] Treat LSP cold-start workspace scans as a separate perf surface from open-document incremental semantics.
- [ ] Audit parser lookahead helpers that currently rescan UTF-8 slices with `chars().nth(...)` in hot tokenization paths.
- [ ] Audit workspace-semantic construction for “walk, read, sort, parse everything” behavior when only a subset of workspace files is needed.

Why this matters:
- [ ] Compiler latency is product latency.
- [ ] Small pass-level improvements compound across every CLI command, CI run, and LSP analysis cycle.

### Sweep B — Native Runtime Shim And Host Bridge

Targets:
- [ ] [crates/driver/src/pipeline/native_runtime_support/runtime_shim/core.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline/native_runtime_support/runtime_shim/core.rs)
- [ ] [crates/driver/src/pipeline/native_runtime_support/runtime_shim/http.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline/native_runtime_support/runtime_shim/http.rs)
- [ ] [crates/driver/src/pipeline/native_runtime_support/runtime_shim/term.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline/native_runtime_support/runtime_shim/term.rs)
- [ ] [crates/driver/src/pipeline/native_runtime_support/runtime_shim/gpu.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline/native_runtime_support/runtime_shim/gpu.rs)

Checklist:
- [ ] Count and classify `fz_intern_slice(...)` call sites by semantic need: persistent, escape-boundary, empty-literal, tiny-literal, transient substring, loop-local temporary.
- [ ] Audit `fz_json_lock` critical sections and repeated JSON lookup helpers for index/cursor/cache opportunities.
- [ ] Review runtime list/map handle helpers for generic-path overhead in local transform pipelines.
- [ ] Audit stream/process/websocket helpers for repeated empty-string/error-kind interning that can be collapsed or cached.
- [ ] Audit request-header/query/body ingestion paths that currently intern nearly every observed token immediately on persistent HTTP flows.
- [ ] Audit JSON object-body extraction paths that still allocate/free temporary parsed keys before map insertion.
- [ ] Ensure any shim fast path preserves strict deterministic replay behavior.

Why this matters:
- [ ] The shim sits directly on hot data movement and host/service boundaries.
- [ ] Lock and intern churn here can dominate perceived “language overhead” even when generated code is otherwise healthy.

### Sweep C — Rust Stdlib Runtime Services

Targets:
- [ ] [crates/stdlib/src/http.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/http.rs)
- [ ] [crates/stdlib/src/process.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/process.rs)
- [ ] [crates/stdlib/src/io.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/io.rs)
- [ ] [crates/stdlib/src/concurrency.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/concurrency.rs)
- [ ] [crates/stdlib/src/observability.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/observability.rs)
- [ ] [crates/stdlib/src/collections.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/collections.rs)
- [ ] [crates/stdlib/src/text.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/text.rs)
- [ ] [crates/stdlib/src/security.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/security.rs)

Checklist:
- [ ] Audit allocation-heavy request/log/metric paths for repeated cloning and owned-string conversion.
- [ ] Review `Arc<Mutex<...>>` hot paths for contention risk and determine where batching, ring buffers, snapshots, or lock narrowing are better fits.
- [ ] Review `BTreeMap` / `BTreeSet` usage and retain it only where stable ordering is materially required.
- [ ] Identify text helpers that eagerly allocate `String` where borrowed view logic could remain live longer.
- [ ] Audit concurrency/process/http helpers for unnecessary intermediate records in common request/control paths.
- [ ] Audit request-path JSON/HTTP response construction for repeated tiny allocations that can dominate tail latency even after larger runtime wins land.
- [ ] Audit stdlib HTTP request handling for the exact current common-path shape: request completeness scan, then full parse, then full response materialization.
- [ ] Audit stdlib HTTP request parsing for the current owned-shape tax: header `String` creation, request-line part collection, header `BTreeMap<String, String>` population, and body `Vec<u8>` duplication on the common path.
- [ ] Audit HTTP response serialization for repeated `format!`-driven status/header assembly when direct-write or reused fragments could keep the same behavior more cheaply.
- [ ] Audit tracer/log sinks for per-event clone work that is semantically unnecessary once the event is committed.
- [ ] Audit memory log sinks and tracer span retention for clone-heavy append/finish behavior under high event volume.
- [ ] Audit metric history structures that currently retain `BTreeMap<String, Vec<MetricPoint>>` state even on paths that are primarily “increment/read latest counter” workloads.

Why this matters:
- [ ] These modules define host-backed behavior the user actually feels.
- [ ] Tail latency often comes from observability and service plumbing, not just core compute kernels.

### Sweep E — Scenario Engine, Replay, And Reporting

Targets:
- [ ] [crates/fzscenario/src/runtime/engine.rs](/Users/deepsaint/Desktop/fozzylang/crates/fzscenario/src/runtime/engine.rs)
- [ ] [crates/fzscenario/src/runtime/run_flow.rs](/Users/deepsaint/Desktop/fozzylang/crates/fzscenario/src/runtime/run_flow.rs)
- [ ] [crates/fzscenario/src/runtime/tracefile.rs](/Users/deepsaint/Desktop/fozzylang/crates/fzscenario/src/runtime/tracefile.rs)
- [ ] [crates/fzscenario/src/model/reporting.rs](/Users/deepsaint/Desktop/fozzylang/crates/fzscenario/src/model/reporting.rs)

Checklist:
- [ ] Count trace-event allocations in common scheduling, replay, network, and memory paths.
- [ ] Audit repeated `String`/`serde_json::Map` construction in step lifecycle events.
- [ ] Audit repeated `step_kind` / `span_id` string construction inside run and replay step loops.
- [ ] Audit checkpoint/restore clone surfaces that grow with scenario state size.
- [ ] Keep report collapsing/rendering off the hot execution path where possible.
- [ ] Audit profile-building/tagging passes for second-stage field copying into `BTreeMap<String, String>` and per-span search/removal behavior.
- [ ] Audit run/replay summary construction for clone-on-record behavior where the trace/report path currently copies already-owned state before output selection is finalized.

Why this matters:
- [ ] Fozzy-first workflows are part of the product surface, so scenario-engine latency is user-visible latency.
- [ ] Deterministic execution can stay exact while still getting materially cheaper to record and replay.

### Sweep D — Fzy Core Module Perf Contracts

Targets:
- [ ] Every `core/src/*.fzy` module already called out in the scalar sweep above
- [ ] Additional sanity pass on `core/src/bytes.fzy`, `core/src/text.fzy`, `core/src/retry.fzy`, `core/src/duration.fzy`, `core/src/capability.fzy`

Checklist:
- [ ] Distinguish type-shape cleanup from true data-path cleanup.
- [ ] Audit helper layering for accidental repeated map/list/string construction in hot APIs.
- [ ] Audit common request/process/io/network flows for normalization helpers that can be folded away.
- [ ] Confirm public Fzy surfaces are not forcing runtime-path work that the Rust/runtime layer already knows how to express more cheaply.

Why this matters:
- [ ] Aggregate overhead frequently enters through “small helper” paths that are individually cheap but ubiquitous.

### Sweep F — Example App Reality Check

Targets:
- [ ] [apps/live_server/src/main.rs](/Users/deepsaint/Desktop/fozzylang/apps/live_server/src/main.rs)
- [ ] [apps/robust_cli/src/main.rs](/Users/deepsaint/Desktop/fozzylang/apps/robust_cli/src/main.rs)

Checklist:
- [ ] Confirm which stdlib/runtime perf debts are exercised by actual request-path and operator-path code today, not just by library abstractions.
- [ ] Audit example flows for mutexed logger/metrics/tracer access, per-request request-id formatting, response-body string construction, and avoidable span/log churn.
- [ ] Audit example service accept/dispatch loops for queue-probing, overload handling, and per-request setup work that can hide under otherwise-good library/runtime perf.
- [ ] Audit example request paths for per-request timeout setting, tiny JSON formatting, and lock acquisition order so p95 control-plane overhead stays visible.
- [ ] Use the example apps as reality checks so library perf work is prioritized by composed end-to-end latency, not by theoretical surface area alone.

Why this matters:
- [ ] The example services are where HTTP, observability, runtime, and persistence costs compose into user-visible latency.
- [ ] They help keep the perf program anchored to real product-path behavior.

---

## Current Low-Latency Priorities

Priority ordering after the full sweep:
- [ ] Priority 1: compiler/build warm-path latency reduction, especially no-op and near-no-op flows
- [ ] Priority 2: runtime-shim de-contention and persistent-path cleanup
- [ ] Priority 3: logging/metrics/tracing request-path overhead
- [ ] Priority 4: targeted Fzy-facing scalar tightening in `core/src/log.fzy`, `core/src/http.fzy`, and `core/src/result.fzy`
- [ ] Priority 5: scenario-engine and trace-event bookkeeping reduction
- [ ] Priority 6: parser/LSP cold-start and workspace-scan cleanup once higher-yield latency work lands

Priority nuance from this sweep:
- [ ] Keep interactive LSP/editor micro-latency as a guarded surface, but do not let currently-green editor gates distract from the much larger warm compile/build debt.
- [ ] Treat cache-boundary clone removal as part of Priority 1 rather than as a nice-to-have refactor; it is one of the clearest ways to turn existing caches into visible latency wins.
- [ ] Treat observability overhead as production-real rather than theoretical: example app request paths currently exercise mutexed logger/metrics/tracer flows directly.
- [ ] Treat persistent HTTP parsing/serialization as the clearest remaining runtime latency target; the latest broad-suite run still identifies `http_kernel_persistent` as the standout laggard.

What this means in practice:
- [ ] The next wins are split across two classes:
- [ ] no-op and near-no-op compiler/build latency
- [ ] p95/p99 runtime control-plane cost
- [ ] It is now easy to hide a real runtime or lowering win behind logging/tracing/JSON/intern overhead unless those paths are measured alongside the kernel ratios.
- [ ] “Language overhead” is increasingly a composite of compile orchestration cost, runtime-shim cost, observability cost, and tooling latency, not just direct compute throughput.

---

## Runtime Coherence Rules

- [ ] Policy A: direct memory first for proven-local, non-escaping data.
- [ ] Policy B: runtime handle path for shared, dynamic, escaping, or capability-bound data.
- [ ] Policy C: determinism-first fallback where optimization could perturb deterministic semantics.
- [ ] Policy D: keep numeric domains numeric; narrow only semantically binary or genuinely multi-state control surfaces.
- [ ] Document exact eligibility matrix for scalar cleanup:
- [ ] hot-path struct
- [ ] binary semantic meaning
- [ ] measurable normalization/branch/layout cost
- [ ] no ABI hazard

---

## Risk Register

- [ ] Risk: scalar churn without measurable gains.
- [ ] Mitigation: require benchmark or layout/branch justification for every hot-path scalar cleanup batch.

- [ ] Risk: semantic drift between Fzy-facing layer and Rust runtime layer.
- [ ] Mitigation: parity sweep and explicit cross-layer contract review.

- [ ] Risk: determinism regressions due to lowering-path changes.
- [ ] Mitigation: strict deterministic replay/trace verification gates per phase.

- [ ] Risk: ABI/interop surprises from representation changes.
- [ ] Mitigation: freeze external ABI contracts; optimize only internal and non-ABI-facing representations unless explicitly approved.

- [ ] Risk: backend divergence (`llvm` vs `cranelift`).
- [ ] Mitigation: backend conformance tests and explicit feature parity tracking.

---

## Validation Matrix (Fozzy-First)

For each phase, run:
- [ ] `fozzy doctor --deep --scenario <scenario> --runs 5 --seed <seed> --json`
- [ ] `fozzy test --det --strict-verify <scenarios...> --json`
- [ ] `fozzy run ... --det --record <trace.fozzy> --json`
- [ ] `fozzy trace verify <trace.fozzy> --strict --json`
- [ ] `fozzy replay <trace.fozzy> --json`
- [ ] `fozzy ci <trace.fozzy> --json`
- [ ] Host-backed run where feasible:
- [ ] `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`

Latest validation refresh (2026-06-13):
- [ ] `fozzy doctor --deep --scenario tests/core.bench_matrix.pass.fozzy.json --runs 5 --seed 20260613 --json`
- [ ] `fozzy test tests/core.bench_matrix.pass.fozzy.json --det --strict-verify --json`
- [ ] `fozzy run tests/core.bench_matrix.pass.fozzy.json --det --strict-verify --record artifacts/core_bench_matrix_review.trace.fozzy --json`
- [ ] `fozzy trace verify artifacts/core_bench_matrix_review.trace.fozzy --strict-verify --json`
- [ ] `fozzy replay artifacts/core_bench_matrix_review.trace.fozzy --json`
- [ ] `fozzy ci artifacts/core_bench_matrix_review.trace.fozzy --json`
- [ ] Determinism audit remained consistent across 5/5 doctor runs for `tests/core.bench_matrix.pass.fozzy.json`.
- [ ] Recorded trace replay/verify/CI all stayed green, so current perf concerns are headroom and latency debt, not active determinism breakage.
- [ ] Additional command-path confirmation from this sweep:
- [ ] `cargo run -p fz -- perf --json` reported `averageRatioFzyOverRust ~1.004x`, `benchCount=17`, and `worstKernel=http_kernel_persistent`
- [ ] `cargo run -p fz -- test --det --strict-verify tests/core.bench_matrix.pass.fozzy.json --json` passed
- [ ] `cargo run -p fz -- run tests/core.bench_matrix.pass.fozzy.json --det --strict-verify --record core_bench_matrix_perf_sweep.trace.fozzy --json` passed
- [ ] `cargo run -p fz -- trace verify core_bench_matrix_perf_sweep.trace.fozzy --strict --json` passed
- [ ] `cargo run -p fz -- replay core_bench_matrix_perf_sweep.trace.fozzy --json` passed
- [ ] `cargo run -p fz -- ci core_bench_matrix_perf_sweep.trace.fozzy --json` passed

Production perf gate:
- [ ] `scripts/direct_memory_perf_gate.py` enforces:
- [ ] `bytes_kernel <= 1.40`
- [ ] `result_classify <= 1.30`
- [ ] `text_kernel <= 1.25`
- [ ] near-parity kernels (`capability_parse`, `task_retry_backoff`, `arithmetic_kernel`, `duration_kernel`, `abi_pair_kernel`) `<= 1.15`
- [ ] bounded service/runtime kernels (`http_kernel_oneoff`, `network_kernel`, `concurrency_kernel`, `process_kernel`, `security_kernel`) `<= 1.20`
- [ ] bounded persistent-path kernel (`http_kernel_persistent`) `<= 1.70`
- [ ] Add scenario-engine perf snapshots for trace-heavy replay/shrink flows so repo-wide latency work is not measured only through kernel benchmarks.

---

## Implementation Notes To Revisit

- [ ] Add compiler flag(s) for fast-path forcing and disabling:
- [ ] `--perf-fastpath=off|on|force`
- [ ] `--perf-lowering-report`
- [ ] Emit per-function lowering report with counts:
- [ ] direct loads/stores
- [ ] runtime handle calls
- [ ] bounds checks emitted/elided
- [ ] match lowered as switch vs branch chain
- [ ] scalar cleanup applied / skipped with reason
- [ ] clone/string/tree churn hotspots by pass
- [ ] shim interning / JSON lock / handle-helper counts by function
- [ ] Track gains per transformation rather than batch-only rollout.

---

## North-Star Targets

- [ ] Eliminate runtime-call overhead from hot numeric kernels where semantics allow direct memory lowering.
- [ ] Converge branch-heavy classify workloads toward near-parity through control-flow/discriminant improvements.
- [ ] Reduce string-kernel overhead primarily by avoiding unnecessary intern/lock/allocation churn.
- [ ] Tighten Fzy-facing scalar representation where it yields measurable layout, branching, or normalization wins in aggregate.
- [ ] Preserve language idioms and deterministic guarantees while improving machine-level efficiency.
