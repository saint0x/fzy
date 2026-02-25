# plan.md — P0 Production Architecture Reset (No Backward Compatibility)

Date: 2026-02-25
Owner: Runtime/Compiler Core
Status: Ready for execution

## 1. Mandate

Implement all 2026-02-25 P0 follow-ups as architectural replacements, not patch fixes.

Constraints for this plan:
- No backward compatibility requirements.
- Any incompatible runtime/trace/API/schema change is allowed.
- Optimize for production correctness first, then latency/throughput, then code simplicity.

## 2. Baseline (captured 2026-02-25)

- [x] ✅ `fozzy map suites --root . --scenario-root tests --profile pedantic --json` baseline captured:
  - `requiredHotspotCount=17`
  - `uncoveredHotspotCount=17`
- [x] ✅ Determinism spot-check passed:
  - `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json` (consistent signatures across all 5 runs)
- [x] ✅ Strict deterministic test spot-check passed:
  - `fozzy test --det --strict tests/example.fozzy.json --seed 4242 --json`
- [x] ✅ Trace lifecycle spot-check passed:
  - `fozzy run tests/example.fozzy.json --det --seed 4242 --record artifacts/p0-audit.trace.fozzy --json`
  - `fozzy trace verify artifacts/p0-audit.trace.fozzy --strict --json`
  - `fozzy replay artifacts/p0-audit.trace.fozzy --json`
  - `fozzy ci artifacts/p0-audit.trace.fozzy --json`
- [x] ✅ Host backend spot-check passed:
  - `fozzy run tests/example.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`

## 3. Architecture Decisions (global)

1. Introduce `runtime.v2` boundaries:
- `net_core` (OS readiness + sockets)
- `http_core` (streaming parser/serializer)
- `sched_core` (deterministic scheduler + timeout wheel)
- `trace_core` (borrowed/streamed decision access)

2. Remove clone-first APIs and replace with borrow/iterator/snapshot-handle APIs.

3. Replace single-shot read/write semantics with framed streaming semantics everywhere HTTP is handled.

4. Deterministic and host backends share the same state-machine contracts; backend-specific behavior only in I/O adapters.

5. Trace/schema bump to vNext with breaking changes accepted.

## 4. Workstreams

## WS1 — `HostNet::listen` contract correctness

Problem:
- `HostNet::listen` validates and records decision but does not invoke OS `listen(2)` semantics.

Design:
- Store pre-listen socket handles (`socket2::Socket`) for listener entries.
- Transition listener lifecycle explicitly: `Bound -> Listening(backlog) -> Closed`.
- Call `socket.listen(backlog)` once; reject repeated listen with incompatible backlog.

Primary files:
- `crates/stdlib/src/net.rs`

Acceptance:
- Binding without listen must not accept connections.
- Listen backlog is enforced and observable under host stress scenarios.

## WS2 — HTTP runtime correctness for partial I/O

Problem:
- Server hot path does single `read` into fixed buffer and assumes full request; response path assumes one-shot serialization/writes.

Design:
- Add `HttpConn` state machine:
  - incremental header parse until `\r\n\r\n`
  - body framing by `Content-Length` and `Transfer-Encoding: chunked`
  - bounded incremental reads respecting limits/timeouts
- Add `write_all_with_budget` loop for short writes and timeout budget enforcement.
- Move `parse_http_request` from `&[u8] -> HttpRequest` to streaming decoder returning `NeedMore | Complete | Error`.

Primary files:
- `crates/stdlib/src/net.rs`
- `apps/live_server/src/main.rs`

Acceptance:
- Partial header/body and short write scenarios pass under host and deterministic backends.
- Keep-alive pipelining and `Expect: 100-continue` behave correctly under fragmented transport.

## WS3 — Remove clone-heavy host poll scan

Problem:
- `scan_poll_interests` clones `poll_interests` each cycle.

Design:
- Replace `BTreeMap<SocketId, PollInterest>` scan model with evented poller registrations:
  - `mio::Poll` + `Events` (or kqueue/epoll wrapper), one registration per socket+interest.
- Maintain socket metadata map; readiness comes from poller events, not map clone iteration.
- Keep deterministic ordering by stable event normalization before enqueue.

Primary files:
- `crates/stdlib/src/net.rs`

Acceptance:
- No `poll_interests.clone()` in hot path.
- Poll cycle cost scales with ready events, not registered sockets.

## WS4 — Remove per-task OS thread spawn in deterministic timeout path

Problem:
- `Executor::execute_task` spawns one OS thread per timed task (`recv_timeout` bridge).

Design:
- Replace with scheduler-native timeout wheel/min-heap:
  - task start timestamp in virtual clock
  - timeout deadline checked at scheduling points
  - timed-out tasks transition without OS thread handoff
- Add deterministic `TaskBudgetExceeded` event for trace.

Primary files:
- `crates/runtime/src/lib.rs`

Acceptance:
- No `std::thread::spawn` inside deterministic task execution path.
- Timeout behavior remains deterministic across seeds and replay.

## WS5 — Replace O(n) mid-queue removals for random/replay

Problem:
- `VecDeque::remove(index)` in random scheduling and replay path is O(n).

Design:
- Replace run queue with deterministic indexed structure:
  - `SlotMap<TaskId, QueueNode>` + intrusive linked list + index vector
  - O(1) pop front/back/random-by-index removal
- Replay path uses direct handle removal, not linear position scans.

Primary files:
- `crates/runtime/src/lib.rs`

Acceptance:
- No linear `position/remove(index)` in scheduler/replay hot paths.
- Seed-deterministic order preserved.

## WS6 — Reduce HTTP parser/serializer allocation churn

Problem:
- Multiple `to_vec`, header-map clones, repeated lowercasing/formatting in request/response handling.

Design:
- Introduce `HttpArena`/scratch buffers per connection.
- Header representation:
  - parsed header table references byte slices
  - canonical comparison via case-folded key cache once per header
- Response serialization uses pre-sized buffers + `writev`-style segmented output.

Primary files:
- `crates/stdlib/src/net.rs`
- `apps/live_server/src/main.rs`

Acceptance:
- Remove clone-heavy header/body materialization in steady state.
- Allocation count drops materially in profile comparison (`fozzy profile diff`).

## WS7 — Remove full decision-log clones in runtime networking surfaces

Problem:
- `decisions() -> Vec<NetDecision>` clones full log.

Design:
- Replace with three APIs:
  - `decisions_iter(&self) -> impl Iterator<Item=&NetDecision>`
  - `decision_cursor(since: DecisionId)` for incremental snapshots
  - `decision_export(range)` for bounded owned export
- Update call sites to consume iterators/cursors.

Primary files:
- `crates/stdlib/src/net.rs`
- downstream callers in `crates/driver` and runtime/report paths

Acceptance:
- No unbounded full-log clone API in core hot paths.

## WS8 — Reduce clone-heavy FIR + driver module merge/qualification/canonicalization

Problem:
- Module merge/qualification/canonicalization repeatedly clone AST/FIR structures.

Design:
- Build immutable module arena with symbol interning (`SymbolId`) and shared strings.
- Merge by node references, not whole-item cloning.
- Qualification/canonicalization becomes in-place ID rewrite pass over compact IR.
- Data-flow/liveness caches keyed by function hash + invalidation on changed nodes only.

Primary files:
- `crates/driver/src/pipeline.rs`
- `crates/fir/src/lib.rs`

Acceptance:
- Remove major `iter().cloned()` merge paths.
- Large-project compile latency materially reduced in profile snapshots.

## WS9 — Close pedantic topology coverage gaps (17 required hotspots)

Problem:
- `fozzy map suites --profile pedantic` reports all 17 required hotspots uncovered.

Design:
- For each required hotspot, add missing suite artifacts:
  - `explore_schedule_faults`
  - `fuzz_inputs`
  - `host_backends_run`
  - `memory_graph_diff_top`
  - `shrink_exercised`
- Create `tests/pedantic/` coverage matrix files by component hotspot.
- Add CI gate that fails on `uncoveredHotspotCount != 0`.

Primary files:
- `tests/` (new scenario files)
- CI config + docs (`USAGE.md`, `README.md`)

Acceptance:
- `fozzy map suites --root . --scenario-root tests --profile pedantic --json` returns `uncoveredHotspotCount=0`.

## 5. Breaking Changes (explicit)

1. Network trace/schema vNext:
- Decision model changes from clone-export snapshots to cursor/iterator-backed events.
- Old trace readers are unsupported.

2. HTTP APIs:
- Parsing and serving APIs become streaming/stateful; one-shot parse helpers become test-only adapters.

3. Runtime scheduler internals:
- Queue and timeout behavior are reimplemented; internal event names may change.

4. Compiler internals:
- FIR/driver internal data structures switch to arena+ID model; old assumptions about cloned AST ownership are invalid.

## 6. Execution Order (must follow)

Phase 0 (guardrails)
- Add microbench/profiling baselines for runtime net/http/scheduler/compiler passes.

Phase 1 (correctness-critical)
- WS1, WS2, WS4 first.

Phase 2 (hot-path latency)
- WS3, WS5, WS6, WS7.

Phase 3 (compile-time latency)
- WS8.

Phase 4 (coverage sign-off)
- WS9.

Phase 5 (release hardening)
- Full Fozzy surface gate and perf/regression thresholds.

## 7. Fozzy-First Validation Gate (release blocker)

Required sequence:

1. Determinism doctor (strict first)
- `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json`

2. Deterministic strict scenario tests
- `fozzy test --det --strict tests/*.fozzy.json --seed 4242 --json`

3. Record + verify + replay + ci for at least one trace per changed subsystem
- `fozzy run <scenario> --det --record artifacts/<name>.trace.fozzy --json`
- `fozzy trace verify artifacts/<name>.trace.fozzy --strict --json`
- `fozzy replay artifacts/<name>.trace.fozzy --json`
- `fozzy ci artifacts/<name>.trace.fozzy --json`

4. Host-backed checks (CLI/runtime delivery)
- `fozzy run <scenario> --proc-backend host --fs-backend host --http-backend host --json`

5. Full surface coverage commands
- `fozzy fuzz scenario:<scenario> --mode coverage --runs 100 --seed 4242 --json`
- `fozzy explore <distributed-scenario> --schedule coverage_guided --steps 200 --seed 4242 --json`
- `fozzy shrink artifacts/<name>.trace.fozzy --json`
- `fozzy artifacts ls latest --json`
- `fozzy report show latest --format json --json`
- `fozzy env --json`
- `fozzy usage --json`

6. Topology closure gate
- `fozzy map suites --root . --scenario-root tests --profile pedantic --json`
- Must produce `uncoveredHotspotCount=0`.

## 8. Done Criteria (production sign-off)

All items must be true:
- WS1..WS9 merged.
- No compatibility shims for removed core APIs remain in runtime/stdlib/driver hot paths.
- Deterministic replay remains stable under new scheduler/network designs.
- Pedantic topology uncovered hotspots reduced from 17 to 0.
- Perf gates show non-regression or improvement for:
  - host net poll path
  - HTTP request/response path
  - deterministic scheduler timeout/random/replay paths
  - FIR+driver module pipeline latency

## 9. Immediate next PR split

PR-A: WS1 + WS3 (HostNet listen + evented poller)
PR-B: WS2 + WS6 (HTTP streaming correctness + low-allocation codec)
PR-C: WS4 + WS5 (scheduler timeout wheel + O(1) queue removals)
PR-D: WS7 (decision API redesign)
PR-E: WS8 (FIR/driver arena and pass rewrite)
PR-F: WS9 (pedantic hotspot suite closure + CI enforcement)
