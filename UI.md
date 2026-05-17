# UI.md

Production execution doc for making Fzy an elite browser-runtime target while keeping framework concerns in Fzact.

## Scope

Fzy core owns:

- compilation
- runtime
- scheduler
- browser ABI
- source maps
- module graph
- async semantics
- frontend-oriented tooling

Fzy core does not own:

- routers
- components
- UI primitives
- JSX
- SSR
- hydration
- design systems
- VDOM architecture
- component libraries
- state management philosophy

Those belong in Fzact.

## Architecture Guardrails

- Preserve and extend the existing architecture:
  parser -> HIR -> FIR -> verifier -> driver -> backend/runtime
- Reuse existing diagnostics, parity, equivalence, deterministic replay, trace, and host-backed validation flows.
- Reuse existing module graph, runtime, scheduler, and LSP infrastructure where possible.
- Do not create duplicate browser-only semantic systems when existing core layers can be extended.
- Keep browser support as an official backend/runtime/tooling path, not a sidecar prototype.

## Delivery Model

This document is organized by agent ownership. Each agent owns one lane, must coordinate with the nearest adjacent lane, and must not expand into Fzact territory.

Each agent section contains:

- exact mission
- current code areas closest to their work
- nearby adjacent work so they do not step on another agent
- production checklist
- strict criteria for success

## Shared Foundations Already Present

✅ Closures, captures, lambdas, async, generics, and traits exist in the current language baseline  
✅ Deterministic scheduler foundations already exist in [crates/runtime/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/lib.rs)  
✅ Rich diagnostics already exist in [crates/diagnostics/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/diagnostics/src/lib.rs) and [docs/compiler-diagnostics-v1.md](/Users/deepsaint/Desktop/fozzylang/docs/compiler-diagnostics-v1.md)  
✅ Incremental document sync and LSP foundations already exist in [crates/driver/src/lsp.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/lsp.rs)  
✅ In-process parse/HIR/FIR caches already exist in [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs)  
✅ Driver/backend orchestration already exists in [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs) and [crates/driver/src/command.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/command.rs)

## Agent 1: JS Backend and ESM Emission

Agent 1 owns the official browser compilation target. Their job is to extend the current parser -> HIR -> FIR -> driver pipeline into a readable, deterministic JS emitter without rewriting language semantics or inventing a separate browser compiler. Their closest working area is [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs), with supporting ownership in [crates/parser/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/parser/src/lib.rs), [crates/ast/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/ast/src/lib.rs), [crates/hir/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/hir/src/lib.rs), [crates/fir/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/fir/src/lib.rs), [crates/verifier/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/verifier/src/lib.rs), [crates/driver/src/command.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/command.rs), and [apps/fozzyc/src/entry.rs](/Users/deepsaint/Desktop/fozzylang/apps/fozzyc/src/entry.rs). Close by their area, Agent 2 will handle source maps and debug mapping, Agent 3 will handle persistent graph caching and invalidation, and Agent 5 will define the runtime semantics that this emitter must lower to. Agent 1 must consume those contracts, not redefine them. Agent 1 must not own browser runtime ABI policy, dev server behavior, HMR, or reactive primitives.

### Checklist

✅ Add official JS backend CLI entrypoint: `fz build <path> --backend js`
✅ Integrate JS backend into existing backend selection logic
✅ Add JS backend artifact model to driver output
✅ Emit readable JavaScript first
✅ Emit deterministic output for unchanged inputs
✅ Avoid minification as a v1 requirement
✅ Avoid optimizer-driven transforms that reduce debuggability in initial rollout
✅ Emit native ESM modules
✅ Support `import`
✅ Support `export`
✅ Support dynamic `import()`
✅ Lower closures to JS
✅ Lower captures to JS
✅ Lower async functions to JS
✅ Lower task primitives to JS runtime hooks defined by Agent 5
✅ Define and implement trait lowering strategy for JS backend
✅ Define and implement generic lowering strategy for JS backend
✅ Lower enums to tagged unions with stable tag rules
✅ Add backend capability diagnostics for JS target
✅ Add representative JS backend parity fixtures
✅ Add representative JS backend equivalence fixtures
✅ Validate compatibility with Vite
✅ Validate compatibility with Rollup
✅ Validate compatibility with ESBuild
✅ Validate compatibility with Bun
✅ Validate direct browser loading contract

### Strict Criteria for Success

✅ `fz build <path> --backend js` must be a supported first-class command path
✅ JS backend must lower from the existing typed pipeline, not a parallel ad hoc path
✅ Output must be readable ESM JavaScript
✅ JS backend must preserve observable semantics for closures, async, enums, and ordinary module imports
✅ Backend must have dedicated parity and equivalence coverage in the same release discipline as native backends
✅ No runtime ABI policy may be hardcoded into emitter logic that should instead live in runtime or stdlib contracts

## Agent 2: Source Maps and Browser Debugging

Agent 2 owns source maps, original-location recovery, and browser-debug readiness for the JS backend. Their work sits closest to [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs), [crates/driver/src/command.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/command.rs), [crates/diagnostics/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/diagnostics/src/lib.rs), and the existing debug and diagnostics flows documented in [docs/compiler-diagnostics-v1.md](/Users/deepsaint/Desktop/fozzylang/docs/compiler-diagnostics-v1.md). They work next to Agent 1 because source maps depend on emitted JS structure, and next to Agent 7 because browser overlays and surfaced errors depend on mapped locations. Agent 2 must preserve the existing diagnostics model and extend it into browser tooling rather than inventing a disconnected debug stack. Agent 2 must not own JS lowering semantics or dev-server transport logic.

### Checklist

✅ Add CLI support: `fz build <path> --backend js --sourcemap`
✅ Emit `<entry>.js`
✅ Emit `<entry>.js.map`
✅ Emit stable source map metadata for unchanged inputs
✅ Preserve original file mapping
✅ Preserve original line mapping
✅ Preserve original symbol mapping where possible
✅ Support browser stack trace mapping
✅ Support async frame mapping
✅ Support breakpoint-friendly source ranges
✅ Support devtools-consumable sourcemap format
✅ Extend `fz debug-check` with JS/sourcemap readiness checks
✅ Add browser-debug-specific regression fixtures
✅ Add source-mapped stack trace fixtures
✅ Add source-mapped async trace fixtures
✅ Add release-gate coverage for sourcemap output validity

### Strict Criteria for Success

✅ `--sourcemap` must emit correct `.js.map` output for the JS backend
✅ Browser devtools must resolve original source positions from emitted JS
✅ Async stack recovery must work at least for the supported v1 async surface
✅ Debugging output must use the shared diagnostic model rather than a separate error vocabulary
✅ Source-map generation must remain stable and reproducible for unchanged inputs

## Agent 3: Persistent Incremental Compilation and Module Graph Performance

Agent 3 owns browser-target iteration speed. Their job is to take the current in-process cache foundations and evolve them into a persistent, graph-aware, disk-backed incremental system suitable for frontend work. Their primary area is [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs), especially the current parsed-program and lowering caches, module graph discovery, dependency graph hash reporting, and parallel parse/load behavior. They also own nearby CLI and measurement surfaces in [crates/driver/src/command.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/command.rs), [apps/fozzyc/src/entry.rs](/Users/deepsaint/Desktop/fozzylang/apps/fozzyc/src/entry.rs), [scripts/bench_compile_times_rust_vs_fzy.py](/Users/deepsaint/Desktop/fozzylang/scripts/bench_compile_times_rust_vs_fzy.py), and release gates that will eventually enforce these budgets. Close by their area, Agent 1 depends on cacheable backend outputs, Agent 6 depends on the same graph for live dev runtime and HMR, and Agent 7 depends on this work for editor responsiveness and dev loop latency. Agent 3 must not take ownership of JS semantic lowering, browser runtime ABI, or LSP protocol features beyond what is necessary to expose cache-aware behavior.

### Checklist

✅ In-process parse/HIR/FIR cache foundations already exist
✅ Add disk-backed persistent parsed-module cache
✅ Add disk-backed persistent typed/lowered IR cache
✅ Add stable cache fingerprinting and versioning
✅ Add dependency graph persistence across CLI invocations
✅ Add fine-grained invalidation for changed leaf modules
✅ Ensure leaf edits do not trigger full application recompilation
✅ Track import graph fanout precisely
✅ Separate semantic invalidation from backend-output invalidation
✅ Add graph-aware parallel rebuild scheduling
✅ Add shared cache coordination for parallel workers
✅ Add deterministic observability for cache hits, misses, and invalidation causes
✅ Add browser-project incremental benchmark suite
✅ Add cold-build target budget
✅ Add warm-rebuild target budget
✅ Add HMR-latency-adjacent graph budget shared with Agent 6
✅ Add release gate enforcement for incremental compile budgets

### Strict Criteria for Success

✅ Warm incremental rebuilds must survive separate process invocations
✅ Single-file edits must invalidate only the necessary graph slice
✅ Cache format must be versioned and safely invalidated on incompatible changes
✅ Compile observability must clearly show why rebuild work happened
✅ Incremental system must integrate with the existing driver/module graph rather than replace it with a second graph engine

## Agent 4: Browser Runtime ABI

Agent 4 owns the browser-facing runtime ABI and only the runtime ABI. Their lane begins in [crates/runtime/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/lib.rs), [crates/runtime/src/service.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/service.rs), [crates/stdlib/src/task.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/task.rs), [crates/stdlib/src/concurrency.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/concurrency.rs), [corelib/src/http.fzy](/Users/deepsaint/Desktop/fozzylang/corelib/src/http.fzy), [corelib/src/concurrency.fzy](/Users/deepsaint/Desktop/fozzylang/corelib/src/concurrency.fzy), and the runtime intrinsic boundary currently represented in [crates/driver/src/pipeline/native_runtime_tables.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline/native_runtime_tables.rs). This agent defines timers, browser event handles, fetch/websocket/storage hooks, and the browser-side ABI contract that Agent 1 lowers to and Agent 5 schedules against. Close by their area, Agent 5 owns event-loop mapping and scheduler semantics, Agent 6 owns loader/runtime patch behavior, and Agent 7 consumes runtime errors for browser overlays and tooling. Agent 4 must not build component APIs, routers, rendering abstractions, or dev tooling transport.

### Checklist

✅ Add browser timer ABI: `set_timeout`
✅ Add browser timer ABI: `set_interval`
✅ Add browser timer ABI: `clear_timeout`
✅ Define ownership and cancellation semantics for timer handles
✅ Add `request_animation_frame`
✅ Define frame callback semantics
✅ Define raw node-handle ABI
✅ Define event-listener ABI
✅ Define callback ABI for event handlers
✅ Define event propagation contract
✅ Define listener registration cleanup rules
✅ Add `fetch` runtime ABI
✅ Add abort-controller integration
✅ Add websocket runtime ABI
✅ Add stream runtime ABI
✅ Add `localStorage` ABI
✅ Add `sessionStorage` ABI
✅ Define browser storage error contract
✅ Add structured console logging surface for browser runtime
✅ Add runtime error hook surface consumable by tooling
✅ Add browser ABI conformance fixtures

### Strict Criteria for Success

✅ Browser ABI must live as runtime/stdlib/corelib primitives, not framework features
✅ Every ABI surface must have explicit lifetime, cancellation, and cleanup rules
✅ Error behavior must map into the existing runtime/diagnostic model
✅ ABI must be consumable by the JS backend without backend-specific semantic exceptions
✅ No Fzact concepts may leak into the ABI surface

## Agent 5: Async, Event Loop Integration, and Scheduler Lanes

Agent 5 owns the semantic bridge between browser execution and the Fzy scheduler model. Their closest code is [crates/runtime/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/lib.rs), [crates/runtime/src/service.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/service.rs), and the concurrency/task surfaces in [crates/stdlib/src/task.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/task.rs) and [crates/stdlib/src/concurrency.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/concurrency.rs). They work directly next to Agent 4 because browser timers, fetches, and event callbacks need runtime scheduling semantics, and directly next to Agent 1 because the JS backend must lower Promise and task behavior to this exact contract. They also work near Agent 7 because async tracing and causality must appear in diagnostics and tooling. Agent 5 must not own the browser ABI itself, dev-server implementation, or JS emission formatting.

### Checklist

✅ Deterministic scheduling foundations already exist
✅ Trace and replay foundations already exist
✅ Define browser event-loop mapping onto Fzy scheduler semantics
✅ Define Promise scheduling contract used by JS backend
✅ Define microtask vs macrotask mapping policy
✅ Preserve deterministic ordering hooks in browser execution mode
✅ Add render-priority lane
✅ Add input-priority lane
✅ Add background-priority lane
✅ Define fairness and starvation guarantees for browser scheduler mode
✅ Track browser task lineage
✅ Track browser async causality
✅ Emit replay-relevant browser scheduling metadata
✅ Extend trace tooling to browser async events
✅ Extend equivalence tooling to browser scheduling normalization
✅ Add browser scheduler regression fixtures

### Strict Criteria for Success

✅ Browser execution must remain compatible with the browser event loop while preserving Fzy scheduling semantics
✅ The JS backend must have one clear Promise/task lowering contract, not per-feature ad hoc scheduling
✅ Priority lanes must be explicit runtime policy, not hidden emitter behavior
✅ Browser async traces must be usable by replay/equivalence tooling
✅ Scheduler semantics must remain documented, testable, and deterministic where claimed

## Agent 6: Module Loader, Dev Runtime, HMR, and Reactive Primitives

Agent 6 owns the browser-native module runtime and the smallest useful reactive substrate that Fzact can build on top of. Their work spans the driver/runtime seam: [crates/driver/src/pipeline.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/pipeline.rs) for module graph awareness, [crates/runtime/src/lib.rs](/Users/deepsaint/Desktop/fozzylang/crates/runtime/src/lib.rs) and [crates/stdlib/src/concurrency.rs](/Users/deepsaint/Desktop/fozzylang/crates/stdlib/src/concurrency.rs) for runtime hooks, and future runtime/corelib homes for `signal<T>`, `computed<T>`, and `effect<T>`. This agent is close to Agent 3 because loader behavior depends on persistent graph knowledge and invalidation boundaries, close to Agent 4 because the loader is built on browser ABI primitives, and close to Agent 7 because HMR and overlays need tooling transport. Agent 6 must keep the reactive layer minimal and must not invent hooks syntax, JSX, component semantics, or rendering APIs.

### Checklist

✅ Add browser-native ESM graph loading model
✅ Support code splitting
✅ Support lazy loading
✅ Support dynamic import boundaries
✅ Define loader/runtime manifest format if required
✅ Define HMR boundary protocol
✅ Add runtime hooks for module replacement
✅ Add invalidation boundaries that preserve unaffected state
✅ Add state preservation hooks for safe runtime patching
✅ Define failure behavior when patch safety cannot be guaranteed
✅ Add `signal<T>` runtime primitive
✅ Add `computed<T>` runtime primitive
✅ Add `effect<T>` runtime primitive
✅ Define batching/update policy
✅ Define cleanup semantics for effects
✅ Define cycle handling and diagnostics
✅ Define reactive graph debug/introspection hooks
✅ Add HMR and reactive runtime regression fixtures

### Strict Criteria for Success

✅ Loader and HMR behavior must build on the official module graph rather than a second hidden graph
✅ Reactive primitives must remain stdlib/runtime primitives, not syntax features
✅ No component model, JSX model, router model, or rendering abstraction may be introduced here
✅ HMR must have explicit safety boundaries and a defined fallback when state cannot be preserved
✅ Fzact must be able to build on these primitives without compiler-core UI assumptions

## Agent 7: Frontend Tooling, Dev Server, Browser Diagnostics, and Package Interop

Agent 7 owns the frontend-facing DX surface. Their primary lane is [crates/driver/src/lsp.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/lsp.rs), [crates/driver/src/command.rs](/Users/deepsaint/Desktop/fozzylang/crates/driver/src/command.rs), [apps/fozzyc/src/entry.rs](/Users/deepsaint/Desktop/fozzylang/apps/fozzyc/src/entry.rs), [tooling/vscode/extension.js](/Users/deepsaint/Desktop/fozzylang/tooling/vscode/extension.js), [docs/editor-tooling-v1.md](/Users/deepsaint/Desktop/fozzylang/docs/editor-tooling-v1.md), and [docs/compiler-diagnostics-v1.md](/Users/deepsaint/Desktop/fozzylang/docs/compiler-diagnostics-v1.md). Their job is to make browser-target iteration feel instantaneous: dev server, live reload or HMR transport, browser overlays, source-mapped runtime errors, browser-target-aware diagnostics, and eventual JS/package interop guidance. Close by their area, Agent 2 provides sourcemap truth, Agent 3 provides graph/incremental speed, Agent 5 provides runtime trace events, and Agent 6 provides HMR/runtime patch hooks. Agent 7 must consume those contracts and expose them cleanly. Agent 7 must not own backend lowering semantics or browser runtime ABI design.

### Checklist

✅ Existing LSP foundations already exist
✅ Existing diagnostics foundations already exist
✅ Add browser-target dev-server command surface
✅ Add browser graph serving for emitted JS modules
✅ Add live reload support
✅ Add HMR transport support
✅ Add browser compiler error overlay
✅ Add browser runtime error overlay
✅ Add source-mapped stack presentation
✅ Add source-mapped async trace presentation
✅ Add browser-target-aware diagnostics
✅ Add JS-backend-specific fix guidance
✅ Add browser-project editor responsiveness gates
✅ Define JS import interop model
✅ Define npm/package resolution strategy
✅ Define foreign-module typing strategy
✅ Define ABI boundary between Fzy-emitted modules and imported JS modules
✅ Add LSP, overlay, and dev-server regression fixtures
✅ Add release-gate coverage for browser DX flows

### Strict Criteria for Success

✅ Frontend dev loop must feel first-class, not like a native compiler awkwardly wrapped for the browser
✅ Browser overlays must use source-mapped original locations
✅ Browser-target diagnostics must remain aligned with the shared compiler diagnostics contract
✅ Dev server and HMR transport must integrate with official graph/runtime hooks from Agents 3 and 6
✅ Package interop rules must be explicit and documented, not implied or accidental

## Cross-Agent Contracts

### Backend and Runtime Contract

✅ Agent 1 and Agent 5 must agree on one Promise/task lowering contract before deep JS emitter work is considered complete
✅ Agent 1 must consume browser ABI intrinsics defined by Agent 4 rather than invent backend-only runtime shims
✅ Agent 2 must lock source-map metadata shape with Agent 1 before browser debug tooling is finalized

### Graph and Dev Runtime Contract

✅ Agent 3 and Agent 6 must share one module graph and invalidation model
✅ Agent 3 and Agent 7 must share one performance budget story for rebuilds and interactive DX
✅ Agent 6 and Agent 7 must agree on HMR boundary protocol and failure fallback behavior

### Diagnostics and Trace Contract

✅ Agent 2 and Agent 7 must share one browser debugging vocabulary built on the existing diagnostics system
✅ Agent 5 and Agent 7 must share one async trace and causality surface for browser tooling

## Production Gates To Add

✅ Add JS backend parity fixtures to release gate
✅ Add JS backend equivalence fixtures to release gate
✅ Add sourcemap verification fixtures to release gate
✅ Add browser runtime ABI conformance fixtures to release gate
✅ Add browser scheduler/event-loop fixtures to release gate
✅ Add HMR and loader fixtures to release gate
✅ Add browser-target incremental compile benchmark gates to release gate
✅ Add browser-target dev-server and overlay smoke gates to release gate

## Final Overseer Responsibilities

The final overseer is responsible for integration, conflict resolution, and truthfulness of the final production claim. That means:

✅ verify every agent stayed inside their lane
✅ verify all cross-agent contracts were explicitly resolved
✅ verify no Fzact concerns leaked into Fzy core
✅ verify release gates cover the full browser-runtime claim
✅ verify docs, CLI, diagnostics, and implementation all agree
✅ verify the final claim is production-true, not plan-true

## End State

✅ Fzy can compile a real browser app through an official JS backend
✅ Output is readable ESM JavaScript
✅ Sourcemaps work in browser devtools
✅ Warm incremental rebuilds are viable for frontend iteration
✅ Browser runtime ABI covers timers, events, network, storage, and debug hooks
✅ Browser scheduling remains deterministic and traceable where claimed
✅ Reactive primitives stay minimal and framework-agnostic
✅ Fzact can build above these primitives without compiler-core UI abstractions
