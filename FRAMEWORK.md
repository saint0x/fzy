# Framework Program (V1+)

## Mission

Ship production-grade higher-level frameworks on top of the pinned V1 language/runtime.

## Program Rules (Same rigor as PLAN)

- [ ] No compatibility shims for deprecated public surfaces; ship canonical APIs directly.
- [ ] Every framework ships deterministic + host-backed behavior contracts.
- [ ] Every framework ships docs, examples, and executable fixtures before marked complete.
- [ ] Every framework has release-gated verification, not best-effort checks.
- [ ] Every framework must define explicit failure-mode contracts (timeout, cancel, retry, policy).

## Cross-Cutting Framework Gates (Required for every framework)

- [ ] Architecture
- [ ] Define package/module boundaries and ownership.
- [ ] Define stable public API surface and internal/private boundaries.
- [ ] Define extension points (middleware/hooks/plugins) with safety constraints.

- [ ] Determinism + Host Parity
- [ ] Deterministic behavior spec for all framework primitives.
- [ ] Host-backed execution checks for all I/O-touching paths.
- [ ] Replayable traces for at least one canonical workflow per framework.

- [ ] Reliability + Policy
- [ ] Timeout/retry/backoff policy primitives and defaults.
- [ ] Cancellation propagation semantics and structured-concurrency behavior.
- [ ] Resource limits and bounded-memory contracts.

- [ ] Security + Trust
- [ ] Capability declarations and verifier alignment.
- [ ] Input validation contracts and default-safe behavior.
- [ ] Auditability for privileged/unsafe edges.

- [ ] Observability + DX
- [ ] Standard metrics/spans/log fields with correlation ID support.
- [ ] Error classification taxonomy and context chaining support.
- [ ] Quickstart docs + reference docs + examples + migration notes.

- [ ] Validation Gate Commands
- [ ] `cargo check --workspace`
- [ ] `cargo test --workspace`
- [ ] `fozzy doctor --deep --scenario <framework_scenario> --runs 5 --seed <seed> --json`
- [ ] `fozzy test --det --strict <framework_scenarios...> --json`
- [ ] `fozzy run <scenario> --det --record artifacts/<framework>.trace.fozzy --json`
- [ ] `fozzy trace verify artifacts/<framework>.trace.fozzy --strict --json`
- [ ] `fozzy replay artifacts/<framework>.trace.fozzy --json`
- [ ] `fozzy ci artifacts/<framework>.trace.fozzy --json`
- [ ] Host-backed run: `fozzy run <scenario> --proc-backend host --fs-backend host --http-backend host --json`

## Priority Roadmap

### Phase 1 (Adoption Accelerators)

- [ ] Web Framework
- [ ] Data Access Framework
- [ ] API Framework
- [ ] Service Framework

### Phase 2 (Production Scale)

- [ ] Async Workflow Framework
- [ ] Eventing/Messaging Framework
- [ ] AuthN/AuthZ Framework
- [ ] Observability Framework
- [ ] Testing Framework Suite

### Phase 3 (Platform + Ecosystem)

- [ ] CLI/App Framework
- [ ] Resilience Framework
- [ ] Edge/Deployment Framework
- [ ] SDK/Client Generation Framework
- [ ] Stateful App Framework
- [ ] Internal Platform Golden-Path Framework

---

## Framework Backlog (Detailed Checklists)

### 1) Web Framework (Highest Priority)

- [ ] Core Architecture
- [ ] Router: static + param + wildcard matching with deterministic precedence.
- [ ] Middleware chain model with pre/post/error interception contracts.
- [ ] Request/response typed builders aligned with `core.http` canonical surface.
- [ ] Body parsing contracts: JSON/form/multipart with bounded limits.

- [ ] Platform Features
- [ ] Sessions (cookie + server-side token models).
- [ ] Auth middleware hooks (JWT/session/custom policy adapters).
- [ ] Static assets and cache-control helpers.
- [ ] WebSocket/SSE abstractions (if in scope for V1 web).

- [ ] Runtime Contracts
- [ ] Graceful shutdown and drain semantics.
- [ ] Per-route timeout/retry/policy overrides.
- [ ] Canonical error mapping for transport/parse/policy/timeouts.

- [ ] Deliverables
- [ ] `examples/web_*` quickstart and production template.
- [ ] Framework scenario + trace lifecycle artifacts.
- [ ] Throughput/latency smoke baseline and regression thresholds.

### 2) Data Access Framework (ORM-lite + Query Layer)

- [ ] Core Architecture
- [ ] Connection management abstraction (pool/lifecycle/limits).
- [ ] Query builder with typed parameter binding.
- [ ] Transaction API (begin/commit/rollback + nesting policy).
- [ ] Migration runner with deterministic ordering and idempotency.

- [ ] Reliability + Safety
- [ ] Retry policy for transient transport errors only.
- [ ] Explicit timeout contracts per operation category.
- [ ] SQL/command injection-safe parameterization by default.

- [ ] Deliverables
- [ ] Reference driver adapters (at least one canonical backend).
- [ ] Migration fixtures + rollback tests.
- [ ] Example service with CRUD + transaction + migration flow.

### 3) API Framework (Contract-First)

- [ ] Core Architecture
- [ ] OpenAPI/schema-first API definition support.
- [ ] Request validation and response validation helpers.
- [ ] Versioning primitives (`v1`, `v2`) with deprecation metadata.
- [ ] Idempotency-key support patterns for mutating endpoints.

- [ ] Security + Policy
- [ ] Rate-limit and quota middleware integration points.
- [ ] Standard auth integration hooks.
- [ ] Canonical API error envelope and status mapping.

- [ ] Deliverables
- [ ] API contract generation + documentation output.
- [ ] SDK generation hook compatibility (input to SDK framework).
- [ ] Integration fixtures validating schema drift detection.

### 4) Service Framework (App Lifecycle + Composition)

- [ ] Core Architecture
- [ ] Service container/registry for lifecycle-managed components.
- [ ] Config/profile system (dev/stage/prod/test) with env overlays.
- [ ] Startup/health/readiness/shutdown orchestration.
- [ ] Background worker lifecycle integration.

- [ ] Reliability + Operations
- [ ] Structured boot failure diagnostics with action hints.
- [ ] Shutdown deadlines and partial-failure behavior policy.
- [ ] Service dependency graph validation.

- [ ] Deliverables
- [ ] Canonical multi-module template using framework conventions.
- [ ] Lifecycle failure-mode scenarios.

### 5) Async Workflow Framework

- [ ] Core Architecture
- [ ] Fan-out/fan-in orchestration primitives.
- [ ] Cancellation-safe task groups and join semantics.
- [ ] Timeouts/deadlines/retry composition helpers.

- [ ] Contracts
- [ ] Deterministic scheduling semantics with explicit guarantees.
- [ ] Failure aggregation model (first-error vs multi-error strategy).
- [ ] Backpressure and bounded concurrency controls.

- [ ] Deliverables
- [ ] Workflow cookbook examples.
- [ ] Deterministic scenario set for race/cancel/timeout behavior.

### 6) Eventing/Messaging Framework

- [ ] Core Architecture
- [ ] Producer/consumer abstraction with transport adapters.
- [ ] Message envelope model (key, payload, headers, trace IDs).
- [ ] Consumer group and partition assignment contracts.

- [ ] Reliability
- [ ] Ack/nack/retry semantics with DLQ policy.
- [ ] Idempotent consumer helper patterns.
- [ ] Exactly-once semantics declaration (if provided, with constraints).

- [ ] Deliverables
- [ ] End-to-end event flow example and replay artifacts.
- [ ] Fault injection fixtures (drop/delay/dup/order).

### 7) AuthN/AuthZ Framework

- [ ] Core Architecture
- [ ] Identity providers abstraction and token/session models.
- [ ] RBAC and ABAC policy engines.
- [ ] Authorization middleware integration for web/API frameworks.

- [ ] Security
- [ ] Credential/token rotation support.
- [ ] Secret handling and redaction defaults.
- [ ] Audit event schema for auth decisions.

- [ ] Deliverables
- [ ] Security-focused examples and policy test suites.
- [ ] Threat model checklist for auth surface.

### 8) Observability Framework

- [ ] Core Architecture
- [ ] Unified logging/metrics/tracing facade.
- [ ] Correlation context propagation across task/workflow boundaries.
- [ ] Standard semantic conventions (field names/units/status labels).

- [ ] Operational Features
- [ ] Pluggable sinks/exports.
- [ ] Sampling policies with deterministic test behavior.
- [ ] Dashboards/alerts starter pack definitions.

- [ ] Deliverables
- [ ] Observability reference profile and example dashboards.
- [ ] Regression checks for critical telemetry invariants.

### 9) Testing Framework Suite

- [ ] Core Architecture
- [ ] HTTP integration harness utilities.
- [ ] Deterministic scenario DSL convenience wrappers.
- [ ] Mock/fake/stub helpers for proc/fs/http boundaries.
- [ ] Property/fuzz test helpers.

- [ ] Deliverables
- [ ] Golden test templates for framework consumers.
- [ ] CI presets (strict deterministic + replay lifecycle).

### 10) CLI/App Framework

- [ ] Core Architecture
- [ ] Command tree parser and typed argument schema.
- [ ] Structured output modes (text/json).
- [ ] Config/profile + env + secure defaults.

- [ ] UX + Reliability
- [ ] Rich help generation and diagnostics.
- [ ] Consistent exit code contracts.
- [ ] Plugin/extension model with safety limits.

- [ ] Deliverables
- [ ] Starter CLI template and command test harness.

### 11) Resilience Framework

- [ ] Core Architecture
- [ ] Circuit breaker primitive.
- [ ] Bulkhead/concurrency isolation.
- [ ] Retry budget and hedged request helpers.

- [ ] Contracts
- [ ] Failure classification integration with `resultx` taxonomy.
- [ ] Deterministic policy decisions under deterministic mode.

- [ ] Deliverables
- [ ] Chaos/fault scenarios and recovery metrics gates.

### 12) Edge/Deployment Framework

- [ ] Core Architecture
- [ ] Build/deploy manifest spec for services and jobs.
- [ ] Runtime profile bundles and policy packs.
- [ ] Health/readiness deployment gates.

- [ ] Deliverables
- [ ] Deployment examples and rollback playbooks.
- [ ] Artifact integrity and environment parity checks.

### 13) SDK/Client Generation Framework

- [ ] Core Architecture
- [ ] Typed client generation from API contracts.
- [ ] Error/status mapping + retry/timeout defaults.
- [ ] Auth injectors and transport adapters.

- [ ] Deliverables
- [ ] Generated SDK conformance tests against API fixtures.
- [ ] Versioning and backwards-change detection reports.

### 14) Stateful App Framework

- [ ] Core Architecture
- [ ] Cache abstraction and consistency policies.
- [ ] Event-sourcing primitives and snapshot helpers.
- [ ] CQRS read/write model helpers.

- [ ] Reliability
- [ ] Replay/recovery contracts and deterministic rehydration.
- [ ] State migration/versioning policy.

- [ ] Deliverables
- [ ] Stateful reference app and failure-recovery scenarios.

### 15) Internal Platform Golden-Path Framework

- [ ] Core Architecture
- [ ] Opinionated stack composition (web + data + auth + observability + deploy).
- [ ] One-command bootstrap for new production service.
- [ ] Policy presets by environment tier.

- [ ] Governance
- [ ] Default guardrails (security, limits, observability, test gates).
- [ ] Upgrade cadence and compatibility policy for platform components.

- [ ] Deliverables
- [ ] `new-service` template, playbooks, and adoption metrics.

---

## Framework Program Exit Criteria (V1 Platform-Ready)

- [ ] Phase 1 complete with production docs/examples and passing gates.
- [ ] At least one end-to-end reference app uses web + data + api + service frameworks in production topology.
- [ ] Deterministic + host-backed scenario coverage exists for all shipped frameworks.
- [ ] Framework docs and implementation are claim-integrity gated.
- [ ] Framework adoption path published (templates, migration guides, ops runbooks).
