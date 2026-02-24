# Stdlib v0

## Scope

The v0 stdlib provides production baseline primitives for:

- networking + HTTP core + deterministic replay surface
- structured observability (logs, metrics, spans)
- process/config/signal controls
- durable filesystem and bounded streaming IO
- bounded concurrency/synchronization/pooling
- security defaults and capability-gated privileged operations
- deploy/runtime profile and manifest conventions

## Stability Guarantees

- Public API contracts in `crates/stdlib/src/*.rs` are semver-stable for v0 behavior.
- `Host` and `Deterministic` runtime modes preserve app API parity; only decision sources differ.
- Security defaults are fail-closed for limits and capability gates.
- Durability primitives keep atomic-write and lock-contention behavior stable.

## Hardening Defaults

- bounded headers, bodies, connection counts, and parse/request timeouts
- structured log redaction for secret/token/password fields
- bounded channels and bounded poll queues by default

## Deploy Conventions

- Health contract: `/healthz` for liveness, `/readyz` for readiness.
- Runtime profiles: `dev`, `verify`, `release` with explicit deterministic/strict behavior.
- Service manifest includes ports, limits, workers, graceful-stop budget.

## Non-goals (v0)

- complete replacement for external observability backends
- platform-specific process supervisor orchestration
- multi-tenant secret management service
