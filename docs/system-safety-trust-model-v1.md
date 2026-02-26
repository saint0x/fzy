# System Safety + Trust Model v1

This document defines what can be claimed publicly today, what is intentionally out of scope, and what evidence is required for each claim.

## Enforced Guarantees Today

- Verifier-enforced ownership/borrow constraints in shipped rule scope (including documented async suspension constraints).
- Runtime fail-closed defaults for capability-sensitive and limit-sensitive paths.
- Native-lowering fail-fast diagnostics for unsupported or partial language shapes (no silent partial semantics on documented guardrails).
- Unsafe budget enforcement with missing-reason rejection.
- FFI boundary policy enforcement for panic contracts and boundary-shape diagnostics.
- Deterministic replay/trace verification gate coverage for reproducibility and incident triage.

## Explicit Non-Goals (Current Scope)

- No claim of Rust-equivalent theorem-proven soundness.
- No claim of complete alias/lifetime theorem proving for all low-level patterns.
- No claim of arbitrary OS-preemptive interleaving coverage beyond documented deterministic scheduling model.
- No claim that every safety property is formally verified end-to-end.

## Required Evidence Artifacts for Public Claims

- Runtime/verifier claim evidence:
  - `fozzy doctor --deep --scenario ... --runs 5 --seed ... --json`
  - `fozzy test --det --strict ... --json`
- Reproducibility/trace claim evidence:
  - `fozzy run ... --det --record <trace.fozzy> --json`
  - `fozzy trace verify <trace.fozzy> --strict --json`
  - `fozzy replay <trace.fozzy> --json`
  - `fozzy ci <trace.fozzy> --json`
- Host-backed claim evidence:
  - `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`
- Unsafe posture claim evidence:
  - `fz audit unsafe <target> --json`
- FFI boundary guarantee evidence:
  - `fz headers ... --json`
  - `fz abi-check ... --baseline ... --json`
- Release readiness claim evidence:
  - `scripts/ship_release_gate.sh`
  - `scripts/exit_criteria_gate.sh`

## Safety Claim Review Checklist

- [x] Memory model claims align with `docs/production-memory-model-v1.md` and do not exceed documented scope.
- [x] Borrow/alias coverage statements explicitly preserve non-theorem-proof caveats.
- [x] Unsafe-budget posture claims are backed by `fz audit unsafe` gate output and missing-reason rejection.
- [x] FFI boundary guarantees are backed by panic-contract enforcement and ABI/header gate checks.
