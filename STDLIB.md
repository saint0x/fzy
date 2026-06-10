# STDLIB.md

- [ ] Date: 2026-06-10
- [ ] Owner: Stdlib Orchestration

## Mission

Track only the remaining production work for the stdlib redesign. This file must contain no completed work and no historical recap. When work is implemented and re-verified, delete it from this file.

## Working Rules

- No backwards compatibility.
- Keep only remaining work here.
- Delete finished work instead of marking it done.
- Public stdlib modules must stay canonical, typed, minimal, and stability-worthy.
- Internal support shelves must not leak into the import story.
- If a build lock or merge lock blocks progress, finish the owned implementation, note the blocked integration point, and pause.

## Remaining Production Work

### 1.0 P1 — Finish Security Layering

- [ ] Split raw crypto-adjacent helpers from blessed security constructions more cleanly inside `core/src/security.fzy`.
- [ ] Decide which of auth, signer versioning, token helpers, and rate limiting are true stdlib responsibilities.
- [ ] Replace remaining mixed raw-plus-policy convenience shapes with a tiered contract.

### 1.1 P2 — Final Public Helper Cleanup

- [ ] Review remaining convenience-heavy public helpers such as `log.request_log_sampled(...)` and keep only what belongs in the final sacred surface.
- [ ] Review remaining score-only helpers such as `gpu.slice_bounds_score(...)` and remove them if they are not needed for real contracts.
- [ ] Review `core/src/util.fzy` and continue shrinking or deleting it as public modules absorb its responsibilities.

## Execution Model

Use 2 engineers for the remaining wave. The remaining work is narrow enough that more parallelism would just create overlap.

## Shared Directive

Work from the current canonical stdlib tree as it exists now. Do not reopen already-resolved architecture questions unless new evidence forces it. Keep edits inside your owned slice unless an interface contract requires coordination. If you hit a build, merge, or interface lock, finish your owned implementation, document the blocker, and pause.

## Engineer 1: Security Contract Cleanup

**Owns**

- `core/src/security.fzy`

**Primary objective**

Finish the security-layering cleanup so `core.security` reads like a deliberate blessed contract rather than a mixed shelf of raw helpers and application policy.

**Context**

The canonical stdlib surface, gate restoration, error collapse, FFI boundary, and thread/concurrency boundary are already resolved. What remains here is contract cleanup inside `core.security`: the file still blends raw crypto-adjacent wrappers, signer/version helpers, auth policy, and rate-limit behavior in one module.

**Must do**

- Separate raw crypto-adjacent helpers from blessed security constructions more clearly.
- Decide which auth, signer versioning, token helpers, and rate limiting behaviors belong in the standard library.
- Remove or demote behavior that is merely convenience-shaped rather than part of the final sacred contract.
- Keep any surviving public surface typed and minimal.

**Must not own**

- logging surface cleanup outside required coordination
- GPU helper cleanup
- util cleanup outside required coordination

**Close boundary workers**

- Engineer 2 for any helper cleanup that touches shared supporting code

**Exit criteria**

- `core.security` has a clearer tiered contract.
- The surviving public surface is deliberate rather than mixed.

## Engineer 2: Logging, GPU, and Utility Cleanup

**Owns**

- `core/src/log.fzy`
- `core/src/gpu.fzy`
- `core/src/util.fzy`

**Primary objective**

Remove the last convenience-heavy and score-only residue from the public/internal helper surfaces.

**Context**

The remaining cleanup is now concentrated here. `core.log` still exposes convenience-heavy request logging helpers to evaluate, `core.gpu` still contains `slice_bounds_score(...)`, and `core/src/util.fzy` still exists as a tiny cross-cutting helper shelf instead of disappearing entirely.

**Must do**

- Review `log.request_log_sampled(...)` and any similar convenience-heavy logging helpers and keep only what belongs in the final sacred surface.
- Review `gpu.slice_bounds_score(...)` and remove it if it is not needed for a real contract.
- Continue shrinking or deleting `core/src/util.fzy` as public modules absorb its responsibilities.
- Coordinate with Engineer 1 if security cleanup needs any shared helper movement.

**Must not own**

- security contract ownership
- reopening resolved stdlib boundary decisions

**Close boundary workers**

- Engineer 1 for any shared helper movement involving security

**Exit criteria**

- No stray convenience-heavy public logging helpers remain unless they are intentionally part of the final contract.
- No score-only GPU helper residue remains unless it is strictly justified.
- `util.fzy` is reduced further or removed.
