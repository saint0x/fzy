# Allocator Contracts v1

## Supported Allocator Policies

- `System`
- `Arena`
- `Bump`
- `Fail`

## OOM Behavior Profiles

- Fail-fast profile: allocation returns `OutOfMemory` and caller must handle.
- Deterministic test profile: allocation failures are deterministic and replayable.

## Hardened Runtime Mode

Hardened memory mode supports:

- poison-on-free behavior (logical contract)
- quarantine-before-reuse behavior (logical contract)
- guard-page policy as backend-specific optional hardening

These modes are represented as runtime policy contracts and must not weaken deterministic replay.

## Leak Budget Enforcement

- Production gate leak policy is fail-on-leak with explicit budget.
- Baseline budget defaults to zero for production memory safety.
- Budget exceptions require explicit release sign-off.

## Resource Consumption Rules

- Linear resources must be consumed exactly once.
- `free(...)`/`close(...)` on non-owned or already-consumed values is invalid.
- Reinitialization after move is required before further use.
