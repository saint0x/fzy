# Memory Unsoundness Incident Process v1

## Scope

This process applies to any memory-safety unsoundness event in compiler, verifier, runtime, stdlib, backend lowering, or FFI boundary contracts.

## RFC Track

- Every memory-safety model change requires a memory RFC.
- RFC must include threat model, soundness argument, and gate impact.

## Unsafe Budget

- Unsafe sites are tracked as release budgets.
- Missing reason/invariant/owner contracts are release-blocking.
- Budget increases require explicit approval.

## Release Sign-Off

Required approvers:

- verifier owner
- runtime owner
- release owner

Sign-off checklist:

- deterministic doctor/test pass
- trace verify/replay/ci pass
- host-backed parity pass
- unsafe budget within threshold

## Hotfix Playbook

When unsoundness is found:

1. open incident ticket immediately
2. add failing regression test or scenario
3. ship minimal containment fix
4. run full memory production gate
5. publish patch release notes

## Postmortem Requirements

Postmortem must include:

- root cause
- exploitability assessment
- blast radius
- why gate missed the issue
- permanent prevention items
- owner and deadline for each prevention item
