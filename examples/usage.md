# Examples Usage (v1)

This file describes how to run first-party examples under production policy.

## Prereqs

- Use deterministic checks first.
- Use host-backed runs for runtime boundary confidence.

## Canonical Commands

```bash
# check/build/test one example project
fz check examples/fullstack --json
fz build examples/fullstack --release --json
fz test examples/fullstack --strict-verify --seed 4242 --json
fz run examples/fullstack --strict-verify --seed 4242 --json

# deterministic lifecycle sample
fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json
fozzy test --det --strict tests/example.fozzy.json --json
fozzy run tests/example.fozzy.json --det --record artifacts/example.trace.fozzy --json
fozzy trace verify artifacts/example.trace.fozzy --strict --json
fozzy replay artifacts/example.trace.fozzy --json
fozzy ci artifacts/example.trace.fozzy --json

# host-backed run sample
fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
```

## Traits/Generics Example Validation

```bash
fz check tests/fixtures/trait_generic/main.fzy --json
fz parity tests/fixtures/trait_generic/main.fzy --seed 4242 --json
fz equivalence tests/fixtures/trait_generic/main.fzy --seed 4242 --json
```

See the language contract at `docs/traits-generics-contract-v1.md`.
