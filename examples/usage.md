# Examples Usage (v1)

This file describes how to run first-party examples under production policy.

## Prereqs

- Use deterministic checks first.
- Use host-backed runs for runtime boundary confidence.
- Direct `fz check path/to/src/module.fzy --json` now resolves through the owning package root, so submodule checks keep normal dependency and sibling-module behavior.

## Canonical Commands

```bash
# check/build/test one example project
fz check examples/fullstack --json
fz check examples/bounds_service/src/services/mod.fzy --json
fz build examples/fullstack --release --json
fz test examples/fullstack --strict-verify --seed 4242 --json
fz run examples/fullstack --strict-verify --seed 4242 --json

# deterministic lifecycle sample
fz doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json
fz test --det --strict-verify tests/example.fozzy.json --json
fz run tests/example.fozzy.json --det --record artifacts/example.trace.fozzy --json
fz trace verify artifacts/example.trace.fozzy --strict --json
fz replay artifacts/example.trace.fozzy --json
fz ci artifacts/example.trace.fozzy --json

# host-backed run sample
fz run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
```

## Traits/Generics Example Validation

```bash
fz check tests/fixtures/trait_generic/main.fzy --json
fz parity tests/fixtures/trait_generic/main.fzy --seed 4242 --json
fz equivalence tests/fixtures/trait_generic/main.fzy --seed 4242 --json
fz doctor --deep --scenario tests/trait_generic.pass.fozzy.json --runs 5 --seed 4242 --json
fz test --det --strict-verify tests/trait_generic.pass.fozzy.json --json
```

See the language contract at `docs/traits-generics-contract-v1.md`.
