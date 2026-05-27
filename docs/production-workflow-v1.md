# Production Workflow v1

This is the canonical production workflow for this repository.

## Scope

Use this flow for every production change:

1. Author code and tests.
2. Run local check/verify surfaces.
3. Run deterministic replay-driven validation.
4. Run full production gate.
5. Record/update exit-criteria tracking evidence.
6. Release only on green gate + exit-criteria readiness.

## 1. Author

- Implement changes in source + tests.
- Keep APIs and command outputs deterministic.
- For tooling changes, include LSP + formatter/doc smoke coverage.

## 2. Check

```bash
cargo check --workspace
cargo test --workspace
```

## 3. Verify

Run strict deterministic validation first:

```bash
fz doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json
fz test --det --strict-verify tests/example.fozzy.json tests/memory.pass.fozzy.json --json
```

Record and validate a real trace:

```bash
fz run tests/example.fozzy.json --det --record artifacts/workflow.trace.fozzy --json
fz trace verify artifacts/workflow.trace.fozzy --strict --json
fz replay artifacts/workflow.trace.fozzy --json
fz ci artifacts/workflow.trace.fozzy --json
```

Run host-backed confidence pass:

```bash
fz run tests/host.pass.fozzy.json --host-backends --json
```

For native source tests, use a single command path:

```bash
fz test <module>.fzy --host-backends --json
```

This automatically generates temporary scenario artifacts and runs host-backed execution without a separate manual scenario conversion step.

For native CLI and terminal-facing products, validate both launch modes:

- `fz run ...` is the canonical compiler-managed launcher and should stay in the gate.
- direct built-binary execution is the final confidence pass for:
  - exact stdout/stderr ordering
  - shell piping
  - interactive prompt behavior
  - launch-environment inheritance

For trait/generic language slices, include the dedicated scenario lifecycle:

```bash
fz doctor --deep --scenario tests/trait_generic.pass.fozzy.json --runs 5 --seed 4242 --json
fz test --det --strict-verify tests/trait_generic.pass.fozzy.json --json
fz run tests/trait_generic.pass.fozzy.json --det --record artifacts/trait-generic.trace.fozzy --json
fz trace verify artifacts/trait-generic.trace.fozzy --strict --json
fz replay artifacts/trait-generic.trace.fozzy --json
fz ci artifacts/trait-generic.trace.fozzy --json
fz run tests/trait_generic.pass.fozzy.json --host-backends --json
```

## 4. Gate

Run the single ship gate entrypoint:

```bash
./scripts/ship_release_gate.sh
```

This gate includes:

- workspace compiler pipeline gate (`cargo check --workspace`)
- warning-free policy gate (`RUSTFLAGS="-D warnings"`)
- workspace test gate (`cargo test --workspace`)
- parity + equivalence representative language probes
- safety-claim integrity gate (`scripts/safety_claim_integrity_gate.py`)
- release-blocking FFI examples gate (`fz headers` + `fz abi-check`)
- strict deterministic and host-backed Fozzy lifecycle
- determinism flake-budget enforcement (`scripts/determinism_flake_budget_gate.py`)
- full command-surface checks
- LSP editor + determinism/protocol smoke
- strict `fz fmt` and `fz doc gen` smokes
- pedantic hotspot closure
- unsafe-budget enforcement

## 5. Release

Record tracking evidence:

```bash
python3 scripts/exit_criteria.py record-day
python3 scripts/exit_criteria.py record-rc --rc-id rc-<date>.<n>
python3 scripts/exit_criteria.py record-local-repro
python3 scripts/exit_criteria.py status
```

Strict readiness gate:

```bash
./scripts/exit_criteria_gate.sh
```

Release only when all prior steps pass without warnings or failures and exit criteria are green.

For failures, use:

- `docs/production-failure-triage-v1.md`
- `docs/exit-criteria-v1.md`
- `docs/traits-generics-contract-v1.md`
- `docs/traits-generics-style-guide-v1.md`
