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
fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json
fozzy test --det --strict tests/example.fozzy.json tests/memory.pass.fozzy.json --json
```

Record and validate a real trace:

```bash
fozzy run tests/example.fozzy.json --det --record artifacts/workflow.trace.fozzy --json
fozzy trace verify artifacts/workflow.trace.fozzy --strict --json
fozzy replay artifacts/workflow.trace.fozzy --json
fozzy ci artifacts/workflow.trace.fozzy --json
```

Run host-backed confidence pass:

```bash
fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
```

For native source tests, use a single command path:

```bash
fz test <module>.fzy --host-backends --json
```

This automatically generates temporary scenario artifacts and runs host-backed execution without a separate manual scenario conversion step.

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
