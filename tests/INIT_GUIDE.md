# fzy Init Guide

This scaffold is set up to run with strict mode by default.
Use `--unsafe` only when intentionally opting out of strict checks.

## Recommended first run
```bash
fz doctor --deep --scenario tests/run.pass.fozzy.json --runs 5 --seed 7 --json
```

## Targeted commands
- Run deterministic scenarios: `fz test tests/run.pass.fozzy.json --det --strict-verify --seed 7 --json`
- Run memory checks: `fz run tests/memory.pass.fozzy.json --det --record artifacts/memory.trace.fozzy --json`
- Run distributed explore: `fz explore tests/distributed.pass.fozzy.json --json`
- Run fuzzing: `fz fuzz tests/example.fozzy.json --json`
- Run host-backed checks: `fz run tests/host.pass.fozzy.json --host-backends --json`

Edit the `tests/*.fozzy.json` scenarios with your own inputs and assertions.
