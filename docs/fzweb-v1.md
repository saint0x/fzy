# fzweb V1

`fzweb` is the core-team framework package at `frameworklib/fzweb`.

## Production Shape

- Concern-grouped modules (not one-file-per-function).
- Deterministic hot path.
- Rust-backed `webcore.http` transport usage.
- Concurrency hooks via `spawn/yield` for multithreaded execution support.

## Module Groups

- `src/webcore/mod.fzy`
- `src/middleware/mod.fzy`
- `src/support/mod.fzy`
- `src/main.fzy`

## Validation Commands

- `python3 scripts/verify_fzweb_framework.py`
- `fozzy doctor --deep --scenario tests/fzweb.framework.pass.fozzy.json --runs 5 --seed 20260227 --json`
- `fozzy test --det --strict tests/fzweb.framework.pass.fozzy.json --json`
- `fozzy run tests/fzweb.framework.pass.fozzy.json --det --record artifacts/fzweb.framework.trace.fozzy --json`
- `fozzy trace verify artifacts/fzweb.framework.trace.fozzy --strict --json`
- `fozzy replay artifacts/fzweb.framework.trace.fozzy --json`
- `fozzy ci artifacts/fzweb.framework.trace.fozzy --json`
- `fozzy run tests/fzweb.framework.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`
