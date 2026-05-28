# fzweb V1

`fzweb` is the core-team framework package at `frameworklib/fzweb`.

## Production Shape

- Concern-grouped modules (not one-file-per-function).
- Deterministic hot path.
- Rust-backed `core.http` transport usage through `webcore` wrappers.
- First-class `core.log` structured logging in live server path.
- Concurrency hooks via `spawn`/`join`/`yield` for multithreaded execution support.

## Module Groups

- `src/webcore/mod.fzy`
- `src/middleware/mod.fzy`
- `src/support/mod.fzy`
- `src/main.fzy`

## Validation Commands

- `python3 scripts/verify_fzweb_framework.py`
- `fz doctor --deep --scenario tests/fzweb.framework.pass.fozzy.json --runs 5 --seed 20260227 --json`
- `fz test --det --strict-verify tests/fzweb.framework.pass.fozzy.json --json`
- `fz run tests/fzweb.framework.pass.fozzy.json --det --record artifacts/fzweb.framework.trace.fozzy --json`
- `fz trace verify artifacts/fzweb.framework.trace.fozzy --strict --json`
- `fz replay artifacts/fzweb.framework.trace.fozzy --json`
- `fz ci artifacts/fzweb.framework.trace.fozzy --json`
- `fz run tests/fzweb.framework.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json`
