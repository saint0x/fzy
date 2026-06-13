# PERF.md

This tracker is closed.

The work that had been tracked here has been landed and verified on `2026-06-13`, so completed items have been removed instead of left behind as stale roadmap text.

Current verification baseline:

- `cargo fmt --all --check`
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo run -p fz -- doctor --deep --scenario tests/core.production_surface.pass.fozzy.json --runs 5 --seed 20260613 --strict --json`
- `cargo run -p fz -- test tests/core.production_surface.pass.fozzy.json --det --strict-verify --seed 20260613 --json`
- `cargo run -p fz -- run tests/core.production_surface.pass.fozzy.json --det --strict-verify --seed 20260613 --record artifacts/perf_closeout.trace.fozzy --json`
- `cargo run -p fz -- trace verify artifacts/perf_closeout.trace.fozzy --strict --json`
- `cargo run -p fz -- replay artifacts/perf_closeout.trace.fozzy --json`
- `cargo run -p fz -- ci artifacts/perf_closeout.trace.fozzy --strict --json`
- `cargo run -p fz -- run tests/host.backends_run.pass.fozzy.json --det --strict-verify --seed 20260613 --proc-backend host --fs-backend host --http-backend host --json`
- `cargo run -p fz -- lsp smoke examples/minimal_runtime/src/main.fzy --json`
- `cargo run -p fz -- perf --json`

Open a new perf tracker only for newly measured, still-unresolved work.
