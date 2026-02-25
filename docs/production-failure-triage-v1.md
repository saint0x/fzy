# Production Failure Triage Playbook v1

This playbook maps common gate failures to exact fix workflows.

## Triage Order

1. Capture failing command and stderr/stdout.
2. Re-run the exact failing step in isolation.
3. Apply section-specific fix workflow below.
4. Re-run isolated step, then full production gate.

## Failure Map

### `cargo check --workspace` / `cargo test --workspace`

Symptoms:

- compile errors
- unit/integration test failures

Fix workflow:

1. Re-run failing crate only (`cargo test -p <crate>`).
2. Fix compile/type errors first.
3. Fix failing test behavior or update tests for intentional behavior changes.
4. Re-run full workspace checks.

### `fozzy doctor` deterministic inconsistency

Symptoms:

- `consistent=false`
- differing signatures across runs

Fix workflow:

1. Verify seed is fixed.
2. Audit nondeterministic inputs (time, filesystem ordering, random source, host I/O).
3. Route randomness through deterministic scheduler/seeded paths.
4. Re-run doctor with same seed and runs.

### `fozzy test --det --strict` failure

Symptoms:

- scenario assertions fail
- strict-mode diagnostics errors

Fix workflow:

1. Run scenario alone with `fozzy run --det` and inspect report.
2. Fix semantic/runtime regression.
3. Add regression test if missing.
4. Re-run strict test set.

### `trace verify` / `replay` / `ci` failure

Symptoms:

- checksum mismatch
- replay outcome mismatch
- CI check `ok=false`

Fix workflow:

1. Re-record trace with explicit overwrite path.
2. Verify artifact path and schema.
3. Compare replay output vs expected status class.
4. Fix trace producer/consumer contract and add regression.

### Host-backed run failure

Symptoms:

- process/fs/http backend mismatch
- live IO operation failures

Fix workflow:

1. Confirm host permissions and environment variables.
2. Validate backend flags and endpoint availability.
3. Reproduce with single host-backed scenario.
4. Fix host adapter behavior and add scenario regression.

### `anthropic_invalid_status` / upstream HTTP status `0` or empty body

Symptoms:

- app route returns `anthropic_invalid_status`
- `http.last_status()` is `0`/`599` and response body is empty or transport-level error text

Fix workflow:

1. Confirm env bootstrap path (`.env` or `FZ_DOTENV_PATH`) and required key presence.
2. Inspect `http.last_error()` in the failing handler path and include it in response/log payloads.
3. Validate direct upstream connectivity with an equivalent out-of-band curl probe.
4. If direct probe succeeds but runtime path fails, treat as runtime HTTP adapter regression and capture stderr diagnostics from `http.last_error`.

### LSP editor/protocol/determinism smoke failure

Symptoms:

- `scripts/lsp_editor_smoke.sh` fails
- `scripts/lsp_determinism_smoke.sh` reports nondeterministic payloads
- post-shutdown request not rejected

Fix workflow:

1. Re-run both scripts locally.
2. Ensure workspace document traversal and symbol collection are stable-order.
3. Ensure shutdown state rejects further requests except `exit`.
4. Add/adjust LSP unit tests for deterministic behavior.

### `RUSTFLAGS="-D warnings" cargo check -p driver --all-targets` failure

Symptoms:

- warning promoted to error

Fix workflow:

1. Remove dead code or gate with precise `#[allow(...)]` when justified.
2. Fix clippy/rustc warning source instead of suppressing globally.
3. Re-run warning-free check.

### `fozzyfmt --check` failure

Symptoms:

- formatting drift detected

Fix workflow:

1. Run `cargo run -q -p fozzyfmt -- <paths>`.
2. Re-run `--check`.
3. Commit formatting changes with associated code change.

### `fozzydoc` smoke failure

Symptoms:

- docs extraction/generation fails
- output artifact missing/empty

Fix workflow:

1. Run `fozzydoc` command manually with same args.
2. Fix malformed declarations/comments in source.
3. Ensure output directory exists and is writable.
4. Re-run smoke and verify non-empty output.

### Pedantic topology closure failure

Symptoms:

- `uncoveredHotspotCount != 0`

Fix workflow:

1. Run `fozzy map suites ... --profile pedantic --json` and inspect uncovered hotspots.
2. Add required scenarios/suites for uncovered areas.
3. Re-run map until zero uncovered hotspots.

### Unsafe budget gate failure

Symptoms:

- `missingReasonCount > 0`
- unsafe entries exceed budget

Fix workflow:

1. Run `fz audit unsafe [target] --json`.
2. Add missing unsafe reason metadata.
3. Remove unnecessary unsafe usage or explicitly approve budget changes.
4. Re-run gate and confirm budget compliance.
