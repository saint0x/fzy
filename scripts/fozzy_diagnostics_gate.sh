#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-tests/example.fozzy.json}"
SEED="${2:-1337}"
TRACE="${3:-artifacts/diagnostics.trace.fozzy}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v fz >/dev/null 2>&1; then
  FZ_CMD=(fz)
else
  FZ_CMD=(cargo run -q -p fz --)
fi

"${FZ_CMD[@]}" doctor --deep --scenario "$SCENARIO" --runs 5 --seed "$SEED" --json
"${FZ_CMD[@]}" test "$SCENARIO" --det --strict-verify --json
"${FZ_CMD[@]}" run "$SCENARIO" --det --seed "$SEED" --record "$TRACE" --json
"${FZ_CMD[@]}" trace verify "$TRACE" --strict --json
"${FZ_CMD[@]}" replay "$TRACE" --json
"${FZ_CMD[@]}" ci "$TRACE" --json
"${FZ_CMD[@]}" run tests/host.pass.fozzy.json --host-backends --json
