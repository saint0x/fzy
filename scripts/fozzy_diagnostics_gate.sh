#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-tests/example.fozzy.json}"
SEED="${2:-1337}"
TRACE="${3:-artifacts/diagnostics.trace.fozzy}"

fozzy doctor --deep --scenario "$SCENARIO" --runs 5 --seed "$SEED" --json
fozzy test --det --strict "$SCENARIO" --json
fozzy run "$SCENARIO" --det --seed "$SEED" --record "$TRACE" --json
fozzy trace verify "$TRACE" --strict --json
fozzy replay "$TRACE" --json
fozzy ci "$TRACE" --json
fozzy run tests/host.pass.fozzy.json --proc-backend host --fs-backend host --http-backend host --json
