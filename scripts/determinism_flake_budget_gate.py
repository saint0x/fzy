#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / "artifacts"
DEFAULT_BUDGET = 0

COUNT_KEYS = {
    "flakeFindings",
    "nondeterministicFindings",
    "deterministicMismatchCount",
    "nondeterministicCount",
}


def collect_counts(payload):
    total = 0
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in COUNT_KEYS and isinstance(value, int):
                total += value
            else:
                total += collect_counts(value)
    elif isinstance(payload, list):
        for value in payload:
            total += collect_counts(value)
    return total


def main() -> int:
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BUDGET
    if not ARTIFACT_DIR.exists():
        print("flake budget gate passed: artifacts directory is absent (count=0)")
        return 0

    total = 0
    scanned = 0
    for path in ARTIFACT_DIR.rglob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        count = collect_counts(payload)
        if count > 0:
            total += count
        scanned += 1

    print(f"flake_findings={total} budget={budget} scanned_json_files={scanned}")
    if total > budget:
        print(
            f"determinism flake budget exceeded: findings={total} budget={budget}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

