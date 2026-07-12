#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "NOJSON.md"

REQUIRED_PHRASES = [
    "typed structures",
    "real boundaries only",
    "serde_json::Value",
    "stable typed payload",
    "cache identity",
    "request/session/domain state typed in memory",
    "versioned, validated, deterministic",
    "add or update tests",
]

FORBIDDEN_PHRASES = [
    "remaining backlog",
    "commit and push the completed chunk immediately",
]


def main() -> int:
    if not DOC.exists():
        print(f"missing NOJSON policy document: {DOC}", file=sys.stderr)
        return 1

    text = DOC.read_text(encoding="utf-8")
    missing = [phrase for phrase in REQUIRED_PHRASES if phrase not in text]
    if missing:
        print("NOJSON policy document is missing required production contract language:", file=sys.stderr)
        for phrase in missing:
            print(f"  - {phrase}", file=sys.stderr)
        return 1

    forbidden = [phrase for phrase in FORBIDDEN_PHRASES if phrase in text]
    if forbidden:
        print("NOJSON policy document still contains backlog/process language instead of architecture policy:", file=sys.stderr)
        for phrase in forbidden:
            print(f"  - {phrase}", file=sys.stderr)
        return 1

    print("nojson policy gate: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
