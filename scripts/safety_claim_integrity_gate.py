#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRUST_MODEL_DOC = ROOT / "docs" / "system-safety-trust-model-v1.md"
USER_FACING_DOCS = [
    ROOT / "README.md",
    ROOT / "USAGE.md",
    ROOT / "docs" / "language-reference-v1.md",
    ROOT / "docs" / "safe-profile-v1.md",
    ROOT / "docs" / "production-memory-model-v1.md",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require_contains(text: str, needle: str, errors: list[str], context: str) -> None:
    if needle not in text:
        errors.append(f"{context} missing required text: {needle}")


def main() -> int:
    errors: list[str] = []

    if not TRUST_MODEL_DOC.exists():
        print(
            "safety claim integrity gate failed:\n- missing trust model doc "
            f"{TRUST_MODEL_DOC.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 2

    trust = read_text(TRUST_MODEL_DOC)
    for heading in [
        "## Enforced Guarantees Today",
        "## Explicit Non-Goals (Current Scope)",
        "## Required Evidence Artifacts for Public Claims",
        "## Safety Claim Review Checklist",
    ]:
        require_contains(trust, heading, errors, "trust model")

    for artifact in [
        "fozzy trace verify",
        "fozzy replay",
        "fozzy ci",
        "fozzy doctor --deep",
        "fozzy test --det --strict",
        "fz audit unsafe",
        "fz abi-check",
        "scripts/ship_release_gate.sh",
    ]:
        require_contains(trust, artifact, errors, "trust model")

    for checklist_line in [
        "- [x] Memory model claims align with `docs/production-memory-model-v1.md` and do not exceed documented scope.",
        "- [x] Borrow/alias coverage statements explicitly preserve non-theorem-proof caveats.",
        "- [x] Unsafe-budget posture claims are backed by `fz audit unsafe` gate output and missing-reason rejection.",
        "- [x] FFI boundary guarantees are backed by panic-contract enforcement and ABI/header gate checks.",
    ]:
        require_contains(trust, checklist_line, errors, "trust model checklist")

    # Reject overstatements in user-facing docs.
    overclaim_patterns = [
        re.compile(r"\bequivalent to rust\b", re.IGNORECASE),
        re.compile(r"\brust[- ]class\b", re.IGNORECASE),
        re.compile(r"\brust[- ]equivalent\b", re.IGNORECASE),
        re.compile(r"\bformally verified end-to-end\b", re.IGNORECASE),
        re.compile(r"\bcomplete alias/lifetime theorem proving\b", re.IGNORECASE),
    ]
    for path in USER_FACING_DOCS:
        if not path.exists():
            errors.append(f"missing user-facing doc: {path.relative_to(ROOT)}")
            continue
        text = read_text(path)
        lower = text.lower()
        for pattern in overclaim_patterns:
            for m in pattern.finditer(lower):
                if "non-rust-equivalent" in lower[max(0, m.start() - 32) : m.end() + 32]:
                    continue
                errors.append(
                    f"overstated safety claim in {path.relative_to(ROOT)} matches /{pattern.pattern}/"
                )

    if errors:
        print("safety claim integrity gate failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 2

    print("safety claim integrity gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
