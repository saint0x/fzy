#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

DEFAULT_SKIP = {"target", ".git", "artifacts", "vendor", "node_modules"}

UNSAFE_BLOCK_RE = re.compile(r"\bunsafe\s*\{")
UNSAFE_FN_RE = re.compile(r"\bunsafe\s+fn\b")


def parse_args():
    p = argparse.ArgumentParser(description="Inventory and gate Rust unsafe usage in first-party crates")
    p.add_argument("--root", default=".")
    p.add_argument("--out", default="artifacts/rust_unsafe_inventory.json")
    p.add_argument("--budget", type=int, default=0)
    p.add_argument("--policy", default="")
    return p.parse_args()


def iter_rs_files(root: pathlib.Path):
    crates = root / "crates"
    if not crates.exists():
        return
    for path in crates.rglob("*.rs"):
        rel_parts = set(path.relative_to(root).parts)
        if rel_parts & DEFAULT_SKIP:
            continue
        yield path


def preceding_safety_comment(lines, idx):
    # Look back a few lines for explicit safety rationale markers.
    start = max(0, idx - 3)
    window = lines[start:idx]
    joined = "\n".join(window)
    return ("Safety:" in joined) or ("SAFETY:" in joined)


def sanitize_rust_source(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    state = "code"
    raw_hashes = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                out.append(" ")
                out.append(" ")
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out.append(" ")
                out.append(" ")
                i += 2
                state = "block_comment"
                continue
            if ch == "r":
                j = i + 1
                while j < n and text[j] == "#":
                    j += 1
                if j < n and text[j] == '"':
                    out.extend(" " * (j - i + 1))
                    raw_hashes = j - i - 1
                    i = j + 1
                    state = "raw_string"
                    continue
            if ch == '"':
                out.append(" ")
                i += 1
                state = "string"
                continue
            if ch == "'":
                out.append(" ")
                i += 1
                state = "char"
                continue
            out.append(ch)
            i += 1
            continue

        if state == "line_comment":
            out.append("\n" if ch == "\n" else " ")
            i += 1
            if ch == "\n":
                state = "code"
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.append(" ")
                out.append(" ")
                i += 2
                state = "code"
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue

        if state == "string":
            if ch == "\\" and i + 1 < n:
                out.append(" ")
                out.append("\n" if text[i + 1] == "\n" else " ")
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            if ch == '"':
                state = "code"
            continue

        if state == "char":
            if ch == "\\" and i + 1 < n:
                out.append(" ")
                out.append("\n" if text[i + 1] == "\n" else " ")
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            if ch == "'":
                state = "code"
            continue

        if state == "raw_string":
            if ch == '"':
                hashes = 0
                j = i + 1
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if hashes == raw_hashes:
                    out.append(" ")
                    out.extend(" " * hashes)
                    i = j
                    state = "code"
                    continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue

    return "".join(out)


def main():
    args = parse_args()
    root = pathlib.Path(args.root).resolve()
    policy = {}
    if args.policy:
        policy_path = pathlib.Path(args.policy)
        if not policy_path.is_absolute():
            policy_path = root / policy_path
        if policy_path.exists():
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
    entries = []

    for file_path in iter_rs_files(root):
        text = file_path.read_text(encoding="utf-8")
        sanitized = sanitize_rust_source(text)
        lines = text.splitlines()
        sanitized_lines = sanitized.splitlines()
        for i, line in enumerate(sanitized_lines, start=1):
            for kind, regex in (("unsafe_block", UNSAFE_BLOCK_RE), ("unsafe_fn", UNSAFE_FN_RE)):
                if not regex.search(line):
                    continue
                documented = preceding_safety_comment(lines, i - 1)
                entries.append(
                    {
                        "file": str(file_path),
                        "line": i,
                        "kind": kind,
                        "snippet": line.strip(),
                        "documented": documented,
                    }
                )

    undocumented = [entry for entry in entries if not entry["documented"]]
    allowed_files = set(policy.get("allowedFiles", []))
    if allowed_files:
        for item in entries:
            rel = str(pathlib.Path(item["file"]).resolve().relative_to(root))
            item["fileRelative"] = rel
    disallowed = []
    if allowed_files:
        disallowed = [
            entry for entry in entries if entry.get("fileRelative", "") not in allowed_files
        ]
    baseline_count = int(policy.get("baselineCount", len(entries)))
    approved_delta = int(policy.get("approvedDelta", 0))
    max_allowed = baseline_count + approved_delta
    payload = {
        "schemaVersion": "fozzylang.rust_unsafe_inventory.v1",
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "budget": args.budget,
        "policy": policy,
        "entries": entries,
        "count": len(entries),
        "undocumentedCount": len(undocumented),
        "disallowedCount": len(disallowed),
        "driftOverCount": max(0, len(entries) - max_allowed),
    }

    out_path = pathlib.Path(args.out)
    if not out_path.is_absolute():
        out_path = root / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "ok": len(undocumented) == 0 and len(disallowed) == 0 and len(entries) <= args.budget and len(entries) <= max_allowed,
        "count": len(entries),
        "undocumentedCount": len(undocumented),
        "disallowedCount": len(disallowed),
        "baselineCount": baseline_count,
        "approvedDelta": approved_delta,
        "maxAllowed": max_allowed,
        "budget": args.budget,
        "out": str(out_path),
    }))

    if undocumented:
        print("undocumented Rust unsafe sites detected", file=sys.stderr)
        sys.exit(2)
    if disallowed:
        print("Rust unsafe used outside approved unsafe-island files", file=sys.stderr)
        sys.exit(4)
    if len(entries) > max_allowed:
        print(
            f"Rust unsafe drift exceeded: count={len(entries)} baseline={baseline_count} approvedDelta={approved_delta}",
            file=sys.stderr,
        )
        sys.exit(5)
    if len(entries) > args.budget:
        print(f"Rust unsafe budget exceeded: count={len(entries)} budget={args.budget}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
