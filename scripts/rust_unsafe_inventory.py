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


def main():
    args = parse_args()
    root = pathlib.Path(args.root).resolve()
    entries = []

    for file_path in iter_rs_files(root):
        text = file_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
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
    payload = {
        "schemaVersion": "fozzylang.rust_unsafe_inventory.v1",
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "budget": args.budget,
        "entries": entries,
        "count": len(entries),
        "undocumentedCount": len(undocumented),
    }

    out_path = pathlib.Path(args.out)
    if not out_path.is_absolute():
        out_path = root / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "ok": len(undocumented) == 0 and len(entries) <= args.budget,
        "count": len(entries),
        "undocumentedCount": len(undocumented),
        "budget": args.budget,
        "out": str(out_path),
    }))

    if undocumented:
        print("undocumented Rust unsafe sites detected", file=sys.stderr)
        sys.exit(2)
    if len(entries) > args.budget:
        print(f"Rust unsafe budget exceeded: count={len(entries)} budget={args.budget}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
