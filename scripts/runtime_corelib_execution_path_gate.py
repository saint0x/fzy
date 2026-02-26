#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cargo_metadata() -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cargo metadata failed")
    return json.loads(proc.stdout)


def package_id_by_name(metadata: dict, name: str) -> str | None:
    for package in metadata.get("packages", []):
        if package.get("name") == name:
            return package.get("id")
    return None


def dependency_closure(metadata: dict, root_id: str) -> set[str]:
    resolve = metadata.get("resolve") or {}
    nodes = {
        node.get("id"): [dep.get("pkg") for dep in node.get("deps", [])]
        for node in resolve.get("nodes", [])
    }
    seen: set[str] = set()
    stack = [root_id]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(nodes.get(current, []))
    return seen


def main() -> int:
    metadata = cargo_metadata()
    fz_id = package_id_by_name(metadata, "fz")
    if fz_id is None:
        print("runtime corelib execution path gate failed: missing `fz` package", file=sys.stderr)
        return 2

    closure = dependency_closure(metadata, fz_id)
    package_name = {pkg.get("id"): pkg.get("name") for pkg in metadata.get("packages", [])}
    closure_names = {package_name.get(pkg_id, "") for pkg_id in closure}

    if "stdlib" in closure_names:
        print(
            "runtime corelib execution path gate failed: `fz` dependency closure includes `stdlib`",
            file=sys.stderr,
        )
        return 2

    required = {"driver", "runtime", "core"}
    missing = sorted(required.difference(closure_names))
    if missing:
        print(
            "runtime corelib execution path gate failed: missing required runtime packages: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    print("runtime-corelib-execution-path-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
