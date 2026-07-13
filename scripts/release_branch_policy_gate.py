#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FZ_CMD = ["cargo", "run", "-q", "-p", "fz", "--"]


def git_ls_files(*patterns: str) -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "--", *patterns],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in proc.stdout.splitlines() if line.strip()]


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_project_filter(env_name: str) -> set[str] | None:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return None
    return {item.strip().strip("/").replace("\\", "/") for item in raw.split(",") if item.strip()}


def project_allowed(project: Path, allowed: set[str] | None) -> bool:
    if allowed is None:
        return True
    return rel(project) in allowed


def files_identical(left: Path, right: Path) -> bool:
    return left.exists() and right.exists() and left.read_bytes() == right.read_bytes()


def normalized_abi_payload(path: Path) -> object | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text())
    for key in ("targetTriple", "compilerIdentityHash", "dataLayoutHash"):
        payload.pop(key, None)
    return payload


def check_lock_and_vendor_drift(project: Path, has_tracked_vendor: bool) -> list[str]:
    failures: list[str] = []
    proc = subprocess.run(
        [*FZ_CMD, "vendor", str(project), "--check", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "vendor check failed"
        failures.append(f"{rel(project)}: {detail}")
        return failures
    payload = json.loads(proc.stdout)
    if has_tracked_vendor and payload.get("vendorState") != "ok":
        failures.append(
            f"{rel(project)}: tracked vendor snapshot missing or unverified (vendorState={payload.get('vendorState')})"
        )
    return failures


def check_ffi_artifacts(project: Path) -> list[str]:
    failures: list[str] = []
    include_dir = project / "include"
    header = include_dir / f"{project.name}.h"
    abi = include_dir / f"{project.name}.abi.json"
    with tempfile.TemporaryDirectory(prefix="fozzy-release-policy-") as temp_dir:
        generated_header = Path(temp_dir) / f"{project.name}.h"
        subprocess.run(
            [*FZ_CMD, "headers", str(project), "--out", str(generated_header), "--json"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        generated_abi = generated_header.with_suffix(".abi.json")
        if not files_identical(header, generated_header):
            failures.append(f"{rel(project)}: checked-in header drifted from generated output")
        if normalized_abi_payload(abi) != normalized_abi_payload(generated_abi):
            failures.append(f"{rel(project)}: checked-in ABI manifest drifted from generated output")
    return failures


def main() -> int:
    lock_projects = sorted({path.parent for path in git_ls_files("*fozzy.lock")})
    tracked_vendor_projects = {path.parent.parent for path in git_ls_files("*/vendor/fozzy-vendor.json", "vendor/fozzy-vendor.json")}
    ffi_projects = sorted({path.parent.parent for path in git_ls_files("*/include/*.h", "*/include/*.abi.json")})

    lock_filter = load_project_filter("RELEASE_POLICY_PROJECTS")
    ffi_filter = load_project_filter("RELEASE_POLICY_FFI_PROJECTS")

    failures: list[str] = []
    for project in lock_projects:
        if not project_allowed(project, lock_filter):
            continue
        failures.extend(
            check_lock_and_vendor_drift(
                project,
                project in tracked_vendor_projects,
            )
        )
    for project in ffi_projects:
        if not project_allowed(project, ffi_filter):
            continue
        failures.extend(check_ffi_artifacts(project))

    if failures:
        print("release branch policy gate failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print(
        "release branch policy gate passed "
        f"(lockProjects={len([p for p in lock_projects if project_allowed(p, lock_filter)])} "
        f"ffiProjects={len([p for p in ffi_projects if project_allowed(p, ffi_filter)])})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
