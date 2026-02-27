#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def parse_json(stdout: str):
    text = stdout.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(text.splitlines()[-1])


def main() -> int:
    check = run(["cargo", "run", "-q", "-p", "fz", "--", "check", "frameworklib/fzweb", "--json"])
    if check.returncode != 0:
        sys.stderr.write(check.stdout)
        sys.stderr.write(check.stderr)
        return 2
    check_payload = parse_json(check.stdout)
    if int(check_payload.get("errors", 1)) != 0:
        sys.stderr.write("fzweb check reported errors\n")
        return 2

    build = run(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "fz",
            "--",
            "build",
            "frameworklib/fzweb",
            "--backend",
            "llvm",
            "--release",
            "--json",
        ]
    )
    if build.returncode != 0:
        sys.stderr.write(build.stdout)
        sys.stderr.write(build.stderr)
        return 2
    build_payload = parse_json(build.stdout)
    if build_payload.get("status") != "ok":
        sys.stderr.write("fzweb build status not ok\n")
        return 2

    print("fzweb-framework-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
