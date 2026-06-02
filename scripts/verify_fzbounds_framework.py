#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "frameworklib" / "fzbounds"
STABLE_CARGO = pathlib.Path("/Users/deepsaint/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo")


def cargo_bin() -> str:
    override = os.environ.get("FZBOUNDS_VERIFY_CARGO")
    if override:
        return override
    if STABLE_CARGO.exists():
        return str(STABLE_CARGO)
    return os.environ.get("CARGO", "cargo")


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def parse_json(stdout: str):
    text = stdout.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(text.splitlines()[-1])


def ensure_ok_payload(payload: dict, label: str):
    status = payload.get("status")
    if status not in (None, "ok"):
        raise RuntimeError(f"{label} returned non-ok status: {payload}")


def binary_stdout(binary: str, *args: str) -> str:
    proc = run([binary, *args])
    if proc.returncode != 0:
        raise RuntimeError(f"{binary} {' '.join(args)} failed rc={proc.returncode} stdout={proc.stdout} stderr={proc.stderr}")
    return proc.stdout


def verify():
    check = run([cargo_bin(), "run", "-q", "-p", "fz", "--", "check", str(PACKAGE), "--json"])
    check_payload = parse_json(check.stdout)
    if check.returncode != 0:
        raise RuntimeError(f"fzbounds check failed: stdout={check.stdout} stderr={check.stderr}")
    ensure_ok_payload(check_payload, "check")

    build = run([cargo_bin(), "run", "-q", "-p", "fz", "--", "build", str(PACKAGE), "--backend", "llvm", "--json"])
    build_payload = parse_json(build.stdout)
    if build.returncode != 0:
        raise RuntimeError(f"fzbounds build failed: stdout={build.stdout} stderr={build.stderr}")
    ensure_ok_payload(build_payload, "build")
    output = build_payload.get("output")
    if not output:
        raise RuntimeError(f"fzbounds build did not return output path: {build_payload}")

    doctor = binary_stdout(output, "doctor")
    inspect = binary_stdout(output, "inspect")
    strict_demo = binary_stdout(output, "strict-demo")
    audit_demo = binary_stdout(output, "audit-demo")

    assert "\"framework\":\"fzbounds\"" in doctor, doctor
    assert "\"request_region\"" in inspect, inspect
    assert "\"demo\":\"strict\"" in strict_demo, strict_demo
    assert "\"demo\":\"audit\"" in audit_demo, audit_demo
    assert "\"framework\":\"fzweb\"" in inspect, inspect

    host_run = run([cargo_bin(), "run", "-q", "-p", "fz", "--", "run", str(PACKAGE), "--host-backends", "--json"])
    host_payload = parse_json(host_run.stdout)
    if host_run.returncode != 0:
        raise RuntimeError(f"fzbounds host-backed run failed: stdout={host_run.stdout} stderr={host_run.stderr}")
    ensure_ok_payload(host_payload, "host-run")

    print("fzbounds-framework-ok")


if __name__ == "__main__":
    try:
        verify()
    except Exception as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)
