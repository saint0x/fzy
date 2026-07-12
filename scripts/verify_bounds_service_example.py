#!/usr/bin/env python3
import json
import os
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT = ROOT / "examples" / "bounds_service"
STABLE_CARGO = pathlib.Path("/Users/deepsaint/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo")


def cargo_bin() -> str:
    override = os.environ.get("BOUNDS_SERVICE_VERIFY_CARGO")
    if override:
        return override
    if STABLE_CARGO.exists():
        return str(STABLE_CARGO)
    return os.environ.get("CARGO", "cargo")


def cargo_prefix() -> list[str]:
    cargo = cargo_bin()
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        return [cargo]
    try:
        desc = subprocess.check_output(["file", cargo], text=True).strip()
    except Exception:
        return [cargo]
    if "arm64" in desc and "x86_64" not in desc:
        return ["/usr/bin/arch", "-arm64", cargo]
    return [cargo]


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


def ensure_ok(payload: dict, label: str):
    status = payload.get("status")
    if status not in (None, "ok", "pass"):
        raise RuntimeError(f"{label} returned non-ok status: {payload}")


def verify():
    cargo = cargo_prefix()

    check = run(cargo + ["run", "-q", "-p", "fz", "--", "check", str(PROJECT), "--json"])
    check_payload = parse_json(check.stdout)
    if check.returncode != 0:
        raise RuntimeError(f"bounds_service check failed: stdout={check.stdout} stderr={check.stderr}")
    ensure_ok(check_payload, "check")

    vendor = run(cargo + ["run", "-q", "-p", "fz", "--", "vendor", str(PROJECT), "--json"])
    if vendor.returncode != 0:
        raise RuntimeError(f"bounds_service vendor failed: stdout={vendor.stdout} stderr={vendor.stderr}")

    build = run(
        cargo + ["run", "-q", "-p", "fz", "--", "build", str(PROJECT), "--backend", "llvm", "--json"]
    )
    build_payload = parse_json(build.stdout)
    if build.returncode != 0:
        raise RuntimeError(f"bounds_service build failed: stdout={build.stdout} stderr={build.stderr}")
    ensure_ok(build_payload, "build")
    output = build_payload.get("output")
    if not output:
        raise RuntimeError(f"bounds_service build missing output path: {build_payload}")

    doctor = subprocess.run([output, "doctor-json"], cwd=ROOT, capture_output=True, text=True)
    if doctor.returncode != 0:
        raise RuntimeError(f"bounds_service doctor-json failed: stdout={doctor.stdout} stderr={doctor.stderr}")
    doctor_payload = parse_json(doctor.stdout)
    local_contract = doctor_payload.get("local_contract", {})
    assert doctor_payload.get("framework") == "bounds_service", doctor_payload
    assert local_contract.get("request_budget_bytes") == 65536, doctor_payload
    assert local_contract.get("header_capacity") == 64, doctor_payload
    assert local_contract.get("body_capacity_bytes") == 65536, doctor_payload
    assert local_contract.get("session_capacity") == 100000, doctor_payload

    gate = subprocess.run([output, "gate-json"], cwd=ROOT, capture_output=True, text=True)
    if gate.returncode != 0:
        raise RuntimeError(f"bounds_service gate-json failed: stdout={gate.stdout} stderr={gate.stderr}")
    gate_payload = parse_json(gate.stdout)
    assert gate_payload.get("status") == "ok", gate_payload
    assert gate_payload.get("alignment", {}).get("runtime_mode_ok") is True, gate_payload

    framework = subprocess.run([output, "framework-json"], cwd=ROOT, capture_output=True, text=True)
    if framework.returncode != 0:
        raise RuntimeError(f"bounds_service framework-json failed: stdout={framework.stdout} stderr={framework.stderr}")
    framework_payload = parse_json(framework.stdout)
    assert framework_payload.get("framework") == "bounds_service", framework_payload
    framework_report = framework_payload.get("framework_report", {})
    assert framework_report.get("status") == "ok", framework_payload
    inspect = framework_report.get("inspect", {})
    assert inspect.get("framework") == "fzbounds", framework_payload
    assert inspect.get("fzweb", {}).get("framework") == "fzweb", framework_payload
    assert framework_payload.get("alignment", {}).get("status") == "ok", framework_payload

    print("bounds-service-example-ok")


if __name__ == "__main__":
    try:
        verify()
    except Exception as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)
