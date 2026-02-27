#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BENCHES = [
    ("resultx_classify", "resultx", ROOT / "examples" / "benchmarks" / "resultx_scratch_bench.fzy"),
    ("text_kernel", "text", ROOT / "examples" / "benchmarks" / "text_scratch_bench.fzy"),
    ("capability_parse", "capability", ROOT / "examples" / "benchmarks" / "capability_parse_scratch_bench.fzy"),
    ("task_retry_backoff", "task_retry", ROOT / "examples" / "benchmarks" / "task_retry_backoff_scratch_bench.fzy"),
    ("arithmetic_kernel", "arithmetic", ROOT / "examples" / "benchmarks" / "arithmetic_scratch_bench.fzy"),
    ("bytes_kernel", "bytes", ROOT / "examples" / "benchmarks" / "bytes_scratch_bench.fzy"),
    ("duration_kernel", "duration", ROOT / "examples" / "benchmarks" / "duration_scratch_bench.fzy"),
    ("abi_pair_kernel", "abi_pair", ROOT / "examples" / "benchmarks" / "abi_pair_scratch_bench.fzy"),
    ("c_interop_contract_kernel", "c_interop_contract", ROOT / "examples" / "benchmarks" / "c_interop_contract_scratch_bench.fzy"),
]


def run(cmd, check=True):
    return subprocess.run(cmd, cwd=ROOT, check=check, capture_output=True, text=True)


def run_json(cmd):
    out = run(cmd).stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


def parse_rust_checksum(stdout: str) -> int:
    return int(stdout.strip().splitlines()[-1].split("checksum=")[-1])


def locate_rust_bin() -> pathlib.Path:
    candidates = [
        ROOT / "target" / "release" / "text_bench_rust",
        ROOT / "target" / "aarch64-apple-darwin" / "release" / "text_bench_rust",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("unable to locate built text_bench_rust binary under target/")


def main():
    run(["cargo", "build", "-p", "text_bench_rust", "--release"])
    rust_bin = locate_rust_bin()

    verified = []
    for name, rust_mode, fzy_src in BENCHES:
        build = run_json(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "fz",
                "--",
                "build",
                str(fzy_src),
                "--backend",
                "llvm",
                "--release",
                "--json",
            ]
        )
        fzy_bin = pathlib.Path(build["output"])

        rust_probe = run([str(rust_bin), rust_mode])
        rust_checksum = parse_rust_checksum(rust_probe.stdout)

        fzy_probe = subprocess.run([str(fzy_bin)], cwd=ROOT, capture_output=True, text=True)
        fzy_checksum = fzy_probe.returncode

        if rust_checksum != fzy_checksum:
            raise RuntimeError(
                f"checksum mismatch bench={name} rust={rust_checksum} fzy={fzy_checksum}"
            )
        verified.append({"bench": name, "checksum": rust_checksum})

    out_path = ROOT / "artifacts" / "corelibs_bench_matrix_verify.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"verified": verified}, indent=2) + "\n", encoding="utf-8")
    print("corelibs-bench-matrix-ok")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
