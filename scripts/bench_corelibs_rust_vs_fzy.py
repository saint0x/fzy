#!/usr/bin/env python3
import argparse
import json
import math
import pathlib
import random
import statistics
import subprocess
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

BENCHES = [
    {
        "name": "resultx_classify",
        "rust_mode": "resultx",
        "fzy_src": ROOT / "examples" / "benchmarks" / "resultx_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "text_kernel",
        "rust_mode": "text",
        "fzy_src": ROOT / "examples" / "benchmarks" / "text_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "capability_parse",
        "rust_mode": "capability",
        "fzy_src": ROOT / "examples" / "benchmarks" / "capability_parse_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "task_retry_backoff",
        "rust_mode": "task_retry",
        "fzy_src": ROOT / "examples" / "benchmarks" / "task_retry_backoff_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "arithmetic_kernel",
        "rust_mode": "arithmetic",
        "fzy_src": ROOT / "examples" / "benchmarks" / "arithmetic_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "bytes_kernel",
        "rust_mode": "bytes",
        "fzy_src": ROOT / "examples" / "benchmarks" / "bytes_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "duration_kernel",
        "rust_mode": "duration",
        "fzy_src": ROOT / "examples" / "benchmarks" / "duration_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "abi_pair_kernel",
        "rust_mode": "abi_pair",
        "fzy_src": ROOT / "examples" / "benchmarks" / "abi_pair_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
    {
        "name": "c_interop_contract_kernel",
        "rust_mode": "c_interop_contract",
        "fzy_src": ROOT / "examples" / "benchmarks" / "c_interop_contract_scratch_bench.fzy",
        "iterations": 8_000_000,
    },
]


def run(cmd, cwd=ROOT, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, capture_output=True)


def run_json(cmd):
    out = run(cmd).stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


def timed_run(cmd, ok_returncodes):
    t0 = time.perf_counter_ns()
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    t1 = time.perf_counter_ns()
    if proc.returncode not in ok_returncodes:
        raise RuntimeError(
            f"command failed rc={proc.returncode}: {' '.join(cmd)}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return (t1 - t0) / 1_000_000.0


def parse_rust_checksum(stdout: str) -> int:
    line = stdout.strip().splitlines()[-1]
    return int(line.split("checksum=")[-1])


def percentile(sorted_vals, p: float):
    if not sorted_vals:
        raise ValueError("empty sample")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (len(sorted_vals) - 1) * p
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return sorted_vals[low]
    frac = rank - low
    return sorted_vals[low] * (1.0 - frac) + sorted_vals[high] * frac


def bootstrap_ratio_ci(fzy_vals, rust_vals, samples: int, seed: int):
    rng = random.Random(seed)
    n = len(fzy_vals)
    ratios = []
    for _ in range(samples):
        fzy_mean = statistics.fmean(fzy_vals[rng.randrange(0, n)] for _ in range(n))
        rust_mean = statistics.fmean(rust_vals[rng.randrange(0, n)] for _ in range(n))
        ratios.append(fzy_mean / rust_mean)
    ratios.sort()
    return {
        "p50": percentile(ratios, 0.5),
        "p025": percentile(ratios, 0.025),
        "p975": percentile(ratios, 0.975),
    }


def stats(values):
    vals = sorted(values)
    n = len(vals)
    mean = statistics.fmean(vals)
    stdev = statistics.pstdev(vals)
    return {
        "runs": n,
        "min_ms": vals[0],
        "p50_ms": percentile(vals, 0.5),
        "p95_ms": percentile(vals, 0.95),
        "p99_ms": percentile(vals, 0.99),
        "max_ms": vals[-1],
        "mean_ms": mean,
        "stdev_ms": stdev,
        "cv": (stdev / mean) if mean > 0 else 0.0,
    }


def locate_rust_bin() -> pathlib.Path:
    candidates = [
        ROOT / "target" / "release" / "text_bench_rust",
        ROOT / "target" / "aarch64-apple-darwin" / "release" / "text_bench_rust",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("unable to locate built text_bench_rust binary under target/")


def parse_args():
    parser = argparse.ArgumentParser(description="Run robust Rust vs Fzy production-corelib benchmark suite")
    parser.add_argument("--warmup-runs", type=int, default=5)
    parser.add_argument("--measured-runs", type=int, default=30)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260226)
    parser.add_argument(
        "--out-prefix",
        default="bench_corelibs_rust_vs_fzy",
        help="Artifact prefix written into artifacts/<prefix>.json|.md",
    )
    return parser.parse_args()


def classify_ratio(ratio: float) -> str:
    if ratio < 0.95:
        return "fzy_faster"
    if ratio > 1.05:
        return "rust_faster"
    return "near_parity"


def main():
    args = parse_args()

    run(["cargo", "build", "-p", "text_bench_rust", "--release"])
    rust_bin = locate_rust_bin()

    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    suite_results = []

    for bench in BENCHES:
        build = run_json(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "fz",
                "--",
                "build",
                str(bench["fzy_src"]),
                "--backend",
                "llvm",
                "--release",
                "--json",
            ]
        )
        fzy_bin = pathlib.Path(build["output"])

        rust_probe = run([str(rust_bin), bench["rust_mode"]])
        rust_checksum = parse_rust_checksum(rust_probe.stdout)

        fzy_probe = subprocess.run([str(fzy_bin)], cwd=ROOT, capture_output=True, text=True)
        fzy_checksum = fzy_probe.returncode
        if rust_checksum != fzy_checksum:
            raise RuntimeError(
                f"checksum mismatch bench={bench['name']} rust={rust_checksum} fzy_exit={fzy_checksum}"
            )

        rust_times = []
        fzy_times = []
        rust_ok = {0}
        fzy_ok = {fzy_checksum}

        for i in range(args.warmup_runs):
            order = ("rust", "fzy") if i % 2 == 0 else ("fzy", "rust")
            for target in order:
                if target == "rust":
                    timed_run([str(rust_bin), bench["rust_mode"]], rust_ok)
                else:
                    timed_run([str(fzy_bin)], fzy_ok)

        for i in range(args.measured_runs):
            order = ("rust", "fzy") if i % 2 == 0 else ("fzy", "rust")
            for target in order:
                if target == "rust":
                    rust_times.append(timed_run([str(rust_bin), bench["rust_mode"]], rust_ok))
                else:
                    fzy_times.append(timed_run([str(fzy_bin)], fzy_ok))

        rust_stats = stats(rust_times)
        fzy_stats = stats(fzy_times)
        ratio = fzy_stats["mean_ms"] / rust_stats["mean_ms"]
        ratio_ci = bootstrap_ratio_ci(
            fzy_times,
            rust_times,
            samples=args.bootstrap_samples,
            seed=(args.seed + len(suite_results) * 997),
        )

        suite_results.append(
            {
                "bench": bench["name"],
                "iterations": bench["iterations"],
                "checksum": rust_checksum,
                "rust_mode": bench["rust_mode"],
                "fzy_source": str(bench["fzy_src"].relative_to(ROOT)),
                "rust": rust_stats,
                "fzy": fzy_stats,
                "ratio_fzy_over_rust": ratio,
                "ratio_ci95_bootstrap": ratio_ci,
                "classification": classify_ratio(ratio),
            }
        )

    wins = {"fzy_faster": 0, "rust_faster": 0, "near_parity": 0}
    for result in suite_results:
        wins[result["classification"]] += 1

    payload = {
        "suite": "corelibs-rust-vs-fzy-production-corelib-robust",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "warmup_runs": args.warmup_runs,
        "measured_runs": args.measured_runs,
        "bootstrap_samples": args.bootstrap_samples,
        "seed": args.seed,
        "benches": suite_results,
        "summary": {
            "classification_counts": wins,
            "geomean_ratio_fzy_over_rust": math.prod(
                r["ratio_fzy_over_rust"] for r in suite_results
            )
            ** (1.0 / len(suite_results)),
            "mean_ratio_fzy_over_rust": statistics.fmean(
                r["ratio_fzy_over_rust"] for r in suite_results
            ),
        },
    }

    json_path = ARTIFACTS / f"{args.out_prefix}.json"
    md_path = ARTIFACTS / f"{args.out_prefix}.md"

    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Core Library Benchmarks (Rust vs Fzy Production Corelib, Robust)",
        "",
        f"- Commit: `{commit}`",
        f"- Timestamp (UTC): {payload['timestamp_utc']}",
        f"- Warmup runs: {args.warmup_runs}",
        f"- Measured runs: {args.measured_runs}",
        f"- Bootstrap samples: {args.bootstrap_samples}",
        f"- Seed: {args.seed}",
        "",
        "| Benchmark | Rust mean ms | Fzy mean ms | Ratio (fzy/rust) | 95% CI ratio | Rust p95 ms | Fzy p95 ms | Verdict |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for result in suite_results:
        ci = result["ratio_ci95_bootstrap"]
        lines.append(
            f"| {result['bench']} | {result['rust']['mean_ms']:.3f} | {result['fzy']['mean_ms']:.3f} | {result['ratio_fzy_over_rust']:.3f}x | [{ci['p025']:.3f}, {ci['p975']:.3f}] | {result['rust']['p95_ms']:.3f} | {result['fzy']['p95_ms']:.3f} | {result['classification']} |"
        )

    lines.extend(
        [
            "",
            "## Suite Summary",
            "",
            f"- Fzy faster (<0.95x): {wins['fzy_faster']}",
            f"- Rust faster (>1.05x): {wins['rust_faster']}",
            f"- Near parity (0.95x-1.05x): {wins['near_parity']}",
            f"- Geometric mean ratio (fzy/rust): {payload['summary']['geomean_ratio_fzy_over_rust']:.3f}x",
            f"- Arithmetic mean ratio (fzy/rust): {payload['summary']['mean_ratio_fzy_over_rust']:.3f}x",
            "",
        ]
    )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2))
    print(f"\nWrote: {json_path}")
    print(f"Wrote: {md_path}")


if __name__ == "__main__":
    main()
