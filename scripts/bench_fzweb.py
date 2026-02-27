#!/usr/bin/env python3
import json
import math
import pathlib
import statistics
import subprocess
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

BENCHES = [
    ("fzweb_route_kernel", ROOT / "frameworklib" / "fzweb" / "src" / "bench_route.fzy"),
    ("fzweb_middleware_kernel", ROOT / "frameworklib" / "fzweb" / "src" / "bench_middleware.fzy"),
    ("fzweb_pipeline_kernel", ROOT / "frameworklib" / "fzweb" / "src" / "bench_pipeline.fzy"),
]

WARMUP = 5
RUNS = 25


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=True)


def timed(bin_path, ok_codes):
    t0 = time.perf_counter_ns()
    proc = subprocess.run([str(bin_path)], cwd=ROOT, capture_output=True, text=True)
    t1 = time.perf_counter_ns()
    if proc.returncode not in ok_codes:
        raise RuntimeError(f"rc={proc.returncode} stdout={proc.stdout} stderr={proc.stderr}")
    return (t1 - t0) / 1_000_000.0


def percentile(vals, p):
    vals = sorted(vals)
    if len(vals) == 1:
        return vals[0]
    rank = (len(vals) - 1) * p
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return vals[lo]
    frac = rank - lo
    return vals[lo] * (1 - frac) + vals[hi] * frac


def stats(vals):
    return {
        "runs": len(vals),
        "min_ms": min(vals),
        "p50_ms": percentile(vals, 0.50),
        "p95_ms": percentile(vals, 0.95),
        "max_ms": max(vals),
        "mean_ms": statistics.fmean(vals),
        "stdev_ms": statistics.pstdev(vals),
    }


def main():
    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    suite = []

    for name, src in BENCHES:
        build = json.loads(
            run([
                "cargo", "run", "-q", "-p", "fz", "--", "build", str(src), "--backend", "llvm", "--release", "--json"
            ]).stdout
        )
        bin_path = pathlib.Path(build["output"])

        probe = subprocess.run([str(bin_path)], cwd=ROOT, capture_output=True, text=True)
        checksum = probe.returncode

        for _ in range(WARMUP):
            timed(bin_path, {checksum})

        samples = [timed(bin_path, {checksum}) for _ in range(RUNS)]
        suite.append({
            "bench": name,
            "source": str(src.relative_to(ROOT)),
            "checksum": checksum,
            "stats": stats(samples),
        })

    suite_sorted = sorted(suite, key=lambda b: b["stats"]["mean_ms"])
    payload = {
        "suite": "fzweb-performance-kernels",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "warmup_runs": WARMUP,
        "measured_runs": RUNS,
        "benches": suite,
        "ranking_fastest_to_slowest": [b["bench"] for b in suite_sorted],
        "winner": suite_sorted[0]["bench"],
    }

    out_json = ARTIFACTS / "bench_fzweb.json"
    out_md = ARTIFACTS / "bench_fzweb.md"
    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# FZWeb Benchmarks",
        "",
        f"- Commit: `{commit}`",
        f"- Timestamp (UTC): {payload['timestamp_utc']}",
        f"- Warmup: {WARMUP}",
        f"- Measured: {RUNS}",
        "",
        "| Benchmark | Mean ms | p50 ms | p95 ms | Winner Rank |",
        "|---|---:|---:|---:|---:|",
    ]
    rank = {name: i + 1 for i, name in enumerate(payload["ranking_fastest_to_slowest"])}
    for b in suite:
        s = b["stats"]
        lines.append(f"| {b['bench']} | {s['mean_ms']:.3f} | {s['p50_ms']:.3f} | {s['p95_ms']:.3f} | {rank[b['bench']]} |")
    lines.append("")
    lines.append(f"- Winner (fastest mean): **{payload['winner']}**")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2))
    print(f"Wrote: {out_json}")
    print(f"Wrote: {out_md}")


if __name__ == "__main__":
    main()
