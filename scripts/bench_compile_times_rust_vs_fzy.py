#!/usr/bin/env python3
import argparse
import json
import math
import pathlib
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
GENERATED_ROOT = ARTIFACTS / "compile_bench_projects"

CASES = [
    {"name": "tiny", "module_count": 6, "helpers_per_module": 8},
    {"name": "small", "module_count": 14, "helpers_per_module": 12},
    {"name": "medium", "module_count": 28, "helpers_per_module": 16},
    {"name": "large", "module_count": 44, "helpers_per_module": 20},
]

PROFILES = [
    {"name": "dev", "rust_args": [], "fzy_args": []},
    {"name": "release", "rust_args": ["--release"], "fzy_args": ["--release"]},
]

MODES = [
    {"name": "cold_full", "description": "clean build from scratch before every run"},
    {"name": "warm_noop", "description": "rebuild without edits after one priming build"},
    {"name": "warm_leaf_change", "description": "rebuild after a semantically neutral leaf-file edit"},
]


def run(cmd, cwd=ROOT, check=True, env=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
        env=env,
    )


def run_json(cmd, cwd=ROOT, env=None):
    out = run(cmd, cwd=cwd, env=env).stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return json.loads(out.splitlines()[-1])


def timed_run(cmd, cwd=ROOT, env=None):
    t0 = time.perf_counter_ns()
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, env=env)
    t1 = time.perf_counter_ns()
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed rc={proc.returncode}: {' '.join(str(part) for part in cmd)}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return (t1 - t0) / 1_000_000.0, proc


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


def stats(values):
    vals = sorted(values)
    mean = statistics.fmean(vals)
    stdev = statistics.pstdev(vals)
    return {
        "runs": len(vals),
        "min_ms": vals[0],
        "p50_ms": percentile(vals, 0.5),
        "p95_ms": percentile(vals, 0.95),
        "max_ms": vals[-1],
        "mean_ms": mean,
        "stdev_ms": stdev,
        "cv": (stdev / mean) if mean > 0 else 0.0,
    }


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


def locate_fz_bin() -> pathlib.Path:
    candidates = [
        ROOT / "target" / "release" / "fz",
        ROOT / "target" / "aarch64-apple-darwin" / "release" / "fz",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("unable to locate release-built fz binary under target/")


def ensure_fz_bin() -> pathlib.Path:
    try:
        return locate_fz_bin()
    except RuntimeError:
        run(["cargo", "build", "-q", "-p", "fz", "--release"])
        return locate_fz_bin()


def count_source_metrics(root: pathlib.Path, suffix: str):
    files = sorted(root.rglob(f"*{suffix}"))
    loc = 0
    total_bytes = 0
    for file in files:
        text = file.read_text(encoding="utf-8")
        loc += sum(1 for line in text.splitlines() if line.strip())
        total_bytes += len(text.encode("utf-8"))
    return {
        "files": len(files),
        "loc_nonblank": loc,
        "bytes": total_bytes,
    }


def rust_module_text(case_name: str, module_index: int, helpers_per_module: int) -> str:
    lines = [f"// compile-bench touch marker: {case_name}:{module_index}:0", ""]
    for helper_index in range(helpers_per_module):
        lines.extend(
            [
                f"fn helper_{helper_index}(seed: i32) -> i32 {{",
                f"    let base = seed + {module_index + helper_index};",
                f"    let lane = [base, base + {helper_index + 1}, base + {helper_index + 2}];",
                f"    lane[1] + lane[2] + {helper_index + 3}",
                "}",
                "",
            ]
        )
    lines.extend(
        [
            "pub fn entry(seed: i32) -> i32 {",
            f"    let mut total = seed + {module_index};",
        ]
    )
    for helper_index in range(helpers_per_module):
        lines.append(f"    total += helper_{helper_index}(seed + {helper_index});")
    lines.extend(
        [
            "    total % 251",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def fzy_module_text(case_name: str, module_index: int, helpers_per_module: int) -> str:
    lines = [f"// compile-bench touch marker: {case_name}:{module_index}:0", ""]
    for helper_index in range(helpers_per_module):
        lines.extend(
            [
                f"fn helper_{helper_index}(seed: i32) -> i32 {{",
                f"    let base = seed + {module_index + helper_index};",
                f"    let lane = [base, base + {helper_index + 1}, base + {helper_index + 2}];",
                f"    return lane[1] + lane[2] + {helper_index + 3}",
                "}",
                "",
            ]
        )
    lines.extend(
        [
            "fn entry(seed: i32) -> i32 {",
            f"    let mut total = seed + {module_index};",
        ]
    )
    for helper_index in range(helpers_per_module):
        lines.append(f"    total += helper_{helper_index}(seed + {helper_index});")
    lines.extend(
        [
            "    return total % 251",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def rust_main_text(module_count: int) -> str:
    lines = [f"mod module_{index:03d};" for index in range(module_count)]
    lines.extend(
        [
            "",
            "fn main() {",
            "    let mut checksum: i32 = 0;",
        ]
    )
    for index in range(module_count):
        lines.append(f"    checksum += module_{index:03d}::entry({index + 1});")
    lines.extend(
        [
            "    checksum %= 251;",
            '    println!("checksum={checksum}");',
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def fzy_main_text(module_count: int) -> str:
    lines = [f"mod module_{index:03d};" for index in range(module_count)]
    lines.extend(
        [
            "",
            "fn main() -> i32 {",
            "    let mut checksum: i32 = 0",
        ]
    )
    for index in range(module_count):
        lines.append(f"    checksum += module_{index:03d}.entry({index + 1});")
    lines.extend(
        [
            "    return checksum % 251",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_case_files(case):
    case_root = GENERATED_ROOT / case["name"]
    rust_root = case_root / "rust"
    fzy_root = case_root / "fzy"

    if case_root.exists():
        shutil.rmtree(case_root)
    rust_src = rust_root / "src"
    fzy_src = fzy_root / "src"
    rust_src.mkdir(parents=True, exist_ok=True)
    fzy_src.mkdir(parents=True, exist_ok=True)

    rust_manifest = "\n".join(
        [
            "[package]",
            f'name = "compile_bench_{case["name"]}_rust"',
            'version = "0.1.0"',
            'edition = "2021"',
            "",
            "[workspace]",
            "",
            "[profile.dev]",
            'incremental = true',
            "",
            "[profile.release]",
            'incremental = false',
            "",
        ]
    )
    (rust_root / "Cargo.toml").write_text(rust_manifest + "\n", encoding="utf-8")
    (rust_src / "main.rs").write_text(rust_main_text(case["module_count"]) + "\n", encoding="utf-8")

    fzy_manifest = "\n".join(
        [
            "[package]",
            f'name = "compile_bench_{case["name"]}_fzy"',
            'version = "0.1.0"',
            "",
            "[[target.bin]]",
            f'name = "compile_bench_{case["name"]}_fzy"',
            'path = "src/main.fzy"',
            "",
            "[unsafe]",
            'contracts = "compiler"',
            "enforce_dev = false",
            "enforce_verify = true",
            "enforce_release = true",
            "",
        ]
    )
    (fzy_root / "fozzy.toml").write_text(fzy_manifest + "\n", encoding="utf-8")
    (fzy_src / "main.fzy").write_text(fzy_main_text(case["module_count"]) + "\n", encoding="utf-8")

    for index in range(case["module_count"]):
        module_name = f"module_{index:03d}"
        (rust_src / f"{module_name}.rs").write_text(
            rust_module_text(case["name"], index, case["helpers_per_module"]) + "\n",
            encoding="utf-8",
        )
        (fzy_src / f"{module_name}.fzy").write_text(
            fzy_module_text(case["name"], index, case["helpers_per_module"]) + "\n",
            encoding="utf-8",
        )

    run(["cargo", "generate-lockfile", "--offline"], cwd=rust_root)

    return {
        "name": case["name"],
        "case_root": case_root,
        "rust_root": rust_root,
        "fzy_root": fzy_root,
        "rust_leaf": rust_src / f"module_{case['module_count'] - 1:03d}.rs",
        "fzy_leaf": fzy_src / f"module_{case['module_count'] - 1:03d}.fzy",
        "module_count": case["module_count"],
        "helpers_per_module": case["helpers_per_module"],
        "total_functions": case["module_count"] * (case["helpers_per_module"] + 1) + 1,
        "rust_metrics": count_source_metrics(rust_root / "src", ".rs"),
        "fzy_metrics": count_source_metrics(fzy_root / "src", ".fzy"),
    }


def generate_cases():
    GENERATED_ROOT.mkdir(parents=True, exist_ok=True)
    return [write_case_files(case) for case in CASES]


def rust_build_cmd(case_info, profile):
    cmd = [
        "cargo",
        "build",
        "--quiet",
        "--offline",
        "--manifest-path",
        str(case_info["rust_root"] / "Cargo.toml"),
        "--target-dir",
        str(case_info["rust_root"] / "target"),
    ]
    cmd.extend(profile["rust_args"])
    return cmd


def fzy_build_cmd(case_info, profile, fz_bin: pathlib.Path):
    cmd = [str(fz_bin), "build", str(case_info["fzy_root"]), "--backend", "llvm", "--json"]
    cmd.extend(profile["fzy_args"])
    return cmd


def clean_rust(case_info):
    shutil.rmtree(case_info["rust_root"] / "target", ignore_errors=True)


def clean_fzy(case_info):
    shutil.rmtree(case_info["fzy_root"] / ".fz", ignore_errors=True)


def parse_rust_checksum(stdout: str) -> int:
    return int(stdout.strip().splitlines()[-1].split("checksum=")[-1])


def parse_fzy_build_output(stdout: str):
    text = stdout.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(text.splitlines()[-1])


def rust_binary_path(case_info, profile):
    profile_dir = "release" if profile["name"] == "release" else "debug"
    crate_name = f"compile_bench_{case_info['name']}_rust"
    candidates = [
        case_info["rust_root"] / "target" / profile_dir / crate_name,
        case_info["rust_root"] / "target" / "aarch64-apple-darwin" / profile_dir / crate_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def verify_case_checksum(case_info, fz_bin: pathlib.Path):
    clean_rust(case_info)
    clean_fzy(case_info)

    rust_proc = run(rust_build_cmd(case_info, PROFILES[0]))
    del rust_proc
    rust_bin = rust_binary_path(case_info, PROFILES[0])
    rust_checksum = parse_rust_checksum(run([str(rust_bin)], cwd=case_info["rust_root"]).stdout)

    fzy_build = run(fzy_build_cmd(case_info, PROFILES[0], fz_bin), cwd=case_info["fzy_root"])
    fzy_payload = parse_fzy_build_output(fzy_build.stdout)
    fzy_bin = pathlib.Path(fzy_payload["output"])
    if not fzy_bin.is_absolute():
        fzy_bin = case_info["fzy_root"] / fzy_bin
    fzy_run = subprocess.run([str(fzy_bin)], cwd=case_info["fzy_root"], capture_output=True, text=True)
    if fzy_run.returncode != rust_checksum:
        raise RuntimeError(
            f"checksum mismatch for {case_info['name']}: rust={rust_checksum} fzy_exit={fzy_run.returncode}"
        )
    return rust_checksum


def update_touch_marker(path: pathlib.Path, value: int):
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError(f"cannot update touch marker in empty file {path}")
    prefix = "// compile-bench touch marker:"
    if not lines[0].startswith(prefix):
        raise RuntimeError(f"missing touch marker in {path}")
    stem = lines[0].rsplit(":", 1)[0]
    lines[0] = f"{stem}:{value}"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def prepare_mode_state(case_info, profile, fz_bin, mode_name):
    clean_rust(case_info)
    clean_fzy(case_info)
    if mode_name == "cold_full":
        return
    run(rust_build_cmd(case_info, profile), cwd=case_info["rust_root"])
    run(fzy_build_cmd(case_info, profile, fz_bin), cwd=case_info["fzy_root"])


def measure_one(case_info, profile, fz_bin, mode_name, language, touch_counter):
    if language == "rust":
        if mode_name == "cold_full":
            clean_rust(case_info)
        elif mode_name == "warm_leaf_change":
            update_touch_marker(case_info["rust_leaf"], touch_counter)
        elapsed_ms, _ = timed_run(rust_build_cmd(case_info, profile), cwd=case_info["rust_root"])
        return elapsed_ms

    if mode_name == "cold_full":
        clean_fzy(case_info)
    elif mode_name == "warm_leaf_change":
        update_touch_marker(case_info["fzy_leaf"], touch_counter)
    elapsed_ms, _ = timed_run(fzy_build_cmd(case_info, profile, fz_bin), cwd=case_info["fzy_root"])
    return elapsed_ms


def benchmark_case(case_info, profile, mode, fz_bin, runs, bootstrap_samples, seed):
    prepare_mode_state(case_info, profile, fz_bin, mode["name"])
    rust_times = []
    fzy_times = []
    rust_touch = 1
    fzy_touch = 1

    for run_index in range(runs):
        order = ("rust", "fzy") if run_index % 2 == 0 else ("fzy", "rust")
        for language in order:
            if language == "rust":
                rust_times.append(
                    measure_one(case_info, profile, fz_bin, mode["name"], language, rust_touch)
                )
                rust_touch += 1
            else:
                fzy_times.append(
                    measure_one(case_info, profile, fz_bin, mode["name"], language, fzy_touch)
                )
                fzy_touch += 1

    rust_stats = stats(rust_times)
    fzy_stats = stats(fzy_times)
    ratio = fzy_stats["mean_ms"] / rust_stats["mean_ms"]
    ratio_ci = bootstrap_ratio_ci(
        fzy_times,
        rust_times,
        samples=bootstrap_samples,
        seed=seed,
    )
    return {
        "case": case_info["name"],
        "profile": profile["name"],
        "mode": mode["name"],
        "mode_description": mode["description"],
        "module_count": case_info["module_count"],
        "helpers_per_module": case_info["helpers_per_module"],
        "total_functions": case_info["total_functions"],
        "rust": rust_stats,
        "fzy": fzy_stats,
        "ratio_fzy_over_rust": ratio,
        "ratio_ci95_bootstrap": ratio_ci,
        "classification": "fzy_wins" if ratio < 1.0 else "rust_wins",
        "source_metrics": {
            "rust": case_info["rust_metrics"],
            "fzy": case_info["fzy_metrics"],
        },
    }


def build_case_summary(case_info, checksum):
    return {
        "case": case_info["name"],
        "module_count": case_info["module_count"],
        "helpers_per_module": case_info["helpers_per_module"],
        "total_functions": case_info["total_functions"],
        "checksum_mod_251": checksum,
        "source_metrics": {
            "rust": case_info["rust_metrics"],
            "fzy": case_info["fzy_metrics"],
        },
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark compile times for matched Rust vs Fzy projects")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--bootstrap-samples", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=20260320)
    parser.add_argument(
        "--out-prefix",
        default="bench_compile_times_rust_vs_fzy",
        help="Artifact prefix written into artifacts/<prefix>.json|.md",
    )
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Generate matched benchmark projects and print the matrix without timing builds",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    fz_bin = ensure_fz_bin()
    cases = generate_cases()

    matrix = {
        "generatedRoot": str(GENERATED_ROOT),
        "cases": [],
    }
    checksums = {}
    for case_info in cases:
        checksum = verify_case_checksum(case_info, fz_bin)
        checksums[case_info["name"]] = checksum
        matrix["cases"].append(build_case_summary(case_info, checksum))

    if args.generate_only:
        print(json.dumps(matrix, indent=2))
        return

    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    rustc_version = run(["rustc", "--version"]).stdout.strip()
    cargo_version = run(["cargo", "--version"]).stdout.strip()
    uname = run(["uname", "-a"]).stdout.strip()

    suite_results = []
    for case_index, case_info in enumerate(cases):
        for profile_index, profile in enumerate(PROFILES):
            for mode_index, mode in enumerate(MODES):
                bench_seed = (
                    args.seed
                    + case_index * 1009
                    + profile_index * 131
                    + mode_index * 17
                )
                suite_results.append(
                    benchmark_case(
                        case_info,
                        profile,
                        mode,
                        fz_bin,
                        runs=args.runs,
                        bootstrap_samples=args.bootstrap_samples,
                        seed=bench_seed,
                    )
                )

    wins = {"fzy_wins": 0, "rust_wins": 0}
    for result in suite_results:
        wins[result["classification"]] += 1

    payload = {
        "suite": "compile-times-rust-vs-fzy-project-matrix",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "runs": args.runs,
        "bootstrap_samples": args.bootstrap_samples,
        "seed": args.seed,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "rustc": rustc_version,
            "cargo": cargo_version,
            "fz": str(fz_bin),
            "uname": uname,
        },
        "matrix": matrix,
        "results": suite_results,
        "summary": {
            "classification_counts": wins,
            "geomean_ratio_fzy_over_rust": math.prod(
                entry["ratio_fzy_over_rust"] for entry in suite_results
            )
            ** (1.0 / len(suite_results)),
            "mean_ratio_fzy_over_rust": statistics.fmean(
                entry["ratio_fzy_over_rust"] for entry in suite_results
            ),
        },
    }

    json_path = ARTIFACTS / f"{args.out_prefix}.json"
    md_path = ARTIFACTS / f"{args.out_prefix}.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Compile-Time Benchmarks (Rust vs Fzy)",
        "",
        "Independent project compile-time suite using generated matched project trees.",
        "",
        f"- Commit: `{commit}`",
        f"- Timestamp (UTC): {payload['timestamp_utc']}",
        f"- Runs per case/mode/profile: {args.runs}",
        f"- Bootstrap samples: {args.bootstrap_samples}",
        f"- Seed: {args.seed}",
        f"- rustc: `{rustc_version}`",
        f"- cargo: `{cargo_version}`",
        f"- fz binary: `{fz_bin}`",
        f"- Host: `{uname}`",
        "",
        "## Matrix",
        "",
        "| Case | Modules | Helpers/module | Total functions | Rust files | Rust LOC | Fzy files | Fzy LOC | Checksum mod 251 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case_summary in matrix["cases"]:
        rust_metrics = case_summary["source_metrics"]["rust"]
        fzy_metrics = case_summary["source_metrics"]["fzy"]
        lines.append(
            f"| {case_summary['case']} | {case_summary['module_count']} | "
            f"{case_summary['helpers_per_module']} | {case_summary['total_functions']} | "
            f"{rust_metrics['files']} | {rust_metrics['loc_nonblank']} | "
            f"{fzy_metrics['files']} | {fzy_metrics['loc_nonblank']} | "
            f"{case_summary['checksum_mod_251']} |"
        )

    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Case | Profile | Mode | Rust mean ms | Fzy mean ms | Ratio (fzy/rust) | 95% CI ratio | Verdict |",
            "|---|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for result in suite_results:
        ci = result["ratio_ci95_bootstrap"]
        lines.append(
            f"| {result['case']} | {result['profile']} | {result['mode']} | "
            f"{result['rust']['mean_ms']:.3f} | {result['fzy']['mean_ms']:.3f} | "
            f"{result['ratio_fzy_over_rust']:.3f}x | [{ci['p025']:.3f}, {ci['p975']:.3f}] | "
            f"{result['classification']} |"
        )

    lines.extend(
        [
            "",
            "## Suite Summary",
            "",
            f"- Fzy wins (ratio < 1.0): {wins['fzy_wins']}",
            f"- Rust wins (ratio >= 1.0): {wins['rust_wins']}",
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
