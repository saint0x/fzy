#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH_JSON = ROOT / "artifacts" / "bench_corelibs_rust_vs_fzy.json"

KERNEL_THRESHOLDS = {
    "bytes_kernel": 1.40,
    "resultx_classify": 1.30,
    "text_kernel": 1.25,
}

NEAR_PARITY_KERNELS = {
    "capability_parse": 1.15,
    "task_retry_backoff": 1.15,
    "arithmetic_kernel": 1.15,
    "duration_kernel": 1.15,
    "abi_pair_kernel": 1.15,
    "http_kernel": 1.20,
    "network_kernel": 1.20,
    "concurrency_kernel": 1.20,
    "process_kernel": 1.20,
    "security_kernel": 1.20,
}


def main() -> int:
    if not BENCH_JSON.exists():
        print(
            f"direct-memory perf gate failed: missing benchmark artifact `{BENCH_JSON}`",
            file=sys.stderr,
        )
        return 2

    payload = json.loads(BENCH_JSON.read_text(encoding="utf-8"))
    benches = {entry["bench"]: float(entry["ratio_fzy_over_rust"]) for entry in payload["benches"]}

    errors: list[str] = []
    for bench, threshold in KERNEL_THRESHOLDS.items():
        ratio = benches.get(bench)
        if ratio is None:
            errors.append(f"missing benchmark `{bench}` in artifact")
            continue
        if ratio > threshold:
            errors.append(
                f"`{bench}` ratio regression: {ratio:.6f} > {threshold:.2f} (fzy slower than target)"
            )

    for bench, threshold in NEAR_PARITY_KERNELS.items():
        ratio = benches.get(bench)
        if ratio is None:
            errors.append(f"missing benchmark `{bench}` in artifact")
            continue
        if ratio > threshold:
            errors.append(
                f"`{bench}` parity regression: {ratio:.6f} > {threshold:.2f}"
            )

    if errors:
        print("direct-memory perf gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    print("direct-memory perf gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
