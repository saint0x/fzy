#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "bench_compile_times_rust_vs_fzy.json"

DEV_BUDGETS_MS = {
    "cold_full": 750.0,
    "warm_noop": 750.0,
    "warm_leaf_change": 750.0,
}


def main() -> int:
    if not ARTIFACT.exists():
        print(f"missing benchmark artifact `{ARTIFACT}`", file=sys.stderr)
        return 1
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    results = payload.get("results")
    if not isinstance(results, list):
        print("benchmark artifact missing `results` array", file=sys.stderr)
        return 1

    maxima = {}
    errors = []
    for mode, budget in DEV_BUDGETS_MS.items():
        samples = [
            entry["fzy"]["mean_ms"]
            for entry in results
            if entry.get("profile") == "dev" and entry.get("mode") == mode
        ]
        if not samples:
            errors.append(f"missing dev benchmark samples for mode `{mode}`")
            continue
        observed = max(samples)
        maxima[mode] = observed
        if observed > budget:
            errors.append(
                f"dev benchmark budget exceeded for `{mode}`: observed={observed:.3f}ms budget={budget:.3f}ms"
            )

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    out = {
        "ok": True,
        "budgetsMs": DEV_BUDGETS_MS,
        "observedMaxMeanMs": maxima,
    }
    out_path = ROOT / "artifacts" / "browser_incremental_budget_gate.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print("browser-incremental-budget-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
