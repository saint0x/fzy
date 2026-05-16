#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bench_compile_times_rust_vs_fzy as suite


def main():
    fz_bin = suite.ensure_fz_bin()
    cases = suite.generate_cases()
    verified = []
    for case_info in cases:
        checksum = suite.verify_case_checksum(case_info, fz_bin)
        rust_metrics = case_info["rust_metrics"]
        fzy_metrics = case_info["fzy_metrics"]
        if rust_metrics["files"] != fzy_metrics["files"]:
            raise RuntimeError(
                f"file-count mismatch for {case_info['name']}: rust={rust_metrics['files']} fzy={fzy_metrics['files']}"
            )
        verified.append(
            {
                "case": case_info["name"],
                "checksum_mod_251": checksum,
                "rust_files": rust_metrics["files"],
                "fzy_files": fzy_metrics["files"],
            }
        )

    out_path = ROOT / "artifacts" / "compile_bench_matrix_verify.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"verified": verified}, indent=2) + "\n", encoding="utf-8")
    print("compile-bench-matrix-ok")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
