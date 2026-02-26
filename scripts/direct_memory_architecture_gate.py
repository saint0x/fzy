#!/usr/bin/env python3
from __future__ import annotations

import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "crates" / "driver" / "src" / "pipeline.rs"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> int:
    src = read_text(PIPELINE)
    errors: list[str] = []

    legacy_array_symbols = [
        "__native.array_new",
        "__native.array_push",
        "__native.array_get",
    ]
    for symbol in legacy_array_symbols:
        if symbol in src:
            errors.append(f"legacy array data-plane symbol reintroduced: `{symbol}`")

    legacy_runtime_import_prefixes = ['callee: "str.', 'callee: "list.', 'callee: "map.']
    for marker in legacy_runtime_import_prefixes:
        if marker in src:
            errors.append(
                f"legacy data-plane runtime import reintroduced in native import table: `{marker}`"
            )

    legacy_shim_exports = (
        r"^int32_t fz_native_str_",
        r"^int32_t fz_native_list_",
        r"^int32_t fz_native_map_",
    )
    for pattern in legacy_shim_exports:
        if re.search(pattern, src, flags=re.MULTILINE):
            errors.append(
                f"legacy shim-exported data-plane symbol reintroduced in runtime shim: `{pattern}`"
            )

    if "build_control_flow_cfg(&function.body)" in src:
        errors.append(
            "backend lowering drift: found CFG build callsite without shared variant-tag map"
        )

    if "ControlFlowBuilder::new(variant_tags.clone()).finish(body)" not in src:
        errors.append("canonical CFG pipeline missing shared variant-tag entrypoint")

    if "variant_tag_for_key(" not in src:
        errors.append("canonical discriminant mapping helper missing")

    required_canonical_plan_markers = [
        "fn build_native_canonical_plan(",
        "let plan = build_native_canonical_plan(fir, enforce_contract_checks);",
        "let plan = build_native_canonical_plan(fir, true);",
    ]
    for marker in required_canonical_plan_markers:
        if marker not in src:
            errors.append(
                f"canonical native plan wiring missing required marker: `{marker}`"
            )

    if (
        "array/index expressions" in src
        and "detected parser-recognized expressions without full lowering parity" in src
    ):
        errors.append(
            "array/index semantic exception drift: partial-native rejection diagnostic reappeared"
        )

    if errors:
        print("direct-memory architecture gate failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 2

    print("direct-memory architecture gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
