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

    if (
        "ControlFlowBuilder::new(variant_tags.clone(), passthrough_functions.clone()).finish(body)"
        not in src
    ):
        errors.append("canonical CFG pipeline missing shared variant-tag entrypoint")

    if "variant_tag_for_key(" not in src:
        errors.append("canonical discriminant mapping helper missing")

    required_canonical_plan_markers = [
        "fn build_native_canonical_plan(",
        "let plan = build_native_canonical_plan(fir, enforce_contract_checks);",
        "let plan = build_native_canonical_plan(fir, true);",
        "data_ops_by_function: HashMap<String, Vec<NativeDataOp>>",
        "fn collect_native_data_ops_for_function(",
        "render_native_data_op(",
        "fn collect_native_string_literals(",
        "fn collect_folded_temp_string_literals(",
    ]
    for marker in required_canonical_plan_markers:
        if marker not in src:
            errors.append(
                f"canonical native plan wiring missing required marker: `{marker}`"
            )

    cfg_builder_calls = src.count("build_control_flow_cfg(")
    if cfg_builder_calls < 2:
        errors.append(
            "canonical cfg construction drift: expected canonical plan builder to construct CFGs, "
            f"found only {cfg_builder_calls} `build_control_flow_cfg(` occurrences"
        )

    cfg_verify_calls = src.count("verify_control_flow_cfg(&cfg)?;")
    if cfg_verify_calls != 1:
        errors.append(
            "canonical cfg verification drift: expected exactly 1 shared verification call in canonical-plan builder, "
            f"found {cfg_verify_calls}"
        )

    required_fail_fast_markers = [
        "fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> Result<String>",
        "fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String>",
        "fn lower_cranelift_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String>",
        "canonical cfg unavailable for `{}`: missing entry",
        "llvm backend failed lowering canonical cfg for `{}`:",
    ]
    for marker in required_fail_fast_markers:
        if marker not in src:
            errors.append(f"native fail-fast contract marker missing: `{marker}`")

    fallback_markers = (
        "; cfg lowering failed:",
        "; cfg-error:",
    )
    for marker in fallback_markers:
        if marker in src:
            errors.append(
                f"silent fallback lowering marker reintroduced (must hard-fail): `{marker}`"
            )

    if (
        "array/index expressions" in src
        and "detected parser-recognized expressions without full lowering parity" in src
    ):
        errors.append(
            "array/index semantic exception drift: partial-native rejection diagnostic reappeared"
        )

    forbidden_data_plane_aliases = (
        'callee: "list.',
        'callee: "map.',
    )
    for marker in forbidden_data_plane_aliases:
        if marker in src:
            errors.append(
                f"non-text data-plane import alias remains in native import table: `{marker}`"
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
