#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "language-primitive-baseline-v1.md"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_matrix(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    row_re = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(implemented|partial|missing)\s*\|")
    for line in read_text(path).splitlines():
        match = row_re.match(line.strip())
        if match:
            rows[match.group(1)] = match.group(2)
    return rows


def main() -> int:
    matrix = load_matrix(DOC)
    parser_src = read_text(ROOT / "crates" / "parser" / "src" / "lib.rs")
    ast_src = read_text(ROOT / "crates" / "ast" / "src" / "lib.rs")
    hir_src = read_text(ROOT / "crates" / "hir" / "src" / "lib.rs")

    expected_status = {
        "function_type_surface": "implemented"
        if "Type::Function {" in ast_src
        and "if self.consume(&TokenKind::KwFn)" in parser_src
        else "missing",
        "typed_function_references": "implemented"
        if "fn function_ref_type(" in hir_src and "Type::Function {" in hir_src
        else "missing",
        "higher_order_callability_checks": "implemented"
        if "is not callable (found" in hir_src
        else "missing",
        "unsupported_use_alias_diag": "implemented"
        if "import aliases are not supported" in parser_src
        else "missing",
        "unsupported_use_wildcard_diag": "implemented"
        if "wildcard imports are not supported" in parser_src
        else "missing",
        "unsupported_use_group_diag": "implemented"
        if "grouped imports are not supported" in parser_src
        else "missing",
        "unsupported_pub_use_reexport_diag": "implemented"
        if "`pub use` re-exports are not supported yet" in parser_src
        else "missing",
        "expanded_item_visibility_struct_enum_trait_impl": "implemented"
        if "pub is_pub: bool" in ast_src
        else "missing",
    }

    errors: list[str] = []
    for key, expected in expected_status.items():
        documented = matrix.get(key)
        if documented is None:
            errors.append(f"matrix is missing primitive row `{key}`")
            continue
        if documented != expected:
            errors.append(
                f"primitive `{key}` drifted: doc={documented} implementation={expected}"
            )

    if errors:
        print("language primitive drift gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    print(f"language primitive drift gate passed ({len(expected_status)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
