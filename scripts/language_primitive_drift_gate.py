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

    has_use_alias = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume(&TokenKind::Ident(\"as\".to_string()))" in parser_src
    )
    has_use_wildcard = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume(&TokenKind::Star)" in parser_src
    )
    has_use_group = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume(&TokenKind::LBrace)" in parser_src
    )
    has_pub_use = "self.module.imports.push(format!(\"pub {import}\"))" in parser_src
    has_let_pattern = (
        "LetPattern" in ast_src
        and "let pattern = self.parse_pattern()?" in parser_src
        and "Stmt::LetPattern" in hir_src
    )

    expected_status = {
        "function_type_surface": "implemented"
        if "Type::Function {" in ast_src
        and "if self.consume(&TokenKind::KwFn)" in parser_src
        else "missing",
        "typed_function_references": "implemented"
        if "fn function_ref_type(" in hir_src
        and "Type::Function {" in hir_src
        and "Value::FnRef" in hir_src
        else "missing",
        "higher_order_callability_checks": "implemented"
        if "is not callable (found" in hir_src
        else "missing",
        "use_alias_support": "implemented" if has_use_alias else "missing",
        "use_wildcard_support": "implemented" if has_use_wildcard else "missing",
        "use_group_support": "implemented" if has_use_group else "missing",
        "pub_use_reexport_support": "implemented" if has_pub_use else "missing",
        "let_mutability_semantics": "implemented"
        if "assignment to immutable binding" in hir_src
        and "let mutable = self.consume(&TokenKind::Ident(\"mut\".to_string()));"
        in parser_src
        else "missing",
        "let_pattern_destructuring": "partial" if has_let_pattern else "missing",
        "const_declaration_surface": "implemented"
        if "fn parse_const(" in parser_src and "ast::Item::Const" in parser_src
        else "missing",
        "static_declaration_surface": "implemented"
        if "fn parse_static(" in parser_src and "ast::Item::Static" in parser_src
        else "missing",
        "static_mut_surface": "missing"
        if "`static mut` is not supported in v1" in parser_src
        else "implemented",
        "closure_lambda_values": "implemented"
        if "Expr::Closure" in ast_src and "parse_lambda" in parser_src
        else "missing",
        "expanded_item_visibility_struct_enum_trait_impl": "implemented"
        if "pub is_pub: bool" in ast_src
        and "self.parse_struct(true)" in parser_src
        and "self.parse_enum(true)" in parser_src
        and "self.parse_trait(true)" in parser_src
        and "self.parse_impl(true)" in parser_src
        else "missing",
        "module_import_alias_reexport_wildcard_support": "implemented"
        if has_use_alias and has_use_wildcard and has_use_group and has_pub_use
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
