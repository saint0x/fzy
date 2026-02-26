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
    pipeline_src = read_text(ROOT / "crates" / "driver" / "src" / "pipeline.rs")

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
    has_closure = (
        "Expr::Closure" in ast_src
        and "fn parse_lambda_expr(" in parser_src
        and "Value::Closure" in hir_src
    )
    has_native_closure_lowering = (
        "LlvmClosureBinding" in pipeline_src
        and "ClifClosureBinding" in pipeline_src
        and "llvm_emit_inlined_closure_call" in pipeline_src
        and "clif_emit_inlined_closure_call" in pipeline_src
    )
    has_native_closure_non_let_diag = (
        "native backend only supports closures bound directly in `let` statements"
        in pipeline_src
    )
    has_native_let_variant_literal_diag = (
        "supports `let` variant payload binding only when the initializer is the same literal enum variant"
        in pipeline_src
    )
    has_native_match_variant_literal_guardrail = (
        "only supports match-arm variant payload bindings for literal enum scrutinees without guards"
        in pipeline_src
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
        "static_mut_surface": "implemented"
        if "let mutable = self.consume(&TokenKind::Ident(\"mut\".to_string()));" in parser_src
        and "pub mutable: bool," in ast_src
        else "missing",
        "closure_lambda_values": "implemented" if has_closure else "missing",
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

    if matrix.get("closure_lambda_values") == "implemented":
        if not has_native_closure_lowering:
            errors.append(
                "closure native lowering drift: docs mark implemented but native lowering hooks are missing"
            )
        if not has_native_closure_non_let_diag:
            errors.append(
                "closure diagnostic drift: docs mention explicit unsupported closure placements but diagnostic is missing"
            )

    if matrix.get("let_pattern_destructuring") == "partial":
        if not has_native_let_variant_literal_diag:
            errors.append(
                "let-pattern partial drift: expected literal-source diagnostic for unsupported native payload binding"
            )
        if not has_native_match_variant_literal_guardrail:
            errors.append(
                "match-pattern partial drift: expected guarded/literal-scrutinee diagnostic for unsupported native payload binding shapes"
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
