#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "language-primitive-baseline-v1.md"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_tree(root: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.rs"))
        if path.is_file()
    )


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
    parser_src = read_tree(ROOT / "crates" / "parser" / "src")
    ast_src = read_tree(ROOT / "crates" / "ast" / "src")
    hir_src = read_tree(ROOT / "crates" / "hir" / "src")
    pipeline_src = read_tree(ROOT / "crates" / "driver" / "src" / "pipeline")

    has_use_alias = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume_ident(\"as\")" in parser_src
    )
    has_use_wildcard = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume(&TokenKind::Star)" in parser_src
    )
    has_use_group = (
        "fn parse_use_tree(" in parser_src
        and "if self.consume(&TokenKind::LBrace)" in parser_src
    )
    has_pub_use = "import.is_pub = true;" in parser_src
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
    has_array_index_surface = (
        "Expr::ArrayLiteral" in ast_src
        and "Expr::Index {" in ast_src
        and "Expr::ArrayLiteral(items)" in parser_src
        and "expr = Expr::Index {" in parser_src
        and "Expr::ArrayLiteral(items)" in hir_src
        and "Expr::Index { base, index }" in hir_src
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
        or "native backend only supports closures bound to local names via `let`/assignment"
        in pipeline_src
    )
    has_struct_pattern_surface = "Pattern::Struct" in ast_src and "struct pattern" in parser_src
    has_typed_local_aggregate_metadata = (
        "pub local_types: BTreeMap<String, Type>" in hir_src
        and "local_types: BTreeMap<String, ast::Type>" in pipeline_src
    )
    has_native_aggregate_handle_lowering = (
        "fz_native_agg_new" in pipeline_src
        and "fz_native_agg_get_i64" in pipeline_src
        and "fz_native_agg_tag" in pipeline_src
    )
    has_cross_backend_parameter_aggregate_parity = (
        "cross_backend_parameter_aggregate_destructuring_executes_consistently"
        in pipeline_src
    )
    has_native_array_index_lowering = (
        (
            "array_slots: HashMap<String, Vec<String>>" in pipeline_src
            or "array_slots: HashMap<String, LlvmArrayBinding>" in pipeline_src
        )
        and (
            "array_bindings: HashMap<String, Vec<LocalBinding>>" in pipeline_src
            or "array_bindings: HashMap<String, ClifArrayBinding>" in pipeline_src
        )
        and "__native.array_get" not in pipeline_src
    )
    has_native_array_index_partial_reject = "array/index expressions" in pipeline_src
    has_cross_backend_native_completeness_parity = (
        "cross_backend_native_completeness_fixture_execute_consistently" in pipeline_src
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
        and "let mutable = self.consume_ident(\"mut\");" in parser_src
        else "missing",
        "let_pattern_destructuring": "implemented" if has_let_pattern else "missing",
        "const_declaration_surface": "implemented"
        if "fn parse_const(" in parser_src and "ast::Item::Const" in parser_src
        else "missing",
        "static_declaration_surface": "implemented"
        if "fn parse_static(" in parser_src and "ast::Item::Static" in parser_src
        else "missing",
        "static_mut_surface": "implemented"
        if "let mutable = self.consume_ident(\"mut\");" in parser_src
        and "pub mutable: bool," in ast_src
        else "missing",
        "closure_lambda_values": "implemented" if has_closure else "missing",
        "array_index_expression_family": "implemented" if has_array_index_surface else "missing",
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

    if matrix.get("array_index_expression_family") == "implemented":
        if not has_native_array_index_lowering:
            errors.append(
                "array/index native lowering drift: docs mark implemented but native integer-array lowering hooks are missing"
            )
        if has_native_array_index_partial_reject:
            errors.append(
                "array/index partial drift: docs mark implemented but native partial-expression rejection still includes array/index"
            )
        if not has_cross_backend_native_completeness_parity:
            errors.append(
                "array/index parity drift: docs mark implemented but cross-backend completeness fixture parity test is missing"
            )

    if matrix.get("let_pattern_destructuring") == "implemented":
        if not has_struct_pattern_surface:
            errors.append(
                "let-pattern implementation drift: expected first-class struct-pattern surface in parser/AST"
            )
        if not has_typed_local_aggregate_metadata:
            errors.append(
                "let-pattern implementation drift: expected typed local aggregate metadata to persist through HIR/native lowering"
            )
        if not has_native_aggregate_handle_lowering:
            errors.append(
                "let-pattern implementation drift: expected first-class native aggregate handle lowering hooks"
            )
        if not has_cross_backend_parameter_aggregate_parity:
            errors.append(
                "let-pattern implementation drift: expected cross-backend parameter aggregate destructuring parity coverage"
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
