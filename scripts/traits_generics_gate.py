#!/usr/bin/env python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PARSER = ROOT / "crates/parser/src/lib.rs"
HIR = ROOT / "crates/hir/src/lib.rs"
DOC = ROOT / "docs/traits-generics-contract-v1.md"

missing = []

if not DOC.exists():
    missing.append("missing docs/traits-generics-contract-v1.md")
else:
    doc = DOC.read_text(encoding="utf-8")
    for marker in [
        "Traits + Generics Contract v1",
        "Trait Coherence Rules (v1)",
        "Trait Associated Items (v1)",
        "Trait Method Restrictions (v1)",
        "Generic Declaration Surface (v1)",
        "Generic Bound Rules (v1)",
        "Unsupported in v1 (Hard Rejected)",
        "Inference and Specialization Policy (v1)",
        "Monomorphization Controls (v1)",
        "Macro Status (Current)",
    ]:
        if marker not in doc:
            missing.append(f"contract doc missing marker: {marker}")

parser_src = PARSER.read_text(encoding="utf-8")
for marker in [
    "expected associated const name",
    "expected associated type name",
    "trait default method bodies are not supported in v1",
    "expected trait method name",
    "parses_generic_item_headers",
    "parses_trait_and_impl_associated_items",
]:
    if marker not in parser_src:
        missing.append(f"parser missing production trait/generic marker: {marker}")

hir_src = HIR.read_text(encoding="utf-8")
for marker in [
    "resolve_method_call_target",
    "overlapping impls for trait",
    "has ambiguous bound",
    "validate_generic_bounds_exist",
    "trait `{}` is not defined",
    "invalid generic specialization syntax for call",
    "monomorphization depth limit exceeded",
    "monomorphization specialization limit exceeded",
    "impl method `{}` in trait `{}` must not declare generic parameters in v1",
    "missing associated type",
    "missing associated const",
    "allows_generic_trait_impl_targets",
]:
    if marker not in hir_src:
        missing.append(f"hir missing enforcement hook: {marker}")

if missing:
    for item in missing:
        print(item)
    sys.exit(2)

print("traits_generics_gate: ok")
