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
        "Unsupported in v1 (Hard Rejected)",
        "Inference and Specialization Policy (v1)",
        "Monomorphization Controls (v1)",
        "Macro Status (Current)",
    ]:
        if marker not in doc:
            missing.append(f"contract doc missing marker: {marker}")

parser_src = PARSER.read_text(encoding="utf-8")
for marker in [
    "generic struct declarations are not supported in v1",
    "generic enum declarations are not supported in v1",
    "generic trait declarations are not supported in v1",
    "generic impl headers are not supported in v1",
    "trait associated constants are not supported in v1",
    "trait associated types are not supported in v1",
    "trait default method bodies are not supported in v1",
    "generic trait methods are not supported in v1",
]:
    if marker not in parser_src:
        missing.append(f"parser missing hard-reject diagnostic: {marker}")

hir_src = HIR.read_text(encoding="utf-8")
for marker in [
    "resolve_method_call_target",
    "impl for trait `{}` must target a concrete type in v1",
    "overlapping impls for trait",
    "has ambiguous bound",
    "validate_generic_bounds_exist",
    "trait `{}` is not defined",
    "invalid generic specialization syntax for call",
    "monomorphization depth limit exceeded",
    "monomorphization specialization limit exceeded",
]:
    if marker not in hir_src:
        missing.append(f"hir missing enforcement hook: {marker}")

if missing:
    for item in missing:
        print(item)
    sys.exit(2)

print("traits_generics_gate: ok")
