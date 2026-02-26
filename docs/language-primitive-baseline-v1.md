# Language Primitive Baseline v1

| Primitive Key | Status | Notes |
| --- | --- | --- |
| `function_type_surface` | implemented | `fn(...) -> ...` is parsed and represented in AST/HIR types. |
| `typed_function_references` | implemented | Function symbols resolve to typed function values instead of `i32` placeholders. |
| `higher_order_callability_checks` | implemented | Type checker enforces callable targets and argument compatibility for function values. |
| `use_alias_support` | implemented | `use path as alias` is parsed and preserved for downstream stages. |
| `use_wildcard_support` | implemented | `use path::*` is parsed and preserved for downstream stages. |
| `use_group_support` | implemented | `use path::{a,b}` (including nested groups) expands into concrete imports. |
| `pub_use_reexport_support` | implemented | `pub use ...` parses as stable re-export/import metadata in module state. |
| `let_mutability_semantics` | implemented | `let` is immutable by default; reassignment requires `let mut` and type-check enforcement. |
| `let_pattern_destructuring` | partial | Variant-pattern destructuring in `let` lowers natively for literal variant initializers; `match` variant payload bindings lower for literal enum scrutinees without guards and are explicitly diagnosed otherwise. Struct-pattern destructuring now supports first-class `let`/`match` bindings for literal struct sources and hard-diagnoses unsupported non-literal native binding shapes; tuple-pattern parity remains open. |
| `const_declaration_surface` | implemented | Module-level `const NAME: Type = expr;` is parsed/typed and resolved in function scope. |
| `static_declaration_surface` | implemented | Module-level `static NAME: Type = expr;` is parsed/typed and resolved in function scope. |
| `static_mut_surface` | implemented | `static mut NAME: Type = const_expr;` parses/typed-checks and lowers through native backends as mutable global storage. |
| `expanded_item_visibility_struct_enum_trait_impl` | implemented | `pub` visibility now applies to `struct`/`enum`/`trait`/`impl` items in AST/parser. |
| `closure_lambda_values` | implemented | Typed lambda expressions with lexical capture are supported in parser/HIR/FIR/evaluator and lower natively for direct `let`-bound closure invocation; unsupported non-`let` closure placements fail with explicit native diagnostics. |
| `module_import_alias_reexport_wildcard_support` | implemented | Ergonomic alias/re-export/wildcard forms are supported in parser/module import metadata. |
