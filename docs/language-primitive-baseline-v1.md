# Language Primitive Baseline v1

| Primitive Key | Status | Notes |
| --- | --- | --- |
| `function_type_surface` | implemented | `fn(...) -> ...` is parsed and represented in AST/HIR types. |
| `typed_function_references` | implemented | Function symbols resolve to typed function values instead of `i32` placeholders. |
| `higher_order_callability_checks` | implemented | Type checker enforces callable targets and argument compatibility for function values. |
| `unsupported_use_alias_diag` | implemented | `use path as alias` is rejected with explicit diagnostics. |
| `unsupported_use_wildcard_diag` | implemented | `use path::*` is rejected with explicit diagnostics. |
| `unsupported_use_group_diag` | implemented | `use path::{a,b}` is rejected with explicit diagnostics. |
| `unsupported_pub_use_reexport_diag` | implemented | `pub use` is rejected with explicit diagnostics and guidance. |
| `expanded_item_visibility_struct_enum_trait_impl` | implemented | `pub` visibility now applies to `struct`/`enum`/`trait`/`impl` items in AST/parser. |
| `closure_lambda_values` | missing | Closure/lambda capture syntax is not yet shipped in v1. |
| `module_import_alias_reexport_wildcard_support` | missing | Ergonomic alias/re-export/wildcard support remains intentionally unsupported. |
