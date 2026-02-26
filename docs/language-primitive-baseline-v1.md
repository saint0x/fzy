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
| `expanded_item_visibility_struct_enum_trait_impl` | implemented | `pub` visibility now applies to `struct`/`enum`/`trait`/`impl` items in AST/parser. |
| `closure_lambda_values` | missing | Closure/lambda capture syntax is not yet shipped in v1. |
| `module_import_alias_reexport_wildcard_support` | implemented | Ergonomic alias/re-export/wildcard forms are supported in parser/module import metadata. |
