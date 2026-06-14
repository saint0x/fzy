#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{parse, parse_type_text};

    #[test]
    fn parses_if_while_and_calls() {
        let source = r#"
            use core.http;
            fn add(x: i32, y: i32) -> i32 { return x + y; }
            fn main() -> i32 {
                let v: i32 = add(1, 2);
                let i: i32 = 0;
                while i < 3 {
                    if v == 3 { return v; } else { return 9; }
                }
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert_eq!(module.capabilities, vec!["http".to_string()]);
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Function(f) if f.name == "main")));
    }

    #[test]
    fn reports_multiple_errors() {
        let source = r#"
            fn main( -> i32 {
                let = 3
                if { return 1; }
            }
        "#;
        let diagnostics = parse(source, "bad").expect_err("should fail");
        assert!(diagnostics.len() >= 2);
    }

    #[test]
    fn parses_traits_impls_and_struct_enum_exprs() {
        let source = r#"
            trait Printable {
                fn render(v: i32) -> i32;
            }
            struct Point { x: i32, y: i32 }
            enum Maybe { Some(i32), None }
            impl Printable for Point {
                fn render(v: i32) -> i32 { return v; }
            }
            fn id<T: Printable>(v: T) -> T { return v; }
            fn main() -> i32 {
                let p = Point { x: 7, y: 3 };
                let px = p.x;
                let m = Maybe::Some(px);
                discard id<Point>(p);
                match m {
                    Maybe::Some(v) => v,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Trait(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Impl(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Struct(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Enum(_))));
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::StructInit { .. },
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::FieldAccess { .. },
                ..
            }
        )));
    }

    #[test]
    fn rejects_unqualified_enum_variant_patterns() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let m = Maybe::Some(1);
                match m {
                    Some(v) => v,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|diag| {
            diag.message
                .contains("unqualified enum variant pattern is not supported")
        }));
    }

    #[test]
    fn rejects_qualified_enum_declaration_variants_with_fixit_message() {
        let source = r#"
            enum Msg {
                Msg::Ping,
                Msg::Pong,
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().all(|diag| {
            diag.message
                .contains("qualified enum declaration variant is not supported")
        }));
    }

    #[test]
    fn rejects_capitalized_bare_patterns() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    Value => Value,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|diag| {
            diag.message
                .contains("capitalized bare pattern is not supported")
        }));
    }

    #[test]
    fn allows_return_in_match_arm_expression() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return 1,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main should exist");
        let arm_returns = main_fn
            .body
            .iter()
            .find_map(|stmt| match stmt {
                ast::Stmt::Match { arms, .. } => {
                    Some(arms.iter().map(|arm| arm.returns).collect::<Vec<_>>())
                }
                _ => None,
            })
            .expect("match should exist");
        assert_eq!(arm_returns, vec![true, false]);
    }

    #[test]
    fn parses_reference_lifetime_annotations() {
        let source = r#"
            fn borrow(value: &'req str) -> &'req str {
                return value;
            }
        "#;
        let module = parse(source, "lifetimes").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "borrow" => Some(function),
                _ => None,
            })
            .expect("borrow function should exist");
        assert!(matches!(
            function.params[0].ty,
            ast::Type::Ref {
                lifetime: Some(_),
                ..
            }
        ));
        assert!(matches!(
            function.return_type,
            ast::Type::Ref {
                lifetime: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn rpc_can_be_used_as_module_name_and_call_path() {
        let source = r#"
            mod rpc;

            fn main() -> i32 {
                rpc.touch();
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert!(module.modules.iter().any(|decl| decl == "rpc"));
    }

    #[test]
    fn parses_rpc_declarations_with_named_and_positional_params() {
        let source = r#"
            rpc Ping(req: str, count: i32) -> str;
            rpc Pong(str, i32) -> i32;
        "#;
        let module = parse(source, "rpc").expect("parse should succeed");
        let mut rpc_functions = module
            .items
            .iter()
            .filter_map(|item| match item {
                ast::Item::Function(function)
                    if function.is_extern && function.abi.as_deref() == Some("rpc") =>
                {
                    Some(function)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        rpc_functions.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(rpc_functions.len(), 2);
        assert_eq!(rpc_functions[0].name, "Ping");
        assert_eq!(rpc_functions[0].params[0].name, "req");
        assert_eq!(rpc_functions[0].params[1].name, "count");
        assert_eq!(rpc_functions[0].return_type.to_string(), "str");
        assert_eq!(rpc_functions[1].name, "Pong");
        assert_eq!(rpc_functions[1].params[0].name, "arg0");
        assert_eq!(rpc_functions[1].params[1].name, "arg1");
        assert_eq!(rpc_functions[1].return_type.to_string(), "i32");
    }

    #[test]
    fn rpc_declaration_requires_method_name_and_open_paren() {
        let missing_name =
            parse("rpc (req: i32) -> i32;", "rpc").expect_err("missing rpc name should fail");
        assert!(missing_name
            .iter()
            .any(|diagnostic| diagnostic.message.contains("expected rpc method name")));

        let missing_paren =
            parse("rpc Ping req: i32) -> i32;", "rpc").expect_err("missing rpc lparen should fail");
        assert!(missing_paren.iter().any(|diagnostic| diagnostic
            .message
            .contains("expected `(` after rpc method name")));
    }

    #[test]
    fn escaped_json_string_round_trips_and_remains_lexically_inert() {
        let source = r#"
            fn main() -> i32 {
                let body: str = "{\"model\":\"claude-sonnet-4-6\",\"msg\":\"x:y\"}";
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        let ast::Stmt::Let { value, .. } = &main_fn.body[0] else {
            panic!("expected first statement to be let");
        };
        let ast::Expr::Str(value) = value else {
            panic!("expected string literal");
        };
        assert_eq!(value, "{\"model\":\"claude-sonnet-4-6\",\"msg\":\"x:y\"}");
    }

    #[test]
    fn string_literal_supports_hex_unicode_and_octal_escapes() {
        let source = r#"
            fn main() -> i32 {
                let ansi: str = "\x1b[31mred\u001b[0m\033";
                let scalar: str = "\u{1f642}";
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        let first = match &main_fn.body[0] {
            ast::Stmt::Let { value, .. } => value,
            _ => panic!("expected first statement to be let"),
        };
        let second = match &main_fn.body[1] {
            ast::Stmt::Let { value, .. } => value,
            _ => panic!("expected second statement to be let"),
        };
        let ast::Expr::Str(ansi) = first else {
            panic!("expected ansi string literal");
        };
        let ast::Expr::Str(scalar) = second else {
            panic!("expected scalar string literal");
        };
        assert_eq!(ansi, "\u{001b}[31mred\u{001b}[0m\u{001b}");
        assert_eq!(scalar, "\u{1f642}");
    }

    #[test]
    fn char_literal_supports_hex_unicode_and_octal_escapes() {
        let source = r#"
            fn main() -> i32 {
                let esc: char = '\x1b';
                let nul: char = '\000';
                let smile: char = '\u263a';
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        let chars = main_fn
            .body
            .iter()
            .filter_map(|stmt| match stmt {
                ast::Stmt::Let {
                    value: ast::Expr::Char(ch),
                    ..
                } => Some(*ch),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(chars, vec!['\u{001b}', '\0', '\u{263a}']);
    }

    #[test]
    fn invalid_hex_unicode_and_octal_escapes_report_actionable_errors() {
        let source = r#"
            fn main() -> i32 {
                let a = "\xzz";
                let b = "\u12";
                let c = "\u{110000}";
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics
            .iter()
            .any(|diag| diag.message.contains("invalid string hex escape")));
        assert!(diagnostics
            .iter()
            .any(|diag| diag.message.contains("invalid string unicode escape")));
        assert!(diagnostics.iter().any(|diag| diag
            .message
            .contains("string unicode escape is out of range")));
    }

    #[test]
    fn reports_unterminated_string_literal_with_span() {
        let source = "fn main() -> i32 { let body: str = \"abc; return 0; }";
        let diagnostics = parse(source, "main").expect_err("should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unterminated string literal") && d.span.is_some()));
    }

    #[test]
    fn parses_async_function_and_await_expression() {
        let source = r#"
            async fn worker() -> i32 { return 7; }
            async fn main() -> i32 {
                let v = await worker();
                return v;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.is_async);
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Await(_),
                ..
            }
        )));
    }

    #[test]
    fn parses_ffi_panic_attribute_on_function() {
        let source = r#"
            #[ffi_panic(abort)]
            pubext c fn add(left: i32, right: i32) -> i32;
        "#;
        let module = parse(source, "ffi").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "add" => Some(function),
                _ => None,
            })
            .expect("ffi function should exist");
        assert_eq!(function.ffi_panic.as_deref(), Some("abort"));
    }

    #[test]
    fn parses_pubext_function_as_c_export() {
        let source = r#"
            pubext c fn add(left: i32, right: i32) -> i32;
        "#;
        let module = parse(source, "ffi").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "add" => Some(function),
                _ => None,
            })
            .expect("ffi function should exist");
        assert!(function.is_pub);
        assert!(function.is_pubext);
        assert!(function.is_extern);
        assert_eq!(function.abi.as_deref(), Some("c"));
    }

    #[test]
    fn parses_pubext_async_function() {
        let source = r#"
            pubext async c fn flush(code: i32) -> i32;
        "#;
        let module = parse(source, "ffi").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "flush" => Some(function),
                _ => None,
            })
            .expect("ffi function should exist");
        assert!(function.is_async);
        assert!(function.is_pubext);
        assert_eq!(function.abi.as_deref(), Some("c"));
    }

    #[test]
    fn rejects_invalid_ffi_panic_mode() {
        let source = r#"
            #[ffi_panic(ignore)]
            pubext c fn add(left: i32, right: i32) -> i32;
        "#;
        let diagnostics = parse(source, "ffi").expect_err("invalid mode should fail");
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("ffi_panic mode must be")));
    }

    #[test]
    fn rejects_pub_ext_export_syntax_in_favor_of_pubext() {
        let source = r#"
            pub ext c fn add(left: i32, right: i32) -> i32;
        "#;
        let diagnostics = parse(source, "ffi").expect_err("syntax should fail");
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("use `pubext c fn`")));
    }

    #[test]
    fn rejects_inline_unsafe_metadata_on_block() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(8);
                unsafe("reason:x", "invariant:pointer is valid", "owner:p", "scope:main", "risk_class:memory", "proof_ref:trace://x") {
                    free(p);
                }
                return 0;
            }
        "#;
        let diagnostics = parse(source, "unsafe").expect_err("inline metadata should fail");
        assert!(diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("inline unsafe metadata is removed")));
    }

    #[test]
    fn rejects_inline_unsafe_metadata_on_function() {
        let source = r#"
            unsafe("reason:x", "invariant:owner_live(p) && ptr_nonnull(p)", "owner:p", "scope:main", "risk_class:memory", "proof_ref:trace://x") fn write(p: *u8) -> i32 {
                return 0;
            }
        "#;
        let diagnostics = parse(source, "unsafe").expect_err("inline metadata should fail");
        assert!(diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("inline unsafe metadata is removed")));
    }

    #[test]
    fn supports_trait_associated_items_but_rejects_default_method_bodies() {
        let source = r#"
            trait Show {
                const TAG: i32;
                type Output;
                fn show<T>(v: i32) -> i32 { return v; }
            }
        "#;
        let diagnostics = parse(source, "trait_v1").expect_err("default bodies should fail");
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("trait default method bodies are not supported in v1")
        }));
    }

    #[test]
    fn parses_trait_and_impl_associated_items() {
        let source = r#"
            trait Cache {
                type Key;
                const VERSION: i32;
                fn get(k: i32) -> i32;
            }
            struct Store {}
            impl Cache for Store {
                type Key = i32;
                const VERSION: i32 = 1;
                fn get(k: i32) -> i32 { return k; }
            }
        "#;
        let module = parse(source, "assoc").expect("parse should succeed");
        let tr = module.items.iter().find_map(|item| match item {
            ast::Item::Trait(item) if item.name == "Cache" => Some(item),
            _ => None,
        });
        assert!(tr.is_some_and(
            |item| !item.associated_types.is_empty() && !item.associated_consts.is_empty()
        ));
        let imp = module.items.iter().find_map(|item| match item {
            ast::Item::Impl(item) => Some(item),
            _ => None,
        });
        assert!(imp.is_some_and(
            |item| !item.associated_types.is_empty() && !item.associated_consts.is_empty()
        ));
    }

    #[test]
    fn parses_trait_methods_using_associated_type_paths() {
        let source = r#"
            trait Store {
                type Key;
                const VERSION: i32;
                fn get(self: Self, key: Self::Key) -> i32;
            }
        "#;
        let module = parse(source, "assoc_paths").expect("trait with Self::Key should parse");
        let method = module.items.iter().find_map(|item| match item {
            ast::Item::Trait(item) if item.name == "Store" => item.methods.first(),
            _ => None,
        });
        let key_ty = method
            .and_then(|method| method.params.get(1))
            .map(|param| param.ty.to_string());
        assert_eq!(key_ty.as_deref(), Some("Self::Key"));
    }

    #[test]
    fn parses_dot_qualified_return_types_in_function_signatures() {
        let source = r#"
            fn kind() -> model.types.ProjectKind {
                return model.types.ProjectKind::Unknown
            }
        "#;
        let module = parse(source, "main").expect("dot-qualified return type should parse");
        let ast::Item::Function(function) = &module.items[0] else {
            panic!("expected function");
        };
        assert_eq!(function.return_type.to_string(), "model.types.ProjectKind");
    }

    #[test]
    fn parses_standalone_type_fragments() {
        let ty = parse_type_text("Result<model.types.ProjectKind, Vec<i32>>")
            .expect("standalone type fragment should parse");
        assert_eq!(ty.to_string(), "Result<model.types.ProjectKind, Vec<i32>>");
    }

    #[test]
    fn parses_generic_item_headers() {
        let source = r#"
            struct Box<T> { value: T }
            enum Maybe<T> { Some(T), None }
            trait Show<T> { fn show(v: i32) -> i32; }
            impl<T> Show for Box<T> {
                fn show(v: i32) -> i32 { return v; }
            }
        "#;
        let module = parse(source, "generic_headers").expect("generic headers should parse");
        let boxed = module.items.iter().find_map(|item| match item {
            ast::Item::Struct(item) if item.name == "Box" => Some(item),
            _ => None,
        });
        assert_eq!(boxed.map(|item| item.generics.len()), Some(1));
        let maybe = module.items.iter().find_map(|item| match item {
            ast::Item::Enum(item) if item.name == "Maybe" => Some(item),
            _ => None,
        });
        assert_eq!(maybe.map(|item| item.generics.len()), Some(1));
        let show = module.items.iter().find_map(|item| match item {
            ast::Item::Trait(item) if item.name == "Show" => Some(item),
            _ => None,
        });
        assert_eq!(show.map(|item| item.generics.len()), Some(1));
        let imp = module.items.iter().find_map(|item| match item {
            ast::Item::Impl(item) => Some(item),
            _ => None,
        });
        assert_eq!(imp.map(|item| item.generics.len()), Some(1));
    }

    #[test]
    fn parses_bare_enum_variant_before_if_block() {
        let source = r#"
            enum LogLevel {
                Info,
                Warn,
            }

            fn sample(level: LogLevel) -> i32 {
                if level == LogLevel::Warn {
                    return 1
                }
                return 0
            }
        "#;
        parse(source, "enum_if_block").expect("bare enum variant in condition should parse");
    }

    #[test]
    fn parses_unsafe_function_and_ext_unsafe_import() {
        let source = r#"
            ext unsafe c fn c_write(ptr: *u8) -> i32;
            unsafe fn write(ptr: *u8) -> i32 {
                unsafe {
                    return c_write(ptr);
                }
            }
        "#;
        let module = parse(source, "unsafe").expect("parse should succeed");
        let c_write = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "c_write" => Some(function),
                _ => None,
            })
            .expect("c_write import should exist");
        assert!(c_write.is_extern);
        assert!(c_write.is_unsafe);

        let write = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "write" => Some(function),
                _ => None,
            })
            .expect("write function should exist");
        assert!(write.is_unsafe);
        assert!(write.unsafe_meta.is_none());
        assert!(write
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::Expr(ast::Expr::UnsafeBlock { .. }))));
    }

    #[test]
    fn parses_pointer_sized_types_and_wide_integer_literals() {
        let source = r#"
            fn main() -> usize {
                let small: isize = 7;
                let wide: i128 = 170141183460469231731687303715884105727;
                let ptr: usize = 42;
                discard small;
                discard wide;
                return ptr;
            }
        "#;
        let module = parse(source, "wide").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(matches!(main_fn.return_type, ast::Type::USize));
        assert!(matches!(main_fn.params.len(), 0));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                ty: Some(ast::Type::ISize),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                ty: Some(ast::Type::Int {
                    signed: true,
                    bits: 128
                }),
                ..
            }
        )));
    }

    #[test]
    fn unknown_token_is_hard_error() {
        let source = r#"
            fn main() -> i32 {
                let x = 1 @ 2;
                return x;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unknown token `@`")));
    }

    #[test]
    fn parses_percent_operator_expression() {
        let source = r#"
            fn main() -> i32 {
                let x = 7 % 3;
                return x;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Binary {
                    op: ast::BinaryOp::Mod,
                    ..
                },
                ..
            }
        )));
    }

    #[test]
    fn parses_loop_for_for_in_and_control_flow() {
        let source = r#"
            fn main() -> i32 {
                let total: i32 = 0;
                for let i: i32 = 0; i < 10; i = i + 1 {
                    if i == 3 { continue; }
                    if i == 8 { break; }
                }
                for n in range.closed(0, 3) {
                    discard n;
                }
                loop { break; }
                return total;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::For { .. })));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::ForIn { .. })));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::Loop { .. })));
    }

    #[test]
    fn parses_if_then_control_statement() {
        let source = r#"
            fn main() -> i32 {
                if true then return 7
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::If { .. })));
    }

    #[test]
    fn parses_if_expression_in_let_binding() {
        let source = r#"
            fn main() -> i32 {
                let x = if true { 7 } else { 3 };
                return x;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::If { .. },
                ..
            }
        )));
    }

    #[test]
    fn parses_discard_expression_in_let_binding() {
        let source = r#"
            fn main() -> i32 {
                let x = discard str.len("abc");
                discard x;
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Discard(_),
                ..
            }
        )));
    }

    #[test]
    fn rejects_inclusive_range_operator() {
        let source = r#"
            fn main() -> i32 {
                for i in 0..=3 {
                    discard i;
                }
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|d| d
            .message
            .contains("`..=` is removed; use `range.closed(start, end)`")));
    }

    #[test]
    fn rejects_let_wildcard_statement() {
        let source = r#"
            fn main() -> i32 {
                let _ = 1;
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|d| d
            .message
            .contains("`let _ = ...` is removed; use `discard <expr>`")));
    }

    #[test]
    fn parses_operator_completeness_and_unit_return() {
        let source = r#"
            fn main() -> void {
                let flags: i32 = 7;
                let ok: bool = !false && true || false;
                let mix: i32 = (~flags) ^ (flags << 1) | (flags >> 1);
                let value: i32 = +flags + (-1);
                flags += 1;
                flags &= 3;
                flags |= 2;
                flags ^= 1;
                flags <<= 1;
                flags >>= 1;
                flags %= 3;
                discard ok;
                discard mix;
                discard value;
                return;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::CompoundAssign {
                op: ast::BinaryOp::BitAnd,
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Binary {
                    op: ast::BinaryOp::Or,
                    ..
                },
                ..
            }
        )));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::Return(None))));
    }

    #[test]
    fn match_pattern_or_remains_supported() {
        let source = r#"
            fn main() -> i32 {
                match 2 {
                    1 | 2 => 7,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Match {
                arms,
                ..
            } if matches!(arms.first().map(|arm| &arm.pattern), Some(ast::Pattern::Or(_)))
        )));
    }

    #[test]
    fn parses_float_char_array_and_index_literals() {
        let source = r#"
            fn main() -> i32 {
                let pi: f64 = 3.14159;
                let ratio: f32 = 1.5f32;
                let ch: char = '\n';
                let arr = [1, 2, 3];
                let v = arr[1];
                discard pi;
                discard ratio;
                discard ch;
                return v;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Float { .. },
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Char(_),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::ArrayLiteral(_),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Index { .. },
                ..
            }
        )));
    }

    #[test]
    fn parses_mutable_let_bindings() {
        let source = r#"
            fn main() -> i32 {
                let mut counter: i32 = 0;
                counter = counter + 1;
                return counter;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                mutable: true,
                name,
                ..
            } if name == "counter"
        )));
    }

    #[test]
    fn test_block_body_is_preserved() {
        let source = r#"
            test "smoke" {
                let values = [1, 2];
                discard values[0];
            }
        "#;
        let module = parse(source, "tests").expect("parse should succeed");
        let test = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Test(test) => Some(test),
                _ => None,
            })
            .expect("test block should exist");
        assert!(!test.body.is_empty());
    }

    #[test]
    fn parses_function_type_and_expanded_pub_items() {
        let source = r#"
            pub const MAGIC: i32 = 7;
            pub static COUNTER: i32 = 0;
            pub struct Exposed { value: i32 }
            pub enum Flag { On, Off }
            pub trait Show { fn show(v: i32) -> i32; }
            pub impl Show for Exposed {
                pub fn show(v: i32) -> i32 { return v; }
            }
            fn apply(f: fn(i32) -> i32, value: i32) -> i32 {
                return f(value);
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let apply = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "apply" => Some(function),
                _ => None,
            })
            .expect("apply function should exist");
        assert!(matches!(
            apply.params.first().map(|param| &param.ty),
            Some(ast::Type::Function { .. })
        ));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Struct(ast::Struct { is_pub: true, .. }))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Enum(ast::Enum { is_pub: true, .. }))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Trait(ast::Trait { is_pub: true, .. }))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Impl(ast::Impl { is_pub: true, .. }))));
        assert!(module.items.iter().any(|item| matches!(
            item,
            ast::Item::Const(ast::ConstItem {
                name,
                is_pub: true,
                ..
            }) if name == "MAGIC"
        )));
        assert!(module.items.iter().any(|item| matches!(
            item,
            ast::Item::Static(ast::StaticItem {
                name,
                is_pub: true,
                mutable: false,
                ..
            }) if name == "COUNTER"
        )));
    }

    #[test]
    fn supports_use_alias_wildcard_group_and_pub_reexport_forms() {
        let source = r#"
            pub use app::net;
            use app::net as netmod;
            use app::net::*;
            use app::fs::{open, close as close_fn};
            use app::{db::{read, write}, os::*};
        "#;
        let module = parse(source, "imports").expect("parse should succeed");
        assert!(module.imports.iter().any(|entry| {
            entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["app".to_string(), "net".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.as_deref() == Some("netmod")
                && entry.path == vec!["app".to_string(), "net".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && entry.wildcard
                && entry.path == vec!["app".to_string(), "net".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["app".to_string(), "fs".to_string(), "open".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.as_deref() == Some("close_fn")
                && entry.path == vec!["app".to_string(), "fs".to_string(), "close".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["app".to_string(), "db".to_string(), "read".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["app".to_string(), "db".to_string(), "write".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && entry.wildcard
                && entry.path == vec!["app".to_string(), "os".to_string()]
        }));
    }

    #[test]
    fn parses_core_stdlib_module_imports_without_treating_them_as_capabilities() {
        let source = r#"
            use core.process;
            use core.term;
            use core.thread;
            use core.log;
            use core.text;
            use core.env;
            use core.str;
            use core.io;
            use core.path;
            use core.http;
            use core.result;
        "#;
        let module = parse(source, "imports").expect("parse should succeed");
        assert_eq!(
            module.capabilities,
            vec!["thread".to_string(), "log".to_string(), "http".to_string()]
        );
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["process".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["term".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["thread".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["log".to_string()]
        }));
        assert!(!module
            .imports
            .iter()
            .any(|entry| entry.path == vec!["env".to_string()]));
        assert!(!module
            .imports
            .iter()
            .any(|entry| entry.path == vec!["str".to_string()]));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["text".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["io".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["path".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["result".to_string()]
        }));
    }

    #[test]
    fn supports_dotted_pub_use_reexport_paths() {
        let source = r#"
            pub use commands.run_chat;
            use cli.helpers.render as render_fn;
        "#;
        let module = parse(source, "imports").expect("parse should succeed");
        assert!(module.imports.iter().any(|entry| {
            entry.is_pub
                && !entry.wildcard
                && entry.alias.is_none()
                && entry.path == vec!["commands".to_string(), "run_chat".to_string()]
        }));
        assert!(module.imports.iter().any(|entry| {
            !entry.is_pub
                && !entry.wildcard
                && entry.alias.as_deref() == Some("render_fn")
                && entry.path
                    == vec![
                        "cli".to_string(),
                        "helpers".to_string(),
                        "render".to_string(),
                    ]
        }));
    }

    #[test]
    fn malformed_wildcard_group_import_reports_diagnostics_without_panicking() {
        let source = "use app::{db::, os::*};\nfn main() -> i32 {\n    return 0\n}\n";
        let result = std::panic::catch_unwind(|| parse(source, "imports"));
        assert!(
            result.is_ok(),
            "parser should not panic on malformed wildcard import"
        );
        let diagnostics = result
            .expect("parser should return diagnostics")
            .expect_err("parse should fail");
        assert!(!diagnostics.is_empty(), "parse should emit diagnostics");
    }

    #[test]
    fn parses_cross_module_qualified_enum_values_in_value_position() {
        let source = r#"
            fn main() -> i32 {
                let ok_status = model.types.control_status_label(model.types.ControlStatus::ControlOk)
                let boot_phase = model.types.queue_phase_label(model.types.QueuePhase::QueueBoot)
                if ok_status == boot_phase {
                    return 1
                }
                return 0
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let ast::Item::Function(function) = &module.items[0] else {
            panic!("expected function");
        };
        let ast::Stmt::Let { value, .. } = &function.body[0] else {
            panic!("expected let binding");
        };
        let ast::Expr::Call { args, .. } = value else {
            panic!("expected call expression");
        };
        assert!(matches!(
            &args[0],
            ast::Expr::EnumInit {
                enum_name,
                variant,
                payload,
                named_payload,
            } if enum_name == "model.types.ControlStatus"
                && variant == "ControlOk"
                && payload.is_empty()
                && named_payload.is_empty()
        ));
    }

    #[test]
    fn parses_static_mut_declaration() {
        let source = r#"
            static mut COUNTER: i32 = 0;
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let parsed = module.items.iter().find_map(|item| match item {
            ast::Item::Static(item) if item.name == "COUNTER" => Some(item),
            _ => None,
        });
        assert!(parsed.is_some_and(|item| item.mutable));
    }

    #[test]
    fn primitive_parity_fixture_parses_full_control_flow_and_operator_surface() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/primitive_parity/main.fzy"),
        )
        .expect("primitive parity fixture should be readable");
        let module = parse(&source, "primitive_parity").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                ty: Some(ast::Type::Int { .. }),
                ..
            }
        )));
        assert!(module.items.iter().any(|item| matches!(
            item,
            ast::Item::Function(ast::Function { name, .. }) if name == "apply_id"
        )));
    }

    #[test]
    fn let_pattern_variant_parses_as_first_class_statement() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let Maybe::Some(v) = Maybe::Some(7);
                return v;
            }
        "#;
        let module = parse(source, "main").expect("parser should accept let patterns");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::LetPattern { pattern, .. } = &main_fn.body[0] else {
            panic!("expected let-pattern statement");
        };
        let ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } = pattern
        else {
            panic!("expected variant pattern");
        };
        assert_eq!(enum_name, "Maybe");
        assert_eq!(variant, "Some");
        assert_eq!(bindings, &vec!["v".to_string()]);
        assert!(named_bindings.is_empty());
    }

    #[test]
    fn let_pattern_struct_parses_as_first_class_statement() {
        let source = r#"
            struct Pair { left: i32, right: i32 }
            fn main() -> i32 {
                let Pair { left, right: r } = Pair { left: 7, right: 9 };
                return left + r;
            }
        "#;
        let module = parse(source, "main").expect("parser should accept struct let patterns");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::LetPattern { pattern, .. } = &main_fn.body[0] else {
            panic!("expected let-pattern statement");
        };
        let ast::Pattern::Struct { name, fields } = pattern else {
            panic!("expected struct pattern");
        };
        assert_eq!(name, "Pair");
        assert_eq!(
            fields,
            &vec![
                ("left".to_string(), "left".to_string()),
                ("right".to_string(), "r".to_string())
            ]
        );
    }

    #[test]
    fn let_pattern_tuple_parses_as_first_class_statement() {
        let source = r#"
            fn main() -> i32 {
                let (left, (right, _)) = (7, (9, 11));
                return left + right;
            }
        "#;
        let module = parse(source, "main").expect("parser should accept tuple let patterns");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::LetPattern { pattern, .. } = &main_fn.body[0] else {
            panic!("expected let-pattern statement");
        };
        let ast::Pattern::Tuple(items) = pattern else {
            panic!("expected tuple pattern");
        };
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], ast::Pattern::Ident(_)));
        assert!(matches!(items[1], ast::Pattern::Tuple(_)));
    }

    #[test]
    fn let_pattern_accepts_or_pattern() {
        let source = r#"
            fn main() -> i32 {
                let a | b = 1;
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("or-patterns in let should parse");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::LetPattern { pattern, .. } = &main_fn.body[0] else {
            panic!("expected let-pattern statement");
        };
        assert!(matches!(pattern, ast::Pattern::Or(_)));
    }

    #[test]
    fn for_clause_let_pattern_accepts_or_pattern() {
        let source = r#"
            fn main() -> i32 {
                for let a | b = 1; a < 3; a = a + 1 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parse(source, "main").expect("or-patterns in for let should parse");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::For {
            init: Some(init), ..
        } = &main_fn.body[0]
        else {
            panic!("expected first statement to be for loop with init");
        };
        let ast::Stmt::LetPattern { pattern, .. } = init.as_ref() else {
            panic!("expected for init to be let-pattern statement");
        };
        assert!(matches!(pattern, ast::Pattern::Or(_)));
    }

    #[test]
    fn parses_lambda_expression_with_typed_params() {
        let source = r#"
            fn main() -> i32 {
                let add1 = |x: i32| x + 1;
                return add1(4);
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        let ast::Stmt::Let { value, .. } = &main_fn.body[0] else {
            panic!("expected first statement to be let binding");
        };
        let ast::Expr::Closure {
            params,
            return_type,
            ..
        } = value
        else {
            panic!("expected lambda expression");
        };
        assert_eq!(params.len(), 1);
        assert!(return_type.is_none());
        assert_eq!(params[0].name, "x");
        assert_eq!(
            params[0].ty,
            ast::Type::Int {
                signed: true,
                bits: 32
            }
        );
    }

    #[test]
    fn parses_bytes_and_tuple_types() {
        let source = r#"
            fn pair(a: bytes, b: (i32, str)) -> i32 {
                let _x: (bytes, i32) = a;
                discard b;
                discard _x;
                return 0;
            }
        "#;
        let module = parse(source, "types").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "pair" => Some(function),
                _ => None,
            })
            .expect("pair function should exist");
        assert!(matches!(function.params[0].ty, ast::Type::Bytes));
        assert!(matches!(function.params[1].ty, ast::Type::Tuple(_)));
    }

    #[test]
    fn parses_enum_struct_variant_forms() {
        let source = r#"
            enum Message {
                Data { id: i32, body: str },
            }
            fn main() -> i32 {
                let m = Message::Data { id: 7, body: "ok" };
                match m {
                    Message::Data { id, body } => return id,
                    _ => return 0,
                }
            }
        "#;
        let module = parse(source, "enum_struct_variant").expect("parse should succeed");
        let message = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Enum(item) if item.name == "Message" => Some(item),
                _ => None,
            })
            .expect("Message enum should exist");
        assert_eq!(message.variants.len(), 1);
        assert_eq!(message.variants[0].named_payload.len(), 2);
    }

    #[test]
    fn parses_future_collection_and_domain_types() {
        let source = r#"
            fn main(
                bi: BigInt,
                bu: BigUint,
                id: Uuid,
                d128: Decimal128,
                fut: Future<i32>,
                m: Map<str, i32>,
                s: Set<str>,
                d: Deque<i32>,
                r: Ring<i32>,
                obj: dyn Error,
                p: Path,
                pb: PathBuf,
                u: Url,
                sa: SocketAddr,
                dur: Duration,
                inst: Instant,
                dec: Decimal,
                dt: DateTimeTz,
                es: ExitStatus
            ) -> i32 {
                discard bi; discard bu; discard id; discard d128;
                discard fut; discard m; discard s; discard d; discard r; discard obj;
                discard p; discard pb; discard u; discard sa; discard dur;
                discard inst; discard dec; discard dt; discard es;
                return 0;
            }
        "#;
        let module = parse(source, "types").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(matches!(main_fn.params[0].ty, ast::Type::BigInt));
        assert!(matches!(main_fn.params[1].ty, ast::Type::BigUint));
        assert!(matches!(main_fn.params[2].ty, ast::Type::Uuid));
        assert!(matches!(main_fn.params[3].ty, ast::Type::Decimal128));
        assert!(matches!(main_fn.params[4].ty, ast::Type::Future(_)));
        assert!(matches!(main_fn.params[5].ty, ast::Type::Map { .. }));
        assert!(matches!(main_fn.params[6].ty, ast::Type::Set(_)));
        assert!(matches!(main_fn.params[7].ty, ast::Type::Deque(_)));
        assert!(matches!(main_fn.params[8].ty, ast::Type::Ring(_)));
        assert!(matches!(main_fn.params[9].ty, ast::Type::DynTrait(_)));
        assert!(matches!(main_fn.params[10].ty, ast::Type::Path));
        assert!(matches!(main_fn.params[11].ty, ast::Type::PathBuf));
        assert!(matches!(main_fn.params[12].ty, ast::Type::Url));
        assert!(matches!(main_fn.params[13].ty, ast::Type::SocketAddr));
        assert!(matches!(main_fn.params[14].ty, ast::Type::Duration));
        assert!(matches!(main_fn.params[15].ty, ast::Type::Instant));
        assert!(matches!(main_fn.params[16].ty, ast::Type::Decimal));
        assert!(matches!(main_fn.params[17].ty, ast::Type::DateTimeTz));
        assert!(matches!(main_fn.params[18].ty, ast::Type::ExitStatus));
    }

    #[test]
    fn parses_type_alias_and_transparent_newtype_items() {
        let source = r#"
            pub type UserId = i64;
            #[repr(transparent)]
            pub newtype SessionId(UserId);
            fn main(id: SessionId) -> i32 { discard id; return 0; }
        "#;
        let module = parse(source, "aliases").expect("parse should succeed");
        let alias = module.items.iter().find_map(|item| match item {
            ast::Item::TypeAlias(item) if item.name == "UserId" => Some(item),
            _ => None,
        });
        assert!(alias.is_some_and(|item| item.is_pub));
        let newtype = module.items.iter().find_map(|item| match item {
            ast::Item::NewType(item) if item.name == "SessionId" => Some(item),
            _ => None,
        });
        assert!(newtype.is_some_and(|item| item.is_pub && item.transparent));
    }

    #[test]
    fn parses_execution_space_function_qualifiers() {
        let source = r#"
            host fn run() -> i32 { return 0; }
            pure fn square(x: i32) -> i32 { return x * x; }
            device fn helper(x: i32) -> i32 { return x; }
            kernel fn launch() -> void {}
        "#;
        let module = parse(source, "gpu_spaces").expect("parse should succeed");
        let spaces = module
            .items
            .iter()
            .filter_map(|item| match item {
                ast::Item::Function(function) => {
                    Some((function.name.as_str(), function.execution_space))
                }
                _ => None,
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(spaces.get("run"), Some(&ast::ExecutionSpace::Host));
        assert_eq!(spaces.get("square"), Some(&ast::ExecutionSpace::Pure));
        assert_eq!(spaces.get("helper"), Some(&ast::ExecutionSpace::Device));
        assert_eq!(spaces.get("launch"), Some(&ast::ExecutionSpace::Kernel));
    }

    #[test]
    fn parses_index_assignment_as_internal_builtin() {
        let source = r#"
            fn main() -> i32 {
                let values = [1, 2, 3];
                values[1] = 9;
                return values[1];
            }
        "#;
        let module = parse(source, "index_assign").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Expr(ast::Expr::Call { callee, .. }) if callee == "__index_assign"
        )));
    }

    #[test]
    fn parse_errors_include_actionable_help() {
        let source = "fn main() -> i32 {\n    let value = 1\n    let add = |x: i32 x + value;\n}\n";
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        let help = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.help.is_some())
            .and_then(|diagnostic| diagnostic.help.as_deref())
            .unwrap_or_default();
        assert!(help.contains("rerun `fz check`"));
    }

    #[test]
    fn parses_embedded_core_log_module_source() {
        let source = include_str!("../../../../core/src/log.fzy");
        parse(source, "log").expect("embedded core.log module should parse");
    }
}
