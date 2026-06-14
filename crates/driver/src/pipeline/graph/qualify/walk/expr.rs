use super::*;

pub(crate) fn qualify_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let (base_callee, generic_suffix) = super::super::text::split_generic_suffix(callee);
            let qualified_suffix = super::super::text::qualify_generic_suffix(
                generic_suffix,
                namespace,
                local_types,
                module_aliases,
            );
            if let Some(qualified) = module_aliases.get(base_callee) {
                *callee = format!("{qualified}{qualified_suffix}");
            } else if local_functions.contains(base_callee) {
                *callee = format!(
                    "{}{}",
                    super::super::text::qualify_name(namespace, base_callee),
                    qualified_suffix
                );
            } else if qualified_suffix != generic_suffix {
                *callee = format!("{base_callee}{qualified_suffix}");
            }
            for arg in args {
                qualify_expr(arg, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            qualify_expr(base, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::StructInit { name, fields } => {
            *name =
                super::super::text::qualify_type_name(name, namespace, local_types, module_aliases);
            for (_, value) in fields {
                qualify_expr(value, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::EnumInit {
            enum_name,
            payload,
            named_payload,
            ..
        } => {
            *enum_name = super::super::text::qualify_type_name(
                enum_name,
                namespace,
                local_types,
                module_aliases,
            );
            for value in payload {
                qualify_expr(value, namespace, local_functions, local_types, module_aliases);
            }
            for (_, value) in named_payload {
                qualify_expr(value, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::Closure { body, .. } => {
            qualify_expr(body, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            qualify_expr(inner, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::Tuple(items) | ast::Expr::ArrayLiteral(items) => {
            for item in items {
                qualify_expr(item, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            qualify_expr(
                try_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                catch_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                then_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            qualify_expr(
                else_expr,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            qualify_expr(
                scrutinee,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for arm in arms {
                qualify_pattern(&mut arm.pattern, namespace, local_types, module_aliases);
                if let Some(guard) = &mut arm.guard {
                    qualify_expr(
                        guard,
                        namespace,
                        local_functions,
                        local_types,
                        module_aliases,
                    );
                }
                qualify_expr(
                    &mut arm.value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                qualify_stmt(init, namespace, local_functions, local_types, module_aliases);
            }
            if let Some(condition) = condition {
                qualify_expr(
                    condition,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            if let Some(step) = step {
                qualify_stmt(step, namespace, local_functions, local_types, module_aliases);
            }
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            qualify_expr(
                iterable,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Expr::Break(value) | ast::Expr::Return(value) => {
            if let Some(value) = value {
                qualify_expr(value, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            qualify_expr(start, namespace, local_functions, local_types, module_aliases);
            qualify_expr(end, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                qualify_expr(value, namespace, local_functions, local_types, module_aliases);
            }
        }
        ast::Expr::Index { base, index } => {
            qualify_expr(base, namespace, local_functions, local_types, module_aliases);
            qualify_expr(index, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::Unary { expr, .. } => {
            qualify_expr(expr, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::Binary { left, right, .. } => {
            qualify_expr(left, namespace, local_functions, local_types, module_aliases);
            qualify_expr(right, namespace, local_functions, local_types, module_aliases);
        }
        ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Continue => {}
    }
}
