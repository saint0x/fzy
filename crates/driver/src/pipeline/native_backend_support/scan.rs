use super::*;

pub(crate) fn collect_unresolved_calls_from_stmt(
    stmt: &ast::Stmt,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_unresolved_calls_from_expr(
            value,
            defined_functions,
            local_callables,
            unresolved,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in then_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in else_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_unresolved_calls_from_stmt(
                    init,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(condition) = condition {
                collect_unresolved_calls_from_expr(
                    condition,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(step) = step {
                collect_unresolved_calls_from_stmt(
                    step,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_unresolved_calls_from_expr(
                iterable,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_unresolved_calls_from_expr(
                scrutinee,
                defined_functions,
                local_callables,
                unresolved,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unresolved_calls_from_expr(
                        guard,
                        defined_functions,
                        local_callables,
                        unresolved,
                    );
                }
                collect_unresolved_calls_from_expr(
                    &arm.value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
    }
}

fn collect_unresolved_calls_from_expr(
    expr: &ast::Expr,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let (base_callee, _) = split_generic_suffix(callee);
            if !defined_functions.contains(callee)
                && !defined_functions.contains(base_callee)
                && !local_callables.contains(callee)
                && !local_callables.contains(base_callee)
                && !native_backend_supports_call(callee)
                && !native_backend_supports_call(base_callee)
            {
                unresolved.insert(callee.clone());
            }
            for arg in args {
                collect_unresolved_calls_from_expr(
                    arg,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_unresolved_calls_from_expr(
                base,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_unresolved_calls_from_expr(
                body,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Group(inner) => {
            collect_unresolved_calls_from_expr(
                inner,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_unresolved_calls_from_expr(
                inner,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            collect_unresolved_calls_from_expr(
                expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unresolved_calls_from_expr(
                try_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                catch_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                then_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                else_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_unresolved_calls_from_expr(
                left,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                right,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Range { start, end, .. } => {
            collect_unresolved_calls_from_expr(
                start,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(end, defined_functions, local_callables, unresolved);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_unresolved_calls_from_expr(
                    item,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            collect_unresolved_calls_from_expr(
                base,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                index,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(crate) fn collect_local_callable_bindings(body: &[ast::Stmt], out: &mut HashSet<String>) {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(name.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::Assign { target, value } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(target.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => collect_local_callable_bindings_from_expr(value, out),
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_local_callable_bindings_from_expr(value, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(then_body, out);
                collect_local_callable_bindings(else_body, out);
            }
            ast::Stmt::While { condition, body } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_local_callable_bindings(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(condition) = condition {
                    collect_local_callable_bindings_from_expr(condition, out);
                }
                if let Some(step) = step {
                    collect_local_callable_bindings(std::slice::from_ref(step.as_ref()), out);
                }
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_local_callable_bindings_from_expr(iterable, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::Loop { body } => collect_local_callable_bindings(body, out),
            ast::Stmt::Match { scrutinee, arms } => {
                collect_local_callable_bindings_from_expr(scrutinee, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_local_callable_bindings_from_expr(guard, out);
                    }
                    collect_local_callable_bindings_from_expr(&arm.value, out);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }
}

fn collect_local_callable_bindings_from_expr(expr: &ast::Expr, out: &mut HashSet<String>) {
    match expr {
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_local_callable_bindings_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            collect_local_callable_bindings(body, out);
        }
        ast::Expr::FieldAccess { base, .. } => collect_local_callable_bindings_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_local_callable_bindings_from_expr(body, out),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_local_callable_bindings_from_expr(inner, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_local_callable_bindings_from_expr(try_expr, out);
            collect_local_callable_bindings_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_local_callable_bindings_from_expr(condition, out);
            collect_local_callable_bindings_from_expr(then_expr, out);
            collect_local_callable_bindings_from_expr(else_expr, out);
        }
        ast::Expr::Unary { expr, .. } => collect_local_callable_bindings_from_expr(expr, out),
        ast::Expr::Binary { left, right, .. } => {
            collect_local_callable_bindings_from_expr(left, out);
            collect_local_callable_bindings_from_expr(right, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_local_callable_bindings_from_expr(start, out);
            collect_local_callable_bindings_from_expr(end, out);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_local_callable_bindings_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_local_callable_bindings_from_expr(base, out);
            collect_local_callable_bindings_from_expr(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(crate) fn native_backend_supports_call(callee: &str) -> bool {
    callee.starts_with("simd.__")
        || callee == "__index_assign"
        || is_gpu_host_runtime_call(callee)
        || native_runtime_import_for_callee(callee).is_some()
        || native_data_plane_import_for_callee(callee).is_some()
}

fn is_gpu_host_runtime_call(callee: &str) -> bool {
    callee.starts_with("gpu.")
}
