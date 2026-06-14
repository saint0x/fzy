use super::*;

pub(crate) fn qualify_stmt(
    stmt: &mut ast::Stmt,
    namespace: &str,
    local_functions: &HashSet<String>,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { ty, value, .. } => {
            if let Some(ty) = ty {
                qualify_type(ty, namespace, local_types, module_aliases);
            }
            qualify_expr(value, namespace, local_functions, local_types, module_aliases)
        }
        ast::Stmt::LetPattern {
            pattern, ty, value, ..
        } => {
            qualify_pattern(pattern, namespace, local_types, module_aliases);
            if let Some(ty) = ty {
                qualify_type(ty, namespace, local_types, module_aliases);
            }
            qualify_expr(value, namespace, local_functions, local_types, module_aliases)
        }
        ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => qualify_expr(
            value,
            namespace,
            local_functions,
            local_types,
            module_aliases,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                qualify_expr(
                    value,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            qualify_expr(
                condition,
                namespace,
                local_functions,
                local_types,
                module_aliases,
            );
            for stmt in then_body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
            for stmt in else_body {
                qualify_stmt(
                    stmt,
                    namespace,
                    local_functions,
                    local_types,
                    module_aliases,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
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
        ast::Stmt::For {
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
        ast::Stmt::ForIn { iterable, body, .. } => {
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
        ast::Stmt::Loop { body } => {
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
        ast::Stmt::Match { scrutinee, arms } => {
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
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}
