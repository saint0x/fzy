use super::*;

pub(crate) fn summarize_gpu_event_terminal_params(
    function: &hir::TypedFunction,
) -> Option<(String, BTreeMap<usize, String>)> {
    let mut terminal_params = BTreeMap::<usize, String>::new();
    for stmt in &function.body {
        collect_gpu_event_terminal_param_stmt(stmt, function, &mut terminal_params);
    }
    (!terminal_params.is_empty()).then_some((function.name.clone(), terminal_params))
}

fn collect_gpu_event_terminal_param_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            collect_gpu_event_terminal_param_expr(value, function, terminal_params);
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for nested in then_body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
            for nested in else_body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_gpu_event_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_gpu_event_terminal_param_stmt(step, function, terminal_params);
            }
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_gpu_event_terminal_param_expr(iterable, function, terminal_params);
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_gpu_event_terminal_param_stmt(nested, function, terminal_params);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_gpu_event_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_terminal_param_expr(guard, function, terminal_params);
                }
                collect_gpu_event_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_gpu_event_terminal_param_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    terminal_params: &mut BTreeMap<usize, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "gpu.wait" | "gpu.wait_async") {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    if let Some((index, _)) =
                        function.params.iter().enumerate().find(|(_, param)| {
                            param.name == *name && param.ty.to_string() == "GpuEvent"
                        })
                    {
                        terminal_params
                            .entry(index)
                            .or_insert_with(|| callee.clone());
                    }
                }
            }
            for arg in args {
                collect_gpu_event_terminal_param_expr(arg, function, terminal_params);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_gpu_event_terminal_param_expr(inner, function, terminal_params);
        }
        ast::Expr::Index { base, index } => {
            collect_gpu_event_terminal_param_expr(base, function, terminal_params);
            collect_gpu_event_terminal_param_expr(index, function, terminal_params);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_gpu_event_terminal_param_expr(left, function, terminal_params);
            collect_gpu_event_terminal_param_expr(right, function, terminal_params);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
            for (_, value) in named_payload {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_gpu_event_terminal_param_expr(body, function, terminal_params);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_gpu_event_terminal_param_expr(try_expr, function, terminal_params);
            collect_gpu_event_terminal_param_expr(catch_expr, function, terminal_params);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            collect_gpu_event_terminal_param_expr(then_expr, function, terminal_params);
            collect_gpu_event_terminal_param_expr(else_expr, function, terminal_params);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_gpu_event_terminal_param_expr(scrutinee, function, terminal_params);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_terminal_param_expr(guard, function, terminal_params);
                }
                collect_gpu_event_terminal_param_expr(&arm.value, function, terminal_params);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_gpu_event_terminal_param_stmt(init, function, terminal_params);
            }
            if let Some(condition) = condition {
                collect_gpu_event_terminal_param_expr(condition, function, terminal_params);
            }
            if let Some(step) = step {
                collect_gpu_event_terminal_param_stmt(step, function, terminal_params);
            }
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_gpu_event_terminal_param_expr(iterable, function, terminal_params);
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_gpu_event_terminal_param_stmt(stmt, function, terminal_params);
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_gpu_event_terminal_param_expr(value, function, terminal_params);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_gpu_event_terminal_param_expr(start, function, terminal_params);
            collect_gpu_event_terminal_param_expr(end, function, terminal_params);
        }
        ast::Expr::Continue
        | ast::Expr::Ident(_)
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_) => {}
    }
}
