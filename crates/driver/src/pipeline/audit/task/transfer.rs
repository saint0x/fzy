use super::*;

pub(crate) fn collect_task_transfer_events(
    function: &hir::TypedFunction,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    collect_task_transfer_events_from_stmts(&function.name, &function.body, &mut out);
    out
}

fn collect_task_transfer_events_from_stmts(
    function_name: &str,
    body: &[ast::Stmt],
    out: &mut Vec<serde_json::Value>,
) {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { value, .. }
            | ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Return(Some(value))
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => {
                collect_task_transfer_events_from_expr(function_name, value, out)
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_task_transfer_events_from_stmts(function_name, then_body, out);
                collect_task_transfer_events_from_stmts(function_name, else_body, out);
            }
            ast::Stmt::While { body, .. }
            | ast::Stmt::ForIn { body, .. }
            | ast::Stmt::Loop { body } => {
                collect_task_transfer_events_from_stmts(function_name, body, out)
            }
            ast::Stmt::For { body, .. } => {
                collect_task_transfer_events_from_stmts(function_name, body, out)
            }
            ast::Stmt::Match { arms, .. } => {
                for arm in arms {
                    collect_task_transfer_events_from_expr(function_name, &arm.value, out);
                }
            }
            ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }
}

fn collect_task_transfer_events_from_expr(
    function_name: &str,
    expr: &ast::Expr,
    out: &mut Vec<serde_json::Value>,
) {
    match expr {
        ast::Expr::Call { callee, args }
            if matches!(
                callee.as_str(),
                "spawn"
                    | "thread.spawn"
                    | "spawn_ctx"
                    | "thread.spawn_ctx"
                    | "task.group_spawn"
                    | "task.group_spawn_n"
                    | "task.parallel_map"
            ) =>
        {
            out.push(serde_json::json!({
                "function": function_name,
                "callee": callee,
                "args": args.iter().map(memory_report_expr_origin).collect::<Vec<_>>(),
                "result": "accepted",
            }));
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            collect_task_transfer_events_from_stmts(function_name, body, out);
        }
        ast::Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            collect_task_transfer_events_from_expr(function_name, then_expr, out);
            collect_task_transfer_events_from_expr(function_name, else_expr, out);
        }
        ast::Expr::Match { arms, .. } => {
            for arm in arms {
                collect_task_transfer_events_from_expr(function_name, &arm.value, out);
            }
        }
        _ => {}
    }
}
