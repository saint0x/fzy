use super::*;

pub(crate) fn collect_task_group_policy_stmt(
    stmt: &ast::Stmt,
    started: &mut BTreeSet<String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            if matches!(value, ast::Expr::Call { callee, .. } if callee == "task.group_begin") {
                started.insert(name.clone());
            }
        }
        ast::Stmt::Expr(ast::Expr::Call { callee, args }) => {
            if matches!(
                callee.as_str(),
                "task.group_join" | "task.group_join_all" | "task.group_cancel"
            ) {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    terminal.entry(name.clone()).or_default().push(callee.clone());
                }
            }
            if let Some(summary) = terminal_param_summaries.get(callee) {
                for (index, terminal_name) in summary {
                    if let Some(ast::Expr::Ident(name)) = args.get(*index) {
                        terminal
                            .entry(name.clone())
                            .or_default()
                            .push(format!("{terminal_name} via {callee}"));
                    }
                }
            }
        }
        ast::Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for nested in then_body {
                collect_task_group_policy_stmt(nested, started, terminal, terminal_param_summaries);
            }
            for nested in else_body {
                collect_task_group_policy_stmt(nested, started, terminal, terminal_param_summaries);
            }
        }
        ast::Stmt::While { body, .. }
        | ast::Stmt::ForIn { body, .. }
        | ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_group_policy_stmt(nested, started, terminal, terminal_param_summaries);
            }
        }
        ast::Stmt::For { body, .. } => {
            for nested in body {
                collect_task_group_policy_stmt(nested, started, terminal, terminal_param_summaries);
            }
        }
        ast::Stmt::Match { arms, .. } => {
            for arm in arms {
                collect_task_group_policy_expr(
                    &arm.value,
                    started,
                    terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Return(Some(value))
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => {
            collect_task_group_policy_expr(value, started, terminal, terminal_param_summaries)
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

pub(crate) fn collect_task_group_policy_expr(
    expr: &ast::Expr,
    started: &mut BTreeSet<String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match expr {
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_task_group_policy_stmt(stmt, started, terminal, terminal_param_summaries);
            }
        }
        ast::Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            collect_task_group_policy_expr(then_expr, started, terminal, terminal_param_summaries);
            collect_task_group_policy_expr(else_expr, started, terminal, terminal_param_summaries);
        }
        ast::Expr::Match { arms, .. } => {
            for arm in arms {
                collect_task_group_policy_expr(
                    &arm.value,
                    started,
                    terminal,
                    terminal_param_summaries,
                );
            }
        }
        _ => {}
    }
}
