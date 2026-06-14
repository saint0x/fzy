use super::*;

pub(crate) fn collect_task_handle_finding_stmt(
    stmt: &ast::Stmt,
    function_name: &str,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    findings: &mut Vec<TaskHandleFinding>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            super::super::common::collect_task_handle_creation(name, value, started);
            super::expr::collect_task_handle_finding_expr(
                value,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            super::expr::collect_task_handle_finding_expr(
                value,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            super::expr::collect_task_handle_finding_expr(
                condition,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for nested in then_body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            for nested in else_body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            super::expr::collect_task_handle_finding_expr(
                condition,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
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
                collect_task_handle_finding_stmt(
                    init,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                super::expr::collect_task_handle_finding_expr(
                    condition,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_task_handle_finding_stmt(
                    step,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            for nested in body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            super::expr::collect_task_handle_finding_expr(
                iterable,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_handle_finding_stmt(
                    nested,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            super::expr::collect_task_handle_finding_expr(
                scrutinee,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    super::expr::collect_task_handle_finding_expr(
                        guard,
                        function_name,
                        started,
                        terminal,
                        findings,
                        terminal_param_summaries,
                    );
                }
                super::expr::collect_task_handle_finding_expr(
                    &arm.value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}
