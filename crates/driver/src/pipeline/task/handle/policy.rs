use super::*;

pub(crate) fn collect_task_handle_policy_events(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<serde_json::Value> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut result_reads_before_terminal = BTreeMap::<String, usize>::new();
    let mut result_reads_after_terminal = BTreeMap::<String, usize>::new();
    for stmt in &function.body {
        collect_task_handle_policy_stmt(
            stmt,
            &mut started,
            &mut terminal,
            &mut result_reads_before_terminal,
            &mut result_reads_after_terminal,
            terminal_param_summaries,
        );
    }
    started
        .into_iter()
        .map(|(name, origin)| {
            let terminals = terminal.get(&name).cloned().unwrap_or_default();
            let mut unique_terminals = Vec::<String>::new();
            for op in terminals {
                if !unique_terminals.contains(&op) {
                    unique_terminals.push(op);
                }
            }
            let policy = unique_terminals
                .first()
                .cloned()
                .unwrap_or_else(|| "missing".to_string());
            let reads_before = result_reads_before_terminal.get(&name).copied().unwrap_or(0);
            let reads_after = result_reads_after_terminal.get(&name).copied().unwrap_or(0);
            let current_state = if reads_after > 0 {
                "invalid_result_after_terminal"
            } else {
                match unique_terminals.as_slice() {
                    [] => "missing_terminal",
                    [single] if single.starts_with("join") => "joined",
                    [single] if single.starts_with("detach") => "detached",
                    [single] if single.starts_with("cancel_task") => "cancelled",
                    [_] => "active",
                    _ => "invalid_multiple_terminal",
                }
            };
            serde_json::json!({
                "function": function.name,
                "handle": name,
                "origin": origin,
                "policy": policy,
                "terminalOperations": unique_terminals,
                "currentState": current_state,
                "resultReadsBeforeTerminal": reads_before,
                "resultReadsAfterTerminal": reads_after,
                "resultReads": reads_before + reads_after,
                "strictReady": current_state != "missing_terminal" && current_state != "invalid_multiple_terminal" && current_state != "invalid_result_after_terminal",
            })
        })
        .collect()
}

pub(crate) fn collect_task_handle_policy_stmt(
    stmt: &ast::Stmt,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    result_reads_before_terminal: &mut BTreeMap<String, usize>,
    result_reads_after_terminal: &mut BTreeMap<String, usize>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            super::common::collect_task_handle_creation(name, value, started);
            super::common::collect_task_handle_effects_from_expr(
                value,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => {
            super::common::collect_task_handle_effects_from_expr(
                value,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Stmt::Return(Some(value)) => {
            super::common::collect_task_handle_effects_from_expr(
                value,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            super::common::collect_task_handle_effects_from_expr(
                condition,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for nested in then_body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            for nested in else_body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            super::common::collect_task_handle_effects_from_expr(
                condition,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
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
                collect_task_handle_policy_stmt(
                    init,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                super::common::collect_task_handle_effects_from_expr(
                    condition,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_task_handle_policy_stmt(
                    step,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            for nested in body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            super::common::collect_task_handle_effects_from_expr(
                iterable,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_handle_policy_stmt(
                    nested,
                    started,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            super::common::collect_task_handle_effects_from_expr(
                scrutinee,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    super::common::collect_task_handle_effects_from_expr(
                        guard,
                        terminal,
                        result_reads_before_terminal,
                        result_reads_after_terminal,
                        terminal_param_summaries,
                    );
                }
                super::common::collect_task_handle_effects_from_expr(
                    &arm.value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}
