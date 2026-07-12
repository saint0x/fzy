use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct TaskHandlePolicyRecord {
    function: String,
    #[serde(rename = "handle")]
    handle_name: String,
    origin: String,
    policy: String,
    #[serde(rename = "terminalOperations")]
    terminal_operations: Vec<String>,
    #[serde(rename = "currentState")]
    current_state: String,
    #[serde(rename = "resultReadsBeforeTerminal")]
    result_reads_before_terminal: usize,
    #[serde(rename = "resultReadsAfterTerminal")]
    result_reads_after_terminal: usize,
    #[serde(rename = "resultReads")]
    result_reads: usize,
    #[serde(rename = "strictReady")]
    strict_ready: bool,
}

pub(crate) fn collect_task_handle_policy_events(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<TaskHandlePolicyRecord> {
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
            let reads_before = result_reads_before_terminal
                .get(&name)
                .copied()
                .unwrap_or(0);
            let reads_after = result_reads_after_terminal.get(&name).copied().unwrap_or(0);
            let current_state = classify_task_handle_state(&unique_terminals, reads_after);
            let result_reads = reads_before + reads_after;
            let strict_ready = !matches!(
                current_state.as_str(),
                "missing_terminal" | "invalid_multiple_terminal" | "invalid_result_after_terminal"
            );
            TaskHandlePolicyRecord {
                function: function.name.clone(),
                handle_name: name,
                origin,
                policy,
                terminal_operations: unique_terminals,
                current_state,
                result_reads_before_terminal: reads_before,
                result_reads_after_terminal: reads_after,
                result_reads,
                strict_ready,
            }
        })
        .collect()
}

fn classify_task_handle_state(unique_terminals: &[String], reads_after: usize) -> String {
    if reads_after > 0 {
        return "invalid_result_after_terminal".to_string();
    }
    match unique_terminals {
        [] => "missing_terminal".to_string(),
        [single] if single.starts_with("join") => "joined".to_string(),
        [single] if single.starts_with("detach") => "detached".to_string(),
        [single] if single.starts_with("cancel_task") => "cancelled".to_string(),
        [_] => "active".to_string(),
        _ => "invalid_multiple_terminal".to_string(),
    }
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
