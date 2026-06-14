use super::*;

pub(crate) fn collect_task_handle_creation(
    binding: &str,
    value: &ast::Expr,
    started: &mut BTreeMap<String, String>,
) {
    let ast::Expr::Call { callee, .. } = value else {
        return;
    };
    if matches!(
        callee.as_str(),
        "spawn" | "thread.spawn" | "spawn_ctx" | "thread.spawn_ctx" | "task.group_spawn"
    ) {
        started.insert(binding.to_string(), callee.clone());
    }
}

pub(crate) fn collect_task_handle_effects_from_expr(
    expr: &ast::Expr,
    terminal: &mut BTreeMap<String, Vec<String>>,
    result_reads_before_terminal: &mut BTreeMap<String, usize>,
    result_reads_after_terminal: &mut BTreeMap<String, usize>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(ast::Expr::Ident(name)) = args.first() {
                match callee.as_str() {
                    "join" | "detach" | "cancel_task" => {
                        terminal
                            .entry(name.clone())
                            .or_default()
                            .push(callee.clone());
                    }
                    "task_result" => {
                        if terminal.contains_key(name) {
                            *result_reads_after_terminal.entry(name.clone()).or_insert(0) += 1;
                        } else {
                            *result_reads_before_terminal
                                .entry(name.clone())
                                .or_insert(0) += 1;
                        }
                    }
                    _ => {}
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
            for arg in args {
                collect_task_handle_effects_from_expr(
                    arg,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_task_handle_effects_from_expr(
                inner,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::Index { base, index } => {
            collect_task_handle_effects_from_expr(
                base,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                index,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_task_handle_effects_from_expr(
                left,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                right,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_task_handle_effects_from_expr(
                    value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_task_handle_effects_from_expr(
                    value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            for (_, value) in named_payload {
                collect_task_handle_effects_from_expr(
                    value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Tuple(payload) | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_task_handle_effects_from_expr(
                    value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_task_handle_effects_from_expr(
                body,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_task_handle_effects_from_expr(
                try_expr,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                catch_expr,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_task_handle_effects_from_expr(
                condition,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                then_expr,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                else_expr,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_task_handle_effects_from_expr(
                scrutinee,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_handle_effects_from_expr(
                        guard,
                        terminal,
                        result_reads_before_terminal,
                        result_reads_after_terminal,
                        terminal_param_summaries,
                    );
                }
                collect_task_handle_effects_from_expr(
                    &arm.value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_task_handle_effects_from_expr(
                condition,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for stmt in body {
                super::policy::collect_task_handle_policy_stmt(
                    stmt,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
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
                super::policy::collect_task_handle_policy_stmt(
                    init,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_task_handle_effects_from_expr(
                    condition,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                super::policy::collect_task_handle_policy_stmt(
                    step,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            for stmt in body {
                super::policy::collect_task_handle_policy_stmt(
                    stmt,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_task_handle_effects_from_expr(
                iterable,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            for stmt in body {
                super::policy::collect_task_handle_policy_stmt(
                    stmt,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                super::policy::collect_task_handle_policy_stmt(
                    stmt,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_task_handle_effects_from_expr(
                    value,
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_task_handle_effects_from_expr(
                start,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
            collect_task_handle_effects_from_expr(
                end,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
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
