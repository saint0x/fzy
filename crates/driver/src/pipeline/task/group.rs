use super::*;

pub(crate) fn collect_task_group_policy_events(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<serde_json::Value> {
    let mut started = BTreeSet::<String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    for stmt in &function.body {
        collect_task_group_policy_stmt(stmt, &mut started, &mut terminal, terminal_param_summaries);
    }
    started
        .into_iter()
        .map(|name| {
            let terminals = terminal.get(&name).cloned().unwrap_or_default();
            let mut unique_terminals = Vec::<String>::new();
            for op in terminals {
                if !unique_terminals.contains(&op) {
                    unique_terminals.push(op);
                }
            }
            let current_state = match unique_terminals.as_slice() {
                [] => "missing_terminal".to_string(),
                [single] if single.starts_with("task.group_join_all") => "joined_all".to_string(),
                [single] if single.starts_with("task.group_join") => "joined".to_string(),
                [single] if single.starts_with("task.group_cancel") => "cancelled".to_string(),
                [_] => "active".to_string(),
                _ => "invalid_multiple_terminal".to_string(),
            };
            serde_json::json!({
                "function": function.name,
                "group": name,
                "policy": unique_terminals.first().cloned().unwrap_or_else(|| "missing".to_string()),
                "terminalOperations": unique_terminals,
                "currentState": current_state,
                "strictReady": current_state != "missing_terminal" && current_state != "invalid_multiple_terminal",
                "resultReadAfterTerminalAllowed": false,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct TaskGroupFinding {
    pub(crate) function: String,
    pub(crate) binding: String,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    pub(crate) help: String,
}

pub(crate) fn collect_task_group_findings(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<TaskGroupFinding> {
    let mut started = BTreeSet::<String>::new();
    let mut terminals = BTreeMap::<String, Vec<String>>::new();
    for stmt in &function.body {
        collect_task_group_findings_stmt(
            stmt,
            &mut started,
            &mut terminals,
            terminal_param_summaries,
        );
    }
    let mut findings = Vec::new();
    for group in started {
        match terminals.get(&group) {
            None => findings.push(TaskGroupFinding {
                function: function.name.clone(),
                binding: group.clone(),
                kind: "task_group_missing_terminal",
                message: format!(
                    "task group `{group}` is created by `task.group_begin()` and exits `{}` without `task.group_join`, `task.group_join_all`, or `task.group_cancel`",
                    function.name
                ),
                help: "Terminate every task group explicitly with `task.group_join`, `task.group_join_all`, or `task.group_cancel` before the function exits."
                    .to_string(),
            }),
            Some(ops) if ops.len() > 1 => findings.push(TaskGroupFinding {
                function: function.name.clone(),
                binding: group.clone(),
                kind: "task_group_double_terminal",
                message: format!(
                    "task group `{group}` is terminated multiple times ({})",
                    ops.join(", ")
                ),
                help: "Choose exactly one terminal group operation for each task group and remove the later terminal calls."
                    .to_string(),
            }),
            _ => {}
        }
    }
    findings
}

pub(crate) fn collect_task_group_findings_stmt(
    stmt: &ast::Stmt,
    started: &mut BTreeSet<String>,
    terminals: &mut BTreeMap<String, Vec<String>>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            if matches!(value, ast::Expr::Call { callee, .. } if callee == "task.group_begin") {
                started.insert(name.clone());
            }
            collect_task_group_findings_expr(value, started, terminals, terminal_param_summaries);
        }
        ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value)
        | ast::Stmt::Return(Some(value)) => {
            collect_task_group_findings_expr(value, started, terminals, terminal_param_summaries);
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_task_group_findings_expr(
                condition,
                started,
                terminals,
                terminal_param_summaries,
            );
            for nested in then_body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            for nested in else_body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_task_group_findings_expr(
                condition,
                started,
                terminals,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
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
                collect_task_group_findings_stmt(
                    init,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_task_group_findings_expr(
                    condition,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_task_group_findings_stmt(
                    step,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            for nested in body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_task_group_findings_expr(
                iterable,
                started,
                terminals,
                terminal_param_summaries,
            );
            for nested in body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_task_group_findings_stmt(
                    nested,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_task_group_findings_expr(
                scrutinee,
                started,
                terminals,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_group_findings_expr(
                        guard,
                        started,
                        terminals,
                        terminal_param_summaries,
                    );
                }
                collect_task_group_findings_expr(
                    &arm.value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

pub(crate) fn collect_task_group_findings_expr(
    expr: &ast::Expr,
    started: &mut BTreeSet<String>,
    terminals: &mut BTreeMap<String, Vec<String>>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(
                callee.as_str(),
                "task.group_join" | "task.group_join_all" | "task.group_cancel"
            ) {
                if let Some(ast::Expr::Ident(name)) = args.first() {
                    terminals
                        .entry(name.clone())
                        .or_default()
                        .push(callee.clone());
                }
            }
            if let Some(summary) = terminal_param_summaries.get(callee) {
                for (index, terminal_name) in summary {
                    if let Some(ast::Expr::Ident(name)) = args.get(*index) {
                        terminals
                            .entry(name.clone())
                            .or_default()
                            .push(format!("{terminal_name} via {callee}"));
                    }
                }
            }
            for arg in args {
                collect_task_group_findings_expr(arg, started, terminals, terminal_param_summaries);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_task_group_findings_expr(inner, started, terminals, terminal_param_summaries);
        }
        ast::Expr::Index { base, index } => {
            collect_task_group_findings_expr(base, started, terminals, terminal_param_summaries);
            collect_task_group_findings_expr(index, started, terminals, terminal_param_summaries);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_task_group_findings_expr(left, started, terminals, terminal_param_summaries);
            collect_task_group_findings_expr(right, started, terminals, terminal_param_summaries);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_task_group_findings_expr(
                    value,
                    started,
                    terminals,
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
                collect_task_group_findings_expr(
                    value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            for (_, value) in named_payload {
                collect_task_group_findings_expr(
                    value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Tuple(payload) | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_task_group_findings_expr(
                    value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_task_group_findings_expr(body, started, terminals, terminal_param_summaries);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_task_group_findings_expr(
                try_expr,
                started,
                terminals,
                terminal_param_summaries,
            );
            collect_task_group_findings_expr(
                catch_expr,
                started,
                terminals,
                terminal_param_summaries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_task_group_findings_expr(
                condition,
                started,
                terminals,
                terminal_param_summaries,
            );
            collect_task_group_findings_expr(
                then_expr,
                started,
                terminals,
                terminal_param_summaries,
            );
            collect_task_group_findings_expr(
                else_expr,
                started,
                terminals,
                terminal_param_summaries,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_task_group_findings_expr(
                scrutinee,
                started,
                terminals,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_group_findings_expr(
                        guard,
                        started,
                        terminals,
                        terminal_param_summaries,
                    );
                }
                collect_task_group_findings_expr(
                    &arm.value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_task_group_findings_expr(
                condition,
                started,
                terminals,
                terminal_param_summaries,
            );
            for stmt in body {
                collect_task_group_findings_stmt(
                    stmt,
                    started,
                    terminals,
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
                collect_task_group_findings_stmt(
                    init,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_task_group_findings_expr(
                    condition,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_task_group_findings_stmt(
                    step,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
            for stmt in body {
                collect_task_group_findings_stmt(
                    stmt,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_task_group_findings_expr(
                iterable,
                started,
                terminals,
                terminal_param_summaries,
            );
            for stmt in body {
                collect_task_group_findings_stmt(
                    stmt,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_task_group_findings_stmt(
                    stmt,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_task_group_findings_expr(
                    value,
                    started,
                    terminals,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_task_group_findings_expr(start, started, terminals, terminal_param_summaries);
            collect_task_group_findings_expr(end, started, terminals, terminal_param_summaries);
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
