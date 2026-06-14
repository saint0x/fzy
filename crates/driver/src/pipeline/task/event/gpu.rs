use super::*;

pub(crate) fn collect_gpu_event_policy_events(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<serde_json::Value> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut wait_bounds = BTreeMap::<String, Vec<bool>>::new();
    let mut timeout_active = false;
    for stmt in &function.body {
        collect_gpu_event_policy_stmt(
            stmt,
            function,
            &mut started,
            &mut terminal,
            &mut wait_bounds,
            &mut timeout_active,
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
            let waits = wait_bounds.get(&name).cloned().unwrap_or_default();
            let all_waits_bounded = waits.iter().all(|value| *value);
            let current_state = match unique_terminals.as_slice() {
                [] => "missing_terminal".to_string(),
                [_] if all_waits_bounded => "waited".to_string(),
                [_] => "pending".to_string(),
                _ => "invalid_multiple_terminal".to_string(),
            };
            let wait_policy = if waits.is_empty() {
                "missing".to_string()
            } else if all_waits_bounded {
                "task_local_timeout_or_deadline".to_string()
            } else {
                "missing_timeout_or_deadline".to_string()
            };
            serde_json::json!({
                "function": function.name,
                "event": name,
                "origin": origin,
                "policy": unique_terminals.first().cloned().unwrap_or_else(|| "missing".to_string()),
                "terminalOperations": unique_terminals,
                "currentState": current_state,
                "waitPolicy": wait_policy,
                "waitBounded": !waits.is_empty() && all_waits_bounded,
                "deadlineScope": "task_local",
                "cancellationPolicy": "deadline_bound_wait_then_cleanup",
                "strictReady": current_state == "waited",
            })
        })
        .collect()
}

pub(crate) fn collect_gpu_event_creation(
    binding: &str,
    value: &ast::Expr,
    started: &mut BTreeMap<String, String>,
) {
    let ast::Expr::Call { callee, .. } = value else {
        return;
    };
    if matches!(
        callee.as_str(),
        "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4"
    ) {
        started.insert(binding.to_string(), callee.clone());
    }
}

pub(crate) fn collect_gpu_event_policy_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    wait_bounds: &mut BTreeMap<String, Vec<bool>>,
    timeout_active: &mut bool,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            collect_gpu_event_creation(name, value, started);
            collect_gpu_event_effects_from_expr(
                value,
                function,
                terminal,
                wait_bounds,
                timeout_active,
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
            collect_gpu_event_effects_from_expr(
                value,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_gpu_event_effects_from_expr(
                condition,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut then_timeout_active = *timeout_active;
            for nested in then_body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut then_timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut else_timeout_active = *timeout_active;
            for nested in else_body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut else_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_gpu_event_effects_from_expr(
                condition,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
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
                collect_gpu_event_policy_stmt(
                    init,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_gpu_event_effects_from_expr(
                    condition,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_gpu_event_policy_stmt(
                    step,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_gpu_event_effects_from_expr(
                iterable,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_policy_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_gpu_event_effects_from_expr(
                scrutinee,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_effects_from_expr(
                        guard,
                        function,
                        terminal,
                        wait_bounds,
                        &mut arm_timeout_active,
                        terminal_param_summaries,
                    );
                }
                collect_gpu_event_effects_from_expr(
                    &arm.value,
                    function,
                    terminal,
                    wait_bounds,
                    &mut arm_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

pub(crate) fn collect_gpu_event_effects_from_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    terminal: &mut BTreeMap<String, Vec<String>>,
    wait_bounds: &mut BTreeMap<String, Vec<bool>>,
    timeout_active: &mut bool,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "timeout" | "deadline") {
                *timeout_active = true;
            }
            if let Some(ast::Expr::Ident(name)) = args.first() {
                if matches!(callee.as_str(), "gpu.wait" | "gpu.wait_async") {
                    terminal.entry(name.clone()).or_default().push(callee.clone());
                    wait_bounds.entry(name.clone()).or_default().push(
                        runtime_wait_policy(callee, *timeout_active)
                            .is_some_and(|(_, bounded)| bounded),
                    );
                }
            }
            if let Some(summary) = terminal_param_summaries.get(callee) {
                for (index, terminal_name) in summary {
                    if let Some(ast::Expr::Ident(name)) = args.get(*index) {
                        terminal
                            .entry(name.clone())
                            .or_default()
                            .push(format!("{terminal_name} via {callee}"));
                        wait_bounds
                            .entry(name.clone())
                            .or_default()
                            .push(*timeout_active);
                    }
                }
            }
            for arg in args {
                collect_gpu_event_effects_from_expr(
                    arg,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_gpu_event_effects_from_expr(
                inner,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Index { base, index } => {
            collect_gpu_event_effects_from_expr(
                base,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_effects_from_expr(
                index,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_gpu_event_effects_from_expr(
                left,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_effects_from_expr(
                right,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_gpu_event_effects_from_expr(
                    value,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
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
                collect_gpu_event_effects_from_expr(
                    value,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            for (_, value) in named_payload {
                collect_gpu_event_effects_from_expr(
                    value,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_gpu_event_effects_from_expr(
                    value,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_gpu_event_effects_from_expr(
                body,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_gpu_event_effects_from_expr(
                try_expr,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_effects_from_expr(
                catch_expr,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_gpu_event_effects_from_expr(
                condition,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut then_timeout_active = *timeout_active;
            collect_gpu_event_effects_from_expr(
                then_expr,
                function,
                terminal,
                wait_bounds,
                &mut then_timeout_active,
                terminal_param_summaries,
            );
            let mut else_timeout_active = *timeout_active;
            collect_gpu_event_effects_from_expr(
                else_expr,
                function,
                terminal,
                wait_bounds,
                &mut else_timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_gpu_event_effects_from_expr(
                scrutinee,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_effects_from_expr(
                        guard,
                        function,
                        terminal,
                        wait_bounds,
                        &mut arm_timeout_active,
                        terminal_param_summaries,
                    );
                }
                collect_gpu_event_effects_from_expr(
                    &arm.value,
                    function,
                    terminal,
                    wait_bounds,
                    &mut arm_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_gpu_event_effects_from_expr(
                condition,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_policy_stmt(
                    stmt,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
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
                collect_gpu_event_policy_stmt(
                    init,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_gpu_event_effects_from_expr(
                    condition,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_gpu_event_policy_stmt(
                    step,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_policy_stmt(
                    stmt,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_gpu_event_effects_from_expr(
                iterable,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_policy_stmt(
                    stmt,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_policy_stmt(
                    stmt,
                    function,
                    &mut BTreeMap::new(),
                    terminal,
                    wait_bounds,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_gpu_event_effects_from_expr(
                    value,
                    function,
                    terminal,
                    wait_bounds,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_gpu_event_effects_from_expr(
                start,
                function,
                terminal,
                wait_bounds,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_effects_from_expr(
                end,
                function,
                terminal,
                wait_bounds,
                timeout_active,
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
