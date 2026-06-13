fn collect_task_group_policy_events(
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
struct TaskGroupFinding {
    function: String,
    binding: String,
    kind: &'static str,
    message: String,
    help: String,
}

fn collect_task_group_findings(
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

fn collect_task_group_findings_stmt(
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

fn collect_task_group_findings_expr(
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

fn collect_task_handle_policy_events(
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

#[derive(Debug, Clone)]
struct TaskHandleFinding {
    function: String,
    handle: String,
    kind: &'static str,
    message: String,
    help: String,
}

fn collect_task_handle_findings(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<TaskHandleFinding> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut findings = Vec::new();
    for stmt in &function.body {
        collect_task_handle_finding_stmt(
            stmt,
            &function.name,
            &mut started,
            &mut terminal,
            &mut findings,
            terminal_param_summaries,
        );
    }
    for (handle, origin) in started {
        if !terminal.contains_key(&handle) {
            findings.push(TaskHandleFinding {
                function: function.name.clone(),
                handle: handle.clone(),
                kind: "task_handle_missing_terminal",
                message: format!(
                    "task handle `{handle}` is created by `{origin}` and exits `{}` without `join`, `detach`, or `cancel_task`",
                    function.name
                ),
                help: "Terminate every task handle exactly once with `join`, `detach`, or `cancel_task` before the function exits."
                    .to_string(),
            });
        }
    }
    findings
}

fn collect_task_handle_finding_stmt(
    stmt: &ast::Stmt,
    function_name: &str,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    findings: &mut Vec<TaskHandleFinding>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            collect_task_handle_creation(name, value, started);
            collect_task_handle_finding_expr(
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
            collect_task_handle_finding_expr(
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
            collect_task_handle_finding_expr(
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
            collect_task_handle_finding_expr(
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
                collect_task_handle_finding_expr(
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
            collect_task_handle_finding_expr(
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
            collect_task_handle_finding_expr(
                scrutinee,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_handle_finding_expr(
                        guard,
                        function_name,
                        started,
                        terminal,
                        findings,
                        terminal_param_summaries,
                    );
                }
                collect_task_handle_finding_expr(
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

fn collect_task_handle_finding_expr(
    expr: &ast::Expr,
    function_name: &str,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    findings: &mut Vec<TaskHandleFinding>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(ast::Expr::Ident(name)) = args.first() {
                match callee.as_str() {
                    "join" | "detach" | "cancel_task" => {
                        if let Some(previous) = terminal.get(name).and_then(|ops| ops.last()) {
                            findings.push(TaskHandleFinding {
                                function: function_name.to_string(),
                                handle: name.clone(),
                                kind: "task_handle_double_terminal",
                                message: format!(
                                    "task handle `{name}` is already terminated by `{previous}({name})` and later consumed again by `{callee}({name})`"
                                ),
                                help: "Consume a task handle exactly once with `join`, `detach`, or `cancel_task`, and remove the later terminal operation."
                                    .to_string(),
                            });
                            terminal
                                .entry(name.clone())
                                .or_default()
                                .push(callee.clone());
                        } else {
                            terminal
                                .entry(name.clone())
                                .or_default()
                                .push(callee.clone());
                        }
                    }
                    "task_result" => {
                        if let Some(previous) = terminal.get(name).and_then(|ops| ops.last()) {
                            findings.push(TaskHandleFinding {
                                function: function_name.to_string(),
                                handle: name.clone(),
                                kind: "task_result_after_terminal",
                                message: format!(
                                    "task handle `{name}` is already terminated by `{previous}({name})` and later observed by `task_result({name})`"
                                ),
                                help: "Read `task_result(...)` before the terminal operation, or remove the later result observation."
                                    .to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            if let Some(summary) = terminal_param_summaries.get(callee) {
                for (index, terminal_name) in summary {
                    if let Some(ast::Expr::Ident(name)) = args.get(*index) {
                        started
                            .entry(name.clone())
                            .or_insert_with(|| "unknown".to_string());
                        if let Some(previous) = terminal.get(name).and_then(|ops| ops.last()) {
                            findings.push(TaskHandleFinding {
                                function: function_name.to_string(),
                                handle: name.clone(),
                                kind: "task_handle_double_terminal",
                                message: format!(
                                    "task handle `{name}` is already terminated by `{previous}({name})` and later consumed again by `{terminal_name}({name}) via {callee}`"
                                ),
                                help: "Consume a task handle exactly once with `join`, `detach`, or `cancel_task`, and remove the later terminal operation."
                                    .to_string(),
                            });
                        }
                        terminal
                            .entry(name.clone())
                            .or_default()
                            .push(format!("{terminal_name} via {callee}"));
                    }
                }
            }
            for arg in args {
                collect_task_handle_finding_expr(
                    arg,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_task_handle_finding_expr(
                inner,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::Index { base, index } => {
            collect_task_handle_finding_expr(
                base,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                index,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_task_handle_finding_expr(
                left,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                right,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_task_handle_finding_expr(
                    value,
                    function_name,
                    started,
                    terminal,
                    findings,
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
                collect_task_handle_finding_expr(
                    value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            for (_, value) in named_payload {
                collect_task_handle_finding_expr(
                    value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Tuple(payload) | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_task_handle_finding_expr(
                    value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_task_handle_finding_expr(
                body,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_task_handle_finding_expr(
                try_expr,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                catch_expr,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_task_handle_finding_expr(
                condition,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                then_expr,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                else_expr,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_task_handle_finding_expr(
                scrutinee,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_task_handle_finding_expr(
                        guard,
                        function_name,
                        started,
                        terminal,
                        findings,
                        terminal_param_summaries,
                    );
                }
                collect_task_handle_finding_expr(
                    &arm.value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_task_handle_finding_expr(
                condition,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for stmt in body {
                collect_task_handle_finding_stmt(
                    stmt,
                    function_name,
                    started,
                    terminal,
                    findings,
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
                collect_task_handle_finding_expr(
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
            for stmt in body {
                collect_task_handle_finding_stmt(
                    stmt,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_task_handle_finding_expr(
                iterable,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            for stmt in body {
                collect_task_handle_finding_stmt(
                    stmt,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_task_handle_finding_stmt(
                    stmt,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_task_handle_finding_expr(
                    value,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_task_handle_finding_expr(
                start,
                function_name,
                started,
                terminal,
                findings,
                terminal_param_summaries,
            );
            collect_task_handle_finding_expr(
                end,
                function_name,
                started,
                terminal,
                findings,
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

fn collect_task_handle_policy_stmt(
    stmt: &ast::Stmt,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    result_reads_before_terminal: &mut BTreeMap<String, usize>,
    result_reads_after_terminal: &mut BTreeMap<String, usize>,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            collect_task_handle_creation(name, value, started);
            collect_task_handle_effects_from_expr(
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
            collect_task_handle_effects_from_expr(
                value,
                terminal,
                result_reads_before_terminal,
                result_reads_after_terminal,
                terminal_param_summaries,
            );
        }
        ast::Stmt::Return(Some(value)) => {
            collect_task_handle_effects_from_expr(
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
            collect_task_handle_effects_from_expr(
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
            collect_task_handle_effects_from_expr(
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
                collect_task_handle_effects_from_expr(
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
            collect_task_handle_effects_from_expr(
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
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_task_handle_creation(
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

fn collect_task_handle_effects_from_expr(
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
                collect_task_handle_policy_stmt(
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
                collect_task_handle_policy_stmt(
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
                collect_task_handle_policy_stmt(
                    step,
                    &mut BTreeMap::new(),
                    terminal,
                    result_reads_before_terminal,
                    result_reads_after_terminal,
                    terminal_param_summaries,
                );
            }
            for stmt in body {
                collect_task_handle_policy_stmt(
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
                collect_task_handle_policy_stmt(
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
                collect_task_handle_policy_stmt(
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

#[derive(Debug, Clone)]
struct AsyncRuntimeWaitFinding {
    message: String,
    help: String,
}

#[derive(Debug, Clone)]
struct GpuEventFinding {
    function: String,
    event: String,
    kind: &'static str,
    message: String,
    help: String,
}

fn function_requires_bounded_runtime_waits(function: &hir::TypedFunction) -> bool {
    function.is_async
        || function
            .required_capabilities
            .iter()
            .any(|capability| capability == "thread")
}

fn runtime_wait_surface(callee: &str) -> Option<&'static str> {
    match callee {
        "proc.wait" => Some("process"),
        "gpu.wait" | "gpu.wait_async" => Some("gpu_event"),
        "http.poll_next" | "http.read" | "http.read_headers" | "http.request_stream" => {
            Some("http")
        }
        "http.stream_read" | "http.stream_read_line" => Some("http_stream"),
        "http.websocket_read" => Some("websocket"),
        _ => None,
    }
}

fn runtime_wait_policy(callee: &str, timeout_active: bool) -> Option<(&'static str, bool)> {
    match callee {
        "proc.wait" => Some(("explicit_timeout_arg", true)),
        "http.poll_next" => Some(("intrinsic_poll_timeout", true)),
        "gpu.wait" | "gpu.wait_async" => {
            if timeout_active {
                Some(("task_local_timeout_or_deadline", true))
            } else {
                Some(("missing_timeout_or_deadline", false))
            }
        }
        "http.read"
        | "http.read_headers"
        | "http.request_stream"
        | "http.stream_read"
        | "http.stream_read_line"
        | "http.websocket_read" => {
            if timeout_active {
                Some(("task_local_timeout_or_deadline", true))
            } else {
                Some(("missing_timeout_or_deadline", false))
            }
        }
        _ => None,
    }
}

fn collect_async_runtime_wait_policies(function: &hir::TypedFunction) -> Vec<serde_json::Value> {
    let mut policies = Vec::<serde_json::Value>::new();
    let mut timeout_active = false;
    for stmt in &function.body {
        collect_async_runtime_wait_policies_stmt(
            stmt,
            function,
            &mut timeout_active,
            &mut policies,
        );
    }
    policies
}

fn collect_async_runtime_wait_policies_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    timeout_active: &mut bool,
    policies: &mut Vec<serde_json::Value>,
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
            collect_async_runtime_wait_policies_expr(value, function, timeout_active, policies)
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_async_runtime_wait_policies_expr(condition, function, timeout_active, policies);
            let mut then_timeout_active = *timeout_active;
            for nested in then_body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut then_timeout_active,
                    policies,
                );
            }
            let mut else_timeout_active = *timeout_active;
            for nested in else_body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut else_timeout_active,
                    policies,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_async_runtime_wait_policies_expr(condition, function, timeout_active, policies);
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut loop_timeout_active,
                    policies,
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
                collect_async_runtime_wait_policies_stmt(init, function, timeout_active, policies);
            }
            if let Some(condition) = condition {
                collect_async_runtime_wait_policies_expr(
                    condition,
                    function,
                    timeout_active,
                    policies,
                );
            }
            if let Some(step) = step {
                collect_async_runtime_wait_policies_stmt(step, function, timeout_active, policies);
            }
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_async_runtime_wait_policies_expr(iterable, function, timeout_active, policies);
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_async_runtime_wait_policies_stmt(
                    nested,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_async_runtime_wait_policies_expr(scrutinee, function, timeout_active, policies);
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_async_runtime_wait_policies_expr(
                        guard,
                        function,
                        &mut arm_timeout_active,
                        policies,
                    );
                }
                collect_async_runtime_wait_policies_expr(
                    &arm.value,
                    function,
                    &mut arm_timeout_active,
                    policies,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_async_runtime_wait_policies_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    timeout_active: &mut bool,
    policies: &mut Vec<serde_json::Value>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "timeout" | "deadline") {
                *timeout_active = true;
            }
            if let (Some(surface), Some((bounding, bounded))) = (
                runtime_wait_surface(callee),
                runtime_wait_policy(callee, *timeout_active),
            ) {
                policies.push(serde_json::json!({
                    "function": function.name,
                    "callee": callee,
                    "surface": surface,
                    "blockingBehavior": "may_block",
                    "requiresBoundedWaits": function_requires_bounded_runtime_waits(function),
                    "bounded": bounded,
                    "bounding": bounding,
                    "cancellation": if surface == "gpu_event" {
                        serde_json::json!("deadline_bound_wait_then_cleanup")
                    } else {
                        serde_json::json!(null)
                    },
                }));
            }
            for arg in args {
                collect_async_runtime_wait_policies_expr(arg, function, timeout_active, policies);
            }
        }
        ast::Expr::Await(inner)
        | ast::Expr::Group(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::FieldAccess { base: inner, .. }
        | ast::Expr::Unary { expr: inner, .. } => {
            collect_async_runtime_wait_policies_expr(inner, function, timeout_active, policies);
        }
        ast::Expr::Index { base, index } => {
            collect_async_runtime_wait_policies_expr(base, function, timeout_active, policies);
            collect_async_runtime_wait_policies_expr(index, function, timeout_active, policies);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_async_runtime_wait_policies_expr(left, function, timeout_active, policies);
            collect_async_runtime_wait_policies_expr(right, function, timeout_active, policies);
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_async_runtime_wait_policies_expr(value, function, timeout_active, policies);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_async_runtime_wait_policies_expr(value, function, timeout_active, policies);
            }
            for (_, value) in named_payload {
                collect_async_runtime_wait_policies_expr(value, function, timeout_active, policies);
            }
        }
        ast::Expr::Tuple(items) | ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_async_runtime_wait_policies_expr(item, function, timeout_active, policies);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_async_runtime_wait_policies_expr(body, function, timeout_active, policies);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_async_runtime_wait_policies_expr(try_expr, function, timeout_active, policies);
            collect_async_runtime_wait_policies_expr(
                catch_expr,
                function,
                timeout_active,
                policies,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_async_runtime_wait_policies_expr(condition, function, timeout_active, policies);
            let mut then_timeout_active = *timeout_active;
            collect_async_runtime_wait_policies_expr(
                then_expr,
                function,
                &mut then_timeout_active,
                policies,
            );
            let mut else_timeout_active = *timeout_active;
            collect_async_runtime_wait_policies_expr(
                else_expr,
                function,
                &mut else_timeout_active,
                policies,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_async_runtime_wait_policies_expr(scrutinee, function, timeout_active, policies);
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_async_runtime_wait_policies_expr(
                        guard,
                        function,
                        &mut arm_timeout_active,
                        policies,
                    );
                }
                collect_async_runtime_wait_policies_expr(
                    &arm.value,
                    function,
                    &mut arm_timeout_active,
                    policies,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_async_runtime_wait_policies_expr(condition, function, timeout_active, policies);
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_async_runtime_wait_policies_stmt(
                    stmt,
                    function,
                    &mut loop_timeout_active,
                    policies,
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
                collect_async_runtime_wait_policies_stmt(init, function, timeout_active, policies);
            }
            if let Some(condition) = condition {
                collect_async_runtime_wait_policies_expr(
                    condition,
                    function,
                    timeout_active,
                    policies,
                );
            }
            if let Some(step) = step {
                collect_async_runtime_wait_policies_stmt(step, function, timeout_active, policies);
            }
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_async_runtime_wait_policies_stmt(
                    stmt,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_async_runtime_wait_policies_expr(iterable, function, timeout_active, policies);
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_async_runtime_wait_policies_stmt(
                    stmt,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_async_runtime_wait_policies_stmt(
                    stmt,
                    function,
                    &mut loop_timeout_active,
                    policies,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_async_runtime_wait_policies_expr(value, function, timeout_active, policies);
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_async_runtime_wait_policies_expr(start, function, timeout_active, policies);
            collect_async_runtime_wait_policies_expr(end, function, timeout_active, policies);
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

fn collect_async_runtime_wait_findings(
    function: &hir::TypedFunction,
) -> Vec<AsyncRuntimeWaitFinding> {
    if !function_requires_bounded_runtime_waits(function) {
        return Vec::new();
    }
    collect_async_runtime_wait_policies(function)
        .into_iter()
        .filter_map(|policy| {
            if policy["bounded"].as_bool() == Some(true) {
                return None;
            }
            let callee = policy["callee"].as_str()?;
            let surface = policy["surface"].as_str()?;
            Some(AsyncRuntimeWaitFinding {
                message: format!(
                    "function `{}` performs blocking {surface} wait `{callee}` without a timeout/deadline bound",
                    function.name
                ),
                help: "Add `timeout(...)` or `deadline(...)` before the blocking call, or switch to an intrinsically bounded wait such as `proc.wait(..., timeout_ms)` or `http.poll_next()`. GPU event waits should be deadline-bound so cancelled async work cannot strand pending launches."
                    .to_string(),
            })
        })
        .collect()
}

fn collect_gpu_event_policy_events(
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

fn collect_gpu_event_creation(
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

fn collect_gpu_event_policy_stmt(
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

fn collect_gpu_event_effects_from_expr(
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
                    terminal
                        .entry(name.clone())
                        .or_default()
                        .push(callee.clone());
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

fn collect_gpu_event_findings(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<GpuEventFinding> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut wait_bounds = BTreeMap::<String, Vec<bool>>::new();
    let mut findings = Vec::new();
    let mut timeout_active = false;
    for stmt in &function.body {
        collect_gpu_event_finding_stmt(
            stmt,
            function,
            &mut started,
            &mut terminal,
            &mut wait_bounds,
            &mut findings,
            &mut timeout_active,
            terminal_param_summaries,
        );
    }
    for (event, origin) in started {
        match terminal.get(&event) {
            None => findings.push(GpuEventFinding {
                function: function.name.clone(),
                event: event.clone(),
                kind: "gpu_event_missing_terminal",
                message: format!(
                    "gpu event `{event}` is created by `{origin}` and exits `{}` without `gpu.wait` or `gpu.wait_async`",
                    function.name
                ),
                help: "Terminate every GPU launch event exactly once with `gpu.wait(...)` or `await gpu.wait_async(...)` before the function exits."
                    .to_string(),
            }),
            Some(ops) if ops.len() > 1 => findings.push(GpuEventFinding {
                function: function.name.clone(),
                event: event.clone(),
                kind: "gpu_event_double_terminal",
                message: format!(
                    "gpu event `{event}` is already terminated by `{}` and later consumed again by `{}`",
                    ops[0], ops[1]
                ),
                help: "Consume each GPU event exactly once and remove the later wait."
                    .to_string(),
            }),
            Some(_) if function_requires_bounded_runtime_waits(function)
                && wait_bounds
                    .get(&event)
                    .is_some_and(|bounds| bounds.iter().any(|bounded| !bounded)) =>
            {
                findings.push(GpuEventFinding {
                    function: function.name.clone(),
                    event: event.clone(),
                    kind: "gpu_event_unbounded_wait",
                    message: format!(
                        "gpu event `{event}` in `{}` reaches `gpu.wait`/`gpu.wait_async` without a task-local timeout/deadline bound",
                        function.name
                    ),
                    help: "Add `timeout(...)` or `deadline(...)` before waiting on the GPU event so async cancellation and pending launch cleanup stay bounded."
                        .to_string(),
                });
            }
            _ => {}
        }
    }
    findings
}

fn collect_gpu_event_finding_stmt(
    stmt: &ast::Stmt,
    function: &hir::TypedFunction,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    wait_bounds: &mut BTreeMap<String, Vec<bool>>,
    findings: &mut Vec<GpuEventFinding>,
    timeout_active: &mut bool,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) {
    match stmt {
        ast::Stmt::Let { name, value, .. } => {
            collect_gpu_event_creation(name, value, started);
            collect_gpu_event_finding_expr(
                value,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
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
            collect_gpu_event_finding_expr(
                value,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_gpu_event_finding_expr(
                condition,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut then_timeout_active = *timeout_active;
            for nested in then_body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut then_timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut else_timeout_active = *timeout_active;
            for nested in else_body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut else_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_gpu_event_finding_expr(
                condition,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
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
                collect_gpu_event_finding_stmt(
                    init,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_gpu_event_finding_expr(
                    condition,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_gpu_event_finding_stmt(
                    step,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_gpu_event_finding_expr(
                iterable,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            let mut loop_timeout_active = *timeout_active;
            for nested in body {
                collect_gpu_event_finding_stmt(
                    nested,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_gpu_event_finding_expr(
                scrutinee,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_finding_expr(
                        guard,
                        function,
                        started,
                        terminal,
                        wait_bounds,
                        findings,
                        &mut arm_timeout_active,
                        terminal_param_summaries,
                    );
                }
                collect_gpu_event_finding_expr(
                    &arm.value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut arm_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_gpu_event_finding_expr(
    expr: &ast::Expr,
    function: &hir::TypedFunction,
    started: &mut BTreeMap<String, String>,
    terminal: &mut BTreeMap<String, Vec<String>>,
    wait_bounds: &mut BTreeMap<String, Vec<bool>>,
    findings: &mut Vec<GpuEventFinding>,
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
                    if let Some(previous) = terminal.get(name).and_then(|ops| ops.last()) {
                        findings.push(GpuEventFinding {
                            function: function.name.clone(),
                            event: name.clone(),
                            kind: "gpu_event_double_terminal",
                            message: format!(
                                "gpu event `{name}` is already terminated by `{previous}` and later consumed again by `{callee}`"
                            ),
                            help: "Consume each GPU event exactly once and remove the later wait."
                                .to_string(),
                        });
                    }
                    terminal
                        .entry(name.clone())
                        .or_default()
                        .push(callee.clone());
                    wait_bounds.entry(name.clone()).or_default().push(
                        runtime_wait_policy(callee, *timeout_active)
                            .is_some_and(|(_, bounded)| bounded),
                    );
                }
            }
            if let Some(summary) = terminal_param_summaries.get(callee) {
                for (index, terminal_name) in summary {
                    if let Some(ast::Expr::Ident(name)) = args.get(*index) {
                        started
                            .entry(name.clone())
                            .or_insert_with(|| "unknown".to_string());
                        if let Some(previous) = terminal.get(name).and_then(|ops| ops.last()) {
                            findings.push(GpuEventFinding {
                                function: function.name.clone(),
                                event: name.clone(),
                                kind: "gpu_event_double_terminal",
                                message: format!(
                                    "gpu event `{name}` is already terminated by `{previous}` and later consumed again by `{terminal_name} via {callee}`"
                                ),
                                help: "Consume each GPU event exactly once and remove the later wait."
                                    .to_string(),
                            });
                        }
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
                collect_gpu_event_finding_expr(
                    arg,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
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
            collect_gpu_event_finding_expr(
                inner,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Index { base, index } => {
            collect_gpu_event_finding_expr(
                base,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_finding_expr(
                index,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_gpu_event_finding_expr(
                left,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_finding_expr(
                right,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_gpu_event_finding_expr(
                    value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
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
                collect_gpu_event_finding_expr(
                    value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            for (_, value) in named_payload {
                collect_gpu_event_finding_expr(
                    value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Tuple(values) | ast::Expr::ArrayLiteral(values) => {
            for value in values {
                collect_gpu_event_finding_expr(
                    value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_gpu_event_finding_expr(
                body,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_gpu_event_finding_expr(
                try_expr,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_finding_expr(
                catch_expr,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_gpu_event_finding_expr(
                condition,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut then_timeout_active = *timeout_active;
            collect_gpu_event_finding_expr(
                then_expr,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                &mut then_timeout_active,
                terminal_param_summaries,
            );
            let mut else_timeout_active = *timeout_active;
            collect_gpu_event_finding_expr(
                else_expr,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                &mut else_timeout_active,
                terminal_param_summaries,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_gpu_event_finding_expr(
                scrutinee,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            for arm in arms {
                let mut arm_timeout_active = *timeout_active;
                if let Some(guard) = &arm.guard {
                    collect_gpu_event_finding_expr(
                        guard,
                        function,
                        started,
                        terminal,
                        wait_bounds,
                        findings,
                        &mut arm_timeout_active,
                        terminal_param_summaries,
                    );
                }
                collect_gpu_event_finding_expr(
                    &arm.value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut arm_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            collect_gpu_event_finding_expr(
                condition,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_finding_stmt(
                    stmt,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
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
                collect_gpu_event_finding_stmt(
                    init,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(condition) = condition {
                collect_gpu_event_finding_expr(
                    condition,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            if let Some(step) = step {
                collect_gpu_event_finding_stmt(
                    step,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_finding_stmt(
                    stmt,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_gpu_event_finding_expr(
                iterable,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_finding_stmt(
                    stmt,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Loop { body } | ast::Expr::UnsafeBlock { body, .. } => {
            let mut loop_timeout_active = *timeout_active;
            for stmt in body {
                collect_gpu_event_finding_stmt(
                    stmt,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    &mut loop_timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(value) = value {
                collect_gpu_event_finding_expr(
                    value,
                    function,
                    started,
                    terminal,
                    wait_bounds,
                    findings,
                    timeout_active,
                    terminal_param_summaries,
                );
            }
        }
        ast::Expr::Range { start, end, .. } => {
            collect_gpu_event_finding_expr(
                start,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
                timeout_active,
                terminal_param_summaries,
            );
            collect_gpu_event_finding_expr(
                end,
                function,
                started,
                terminal,
                wait_bounds,
                findings,
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

fn collect_task_group_policy_stmt(
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
                    terminal
                        .entry(name.clone())
                        .or_default()
                        .push(callee.clone());
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

fn collect_task_group_policy_expr(
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

