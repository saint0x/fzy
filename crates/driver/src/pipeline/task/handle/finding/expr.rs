use super::*;

pub(crate) fn collect_task_handle_finding_expr(
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
                            terminal.entry(name.clone()).or_default().push(callee.clone());
                        } else {
                            terminal.entry(name.clone()).or_default().push(callee.clone());
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
                super::stmt::collect_task_handle_finding_stmt(
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
                super::stmt::collect_task_handle_finding_stmt(
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
                super::stmt::collect_task_handle_finding_stmt(
                    step,
                    function_name,
                    started,
                    terminal,
                    findings,
                    terminal_param_summaries,
                );
            }
            for stmt in body {
                super::stmt::collect_task_handle_finding_stmt(
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
                super::stmt::collect_task_handle_finding_stmt(
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
                super::stmt::collect_task_handle_finding_stmt(
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
