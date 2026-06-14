use super::*;

pub(crate) fn collect_gpu_event_finding_expr(
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
                        started.entry(name.clone()).or_insert_with(|| "unknown".to_string());
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
                        wait_bounds.entry(name.clone()).or_default().push(*timeout_active);
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
                super::stmt::collect_gpu_event_finding_stmt(
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
                super::stmt::collect_gpu_event_finding_stmt(
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
                super::stmt::collect_gpu_event_finding_stmt(
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
                super::stmt::collect_gpu_event_finding_stmt(
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
                super::stmt::collect_gpu_event_finding_stmt(
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
                super::stmt::collect_gpu_event_finding_stmt(
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
