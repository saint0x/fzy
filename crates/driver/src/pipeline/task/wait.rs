#[derive(Debug, Clone)]
pub(crate) struct AsyncRuntimeWaitFinding {
    pub(crate) message: String,
    pub(crate) help: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GpuEventFinding {
    pub(crate) function: String,
    pub(crate) event: String,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    pub(crate) help: String,
}

pub(crate) fn function_requires_bounded_runtime_waits(function: &hir::TypedFunction) -> bool {
    function.is_async
        || function
            .required_capabilities
            .iter()
            .any(|capability| capability == "thread")
}

pub(crate) fn runtime_wait_surface(callee: &str) -> Option<&'static str> {
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

pub(crate) fn runtime_wait_policy(
    callee: &str,
    timeout_active: bool,
) -> Option<(&'static str, bool)> {
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

pub(crate) fn collect_async_runtime_wait_policies(
    function: &hir::TypedFunction,
) -> Vec<serde_json::Value> {
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

pub(crate) fn collect_async_runtime_wait_policies_stmt(
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

pub(crate) fn collect_async_runtime_wait_policies_expr(
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

pub(crate) fn collect_async_runtime_wait_findings(
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
