use serde::Serialize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeWaitSurface {
    Process,
    GpuEvent,
    Http,
    HttpStream,
    Websocket,
}

impl RuntimeWaitSurface {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::GpuEvent => "gpu_event",
            Self::Http => "http",
            Self::HttpStream => "http_stream",
            Self::Websocket => "websocket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeWaitBounding {
    ExplicitTimeoutArg,
    IntrinsicPollTimeout,
    TaskLocalTimeoutOrDeadline,
    MissingTimeoutOrDeadline,
}

impl RuntimeWaitBounding {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitTimeoutArg => "explicit_timeout_arg",
            Self::IntrinsicPollTimeout => "intrinsic_poll_timeout",
            Self::TaskLocalTimeoutOrDeadline => "task_local_timeout_or_deadline",
            Self::MissingTimeoutOrDeadline => "missing_timeout_or_deadline",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeWaitBlockingBehavior {
    MayBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeWaitCancellationPolicy {
    DeadlineBoundWaitThenCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeWaitPolicyDecision {
    pub(crate) bounding: RuntimeWaitBounding,
    pub(crate) bounded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AsyncRuntimeWaitPolicy {
    pub(crate) function: String,
    pub(crate) callee: String,
    pub(crate) surface: RuntimeWaitSurface,
    #[serde(rename = "blockingBehavior")]
    pub(crate) blocking_behavior: RuntimeWaitBlockingBehavior,
    #[serde(rename = "requiresBoundedWaits")]
    pub(crate) requires_bounded_waits: bool,
    pub(crate) bounded: bool,
    pub(crate) bounding: RuntimeWaitBounding,
    pub(crate) cancellation: Option<RuntimeWaitCancellationPolicy>,
}

pub(crate) fn function_requires_bounded_runtime_waits(function: &hir::TypedFunction) -> bool {
    function.is_async
        || function
            .required_capabilities
            .iter()
            .any(|capability| capability == "thread")
}

pub(crate) fn runtime_wait_policy(
    callee: &str,
    timeout_active: bool,
) -> Option<(&'static str, bool)> {
    runtime_wait_policy_decision(callee, timeout_active)
        .map(|decision| (decision.bounding.as_str(), decision.bounded))
}

pub(crate) fn runtime_wait_surface_kind(callee: &str) -> Option<RuntimeWaitSurface> {
    match callee {
        "proc.wait" => Some(RuntimeWaitSurface::Process),
        "gpu.wait" | "gpu.wait_async" => Some(RuntimeWaitSurface::GpuEvent),
        "http.poll_next" | "http.read" | "http.read_headers" | "http.request_stream" => {
            Some(RuntimeWaitSurface::Http)
        }
        "http.stream_read" | "http.stream_read_line" => Some(RuntimeWaitSurface::HttpStream),
        "http.websocket_read" => Some(RuntimeWaitSurface::Websocket),
        _ => None,
    }
}

pub(crate) fn runtime_wait_policy_decision(
    callee: &str,
    timeout_active: bool,
) -> Option<RuntimeWaitPolicyDecision> {
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
    .map(|(bounding, bounded)| RuntimeWaitPolicyDecision {
        bounding: match bounding {
            "explicit_timeout_arg" => RuntimeWaitBounding::ExplicitTimeoutArg,
            "intrinsic_poll_timeout" => RuntimeWaitBounding::IntrinsicPollTimeout,
            "task_local_timeout_or_deadline" => RuntimeWaitBounding::TaskLocalTimeoutOrDeadline,
            "missing_timeout_or_deadline" => RuntimeWaitBounding::MissingTimeoutOrDeadline,
            _ => unreachable!("runtime wait policy bounding must stay in sync"),
        },
        bounded,
    })
}

pub(crate) fn collect_async_runtime_wait_policies(
    function: &hir::TypedFunction,
) -> Vec<AsyncRuntimeWaitPolicy> {
    let mut policies = Vec::<AsyncRuntimeWaitPolicy>::new();
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
    policies: &mut Vec<AsyncRuntimeWaitPolicy>,
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
    policies: &mut Vec<AsyncRuntimeWaitPolicy>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if matches!(callee.as_str(), "timeout" | "deadline") {
                *timeout_active = true;
            }
            if let (Some(surface), Some(decision)) = (
                runtime_wait_surface_kind(callee),
                runtime_wait_policy_decision(callee, *timeout_active),
            ) {
                policies.push(AsyncRuntimeWaitPolicy {
                    function: function.name.clone(),
                    callee: callee.clone(),
                    surface,
                    blocking_behavior: RuntimeWaitBlockingBehavior::MayBlock,
                    requires_bounded_waits: function_requires_bounded_runtime_waits(function),
                    bounded: decision.bounded,
                    bounding: decision.bounding,
                    cancellation: matches!(surface, RuntimeWaitSurface::GpuEvent)
                        .then_some(RuntimeWaitCancellationPolicy::DeadlineBoundWaitThenCleanup),
                });
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
            if policy.bounded {
                return None;
            }
            Some(AsyncRuntimeWaitFinding {
                message: format!(
                    "function `{}` performs blocking {} wait `{}` without a timeout/deadline bound",
                    function.name,
                    policy.surface.as_str(),
                    policy.callee
                ),
                help: "Add `timeout(...)` or `deadline(...)` before the blocking call, or switch to an intrinsically bounded wait such as `proc.wait(..., timeout_ms)` or `http.poll_next()`. GPU event waits should be deadline-bound so cancelled async work cannot strand pending launches."
                    .to_string(),
            })
        })
        .collect()
}
