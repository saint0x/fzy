use super::*;

pub(crate) fn collect_gpu_event_finding_stmt(
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
            super::super::gpu::collect_gpu_event_creation(name, value, started);
            super::expr::collect_gpu_event_finding_expr(
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
            super::expr::collect_gpu_event_finding_expr(
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
            super::expr::collect_gpu_event_finding_expr(
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
            super::expr::collect_gpu_event_finding_expr(
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
                super::expr::collect_gpu_event_finding_expr(
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
            super::expr::collect_gpu_event_finding_expr(
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
            super::expr::collect_gpu_event_finding_expr(
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
                    super::expr::collect_gpu_event_finding_expr(
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
                super::expr::collect_gpu_event_finding_expr(
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
