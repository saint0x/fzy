use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FreezeStateSet {
    pub(crate) unfrozen: bool,
    pub(crate) frozen: bool,
}

impl FreezeStateSet {
    fn unfrozen() -> Self {
        Self {
            unfrozen: true,
            frozen: false,
        }
    }

    fn frozen() -> Self {
        Self {
            unfrozen: false,
            frozen: true,
        }
    }

    fn union(self, other: Self) -> Self {
        Self {
            unfrozen: self.unfrozen || other.unfrozen,
            frozen: self.frozen || other.frozen,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FreezeFunctionSummary {
    pub(crate) exit_from_unfrozen: FreezeStateSet,
    pub(crate) exit_from_frozen: FreezeStateSet,
    pub(crate) alloc_violation_from_unfrozen: bool,
    pub(crate) alloc_violation_from_frozen: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct FreezePhaseFinding {
    pub(crate) message: String,
    pub(crate) help: String,
}

pub(crate) fn is_freeze_phase_call(callee: &str) -> bool {
    callee == "mem.freeze"
}

pub(crate) fn is_unfreeze_phase_call(callee: &str) -> bool {
    callee == "mem.unfreeze"
}

pub(crate) fn is_memory_phase_alloc_like_callee(callee: &str) -> bool {
    callee == "alloc" || callee.ends_with(".alloc") || callee.starts_with("gpu.alloc_")
}

pub(crate) fn build_freeze_phase_summaries(
    fir: &fir::FirModule,
) -> HashMap<String, FreezeFunctionSummary> {
    fn scan_expr_states(
        expr: &ast::Expr,
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
    ) -> (FreezeStateSet, bool) {
        match expr {
            ast::Expr::Call { callee, args } => {
                let mut current = states;
                let mut violation = false;
                for arg in args {
                    let (next, next_violation) = scan_expr_states(arg, current, summaries);
                    current = next;
                    violation |= next_violation;
                }
                if is_freeze_phase_call(callee) {
                    return (FreezeStateSet::frozen(), violation);
                }
                if is_unfreeze_phase_call(callee) {
                    return (FreezeStateSet::unfrozen(), violation);
                }
                if is_memory_phase_alloc_like_callee(callee) && current.frozen {
                    violation = true;
                }
                if let Some(summary) = summaries.get(callee) {
                    if current.unfrozen {
                        violation |= summary.alloc_violation_from_unfrozen;
                    }
                    if current.frozen {
                        violation |= summary.alloc_violation_from_frozen;
                    }
                    let mut exits = FreezeStateSet::default();
                    if current.unfrozen {
                        exits = exits.union(summary.exit_from_unfrozen);
                    }
                    if current.frozen {
                        exits = exits.union(summary.exit_from_frozen);
                    }
                    return (exits, violation);
                }
                (current, violation)
            }
            ast::Expr::UnsafeBlock { body, .. } => scan_stmt_states(body, states, summaries),
            ast::Expr::Group(inner)
            | ast::Expr::Await(inner)
            | ast::Expr::Discard(inner)
            | ast::Expr::Unary { expr: inner, .. } => scan_expr_states(inner, states, summaries),
            ast::Expr::FieldAccess { base, .. } => scan_expr_states(base, states, summaries),
            ast::Expr::Index { base, index } => {
                let (after_base, base_violation) = scan_expr_states(base, states, summaries);
                let (after_index, index_violation) = scan_expr_states(index, after_base, summaries);
                (after_index, base_violation || index_violation)
            }
            ast::Expr::Binary { left, right, .. } => {
                let (after_left, left_violation) = scan_expr_states(left, states, summaries);
                let (after_right, right_violation) = scan_expr_states(right, after_left, summaries);
                (after_right, left_violation || right_violation)
            }
            ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
                let mut current = states;
                let mut violation = false;
                for (_, value) in fields {
                    let (next, next_violation) = scan_expr_states(value, current, summaries);
                    current = next;
                    violation |= next_violation;
                }
                (current, violation)
            }
            ast::Expr::EnumInit {
                payload,
                named_payload,
                ..
            } => {
                let mut current = states;
                let mut violation = false;
                for value in payload {
                    let (next, next_violation) = scan_expr_states(value, current, summaries);
                    current = next;
                    violation |= next_violation;
                }
                for (_, value) in named_payload {
                    let (next, next_violation) = scan_expr_states(value, current, summaries);
                    current = next;
                    violation |= next_violation;
                }
                (current, violation)
            }
            ast::Expr::Closure { body, .. } => scan_expr_states(body, states, summaries),
            ast::Expr::Tuple(items) | ast::Expr::ArrayLiteral(items) => {
                let mut current = states;
                let mut violation = false;
                for item in items {
                    let (next, next_violation) = scan_expr_states(item, current, summaries);
                    current = next;
                    violation |= next_violation;
                }
                (current, violation)
            }
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                let (after_try, try_violation) = scan_expr_states(try_expr, states, summaries);
                let (after_catch, catch_violation) =
                    scan_expr_states(catch_expr, states, summaries);
                (
                    after_try.union(after_catch),
                    try_violation || catch_violation,
                )
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                let (after_condition, condition_violation) =
                    scan_expr_states(condition, states, summaries);
                let (after_then, then_violation) =
                    scan_expr_states(then_expr, after_condition, summaries);
                let (after_else, else_violation) =
                    scan_expr_states(else_expr, after_condition, summaries);
                (
                    after_then.union(after_else),
                    condition_violation || then_violation || else_violation,
                )
            }
            ast::Expr::Match { scrutinee, arms } => {
                let (after_scrutinee, scrutinee_violation) =
                    scan_expr_states(scrutinee, states, summaries);
                let mut exits = FreezeStateSet::default();
                let mut violation = scrutinee_violation;
                for arm in arms {
                    let (after_arm, arm_violation) =
                        scan_expr_states(&arm.value, after_scrutinee, summaries);
                    exits = exits.union(after_arm);
                    violation |= arm_violation;
                }
                (exits, violation)
            }
            ast::Expr::While { condition, body } => {
                let (after_condition, condition_violation) =
                    scan_expr_states(condition, states, summaries);
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_condition, summaries);
                (
                    after_condition.union(after_body),
                    condition_violation || body_violation,
                )
            }
            ast::Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                let (after_init, init_violation) =
                    init.as_deref().map_or((states, false), |stmt| {
                        scan_stmt_state(stmt, states, summaries)
                    });
                let (after_condition, condition_violation) =
                    condition.as_deref().map_or((after_init, false), |expr| {
                        scan_expr_states(expr, after_init, summaries)
                    });
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_condition, summaries);
                let (after_step, step_violation) =
                    step.as_deref().map_or((after_body, false), |stmt| {
                        scan_stmt_state(stmt, after_body, summaries)
                    });
                (
                    after_condition.union(after_step),
                    init_violation || condition_violation || body_violation || step_violation,
                )
            }
            ast::Expr::ForIn { iterable, body, .. } => {
                let (after_iterable, iterable_violation) =
                    scan_expr_states(iterable, states, summaries);
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_iterable, summaries);
                (
                    after_iterable.union(after_body),
                    iterable_violation || body_violation,
                )
            }
            ast::Expr::Loop { body } => {
                let (after_body, body_violation) = scan_stmt_states(body, states, summaries);
                (states.union(after_body), body_violation)
            }
            ast::Expr::Break(value) | ast::Expr::Return(value) => {
                value.as_deref().map_or((states, false), |expr| {
                    scan_expr_states(expr, states, summaries)
                })
            }
            ast::Expr::Range { start, end, .. } => {
                let (after_start, start_violation) = scan_expr_states(start, states, summaries);
                let (after_end, end_violation) = scan_expr_states(end, after_start, summaries);
                (after_end, start_violation || end_violation)
            }
            ast::Expr::Continue
            | ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Ident(_) => (states, false),
        }
    }

    fn scan_stmt_state(
        stmt: &ast::Stmt,
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
    ) -> (FreezeStateSet, bool) {
        match stmt {
            ast::Stmt::Let { value, .. }
            | ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Expr(value)
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value) => scan_expr_states(value, states, summaries),
            ast::Stmt::Return(Some(value)) | ast::Stmt::Break(Some(value)) => {
                scan_expr_states(value, states, summaries)
            }
            ast::Stmt::Return(None) | ast::Stmt::Break(None) | ast::Stmt::Continue => {
                (states, false)
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let (after_condition, condition_violation) =
                    scan_expr_states(condition, states, summaries);
                let (after_then, then_violation) =
                    scan_stmt_states(then_body, after_condition, summaries);
                let (after_else, else_violation) =
                    scan_stmt_states(else_body, after_condition, summaries);
                (
                    after_then.union(after_else),
                    condition_violation || then_violation || else_violation,
                )
            }
            ast::Stmt::While { condition, body } => {
                let (after_condition, condition_violation) =
                    scan_expr_states(condition, states, summaries);
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_condition, summaries);
                (
                    after_condition.union(after_body),
                    condition_violation || body_violation,
                )
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                let (after_init, init_violation) =
                    init.as_deref().map_or((states, false), |stmt| {
                        scan_stmt_state(stmt, states, summaries)
                    });
                let (after_condition, condition_violation) =
                    condition.as_ref().map_or((after_init, false), |expr| {
                        scan_expr_states(expr, after_init, summaries)
                    });
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_condition, summaries);
                let (after_step, step_violation) =
                    step.as_deref().map_or((after_body, false), |stmt| {
                        scan_stmt_state(stmt, after_body, summaries)
                    });
                (
                    after_condition.union(after_step),
                    init_violation || condition_violation || body_violation || step_violation,
                )
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                let (after_iterable, iterable_violation) =
                    scan_expr_states(iterable, states, summaries);
                let (after_body, body_violation) =
                    scan_stmt_states(body, after_iterable, summaries);
                (
                    after_iterable.union(after_body),
                    iterable_violation || body_violation,
                )
            }
            ast::Stmt::Loop { body } => {
                let (after_body, body_violation) = scan_stmt_states(body, states, summaries);
                (states.union(after_body), body_violation)
            }
            ast::Stmt::Match { scrutinee, arms } => {
                let (after_scrutinee, scrutinee_violation) =
                    scan_expr_states(scrutinee, states, summaries);
                let mut exits = FreezeStateSet::default();
                let mut violation = scrutinee_violation;
                for arm in arms {
                    let (after_arm, arm_violation) =
                        scan_expr_states(&arm.value, after_scrutinee, summaries);
                    exits = exits.union(after_arm);
                    violation |= arm_violation;
                }
                (exits, violation)
            }
        }
    }

    fn scan_stmt_states(
        body: &[ast::Stmt],
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
    ) -> (FreezeStateSet, bool) {
        let mut current = states;
        let mut violation = false;
        for stmt in body {
            let (next, next_violation) = scan_stmt_state(stmt, current, summaries);
            current = next;
            violation |= next_violation;
        }
        (current, violation)
    }

    let mut summaries = fir
        .typed_functions
        .iter()
        .map(|function| (function.name.clone(), FreezeFunctionSummary::default()))
        .collect::<HashMap<_, _>>();
    loop {
        let mut changed = false;
        let mut next_summaries = summaries.clone();
        for function in &fir.typed_functions {
            let (exit_from_unfrozen, alloc_violation_from_unfrozen) =
                scan_stmt_states(&function.body, FreezeStateSet::unfrozen(), &summaries);
            let (exit_from_frozen, alloc_violation_from_frozen) =
                scan_stmt_states(&function.body, FreezeStateSet::frozen(), &summaries);
            let summary = FreezeFunctionSummary {
                exit_from_unfrozen,
                exit_from_frozen,
                alloc_violation_from_unfrozen,
                alloc_violation_from_frozen,
            };
            if next_summaries.get(&function.name) != Some(&summary) {
                next_summaries.insert(function.name.clone(), summary);
                changed = true;
            }
        }
        summaries = next_summaries;
        if !changed {
            break;
        }
    }
    summaries
}

pub(crate) fn collect_freeze_phase_findings(
    fir: &fir::FirModule,
    summaries: &HashMap<String, FreezeFunctionSummary>,
) -> Vec<FreezePhaseFinding> {
    fn scan_expr_findings(
        function_name: &str,
        expr: &ast::Expr,
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
        findings: &mut Vec<FreezePhaseFinding>,
    ) -> FreezeStateSet {
        match expr {
            ast::Expr::Call { callee, args } => {
                let mut current = states;
                for arg in args {
                    current = scan_expr_findings(function_name, arg, current, summaries, findings);
                }
                if is_freeze_phase_call(callee) {
                    return FreezeStateSet::frozen();
                }
                if is_unfreeze_phase_call(callee) {
                    return FreezeStateSet::unfrozen();
                }
                if is_memory_phase_alloc_like_callee(callee) && current.frozen {
                    findings.push(FreezePhaseFinding {
                        message: format!(
                            "function `{function_name}` performs allocation `{callee}` after `mem.freeze()` under strict memory phase checking"
                        ),
                        help: "Move the allocation before `mem.freeze()`, insert `mem.unfreeze()` before the allocating operation, or split boot-time setup from steady-state execution.".to_string(),
                    });
                } else if current.frozen {
                    if let Some(summary) = summaries.get(callee) {
                        if summary.alloc_violation_from_frozen {
                            findings.push(FreezePhaseFinding {
                                message: format!(
                                    "function `{function_name}` calls `{callee}` from a frozen memory phase even though `{callee}` may allocate before `mem.unfreeze()`"
                                ),
                                help: "Call the helper before `mem.freeze()`, unfreeze explicitly before the call, or refactor the helper so every allocation happens before the frozen phase begins.".to_string(),
                            });
                        }
                        let mut exits = FreezeStateSet::default();
                        if current.unfrozen {
                            exits = exits.union(summary.exit_from_unfrozen);
                        }
                        if current.frozen {
                            exits = exits.union(summary.exit_from_frozen);
                        }
                        return exits;
                    }
                } else if let Some(summary) = summaries.get(callee) {
                    let mut exits = FreezeStateSet::default();
                    if current.unfrozen {
                        exits = exits.union(summary.exit_from_unfrozen);
                    }
                    if current.frozen {
                        exits = exits.union(summary.exit_from_frozen);
                    }
                    return exits;
                }
                current
            }
            ast::Expr::UnsafeBlock { body, .. } => {
                scan_stmt_findings(function_name, body, states, summaries, findings)
            }
            ast::Expr::Group(inner)
            | ast::Expr::Await(inner)
            | ast::Expr::Discard(inner)
            | ast::Expr::Unary { expr: inner, .. } => {
                scan_expr_findings(function_name, inner, states, summaries, findings)
            }
            ast::Expr::FieldAccess { base, .. } => {
                scan_expr_findings(function_name, base, states, summaries, findings)
            }
            ast::Expr::Index { base, index } => {
                let after_base =
                    scan_expr_findings(function_name, base, states, summaries, findings);
                scan_expr_findings(function_name, index, after_base, summaries, findings)
            }
            ast::Expr::Binary { left, right, .. } => {
                let after_left =
                    scan_expr_findings(function_name, left, states, summaries, findings);
                scan_expr_findings(function_name, right, after_left, summaries, findings)
            }
            ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
                let mut current = states;
                for (_, value) in fields {
                    current =
                        scan_expr_findings(function_name, value, current, summaries, findings);
                }
                current
            }
            ast::Expr::EnumInit {
                payload,
                named_payload,
                ..
            } => {
                let mut current = states;
                for value in payload {
                    current =
                        scan_expr_findings(function_name, value, current, summaries, findings);
                }
                for (_, value) in named_payload {
                    current =
                        scan_expr_findings(function_name, value, current, summaries, findings);
                }
                current
            }
            ast::Expr::Closure { body, .. } => {
                scan_expr_findings(function_name, body, states, summaries, findings)
            }
            ast::Expr::Tuple(items) | ast::Expr::ArrayLiteral(items) => {
                let mut current = states;
                for item in items {
                    current = scan_expr_findings(function_name, item, current, summaries, findings);
                }
                current
            }
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                let after_try =
                    scan_expr_findings(function_name, try_expr, states, summaries, findings);
                let after_catch =
                    scan_expr_findings(function_name, catch_expr, states, summaries, findings);
                after_try.union(after_catch)
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                let after_condition =
                    scan_expr_findings(function_name, condition, states, summaries, findings);
                let after_then = scan_expr_findings(
                    function_name,
                    then_expr,
                    after_condition,
                    summaries,
                    findings,
                );
                let after_else = scan_expr_findings(
                    function_name,
                    else_expr,
                    after_condition,
                    summaries,
                    findings,
                );
                after_then.union(after_else)
            }
            ast::Expr::Match { scrutinee, arms } => {
                let after_scrutinee =
                    scan_expr_findings(function_name, scrutinee, states, summaries, findings);
                let mut exits = FreezeStateSet::default();
                for arm in arms {
                    exits = exits.union(scan_expr_findings(
                        function_name,
                        &arm.value,
                        after_scrutinee,
                        summaries,
                        findings,
                    ));
                }
                exits
            }
            ast::Expr::While { condition, body } => {
                let after_condition =
                    scan_expr_findings(function_name, condition, states, summaries, findings);
                let after_body =
                    scan_stmt_findings(function_name, body, after_condition, summaries, findings);
                after_condition.union(after_body)
            }
            ast::Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                let after_init = init.as_deref().map_or(states, |stmt| {
                    scan_single_stmt_findings(function_name, stmt, states, summaries, findings)
                });
                let after_condition = condition.as_deref().map_or(after_init, |expr| {
                    scan_expr_findings(function_name, expr, after_init, summaries, findings)
                });
                let after_body =
                    scan_stmt_findings(function_name, body, after_condition, summaries, findings);
                let after_step = step.as_deref().map_or(after_body, |stmt| {
                    scan_single_stmt_findings(function_name, stmt, after_body, summaries, findings)
                });
                after_condition.union(after_step)
            }
            ast::Expr::ForIn { iterable, body, .. } => {
                let after_iterable =
                    scan_expr_findings(function_name, iterable, states, summaries, findings);
                let after_body =
                    scan_stmt_findings(function_name, body, after_iterable, summaries, findings);
                after_iterable.union(after_body)
            }
            ast::Expr::Loop { body } => {
                let after_body =
                    scan_stmt_findings(function_name, body, states, summaries, findings);
                states.union(after_body)
            }
            ast::Expr::Break(value) | ast::Expr::Return(value) => {
                value.as_deref().map_or(states, |value| {
                    scan_expr_findings(function_name, value, states, summaries, findings)
                })
            }
            ast::Expr::Range { start, end, .. } => {
                let after_start =
                    scan_expr_findings(function_name, start, states, summaries, findings);
                scan_expr_findings(function_name, end, after_start, summaries, findings)
            }
            ast::Expr::Continue
            | ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Ident(_) => states,
        }
    }

    fn scan_single_stmt_findings(
        function_name: &str,
        stmt: &ast::Stmt,
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
        findings: &mut Vec<FreezePhaseFinding>,
    ) -> FreezeStateSet {
        match stmt {
            ast::Stmt::Let { value, .. }
            | ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Expr(value)
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value) => {
                scan_expr_findings(function_name, value, states, summaries, findings)
            }
            ast::Stmt::Return(Some(value)) | ast::Stmt::Break(Some(value)) => {
                scan_expr_findings(function_name, value, states, summaries, findings)
            }
            ast::Stmt::Return(None) | ast::Stmt::Break(None) | ast::Stmt::Continue => states,
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let after_condition =
                    scan_expr_findings(function_name, condition, states, summaries, findings);
                let after_then = scan_stmt_findings(
                    function_name,
                    then_body,
                    after_condition,
                    summaries,
                    findings,
                );
                let after_else = scan_stmt_findings(
                    function_name,
                    else_body,
                    after_condition,
                    summaries,
                    findings,
                );
                after_then.union(after_else)
            }
            ast::Stmt::While { condition, body } => {
                let after_condition =
                    scan_expr_findings(function_name, condition, states, summaries, findings);
                let after_body =
                    scan_stmt_findings(function_name, body, after_condition, summaries, findings);
                after_condition.union(after_body)
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                let after_init = init.as_deref().map_or(states, |stmt| {
                    scan_single_stmt_findings(function_name, stmt, states, summaries, findings)
                });
                let after_condition = condition.as_ref().map_or(after_init, |expr| {
                    scan_expr_findings(function_name, expr, after_init, summaries, findings)
                });
                let after_body =
                    scan_stmt_findings(function_name, body, after_condition, summaries, findings);
                let after_step = step.as_deref().map_or(after_body, |stmt| {
                    scan_single_stmt_findings(function_name, stmt, after_body, summaries, findings)
                });
                after_condition.union(after_step)
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                let after_iterable =
                    scan_expr_findings(function_name, iterable, states, summaries, findings);
                let after_body =
                    scan_stmt_findings(function_name, body, after_iterable, summaries, findings);
                after_iterable.union(after_body)
            }
            ast::Stmt::Loop { body } => {
                let after_body =
                    scan_stmt_findings(function_name, body, states, summaries, findings);
                states.union(after_body)
            }
            ast::Stmt::Match { scrutinee, arms } => {
                let after_scrutinee =
                    scan_expr_findings(function_name, scrutinee, states, summaries, findings);
                let mut exits = FreezeStateSet::default();
                for arm in arms {
                    exits = exits.union(scan_expr_findings(
                        function_name,
                        &arm.value,
                        after_scrutinee,
                        summaries,
                        findings,
                    ));
                }
                exits
            }
        }
    }

    fn scan_stmt_findings(
        function_name: &str,
        body: &[ast::Stmt],
        states: FreezeStateSet,
        summaries: &HashMap<String, FreezeFunctionSummary>,
        findings: &mut Vec<FreezePhaseFinding>,
    ) -> FreezeStateSet {
        let mut current = states;
        for stmt in body {
            current = scan_single_stmt_findings(function_name, stmt, current, summaries, findings);
        }
        current
    }

    let mut findings = Vec::new();
    for function in &fir.typed_functions {
        scan_stmt_findings(
            &function.name,
            &function.body,
            FreezeStateSet::unfrozen(),
            summaries,
            &mut findings,
        );
    }
    findings
}
